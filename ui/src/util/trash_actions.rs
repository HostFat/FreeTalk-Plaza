//! Client side of the hide flow: build the encrypted bundle, add the trash
//! item, and let the normal message filter hide it.

use crate::util::ecies::encrypt_with_symmetric_key;
use crate::util::message_actions::{apply_state_delta, ActionContext};
use plaza_core::board_state::message::MessageId;
use plaza_core::board_state::moderation::category_chain;
use plaza_core::board_state::trash::{AuthorizedTrashItem, TrashDelta, TrashItemV1};
use plaza_core::board_state::ChatBoardStateV1Delta;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct TrashBundleV1 {
    messages: Vec<plaza_core::board_state::message::AuthorizedMessageV1>,
    routes: Vec<plaza_core::board_state::moderation::AuthorizedMessageRoute>,
}

pub async fn hide_topic(ctx: &ActionContext, root: MessageId) -> Result<(), String> {
    let self_id = plaza_core::board_state::member::MemberId::from(&ctx.self_sk.verifying_key());
    let is_owner = self_id == plaza_core::board_state::member::MemberId::from(&ctx.current_board);
    let is_admin = ctx
        .board_state
        .admin
        .admins
        .iter()
        .any(|admin| admin.admin.id() == self_id);
    if !is_owner && !is_admin && !ctx.board_state.roles.can_manage_trash(&self_id) {
        return Err("You cannot hide topics".to_string());
    }

    let routes = ctx.board_state.moderation.routes_map();
    let mut ids = Vec::new();
    let mut stack = vec![root];
    while let Some(id) = stack.pop() {
        if ids.contains(&id) {
            continue;
        }
        ids.push(id);
        for (child, route) in &routes {
            if route.reply_to == Some(id) {
                stack.push(*child);
            }
        }
    }
    ids.sort();

    let messages = ctx
        .board_state
        .recent_messages
        .messages
        .iter()
        .filter(|message| ids.contains(&message.id()))
        .cloned()
        .collect::<Vec<_>>();
    let route_records = ctx
        .board_state
        .moderation
        .routes
        .iter()
        .filter(|route| ids.contains(&route.route.message_id))
        .cloned()
        .collect::<Vec<_>>();
    let bundle = TrashBundleV1 {
        messages,
        routes: route_records,
    };
    let mut plaintext = Vec::new();
    ciborium::ser::into_writer(&bundle, &mut plaintext)
        .map_err(|error| format!("Could not encode the trash bundle: {error}"))?;

    let item_key = rand::random::<[u8; 32]>();
    let (bundle_ciphertext, bundle_nonce) = encrypt_with_symmetric_key(&item_key, &plaintext, 0);

    // Prefer the dedicated trash key, shared only with the trash managers.
    let mut pq_set = None;
    let (secret, secret_version) = if let Some((version, key)) = ctx.trash_secret {
        (key, version)
    } else {
        use plaza_core::board_state::pq_secrets::{
            AuthorizedPqSecretSet, PqScope, PqSecretSet, PqSecretsDelta,
        };
        use std::collections::BTreeSet;

        let mut managers = BTreeSet::new();
        managers.insert(plaza_core::board_state::member::MemberId::from(
            &ctx.current_board,
        ));
        for admin in &ctx.board_state.admin.admins {
            managers.insert(admin.admin.id());
        }
        for assignment in &ctx.board_state.roles.assignments {
            if assignment.assignment.revoked {
                continue;
            }
            if ctx.board_state.roles.roles.iter().any(|role| {
                role.role.id == assignment.assignment.role_id
                    && role.role.can_manage_trash
                    && !role.role.deleted
            }) {
                managers.insert(assignment.assignment.member_id);
            }
        }

        let trash_key = rand::random::<[u8; 32]>();
        let mut sealed = Vec::new();
        for manager in &managers {
            let Some(kem) = ctx.board_state.pq_secrets.key_for(*manager) else {
                continue;
            };
            let vk = if *manager
                == plaza_core::board_state::member::MemberId::from(&ctx.current_board)
            {
                ctx.current_board
            } else if let Some(member) = ctx
                .board_state
                .members
                .members
                .iter()
                .find(|member| member.member.id() == *manager)
            {
                member.member.member_vk
            } else {
                continue;
            };
            if let Ok(record) = crate::util::pq::seal_secret(&trash_key, &kem.ek, *manager, &vk) {
                sealed.push(record);
            }
        }

        if sealed.is_empty() {
            // No manager has a PQ key yet: fall back to the board secret.
            let version = ctx.board_state.secrets.current_version;
            let key = ctx
                .board_secrets
                .get(&version)
                .copied()
                .ok_or("The board has no secret to protect the trash")?;
            (key, version)
        } else {
            let version = ctx
                .board_state
                .pq_secrets
                .sets
                .iter()
                .filter(|entry| matches!(entry.set.scope, PqScope::Trash))
                .map(|entry| entry.set.version)
                .max()
                .unwrap_or(0)
                + 1;
            let set = AuthorizedPqSecretSet::new(
                PqSecretSet {
                    scope: PqScope::Trash,
                    version,
                    secret_version: 1,
                    secrets: sealed,
                },
                &ctx.self_sk,
            );
            pq_set = Some(PqSecretsDelta {
                keys: Vec::new(),
                sets: vec![set],
            });
            (trash_key, 1)
        }
    };

    let (sealed_item_key, item_key_nonce) =
        encrypt_with_symmetric_key(&secret, &item_key, secret_version);

    let section = category_chain(&routes, &root).first().copied();
    let mut item = TrashItemV1 {
        id: MessageId::from_bytes([0u8; 32]),
        root,
        messages: ids,
        section,
        bundle: bundle_ciphertext,
        bundle_nonce,
        sealed_item_key,
        item_key_nonce,
        secret_version,
        hidden_at: chrono::Utc::now().timestamp(),
        reason: "hidden for review".to_string(),
        generation: 1,
    };
    item.id = item.compute_id();
    let authorized = AuthorizedTrashItem::new(item, &ctx.self_sk);

    apply_state_delta(
        ctx,
        ChatBoardStateV1Delta {
            trash: Some(TrashDelta {
                items: vec![authorized],
                actions: Vec::new(),
            }),
            pq_secrets: pq_set,
            ..Default::default()
        },
    )
    .map(|_| {
        if let Some(board) = crate::components::app::BOARDS
            .write()
            .map
            .get_mut(&ctx.current_board)
        {
            board.trash_secret = Some((secret_version, secret));
        }
    })
}
