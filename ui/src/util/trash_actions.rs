//! Client side of the hide flow: build the encrypted bundle, add the trash
//! item, and let the normal message filter hide it.

use crate::util::ecies::{decrypt_with_symmetric_key, encrypt_with_symmetric_key};
use crate::util::message_actions::{apply_state_delta, ActionContext};
use dioxus::prelude::*;
use plaza_core::board_state::message::MessageId;
use plaza_core::board_state::moderation::{
    category_chain, AuthorizedThreadMove, ModerationDelta, ThreadMoveV1,
};
use plaza_core::board_state::trash::{
    AuthorizedTrashAction, AuthorizedTrashItem, TrashActionKind, TrashActionV1, TrashDelta,
    TrashItemV1,
};
use plaza_core::board_state::ChatBoardStateV1Delta;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub(crate) struct TrashBundleV1 {
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
    let authors: Vec<_> = messages
        .iter()
        .map(|message| message.message.author)
        .collect();
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
        authors,
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

fn decrypt_bundle(
    ctx: &ActionContext,
    item: &AuthorizedTrashItem,
) -> Result<TrashBundleV1, String> {
    let (secret_version, trash_key) = ctx.trash_secret.ok_or("This member has no trash key")?;
    let item_key = decrypt_with_symmetric_key(
        &trash_key,
        &item.item.sealed_item_key,
        &item.item.item_key_nonce,
        secret_version,
    )?;
    let item_key: [u8; 32] = item_key
        .try_into()
        .map_err(|_| "Trash item key has an invalid length".to_string())?;
    let plaintext =
        decrypt_with_symmetric_key(&item_key, &item.item.bundle, &item.item.bundle_nonce, 0)?;
    ciborium::de::from_reader(plaintext.as_slice())
        .map_err(|error| format!("Could not decode the trash bundle: {error}"))
}

/// Decrypted titles and bodies, for the moderator preview.
pub fn preview_item(
    ctx: &ActionContext,
    item: &AuthorizedTrashItem,
) -> Result<Vec<(String, String)>, String> {
    let bundle = decrypt_bundle(ctx, item)?;
    let mut temporary = ctx.board_state.clone();
    temporary.trash = Default::default();
    temporary.recent_messages = plaza_core::board_state::message::MessagesV1 {
        messages: bundle.messages,
        ..Default::default()
    };
    temporary.moderation.routes = bundle.routes;
    let data = crate::components::app::BOARDS
        .read()
        .map
        .get(&ctx.current_board)
        .cloned()
        .ok_or("Board data is not available")?;
    let messages = crate::components::conversation::get_all_messages(
        &temporary,
        plaza_core::board_state::member::MemberId::from(&ctx.self_sk.verifying_key()),
        &data.secrets,
        &data.category_secrets,
        &data.old_category_secrets,
    );
    Ok(messages
        .into_iter()
        .filter(|message| !message.is_category)
        .map(|message| (message.title_text, message.content_text))
        .collect())
}

pub async fn restore_item(
    ctx: &ActionContext,
    item: &AuthorizedTrashItem,
    destination: Option<MessageId>,
) -> Result<(), String> {
    let bundle = decrypt_bundle(ctx, item)?;

    let action = AuthorizedTrashAction::new(
        TrashActionV1 {
            item_id: item.item.id,
            kind: TrashActionKind::Restore,
            generation: item.item.generation + 1,
            acted_at: chrono::Utc::now().timestamp(),
            reason: "restored by moderator".to_string(),
            content_hash: None,
        },
        &ctx.self_sk,
    );

    let existing_messages: std::collections::HashSet<_> = ctx
        .board_state
        .recent_messages
        .messages
        .iter()
        .map(|message| message.id())
        .collect();
    let existing_routes: std::collections::HashSet<_> = ctx
        .board_state
        .moderation
        .routes
        .iter()
        .map(|route| route.route.message_id)
        .collect();
    let messages = bundle
        .messages
        .into_iter()
        .filter(|message| !existing_messages.contains(&message.id()))
        .collect();
    let routes = bundle
        .routes
        .into_iter()
        .filter(|route| !existing_routes.contains(&route.route.message_id))
        .collect();
    apply_state_delta(
        ctx,
        ChatBoardStateV1Delta {
            recent_messages: Some(messages),
            moderation: Some(ModerationDelta {
                routes,
                feature_flags: Vec::new(),
                moves: Vec::new(),
                thread_moves: destination
                    .map(|destination| {
                        vec![AuthorizedThreadMove::new(
                            ThreadMoveV1 {
                                topic: item.item.root,
                                from_section: item.item.section,
                                to_section: Some(destination),
                                message_ids: item.item.messages.clone(),
                                generation: 1,
                                moved_at: chrono::Utc::now().timestamp(),
                                leave_redirect: false,
                            },
                            &ctx.self_sk,
                        )]
                    })
                    .unwrap_or_default(),
            }),
            trash: Some(TrashDelta {
                items: Vec::new(),
                actions: vec![action],
            }),
            ..Default::default()
        },
    )
}
