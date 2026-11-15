//! Client side of the hide flow: build the encrypted bundle, add the trash
//! item, and let the normal message filter hide it.

use crate::util::ecies::{decrypt_with_symmetric_key, encrypt_with_symmetric_key};
use crate::util::message_actions::{apply_state_delta, ActionContext};
use dioxus::prelude::*;
use plaza_core::board_state::message::{
    AuthorizedMessageV1, BoardMessageBody, MessageId, MessageV1,
};
use plaza_core::board_state::moderation::{
    category_chain, AuthorizedMessageRoute, AuthorizedThreadMove, MessageRoute, ModerationDelta,
    ThreadMoveV1,
};
use plaza_core::board_state::trash::{
    AuthorizedTrashAction, AuthorizedTrashItem, ReasonCode, TrashActionKind, TrashActionV1,
    TrashDelta, TrashItemV1,
};
use plaza_core::board_state::ChatBoardStateV1Delta;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub(crate) struct TrashBundleV1 {
    messages: Vec<plaza_core::board_state::message::AuthorizedMessageV1>,
    routes: Vec<plaza_core::board_state::moderation::AuthorizedMessageRoute>,
}

pub async fn hide_topic(
    ctx: &ActionContext,
    root: MessageId,
    reason: &str,
    code: ReasonCode,
) -> Result<(), String> {
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
            )
            .with_optional_authority(trash_authority(ctx));
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
        reason_code: code,
        reason: reason.to_string(),
        generation: 1,
    };
    item.id = item.compute_id();
    let authorized = AuthorizedTrashItem::new(item, &ctx.self_sk)
        .with_optional_authority(trash_authority(ctx));

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
            reason_code: ReasonCode::Other,
            reason: "restored by moderator".to_string(),
            content_hash: None,
        },
        &ctx.self_sk,
    )
    .with_optional_authority(trash_authority(ctx));

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
                illegal_purges: Vec::new(),
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

pub async fn purge_item(
    ctx: &ActionContext,
    item: &AuthorizedTrashItem,
    reason: &str,
    code: ReasonCode,
) -> Result<(), String> {
    // Keep only a hash of the decrypted bundle in the audit. If the admin has
    // no trash key, the purge still proceeds with no content hash.
    let content_hash = preview_bundle_bytes(ctx, item)
        .ok()
        .map(|bytes| *blake3::hash(&bytes).as_bytes());
    let action = AuthorizedTrashAction::new(
        TrashActionV1 {
            item_id: item.item.id,
            kind: TrashActionKind::Purge,
            reason_code: code,
            generation: item.item.generation + 1,
            acted_at: chrono::Utc::now().timestamp(),
            reason: reason.to_string(),
            content_hash,
        },
        &ctx.self_sk,
    )
    .with_optional_authority(trash_authority(ctx));
    apply_state_delta(
        ctx,
        ChatBoardStateV1Delta {
            trash: Some(TrashDelta {
                items: Vec::new(),
                actions: vec![action],
            }),
            ..Default::default()
        },
    )
}

fn preview_bundle_bytes(
    ctx: &ActionContext,
    item: &AuthorizedTrashItem,
) -> Result<Vec<u8>, String> {
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
    decrypt_with_symmetric_key(&item_key, &item.item.bundle, &item.item.bundle_nonce, 0)
}

pub async fn purge_illegal(
    ctx: &ActionContext,
    topic: MessageId,
    reason: &str,
    code: ReasonCode,
) -> Result<(), String> {
    log_debug(&format!(
        "purge_illegal start topic={topic} reason={reason}"
    ));
    let messages = ctx
        .board_state
        .recent_messages
        .messages
        .iter()
        .filter(|message| message.id() == topic)
        .cloned()
        .collect::<Vec<_>>();
    let mut plaintext = Vec::new();
    ciborium::ser::into_writer(&messages, &mut plaintext)
        .map_err(|error| format!("Could not encode the purge audit: {error}"))?;
    let content_hash = *blake3::hash(&plaintext).as_bytes();
    log_debug("purge: messages collected and hashed");
    *crate::components::app::PURGE_STEP.write() = "messages".to_string();

    let descendants = {
        let routes = ctx.board_state.moderation.routes_map();
        let mut ids = Vec::new();
        let mut stack = vec![topic];
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
        ids
    };

    log_debug(&format!("purge: descendants={}", descendants.len()));
    *crate::components::app::PURGE_STEP.write() = "descendants".to_string();
    let entry = plaza_core::board_state::moderation::AuthorizedIllegalPurge::new(
        plaza_core::board_state::moderation::IllegalPurgeV1 {
            topic,
            message_ids: descendants,
            reason_code: code,
            reason: reason.to_string(),
            content_hash: Some(content_hash),
            acted_at: chrono::Utc::now().timestamp(),
            generation: 1,
        },
        &ctx.self_sk,
    );
    if reason == "debug purge" {
        return apply_state_delta(
            ctx,
            ChatBoardStateV1Delta {
                moderation: Some(ModerationDelta {
                    routes: Vec::new(),
                    feature_flags: Vec::new(),
                    moves: Vec::new(),
                    thread_moves: Vec::new(),
                    illegal_purges: vec![entry],
                }),
                ..Default::default()
            },
        );
    }
    log_debug("purge: building replacement");
    *crate::components::app::PURGE_STEP.write() = "replacement-build".to_string();
    *crate::components::app::PURGE_STEP.write() = "entry".to_string();
    let self_id = plaza_core::board_state::member::MemberId::from(&ctx.self_sk.verifying_key());
    let owner_id = plaza_core::board_state::member::MemberId::from(&ctx.current_board);
    let topic_author = ctx
        .board_state
        .recent_messages
        .messages
        .iter()
        .find(|message| message.id() == topic)
        .map(|message| message.message.author);

    // Replacement topic, public or sealed with the section/board key.
    let section = ctx
        .board_state
        .moderation
        .routes_map()
        .get(&topic)
        .and_then(|route| route.category_id);
    let mut messages = Vec::new();
    let mut routes = Vec::new();
    {
        use plaza_core::board_state::content::{
            TextContentV1, CONTENT_TYPE_TEXT, TEXT_CONTENT_VERSION,
        };
        use plaza_core::board_state::message::SecretScope;

        let title = "Contenuto rimosso".to_string();
        let text =
            "Il topic originale è stato rimosso dai moderatori per contenuto illegale.".to_string();

        let content = if reason == "debug replacement" {
            BoardMessageBody::public(title.clone(), text.clone())
        } else if let Some(section) = section {
            if let Some((version, key)) = ctx.category_secrets.get(&section).copied() {
                let (ciphertext, nonce) = encrypt_with_symmetric_key(
                    &key,
                    &TextContentV1::new(title.clone(), text.clone()).encode(),
                    version,
                );
                BoardMessageBody::Private {
                    content_type: CONTENT_TYPE_TEXT,
                    content_version: TEXT_CONTENT_VERSION,
                    ciphertext,
                    nonce,
                    secret_version: version,
                    secret_scope: SecretScope::Category(section),
                }
            } else {
                public_replacement_body(title, text)
            }
        } else if let Some(key) = ctx
            .board_secrets
            .get(&ctx.board_state.secrets.current_version)
        {
            let version = ctx.board_state.secrets.current_version;
            let (ciphertext, nonce) = encrypt_with_symmetric_key(
                key,
                &TextContentV1::new(title.clone(), text.clone()).encode(),
                version,
            );
            BoardMessageBody::private(
                CONTENT_TYPE_TEXT,
                TEXT_CONTENT_VERSION,
                ciphertext,
                nonce,
                version,
            )
        } else {
            public_replacement_body(title, text)
        };

        *crate::components::app::PURGE_STEP.write() = "replacement-content".to_string();
        let message = MessageV1 {
            board_owner: owner_id,
            author: self_id,
            time: chrono::Utc::now().into(),
            content,
        };
        // In debug mode skip signing entirely: a dummy signature lets us see
        // whether `AuthorizedMessageV1::new` is the call that blocks.
        let replacement = if reason == "debug replacement" {
            AuthorizedMessageV1::with_signature(
                message,
                ed25519_dalek::Signature::from_bytes(&[0u8; 64]),
            )
        } else {
            AuthorizedMessageV1::new(message, &ctx.self_sk)
        };
        *crate::components::app::PURGE_STEP.write() = "replacement-message".to_string();
        let replacement_id = replacement.id();
        *crate::components::app::PURGE_STEP.write() = "replacement-id".to_string();
        *crate::components::app::PURGE_STEP.write() = "replacement-route".to_string();
        routes.push(AuthorizedMessageRoute::new(
            MessageRoute {
                message_id: replacement_id,
                reply_to: None,
                category_id: section,
                is_category: false,
                parent_category_id: None,
                is_group: false,
                generation: 1,
            },
            &ctx.self_sk,
        ));
        messages.push(replacement);
        *crate::components::app::PURGE_STEP.write() = "replacement-pushed".to_string();
    }

    log_debug("purge: replacement built, building ban");
    *crate::components::app::PURGE_STEP.write() = "replacement".to_string();
    if reason == "debug replacement" {
        return apply_state_delta(
            ctx,
            ChatBoardStateV1Delta {
                recent_messages: Some(messages),
                moderation: Some(ModerationDelta {
                    routes,
                    feature_flags: Vec::new(),
                    moves: Vec::new(),
                    thread_moves: Vec::new(),
                    illegal_purges: vec![entry],
                }),
                ..Default::default()
            },
        );
    }
    *crate::components::app::PURGE_STEP.write() = "ban-build".to_string();
    // Ban the author when they are a regular member or admin, never the owner.
    let mut bans = Vec::new();
    if let Some(author) = topic_author {
        if author != owner_id && author != self_id {
            if let Some(target) = ctx
                .board_state
                .members
                .members
                .iter()
                .find(|member| member.member.id() == author)
                .cloned()
            {
                let mut chain = Vec::new();
                let mut inviter = target.member.invited_by;
                let mut guard = 0;
                while inviter != owner_id && guard < 64 {
                    guard += 1;
                    let Some(member) = ctx
                        .board_state
                        .members
                        .members
                        .iter()
                        .find(|member| member.member.id() == inviter)
                        .cloned()
                    else {
                        break;
                    };
                    inviter = member.member.invited_by;
                    chain.push(member);
                }
                let ban = plaza_core::board_state::ban::UserBan {
                    owner_member_id: owner_id,
                    banned_at: chrono::Utc::now().into(),
                    banned_user: author,
                    expires_at: None,
                    target_member: Some(target),
                    invite_chain: chain,
                };
                bans.push(plaza_core::board_state::ban::AuthorizedUserBan::new(
                    ban,
                    self_id,
                    &ctx.self_sk,
                ));
            }
        }
    }

    // Three separate updates so a rejection in the replacement or the ban
    // does not hide which part failed.
    log_debug("purge: ban built, phase 1");
    *crate::components::app::PURGE_STEP.write() = "ban".to_string();
    log_debug("purge phase 1: illegal purge record");
    apply_state_delta(
        ctx,
        ChatBoardStateV1Delta {
            moderation: Some(ModerationDelta {
                routes: Vec::new(),
                feature_flags: Vec::new(),
                moves: Vec::new(),
                thread_moves: Vec::new(),
                illegal_purges: vec![entry],
            }),
            ..Default::default()
        },
    )
    .map_err(|error| format!("Purge record rejected: {error}"))?;

    log_debug(&format!(
        "purge phase 1 ok, replacement messages={}",
        messages.len()
    ));
    if !messages.is_empty() || !routes.is_empty() {
        let ctx =
            ActionContext::from_current_board().ok_or("Board context is gone after the purge")?;
        apply_state_delta(
            &ctx,
            ChatBoardStateV1Delta {
                recent_messages: Some(messages),
                moderation: Some(ModerationDelta {
                    routes,
                    feature_flags: Vec::new(),
                    moves: Vec::new(),
                    thread_moves: Vec::new(),
                    illegal_purges: Vec::new(),
                }),
                ..Default::default()
            },
        )
        .map_err(|error| format!("Replacement topic rejected: {error}"))?;
    }

    log_debug("purge phase 2 ok, applying ban");
    *crate::components::app::PURGE_STEP.write() = "phase2-ok".to_string();
    if !bans.is_empty() {
        let ctx =
            ActionContext::from_current_board().ok_or("Board context is gone after the purge")?;
        apply_state_delta(
            &ctx,
            ChatBoardStateV1Delta {
                bans: Some(bans),
                ..Default::default()
            },
        )
        .map_err(|error| format!("Author ban rejected: {error}"))?;
    }
    log_debug("purge completed");
    *crate::components::app::PURGE_STEP.write() = "done".to_string();
    Ok(())
}

fn log_debug(message: &str) {
    web_sys::console::log_1(&message.into());
}

pub fn parse_reason_code(code: &str) -> ReasonCode {
    match code {
        "severe" | "illegal" => ReasonCode::Severe,
        "spam" => ReasonCode::Spam,
        "harassment" => ReasonCode::Harassment,
        "off_topic" => ReasonCode::OffTopic,
        "rules" => ReasonCode::Rules,
        _ => ReasonCode::Other,
    }
}

pub async fn grant_trash_access(
    ctx: &ActionContext,
    member: plaza_core::board_state::member::MemberId,
) -> Result<(), String> {
    use plaza_core::board_state::pq_secrets::{
        AuthorizedPqSecretSet, PqScope, PqSecretSet, PqSecretsDelta,
    };

    let (secret_version, trash_key) = ctx.trash_secret.ok_or("You do not have the trash key")?;
    let kem = ctx
        .board_state
        .pq_secrets
        .key_for(member)
        .ok_or("That member has no PQ key yet; they must open the board first")?;
    let owner_id = plaza_core::board_state::member::MemberId::from(&ctx.current_board);
    let vk = if member == owner_id {
        ctx.current_board
    } else {
        ctx.board_state
            .members
            .members
            .iter()
            .find(|entry| entry.member.id() == member)
            .map(|entry| entry.member.member_vk)
            .ok_or("That member is not in the member list")?
    };
    let sealed = crate::util::pq::seal_secret(&trash_key, &kem.ek, member, &vk)
        .map_err(|error| format!("Could not seal the trash key: {error}"))?;

    let latest = ctx
        .board_state
        .pq_secrets
        .sets
        .iter()
        .filter(|entry| matches!(entry.set.scope, PqScope::Trash))
        .max_by_key(|entry| entry.set.version);
    let mut secrets = latest
        .map(|entry| entry.set.secrets.clone())
        .unwrap_or_default();
    secrets.retain(|entry| entry.member_id != member);
    secrets.push(sealed);
    let version = latest.map(|entry| entry.set.version).unwrap_or(0) + 1;
    let set = AuthorizedPqSecretSet::new(
        PqSecretSet {
            scope: PqScope::Trash,
            version,
            secret_version,
            secrets,
        },
        &ctx.self_sk,
    )
    .with_optional_authority(trash_authority(ctx));
    apply_state_delta(
        ctx,
        ChatBoardStateV1Delta {
            pq_secrets: Some(PqSecretsDelta {
                keys: Vec::new(),
                sets: vec![set],
            }),
            ..Default::default()
        },
    )
}

/// Remove a member from the trash key set. This stops future distribution only:
/// a member who already decrypted the key keeps it until the key is rotated.
pub async fn revoke_trash_access(
    ctx: &ActionContext,
    member: plaza_core::board_state::member::MemberId,
) -> Result<(), String> {
    use plaza_core::board_state::pq_secrets::{
        AuthorizedPqSecretSet, PqScope, PqSecretSet, PqSecretsDelta,
    };

    let owner_id = plaza_core::board_state::member::MemberId::from(&ctx.current_board);
    if member == owner_id {
        return Err("The owner always keeps the trash key".to_string());
    }
    let (_, _) = ctx.trash_secret.ok_or("You do not have the trash key")?;
    let latest = ctx
        .board_state
        .pq_secrets
        .sets
        .iter()
        .filter(|entry| matches!(entry.set.scope, PqScope::Trash))
        .max_by_key(|entry| entry.set.version)
        .ok_or("This board has no trash key yet")?;
    let mut secrets = latest.set.secrets.clone();
    let before = secrets.len();
    secrets.retain(|entry| entry.member_id != member);
    if secrets.len() == before {
        return Err("That member does not have the trash key".to_string());
    }
    let set = AuthorizedPqSecretSet::new(
        PqSecretSet {
            scope: PqScope::Trash,
            version: latest.set.version + 1,
            secret_version: latest.set.secret_version,
            secrets,
        },
        &ctx.self_sk,
    )
    .with_optional_authority(trash_authority(ctx));
    apply_state_delta(
        ctx,
        ChatBoardStateV1Delta {
            pq_secrets: Some(PqSecretsDelta {
                keys: Vec::new(),
                sets: vec![set],
            }),
            ..Default::default()
        },
    )
}

fn public_replacement_body(title: String, text: String) -> BoardMessageBody {
    BoardMessageBody::public(title, text)
}

/// Authority the current signer holds for a Trash set. Keeping the admin record
/// or the role grant in the set lets it verify after the signer loses the role.
fn trash_authority(
    ctx: &ActionContext,
) -> Option<plaza_core::board_state::roles::AuthorityProof> {
    use plaza_core::board_state::roles::{admin_authority_proof, trash_authority_proof};
    let signer = plaza_core::board_state::member::MemberId::from(&ctx.self_sk.verifying_key());
    admin_authority_proof(&ctx.board_state, &signer)
        .or_else(|| trash_authority_proof(&ctx.board_state, &signer))
}

/// Native fallback used while the custom modal has an event-handling issue.
pub fn ask_reason(default: &str) -> Option<(ReasonCode, String)> {
    let window = web_sys::window()?;
    let text = window
        .prompt_with_message(&format!(
            "Reason (severe = severe rule violation, spam, harassment, off_topic, rules). Add details after the code. Default: {default}"
        ))
        .ok()
        .flatten()?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_lowercase();
    let code = if lower.starts_with("severe") || lower.starts_with("illegal") {
        ReasonCode::Severe
    } else if lower.starts_with("spam") {
        ReasonCode::Spam
    } else if lower.starts_with("harassment") {
        ReasonCode::Harassment
    } else if lower.starts_with("off_topic") || lower.starts_with("off-topic") {
        ReasonCode::OffTopic
    } else if lower.starts_with("rules") {
        ReasonCode::Rules
    } else {
        ReasonCode::Other
    };
    Some((code, trimmed.to_string()))
}

pub fn ask_confirmation_word(word: &str) -> bool {
    web_sys::window()
        .and_then(|window| {
            window
                .prompt_with_message(&format!("Type {word} to confirm this action."))
                .ok()
                .flatten()
        })
        .map(|value| value.trim() == word)
        .unwrap_or(false)
}

/// Run work after the current event handler returns. Native dialogs block the
/// Dioxus handler; scheduling on the next tick lets the async action start.
pub fn run_later<F: FnOnce() + 'static>(work: F) {
    use wasm_bindgen::JsCast;
    let callback =
        wasm_bindgen::closure::Closure::once_into_js(Box::new(work) as Box<dyn FnOnce()>);
    if let Some(window) = web_sys::window() {
        let _ = window
            .set_timeout_with_callback_and_timeout_and_arguments_0(callback.unchecked_ref(), 0);
    }
}
