//! Message sending utilities for the UI.

use crate::components::app::notifications::request_permission_on_first_message;
use crate::components::app::{mark_needs_sync, BOARDS};
use crate::util::ecies::encrypt_with_symmetric_key;
use crate::util::get_current_system_time;
use dioxus::logger::tracing::{error, info, warn};
use dioxus::prelude::ReadableExt;
use ed25519_dalek::{SigningKey, VerifyingKey};
use freenet_scaffold::ComposableState;
use plaza_core::board_state::admin::{AdminsDelta, AuthorizedAdminRevocation};
use plaza_core::board_state::category_secrets::CategorySecretsDelta;
use plaza_core::board_state::content::{
    CategoryContentV1, CategoryEditPayload, ReplyContentV1, TextContentV1,
    CATEGORY_CONTENT_VERSION, CONTENT_TYPE_CATEGORY, CONTENT_TYPE_REPLY, CONTENT_TYPE_TEXT,
    REPLY_CONTENT_VERSION, TEXT_CONTENT_VERSION,
};
use plaza_core::board_state::member::MemberId;
use plaza_core::board_state::message::{
    AuthorizedMessageV1, BoardMessageBody, MessageId, MessageV1,
};
use plaza_core::board_state::moderation::{AuthorizedMessageRoute, MessageRoute, ModerationDelta};
use plaza_core::board_state::roles::RoleId;
use plaza_core::board_state::{ChatBoardParametersV1, ChatBoardStateV1, ChatBoardStateV1Delta};
use plaza_core::chat_delegate::BoardKey;

/// Context for a reply message
#[derive(Clone, PartialEq, Debug)]
pub struct ReplyContext {
    pub message_id: MessageId,
    pub author_name: String,
    pub content_preview: String,
}

/// Send a message to a board.
///
/// This handles both regular text messages and replies, as well as
/// encryption for private boards.
pub async fn send_message(
    current_board: VerifyingKey,
    board_key: BoardKey,
    self_sk: SigningKey,
    board_state_clone: ChatBoardStateV1,
    is_private: bool,
    secret_opt: Option<([u8; 32], u32)>,
    // Set when posting inside a restricted category: (category, key, version)
    category_secret: Option<(MessageId, [u8; 32], u32)>,
    category_id: Option<MessageId>,
    title_text: String,
    message_text: String,
    reply_ctx: Option<ReplyContext>,
) {
    if message_text.is_empty() {
        warn!("Message is empty");
        return;
    }

    let max_message_size = board_state_clone
        .configuration
        .configuration
        .max_message_size;

    let reply_target = reply_ctx.as_ref().map(|reply| reply.message_id.clone());

    // Build content based on whether this is a reply or regular message
    let content = if let Some((category_id, secret, version)) = category_secret {
        // Restricted categories seal their posts with their own key, on public
        // boards too: the board key would expose the post to every member.
        let (content_type, content_version, content_bytes) = match reply_ctx {
            Some(reply) => (
                CONTENT_TYPE_REPLY,
                REPLY_CONTENT_VERSION,
                ReplyContentV1::new(
                    title_text.clone(),
                    message_text.clone(),
                    reply.message_id,
                    reply.author_name,
                    reply.content_preview,
                )
                .encode(),
            ),
            None => (
                CONTENT_TYPE_TEXT,
                TEXT_CONTENT_VERSION,
                TextContentV1::new(title_text.clone(), message_text.clone()).encode(),
            ),
        };
        let (ciphertext, nonce) = encrypt_with_symmetric_key(&secret, &content_bytes);
        BoardMessageBody::Private {
            content_type,
            content_version,
            ciphertext,
            nonce,
            secret_version: version,
            secret_scope: plaza_core::board_state::message::SecretScope::Category(category_id),
        }
    } else if let Some(reply) = reply_ctx {
        // Reply message
        if is_private {
            if let Some((secret, version)) = secret_opt {
                let reply_content = ReplyContentV1::new(
                    title_text.clone(),
                    message_text.clone(),
                    reply.message_id,
                    reply.author_name,
                    reply.content_preview,
                );
                let content_bytes = reply_content.encode();
                let (ciphertext, nonce) = encrypt_with_symmetric_key(&secret, &content_bytes);
                BoardMessageBody::private(
                    CONTENT_TYPE_REPLY,
                    REPLY_CONTENT_VERSION,
                    ciphertext,
                    nonce,
                    version,
                )
            } else {
                warn!("Board is private but no secret available, sending reply as public");
                BoardMessageBody::reply(
                    title_text.clone(),
                    message_text.clone(),
                    reply.message_id,
                    reply.author_name,
                    reply.content_preview,
                )
            }
        } else {
            BoardMessageBody::reply(
                title_text.clone(),
                message_text.clone(),
                reply.message_id,
                reply.author_name,
                reply.content_preview,
            )
        }
    } else {
        // Regular text message
        if is_private {
            if let Some((secret, version)) = secret_opt {
                let text_content = TextContentV1::new(title_text.clone(), message_text.clone());
                let content_bytes = text_content.encode();
                let (ciphertext, nonce) = encrypt_with_symmetric_key(&secret, &content_bytes);
                BoardMessageBody::private(
                    CONTENT_TYPE_TEXT,
                    TEXT_CONTENT_VERSION,
                    ciphertext,
                    nonce,
                    version,
                )
            } else {
                warn!("Board is private but no secret available, sending as public");
                BoardMessageBody::public(title_text.clone(), message_text.clone())
            }
        } else {
            BoardMessageBody::public(title_text.clone(), message_text.clone())
        }
    };

    // Safety net: check encoded content size before signing.
    // The input UI blocks sending when text is over limit, but
    // encoded size can differ slightly from raw text length.
    let content_size = content.content_len();
    if content_size > max_message_size {
        warn!(
            "Message too long: {} encoded bytes, max {} bytes",
            content_size, max_message_size
        );
        return;
    }

    let message = MessageV1 {
        board_owner: MemberId::from(current_board),
        author: MemberId::from(&self_sk.verifying_key()),
        content,
        time: get_current_system_time(),
    };

    // Serialize message to CBOR for signing
    let mut message_bytes = Vec::new();
    if let Err(e) = ciborium::ser::into_writer(&message, &mut message_bytes) {
        error!("Failed to serialize message for signing: {:?}", e);
        return;
    }

    // Sign using delegate with fallback to local signing
    let signature =
        crate::signing::sign_message_with_fallback(board_key, message_bytes, &self_sk).await;

    let auth_message = AuthorizedMessageV1::with_signature(message, signature);

    // Check if we need to re-add ourselves (pruned for inactivity)
    let (members_delta, member_info_delta) = {
        let boards_read = BOARDS.read();
        if let Some(board_data) = boards_read.map.get(&current_board) {
            let self_vk = board_data.self_sk.verifying_key();
            let is_in_members = self_vk == current_board
                || board_data
                    .board_state
                    .members
                    .members
                    .iter()
                    .any(|m| m.member.member_vk == self_vk);

            if !is_in_members {
                if let Some(ref authorized_member) = board_data.self_authorized_member {
                    let current_member_ids: std::collections::HashSet<_> = board_data
                        .board_state
                        .members
                        .members
                        .iter()
                        .map(|m| m.member.id())
                        .collect();
                    let mut members_to_add: Vec<plaza_core::board_state::member::AuthorizedMember> =
                        vec![authorized_member.clone()];
                    for chain_member in &board_data.invite_chain {
                        if !current_member_ids.contains(&chain_member.member.id()) {
                            members_to_add.push(chain_member.clone());
                        }
                    }

                    // Use stored member_info to preserve nickname, or fall back to "Member"
                    use plaza_core::board_state::member_info::{AuthorizedMemberInfo, MemberInfo};
                    let authorized_info: AuthorizedMemberInfo = if let Some(ref stored_info) =
                        board_data.self_member_info
                    {
                        stored_info.clone()
                    } else {
                        use plaza_core::board_state::privacy::SealedBytes;
                        let member_id = MemberId::from(&self_vk);
                        let existing_version = board_data
                            .board_state
                            .member_info
                            .member_info
                            .iter()
                            .find(|i| i.member_info.member_id == member_id)
                            .map(|i| i.member_info.version)
                            .unwrap_or(0);
                        let member_info = MemberInfo {
                            member_id,
                            version: existing_version,
                            preferred_nickname: SealedBytes::public(
                                "Member".to_string().into_bytes(),
                            ),
                        };
                        AuthorizedMemberInfo::new_with_member_key(member_info, &board_data.self_sk)
                    };

                    (
                        Some(plaza_core::board_state::member::MembersDelta::new(
                            members_to_add,
                        )),
                        Some(vec![authorized_info]),
                    )
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            }
        } else {
            (None, None)
        }
    };

    let route = AuthorizedMessageRoute::new(
        MessageRoute {
            message_id: auth_message.id(),
            reply_to: reply_target,
            category_id,
            is_category: false,
            parent_category_id: None,
            is_group: false,
            generation: 1,
        },
        &self_sk,
    );
    let delta = ChatBoardStateV1Delta {
        recent_messages: Some(vec![auth_message.clone()]),
        members: members_delta,
        member_info: member_info_delta,
        moderation: Some(ModerationDelta {
            routes: vec![route],
            flags: Vec::new(),
        }),
        ..Default::default()
    };

    info!("Sending message: {:?}", auth_message);

    BOARDS.with_mut(|boards| {
        if let Some(board_data) = boards.map.get_mut(&current_board) {
            if let Err(e) = board_data.board_state.apply_delta(
                &board_state_clone,
                &ChatBoardParametersV1 {
                    owner: current_board,
                },
                &Some(delta),
            ) {
                error!("Failed to apply message delta: {:?}", e);
            } else {
                // Mark board as needing sync after message added (deferred to avoid RefCell panics)
                mark_needs_sync(current_board);

                // Request notification permission on first message
                request_permission_on_first_message();
            }
        }
    });
}

/// Remove an admin's rights.
///
/// Only the board owner can do this: the revocation is signed with the owner's
/// key and is permanent for that member.
pub async fn revoke_admin(member_id: MemberId) -> Result<(), String> {
    use crate::components::app::CURRENT_BOARD;

    let (current_board, owner_sk, board_state_clone, generation) = {
        let current_board_read = CURRENT_BOARD.read();
        let boards_read = BOARDS.read();

        let current_board = current_board_read.owner_key.ok_or("No board selected")?;
        let board_data = boards_read
            .map
            .get(&current_board)
            .ok_or("Board not found")?;

        let self_id = MemberId::from(&board_data.self_sk.verifying_key());
        if self_id != MemberId::from(current_board) {
            return Err("Only the board owner can remove an admin".to_string());
        }

        (
            current_board,
            board_data.self_sk.clone(),
            board_data.board_state.clone(),
            board_data.board_state.admin.next_generation(&member_id),
        )
    };

    let revocation = AuthorizedAdminRevocation::new(member_id, generation, &owner_sk);
    let delta = ChatBoardStateV1Delta {
        admin: Some(AdminsDelta::revocation(vec![revocation])),
        ..Default::default()
    };

    let mut apply_error: Option<String> = None;
    BOARDS.with_mut(|boards| {
        if let Some(board_data) = boards.map.get_mut(&current_board) {
            match board_data.board_state.apply_delta(
                &board_state_clone,
                &ChatBoardParametersV1 {
                    owner: current_board,
                },
                &Some(delta),
            ) {
                Ok(_) => mark_needs_sync(current_board),
                Err(e) => apply_error = Some(e),
            }
        }
    });

    match apply_error {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Send a category message to the current board.
///
/// Only board owners and admins can create categories. Restricted categories
/// (a non-empty `restricted_roles`) can only be created by the owner, because
/// the per-category secret records must be signed with the owner key.
pub async fn send_category(
    name: String,
    description: Option<String>,
    icon: Option<String>,
    color: String,
    parent_category_id: Option<MessageId>,
    restricted_roles: Vec<RoleId>,
    hidden: bool,
) -> Result<(), String> {
    use crate::components::app::CURRENT_BOARD;

    // Get required board data
    let (current_board, board_key, self_sk, can_create, secret_opt, board_snapshot) = {
        let current_board_read = CURRENT_BOARD.read();
        let boards_read = BOARDS.read();

        let current_board = current_board_read.owner_key.ok_or("No board selected")?;

        let board_data = boards_read
            .map
            .get(&current_board)
            .ok_or("Board not found")?;

        let can_create = board_data.can_create_categories();

        // Categories live in the message log, so on a private board they have to
        // be sealed like any other content.
        let secret_opt = if board_data.is_private() {
            board_data
                .secrets
                .iter()
                .max_by_key(|(version, _)| *version)
                .map(|(version, secret)| (*secret, *version))
        } else {
            None
        };

        (
            current_board,
            board_data.board_key(),
            board_data.self_sk.clone(),
            can_create,
            secret_opt,
            board_data.clone(),
        )
    };

    if !can_create {
        return Err("Only board owners and admins can create categories".to_string());
    }
    if !restricted_roles.is_empty() && self_sk.verifying_key() != current_board {
        return Err("Only the board owner can create restricted categories".to_string());
    }

    let parent_for_route = parent_category_id.clone();
    let mut category = CategoryContentV1::new(name.clone(), description, color);
    if let Some(i) = icon {
        category = category.with_icon(i);
    }
    if let Some(p) = parent_category_id {
        category = category.with_parent(p);
    }

    // A restricted category gets its own key. The real name is sealed with it
    // and the public name becomes a placeholder, so listing a category does not
    // reveal the name to members outside its roles.
    let category_secret = if restricted_roles.is_empty() {
        None
    } else {
        let secret = crate::util::ecies::generate_board_secret();
        let sealed_name = crate::util::ecies::seal_bytes(name.as_bytes(), &secret, 0);
        category = category.with_allowed_roles(restricted_roles, sealed_name, hidden);
        category.name = CategoryEditPayload::placeholder_name(hidden);
        Some((secret, 0u32))
    };

    // On a private board the whole category is sealed with the board key as
    // well; the contract rejects public messages there.
    let content = match secret_opt {
        Some((secret, version)) => {
            let (ciphertext, nonce) = encrypt_with_symmetric_key(&secret, &category.encode());
            BoardMessageBody::Private {
                content_type: CONTENT_TYPE_CATEGORY,
                content_version: CATEGORY_CONTENT_VERSION,
                ciphertext,
                nonce,
                secret_version: version,
                secret_scope: plaza_core::board_state::message::SecretScope::Board,
            }
        }
        None => BoardMessageBody::public_raw(
            CONTENT_TYPE_CATEGORY,
            CATEGORY_CONTENT_VERSION,
            category.encode(),
        ),
    };

    let message = MessageV1 {
        board_owner: MemberId::from(current_board),
        author: MemberId::from(&self_sk.verifying_key()),
        content,
        time: get_current_system_time(),
    };

    // Serialize message to CBOR for signing
    let mut message_bytes = Vec::new();
    ciborium::ser::into_writer(&message, &mut message_bytes)
        .map_err(|e| format!("Failed to serialize message: {:?}", e))?;

    // Sign using delegate with fallback to local signing
    let signature =
        crate::signing::sign_message_with_fallback(board_key, message_bytes, &self_sk).await;

    let auth_message = AuthorizedMessageV1::with_signature(message, signature);
    let category_id = auth_message.id();

    // Distribute the new key to the owner and to every member of the chosen
    // roles. Members of the roles join later get their blob from
    // `distribute_missing_category_secrets`.
    let category_secrets = category_secret.map(|(secret, version)| {
        let readers = board_snapshot.category_readers(&category);
        CategorySecretsDelta {
            sets: vec![board_snapshot.new_category_secret_set(
                &category_id,
                &secret,
                version,
                &readers,
            )],
        }
    });

    let route = AuthorizedMessageRoute::new(
        MessageRoute {
            message_id: auth_message.id(),
            reply_to: None,
            category_id: Some(auth_message.id()),
            is_category: true,
            parent_category_id: parent_for_route,
            is_group: false,
            generation: 1,
        },
        &self_sk,
    );
    let delta = ChatBoardStateV1Delta {
        recent_messages: Some(vec![auth_message.clone()]),
        category_secrets,
        moderation: Some(ModerationDelta {
            routes: vec![route],
            flags: Vec::new(),
        }),
        ..Default::default()
    };

    info!("Creating category: {:?}", auth_message);

    // Apply the delta. Report the failure to the caller instead of closing the
    // modal as if the category had been created.
    let mut apply_error: Option<String> = None;
    BOARDS.with_mut(|boards| {
        if let Some(board_data) = boards.map.get_mut(&current_board) {
            let state_before = board_data.board_state.clone();
            if let Err(e) = board_data.board_state.apply_delta(
                &state_before,
                &ChatBoardParametersV1 {
                    owner: current_board,
                },
                &Some(delta),
            ) {
                error!("Failed to apply category delta: {:?}", e);
                apply_error = Some(e);
            } else {
                // The owner holds the new key; cache it for immediate use.
                board_data.decrypt_category_secrets();
                // Mark board as needing sync
                mark_needs_sync(current_board);
            }
        }
    });

    if let Some(e) = apply_error {
        return Err(e);
    }

    Ok(())
}

/// Create a homepage group. Groups contain sections and have no posts.
pub async fn send_group(
    name: String,
    description: Option<String>,
    icon: Option<String>,
    color: String,
) -> Result<(), String> {
    use crate::components::app::CURRENT_BOARD;

    let (current_board, board_key, self_sk, can_create, secret_opt) = {
        let current_board_read = CURRENT_BOARD.read();
        let boards_read = BOARDS.read();
        let current_board = current_board_read.owner_key.ok_or("No board selected")?;
        let board_data = boards_read
            .map
            .get(&current_board)
            .ok_or("Board not found")?;
        let can_create = board_data.can_create_categories();
        let secret_opt = if board_data.is_private() {
            board_data
                .secrets
                .iter()
                .max_by_key(|(version, _)| *version)
                .map(|(version, secret)| (*secret, *version))
        } else {
            None
        };
        (
            current_board,
            board_data.board_key(),
            board_data.self_sk.clone(),
            can_create,
            secret_opt,
        )
    };

    if !can_create {
        return Err("Only board owners and admins can create groups".to_string());
    }

    let mut group = CategoryContentV1::new(name, description, color);
    if let Some(icon) = icon {
        group = group.with_icon(icon);
    }
    group = group.with_group();

    let content = match secret_opt {
        Some((secret, version)) => {
            let (ciphertext, nonce) = encrypt_with_symmetric_key(&secret, &group.encode());
            BoardMessageBody::Private {
                content_type: CONTENT_TYPE_CATEGORY,
                content_version: CATEGORY_CONTENT_VERSION,
                ciphertext,
                nonce,
                secret_version: version,
                secret_scope: plaza_core::board_state::message::SecretScope::Board,
            }
        }
        None => BoardMessageBody::public_raw(
            CONTENT_TYPE_CATEGORY,
            CATEGORY_CONTENT_VERSION,
            group.encode(),
        ),
    };

    let message = MessageV1 {
        board_owner: MemberId::from(current_board),
        author: MemberId::from(&self_sk.verifying_key()),
        content,
        time: get_current_system_time(),
    };
    let mut message_bytes = Vec::new();
    ciborium::ser::into_writer(&message, &mut message_bytes)
        .map_err(|e| format!("Failed to serialize message: {:?}", e))?;
    let signature =
        crate::signing::sign_message_with_fallback(board_key, message_bytes, &self_sk).await;
    let auth_message = AuthorizedMessageV1::with_signature(message, signature);

    let route = AuthorizedMessageRoute::new(
        MessageRoute {
            message_id: auth_message.id(),
            reply_to: None,
            category_id: Some(auth_message.id()),
            is_category: true,
            parent_category_id: None,
            is_group: true,
            generation: 1,
        },
        &self_sk,
    );
    let delta = ChatBoardStateV1Delta {
        recent_messages: Some(vec![auth_message]),
        moderation: Some(ModerationDelta {
            routes: vec![route],
            flags: Vec::new(),
        }),
        ..Default::default()
    };

    let mut apply_error: Option<String> = None;
    BOARDS.with_mut(|boards| {
        if let Some(board_data) = boards.map.get_mut(&current_board) {
            let state_before = board_data.board_state.clone();
            if let Err(e) = board_data.board_state.apply_delta(
                &state_before,
                &ChatBoardParametersV1 {
                    owner: current_board,
                },
                &Some(delta),
            ) {
                apply_error = Some(e);
            } else {
                mark_needs_sync(current_board);
            }
        }
    });
    match apply_error {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Hand per-category secrets to members who are now in an allowed role.
///
/// Only the owner signs these records, so this is a no-op on other clients.
/// Returns true when a delta was applied and should be pushed to the network.
pub fn distribute_category_secrets(owner: VerifyingKey) -> bool {
    let mut distributed = false;
    BOARDS.with_mut(|boards| {
        let Some(board_data) = boards.map.get_mut(&owner) else {
            return;
        };
        let Some(delta) = board_data.generate_missing_category_secrets() else {
            return;
        };
        let state_before = board_data.board_state.clone();
        let params = ChatBoardParametersV1 { owner };
        match board_data.board_state.apply_delta(
            &state_before,
            &params,
            &Some(ChatBoardStateV1Delta {
                category_secrets: Some(delta),
                ..Default::default()
            }),
        ) {
            Ok(_) => {
                info!("Distributed category secrets to new members");
                board_data.decrypt_category_secrets();
                mark_needs_sync(owner);
                distributed = true;
            }
            Err(e) => error!("Failed to distribute category secrets: {}", e),
        }
    });
    distributed
}
