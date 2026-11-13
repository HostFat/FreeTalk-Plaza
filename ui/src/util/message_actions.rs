//! Shared message action handlers for reactions, edits, and deletions.

use crate::components::app::{mark_needs_sync, BOARDS};
use crate::util::ecies::encrypt_with_symmetric_key;
use crate::util::ecies::seal_bytes;
use crate::util::ecies::unseal_bytes;
use crate::util::get_current_system_time;
use dioxus::prelude::*;
use ed25519_dalek::{SigningKey, VerifyingKey};
use freenet_scaffold::ComposableState;
use plaza_core::board_state::content::{
    ActionContentV1, CategoryContentV1, CategoryEditPayload, ModerationActionV1, ReplyContentV1,
    ACTION_CONTENT_VERSION, CONTENT_TYPE_ACTION, CONTENT_TYPE_MODERATION_ACTION,
    CONTENT_TYPE_REPLY, REPLY_CONTENT_VERSION,
};
use plaza_core::board_state::member::MemberId;
use plaza_core::board_state::message::{
    AuthorizedMessageV1, BoardMessageBody, MessageId, MessageV1, SecretScope,
};
use plaza_core::board_state::moderation::{
    category_chain, AuthorizedFeatureFlag, AuthorizedPostMove, FeatureFlag, FeatureKind,
    ModerationDelta, PostMove,
};
use plaza_core::board_state::privacy::SealedBytes;
use plaza_core::board_state::roles::{
    admin_authority_proof, moderation_authority_proof, AuthorityProof, ModerationPower,
};
use plaza_core::board_state::{ChatBoardParametersV1, ChatBoardStateV1, ChatBoardStateV1Delta};
use plaza_core::chat_delegate::BoardKey;

/// Parameters needed for message actions
#[derive(Clone)]
pub struct ActionContext {
    pub current_board: VerifyingKey,
    pub board_key: BoardKey,
    pub self_sk: SigningKey,
    pub board_state: ChatBoardStateV1,
    pub is_private: bool,
    pub secret_opt: Option<([u8; 32], u32)>,
    pub board_secrets: std::collections::HashMap<u32, [u8; 32]>,
    pub category_secrets: std::collections::HashMap<MessageId, (u32, [u8; 32])>,
    pub old_category_secrets:
        std::collections::HashMap<MessageId, std::collections::HashMap<u32, [u8; 32]>>,
}

impl ActionContext {
    /// Create an ActionContext from the current board data, if available
    pub fn from_current_board() -> Option<Self> {
        use crate::components::app::CURRENT_BOARD;

        let current_board = CURRENT_BOARD.read();
        if let Some(key) = current_board.owner_key {
            let boards = BOARDS.read();
            if let Some(board_data) = boards.map.get(&key) {
                // One gate for every action: banned, suspended and non-member
                // identities get no context, so no action can be sent.
                board_data.ensure_can_write().ok()?;
                return Some(Self {
                    current_board: key,
                    board_key: board_data.board_key(),
                    self_sk: board_data.self_sk.clone(),
                    board_state: board_data.board_state.clone(),
                    is_private: board_data.is_private(),
                    secret_opt: board_data.get_secret().map(|(s, v)| (*s, v)),
                    board_secrets: board_data.secrets.clone(),
                    category_secrets: board_data.category_secrets.clone(),
                    old_category_secrets: board_data.old_category_secrets.clone(),
                });
            }
        }
        None
    }

    /// Category content of a message, opened with whichever key sealed it.
    fn category_content(&self, target: &MessageId) -> Option<CategoryContentV1> {
        let message = self
            .board_state
            .recent_messages
            .messages
            .iter()
            .find(|m| m.id() == *target)?;
        match &message.message.content {
            BoardMessageBody::Public {
                content_type, data, ..
            } if *content_type == plaza_core::board_state::content::CONTENT_TYPE_CATEGORY => {
                CategoryContentV1::decode(data).ok()
            }
            BoardMessageBody::Private {
                content_type,
                ciphertext,
                nonce,
                secret_version,
                secret_scope,
                ..
            } if *content_type == plaza_core::board_state::content::CONTENT_TYPE_CATEGORY => {
                let key = match secret_scope {
                    SecretScope::Board => self.board_secrets.get(secret_version).copied(),
                    SecretScope::Category(id) => self.category_secrets.get(id).map(|(_, key)| *key),
                }?;
                let bytes =
                    crate::util::ecies::decrypt_with_symmetric_key(&key, ciphertext, nonce).ok()?;
                CategoryContentV1::decode(&bytes).ok()
            }
            _ => None,
        }
    }

    /// Category whose key must seal content about `target`.
    fn category_id_for(&self, target: &MessageId) -> Option<MessageId> {
        if let Some(category) = self.category_content(target) {
            if category.is_restricted() {
                return Some(target.clone());
            }
        }
        let message = self
            .board_state
            .recent_messages
            .messages
            .iter()
            .find(|m| m.id() == *target)?;
        match &message.message.content {
            BoardMessageBody::Private {
                secret_scope: SecretScope::Category(id),
                ..
            } => Some(id.clone()),
            _ => None,
        }
    }

    fn category_secret_for(&self, target: &MessageId) -> Option<(MessageId, [u8; 32], u32)> {
        let category_id = self.category_id_for(target)?;
        let (version, key) = self.category_secrets.get(&category_id).copied()?;
        Some((category_id, key, version))
    }
}

/// Seal an action with the key that guards its target.
fn seal_action(
    ctx: &ActionContext,
    action: ActionContentV1,
    target: &MessageId,
) -> Option<BoardMessageBody> {
    if let Some((category_id, key, version)) = ctx.category_secret_for(target) {
        return Some(seal_action_with(
            action,
            SecretScope::Category(category_id),
            &key,
            version,
        ));
    }
    if ctx.is_private {
        let (key, version) = ctx.secret_opt?;
        return Some(seal_action_with(action, SecretScope::Board, &key, version));
    }
    Some(BoardMessageBody::public_raw(
        CONTENT_TYPE_ACTION,
        ACTION_CONTENT_VERSION,
        action.encode(),
    ))
}

fn seal_action_with(
    action: ActionContentV1,
    scope: SecretScope,
    key: &[u8; 32],
    version: u32,
) -> BoardMessageBody {
    let (ciphertext, nonce) = encrypt_with_symmetric_key(key, &action.encode());
    BoardMessageBody::Private {
        content_type: CONTENT_TYPE_ACTION,
        content_version: ACTION_CONTENT_VERSION,
        ciphertext,
        nonce,
        secret_version: version,
        secret_scope: scope,
    }
}

/// Toggle a reaction on a message (add or remove)
pub async fn toggle_reaction(ctx: ActionContext, target_message_id: MessageId, emoji: String) {
    let self_member_id = MemberId::from(&ctx.self_sk.verifying_key());

    // Check if user already has this reaction
    let existing_reaction: Option<String> = {
        let boards = BOARDS.read();
        boards.map.get(&ctx.current_board).and_then(|board_data| {
            board_data
                .board_state
                .recent_messages
                .reactions(&target_message_id)
                .and_then(|reactions| {
                    reactions.iter().find_map(|(e, reactors)| {
                        if reactors.contains(&self_member_id) {
                            Some(e.clone())
                        } else {
                            None
                        }
                    })
                })
        })
    };

    let clicked_same = existing_reaction.as_ref() == Some(&emoji);
    let mut actions = Vec::new();

    if clicked_same {
        actions.push(ActionContentV1::remove_reaction(
            target_message_id.clone(),
            emoji,
        ));
    } else {
        if let Some(old_emoji) = existing_reaction {
            actions.push(ActionContentV1::remove_reaction(
                target_message_id.clone(),
                old_emoji,
            ));
        }
        actions.push(ActionContentV1::reaction(target_message_id.clone(), emoji));
    }

    send_actions(ctx, actions).await;
}

/// Owner-only, after a key rotation: publish an edit that re-seals the real
/// category name with the current key, so members who join later read it.
pub async fn reseal_category_name(category_id: MessageId) {
    let Some(ctx) = ActionContext::from_current_board() else {
        return;
    };
    if ctx.self_sk.verifying_key() != ctx.current_board {
        return;
    }
    let Some(category) = ctx.category_content(&category_id) else {
        return;
    };
    if !category.is_restricted() {
        return;
    }
    let Some(sealed) = category.sealed_name.clone() else {
        return;
    };
    let Some((_, new_key, version)) = ctx.category_secret_for(&category_id) else {
        return;
    };
    // The old name may be sealed with an earlier version; keep every old key
    // on this device for exactly this case.
    let old_key = sealed.secret_version().and_then(|sealed_version| {
        if sealed_version == version {
            Some(new_key)
        } else {
            ctx.old_category_secrets
                .get(&category_id)
                .and_then(|versions| versions.get(&sealed_version).copied())
        }
    });
    let Some(old_key) = old_key else {
        return;
    };
    let Ok(name_bytes) = unseal_bytes(&sealed, Some(&old_key)) else {
        return;
    };
    let Ok(name) = String::from_utf8(name_bytes) else {
        return;
    };
    if name.is_empty() {
        return;
    }
    let sealed_name = seal_bytes(name.as_bytes(), &new_key, version);
    let action = ActionContentV1::edit_category_sealed(
        category_id.clone(),
        CategoryEditPayload::placeholder_name(category.hidden),
        category.description.clone(),
        category.icon.clone(),
        category.color.clone(),
        sealed_name,
        category.allowed_roles.clone(),
        category.hidden,
    );
    send_actions(ctx, vec![action]).await;
}

/// Delete a message
pub async fn delete_message(ctx: ActionContext, target_message_id: MessageId) {
    let action = ActionContentV1::delete(target_message_id.clone());
    send_actions(ctx, vec![action]).await;
}

/// Edit a message
pub async fn edit_message(
    ctx: ActionContext,
    target_message_id: MessageId,
    new_title: String,
    new_text: String,
) {
    if new_text.is_empty() {
        return;
    }

    let action = ActionContentV1::edit(target_message_id.clone(), new_title, new_text);
    send_actions(ctx, vec![action]).await;
}

/// Edit a category
pub async fn edit_category(
    ctx: ActionContext,
    target_message_id: MessageId,
    new_name: String,
    new_description: Option<String>,
    new_icon: Option<String>,
    new_color: String,
    new_parent: Option<Option<MessageId>>,
) {
    if new_name.is_empty() {
        return;
    }

    let content = match (
        ctx.category_content(&target_message_id)
            .filter(|category| category.is_restricted()),
        ctx.category_secret_for(&target_message_id),
    ) {
        (Some(category), Some((category_id, key, version))) => {
            // Keep the real name sealed and re-state the ACL so an edit cannot
            // turn a restricted category into a public one.
            let sealed_name = crate::util::ecies::seal_bytes(new_name.as_bytes(), &key, version);
            let action = match new_parent.clone() {
                Some(parent) => ActionContentV1::edit_category_sealed_with_parent(
                    target_message_id.clone(),
                    CategoryEditPayload::placeholder_name(category.hidden),
                    new_description,
                    new_icon,
                    new_color,
                    sealed_name,
                    category.allowed_roles.clone(),
                    category.hidden,
                    parent,
                ),
                None => ActionContentV1::edit_category_sealed(
                    target_message_id.clone(),
                    CategoryEditPayload::placeholder_name(category.hidden),
                    new_description,
                    new_icon,
                    new_color,
                    sealed_name,
                    category.allowed_roles.clone(),
                    category.hidden,
                ),
            };
            seal_action_with(action, SecretScope::Category(category_id), &key, version)
        }
        _ => {
            let action = match new_parent.clone() {
                Some(parent) => ActionContentV1::edit_category_with_parent(
                    target_message_id.clone(),
                    new_name,
                    new_description,
                    new_icon,
                    new_color,
                    parent,
                ),
                None => ActionContentV1::edit_category(
                    target_message_id.clone(),
                    new_name,
                    new_description,
                    new_icon,
                    new_color,
                ),
            };
            match seal_action(&ctx, action, &target_message_id) {
                Some(content) => content,
                None => return,
            }
        }
    };

    send_action_messages(ctx, vec![content]).await;
}

fn self_member_id(ctx: &ActionContext) -> MemberId {
    MemberId::from(&ctx.self_sk.verifying_key())
}

/// Authority the current identity holds for a moderation power, used to keep
/// the record verifiable after a later demotion.
pub(crate) fn moderation_proof(
    ctx: &ActionContext,
    target: &MessageId,
    power: ModerationPower,
) -> Option<AuthorityProof> {
    let self_id = self_member_id(ctx);
    if let Some(proof) = admin_authority_proof(&ctx.board_state, &self_id) {
        return Some(proof);
    }
    let routes = ctx.board_state.moderation.routes_map();
    let chain = category_chain(&routes, target);
    moderation_authority_proof(&ctx.board_state, &self_id, power, &chain)
}

fn admin_proof(ctx: &ActionContext) -> Option<AuthorityProof> {
    admin_authority_proof(&ctx.board_state, &self_member_id(ctx))
}

/// Pin/unpin or close/reopen a post. The contract verifies the signer's power
/// and scope against the public moderation state.
pub fn set_post_flag(
    ctx: ActionContext,
    target: MessageId,
    pinned: Option<bool>,
    closed: Option<bool>,
    announced: Option<bool>,
) -> Result<(), String> {
    let next_generation = |kind: FeatureKind| {
        ctx.board_state
            .moderation
            .feature_flag_for(&target, kind)
            .map(|flag| flag.generation + 1)
            .unwrap_or(1)
    };
    let now = chrono::Utc::now().timestamp_millis();
    let mut flags = Vec::new();
    if let Some(value) = pinned {
        flags.push(
            AuthorizedFeatureFlag::new(
                FeatureFlag {
                    target,
                    kind: FeatureKind::Pinned,
                    value,
                    destination: None,
                    generation: next_generation(FeatureKind::Pinned),
                    created_at: now,
                },
                &ctx.self_sk,
            )
            .with_optional_authority(moderation_proof(
                &ctx,
                &target,
                ModerationPower::Pin,
            )),
        );
    }
    if let Some(value) = closed {
        flags.push(
            AuthorizedFeatureFlag::new(
                FeatureFlag {
                    target,
                    kind: FeatureKind::Closed,
                    value,
                    destination: None,
                    generation: next_generation(FeatureKind::Closed),
                    created_at: now,
                },
                &ctx.self_sk,
            )
            .with_optional_authority(moderation_proof(
                &ctx,
                &target,
                ModerationPower::Close,
            )),
        );
    }
    if let Some(value) = announced {
        flags.push(
            AuthorizedFeatureFlag::new(
                FeatureFlag {
                    target,
                    kind: FeatureKind::Announced,
                    value,
                    destination: None,
                    generation: next_generation(FeatureKind::Announced),
                    created_at: now,
                },
                &ctx.self_sk,
            )
            .with_optional_authority(admin_proof(&ctx)),
        );
    }
    if flags.is_empty() {
        return Ok(());
    }
    let delta = ChatBoardStateV1Delta {
        moderation: Some(ModerationDelta {
            routes: Vec::new(),
            feature_flags: flags,
            moves: Vec::new(),
        }),
        ..Default::default()
    };
    apply_state_delta(&ctx, delta)
}

fn next_move_generation(ctx: &ActionContext, target: &MessageId) -> u64 {
    ctx.board_state
        .moderation
        .moves
        .iter()
        .filter(|entry| entry.change.target == *target)
        .map(|entry| entry.change.generation)
        .max()
        .unwrap_or(0)
        + 1
}

pub(crate) fn apply_state_delta(
    ctx: &ActionContext,
    delta: ChatBoardStateV1Delta,
) -> Result<(), String> {
    if let Some(board) = BOARDS.read().map.get(&ctx.current_board) {
        board.ensure_can_write()?;
    }
    let parent = ctx.board_state.clone();
    let owner = ctx.current_board;
    let mut error: Option<String> = None;
    BOARDS.with_mut(|boards| {
        if let Some(board) = boards.map.get_mut(&owner) {
            if let Err(e) = board.board_state.apply_delta(
                &parent,
                &ChatBoardParametersV1 { owner },
                &Some(delta),
            ) {
                error = Some(e);
            }
        }
    });
    if let Some(error) = error {
        return Err(error);
    }
    mark_needs_sync(owner);
    Ok(())
}

/// Move a topic to another section, or a reply under another topic.
pub fn move_post(
    ctx: &ActionContext,
    target: MessageId,
    new_parent: Option<MessageId>,
) -> Result<(), String> {
    let change = PostMove {
        target,
        new_parent,
        generation: next_move_generation(ctx, &target),
        created_at: chrono::Utc::now().timestamp_millis(),
    };
    let delta = ChatBoardStateV1Delta {
        moderation: Some(ModerationDelta {
            routes: Vec::new(),
            feature_flags: Vec::new(),
            moves: vec![AuthorizedPostMove::new(change, &ctx.self_sk)
                .with_optional_authority(moderation_proof(ctx, &target, ModerationPower::Move))],
        }),
        ..Default::default()
    };
    apply_state_delta(ctx, delta)
}

/// Merge a topic into another one: hide the source, close it, and move its
/// direct replies under the destination. Descendants follow their parent.
pub fn merge_topic(
    ctx: &ActionContext,
    source: MessageId,
    destination: MessageId,
    direct_replies: Vec<MessageId>,
) -> Result<(), String> {
    if source == destination {
        return Err("A topic cannot be merged into itself".to_string());
    }
    let now = chrono::Utc::now().timestamp_millis();
    let next_generation = |kind: FeatureKind| {
        ctx.board_state
            .moderation
            .feature_flag_for(&source, kind)
            .map(|flag| flag.generation + 1)
            .unwrap_or(1)
    };
    let merged = AuthorizedFeatureFlag::new(
        FeatureFlag {
            target: source,
            kind: FeatureKind::Merged,
            value: true,
            destination: Some(destination),
            generation: next_generation(FeatureKind::Merged),
            created_at: now,
        },
        &ctx.self_sk,
    )
    .with_optional_authority(moderation_proof(ctx, &source, ModerationPower::Move));
    let closed = AuthorizedFeatureFlag::new(
        FeatureFlag {
            target: source,
            kind: FeatureKind::Closed,
            value: true,
            destination: None,
            generation: next_generation(FeatureKind::Closed),
            created_at: now,
        },
        &ctx.self_sk,
    )
    .with_optional_authority(moderation_proof(ctx, &source, ModerationPower::Close));
    let moves: Vec<AuthorizedPostMove> =
        direct_replies
            .into_iter()
            .filter(|reply| *reply != destination)
            .map(|reply| {
                let change = PostMove {
                    target: reply,
                    new_parent: Some(destination),
                    generation: next_move_generation(ctx, &reply),
                    created_at: chrono::Utc::now().timestamp_millis(),
                };
                AuthorizedPostMove::new(change, &ctx.self_sk)
                    .with_optional_authority(moderation_proof(ctx, &reply, ModerationPower::Move))
            })
            .collect();
    let delta = ChatBoardStateV1Delta {
        moderation: Some(ModerationDelta {
            routes: Vec::new(),
            feature_flags: vec![merged, closed],
            moves,
        }),
        ..Default::default()
    };
    apply_state_delta(ctx, delta)
}

/// Split one reply into a new topic in its section: create the topic, then
/// move the reply under it.
pub async fn split_reply(
    ctx: &ActionContext,
    reply: MessageId,
    category: MessageId,
    category_author: String,
    category_preview: String,
    title: String,
) -> Result<(), String> {
    let reply_content = ReplyContentV1::new(
        title,
        String::new(),
        category,
        category_author,
        category_preview,
    );
    let content_bytes = reply_content.encode();
    let (content_type, content_version) = (CONTENT_TYPE_REPLY, REPLY_CONTENT_VERSION);
    let category_secret = ctx.category_secret_for(&category);
    let content = if let Some((category_id, secret, version)) = category_secret {
        let (ciphertext, nonce) = encrypt_with_symmetric_key(&secret, &content_bytes);
        BoardMessageBody::Private {
            content_type,
            content_version,
            ciphertext,
            nonce,
            secret_version: version,
            secret_scope: SecretScope::Category(category_id),
        }
    } else if ctx.is_private {
        match ctx.secret_opt {
            Some((secret, version)) => {
                let (ciphertext, nonce) = encrypt_with_symmetric_key(&secret, &content_bytes);
                BoardMessageBody::private(content_type, content_version, ciphertext, nonce, version)
            }
            None => BoardMessageBody::public_raw(content_type, content_version, content_bytes),
        }
    } else {
        BoardMessageBody::public_raw(content_type, content_version, content_bytes)
    };

    let new_topic = crate::util::messaging::publish_message(
        ctx.current_board,
        ctx.board_key,
        ctx.self_sk.clone(),
        ctx.board_state.clone(),
        content,
        Some(category),
        Some(category),
    )
    .await
    .ok_or("Could not create the split topic")?;

    move_post(ctx, reply, Some(new_topic))
}

/// Build the action that moves a section to a new parent. Restricted sections
/// keep their sealed name and ACL; the parent change does not need the key.
fn move_category_action(
    ctx: &ActionContext,
    category_id: &MessageId,
    new_parent: Option<MessageId>,
) -> Option<BoardMessageBody> {
    let category = ctx.category_content(category_id)?;
    let action = if category.is_restricted() {
        ActionContentV1::edit_category_sealed_with_parent(
            category_id.clone(),
            category.name.clone(),
            category.description.clone(),
            category.icon.clone(),
            category.color.clone(),
            category.sealed_name.clone()?,
            category.allowed_roles.clone(),
            category.hidden,
            new_parent,
        )
    } else {
        ActionContentV1::edit_category_with_parent(
            category_id.clone(),
            category.name.clone(),
            category.description.clone(),
            category.icon.clone(),
            category.color.clone(),
            new_parent,
        )
    };
    seal_action(ctx, action, category_id)
}

/// Delete a group and move its sections to Ungrouped in the same delta.
pub async fn delete_group(
    ctx: ActionContext,
    group_id: MessageId,
    child_ids: Vec<MessageId>,
) -> Result<(), String> {
    let mut contents = Vec::new();
    for child in child_ids {
        let body = move_category_action(&ctx, &child, None)
            .ok_or("Could not move a section out of the group")?;
        contents.push(body);
    }
    let delete = ActionContentV1::delete(group_id.clone());
    let body = seal_action(&ctx, delete, &group_id).ok_or("Could not seal the group deletion")?;
    contents.push(body);

    send_action_messages(ctx, contents).await;
    Ok(())
}

// Helper to build remove reaction content
fn build_remove_reaction_content(
    ctx: &ActionContext,
    target_message_id: MessageId,
    emoji: String,
) -> Option<BoardMessageBody> {
    let action = ActionContentV1::remove_reaction(target_message_id.clone(), emoji);
    seal_action(ctx, action, &target_message_id)
}

// Helper to build add reaction content
fn build_add_reaction_content(
    ctx: &ActionContext,
    target_message_id: MessageId,
    emoji: String,
) -> Option<BoardMessageBody> {
    let action = ActionContentV1::reaction(target_message_id.clone(), emoji);
    seal_action(ctx, action, &target_message_id)
}

/// Wrap each action in the public moderation envelope. The contract reads the
/// type and target; the payload stays sealed on private boards.
async fn send_actions(ctx: ActionContext, actions: Vec<ActionContentV1>) {
    let self_id = plaza_core::board_state::member::MemberId::from(&ctx.self_sk.verifying_key());
    if ctx
        .board_state
        .suspensions
        .active_until(self_id, chrono::Utc::now().timestamp_millis())
        .is_some()
    {
        dioxus::logger::tracing::warn!("Suspended members cannot edit or react");
        return;
    }
    let mut contents = Vec::new();
    for action in actions {
        let encoded = action.encode();
        let payload = if let Some((_, key, version)) = ctx.category_secret_for(&action.target) {
            seal_bytes(&encoded, &key, version)
        } else if ctx.is_private {
            let Some((key, version)) = ctx.secret_opt else {
                return;
            };
            seal_bytes(&encoded, &key, version)
        } else {
            SealedBytes::public(encoded)
        };
        let envelope = ModerationActionV1::new(action.action_type, action.target, payload);
        contents.push(BoardMessageBody::public_raw(
            CONTENT_TYPE_MODERATION_ACTION,
            ACTION_CONTENT_VERSION,
            envelope.encode(),
        ));
    }
    send_action_messages(ctx, contents).await;
}

// Send action messages and apply delta
async fn send_action_messages(ctx: ActionContext, contents: Vec<BoardMessageBody>) {
    if contents.is_empty() {
        return;
    }

    let mut auth_messages = Vec::new();
    for content in contents {
        let message = MessageV1 {
            board_owner: MemberId::from(ctx.current_board),
            author: MemberId::from(&ctx.self_sk.verifying_key()),
            content,
            time: get_current_system_time(),
        };

        let mut message_bytes = Vec::new();
        if ciborium::ser::into_writer(&message, &mut message_bytes).is_err() {
            return;
        }

        let signature =
            crate::signing::sign_message_with_fallback(ctx.board_key, message_bytes, &ctx.self_sk)
                .await;

        auth_messages.push(AuthorizedMessageV1::with_signature(message, signature));
    }

    if !auth_messages.is_empty() {
        let delta = ChatBoardStateV1Delta {
            recent_messages: Some(auth_messages),
            ..Default::default()
        };

        let board_state_clone = ctx.board_state.clone();
        let current_board = ctx.current_board;

        BOARDS.with_mut(|boards| {
            if let Some(board_data) = boards.map.get_mut(&current_board) {
                let params = ChatBoardParametersV1 {
                    owner: current_board,
                };
                if board_data
                    .board_state
                    .apply_delta(&board_state_clone, &params, &Some(delta))
                    .is_ok()
                {
                    // The action itself is sealed; apply it locally too.
                    board_data.rebuild_actions_with_local_secrets(&params);
                    mark_needs_sync(current_board);
                }
            }
        });
    }
}
