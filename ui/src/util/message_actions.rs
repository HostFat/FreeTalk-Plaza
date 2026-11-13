//! Shared message action handlers for reactions, edits, and deletions.

use crate::components::app::{mark_needs_sync, BOARDS};
use crate::util::ecies::encrypt_with_symmetric_key;
use crate::util::get_current_system_time;
use dioxus::prelude::*;
use ed25519_dalek::{SigningKey, VerifyingKey};
use freenet_scaffold::ComposableState;
use plaza_core::board_state::content::{
    ActionContentV1, CategoryContentV1, CategoryEditPayload, ACTION_CONTENT_VERSION,
    CONTENT_TYPE_ACTION,
};
use plaza_core::board_state::member::MemberId;
use plaza_core::board_state::message::{
    AuthorizedMessageV1, BoardMessageBody, MessageId, MessageV1, SecretScope,
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
}

impl ActionContext {
    /// Create an ActionContext from the current board data, if available
    pub fn from_current_board() -> Option<Self> {
        use crate::components::app::CURRENT_BOARD;

        let current_board = CURRENT_BOARD.read();
        if let Some(key) = current_board.owner_key {
            let boards = BOARDS.read();
            if let Some(board_data) = boards.map.get(&key) {
                return Some(Self {
                    current_board: key,
                    board_key: board_data.board_key(),
                    self_sk: board_data.self_sk.clone(),
                    board_state: board_data.board_state.clone(),
                    is_private: board_data.is_private(),
                    secret_opt: board_data.get_secret().map(|(s, v)| (*s, v)),
                    board_secrets: board_data.secrets.clone(),
                    category_secrets: board_data.category_secrets.clone(),
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
    let mut messages_to_send = Vec::new();

    if clicked_same {
        // Remove the reaction
        let content = build_remove_reaction_content(&ctx, target_message_id.clone(), emoji);
        if let Some(content) = content {
            messages_to_send.push(content);
        }
    } else {
        // Remove old reaction if exists, then add new one
        if let Some(old_emoji) = existing_reaction {
            let content = build_remove_reaction_content(&ctx, target_message_id.clone(), old_emoji);
            if let Some(content) = content {
                messages_to_send.push(content);
            }
        }

        let content = build_add_reaction_content(&ctx, target_message_id.clone(), emoji);
        if let Some(content) = content {
            messages_to_send.push(content);
        }
    }

    send_action_messages(ctx, messages_to_send).await;
}

/// Delete a message
pub async fn delete_message(ctx: ActionContext, target_message_id: MessageId) {
    let action = ActionContentV1::delete(target_message_id.clone());
    let Some(content) = seal_action(&ctx, action, &target_message_id) else {
        return;
    };

    send_action_messages(ctx, vec![content]).await;
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
    let Some(content) = seal_action(&ctx, action, &target_message_id) else {
        return;
    };

    send_action_messages(ctx, vec![content]).await;
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
pub async fn delete_group(ctx: ActionContext, group_id: MessageId) -> Result<(), String> {
    let children: Vec<MessageId> = ctx
        .board_state
        .recent_messages
        .messages
        .iter()
        .filter_map(|message| {
            let category = ctx.category_content(&message.id())?;
            (!category.is_group && category.parent_category_id.as_ref() == Some(&group_id))
                .then(|| message.id())
        })
        .collect();

    let mut contents = Vec::new();
    for child in children {
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
