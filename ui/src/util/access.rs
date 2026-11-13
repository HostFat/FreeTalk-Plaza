//! Roles, invite links and token joins.

use crate::board_data::BoardData;
use crate::components::app::freenet_api::freenet_synchronizer::SynchronizerMessage;
use crate::components::app::{
    mark_needs_sync, BOARDS, CURRENT_BOARD, PENDING_INVITES, SYNCHRONIZER,
};
use crate::invites::{PendingBoardJoin, PendingBoardStatus};
use dioxus::logger::tracing::info;
use dioxus::prelude::ReadableExt;
use ed25519_dalek::{SigningKey, VerifyingKey};
use freenet_scaffold::ComposableState;
use plaza_core::board_state::invites::{join_message, InviteToken, JoinProof, TokenId};
use plaza_core::board_state::invites::{AuthorizedInviteToken, InviteTokensDelta};
use plaza_core::board_state::member::{AuthorizedMember, Member, MemberId};
use plaza_core::board_state::message::MessageId;
use plaza_core::board_state::roles::{
    AuthorizedRole, AuthorizedRoleAssignment, Role, RoleAssignment, RoleId, RolesDelta,
};
use plaza_core::board_state::{ChatBoardParametersV1, ChatBoardStateV1Delta};
use serde::{Deserialize, Serialize};

/// What a link carries: which board, which token, and the token's signing key.
///
/// When the admin chooses to include them, the link also carries the keys of
/// the restricted categories that role can read. The recipient can then open
/// those categories even while every key holder is offline.
#[derive(Serialize, Deserialize, Clone)]
pub struct JoinLink {
    pub board: VerifyingKey,
    pub token_id: TokenId,
    pub token_key: SigningKey,
    #[serde(default)]
    pub category_keys: Vec<(MessageId, [u8; 32])>,
}

impl PartialEq for JoinLink {
    fn eq(&self, other: &Self) -> bool {
        self.board == other.board
            && self.token_id == other.token_id
            && self.token_key.to_bytes() == other.token_key.to_bytes()
            && self.category_keys == other.category_keys
    }
}

impl JoinLink {
    pub fn encode(&self) -> String {
        let mut data = Vec::new();
        ciborium::ser::into_writer(self, &mut data).expect("serialization cannot fail");
        bs58::encode(data).into_string()
    }

    pub fn decode(s: &str) -> Result<Self, String> {
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|e| format!("Invalid invite link: {e}"))?;
        ciborium::de::from_reader(&bytes[..]).map_err(|e| format!("Invalid invite link: {e}"))
    }
}

fn with_manager_board<T>(
    f: impl FnOnce(&BoardData, SigningKey, VerifyingKey, MemberId) -> Result<T, String>,
) -> Result<T, String> {
    let (board_key, self_sk, data) = {
        let current_board = CURRENT_BOARD.read().owner_key.ok_or("No board selected")?;
        let boards = BOARDS.read();
        let data = boards
            .map
            .get(&current_board)
            .ok_or("Board not found")?
            .clone();
        (current_board, data.self_sk.clone(), data)
    };
    let self_id = MemberId::from(&self_sk.verifying_key());
    let is_owner = self_id == MemberId::from(board_key);
    if !is_owner && !data.board_state.roles.can_manage_access(&self_id) {
        return Err("You are not allowed to manage access on this board".to_string());
    }
    f(&data, self_sk, board_key, self_id)
}

fn signer_for(self_id: MemberId, board_key: VerifyingKey) -> Option<MemberId> {
    if self_id == MemberId::from(board_key) {
        None
    } else {
        Some(self_id)
    }
}

/// Role definitions may be signed by the owner or a board admin.
fn with_admin_board<T>(
    f: impl FnOnce(&BoardData, SigningKey, VerifyingKey, MemberId) -> Result<T, String>,
) -> Result<T, String> {
    let (board_key, self_sk, data) = {
        let current_board = CURRENT_BOARD.read().owner_key.ok_or("No board selected")?;
        let boards = BOARDS.read();
        let data = boards
            .map
            .get(&current_board)
            .ok_or("Board not found")?
            .clone();
        (current_board, data.self_sk.clone(), data)
    };
    let self_id = MemberId::from(&self_sk.verifying_key());
    if self_id != MemberId::from(board_key)
        && !plaza_core::board_state::roles::is_board_admin(&data.board_state, &self_id)
    {
        return Err("Only the board owner or an admin can define roles".to_string());
    }
    f(&data, self_sk, board_key, self_id)
}

/// Role definitions are owner-only: a manager must not be able to widen its own
/// permissions.
fn with_owner_board<T>(
    f: impl FnOnce(&BoardData, SigningKey, VerifyingKey) -> Result<T, String>,
) -> Result<T, String> {
    let (board_key, self_sk, data) = {
        let current_board = CURRENT_BOARD.read().owner_key.ok_or("No board selected")?;
        let boards = BOARDS.read();
        let data = boards
            .map
            .get(&current_board)
            .ok_or("Board not found")?
            .clone();
        (current_board, data.self_sk.clone(), data)
    };
    if MemberId::from(&self_sk.verifying_key()) != MemberId::from(board_key) {
        return Err("Only the board owner can define roles".to_string());
    }
    f(&data, self_sk, board_key)
}

fn apply_and_sync(
    board_key: VerifyingKey,
    parent: &plaza_core::ChatBoardStateV1,
    delta: ChatBoardStateV1Delta,
) -> Result<(), String> {
    let mut error: Option<String> = None;
    let mut applied = false;
    BOARDS.with_mut(|boards| {
        if let Some(board) = boards.map.get_mut(&board_key) {
            match board.board_state.apply_delta(
                parent,
                &ChatBoardParametersV1 { owner: board_key },
                &Some(delta),
            ) {
                Ok(_) => {
                    board.rebuild_actions_with_local_secrets(&ChatBoardParametersV1 {
                        owner: board_key,
                    });
                    applied = true;
                }
                Err(e) => error = Some(e),
            }
        }
    });
    if applied {
        // A role change can put new members in a restricted category's ACL;
        // the owner owes them the category key.
        if !crate::util::messaging::distribute_category_secrets(board_key) {
            mark_needs_sync(board_key);
        }
    }
    match error {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn create_role(
    name: String,
    can_manage_access: bool,
    can_distribute_keys: bool,
    can_edit_posts: bool,
    can_delete_posts: bool,
    can_close_posts: bool,
    can_pin_posts: bool,
    can_move_posts: bool,
    mut scope: Vec<MessageId>,
) -> Result<(), String> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("Role name cannot be empty".to_string());
    }
    scope.sort();
    scope.dedup();
    with_admin_board(|data, signing_key, board_key, self_id| {
        let mut id: RoleId = [0u8; 16];
        let random = SigningKey::generate(&mut rand::thread_rng());
        id.copy_from_slice(&random.to_bytes()[..16]);

        let role = Role {
            id,
            name,
            generation: 1,
            can_manage_access,
            can_distribute_keys,
            can_edit_posts,
            can_delete_posts,
            can_close_posts,
            can_pin_posts,
            can_move_posts,
            scope,
            deleted: false,
        };
        let authorized = match signer_for(self_id, board_key) {
            Some(signer) => AuthorizedRole::signed_by(role, signer, &signing_key),
            None => AuthorizedRole::new(role, &signing_key),
        };
        let delta = ChatBoardStateV1Delta {
            roles: Some(RolesDelta {
                roles: vec![authorized],
                assignments: vec![],
            }),
            ..Default::default()
        };
        apply_and_sync(board_key, &data.board_state.clone(), delta)
    })
}

/// Update a role's moderation powers and section scope.
#[allow(clippy::too_many_arguments)]
pub fn update_role_moderation(
    role_id: RoleId,
    can_edit_posts: bool,
    can_delete_posts: bool,
    can_close_posts: bool,
    can_pin_posts: bool,
    can_move_posts: bool,
    mut scope: Vec<MessageId>,
) -> Result<(), String> {
    scope.sort();
    scope.dedup();
    with_admin_board(|data, signing_key, board_key, self_id| {
        let current = data
            .board_state
            .roles
            .roles
            .iter()
            .find(|r| r.role.id == role_id)
            .map(|r| r.role.clone())
            .ok_or("Role not found")?;
        let role = Role {
            generation: current.generation + 1,
            can_edit_posts,
            can_delete_posts,
            can_close_posts,
            can_pin_posts,
            can_move_posts,
            scope,
            ..current
        };
        let authorized = match signer_for(self_id, board_key) {
            Some(signer) => AuthorizedRole::signed_by(role, signer, &signing_key),
            None => AuthorizedRole::new(role, &signing_key),
        };
        let delta = ChatBoardStateV1Delta {
            roles: Some(RolesDelta {
                roles: vec![authorized],
                assignments: vec![],
            }),
            ..Default::default()
        };
        apply_and_sync(board_key, &data.board_state.clone(), delta)
    })
}

/// Owner-only: allow or stop a role from signing category key distributions.
pub fn set_role_can_distribute_keys(role_id: RoleId, value: bool) -> Result<(), String> {
    with_owner_board(|data, owner_sk, board_key| {
        let current = data
            .board_state
            .roles
            .roles
            .iter()
            .find(|r| r.role.id == role_id)
            .map(|r| r.role.clone())
            .ok_or("Role not found")?;
        let role = Role {
            generation: current.generation + 1,
            can_distribute_keys: value,
            ..current
        };
        let delta = ChatBoardStateV1Delta {
            roles: Some(RolesDelta {
                roles: vec![AuthorizedRole::new(role, &owner_sk)],
                assignments: vec![],
            }),
            ..Default::default()
        };
        apply_and_sync(board_key, &data.board_state.clone(), delta)
    })
}

pub fn remove_role(role_id: RoleId) -> Result<(), String> {
    with_owner_board(|data, owner_sk, board_key| {
        let current = data
            .board_state
            .roles
            .roles
            .iter()
            .find(|r| r.role.id == role_id)
            .map(|r| r.role.clone())
            .ok_or("Role not found")?;
        let role = Role {
            generation: current.generation + 1,
            deleted: true,
            ..current
        };
        let delta = ChatBoardStateV1Delta {
            roles: Some(RolesDelta {
                roles: vec![AuthorizedRole::new(role, &owner_sk)],
                assignments: vec![],
            }),
            ..Default::default()
        };
        apply_and_sync(board_key, &data.board_state.clone(), delta)
    })
}

pub fn set_role_member(role_id: RoleId, member_id: MemberId, grant: bool) -> Result<(), String> {
    with_manager_board(|data, self_sk, board_key, self_id| {
        let generation = data
            .board_state
            .roles
            .next_assignment_generation(&role_id, &member_id);
        let assignment = RoleAssignment {
            role_id,
            member_id,
            generation,
            revoked: !grant,
        };
        let authorized = match signer_for(self_id, board_key) {
            Some(signer) => AuthorizedRoleAssignment::signed_by(assignment, signer, &self_sk),
            None => AuthorizedRoleAssignment::new(assignment, &self_sk),
        };
        let delta = ChatBoardStateV1Delta {
            roles: Some(RolesDelta {
                roles: vec![],
                assignments: vec![authorized],
            }),
            ..Default::default()
        };
        apply_and_sync(board_key, &data.board_state.clone(), delta)
    })
}

/// Category keys this link would carry: every restricted category that the
/// role can read and whose key this client holds.
fn category_keys_for_role(data: &BoardData, role_id: RoleId) -> Vec<(MessageId, [u8; 32])> {
    data.restricted_categories()
        .into_iter()
        .filter(|(_, category)| category.allowed_roles.contains(&role_id))
        .filter_map(|(category_id, _)| {
            data.category_secret(&category_id)
                .map(|(_, key)| (category_id, key))
        })
        .collect()
}

/// Owner/manager: rename a link so the list stays readable.
pub fn rename_invite_link(token_id: TokenId, label: String) -> Result<(), String> {
    with_manager_board(|data, self_sk, board_key, self_id| {
        let current = data
            .board_state
            .invites
            .token(&token_id)
            .cloned()
            .ok_or("Link not found")?;
        let token = InviteToken {
            generation: current.generation + 1,
            label: label
                .trim()
                .chars()
                .take(plaza_core::board_state::invites::MAX_INVITE_LABEL)
                .collect(),
            ..current
        };
        let authorized = match signer_for(self_id, board_key) {
            Some(signer) => AuthorizedInviteToken::signed_by(token, signer, &self_sk),
            None => AuthorizedInviteToken::new(token, &self_sk),
        };
        let delta = ChatBoardStateV1Delta {
            invites: Some(InviteTokensDelta {
                tokens: vec![authorized],
            }),
            ..Default::default()
        };
        apply_and_sync(board_key, &data.board_state.clone(), delta)
    })
}

/// Create a link and return its encoded form. With `include_category_keys`,
/// the link carries the keys of the categories the role can read.
pub fn create_invite_link(
    role_id: RoleId,
    max_uses: Option<u32>,
    include_category_keys: bool,
    label: String,
) -> Result<String, String> {
    with_manager_board(|data, self_sk, board_key, self_id| {
        if data.board_state.roles.role(&role_id).is_none() {
            return Err("Role not found".to_string());
        }

        let token_key = SigningKey::generate(&mut rand::thread_rng());
        let mut id: TokenId = [0u8; 16];
        id.copy_from_slice(&token_key.to_bytes()[..16]);

        let token = InviteToken {
            id,
            verifying_key: token_key.verifying_key(),
            role_id,
            max_uses,
            not_after: None,
            generation: 1,
            deleted: false,
            label: label
                .trim()
                .chars()
                .take(plaza_core::board_state::invites::MAX_INVITE_LABEL)
                .collect(),
            created_at: Some(crate::util::get_current_system_time()),
            includes_category_keys: include_category_keys,
        };
        let authorized = match signer_for(self_id, board_key) {
            Some(signer) => AuthorizedInviteToken::signed_by(token, signer, &self_sk),
            None => AuthorizedInviteToken::new(token, &self_sk),
        };
        let delta = ChatBoardStateV1Delta {
            invites: Some(InviteTokensDelta {
                tokens: vec![authorized],
            }),
            ..Default::default()
        };
        apply_and_sync(board_key, &data.board_state.clone(), delta)?;

        let category_keys = if include_category_keys {
            category_keys_for_role(data, role_id)
        } else {
            Vec::new()
        };

        Ok(JoinLink {
            board: board_key,
            token_id: id,
            token_key,
            category_keys,
        }
        .encode())
    })
}

pub fn revoke_invite_link(token_id: TokenId) -> Result<(), String> {
    with_manager_board(|data, self_sk, board_key, self_id| {
        let current = data
            .board_state
            .invites
            .tokens
            .iter()
            .find(|t| t.token.id == token_id)
            .map(|t| t.token.clone())
            .ok_or("Invite link not found")?;
        let token = InviteToken {
            generation: current.generation + 1,
            deleted: true,
            ..current
        };
        let authorized = match signer_for(self_id, board_key) {
            Some(signer) => AuthorizedInviteToken::signed_by(token, signer, &self_sk),
            None => AuthorizedInviteToken::new(token, &self_sk),
        };
        let delta = ChatBoardStateV1Delta {
            invites: Some(InviteTokensDelta {
                tokens: vec![authorized],
            }),
            ..Default::default()
        };
        apply_and_sync(board_key, &data.board_state.clone(), delta)
    })
}

/// Join a board through a link: create our own identity, prove we hold the link
/// key, and hand the member record to the synchronizer, which fetches the board
/// state and subscribes.
pub fn join_with_token(link: &JoinLink, nickname: String) -> Result<(), String> {
    let nickname = nickname.trim().to_string();
    if nickname.is_empty() {
        return Err("Please choose a nickname".to_string());
    }

    let member_sk = SigningKey::generate(&mut rand::thread_rng());
    let member_vk = member_sk.verifying_key();
    let owner_id = MemberId::from(link.board);
    let member_id = MemberId::from(&member_vk);

    let proof = JoinProof::new(
        link.token_id,
        &link.token_key,
        &join_message(&link.board, &member_vk),
    );
    let member = Member {
        owner_member_id: owner_id,
        invited_by: member_id,
        member_vk,
        join_proof: Some(proof),
    };
    let authorized = AuthorizedMember::new(member, &member_sk);

    PENDING_INVITES.with_mut(|pending| {
        pending.map.insert(
            link.board,
            PendingBoardJoin {
                authorized_member: authorized.clone(),
                invitee_signing_key: member_sk.clone(),
                preferred_nickname: nickname.clone(),
                status: PendingBoardStatus::PendingSubscription,
                subscribing_since: None,
                retry_count: 0,
                category_keys: link.category_keys.clone(),
            },
        );
    });

    SYNCHRONIZER
        .write()
        .get_message_sender()
        .unbounded_send(SynchronizerMessage::AcceptInvitation {
            owner_vk: link.board,
            authorized_member: Box::new(authorized),
            invitee_signing_key: Box::new(member_sk),
            nickname,
        })
        .map_err(|e| format!("Failed to join: {e}"))?;

    info!("Join request sent for board {}", MemberId::from(link.board));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use freenet_scaffold::util::FastHash;

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    #[test]
    fn a_link_roundtrips_the_category_keys_it_carries() {
        let link = JoinLink {
            board: key(1).verifying_key(),
            token_id: [2u8; 16],
            token_key: key(3),
            category_keys: vec![(MessageId(FastHash(7)), [4u8; 32])],
        };

        let decoded = JoinLink::decode(&link.encode()).unwrap();
        assert!(decoded == link);
        assert_eq!(decoded.category_keys.len(), 1);
    }

    #[test]
    fn an_old_link_decodes_without_category_keys() {
        #[derive(Serialize)]
        struct OldLink {
            board: VerifyingKey,
            token_id: TokenId,
            token_key: SigningKey,
        }

        let old = OldLink {
            board: key(1).verifying_key(),
            token_id: [2u8; 16],
            token_key: key(3),
        };
        let mut data = Vec::new();
        ciborium::ser::into_writer(&old, &mut data).unwrap();
        let encoded = bs58::encode(data).into_string();

        let decoded = JoinLink::decode(&encoded).unwrap();
        assert!(decoded.category_keys.is_empty());
        assert_eq!(decoded.board, old.board);
    }
}
