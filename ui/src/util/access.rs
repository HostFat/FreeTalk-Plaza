//! Roles, invite links and token joins.

use crate::board_data::BoardData;
use crate::components::app::freenet_api::freenet_synchronizer::SynchronizerMessage;
use crate::components::app::{
    mark_needs_sync, BOARDS, CURRENT_BOARD, PENDING_INVITES, SYNCHRONIZER,
};
use crate::invites::{PendingBoardJoin, PendingBoardStatus};
use dioxus::logger::tracing::{debug, info};
use dioxus::prelude::ReadableExt;
use ed25519_dalek::{SigningKey, VerifyingKey};
use freenet_scaffold::ComposableState;
use plaza_core::board_state::invites::{join_message, InviteToken, JoinProof, TokenId};
use plaza_core::board_state::invites::{AuthorizedInviteToken, InviteTokensDelta};
use plaza_core::board_state::member::{AuthorizedMember, Member, MemberId};
use plaza_core::board_state::message::MessageId;
use plaza_core::board_state::roles::{
    admin_authority_proof, manager_authority_proof, AuthorizedRole, AuthorizedRoleAssignment, Role,
    RoleAssignment, RoleId, RolesDelta,
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

/// The serialized form. `checksum` is optional for links made before it
/// existed, and older clients ignore the field they do not know.
#[derive(Serialize, Deserialize, Clone)]
struct JoinLinkWire {
    board: VerifyingKey,
    token_id: TokenId,
    token_key: SigningKey,
    #[serde(default)]
    category_keys: Vec<(MessageId, [u8; 32])>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    checksum: Option<[u8; 4]>,
}

const INVITE_CHECKSUM_DOMAIN: &[u8] = b"freetalk-invite-link-v1";

fn invite_checksum(wire: &JoinLinkWire) -> [u8; 4] {
    let unsigned = JoinLinkWire {
        checksum: None,
        ..wire.clone()
    };
    let mut data = Vec::new();
    ciborium::ser::into_writer(&unsigned, &mut data).expect("serialization cannot fail");
    let mut hasher = blake3::Hasher::new();
    hasher.update(INVITE_CHECKSUM_DOMAIN);
    hasher.update(&data);
    let hash = hasher.finalize();
    let mut checksum = [0u8; 4];
    checksum.copy_from_slice(&hash.as_bytes()[..4]);
    checksum
}

fn damaged_link_message() -> String {
    "This invite link is incomplete or damaged. Ask the sender to copy it again with the Copy button, then paste the full link below.".to_string()
}

/// Extract the token from a pasted value. Accepts a full `#/join/` URL, a bare
/// token, and a token that a chat client wrapped across lines.
pub fn token_from_input(input: &str) -> String {
    let trimmed = input.trim();
    let after_join = trimmed
        .split_once("#/join/")
        .or_else(|| trimmed.split_once("/join/"))
        .map(|(_, token)| token)
        .unwrap_or(trimmed);
    let token = after_join
        .split(['?', '&', '#'])
        .next()
        .unwrap_or(after_join);
    token
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .trim_end_matches('/')
        .to_string()
}

impl JoinLink {
    pub fn encode(&self) -> String {
        let mut wire = JoinLinkWire {
            board: self.board,
            token_id: self.token_id,
            token_key: self.token_key.clone(),
            category_keys: self.category_keys.clone(),
            checksum: None,
        };
        wire.checksum = Some(invite_checksum(&wire));
        let mut data = Vec::new();
        ciborium::ser::into_writer(&wire, &mut data).expect("serialization cannot fail");
        bs58::encode(data).into_string()
    }

    pub fn decode(s: &str) -> Result<Self, String> {
        let token = token_from_input(s);
        if token.is_empty() {
            return Err(damaged_link_message());
        }
        let bytes = bs58::decode(&token)
            .into_vec()
            .map_err(|e| {
                debug!("Invite link is not base58: {e}");
                damaged_link_message()
            })?;
        let wire: JoinLinkWire = ciborium::de::from_reader(&bytes[..]).map_err(|e| {
            debug!("Invite link is not a valid JoinLink: {e}");
            damaged_link_message()
        })?;
        if let Some(expected) = wire.checksum {
            if expected != invite_checksum(&wire) {
                debug!("Invite link checksum does not match");
                return Err(damaged_link_message());
            }
        }
        Ok(JoinLink {
            board: wire.board,
            token_id: wire.token_id,
            token_key: wire.token_key,
            category_keys: wire.category_keys,
        })
    }
}

fn with_manager_board<T>(
    f: impl FnOnce(&BoardData, SigningKey, VerifyingKey, Option<MemberId>) -> Result<T, String>,
) -> Result<T, String> {
    let (board_key, data) = {
        let current_board = CURRENT_BOARD.read().owner_key.ok_or("No board selected")?;
        let boards = BOARDS.read();
        let data = boards
            .map
            .get(&current_board)
            .ok_or("Board not found")?
            .clone();
        (current_board, data)
    };
    let self_id = MemberId::from(&data.self_sk.verifying_key());
    data.ensure_can_write()?;
    if !data.is_current_owner() && !data.board_state.roles.can_manage_access(&self_id) {
        return Err("You are not allowed to manage access on this board".to_string());
    }
    let (signing_key, signer) = data.management_signer();
    f(&data, signing_key, board_key, signer)
}

/// Role definitions may be signed by the owner or a board admin.
fn with_admin_board<T>(
    f: impl FnOnce(&BoardData, SigningKey, VerifyingKey, Option<MemberId>) -> Result<T, String>,
) -> Result<T, String> {
    let (board_key, data) = {
        let current_board = CURRENT_BOARD.read().owner_key.ok_or("No board selected")?;
        let boards = BOARDS.read();
        let data = boards
            .map
            .get(&current_board)
            .ok_or("Board not found")?
            .clone();
        (current_board, data)
    };
    let self_id = MemberId::from(&data.self_sk.verifying_key());
    data.ensure_can_write()?;
    if !data.is_current_owner()
        && !plaza_core::board_state::roles::is_board_admin(&data.board_state, &self_id)
    {
        return Err("Only the board owner or an admin can define roles".to_string());
    }
    let (signing_key, signer) = data.management_signer();
    f(&data, signing_key, board_key, signer)
}

/// Sign an invite token with the key that holds access authority. The founding
/// owner keeps the historical signer-less form; a transferred owner signs with
/// its current member id, which the contract resolves from the embedded key.
fn authorized_invite_token(
    data: &BoardData,
    token: InviteToken,
    signing_key: &SigningKey,
    signer: Option<MemberId>,
) -> AuthorizedInviteToken {
    match signer {
        Some(signer_id) => AuthorizedInviteToken::signed_by(token, signer_id, signing_key)
            .with_optional_authority(manager_authority_proof(&data.board_state, &signer_id)),
        None if data.current_owner_id() == MemberId::from(&data.owner_vk) => {
            AuthorizedInviteToken::new(token, signing_key)
        }
        None => {
            let owner_id = data.current_owner_id();
            AuthorizedInviteToken::signed_by(token, owner_id, signing_key)
                .with_optional_authority(manager_authority_proof(&data.board_state, &owner_id))
        }
    }
}

/// Role definitions are owner-only: a manager must not be able to widen its own
/// permissions.
fn with_owner_board<T>(
    f: impl FnOnce(&BoardData, SigningKey, VerifyingKey) -> Result<T, String>,
) -> Result<T, String> {
    let (board_key, data) = {
        let current_board = CURRENT_BOARD.read().owner_key.ok_or("No board selected")?;
        let boards = BOARDS.read();
        let data = boards
            .map
            .get(&current_board)
            .ok_or("Board not found")?
            .clone();
        (current_board, data)
    };
    data.ensure_can_write()?;
    if !data.is_current_owner() {
        return Err("Only the board owner can define roles".to_string());
    }
    f(&data, data.owner_key().clone(), board_key)
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
                    applied = true;
                }
                Err(e) => error = Some(e),
            }
        }
    });
    if applied {
        // A role change can put new members in a restricted category's ACL;
        // the owner owes them the category key.
        let _ = crate::util::messaging::distribute_category_secrets(board_key);
        // Persist and publish role/policy changes even when no category key
        // needs redistribution.
        mark_needs_sync(board_key);
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
    with_admin_board(|data, signing_key, board_key, signer_id| {
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
            can_manage_trash: false,
            can_attach_images: false,
            can_retire_images: false,
            scope,
            deleted: false,
            signed_at: crate::util::get_current_system_time(),
        };
        let authorized = match signer_id {
            Some(signer) => AuthorizedRole::signed_by(role, signer, &signing_key)
                .with_optional_authority(admin_authority_proof(&data.board_state, &signer)),
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
    with_admin_board(|data, signing_key, board_key, signer_id| {
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
            signed_at: crate::util::get_current_system_time(),
            ..current
        };
        let authorized = match signer_id {
            Some(signer) => AuthorizedRole::signed_by(role, signer, &signing_key)
                .with_optional_authority(admin_authority_proof(&data.board_state, &signer)),
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
            signed_at: crate::util::get_current_system_time(),
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

/// Owner-only: allow or stop a role from seeing and restoring the trash.
pub fn set_role_can_manage_trash(role_id: RoleId, value: bool) -> Result<(), String> {
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
            can_manage_trash: value,
            signed_at: crate::util::get_current_system_time(),
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

/// Owner-only: allow or stop a role from attaching images. A section that
/// forbids images still wins over this.
pub fn set_role_can_attach_images(role_id: RoleId, value: bool) -> Result<(), String> {
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
            can_attach_images: value,
            signed_at: crate::util::get_current_system_time(),
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

/// Owner-only: allow or stop a role from retiring images for the board.
pub fn set_role_can_retire_images(role_id: RoleId, value: bool) -> Result<(), String> {
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
            can_retire_images: value,
            signed_at: crate::util::get_current_system_time(),
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
            signed_at: crate::util::get_current_system_time(),
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
    with_manager_board(|data, signing_key, board_key, signer_id| {
        let generation = data
            .board_state
            .roles
            .next_assignment_generation(&role_id, &member_id);
        let assignment = RoleAssignment {
            role_id,
            member_id,
            generation,
            revoked: !grant,
            signed_at: crate::util::get_current_system_time(),
        };
        let authorized = match signer_id {
            Some(signer) => AuthorizedRoleAssignment::signed_by(assignment, signer, &signing_key)
                .with_optional_authority(manager_authority_proof(&data.board_state, &signer)),
            None => AuthorizedRoleAssignment::new(assignment, &signing_key),
        };
        let materialized = if grant {
            crate::components::app::member_contract::records_for_parent_board(
                board_key,
                &data.board_state,
                member_id,
            )
        } else {
            Vec::new()
        };
        let delta = ChatBoardStateV1Delta {
            roles: Some(RolesDelta {
                roles: vec![],
                assignments: vec![authorized],
            }),
            members: if materialized.is_empty() {
                None
            } else {
                Some(plaza_core::board_state::member::MembersDelta::new(
                    materialized,
                ))
            },
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
    with_manager_board(|data, signing_key, board_key, signer_id| {
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
        let authorized =
            authorized_invite_token(data, token, &signing_key, signer_id);
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
    with_manager_board(|data, signing_key, board_key, signer_id| {
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
        let authorized =
            authorized_invite_token(data, token, &signing_key, signer_id);
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
    with_manager_board(|data, signing_key, board_key, signer_id| {
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
        let authorized =
            authorized_invite_token(data, token, &signing_key, signer_id);
        let delta = ChatBoardStateV1Delta {
            invites: Some(InviteTokensDelta {
                tokens: vec![authorized],
            }),
            ..Default::default()
        };
        apply_and_sync(board_key, &data.board_state.clone(), delta)
    })
}

/// Key a join uses for the chosen profile. The board's privacy is unknown
/// before joining, so a separate identity derives a board key by default and
/// reusing the root key is the explicit same-identity choice.
pub fn join_identity_key(
    board: &VerifyingKey,
    profile: &crate::board_data::IdentityProfile,
    separate_identity: bool,
) -> SigningKey {
    if separate_identity {
        profile.derive_for_board(board)
    } else {
        profile.signing_key.clone()
    }
}

/// Join a board through a link: use the chosen profile (or create an
/// unlinkable one), prove we hold the link key, and hand the member record to
/// the synchronizer, which fetches the board state and subscribes.
pub fn join_with_token(
    link: &JoinLink,
    nickname: String,
    profile: Option<crate::board_data::IdentityProfile>,
    separate_identity: bool,
) -> Result<(), String> {
    let nickname = nickname.trim().to_string();
    if nickname.is_empty() {
        return Err("Please choose a nickname".to_string());
    }

    let (member_sk, profile_id) = match profile {
        Some(profile) => {
            let member_sk = join_identity_key(&link.board, &profile, separate_identity);
            let profile_id = profile.id.clone();
            BOARDS.with_mut(|boards| boards.remember_profile(profile));
            (member_sk, Some(profile_id))
        }
        None => {
            let member_sk = SigningKey::generate(&mut rand::thread_rng());
            let profile =
                crate::board_data::IdentityProfile::new(nickname.clone(), member_sk.clone());
            let profile_id = profile.id.clone();
            BOARDS.with_mut(|boards| boards.remember_profile(profile));
            (member_sk, Some(profile_id))
        }
    };
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
                profile_id,
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

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    /// A join derives a board key by default and reuses the root key only
    /// when the user explicitly keeps the same identity.
    #[test]
    fn a_join_derives_a_separate_identity_or_reuses_the_root_key() {
        let profile = crate::board_data::IdentityProfile::new("Profile".to_string(), key(9));
        let board = key(1).verifying_key();

        let derived = join_identity_key(&board, &profile, true);
        assert_eq!(
            derived.verifying_key(),
            profile.derive_for_board(&board).verifying_key()
        );
        assert_ne!(derived.verifying_key(), profile.signing_key.verifying_key());

        let same = join_identity_key(&board, &profile, false);
        assert_eq!(same.verifying_key(), profile.signing_key.verifying_key());
    }

    #[test]
    fn a_link_roundtrips_the_category_keys_it_carries() {
        let link = JoinLink {
            board: key(1).verifying_key(),
            token_id: [2u8; 16],
            token_key: key(3),
            category_keys: vec![(MessageId::from_bytes([7u8; 32]), [4u8; 32])],
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

    /// Links made before the checksum existed must keep working.
    #[test]
    fn an_older_client_can_still_read_a_new_link() {
        #[derive(Deserialize)]
        struct OlderLink {
            board: VerifyingKey,
            token_id: TokenId,
            token_key: SigningKey,
        }

        let link = JoinLink {
            board: key(1).verifying_key(),
            token_id: [2u8; 16],
            token_key: key(3),
            category_keys: vec![],
        };
        let bytes = bs58::decode(link.encode()).into_vec().unwrap();
        let decoded: OlderLink = ciborium::de::from_reader(&bytes[..]).unwrap();
        assert_eq!(decoded.board, link.board);
        assert_eq!(decoded.token_id, link.token_id);
        assert_eq!(
            decoded.token_key.verifying_key(),
            link.token_key.verifying_key()
        );
    }

    #[test]
    fn a_full_link_and_a_wrapped_token_both_decode() {
        let link = JoinLink {
            board: key(1).verifying_key(),
            token_id: [2u8; 16],
            token_key: key(3),
            category_keys: vec![],
        };
        let token = link.encode();

        let full = format!(
            "  https://forum.example/index.html?v=12#/join/{token}?from=chat  ",
        );
        assert!(JoinLink::decode(&full).unwrap() == link);

        let wrapped = token
            .as_bytes()
            .chunks(20)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(JoinLink::decode(&wrapped).unwrap() == link);
    }

    #[test]
    fn a_broken_checksum_is_reported_as_a_damaged_link() {
        let link = JoinLink {
            board: key(1).verifying_key(),
            token_id: [2u8; 16],
            token_key: key(3),
            category_keys: vec![],
        };
        let mut bytes = bs58::decode(link.encode()).into_vec().unwrap();
        let last = bytes.last_mut().unwrap();
        *last ^= 1;
        let broken = bs58::encode(bytes).into_string();

        let error = match JoinLink::decode(&broken) {
            Ok(_) => panic!("a link with a broken checksum was accepted"),
            Err(error) => error,
        };
        assert!(error.contains("incomplete or damaged"), "{error}");
    }
}
