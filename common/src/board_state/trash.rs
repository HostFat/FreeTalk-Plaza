//! Moderator trash.
//!
//! A trash item holds an encrypted bundle (the original messages, their routes
//! and related records) and the item key sealed under the board's trash key.
//! Only members with `can_manage_trash`, the owner and admins can add or
//! restore items; only the owner and admins can purge one for good.

use crate::board_state::member::MemberId;
use crate::board_state::message::MessageId;
use crate::board_state::roles::{
    is_board_admin, resolve_signer_key, verify_admin_authority, AuthorityProof,
};
use crate::board_state::ChatBoardParametersV1;
use crate::util::{sign_struct, verify_struct};
use crate::ChatBoardStateV1;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use freenet_scaffold::ComposableState;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const MAX_BUNDLE_BYTES: usize = 8 * 1024 * 1024;
const MAX_REASON_CHARS: usize = 500;

/// Machine-readable reason for the audit, independent of the UI language.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    #[serde(alias = "illegal")]
    Severe,
    Spam,
    Harassment,
    OffTopic,
    Rules,
    #[default]
    Other,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct TrashItemV1 {
    pub id: MessageId,
    pub root: MessageId,
    pub messages: Vec<MessageId>,
    /// Authors of the hidden messages. Kept so cleanup does not prune them
    /// while the thread is in the trash and restore still has their records.
    #[serde(default)]
    pub authors: Vec<MemberId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section: Option<MessageId>,
    pub bundle: Vec<u8>,
    pub bundle_nonce: [u8; 12],
    pub sealed_item_key: Vec<u8>,
    pub item_key_nonce: [u8; 12],
    pub secret_version: u32,
    pub hidden_at: i64,
    #[serde(default)]
    pub reason_code: ReasonCode,
    pub reason: String,
    pub generation: u64,
}

impl TrashItemV1 {
    pub fn compute_id(&self) -> MessageId {
        let mut bytes = self.bundle.clone();
        bytes.extend_from_slice(&self.bundle_nonce);
        bytes.extend_from_slice(&self.sealed_item_key);
        bytes.extend_from_slice(&self.item_key_nonce);
        bytes.extend_from_slice(self.root.as_bytes());
        MessageId::from_bytes(*blake3::hash(&bytes).as_bytes())
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedTrashItem {
    pub item: TrashItemV1,
    pub signature: Signature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<MemberId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_key: Option<VerifyingKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<Box<AuthorityProof>>,
}

impl AuthorizedTrashItem {
    pub fn new(item: TrashItemV1, signing_key: &SigningKey) -> Self {
        Self {
            signature: sign_struct(&item, signing_key),
            item,
            signer: Some(MemberId::from(&signing_key.verifying_key())),
            signer_key: Some(signing_key.verifying_key()),
            authority: None,
        }
    }

    pub fn with_optional_authority(mut self, proof: Option<AuthorityProof>) -> Self {
        self.authority = proof.map(Box::new);
        self
    }

    pub fn signer_id(&self, parameters: &ChatBoardParametersV1) -> MemberId {
        self.signer.unwrap_or_else(|| parameters.owner_id())
    }

    fn verify_signature_with(&self, key: &VerifyingKey) -> Result<(), String> {
        verify_struct(&self.item, &self.signature, key)
            .map_err(|e| format!("Invalid trash item signature: {e}"))
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub enum TrashActionKind {
    Restore,
    Purge,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct TrashActionV1 {
    pub item_id: MessageId,
    pub kind: TrashActionKind,
    pub generation: u64,
    pub acted_at: i64,
    #[serde(default)]
    pub reason_code: ReasonCode,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<[u8; 32]>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedTrashAction {
    pub action: TrashActionV1,
    pub signature: Signature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<MemberId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_key: Option<VerifyingKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<Box<AuthorityProof>>,
}

impl AuthorizedTrashAction {
    pub fn new(action: TrashActionV1, signing_key: &SigningKey) -> Self {
        Self {
            signature: sign_struct(&action, signing_key),
            action,
            signer: Some(MemberId::from(&signing_key.verifying_key())),
            signer_key: Some(signing_key.verifying_key()),
            authority: None,
        }
    }

    pub fn with_optional_authority(mut self, proof: Option<AuthorityProof>) -> Self {
        self.authority = proof.map(Box::new);
        self
    }

    pub fn signer_id(&self, parameters: &ChatBoardParametersV1) -> MemberId {
        self.signer.unwrap_or_else(|| parameters.owner_id())
    }

    fn verify_signature_with(&self, key: &VerifyingKey) -> Result<(), String> {
        verify_struct(&self.action, &self.signature, key)
            .map_err(|e| format!("Invalid trash action signature: {e}"))
    }
}

#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Eq, Debug)]
pub struct TrashV1 {
    #[serde(default)]
    pub items: Vec<AuthorizedTrashItem>,
    #[serde(default)]
    pub actions: Vec<AuthorizedTrashAction>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct TrashState {
    pub active: bool,
    pub generation: u64,
    #[serde(default)]
    pub digest: i64,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct TrashSummary {
    pub items: BTreeMap<MessageId, TrashState>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct TrashDelta {
    #[serde(default)]
    pub items: Vec<AuthorizedTrashItem>,
    #[serde(default)]
    pub actions: Vec<AuthorizedTrashAction>,
}

fn digest<T: serde::Serialize>(value: &T) -> i64 {
    let mut bytes = Vec::new();
    let _ = ciborium::ser::into_writer(value, &mut bytes);
    freenet_scaffold::util::fast_hash(&bytes).0
}

impl TrashV1 {
    pub fn active_item(&self, id: &MessageId) -> Option<&AuthorizedTrashItem> {
        let item = self.items.iter().find(|item| item.item.id == *id)?;
        let last_action = self
            .actions
            .iter()
            .filter(|action| action.action.item_id == *id)
            .max_by_key(|action| action.action.generation);
        match last_action {
            Some(action) if action.action.generation >= item.item.generation => None,
            _ => Some(item),
        }
    }

    pub fn is_trashed(&self, message: &MessageId) -> bool {
        self.items
            .iter()
            .filter(|item| item.item.messages.contains(message))
            .any(|item| self.active_item(&item.item.id).is_some())
    }

    /// Drop actions whose signer can no longer be verified. A manager who loses
    /// the role keeps a restore only when the record carries the grant that
    /// allowed it; old records without that proof are dropped so the state stays
    /// valid, matching how reports and approvals converge.
    pub fn cleanup(&mut self, state: &ChatBoardStateV1, parameters: &ChatBoardParametersV1) {
        self.actions
            .retain(|entry| verify_action(state, parameters, entry, &[]).is_ok());
    }
}

fn verify_item(
    state: &ChatBoardStateV1,
    parameters: &ChatBoardParametersV1,
    entry: &AuthorizedTrashItem,
) -> Result<(), String> {
    let item = &entry.item;
    let signer = entry.signer_id(parameters);
    let key = resolve_signer_key(state, parameters, &signer, entry.signer_key.as_ref())?;
    entry.verify_signature_with(&key)?;

    // Keep the item verifiable after its signer loses the role: the stored
    // grant proves the permission at signing time.
    if crate::board_state::roles::verify_trash_authority(
        state,
        parameters,
        &signer,
        entry.authority.as_deref(),
    )
    .is_err()
    {
        return Err("Signer cannot manage the trash".to_string());
    }

    if item.generation == 0 {
        return Err("Trash item needs a generation".to_string());
    }
    if item.id != item.compute_id() {
        return Err("Trash item id does not match its bundle".to_string());
    }
    if item.bundle.is_empty() || item.bundle.len() > MAX_BUNDLE_BYTES {
        return Err("Trash bundle size is invalid".to_string());
    }
    if item.sealed_item_key.len() < 32 || item.sealed_item_key.len() > 4096 {
        return Err("Sealed trash item key size is invalid".to_string());
    }
    if item.reason.chars().count() > MAX_REASON_CHARS {
        return Err("Trash reason is too long".to_string());
    }
    if item.messages.is_empty() || !item.messages.contains(&item.root) {
        return Err("Trash bundle must contain the root message".to_string());
    }
    // Hidden messages are removed from `recent_messages`; the encrypted bundle
    // keeps the original records. Only the moderator-signed item is checked
    // here, not the live message list.
    if let Some(section) = item.section {
        let routes = state.moderation.routes_map();
        if let Some(route) = routes.get(&section) {
            if !route.is_category {
                return Err("Trash item section is not a category".to_string());
            }
        }
    }
    Ok(())
}

fn verify_action(
    state: &ChatBoardStateV1,
    parameters: &ChatBoardParametersV1,
    entry: &AuthorizedTrashAction,
    delta_items: &[AuthorizedTrashItem],
) -> Result<(), String> {
    let action = &entry.action;
    let signer = entry.signer_id(parameters);
    let key = resolve_signer_key(state, parameters, &signer, entry.signer_key.as_ref())?;
    entry.verify_signature_with(&key)?;

    // The action may outlive the item: purge removes the bundle and leaves the
    // action as a compact tombstone.
    if let Some(item) = state
        .trash
        .items
        .iter()
        .find(|item| item.item.id == action.item_id)
        .or_else(|| {
            delta_items
                .iter()
                .find(|item| item.item.id == action.item_id)
        })
    {
        if action.generation < item.item.generation {
            return Err("Trash action generation is older than the item".to_string());
        }
    }
    if action.reason.chars().count() > MAX_REASON_CHARS {
        return Err("Trash action reason is too long".to_string());
    }

    let is_owner_or_admin = signer == parameters.owner_id()
        || is_board_admin(state, &signer)
        || verify_admin_authority(state, parameters, &signer, entry.authority.as_deref(), 8)
            .is_ok();
    let allowed = match action.kind {
        // A restore stays valid after the manager loses the role when the
        // action carries the grant that allowed it.
        TrashActionKind::Restore => crate::board_state::roles::verify_trash_authority(
            state,
            parameters,
            &signer,
            entry.authority.as_deref(),
        )
        .is_ok(),
        TrashActionKind::Purge => is_owner_or_admin,
    };
    if !allowed {
        return Err("Signer cannot perform this trash action".to_string());
    }
    Ok(())
}

impl ComposableState for TrashV1 {
    type ParentState = ChatBoardStateV1;
    type Summary = TrashSummary;
    type Delta = TrashDelta;
    type Parameters = ChatBoardParametersV1;

    fn verify(
        &self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
    ) -> Result<(), String> {
        for item in &self.items {
            verify_item(parent_state, parameters, item)?;
        }
        for action in &self.actions {
            verify_action(parent_state, parameters, action, &[])?;
        }
        Ok(())
    }

    fn summarize(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
    ) -> Self::Summary {
        let mut items = BTreeMap::new();
        for item in self.items.iter() {
            items.insert(
                item.item.id,
                TrashState {
                    active: self.active_item(&item.item.id).is_some(),
                    generation: item.item.generation,
                    digest: digest(&item.item),
                },
            );
        }
        for action in &self.actions {
            let entry = items.entry(action.action.item_id).or_default();
            if action.action.generation >= entry.generation {
                entry.active = false;
                entry.generation = action.action.generation;
                entry.digest = digest(&action.action);
            }
        }
        TrashSummary { items }
    }

    fn delta(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
        old_state: &Self::Summary,
    ) -> Option<Self::Delta> {
        let items = self
            .items
            .iter()
            .filter(|item| {
                old_state
                    .items
                    .get(&item.item.id)
                    .map(|old| {
                        old.generation < item.item.generation
                            || (old.generation == item.item.generation
                                && old.digest != digest(&item.item))
                    })
                    .unwrap_or(true)
            })
            .cloned()
            .collect::<Vec<_>>();
        let actions = self
            .actions
            .iter()
            .filter(|action| {
                old_state
                    .items
                    .get(&action.action.item_id)
                    .map(|old| {
                        old.generation < action.action.generation
                            || (old.generation == action.action.generation
                                && old.digest != digest(&action.action))
                    })
                    .unwrap_or(true)
            })
            .cloned()
            .collect::<Vec<_>>();
        if items.is_empty() && actions.is_empty() {
            None
        } else {
            Some(TrashDelta { items, actions })
        }
    }

    fn apply_delta(
        &mut self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
        delta: &Option<Self::Delta>,
    ) -> Result<(), String> {
        let Some(delta) = delta else {
            return Ok(());
        };
        for entry in &delta.items {
            verify_item(parent_state, parameters, entry)?;
            match self
                .items
                .iter()
                .find(|existing| existing.item.id == entry.item.id)
            {
                Some(existing)
                    if existing.item.generation > entry.item.generation
                        || (existing.item.generation == entry.item.generation
                            && digest(&existing.item) <= digest(&entry.item)) => {}
                _ => {
                    self.items
                        .retain(|existing| existing.item.id != entry.item.id);
                    self.items.push(entry.clone());
                }
            }
        }
        for action in &delta.actions {
            verify_action(parent_state, parameters, action, &delta.items)?;
            match self
                .actions
                .iter()
                .find(|existing| existing.action.item_id == action.action.item_id)
            {
                Some(existing)
                    if existing.action.generation > action.action.generation
                        || (existing.action.generation == action.action.generation
                            && digest(&existing.action) <= digest(&action.action)) => {}
                _ => {
                    self.actions
                        .retain(|existing| existing.action.item_id != action.action.item_id);
                    self.actions.push(action.clone());
                }
            }
            // Purge and restore both drop the encrypted bundle; the action
            // above is the tombstone that prevents a stale peer from bringing
            // the item back.
            self.items
                .retain(|item| item.item.id != action.action.item_id);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board_state::configuration::{AuthorizedConfigurationV1, Configuration};
    use crate::board_state::member::{AuthorizedMember, Member};
    use crate::board_state::message::{
        AuthorizedMessageV1, BoardMessageBody, MessageV1, MessagesV1,
    };
    use crate::board_state::roles::{
        AuthorizedRole, AuthorizedRoleAssignment, Role, RoleAssignment,
    };
    use crate::board_state::ChatBoardStateV1;
    use ed25519_dalek::SigningKey;

    fn params(owner: &SigningKey) -> ChatBoardParametersV1 {
        ChatBoardParametersV1 {
            owner: owner.verifying_key(),
        }
    }

    fn board(owner: &SigningKey) -> ChatBoardStateV1 {
        ChatBoardStateV1 {
            configuration: AuthorizedConfigurationV1::new(Configuration::default(), owner),
            ..Default::default()
        }
    }

    fn member(sk: &SigningKey, owner_id: MemberId, owner: &SigningKey) -> AuthorizedMember {
        AuthorizedMember::new(
            Member {
                owner_member_id: owner_id,
                invited_by: owner_id,
                member_vk: sk.verifying_key(),
                join_proof: None,
            },
            owner,
        )
    }

    fn post(sk: &SigningKey, owner_id: MemberId, body: &str) -> AuthorizedMessageV1 {
        AuthorizedMessageV1::new(
            MessageV1 {
                board_owner: owner_id,
                author: MemberId::from(&sk.verifying_key()),
                time: std::time::SystemTime::now(),
                content: BoardMessageBody::public("t".to_string(), body.to_string()),
            },
            sk,
        )
    }

    fn item(root: MessageId, messages: Vec<MessageId>, generation: u64) -> TrashItemV1 {
        TrashItemV1 {
            id: MessageId::from_bytes([0u8; 32]),
            root,
            messages,
            authors: Vec::new(),
            section: None,
            bundle: vec![1, 2, 3],
            bundle_nonce: [1u8; 12],
            sealed_item_key: vec![4u8; 48],
            item_key_nonce: [2u8; 12],
            secret_version: 1,
            hidden_at: 1,
            reason_code: ReasonCode::Other,
            reason: "review".to_string(),
            generation,
        }
    }

    #[test]
    fn only_trash_managers_can_add_and_only_admins_purge() {
        let owner = SigningKey::from_bytes(&[1u8; 32]);
        let moderator = SigningKey::from_bytes(&[2u8; 32]);
        let stranger = SigningKey::from_bytes(&[3u8; 32]);
        let parameters = params(&owner);
        let owner_id = parameters.owner_id();
        let moderator_id = MemberId::from(&moderator.verifying_key());

        let mut state = board(&owner);
        state
            .members
            .members
            .push(member(&moderator, owner_id, &owner));
        state
            .members
            .members
            .push(member(&stranger, owner_id, &owner));
        let post = post(&moderator, owner_id, "hello");
        let post_id = post.id();
        state.recent_messages = MessagesV1 {
            messages: vec![post],
            ..Default::default()
        };

        let role_id = [9u8; 16];
        state.roles.roles.push(AuthorizedRole::new(
            Role {
                id: role_id,
                name: "trash".to_string(),
                generation: 1,
                can_manage_access: false,
                can_distribute_keys: false,
                can_edit_posts: false,
                can_delete_posts: false,
                can_close_posts: false,
                can_pin_posts: false,
                can_move_posts: false,
                can_manage_trash: true,
                scope: Vec::new(),
                deleted: false,
            },
            &owner,
        ));
        state.roles.assignments.push(AuthorizedRoleAssignment::new(
            RoleAssignment {
                role_id,
                member_id: moderator_id,
                generation: 1,
                revoked: false,
            },
            &owner,
        ));

        let mut trash_item = item(post_id, vec![post_id], 1);
        trash_item.id = trash_item.compute_id();
        let authorized = AuthorizedTrashItem::new(trash_item.clone(), &moderator);

        let mut stranger_item = item(post_id, vec![post_id], 1);
        stranger_item.id = stranger_item.compute_id();
        let stranger_authorized = AuthorizedTrashItem::new(stranger_item, &stranger);
        assert!(verify_item(&state, &parameters, &stranger_authorized).is_err());

        state.trash.items.push(authorized);
        assert!(state.trash.active_item(&trash_item.id).is_some());
        state
            .trash
            .verify(&state.clone(), &parameters)
            .expect("trash manager can add");

        let purge = AuthorizedTrashAction::new(
            TrashActionV1 {
                item_id: trash_item.id,
                kind: TrashActionKind::Purge,
                generation: 1,
                acted_at: 2,
                reason_code: ReasonCode::Other,
                reason: "illegal".to_string(),
                content_hash: Some([7u8; 32]),
            },
            &moderator,
        );
        state.trash.actions.push(purge);
        assert!(state.trash.verify(&state.clone(), &parameters).is_err());
        state.trash.actions.clear();

        let restore = AuthorizedTrashAction::new(
            TrashActionV1 {
                item_id: trash_item.id,
                kind: TrashActionKind::Restore,
                generation: 1,
                acted_at: 2,
                reason_code: ReasonCode::Other,
                reason: "ok".to_string(),
                content_hash: None,
            },
            &moderator,
        );
        state.trash.actions.push(restore);
        state
            .trash
            .verify(&state.clone(), &parameters)
            .expect("trash manager can restore");
        assert!(state.trash.active_item(&trash_item.id).is_none());
    }

    #[test]
    fn trash_records_signed_by_a_manager_survive_losing_the_role() {
        use crate::board_state::roles::trash_authority_proof;
        let owner = SigningKey::from_bytes(&[1u8; 32]);
        let moderator = SigningKey::from_bytes(&[2u8; 32]);
        let parameters = params(&owner);
        let owner_id = parameters.owner_id();
        let moderator_id = MemberId::from(&moderator.verifying_key());

        let mut state = board(&owner);
        state
            .members
            .members
            .push(member(&moderator, owner_id, &owner));
        let post = post(&moderator, owner_id, "hello");
        let post_id = post.id();
        state.recent_messages = MessagesV1 {
            messages: vec![post],
            ..Default::default()
        };
        let role_id = [9u8; 16];
        state.roles.roles.push(AuthorizedRole::new(
            Role {
                id: role_id,
                name: "trash".to_string(),
                generation: 1,
                can_manage_access: false,
                can_distribute_keys: false,
                can_edit_posts: false,
                can_delete_posts: false,
                can_close_posts: false,
                can_pin_posts: false,
                can_move_posts: false,
                can_manage_trash: true,
                scope: Vec::new(),
                deleted: false,
            },
            &owner,
        ));
        state.roles.assignments.push(AuthorizedRoleAssignment::new(
            RoleAssignment {
                role_id,
                member_id: moderator_id,
                generation: 1,
                revoked: false,
            },
            &owner,
        ));

        let proof = trash_authority_proof(&state, &moderator_id);
        let mut trash_item = item(post_id, vec![post_id], 1);
        trash_item.id = trash_item.compute_id();
        state.trash.items.push(
            AuthorizedTrashItem::new(trash_item.clone(), &moderator)
                .with_optional_authority(proof.clone()),
        );
        state.trash.actions.push(
            AuthorizedTrashAction::new(
                TrashActionV1 {
                    item_id: trash_item.id,
                    kind: TrashActionKind::Restore,
                    generation: 2,
                    acted_at: 2,
                    reason_code: ReasonCode::Other,
                    reason: "restored".to_string(),
                    content_hash: None,
                },
                &moderator,
            )
            .with_optional_authority(proof),
        );

        state.roles.assignments[0] = AuthorizedRoleAssignment::new(
            RoleAssignment {
                role_id,
                member_id: moderator_id,
                generation: 2,
                revoked: true,
            },
            &owner,
        );
        assert!(!state.roles.can_manage_trash(&moderator_id));
        state
            .trash
            .verify(&state.clone(), &parameters)
            .expect("the stored grant keeps the item and the restore valid");
    }

    #[test]
    fn cleanup_drops_actions_with_an_unauthorized_signer() {
        let owner = SigningKey::from_bytes(&[1u8; 32]);
        let stranger = SigningKey::from_bytes(&[3u8; 32]);
        let parameters = params(&owner);
        let owner_id = parameters.owner_id();
        let mut state = board(&owner);
        state
            .members
            .members
            .push(member(&stranger, owner_id, &owner));
        let post = post(&stranger, owner_id, "hi");
        let post_id = post.id();
        state.recent_messages = MessagesV1 {
            messages: vec![post],
            ..Default::default()
        };
        let mut trash_item = item(post_id, vec![post_id], 1);
        trash_item.id = trash_item.compute_id();
        state
            .trash
            .items
            .push(AuthorizedTrashItem::new(trash_item.clone(), &owner));
        state.trash.actions.push(AuthorizedTrashAction::new(
            TrashActionV1 {
                item_id: trash_item.id,
                kind: TrashActionKind::Restore,
                generation: 2,
                acted_at: 2,
                reason_code: ReasonCode::Other,
                reason: "x".to_string(),
                content_hash: None,
            },
            &stranger,
        ));
        assert!(state.trash.verify(&state.clone(), &parameters).is_err());

        let mut trash = std::mem::take(&mut state.trash);
        trash.cleanup(&state, &parameters);
        assert!(trash.actions.is_empty(), "unauthorized action is dropped");
    }
}
