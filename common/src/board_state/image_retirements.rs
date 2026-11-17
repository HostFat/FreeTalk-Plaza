//! Board-level retirements for images uploaded by anyone.
//!
//! The blob contract can only be retired by its uploader and the board owners
//! recorded in its parameters. Moderators need a lever that follows the living
//! admin list, so the board keeps signed records naming the image contract and
//! its hash. Clients stop showing, fetching and re-serving those images, and
//! the hash list also blocks the same file uploaded again under another
//! contract.
//!
//! Retiring here does not delete bytes from nodes that never see this board;
//! it stops the forum from distributing the image.

use crate::board_state::id::BoardId;
use crate::board_state::message::MessageId;
use crate::board_state::roles::{
    resolve_signer_key, verify_image_retire_authority, AuthorityProof,
};
use crate::board_state::ChatBoardParametersV1;
use crate::util::{sign_struct, verify_struct};
use crate::ChatBoardStateV1;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use freenet_scaffold::ComposableState;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Longest accepted reason. The record is public board state.
pub const MAX_RETIREMENT_REASON: usize = 280;

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct ImageRetirementV1 {
    /// Image contract instance.
    pub instance: [u8; 32],
    /// SHA-256 of the image bytes, kept as a denylist entry.
    pub sha256: [u8; 32],
    pub reason: String,
    pub created_at: i64,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedImageRetirement {
    pub retirement: ImageRetirementV1,
    pub signature: Signature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<crate::board_state::member::MemberId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_key: Option<VerifyingKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<Box<AuthorityProof>>,
}

impl AuthorizedImageRetirement {
    pub fn new(retirement: ImageRetirementV1, signing_key: &SigningKey) -> Self {
        Self {
            signature: sign_struct(&retirement, signing_key),
            retirement,
            signer: Some(crate::board_state::member::MemberId::from(
                &signing_key.verifying_key(),
            )),
            signer_key: Some(signing_key.verifying_key()),
            authority: None,
        }
    }

    pub fn with_optional_authority(mut self, proof: Option<AuthorityProof>) -> Self {
        self.authority = proof.map(Box::new);
        self
    }

    pub fn signer_id(&self, parameters: &ChatBoardParametersV1) -> crate::board_state::member::MemberId {
        self.signer.unwrap_or_else(|| parameters.owner_id())
    }

    pub fn id(&self) -> MessageId {
        MessageId(BoardId::hash(&self.signature.to_bytes()))
    }

    pub fn verify_signature_with(&self, key: &VerifyingKey) -> Result<(), String> {
        verify_struct(&self.retirement, &self.signature, key)
            .map_err(|e| format!("Invalid image retirement signature: {e}"))
    }
}

fn verify_retirement(
    state: &ChatBoardStateV1,
    parameters: &ChatBoardParametersV1,
    entry: &AuthorizedImageRetirement,
) -> Result<(), String> {
    let retirement = &entry.retirement;
    if retirement.reason.chars().count() > MAX_RETIREMENT_REASON {
        return Err("Image retirement reason is too long".to_string());
    }
    if retirement.instance == [0u8; 32] || retirement.sha256 == [0u8; 32] {
        return Err("Image retirement needs a contract and a hash".to_string());
    }
    let signer = entry.signer_id(parameters);
    let key = resolve_signer_key(state, parameters, &signer, entry.signer_key.as_ref())?;
    entry.verify_signature_with(&key)?;
    verify_image_retire_authority(
        state,
        parameters,
        &signer,
        entry.authority.as_deref(),
        crate::board_state::rate_limit::system_time_from_ms(retirement.created_at),
    )
    .map_err(|_| "Only the owner, an admin or a role allowed to retire images can do this".to_string())
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct ImageRetirementsV1 {
    pub retirements: Vec<AuthorizedImageRetirement>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct ImageRetirementsSummary {
    pub entries: BTreeSet<MessageId>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct ImageRetirementsDelta {
    #[serde(default)]
    pub retirements: Vec<AuthorizedImageRetirement>,
}

impl ImageRetirementsV1 {
    pub fn is_retired(&self, instance: &[u8; 32]) -> bool {
        self.retirements
            .iter()
            .any(|entry| entry.retirement.instance == *instance)
    }

    pub fn is_hash_denied(&self, sha256: &[u8; 32]) -> bool {
        self.retirements
            .iter()
            .any(|entry| entry.retirement.sha256 == *sha256)
    }

    pub fn for_hash(&self, sha256: &[u8; 32]) -> Option<&AuthorizedImageRetirement> {
        self.retirements
            .iter()
            .find(|entry| entry.retirement.sha256 == *sha256)
    }

    pub fn cleanup(&mut self, state: &ChatBoardStateV1, parameters: &ChatBoardParametersV1) {
        self.retirements
            .retain(|entry| verify_retirement(state, parameters, entry).is_ok());
        self.retirements.sort_by_key(|entry| entry.id().0 .0);
        self.retirements.dedup_by_key(|entry| entry.id());
    }
}

impl ComposableState for ImageRetirementsV1 {
    type ParentState = ChatBoardStateV1;
    type Summary = ImageRetirementsSummary;
    type Delta = ImageRetirementsDelta;
    type Parameters = ChatBoardParametersV1;

    fn verify(
        &self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
    ) -> Result<(), String> {
        let mut ids = BTreeSet::new();
        for entry in &self.retirements {
            if !ids.insert(entry.id()) {
                return Err("Duplicate image retirement".to_string());
            }
            verify_retirement(parent_state, parameters, entry)?;
        }
        Ok(())
    }

    fn summarize(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
    ) -> Self::Summary {
        ImageRetirementsSummary {
            entries: self.retirements.iter().map(|entry| entry.id()).collect(),
        }
    }

    fn delta(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
        old_state: &Self::Summary,
    ) -> Option<Self::Delta> {
        let retirements: Vec<AuthorizedImageRetirement> = self
            .retirements
            .iter()
            .filter(|entry| !old_state.entries.contains(&entry.id()))
            .cloned()
            .collect();
        if retirements.is_empty() {
            None
        } else {
            Some(ImageRetirementsDelta { retirements })
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
        for entry in &delta.retirements {
            verify_retirement(parent_state, parameters, entry)?;
            if !self
                .retirements
                .iter()
                .any(|existing| existing.id() == entry.id())
            {
                self.retirements.push(entry.clone());
            }
        }
        self.retirements.sort_by_key(|entry| entry.id().0 .0);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board_state::configuration::{AuthorizedConfigurationV1, Configuration};
    use crate::board_state::member::{AuthorizedMember, Member};

    fn fixture() -> (
        SigningKey,
        SigningKey,
        ChatBoardStateV1,
        ChatBoardParametersV1,
        crate::board_state::member::MemberId,
        crate::board_state::member::MemberId,
    ) {
        use crate::board_state::member::MemberId;
        let owner = SigningKey::from_bytes(&[51u8; 32]);
        let member = SigningKey::from_bytes(&[52u8; 32]);
        let owner_id = MemberId::from(&owner.verifying_key());
        let member_id = MemberId::from(&member.verifying_key());
        let mut state = ChatBoardStateV1 {
            configuration: AuthorizedConfigurationV1::new(Configuration::default(), &owner),
            ..Default::default()
        };
        state.members.members.push(AuthorizedMember::new(
            Member {
                owner_member_id: owner_id,
                invited_by: owner_id,
                member_vk: member.verifying_key(),
                join_proof: None,
            },
            &owner,
        ));
        let parameters = ChatBoardParametersV1 {
            owner: owner.verifying_key(),
        };
        (owner, member, state, parameters, owner_id, member_id)
    }

    fn record() -> ImageRetirementV1 {
        ImageRetirementV1 {
            instance: [61u8; 32],
            sha256: [62u8; 32],
            reason: "illegal content".to_string(),
            created_at: 1_700_000_000_000,
        }
    }

    fn grant_retire_role(
        state: &mut ChatBoardStateV1,
        owner: &SigningKey,
        member: crate::board_state::member::MemberId,
    ) {
        use crate::board_state::roles::{
            AuthorizedRole, AuthorizedRoleAssignment, Role, RoleAssignment,
        };
        let role = Role {
            id: [63u8; 16],
            name: "moderator".to_string(),
            generation: 1,
            can_manage_access: false,
            can_distribute_keys: false,
            can_edit_posts: false,
            can_delete_posts: false,
            can_close_posts: false,
            can_pin_posts: false,
            can_move_posts: false,
            can_manage_trash: false,
            can_attach_images: false,
            can_retire_images: true,
            scope: Vec::new(),
            deleted: false,
            signed_at: std::time::SystemTime::UNIX_EPOCH,
        };
        state.roles.roles.push(AuthorizedRole::new(role, owner));
        state
            .roles
            .assignments
            .push(AuthorizedRoleAssignment::new(
                RoleAssignment {
                    role_id: [63u8; 16],
                    member_id: member,
                    generation: 1,
                    revoked: false,
                    signed_at: std::time::SystemTime::UNIX_EPOCH,
                },
                owner,
            ));
    }

    #[test]
    fn the_owner_can_retire_an_image_and_the_hash_is_denied() {
        let (owner, _, state, parameters, _, _) = fixture();
        let entry = AuthorizedImageRetirement::new(record(), &owner);
        let mut list = ImageRetirementsV1 {
            retirements: vec![entry.clone()],
        };
        list.verify(&state, &parameters).expect("the owner may retire");
        assert!(list.is_retired(&[61u8; 32]));
        assert!(list.is_hash_denied(&[62u8; 32]));
        list.cleanup(&state, &parameters);
        assert_eq!(list.retirements.len(), 1);
    }

    #[test]
    fn a_plain_member_cannot_retire_an_image() {
        let (_, member, state, parameters, _, _) = fixture();
        let entry = AuthorizedImageRetirement::new(record(), &member);
        let list = ImageRetirementsV1 {
            retirements: vec![entry],
        };
        let refused = list.verify(&state, &parameters).unwrap_err();
        assert!(refused.contains("Only the owner"), "{refused}");
    }

    #[test]
    fn a_role_with_the_permission_can_retire_an_image() {
        let (owner, member, mut state, parameters, _, member_id) = fixture();
        grant_retire_role(&mut state, &owner, member_id);
        let entry = AuthorizedImageRetirement::new(record(), &member);
        let list = ImageRetirementsV1 {
            retirements: vec![entry],
        };
        list.verify(&state, &parameters)
            .expect("a role with can_retire_images may retire");
    }
}
