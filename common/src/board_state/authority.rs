//! Compact board authority for topics.
//!
//! A topic does not need every member, role and ban of the board. It needs the
//! authority records of its participants and moderators. The board authority is
//! committed to a Merkle root; each topic keeps the root and a proof for each
//! member it references. A role or ban change moves one leaf, and the topic
//! only needs that member's new proof.

use crate::board_state::ban::{AuthorizedBanRevocation, AuthorizedUserBan};
use crate::board_state::member::{AuthorizedMember, MemberId};
use crate::board_state::member_info::AuthorizedMemberInfo;
use crate::board_state::member_moderation::AuthorizedSuspension;
use crate::board_state::rate_limit::system_time_from_ms;
use crate::board_state::roles::{AuthorizedRole, AuthorizedRoleAssignment};
use crate::board_state::ChatBoardParametersV1;
use crate::util::{sign_struct, verify_struct};
use crate::ChatBoardStateV1;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use freenet_scaffold::ComposableState;
use serde::{Deserialize, Serialize};

pub const AUTHORITY_ROOT_VERSION: u8 = 1;
const EMPTY_LEAF: &[u8] = b"plaza-authority-empty";

/// The authority records that belong to one member: their member record, the
/// roles they hold (definitions and assignments), bans and suspensions against
/// them, and the revocations of those bans.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct MemberStatusV1 {
    pub member: AuthorizedMember,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<AuthorizedRole>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assignments: Vec<AuthorizedRoleAssignment>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bans: Vec<AuthorizedUserBan>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revocations: Vec<AuthorizedBanRevocation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suspensions: Vec<AuthorizedSuspension>,
    /// The member's current nickname record. Covered by the root so a board
    /// with thousands of nicknames does not verify each signature again when
    /// the owner-signed root already attests it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_info: Option<AuthorizedMemberInfo>,
}

impl MemberStatusV1 {
    pub fn member_id(&self) -> MemberId {
        self.member.member.id()
    }

    pub fn leaf_hash(&self) -> [u8; 32] {
        let mut bytes = Vec::new();
        if ciborium::ser::into_writer(self, &mut bytes).is_err() {
            return [0u8; 32];
        }
        *blake3::hash(&bytes).as_bytes()
    }
}

/// A root committed by the board authority. The epoch is a client timestamp:
/// a topic keeps the highest epoch it has seen, so an older root cannot roll a
/// ban back.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorityRootV1 {
    pub version: u8,
    /// Board owner key this root belongs to, so a root cannot be replayed on
    /// another board with the same owner and member set.
    #[serde(default)]
    pub board: [u8; 32],
    /// Monotonic client timestamp; a newer root wins when merging.
    pub epoch: i64,
    /// Hash of the authority content, so a sync can skip an unchanged set.
    #[serde(default)]
    pub content_hash: i64,
    pub digest: [u8; 32],
}

/// A root signed by the board owner. Members copy this value into their
/// topics, so a topic can verify that the root is the board's canonical one
/// instead of accepting a root assembled by whichever client created it.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct AuthorizedAuthorityRootV1 {
    pub root: AuthorityRootV1,
    pub signer: MemberId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_key: Option<VerifyingKey>,
    pub signature: Signature,
}

impl AuthorizedAuthorityRootV1 {
    pub fn new(mut root: AuthorityRootV1, owner: &SigningKey) -> Self {
        root.board = owner.verifying_key().to_bytes();
        Self {
            signature: sign_struct(&root, owner),
            root,
            signer: MemberId::from(&owner.verifying_key()),
            signer_key: Some(owner.verifying_key()),
        }
    }

    pub fn verify(&self, owner_key: &VerifyingKey) -> Result<(), String> {
        if self.signer != MemberId::from(owner_key) {
            return Err("authority root is signed by someone other than the owner".to_string());
        }
        if self.root.board != owner_key.to_bytes() {
            return Err("authority root belongs to another board".to_string());
        }
        verify_struct(&self.root, &self.signature, owner_key)
            .map_err(|error| format!("invalid authority root signature: {error}"))
    }
}

/// The board's stored root. It is the last composable field, so its
/// verification sees the authority records that were applied in the same delta.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct AuthorityRootStateV1(pub Option<AuthorizedAuthorityRootV1>);

impl ComposableState for AuthorityRootStateV1 {
    type ParentState = ChatBoardStateV1;
    type Summary = Option<AuthorizedAuthorityRootV1>;
    type Delta = AuthorizedAuthorityRootV1;
    type Parameters = ChatBoardParametersV1;

    fn verify(
        &self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
    ) -> Result<(), String> {
        let Some(root) = &self.0 else {
            return Ok(());
        };
        self.verify_signature(parent_state, parameters)?;
        let tree = AuthorityTreeV1::from_board(parent_state);
        let expected = tree.root(root.root.epoch);
        if expected.digest != root.root.digest {
            return Err("the authority root does not match the board members".to_string());
        }
        if tree.content_hash() != root.root.content_hash {
            return Err("the authority root content hash is stale".to_string());
        }
        Ok(())
    }

    fn summarize(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
    ) -> Self::Summary {
        self.0.clone()
    }

    fn delta(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
        old_state_summary: &Self::Summary,
    ) -> Option<Self::Delta> {
        let current = self.0.as_ref()?;
        match old_state_summary {
            Some(previous) if previous.root.epoch >= current.root.epoch => None,
            _ => Some(current.clone()),
        }
    }

    fn apply_delta(
        &mut self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
        delta: &Option<Self::Delta>,
    ) -> Result<(), String> {
        if let Some(root) = delta {
            let mut candidate = AuthorityRootStateV1(Some(root.clone()));
            candidate.verify_signature(parent_state, parameters)?;
            let should_replace = match &self.0 {
                Some(existing) => root.root.epoch > existing.root.epoch,
                None => true,
            };
            if should_replace {
                self.0 = Some(root.clone());
            }
        }
        // The tree may still change in `post_apply_cleanup` (a member can be
        // pruned); the board verifies the full root after cleanup. Here we
        // only need the signature and the board binding.
        self.verify_signature(parent_state, parameters)
    }
}

impl AuthorityRootStateV1 {
    fn verify_signature(
        &self,
        parent_state: &ChatBoardStateV1,
        parameters: &ChatBoardParametersV1,
    ) -> Result<(), String> {
        let Some(root) = &self.0 else {
            return Ok(());
        };
        if let Some(last_transfer) = parent_state.ownership.transfers.last() {
            let last_ms = crate::board_state::rate_limit::system_time_ms(
                last_transfer.transfer.transferred_at,
            );
            if root.root.epoch < last_ms {
                return Err(
                    "Authority root signed by a former owner before the latest ownership transfer is no longer valid"
                        .to_string(),
                );
            }
        }
        let owner_key = parent_state
            .ownership
            .owner_key_at(parameters, system_time_from_ms(root.root.epoch));
        root.verify(&owner_key)
    }
}

/// One member's leaf and its path to the root. `leaf_count` is the padded tree
/// size, so the verifier knows which levels are padding.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct MemberStatusProofV1 {
    pub status: MemberStatusV1,
    pub index: u32,
    pub leaf_count: u32,
    pub path: Vec<[u8; 32]>,
}

/// A deterministic Merkle tree over the board's member statuses. The leaf set
/// is sorted by member id and padded to a power of two, so every member has a
/// fixed position while the member set is unchanged.
pub struct AuthorityTreeV1 {
    statuses: Vec<MemberStatusV1>,
    leaves: Vec<[u8; 32]>,
    levels: Vec<Vec<[u8; 32]>>,
}

impl AuthorityTreeV1 {
    pub fn new(mut statuses: Vec<MemberStatusV1>) -> Self {
        statuses.sort_by_key(|status| *status.member_id().as_bytes());
        let padded = statuses.len().max(1).next_power_of_two();
        let mut leaves: Vec<[u8; 32]> = statuses
            .iter()
            .map(MemberStatusV1::leaf_hash)
            .collect();
        let empty = *blake3::hash(EMPTY_LEAF).as_bytes();
        leaves.resize(padded, empty);
        let mut levels = vec![leaves.clone()];
        while levels.last().map_or(0, Vec::len) > 1 {
            let previous = levels.last().expect("a level exists");
            let mut next = Vec::with_capacity(previous.len() / 2);
            for pair in previous.chunks(2) {
                let mut bytes = Vec::with_capacity(64);
                bytes.extend_from_slice(&pair[0]);
                bytes.extend_from_slice(pair.get(1).unwrap_or(&empty));
                next.push(*blake3::hash(&bytes).as_bytes());
            }
            levels.push(next);
        }
        Self {
            statuses,
            leaves,
            levels,
        }
    }

    pub fn from_board(state: &ChatBoardStateV1) -> Self {
        // A ban removes the member from the board list but keeps the target
        // record in the ban. The topic still needs a status leaf for that
        // member so it can show the ban and reject new posts.
        let mut members: std::collections::BTreeMap<MemberId, AuthorizedMember> = state
            .members
            .members
            .iter()
            .map(|member| (member.member.id(), member.clone()))
            .collect();
        for ban in &state.bans.0 {
            if let Some(target) = &ban.ban.target_member {
                members
                    .entry(target.member.id())
                    .or_insert_with(|| target.clone());
            }
        }
        let mut statuses = Vec::with_capacity(members.len());
        for (member_id, member) in members {
            let assignments: Vec<AuthorizedRoleAssignment> = state
                .roles
                .assignments
                .iter()
                .filter(|assignment| assignment.assignment.member_id == member_id)
                .cloned()
                .collect();
            let role_ids: std::collections::HashSet<_> = assignments
                .iter()
                .map(|assignment| assignment.assignment.role_id)
                .collect();
            let roles: Vec<AuthorizedRole> = state
                .roles
                .roles
                .iter()
                .filter(|role| role_ids.contains(&role.role.id))
                .cloned()
                .collect();
            let bans: Vec<AuthorizedUserBan> = state
                .bans
                .0
                .iter()
                .filter(|ban| ban.ban.banned_user == member_id)
                .cloned()
                .collect();
            let revocations: Vec<AuthorizedBanRevocation> = state
                .ban_revocations
                .revocations
                .iter()
                .filter(|revocation| revocation.revocation.banned_user == member_id)
                .cloned()
                .collect();
            let suspensions: Vec<AuthorizedSuspension> = state
                .suspensions
                .suspensions
                .iter()
                .filter(|suspension| suspension.suspension.target == member_id)
                .cloned()
                .collect();
            let member_info = state
                .member_info
                .member_info
                .iter()
                .filter(|info| info.member_info.member_id == member_id)
                .max_by_key(|info| info.member_info.version)
                .cloned();
            statuses.push(MemberStatusV1 {
                member: member.clone(),
                roles,
                assignments,
                bans,
                revocations,
                suspensions,
                member_info,
            });
        }
        Self::new(statuses)
    }

    pub fn root(&self, epoch: i64) -> AuthorityRootV1 {
        AuthorityRootV1 {
            version: AUTHORITY_ROOT_VERSION,
            board: [0u8; 32],
            epoch,
            content_hash: 0,
            digest: *self
                .levels
                .last()
                .and_then(|level| level.first())
                .unwrap_or(&[0u8; 32]),
        }
    }

    /// Canonical hash of the leaf set. Both the board contract and the client
    /// derive it from the same sorted leaves.
    pub fn content_hash(&self) -> i64 {
        let mut bytes = Vec::with_capacity(self.leaves.len() * 32);
        for leaf in &self.leaves {
            bytes.extend_from_slice(leaf);
        }
        let hash = blake3::hash(&bytes);
        i64::from_le_bytes(hash.as_bytes()[..8].try_into().unwrap_or([0u8; 8]))
    }

    pub fn proof(&self, member_id: MemberId) -> Option<MemberStatusProofV1> {
        let index = self
            .statuses
            .iter()
            .position(|status| status.member_id() == member_id)?;
        let mut path = Vec::with_capacity(self.levels.len().saturating_sub(1));
        let mut position = index;
        for level in self.levels.iter().take(self.levels.len().saturating_sub(1)) {
            let sibling = position ^ 1;
            let hash = level.get(sibling).copied().unwrap_or(*blake3::hash(EMPTY_LEAF).as_bytes());
            path.push(hash);
            position /= 2;
        }
        Some(MemberStatusProofV1 {
            status: self.statuses[index].clone(),
            index: index as u32,
            leaf_count: self.leaves.len() as u32,
            path,
        })
    }

    pub fn proofs_for<'a>(
        &self,
        ids: impl IntoIterator<Item = &'a MemberId>,
    ) -> Vec<MemberStatusProofV1> {
        let mut seen = std::collections::HashSet::new();
        let mut proofs = Vec::new();
        for id in ids {
            if !seen.insert(*id) {
                continue;
            }
            if let Some(proof) = self.proof(*id) {
                proofs.push(proof);
            }
        }
        proofs.sort_by_key(|proof| *proof.status.member_id().as_bytes());
        proofs
    }
}

impl MemberStatusProofV1 {
    pub fn verify(&self, root: &AuthorityRootV1) -> Result<(), String> {
        if root.version != AUTHORITY_ROOT_VERSION {
            return Err("unsupported authority root version".to_string());
        }
        if !self.leaf_count.is_power_of_two() {
            return Err("authority proof leaf count is not a power of two".to_string());
        }
        if self.index >= self.leaf_count {
            return Err("authority proof index is out of range".to_string());
        }
        let mut position = self.index as usize;
        let mut hash = self.status.leaf_hash();
        for sibling in &self.path {
            let mut bytes = Vec::with_capacity(64);
            if position % 2 == 0 {
                bytes.extend_from_slice(&hash);
                bytes.extend_from_slice(sibling);
            } else {
                bytes.extend_from_slice(sibling);
                bytes.extend_from_slice(&hash);
            }
            hash = *blake3::hash(&bytes).as_bytes();
            position /= 2;
        }
        if hash != root.digest {
            return Err("authority proof does not match the root".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use crate::board_state::member::{Member, MembersV1};
    use std::time::SystemTime;

    fn member(index: u8, owner: &SigningKey) -> AuthorizedMember {
        AuthorizedMember::new(
            Member {
                owner_member_id: MemberId::from(&owner.verifying_key()),
                invited_by: MemberId::from(&owner.verifying_key()),
                member_vk: SigningKey::from_bytes(&[index; 32]).verifying_key(),
                join_proof: None,
            },
            owner,
        )
    }

    fn status(index: u8, owner: &SigningKey) -> MemberStatusV1 {
        MemberStatusV1 {
            member: member(index, owner),
            roles: Vec::new(),
            assignments: Vec::new(),
            bans: Vec::new(),
            revocations: Vec::new(),
            suspensions: Vec::new(),
            member_info: None,
        }
    }

    #[test]
    fn a_proof_verifies_against_the_root() {
        let owner = SigningKey::from_bytes(&[1u8; 32]);
        let tree = AuthorityTreeV1::new(vec![status(2, &owner), status(3, &owner), status(4, &owner)]);
        let root = tree.root(10);
        for index in [2u8, 3, 4] {
            let id = MemberId::from(&SigningKey::from_bytes(&[index; 32]).verifying_key());
            let proof = tree.proof(id).expect("a proof exists");
            proof.verify(&root).expect("the proof verifies");
        }
    }

    #[test]
    fn a_tampered_status_breaks_the_proof() {
        let owner = SigningKey::from_bytes(&[1u8; 32]);
        let tree = AuthorityTreeV1::new(vec![status(2, &owner), status(3, &owner)]);
        let root = tree.root(10);
        let id = MemberId::from(&SigningKey::from_bytes(&[2u8; 32]).verifying_key());
        let mut proof = tree.proof(id).unwrap();
        proof.status.member = member(9, &owner);
        assert!(proof.verify(&root).is_err());
    }

    #[test]
    fn a_member_outside_the_tree_has_no_proof() {
        let owner = SigningKey::from_bytes(&[1u8; 32]);
        let tree = AuthorityTreeV1::new(vec![status(2, &owner)]);
        let id = MemberId::from(&SigningKey::from_bytes(&[9u8; 32]).verifying_key());
        assert!(tree.proof(id).is_none());
    }

    #[test]
    fn a_signed_root_matches_the_board() {
        let owner = SigningKey::from_bytes(&[1u8; 32]);
        let mut state = ChatBoardStateV1::default();
        state.members.members.push(member(2, &owner));
        let tree = AuthorityTreeV1::from_board(&state);
        let mut root = tree.root(1);
        root.content_hash = tree.content_hash();
        let stored = AuthorityRootStateV1(Some(AuthorizedAuthorityRootV1::new(root, &owner)));
        let params = crate::board_state::ChatBoardParametersV1 {
            owner: owner.verifying_key(),
        };
        stored.verify(&state, &params).unwrap();
    }

    #[test]
    fn a_root_from_another_board_is_rejected() {
        let owner = SigningKey::from_bytes(&[1u8; 32]);
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let mut state = ChatBoardStateV1::default();
        state.members.members.push(member(2, &owner));
        let tree = AuthorityTreeV1::from_board(&state);
        let root = AuthorizedAuthorityRootV1::new(tree.root(1), &other);
        let params = crate::board_state::ChatBoardParametersV1 {
            owner: owner.verifying_key(),
        };
        assert!(root.verify(&params.owner).is_err());
    }

    #[test]
    fn a_stale_root_is_rejected() {
        let owner = SigningKey::from_bytes(&[1u8; 32]);
        let mut state = ChatBoardStateV1::default();
        state.members.members.push(member(2, &owner));
        let tree = AuthorityTreeV1::from_board(&state);
        let mut root = tree.root(1);
        root.content_hash = tree.content_hash();
        let stored = AuthorityRootStateV1(Some(AuthorizedAuthorityRootV1::new(root, &owner)));
        let params = crate::board_state::ChatBoardParametersV1 {
            owner: owner.verifying_key(),
        };
        state.members.members.push(member(3, &owner));
        assert!(stored.verify(&state, &params).is_err());
    }

    #[test]
    fn a_banned_non_member_gets_a_status_leaf() {
        use crate::board_state::ban::UserBan;
        let owner = SigningKey::from_bytes(&[1u8; 32]);
        let owner_id = MemberId::from(&owner.verifying_key());
        let target = member(2, &owner);
        let mut state = ChatBoardStateV1::default();
        state.bans.0.push(AuthorizedUserBan::new(
            UserBan {
                owner_member_id: owner_id,
                banned_at: SystemTime::UNIX_EPOCH,
                banned_user: target.member.id(),
                expires_at: None,
                target_member: Some(target.clone()),
                invite_chain: Vec::new(),
            },
            owner_id,
            &owner,
        ));
        let tree = AuthorityTreeV1::from_board(&state);
        let proof = tree.proof(target.member.id()).expect("the banned member has a leaf");
        assert_eq!(proof.status.bans.len(), 1);
    }

    #[test]
    fn a_board_status_contains_roles_and_bans_for_one_member() {
        let owner = SigningKey::from_bytes(&[1u8; 32]);
        let mut state = ChatBoardStateV1::default();
        state.members = MembersV1 {
            members: vec![member(2, &owner), member(3, &owner)],
        };
        let tree = AuthorityTreeV1::from_board(&state);
        assert_eq!(tree.statuses.len(), 2);
        let proof = tree
            .proof(MemberId::from(
                &SigningKey::from_bytes(&[2u8; 32]).verifying_key(),
            ))
            .unwrap();
        assert!(proof.status.roles.is_empty());
        assert!(proof.status.bans.is_empty());
    }
}
