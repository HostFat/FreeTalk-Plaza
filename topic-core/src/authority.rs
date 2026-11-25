//! Compact board authority for topics.
//!
//! A topic does not need every member, role and ban of the board. It needs the
//! authority records of its participants and moderators. The board authority is
//! committed to a Merkle root; each topic keeps the root and a proof for each
//! member it references. A role or ban change moves one leaf, and the topic
//! only needs that member's new proof.

use plaza_core::board_state::ban::{AuthorizedBanRevocation, AuthorizedUserBan};
use plaza_core::board_state::member::{AuthorizedMember, MemberId};
use plaza_core::board_state::member_moderation::AuthorizedSuspension;
use plaza_core::board_state::roles::{AuthorizedRole, AuthorizedRoleAssignment};
use plaza_core::ChatBoardStateV1;
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
    /// Monotonic client timestamp; a newer root wins when merging.
    pub epoch: i64,
    /// Hash of the authority content, so a sync can skip an unchanged set.
    #[serde(default)]
    pub content_hash: i64,
    pub digest: [u8; 32],
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
            statuses.push(MemberStatusV1 {
                member: member.clone(),
                roles,
                assignments,
                bans,
                revocations,
                suspensions,
            });
        }
        Self::new(statuses)
    }

    pub fn root(&self, epoch: i64) -> AuthorityRootV1 {
        AuthorityRootV1 {
            version: AUTHORITY_ROOT_VERSION,
            epoch,
            content_hash: 0,
            digest: *self
                .levels
                .last()
                .and_then(|level| level.first())
                .unwrap_or(&[0u8; 32]),
        }
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
    use plaza_core::board_state::member::{Member, MembersV1};
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
    fn a_banned_non_member_gets_a_status_leaf() {
        use plaza_core::board_state::ban::UserBan;
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
