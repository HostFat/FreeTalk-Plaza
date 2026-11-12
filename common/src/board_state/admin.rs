use crate::board_state::member::MemberId;
use crate::board_state::ChatBoardParametersV1;
use crate::util::{sign_struct, verify_struct};
use crate::ChatBoardStateV1;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use freenet_scaffold::ComposableState;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::hash::{Hash, Hasher};

/// Admin records plus the owner's revocations.
///
/// Every record carries a generation chosen by the owner. For a member the
/// highest generation decides: an admin record grants the rights, a revocation
/// removes them, and on a tie the revocation wins. Merging is therefore order
/// independent, and the owner can still re-add someone after revoking them by
/// issuing a higher generation.
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, Default)]
pub struct AdminsV1 {
    pub admins: Vec<AuthorizedAdmin>,
    #[serde(default)]
    pub revoked: Vec<AuthorizedAdminRevocation>,
}

impl ComposableState for AdminsV1 {
    type ParentState = ChatBoardStateV1;
    type Summary = AdminsSummary;
    type Delta = AdminsDelta;
    type Parameters = ChatBoardParametersV1;

    fn verify(
        &self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
    ) -> Result<(), String> {
        let owner_id = parameters.owner_id();

        if !self.admins.is_empty() {
            if self.admins.len() > parent_state.configuration.configuration.max_admins {
                return Err(format!(
                    "Too many admins: {} > {}",
                    self.admins.len(),
                    parent_state.configuration.configuration.max_admins
                ));
            }

            for admin in &self.admins {
                if admin.admin.id() == owner_id {
                    return Err("Owner should not be included in the admins list".to_string());
                }

                admin.verify_signature(&parameters.owner)?;
            }
        }

        for revocation in &self.revoked {
            revocation.verify_signature(&parameters.owner)?;
        }

        // One record per member: the winner is decided by generation when the
        // lists are merged, so a normalized state has no member in both.
        for admin in &self.admins {
            if self.revoked.iter().any(|r| r.id() == admin.admin.id()) {
                return Err("A member cannot be both admin and revoked".to_string());
            }
        }

        let mut seen = std::collections::HashSet::new();
        if !self.admins.iter().all(|a| seen.insert(a.admin.id())) {
            return Err("Duplicate admin records".to_string());
        }
        seen.clear();
        if !self.revoked.iter().all(|r| seen.insert(r.id())) {
            return Err("Duplicate revocation records".to_string());
        }

        Ok(())
    }

    fn summarize(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
    ) -> Self::Summary {
        let mut records = BTreeMap::new();
        for admin in &self.admins {
            records.insert(
                admin.admin.id(),
                AdminRecordState {
                    generation: admin.admin.generation,
                    revoked: false,
                },
            );
        }
        for revocation in &self.revoked {
            records.insert(
                revocation.id(),
                AdminRecordState {
                    generation: revocation.revocation.generation,
                    revoked: true,
                },
            );
        }
        AdminsSummary { records }
    }

    fn delta(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
        old_state_summary: &Self::Summary,
    ) -> Option<Self::Delta> {
        // Send a record when the peer's summary does not already reflect it.
        let is_known = |member: &MemberId, generation: u64, revoked: bool| {
            old_state_summary
                .records
                .get(member)
                .map(|r| r.generation >= generation && r.revoked == revoked)
                .unwrap_or(false)
        };

        let added = self
            .admins
            .iter()
            .filter(|a| !is_known(&a.admin.id(), a.admin.generation, false))
            .cloned()
            .collect::<Vec<_>>();
        let revoked = self
            .revoked
            .iter()
            .filter(|r| !is_known(&r.id(), r.revocation.generation, true))
            .cloned()
            .collect::<Vec<_>>();

        if added.is_empty() && revoked.is_empty() {
            None
        } else {
            Some(AdminsDelta { added, revoked })
        }
    }

    fn apply_delta(
        &mut self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
        delta: &Option<Self::Delta>,
    ) -> Result<(), String> {
        let max_admins = parent_state.configuration.configuration.max_admins;

        if let Some(delta) = delta {
            let owner_id = parameters.owner_id();

            for admin in &delta.added {
                if admin.admin.id() == owner_id {
                    return Err("Owner cannot be added as an admin".to_string());
                }
                admin.verify_signature(&parameters.owner)?;
            }
            for revocation in &delta.revoked {
                revocation.verify_signature(&parameters.owner)?;
            }

            for admin in &delta.added {
                let incoming = admin.admin.generation;
                match self.record_for(&admin.admin.id()) {
                    Some((local, revoked)) if revoked => {
                        // A revocation only gives way to a strictly newer grant.
                        if incoming <= local {
                            continue;
                        }
                    }
                    Some((local, _)) if incoming <= local => continue,
                    _ => {}
                }
                self.remove_records_for(&admin.admin.id());
                self.admins.push(admin.clone());
            }

            for revocation in &delta.revoked {
                let incoming = revocation.revocation.generation;
                match self.record_for(&revocation.id()) {
                    Some((local, false)) if incoming < local => continue,
                    Some((local, true)) if incoming <= local => continue,
                    _ => {}
                }
                self.remove_records_for(&revocation.id());
                self.revoked.push(revocation.clone());
            }

            if self.admins.len() > max_admins {
                return Err(format!(
                    "Too many admins after delta: {} > {}",
                    self.admins.len(),
                    max_admins
                ));
            }

            // Deterministic ordering for CRDT convergence.
            self.admins.sort_by_key(|a| a.admin.id());
            self.revoked.sort_by_key(|r| r.id());
        }

        Ok(())
    }
}

impl AdminsV1 {
    /// Note: doesn't include the owner.
    pub fn admins_by_member_id(&self) -> HashMap<MemberId, &AuthorizedAdmin> {
        self.admins.iter().map(|m| (m.admin.id(), m)).collect()
    }

    /// The winning record for a member: (generation, is_revocation).
    pub fn record_for(&self, member_id: &MemberId) -> Option<(u64, bool)> {
        if let Some(admin) = self.admins.iter().find(|a| a.admin.id() == *member_id) {
            return Some((admin.admin.generation, false));
        }
        self.revoked
            .iter()
            .find(|r| r.id() == *member_id)
            .map(|r| (r.revocation.generation, true))
    }

    pub fn is_revoked(&self, member_id: &MemberId) -> bool {
        self.revoked.iter().any(|r| r.id() == *member_id)
    }

    /// Generation the owner should use for the next change to this member.
    pub fn next_generation(&self, member_id: &MemberId) -> u64 {
        self.record_for(member_id)
            .map(|(generation, _)| generation + 1)
            .unwrap_or(1)
    }

    fn remove_records_for(&mut self, member_id: &MemberId) {
        self.admins.retain(|a| a.admin.id() != *member_id);
        self.revoked.retain(|r| r.id() != *member_id);
    }

    /// Keep only the winning record per member. Used by the state cleanup so
    /// merged states stay normalized.
    pub fn resolve_conflicts(&mut self) {
        let mut conflicts: Vec<MemberId> = self
            .admins
            .iter()
            .filter(|a| self.revoked.iter().any(|r| r.id() == a.admin.id()))
            .map(|a| a.admin.id())
            .collect();
        conflicts.sort();
        conflicts.dedup();

        for member_id in conflicts {
            let admin = self
                .admins
                .iter()
                .find(|a| a.admin.id() == member_id)
                .cloned();
            let revocation = self
                .revoked
                .iter()
                .find(|r| r.id() == member_id)
                .cloned();
            self.remove_records_for(&member_id);

            if let (Some(admin), Some(revocation)) = (admin, revocation) {
                // On a tie the revocation wins, matching apply_delta.
                if revocation.revocation.generation >= admin.admin.generation {
                    self.revoked.push(revocation);
                } else {
                    self.admins.push(admin);
                }
            }
        }

        self.admins.sort_by_key(|a| a.admin.id());
        self.revoked.sort_by_key(|r| r.id());
    }
}

/// Summary of the admin state: the winning record for every member.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct AdminsSummary {
    pub records: BTreeMap<MemberId, AdminRecordState>,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub struct AdminRecordState {
    pub generation: u64,
    pub revoked: bool,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug)]
pub struct AdminsDelta {
    added: Vec<AuthorizedAdmin>,
    #[serde(default)]
    revoked: Vec<AuthorizedAdminRevocation>,
}

impl AdminsDelta {
    pub fn new(added: Vec<AuthorizedAdmin>) -> Self {
        AdminsDelta {
            added,
            revoked: Vec::new(),
        }
    }

    /// A delta that only revokes an admin. Requires the owner's signature.
    pub fn revocation(revoked: Vec<AuthorizedAdminRevocation>) -> Self {
        AdminsDelta {
            added: Vec::new(),
            revoked,
        }
    }
}

// TODO: need to generalize to support multiple authorization mechanisms such as ghost keys

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug)]
pub struct AuthorizedAdmin {
    pub admin: Admin,
    pub signature: Signature,
}

impl AuthorizedAdmin {
    pub fn new(admin: Admin, owner_vk: &SigningKey) -> Self {
        Self {
            admin: admin.clone(),
            signature: sign_struct(&admin, owner_vk),
        }
    }

    /// Create an AuthorizedAdmin with a pre-computed signature.
    pub fn with_signature(admin: Admin, signature: Signature) -> Self {
        Self { admin, signature }
    }

    pub fn verify_signature(&self, owner_vk: &VerifyingKey) -> Result<(), String> {
        verify_struct(&self.admin, &self.signature, owner_vk)
            .map_err(|e| format!("Invalid signature: {}", e))
    }
}

impl Hash for AuthorizedAdmin {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.admin.hash(state);
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Hash, Clone)]
pub struct Admin {
    pub member_id: MemberId,
    /// Owner-chosen generation. Higher generations supersede lower ones.
    #[serde(default)]
    pub generation: u64,
}

impl fmt::Debug for Admin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Admin")
            .field("member_id", &format_args!("{}", self.member_id))
            .field("generation", &self.generation)
            .finish()
    }
}

impl Admin {
    pub fn id(&self) -> MemberId {
        self.member_id.into()
    }
}

/// Revocation of a member's admin rights. Only the board owner can issue one.
#[derive(Serialize, Deserialize, Eq, PartialEq, Hash, Clone, Copy, Debug)]
pub struct AdminRevocation {
    pub member_id: MemberId,
    #[serde(default)]
    pub generation: u64,
}

impl AdminRevocation {
    pub fn id(&self) -> MemberId {
        self.member_id
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug)]
pub struct AuthorizedAdminRevocation {
    pub revocation: AdminRevocation,
    pub signature: Signature,
}

impl AuthorizedAdminRevocation {
    pub fn new(member_id: MemberId, generation: u64, owner_sk: &SigningKey) -> Self {
        let revocation = AdminRevocation {
            member_id,
            generation,
        };
        Self {
            signature: sign_struct(&revocation, owner_sk),
            revocation,
        }
    }

    /// Create one with a pre-computed signature (e.g. produced by the delegate).
    pub fn with_signature(revocation: AdminRevocation, signature: Signature) -> Self {
        Self {
            revocation,
            signature,
        }
    }

    pub fn id(&self) -> MemberId {
        self.revocation.id()
    }

    pub fn verify_signature(&self, owner_vk: &VerifyingKey) -> Result<(), String> {
        verify_struct(&self.revocation, &self.signature, owner_vk)
            .map_err(|e| format!("Invalid revocation signature: {}", e))
    }
}

#[cfg(test)]
mod revocation_tests {
    use super::*;

    fn owner_key() -> SigningKey {
        SigningKey::from_bytes(&[1u8; 32])
    }

    fn member_key() -> SigningKey {
        SigningKey::from_bytes(&[2u8; 32])
    }

    fn params(owner: &SigningKey) -> ChatBoardParametersV1 {
        ChatBoardParametersV1 {
            owner: owner.verifying_key(),
        }
    }

    fn grant(member_id: MemberId, generation: u64, owner: &SigningKey) -> AuthorizedAdmin {
        AuthorizedAdmin::new(
            Admin {
                member_id,
                generation,
            },
            owner,
        )
    }

    #[test]
    fn revoke_then_readd_with_a_newer_generation() {
        let owner = owner_key();
        let admin_id = MemberId::from(member_key().verifying_key());
        let params = params(&owner);
        let parent = ChatBoardStateV1::default();

        let mut admins = AdminsV1::default();
        admins
            .apply_delta(&parent, &params, &Some(AdminsDelta::new(vec![grant(admin_id, 1, &owner)])))
            .unwrap();
        assert_eq!(admins.admins.len(), 1);
        assert_eq!(admins.next_generation(&admin_id), 2);

        admins
            .apply_delta(
                &parent,
                &params,
                &Some(AdminsDelta::revocation(vec![AuthorizedAdminRevocation::new(
                    admin_id, 2, &owner,
                )])),
            )
            .unwrap();
        assert!(admins.admins.is_empty());
        assert!(admins.is_revoked(&admin_id));
        admins.verify(&parent, &params).unwrap();

        admins
            .apply_delta(&parent, &params, &Some(AdminsDelta::new(vec![grant(admin_id, 3, &owner)])))
            .unwrap();
        assert_eq!(admins.admins.len(), 1);
        assert!(!admins.is_revoked(&admin_id));
        admins.verify(&parent, &params).unwrap();
    }

    #[test]
    fn stale_records_are_ignored_in_both_orders() {
        let owner = owner_key();
        let admin_id = MemberId::from(member_key().verifying_key());
        let params = params(&owner);
        let parent = ChatBoardStateV1::default();

        let revocation = AuthorizedAdminRevocation::new(admin_id, 2, &owner);
        let grant_v3 = grant(admin_id, 3, &owner);

        // Revocation first, then the newer grant.
        let mut a = AdminsV1::default();
        a.apply_delta(&parent, &params, &Some(AdminsDelta::revocation(vec![revocation.clone()])))
            .unwrap();
        a.apply_delta(&parent, &params, &Some(AdminsDelta::new(vec![grant_v3.clone()])))
            .unwrap();

        // The reverse order must converge to the same state.
        let mut b = AdminsV1::default();
        b.apply_delta(&parent, &params, &Some(AdminsDelta::new(vec![grant_v3])))
            .unwrap();
        b.apply_delta(&parent, &params, &Some(AdminsDelta::revocation(vec![revocation])))
            .unwrap();

        assert_eq!(a, b);
        assert_eq!(a.admins.len(), 1);
        assert!(a.revoked.is_empty());
    }

    #[test]
    fn an_older_grant_does_not_beat_a_revocation() {
        let owner = owner_key();
        let admin_id = MemberId::from(member_key().verifying_key());
        let params = params(&owner);
        let parent = ChatBoardStateV1::default();

        let mut admins = AdminsV1::default();
        admins
            .apply_delta(
                &parent,
                &params,
                &Some(AdminsDelta::revocation(vec![AuthorizedAdminRevocation::new(
                    admin_id, 5, &owner,
                )])),
            )
            .unwrap();
        admins
            .apply_delta(&parent, &params, &Some(AdminsDelta::new(vec![grant(admin_id, 4, &owner)])))
            .unwrap();

        assert!(admins.admins.is_empty());
        assert!(admins.is_revoked(&admin_id));
        admins.verify(&parent, &params).unwrap();
    }

    #[test]
    fn non_owner_revocations_are_rejected() {
        let owner = owner_key();
        let admin_id = MemberId::from(member_key().verifying_key());
        let imposter = SigningKey::from_bytes(&[3u8; 32]);
        let params = params(&owner);
        let parent = ChatBoardStateV1::default();

        let fake = AuthorizedAdminRevocation::new(admin_id, 1, &imposter);
        let mut admins = AdminsV1::default();
        assert!(admins
            .apply_delta(&parent, &params, &Some(AdminsDelta::revocation(vec![fake])))
            .is_err());
    }
}
