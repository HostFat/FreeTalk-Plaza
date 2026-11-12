use crate::board_state::member::MemberId;
use crate::board_state::ChatBoardParametersV1;
use crate::util::{sign_struct, verify_struct};
use crate::ChatBoardStateV1;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use freenet_scaffold::ComposableState;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::fmt::Debug;
use std::hash::{Hash, Hasher};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, Default)]
pub struct AdminsV1 {
    pub admins: Vec<AuthorizedAdmin>,
    /// Owner-signed revocations. A revocation is permanent and wins over any
    /// admin record for the same member, so the outcome does not depend on the
    /// order in which peers merge.
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

        // Revocations win over admin records, so a state that still lists a
        // revoked member is not normalized.
        if self
            .admins
            .iter()
            .any(|a| self.revoked.iter().any(|r| r.id() == a.admin.id()))
        {
            return Err("Revoked members must not be listed as admins".to_string());
        }

        Ok(())
    }
    fn summarize(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
    ) -> Self::Summary {
        AdminsSummary {
            present: self.admins.iter().map(|m| m.admin.id()).collect(),
            revoked: self.revoked.iter().map(|r| r.id()).collect(),
        }
    }

    fn delta(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
        old_state_summary: &Self::Summary,
    ) -> Option<Self::Delta> {
        let added = self
            .admins
            .iter()
            .filter(|m| !old_state_summary.present.contains(&m.admin.id()))
            .cloned()
            .collect::<Vec<_>>();
        let revoked = self
            .revoked
            .iter()
            .filter(|r| !old_state_summary.revoked.contains(&r.id()))
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
            // Build a combined lookup map that includes both existing admins
            // AND admins being added in this delta. This is necessary because
            // during merge, a admin and their inviter may both be in the delta
            // (e.g., admin B invited by admin A, both being added from the
            // other state). Without this, verify would fail with "Inviter not found".
            let mut combined_admins_by_id = self.admins_by_member_id();
            for admin in &delta.added {
                combined_admins_by_id
                    .entry(admin.admin.id())
                    .or_insert(admin);
            }

            if combined_admins_by_id.len() > max_admins {
                return Err(format!(
                    "Too many admins after delta: {} > {}",
                    combined_admins_by_id.len(),
                    max_admins
                ));
            }

            let owner_id = parameters.owner_id();

            // Verify that all new admins have valid signatures and are not the owner
            for admin in &delta.added {
                if admin.admin.id() == owner_id {
                    return Err("Owner cannot be added as an admin".to_string());
                }
                admin.verify_signature(&parameters.owner)?;
            }

            // Add ALL new admins (deduplicated).
            // This ensures CRDT convergence: regardless of delta order, the same set of
            // admins will be kept.
            for admin in &delta.added {
                // Skip if this admin already exists
                if self.admins.iter().any(|m| m.admin.id() == admin.admin.id()) {
                    continue;
                }
                self.admins.push(admin.clone());
            }

            // Revocations are signed by the owner and win over admin records,
            // whatever order they arrive in.
            for revocation in &delta.revoked {
                revocation.verify_signature(&parameters.owner)?;
                if self.revoked.iter().any(|r| r.id() == revocation.id()) {
                    continue;
                }
                self.revoked.push(revocation.clone());
            }
            self.admins
                .retain(|admin| !self.revoked.iter().any(|r| r.id() == admin.admin.id()));
            self.revoked.sort_by_key(|r| r.id());
        }

        // Sort for deterministic ordering (CRDT convergence requirement)
        self.admins.sort_by_key(|m| m.admin.id());

        Ok(())
    }
}

impl AdminsV1 {
    /// Note: doesn't include owner
    pub fn admins_by_member_id(&self) -> HashMap<MemberId, &AuthorizedAdmin> {
        self.admins.iter().map(|m| (m.admin.id(), m)).collect()
    }

    /* /// Checks if there are any banned admins or admins downstream of banned admins in the invite chain
    pub fn has_banned_admins(&self, bans_v1: &BansV1, parameters: &ChatBoardParametersV1) -> bool {
        self.check_banned_admins(bans_v1, parameters).is_some()
    }

    /// Removes banned admins or admins downstream of banned admins in the invite chain
    fn remove_banned_admins(&mut self, bans_v1: &BansV1, _parameters: &ChatBoardParametersV1) {
        let mut banned_ids = HashSet::new();
        for ban in &bans_v1.0 {
            banned_ids.insert(ban.ban.banned_user);
            banned_ids.extend(self.get_downstream_admins(ban.ban.banned_user));
        }
        self.admins
            .retain(|m| !banned_ids.contains(&m.admin.id()));
    }

    /// Checks for banned admins and returns a set of admin IDs to be removed if any are found.
    /// Uses chain walking without Ed25519 verification since we only need to check adminship,
    /// not cryptographic validity.
    fn check_banned_admins(
        &self,
        bans_v1: &BansV1,
        parameters: &ChatBoardParametersV1,
    ) -> Option<HashSet<MemberId>> {
        let banned_user_ids: HashSet<MemberId> =
            bans_v1.0.iter().map(|b| b.ban.banned_user).collect();
        if banned_user_ids.is_empty() {
            return None;
        }

        let admins_by_id = self.admins_by_member_id();
        let owner_id = parameters.owner_id();
        let mut result = HashSet::new();

        for m in &self.admins {
            // Walk the invite chain without Ed25519 verification
            let chain_ids = Self::invite_chain_ids(m, owner_id, &admins_by_id);
            if chain_ids.iter().any(|id| banned_user_ids.contains(id)) {
                result.insert(m.admin.id());
            }
        }

        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }*/
    /// Whether the owner has revoked this member's admin rights.
    pub fn is_revoked(&self, member_id: &MemberId) -> bool {
        self.revoked.iter().any(|r| r.id() == *member_id)
    }

    /// Drop admin records whose member has been revoked. Used by the state
    /// cleanup so merges converge on the owner's decision.
    pub fn prune_revoked(&mut self) {
        if self.revoked.is_empty() {
            return;
        }
        self.admins
            .retain(|admin| !self.revoked.iter().any(|r| r.id() == admin.admin.id()));
    }
}

/// Summary of the admin state: who is an admin and who the owner has revoked.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct AdminsSummary {
    pub present: BTreeSet<MemberId>,
    pub revoked: BTreeSet<MemberId>,
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
    /// Use this when signing is done externally (e.g., via delegate).
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
}

impl fmt::Debug for Admin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Admin")
            .field("member_id", &format_args!("{}", self.member_id))
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
    pub fn new(member_id: MemberId, owner_sk: &SigningKey) -> Self {
        let revocation = AdminRevocation { member_id };
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

    #[test]
    fn owner_revocation_removes_the_admin_and_survives_merge_order() {
        let owner = owner_key();
        let admin_id = MemberId::from(member_key().verifying_key());
        let params = params(&owner);
        let parent = ChatBoardStateV1::default();

        let added = AuthorizedAdmin::new(
            Admin {
                member_id: admin_id,
            },
            &owner,
        );
        let revoked = AuthorizedAdminRevocation::new(admin_id, &owner);

        // Add, then revoke.
        let mut first = AdminsV1::default();
        first
            .apply_delta(&parent, &params, &Some(AdminsDelta::new(vec![added.clone()])))
            .unwrap();
        first
            .apply_delta(
                &parent,
                &params,
                &Some(AdminsDelta::revocation(vec![revoked.clone()])),
            )
            .unwrap();
        assert!(first.admins.is_empty());
        assert!(first.is_revoked(&admin_id));
        first.verify(&parent, &params).unwrap();

        // Revoke, then add: the revocation wins and the admin does not come back.
        let mut second = AdminsV1::default();
        second
            .apply_delta(
                &parent,
                &params,
                &Some(AdminsDelta::revocation(vec![revoked])),
            )
            .unwrap();
        second
            .apply_delta(&parent, &params, &Some(AdminsDelta::new(vec![added])))
            .unwrap();
        assert!(second.admins.is_empty());
        assert_eq!(first, second);
    }

    #[test]
    fn non_owner_revocation_is_rejected() {
        let owner = owner_key();
        let admin_id = MemberId::from(member_key().verifying_key());
        let imposter = SigningKey::from_bytes(&[3u8; 32]);
        let params = params(&owner);
        let parent = ChatBoardStateV1::default();

        let fake = AuthorizedAdminRevocation::new(admin_id, &imposter);
        let mut admins = AdminsV1::default();
        assert!(admins
            .apply_delta(
                &parent,
                &params,
                &Some(AdminsDelta::revocation(vec![fake])),
            )
            .is_err());
    }

    #[test]
    fn verify_rejects_an_admin_that_is_also_revoked() {
        let owner = owner_key();
        let admin_id = MemberId::from(member_key().verifying_key());
        let params = params(&owner);
        let parent = ChatBoardStateV1::default();

        let mut admins = AdminsV1 {
            admins: vec![AuthorizedAdmin::new(
                Admin {
                    member_id: admin_id,
                },
                &owner,
            )],
            revoked: vec![AuthorizedAdminRevocation::new(admin_id, &owner)],
        };
        assert!(admins.verify(&parent, &params).is_err());
        admins.prune_revoked();
        assert!(admins.admins.is_empty());
        admins.verify(&parent, &params).unwrap();
    }
}
