//! Named roles and their members.
//!
//! Records are owner-signed and carry a generation, like admins: the highest
//! generation wins and a tombstone wins ties, so merging is order independent.

use crate::board_state::member::MemberId;
use crate::board_state::ChatBoardParametersV1;
use crate::util::{sign_struct, verify_struct};
use crate::ChatBoardStateV1;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use freenet_scaffold::ComposableState;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

pub type RoleId = [u8; 16];

/// Resolve the key that signed a management record: the owner, or a member of
/// the board.
pub(crate) fn signer_key(
    state: &ChatBoardStateV1,
    parameters: &ChatBoardParametersV1,
    signer: &MemberId,
) -> Result<VerifyingKey, String> {
    if *signer == parameters.owner_id() {
        return Ok(parameters.owner);
    }
    state
        .members
        .members
        .iter()
        .find(|m| m.member.id() == *signer)
        .map(|m| m.member.member_vk)
        .ok_or_else(|| "Signer is not a member of this board".to_string())
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct Role {
    pub id: RoleId,
    pub name: String,
    pub generation: u64,
    /// Members holding this role may create invite links and grant access.
    pub can_manage_access: bool,
    /// A deleted role grants nothing; the tombstone keeps the id reserved.
    pub deleted: bool,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedRole {
    pub role: Role,
    pub signature: Signature,
}

impl AuthorizedRole {
    pub fn new(role: Role, owner_sk: &SigningKey) -> Self {
        Self {
            signature: sign_struct(&role, owner_sk),
            role,
        }
    }

    pub fn verify_signature(&self, owner_vk: &VerifyingKey) -> Result<(), String> {
        verify_struct(&self.role, &self.signature, owner_vk)
            .map_err(|e| format!("Invalid role signature: {}", e))
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct RoleAssignment {
    pub role_id: RoleId,
    pub member_id: MemberId,
    pub generation: u64,
    pub revoked: bool,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedRoleAssignment {
    pub assignment: RoleAssignment,
    pub signature: Signature,
    /// Who signed it. `None` means the owner. Kept outside the signed payload so
    /// adding it does not invalidate records written before delegation existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<MemberId>,
}

impl AuthorizedRoleAssignment {
    pub fn new(assignment: RoleAssignment, owner_sk: &SigningKey) -> Self {
        Self {
            signature: sign_struct(&assignment, owner_sk),
            assignment,
            signer: None,
        }
    }

    /// A record signed by a member who manages access.
    pub fn signed_by(
        assignment: RoleAssignment,
        signer: MemberId,
        signing_key: &SigningKey,
    ) -> Self {
        Self {
            signature: sign_struct(&assignment, signing_key),
            assignment,
            signer: Some(signer),
        }
    }

    pub fn signer_id(&self, parameters: &ChatBoardParametersV1) -> MemberId {
        self.signer.unwrap_or_else(|| parameters.owner_id())
    }

    pub fn verify_signature(&self, owner_vk: &VerifyingKey) -> Result<(), String> {
        verify_struct(&self.assignment, &self.signature, owner_vk)
            .map_err(|e| format!("Invalid role assignment signature: {}", e))
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct RolesV1 {
    pub roles: Vec<AuthorizedRole>,
    pub assignments: Vec<AuthorizedRoleAssignment>,
}

impl ComposableState for RolesV1 {
    type ParentState = ChatBoardStateV1;
    type Summary = RolesSummary;
    type Delta = RolesDelta;
    type Parameters = ChatBoardParametersV1;

    fn verify(
        &self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
    ) -> Result<(), String> {
        let mut role_ids = std::collections::HashSet::new();
        for role in &self.roles {
            // Role definitions stay owner-only: a manager must not be able to
            // create a role that grants more access.
            role.verify_signature(&parameters.owner)?;
            if !role_ids.insert(role.role.id) {
                return Err("Duplicate role record".to_string());
            }
        }

        let mut assignment_keys = std::collections::HashSet::new();
        for assignment in &self.assignments {
            let signer = assignment.signer_id(parameters);
            if signer != parameters.owner_id() && !self.can_manage_access(&signer) {
                return Err("Role assignment signer cannot manage access".to_string());
            }
            let signing_key = signer_key(parent_state, parameters, &signer)?;
            verify_struct(&assignment.assignment, &assignment.signature, &signing_key)
                .map_err(|e| format!("Invalid role assignment signature: {}", e))?;

            let key = (
                assignment.assignment.role_id,
                assignment.assignment.member_id,
            );
            if !assignment_keys.insert(key) {
                return Err("Duplicate role assignment".to_string());
            }
        }

        Ok(())
    }

    fn summarize(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
    ) -> Self::Summary {
        let mut roles = BTreeMap::new();
        for role in &self.roles {
            roles.insert(
                role.role.id,
                RoleState {
                    generation: role.role.generation,
                    deleted: role.role.deleted,
                },
            );
        }
        let mut assignments = BTreeMap::new();
        for assignment in &self.assignments {
            assignments.insert(
                (
                    assignment.assignment.role_id,
                    assignment.assignment.member_id,
                ),
                AssignmentState {
                    generation: assignment.assignment.generation,
                    revoked: assignment.assignment.revoked,
                },
            );
        }
        RolesSummary { roles, assignments }
    }

    fn delta(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
        old_state_summary: &Self::Summary,
    ) -> Option<Self::Delta> {
        let roles = self
            .roles
            .iter()
            .filter(|r| {
                old_state_summary
                    .roles
                    .get(&r.role.id)
                    .map(|s| s.generation < r.role.generation)
                    .unwrap_or(true)
            })
            .cloned()
            .collect::<Vec<_>>();
        let assignments = self
            .assignments
            .iter()
            .filter(|a| {
                old_state_summary
                    .assignments
                    .get(&(a.assignment.role_id, a.assignment.member_id))
                    .map(|s| s.generation < a.assignment.generation)
                    .unwrap_or(true)
            })
            .cloned()
            .collect::<Vec<_>>();

        if roles.is_empty() && assignments.is_empty() {
            None
        } else {
            Some(RolesDelta { roles, assignments })
        }
    }

    fn apply_delta(
        &mut self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
        delta: &Option<Self::Delta>,
    ) -> Result<(), String> {
        if let Some(delta) = delta {
            // Definitions: owner only.
            for role in &delta.roles {
                role.verify_signature(&parameters.owner)?;
            }

            // Merge first, then validate assignments against the resulting
            // manager set: a grant and the manager's own assignment may arrive
            // in the same delta.
            let mut combined = self.clone();
            for role in &delta.roles {
                match combined.roles.iter().find(|r| r.role.id == role.role.id) {
                    Some(existing) if existing.role.generation >= role.role.generation => {}
                    _ => {
                        combined.roles.retain(|r| r.role.id != role.role.id);
                        combined.roles.push(role.clone());
                    }
                }
            }
            for assignment in &delta.assignments {
                let key = (
                    assignment.assignment.role_id,
                    assignment.assignment.member_id,
                );
                match combined
                    .assignments
                    .iter()
                    .find(|a| (a.assignment.role_id, a.assignment.member_id) == key)
                {
                    Some(existing)
                        if existing.assignment.generation > assignment.assignment.generation
                            || (existing.assignment.generation
                                == assignment.assignment.generation
                                && existing.assignment.revoked) => {}
                    _ => {
                        combined
                            .assignments
                            .retain(|a| (a.assignment.role_id, a.assignment.member_id) != key);
                        combined.assignments.push(assignment.clone());
                    }
                }
            }

            for assignment in &delta.assignments {
                let signer = assignment.signer_id(parameters);
                if signer != parameters.owner_id() && !combined.can_manage_access(&signer) {
                    return Err("Role assignment signer cannot manage access".to_string());
                }
                let signing_key = signer_key(parent_state, parameters, &signer)?;
                verify_struct(&assignment.assignment, &assignment.signature, &signing_key)
                    .map_err(|e| format!("Invalid role assignment signature: {}", e))?;
            }

            combined.roles.sort_by_key(|r| r.role.id);
            combined
                .assignments
                .sort_by_key(|a| (a.assignment.role_id, a.assignment.member_id));
            *self = combined;
        }

        Ok(())
    }
}

impl RolesV1 {
    /// Roles currently granted to a member, ignoring tombstones and revocations.
    pub fn active_roles_of(&self, member_id: &MemberId) -> Vec<&Role> {
        let mut result = Vec::new();
        for assignment in &self.assignments {
            if assignment.assignment.member_id != *member_id || assignment.assignment.revoked {
                continue;
            }
            if let Some(role) = self
                .roles
                .iter()
                .find(|r| r.role.id == assignment.assignment.role_id)
            {
                if !role.role.deleted {
                    result.push(&role.role);
                }
            }
        }
        result
    }

    pub fn role(&self, id: &RoleId) -> Option<&Role> {
        self.roles
            .iter()
            .find(|r| r.role.id == *id && !r.role.deleted)
            .map(|r| &r.role)
    }

    pub fn role_exists(&self, id: &RoleId) -> bool {
        self.role(id).is_some()
    }

    pub fn next_role_generation(&self, id: &RoleId) -> u64 {
        self.roles
            .iter()
            .find(|r| r.role.id == *id)
            .map(|r| r.role.generation + 1)
            .unwrap_or(1)
    }

    pub fn next_assignment_generation(&self, role_id: &RoleId, member_id: &MemberId) -> u64 {
        self.assignments
            .iter()
            .find(|a| a.assignment.role_id == *role_id && a.assignment.member_id == *member_id)
            .map(|a| a.assignment.generation + 1)
            .unwrap_or(1)
    }

    /// Whether the member may manage access (roles, invite links).
    pub fn can_manage_access(&self, member_id: &MemberId) -> bool {
        self.active_roles_of(member_id)
            .iter()
            .any(|role| role.can_manage_access)
    }

    /// Member ids per role, for role-based permissions and key distribution.
    pub fn members_of_role(&self, role_id: &RoleId) -> Vec<MemberId> {
        self.assignments
            .iter()
            .filter(|a| {
                a.assignment.role_id == *role_id
                    && !a.assignment.revoked
                    && self.role_exists(role_id)
            })
            .map(|a| a.assignment.member_id)
            .collect()
    }

    pub fn assignments_by_member(&self) -> HashMap<MemberId, Vec<&AuthorizedRoleAssignment>> {
        let mut map: HashMap<MemberId, Vec<&AuthorizedRoleAssignment>> = HashMap::new();
        for assignment in &self.assignments {
            map.entry(assignment.assignment.member_id)
                .or_default()
                .push(assignment);
        }
        map
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct RolesSummary {
    pub roles: BTreeMap<RoleId, RoleState>,
    pub assignments: BTreeMap<(RoleId, MemberId), AssignmentState>,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub struct RoleState {
    pub generation: u64,
    pub deleted: bool,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub struct AssignmentState {
    pub generation: u64,
    pub revoked: bool,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct RolesDelta {
    pub roles: Vec<AuthorizedRole>,
    pub assignments: Vec<AuthorizedRoleAssignment>,
}

#[cfg(test)]
mod delegation_tests {
    use super::*;
    use crate::board_state::configuration::{AuthorizedConfigurationV1, Configuration};
    use crate::board_state::member::{AuthorizedMember, Member};
    use freenet_scaffold::ComposableState;

    fn params(owner: &SigningKey) -> ChatBoardParametersV1 {
        ChatBoardParametersV1 {
            owner: owner.verifying_key(),
        }
    }

    /// Owner plus one member holding a role that may manage access.
    fn state_with_manager(owner: &SigningKey, manager_sk: &SigningKey) -> ChatBoardStateV1 {
        let owner_id = MemberId::from(&owner.verifying_key());
        let manager_id = MemberId::from(&manager_sk.verifying_key());

        let mut state = ChatBoardStateV1 {
            configuration: AuthorizedConfigurationV1::new(Configuration::default(), owner),
            ..Default::default()
        };
        state.members.members.push(AuthorizedMember::new(
            Member {
                owner_member_id: owner_id,
                invited_by: owner_id,
                member_vk: manager_sk.verifying_key(),
                join_proof: None,
            },
            owner,
        ));
        state.roles.roles.push(AuthorizedRole::new(
            Role {
                id: [5u8; 16],
                name: "staff".to_string(),
                generation: 1,
                can_manage_access: true,
                deleted: false,
            },
            owner,
        ));
        state.roles.assignments.push(AuthorizedRoleAssignment::new(
            RoleAssignment {
                role_id: [5u8; 16],
                member_id: manager_id,
                generation: 1,
                revoked: false,
            },
            owner,
        ));
        state
    }

    #[test]
    fn a_manager_can_assign_a_role() {
        let owner = SigningKey::from_bytes(&[1u8; 32]);
        let manager = SigningKey::from_bytes(&[7u8; 32]);
        let other = SigningKey::from_bytes(&[8u8; 32]);
        let params = params(&owner);
        let mut state = state_with_manager(&owner, &manager);

        let assignment = RoleAssignment {
            role_id: [5u8; 16],
            member_id: MemberId::from(&other.verifying_key()),
            generation: 1,
            revoked: false,
        };
        let delta = RolesDelta {
            roles: vec![],
            assignments: vec![AuthorizedRoleAssignment::signed_by(
                assignment,
                MemberId::from(&manager.verifying_key()),
                &manager,
            )],
        };

        state
            .roles
            .apply_delta(&state.clone(), &params, &Some(delta))
            .expect("manager may assign roles");
        state.verify(&state.clone(), &params).unwrap();
    }

    #[test]
    fn a_member_without_the_permission_cannot_assign() {
        let owner = SigningKey::from_bytes(&[1u8; 32]);
        let manager = SigningKey::from_bytes(&[7u8; 32]);
        let outsider = SigningKey::from_bytes(&[9u8; 32]);
        let target = SigningKey::from_bytes(&[8u8; 32]);
        let params = params(&owner);
        let mut state = state_with_manager(&owner, &manager);

        // Add the outsider as a plain member first.
        state.members.members.push(AuthorizedMember::new(
            Member {
                owner_member_id: MemberId::from(&owner.verifying_key()),
                invited_by: MemberId::from(&owner.verifying_key()),
                member_vk: outsider.verifying_key(),
                join_proof: None,
            },
            &owner,
        ));

        let assignment = RoleAssignment {
            role_id: [5u8; 16],
            member_id: MemberId::from(&target.verifying_key()),
            generation: 1,
            revoked: false,
        };
        let delta = RolesDelta {
            roles: vec![],
            assignments: vec![AuthorizedRoleAssignment::signed_by(
                assignment,
                MemberId::from(&outsider.verifying_key()),
                &outsider,
            )],
        };

        assert!(state
            .roles
            .apply_delta(&state.clone(), &params, &Some(delta))
            .is_err());
    }

    #[test]
    fn only_the_owner_can_define_roles() {
        let owner = SigningKey::from_bytes(&[1u8; 32]);
        let manager = SigningKey::from_bytes(&[7u8; 32]);
        let params = params(&owner);
        let mut state = state_with_manager(&owner, &manager);

        let role = Role {
            id: [6u8; 16],
            name: "sneaky".to_string(),
            generation: 1,
            can_manage_access: true,
            deleted: false,
        };
        let delta = RolesDelta {
            roles: vec![AuthorizedRole::new(role, &manager)],
            assignments: vec![],
        };
        assert!(state
            .roles
            .apply_delta(&state.clone(), &params, &Some(delta))
            .is_err());
    }
}
