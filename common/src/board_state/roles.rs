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
}

impl AuthorizedRoleAssignment {
    pub fn new(assignment: RoleAssignment, owner_sk: &SigningKey) -> Self {
        Self {
            signature: sign_struct(&assignment, owner_sk),
            assignment,
        }
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
        _parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
    ) -> Result<(), String> {
        let mut role_ids = std::collections::HashSet::new();
        for role in &self.roles {
            role.verify_signature(&parameters.owner)?;
            if !role_ids.insert(role.role.id) {
                return Err("Duplicate role record".to_string());
            }
        }

        let mut assignment_keys = std::collections::HashSet::new();
        for assignment in &self.assignments {
            assignment.verify_signature(&parameters.owner)?;
            let key = (assignment.assignment.role_id, assignment.assignment.member_id);
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
                (assignment.assignment.role_id, assignment.assignment.member_id),
                AssignmentState {
                    generation: assignment.assignment.generation,
                    revoked: assignment.assignment.revoked,
                },
            );
        }
        RolesSummary {
            roles,
            assignments,
        }
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
            Some(RolesDelta {
                roles,
                assignments,
            })
        }
    }

    fn apply_delta(
        &mut self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
        delta: &Option<Self::Delta>,
    ) -> Result<(), String> {
        if let Some(delta) = delta {
            for role in &delta.roles {
                role.verify_signature(&parameters.owner)?;
                match self.roles.iter().find(|r| r.role.id == role.role.id) {
                    Some(existing) if existing.role.generation >= role.role.generation => continue,
                    _ => {}
                }
                self.roles.retain(|r| r.role.id != role.role.id);
                self.roles.push(role.clone());
            }

            for assignment in &delta.assignments {
                assignment.verify_signature(&parameters.owner)?;
                let key = (
                    assignment.assignment.role_id,
                    assignment.assignment.member_id,
                );
                match self.assignments.iter().find(|a| {
                    (a.assignment.role_id, a.assignment.member_id) == key
                }) {
                    Some(existing)
                        if existing.assignment.generation > assignment.assignment.generation
                            || (existing.assignment.generation
                                == assignment.assignment.generation
                                && existing.assignment.revoked) =>
                    {
                        continue
                    }
                    _ => {}
                }
                self.assignments.retain(|a| {
                    (a.assignment.role_id, a.assignment.member_id) != key
                });
                self.assignments.push(assignment.clone());
            }

            self.roles.sort_by_key(|r| r.role.id);
            self.assignments.sort_by_key(|a| {
                (a.assignment.role_id, a.assignment.member_id)
            });
        }

        let _ = parent_state;
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
            .find(|a| {
                a.assignment.role_id == *role_id && a.assignment.member_id == *member_id
            })
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
