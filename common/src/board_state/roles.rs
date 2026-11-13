//! Named roles and their members.
//!
//! Records are owner-signed and carry a generation, like admins: the highest
//! generation wins and a tombstone wins ties, so merging is order independent.

use crate::board_state::admin::AuthorizedAdmin;
use crate::board_state::member::MemberId;
use crate::board_state::message::MessageId;
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
/// Owner or a current board admin.
pub fn is_board_admin(state: &ChatBoardStateV1, member: &MemberId) -> bool {
    state
        .admin
        .admins
        .iter()
        .any(|admin| admin.admin.id() == *member)
}

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
    /// Members holding this role may sign per-category key distributions.
    /// Omitted at false so role records signed before the flag existed keep
    /// verifying byte for byte.
    #[serde(default, skip_serializing_if = "is_false")]
    pub can_distribute_keys: bool,
    /// Moderation powers. Each one can be enabled or disabled independently.
    #[serde(default, skip_serializing_if = "is_false")]
    pub can_edit_posts: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub can_delete_posts: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub can_close_posts: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub can_pin_posts: bool,
    /// Move, merge and split posts between sections.
    #[serde(default, skip_serializing_if = "is_false")]
    pub can_move_posts: bool,
    /// Sections where the moderation powers apply, including their
    /// subsections. Empty means the whole board.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scope: Vec<MessageId>,
    /// A deleted role grants nothing; the tombstone keeps the id reserved.
    pub deleted: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// Proof that a member was allowed to sign a management record when they did.
///
/// Authority is checked against the current state first. When the signer has
/// since lost their admin seat or role, this proof keeps the record verifiable:
/// the admin record is owner-signed, and the role grant carries the role
/// definition plus the signer's assignment, which recursively carry their own
/// proofs.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorityProof {
    /// Owner-signed record that appointed the signer as an admin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin: Option<AuthorizedAdmin>,
    /// Role definition and assignment that granted access management.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<Box<RoleGrantProof>>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct RoleGrantProof {
    pub role: AuthorizedRole,
    pub assignment: AuthorizedRoleAssignment,
}

/// Cap on nested authority proofs; each level is a signed grant.
const MAX_AUTHORITY_DEPTH: u8 = 8;

/// Resolve the key that signed a record: the board owner, the embedded key when
/// the record carries one, or the current member record.
pub fn resolve_signer_key(
    state: &ChatBoardStateV1,
    parameters: &ChatBoardParametersV1,
    signer: &MemberId,
    embedded: Option<&VerifyingKey>,
) -> Result<VerifyingKey, String> {
    if *signer == parameters.owner_id() {
        return Ok(parameters.owner);
    }
    if let Some(key) = embedded {
        return if MemberId::from(key) == *signer {
            Ok(*key)
        } else {
            Err("Embedded signer key does not match the signer".to_string())
        };
    }
    signer_key(state, parameters, signer)
}

/// Proof for a signer who is currently a board admin.
pub fn admin_authority_proof(
    state: &ChatBoardStateV1,
    signer: &MemberId,
) -> Option<AuthorityProof> {
    state
        .admin
        .admins
        .iter()
        .find(|admin| admin.admin.id() == *signer)
        .map(|admin| AuthorityProof {
            admin: Some(admin.clone()),
            grant: None,
        })
}

/// Proof for a signer who currently manages access through a role.
pub fn manager_authority_proof(
    state: &ChatBoardStateV1,
    signer: &MemberId,
) -> Option<AuthorityProof> {
    let assignment = state.roles.assignments.iter().find(|entry| {
        entry.assignment.member_id == *signer
            && !entry.assignment.revoked
            && state.roles.roles.iter().any(|role| {
                role.role.id == entry.assignment.role_id
                    && role.role.can_manage_access
                    && !role.role.deleted
            })
    })?;
    let role = state
        .roles
        .roles
        .iter()
        .find(|role| role.role.id == assignment.assignment.role_id)?;
    Some(AuthorityProof {
        admin: None,
        grant: Some(Box::new(RoleGrantProof {
            role: role.clone(),
            assignment: assignment.clone(),
        })),
    })
}

pub(crate) fn verify_admin_authority(
    state: &ChatBoardStateV1,
    parameters: &ChatBoardParametersV1,
    signer: &MemberId,
    proof: Option<&AuthorityProof>,
    depth: u8,
) -> Result<(), String> {
    if *signer == parameters.owner_id() || is_board_admin(state, signer) {
        return Ok(());
    }
    if depth == 0 {
        return Err("Authority proof is nested too deeply".to_string());
    }
    let proof = proof.ok_or("Signer is not an admin and carries no proof")?;
    if let Some(admin) = &proof.admin {
        admin.verify_signature(&parameters.owner)?;
        if admin.admin.id() == *signer {
            return Ok(());
        }
    }
    Err("Signer was not an admin when the record was signed".to_string())
}

pub(crate) fn verify_manager_authority(
    state: &ChatBoardStateV1,
    parameters: &ChatBoardParametersV1,
    signer: &MemberId,
    proof: Option<&AuthorityProof>,
    depth: u8,
) -> Result<(), String> {
    if *signer == parameters.owner_id() || state.roles.can_manage_access(signer) {
        return Ok(());
    }
    if depth == 0 {
        return Err("Authority proof is nested too deeply".to_string());
    }
    let proof = proof.ok_or("Signer cannot manage access and carries no proof")?;
    let grant = proof
        .grant
        .as_ref()
        .ok_or("Authority proof has no role grant")?;
    if grant.role.role.deleted || !grant.role.role.can_manage_access {
        return Err("The proof role does not grant access management".to_string());
    }
    if grant.assignment.assignment.role_id != grant.role.role.id
        || grant.assignment.assignment.member_id != *signer
        || grant.assignment.assignment.revoked
    {
        return Err("The proof assignment does not grant this role".to_string());
    }

    let role_signer = grant.role.signer_id(parameters);
    let role_key = resolve_signer_key(
        state,
        parameters,
        &role_signer,
        grant.role.signer_key.as_ref(),
    )?;
    grant.role.verify_signature_with(&role_key)?;
    verify_admin_authority(
        state,
        parameters,
        &role_signer,
        grant.role.authority.as_deref(),
        depth - 1,
    )?;

    let assign_signer = grant.assignment.signer_id(parameters);
    if assign_signer == *signer {
        return Err("The proof assignment is self-granted".to_string());
    }
    let assign_key = resolve_signer_key(
        state,
        parameters,
        &assign_signer,
        grant.assignment.signer_key.as_ref(),
    )?;
    verify_struct(
        &grant.assignment.assignment,
        &grant.assignment.signature,
        &assign_key,
    )
    .map_err(|e| format!("Invalid role assignment signature: {}", e))?;
    verify_manager_authority(
        state,
        parameters,
        &assign_signer,
        grant.assignment.authority.as_deref(),
        depth - 1,
    )
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedRole {
    pub role: Role,
    pub signature: Signature,
    /// Who signed it. `None` means the owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<MemberId>,
    /// Signer's public key, kept so the record still verifies after the member
    /// is pruned from the board. It must hash to `signer`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_key: Option<VerifyingKey>,
    /// Authority the signer held when the record was signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<Box<AuthorityProof>>,
}

impl AuthorizedRole {
    pub fn new(role: Role, owner_sk: &SigningKey) -> Self {
        Self {
            signature: sign_struct(&role, owner_sk),
            role,
            signer: None,
            signer_key: None,
            authority: None,
        }
    }

    /// A role definition signed by a board admin.
    pub fn signed_by(role: Role, signer: MemberId, signing_key: &SigningKey) -> Self {
        Self {
            signature: sign_struct(&role, signing_key),
            role,
            signer: Some(signer),
            signer_key: Some(signing_key.verifying_key()),
            authority: None,
        }
    }

    pub fn with_authority(mut self, proof: AuthorityProof) -> Self {
        self.authority = Some(Box::new(proof));
        self
    }

    pub fn with_optional_authority(mut self, proof: Option<AuthorityProof>) -> Self {
        if self.signer.is_some() {
            self.authority = proof.map(Box::new);
        }
        self
    }

    pub fn signer_id(&self, parameters: &ChatBoardParametersV1) -> MemberId {
        self.signer.unwrap_or_else(|| parameters.owner_id())
    }

    pub fn verify_signature(&self, owner_vk: &VerifyingKey) -> Result<(), String> {
        verify_struct(&self.role, &self.signature, owner_vk)
            .map_err(|e| format!("Invalid role signature: {}", e))
    }

    pub fn verify_signature_with(&self, signing_key: &VerifyingKey) -> Result<(), String> {
        verify_struct(&self.role, &self.signature, signing_key)
            .map_err(|e| format!("Invalid role signature: {}", e))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ModerationPower {
    Edit,
    Delete,
    Close,
    Pin,
    Move,
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
    /// Signer's public key, kept so the record still verifies after the member
    /// is pruned from the board. It must hash to `signer`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_key: Option<VerifyingKey>,
    /// Authority the signer held when the record was signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<Box<AuthorityProof>>,
}

impl AuthorizedRoleAssignment {
    pub fn new(assignment: RoleAssignment, owner_sk: &SigningKey) -> Self {
        Self {
            signature: sign_struct(&assignment, owner_sk),
            assignment,
            signer: None,
            signer_key: None,
            authority: None,
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
            signer_key: Some(signing_key.verifying_key()),
            authority: None,
        }
    }

    pub fn with_authority(mut self, proof: AuthorityProof) -> Self {
        self.authority = Some(Box::new(proof));
        self
    }

    pub fn with_optional_authority(mut self, proof: Option<AuthorityProof>) -> Self {
        if self.signer.is_some() {
            self.authority = proof.map(Box::new);
        }
        self
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
            // Owner and board admins may define roles. Managers cannot, so a
            // delegated access manager cannot grant itself moderation powers.
            // A proof keeps records signed by an admin who has since lost the
            // seat verifiable.
            let signer = role.signer_id(parameters);
            let signing_key =
                resolve_signer_key(parent_state, parameters, &signer, role.signer_key.as_ref())?;
            role.verify_signature_with(&signing_key)?;
            verify_admin_authority(
                parent_state,
                parameters,
                &signer,
                role.authority.as_deref(),
                MAX_AUTHORITY_DEPTH,
            )?;
            if !role_ids.insert(role.role.id) {
                return Err("Duplicate role record".to_string());
            }
        }

        let mut assignment_keys = std::collections::HashSet::new();
        for assignment in &self.assignments {
            let signer = assignment.signer_id(parameters);
            // Evaluating authority against the list that contains this record
            // would let a manager grant a role to themselves. Delegation to
            // another member is allowed; self-promotion is not.
            if signer != parameters.owner_id()
                && assignment.assignment.member_id == signer
                && !is_board_admin(parent_state, &signer)
            {
                return Err("A manager cannot assign a role to themselves".to_string());
            }
            let signing_key = resolve_signer_key(
                parent_state,
                parameters,
                &signer,
                assignment.signer_key.as_ref(),
            )?;
            verify_struct(&assignment.assignment, &assignment.signature, &signing_key)
                .map_err(|e| format!("Invalid role assignment signature: {}", e))?;
            verify_manager_authority(
                parent_state,
                parameters,
                &signer,
                assignment.authority.as_deref(),
                MAX_AUTHORITY_DEPTH,
            )?;

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
                    digest: record_digest(&role.role),
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
                    digest: record_digest(&assignment.assignment),
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
                    .map(|s| {
                        s.generation < r.role.generation
                            || (s.generation == r.role.generation
                                && s.digest != record_digest(&r.role))
                    })
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
                    .map(|s| {
                        s.generation < a.assignment.generation
                            || (s.generation == a.assignment.generation
                                && s.digest != record_digest(&a.assignment))
                    })
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
            // Definitions: owner or a current board admin.
            for role in &delta.roles {
                let signer = role.signer_id(parameters);
                if signer != parameters.owner_id() && !is_board_admin(parent_state, &signer) {
                    return Err("Role definition signer must be the owner or an admin".to_string());
                }
                let signing_key = signer_key(parent_state, parameters, &signer)?;
                role.verify_signature_with(&signing_key)?;
            }

            // Merge first, then validate assignments against the resulting
            // manager set: a grant and the manager's own assignment may arrive
            // in the same delta. Authorization is checked against the state
            // before the delta, so a manager cannot grant a role to themselves
            // and use that same grant to pass the check.
            for assignment in &delta.assignments {
                let signer = assignment.signer_id(parameters);
                if signer != parameters.owner_id() && !self.can_manage_access(&signer) {
                    return Err("Role assignment signer cannot manage access".to_string());
                }
                if signer != parameters.owner_id()
                    && assignment.assignment.member_id == signer
                    && !is_board_admin(parent_state, &signer)
                {
                    return Err("A manager cannot assign a role to themselves".to_string());
                }
                let signing_key = signer_key(parent_state, parameters, &signer)?;
                verify_struct(&assignment.assignment, &assignment.signature, &signing_key)
                    .map_err(|e| format!("Invalid role assignment signature: {}", e))?;
            }

            let mut combined = self.clone();
            for role in &delta.roles {
                match combined.roles.iter().find(|r| r.role.id == role.role.id) {
                    Some(existing)
                        if existing.role.generation > role.role.generation
                            || (existing.role.generation == role.role.generation
                                && record_digest(&existing.role) <= record_digest(&role.role)) => {}
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
                                && (existing.assignment.revoked
                                    || record_digest(&existing.assignment)
                                        <= record_digest(&assignment.assignment))) => {}
                    _ => {
                        combined
                            .assignments
                            .retain(|a| (a.assignment.role_id, a.assignment.member_id) != key);
                        combined.assignments.push(assignment.clone());
                    }
                }
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

    /// Whether the member may sign category key distributions.
    pub fn can_distribute_keys(&self, member_id: &MemberId) -> bool {
        self.active_roles_of(member_id)
            .iter()
            .any(|role| role.can_distribute_keys)
    }

    /// Whether a moderation power applies to a target whose category chain is
    /// `scope_chain` (the target section and its ancestors). An empty role
    /// scope means the whole board.
    pub fn has_moderation_power(
        &self,
        member_id: &MemberId,
        power: ModerationPower,
        scope_chain: &[MessageId],
    ) -> bool {
        self.active_roles_of(member_id).iter().any(|role| {
            let enabled = match power {
                ModerationPower::Edit => role.can_edit_posts,
                ModerationPower::Delete => role.can_delete_posts,
                ModerationPower::Close => role.can_close_posts,
                ModerationPower::Pin => role.can_pin_posts,
                ModerationPower::Move => role.can_move_posts,
            };
            enabled
                && (role.scope.is_empty()
                    || role
                        .scope
                        .iter()
                        .any(|scope_id| scope_chain.contains(scope_id)))
        })
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
    #[serde(default)]
    pub digest: i64,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub struct AssignmentState {
    pub generation: u64,
    pub revoked: bool,
    #[serde(default)]
    pub digest: i64,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct RolesDelta {
    pub roles: Vec<AuthorizedRole>,
    pub assignments: Vec<AuthorizedRoleAssignment>,
}

fn record_digest<T: serde::Serialize>(value: &T) -> i64 {
    let mut bytes = Vec::new();
    let _ = ciborium::ser::into_writer(value, &mut bytes);
    freenet_scaffold::util::fast_hash(&bytes).0
}

#[cfg(test)]
mod delegation_tests {
    use super::*;
    use crate::board_state::admin::{Admin, AuthorizedAdmin, AuthorizedAdminRevocation};
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
                can_distribute_keys: false,
                can_edit_posts: false,
                can_delete_posts: false,
                can_close_posts: false,
                can_pin_posts: false,
                can_move_posts: false,
                scope: Vec::new(),
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
    fn a_manager_cannot_assign_a_role_to_themselves() {
        let owner = SigningKey::from_bytes(&[1u8; 32]);
        let manager = SigningKey::from_bytes(&[7u8; 32]);
        let params = params(&owner);
        let mut state = state_with_manager(&owner, &manager);

        let role = Role {
            id: [6u8; 16],
            name: "moderator".to_string(),
            generation: 1,
            can_manage_access: false,
            can_distribute_keys: false,
            can_edit_posts: false,
            can_delete_posts: true,
            can_close_posts: false,
            can_pin_posts: false,
            can_move_posts: false,
            scope: Vec::new(),
            deleted: false,
        };
        state
            .roles
            .apply_delta(
                &state.clone(),
                &params,
                &Some(RolesDelta {
                    roles: vec![AuthorizedRole::new(role, &owner)],
                    assignments: vec![],
                }),
            )
            .expect("the owner defines the moderator role");

        let manager_id = MemberId::from(&manager.verifying_key());
        let assignment = RoleAssignment {
            role_id: [6u8; 16],
            member_id: manager_id,
            generation: 1,
            revoked: false,
        };
        let delta = RolesDelta {
            roles: vec![],
            assignments: vec![AuthorizedRoleAssignment::signed_by(
                assignment, manager_id, &manager,
            )],
        };
        assert!(
            state
                .roles
                .apply_delta(&state.clone(), &params, &Some(delta))
                .is_err(),
            "a manager must not promote themselves"
        );
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
            can_distribute_keys: false,
            can_edit_posts: false,
            can_delete_posts: false,
            can_close_posts: false,
            can_pin_posts: false,
            can_move_posts: false,
            scope: Vec::new(),
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

    fn member_record(sk: &SigningKey, owner_id: MemberId, owner: &SigningKey) -> AuthorizedMember {
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

    fn role_record(id: RoleId, name: &str, can_manage_access: bool) -> Role {
        Role {
            id,
            name: name.to_string(),
            generation: 1,
            can_manage_access,
            can_distribute_keys: false,
            can_edit_posts: false,
            can_delete_posts: false,
            can_close_posts: false,
            can_pin_posts: false,
            can_move_posts: false,
            scope: Vec::new(),
            deleted: false,
        }
    }

    #[test]
    fn admin_signed_role_verifies_after_the_admin_is_removed() {
        let owner = SigningKey::from_bytes(&[1u8; 32]);
        let admin_sk = SigningKey::from_bytes(&[6u8; 32]);
        let params = params(&owner);
        let owner_id = params.owner_id();
        let admin_id = MemberId::from(&admin_sk.verifying_key());

        let mut state = ChatBoardStateV1 {
            configuration: AuthorizedConfigurationV1::new(Configuration::default(), &owner),
            ..Default::default()
        };
        state
            .members
            .members
            .push(member_record(&admin_sk, owner_id, &owner));
        state.admin.admins.push(AuthorizedAdmin::new(
            Admin {
                member_id: admin_id,
                generation: 1,
            },
            &owner,
        ));

        let proof = admin_authority_proof(&state, &admin_id).expect("admin proof");
        state.roles.roles.push(
            AuthorizedRole::signed_by(role_record([9u8; 16], "staff", true), admin_id, &admin_sk)
                .with_authority(proof),
        );
        state.verify(&state.clone(), &params).unwrap();

        // The owner demotes the admin and the member record is pruned.
        state.admin.admins.clear();
        state
            .admin
            .revoked
            .push(AuthorizedAdminRevocation::new(admin_id, 2, &owner));
        state.members.members.clear();

        state
            .verify(&state.clone(), &params)
            .expect("historical admin proof keeps the role verifiable");
    }

    #[test]
    fn admin_signed_role_without_proof_fails_after_demotion() {
        let owner = SigningKey::from_bytes(&[1u8; 32]);
        let admin_sk = SigningKey::from_bytes(&[6u8; 32]);
        let params = params(&owner);
        let owner_id = params.owner_id();
        let admin_id = MemberId::from(&admin_sk.verifying_key());

        let mut state = ChatBoardStateV1 {
            configuration: AuthorizedConfigurationV1::new(Configuration::default(), &owner),
            ..Default::default()
        };
        state
            .members
            .members
            .push(member_record(&admin_sk, owner_id, &owner));
        state.roles.roles.push(AuthorizedRole::signed_by(
            role_record([9u8; 16], "staff", true),
            admin_id,
            &admin_sk,
        ));
        state.admin.admins.push(AuthorizedAdmin::new(
            Admin {
                member_id: admin_id,
                generation: 1,
            },
            &owner,
        ));
        state.verify(&state.clone(), &params).unwrap();

        state.admin.admins.clear();
        assert!(state.verify(&state.clone(), &params).is_err());
    }

    #[test]
    fn manager_assignment_verifies_after_the_manager_loses_the_role() {
        let owner = SigningKey::from_bytes(&[1u8; 32]);
        let manager = SigningKey::from_bytes(&[7u8; 32]);
        let other = SigningKey::from_bytes(&[8u8; 32]);
        let params = params(&owner);
        let owner_id = params.owner_id();
        let manager_id = MemberId::from(&manager.verifying_key());
        let other_id = MemberId::from(&other.verifying_key());

        let mut state = state_with_manager(&owner, &manager);
        state
            .members
            .members
            .push(member_record(&other, owner_id, &owner));

        let proof = manager_authority_proof(&state, &manager_id).expect("manager proof");
        state.roles.assignments.push(
            AuthorizedRoleAssignment::signed_by(
                RoleAssignment {
                    role_id: [5u8; 16],
                    member_id: other_id,
                    generation: 1,
                    revoked: false,
                },
                manager_id,
                &manager,
            )
            .with_authority(proof),
        );
        state.verify(&state.clone(), &params).unwrap();

        // Revoke the manager's own assignment, then prune the member.
        state
            .roles
            .assignments
            .retain(|a| a.assignment.member_id != manager_id);
        state.roles.assignments.push(AuthorizedRoleAssignment::new(
            RoleAssignment {
                role_id: [5u8; 16],
                member_id: manager_id,
                generation: 2,
                revoked: true,
            },
            &owner,
        ));
        state
            .members
            .members
            .retain(|m| m.member.id() != manager_id);

        state
            .verify(&state.clone(), &params)
            .expect("historical manager proof keeps the assignment verifiable");
    }

    /// The new permission must stay out of the signed bytes when it is off,
    /// so roles signed before it existed keep verifying.
    #[test]
    fn role_without_key_permission_roundtrips_unchanged() {
        let owner = SigningKey::from_bytes(&[1u8; 32]);
        let role = Role {
            id: [8u8; 16],
            name: "reader".to_string(),
            generation: 1,
            can_manage_access: false,
            can_distribute_keys: false,
            can_edit_posts: false,
            can_delete_posts: false,
            can_close_posts: false,
            can_pin_posts: false,
            can_move_posts: false,
            scope: Vec::new(),
            deleted: false,
        };

        let mut original = Vec::new();
        ciborium::into_writer(&role, &mut original).unwrap();
        assert!(!String::from_utf8_lossy(&original).contains("can_distribute_keys"));

        let decoded: Role = ciborium::from_reader(&original[..]).unwrap();
        let mut again = Vec::new();
        ciborium::into_writer(&decoded, &mut again).unwrap();
        assert_eq!(original, again);

        let signature = sign_struct(&role, &owner);
        assert!(verify_struct(&decoded, &signature, &owner.verifying_key()).is_ok());
    }
}
