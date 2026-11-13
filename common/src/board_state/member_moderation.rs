//! Warnings and temporary suspensions addressed to one member.
//!
//! Both are public signed records. The contract checks who may issue them and
//! that the target is a current member. A suspension is a client-side block:
//! the contract cannot use wall-clock time deterministically, so clients stop a
//! suspended member from posting until `until` instead of removing them.

use crate::board_state::member::MemberId;
use crate::board_state::message::MessageId;
use crate::board_state::reports::ReportReason;
use crate::board_state::roles::{resolve_signer_key, AuthorityProof};
use crate::board_state::ChatBoardParametersV1;
use crate::util::{sign_struct, verify_struct};
use crate::ChatBoardStateV1;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use freenet_scaffold::util::fast_hash;
use freenet_scaffold::ComposableState;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

/// Old warnings over this limit are dropped deterministically.
pub const MAX_WARNINGS_PER_MEMBER: usize = 20;

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct WarningV1 {
    pub target: MemberId,
    pub reason: ReportReason,
    pub created_at: i64,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedWarning {
    pub warning: WarningV1,
    pub signature: Signature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<MemberId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_key: Option<VerifyingKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<Box<AuthorityProof>>,
}

impl AuthorizedWarning {
    pub fn new(warning: WarningV1, signing_key: &SigningKey) -> Self {
        Self {
            signature: sign_struct(&warning, signing_key),
            warning,
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

    pub fn id(&self) -> MessageId {
        MessageId(fast_hash(&self.signature.to_bytes()))
    }

    pub fn verify_signature_with(&self, key: &VerifyingKey) -> Result<(), String> {
        verify_struct(&self.warning, &self.signature, key)
            .map_err(|e| format!("Invalid warning signature: {}", e))
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct WarningsV1 {
    pub warnings: Vec<AuthorizedWarning>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct WarningState {
    pub count: usize,
    pub newest: i64,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct WarningsSummary {
    pub warnings: BTreeMap<MemberId, WarningState>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct WarningsDelta {
    #[serde(default)]
    pub warnings: Vec<AuthorizedWarning>,
}

fn warning_map(warnings: &[AuthorizedWarning]) -> BTreeMap<MemberId, WarningState> {
    let mut map: BTreeMap<MemberId, WarningState> = BTreeMap::new();
    for entry in warnings {
        let state = map.entry(entry.warning.target).or_default();
        state.count += 1;
        state.newest = state.newest.max(entry.warning.created_at);
    }
    map
}

fn verify_warning(
    state: &ChatBoardStateV1,
    parameters: &ChatBoardParametersV1,
    entry: &AuthorizedWarning,
) -> Result<(), String> {
    let signer = entry.signer_id(parameters);
    let key = resolve_signer_key(state, parameters, &signer, entry.signer_key.as_ref())?;
    entry.verify_signature_with(&key)?;
    crate::board_state::roles::verify_admin_authority(
        state,
        parameters,
        &signer,
        entry.authority.as_deref(),
        8,
    )
    .map_err(|_| "Only the owner or an admin can warn a member".to_string())?;
    if entry.warning.target == parameters.owner_id() {
        return Err("The owner cannot be warned".to_string());
    }
    if !state
        .members
        .members
        .iter()
        .any(|member| member.member.id() == entry.warning.target)
    {
        return Err("Warning targets a member who is not on this board".to_string());
    }
    Ok(())
}

impl WarningsV1 {
    pub fn count_for(&self, member: MemberId) -> usize {
        self.warnings
            .iter()
            .filter(|entry| entry.warning.target == member)
            .count()
    }

    pub fn for_member(&self, member: MemberId) -> Vec<&AuthorizedWarning> {
        let mut list: Vec<&AuthorizedWarning> = self
            .warnings
            .iter()
            .filter(|entry| entry.warning.target == member)
            .collect();
        list.sort_by_key(|entry| std::cmp::Reverse(entry.warning.created_at));
        list
    }

    pub fn cleanup(&mut self, state: &ChatBoardStateV1, parameters: &ChatBoardParametersV1) {
        self.warnings.retain(|entry| {
            entry.warning.target != parameters.owner_id()
                && state
                    .members
                    .members
                    .iter()
                    .any(|member| member.member.id() == entry.warning.target)
                && verify_warning(state, parameters, entry).is_ok()
        });
        self.warnings.sort_by_key(|entry| entry.id().0 .0);
        self.warnings.dedup_by_key(|entry| entry.id());

        // Keep the newest warnings for each member.
        let mut per_member: HashMap<MemberId, Vec<MessageId>> = HashMap::new();
        for entry in &self.warnings {
            per_member
                .entry(entry.warning.target)
                .or_default()
                .push(entry.id());
        }
        let mut keep: HashSet<MessageId> = HashSet::new();
        for ids in per_member.values() {
            if ids.len() <= MAX_WARNINGS_PER_MEMBER {
                keep.extend(ids.iter().copied());
                continue;
            }
            let mut entries: Vec<&AuthorizedWarning> = self
                .warnings
                .iter()
                .filter(|entry| ids.contains(&entry.id()))
                .collect();
            entries.sort_by_key(|entry| {
                (std::cmp::Reverse(entry.warning.created_at), entry.id().0 .0)
            });
            keep.extend(
                entries
                    .iter()
                    .take(MAX_WARNINGS_PER_MEMBER)
                    .map(|entry| entry.id()),
            );
        }
        self.warnings.retain(|entry| keep.contains(&entry.id()));
        self.warnings.sort_by_key(|entry| entry.id().0 .0);
    }
}

impl ComposableState for WarningsV1 {
    type ParentState = ChatBoardStateV1;
    type Summary = WarningsSummary;
    type Delta = WarningsDelta;
    type Parameters = ChatBoardParametersV1;

    fn verify(
        &self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
    ) -> Result<(), String> {
        let mut ids = HashSet::new();
        for entry in &self.warnings {
            if !ids.insert(entry.id()) {
                return Err("Duplicate warning".to_string());
            }
            verify_warning(parent_state, parameters, entry)?;
        }
        Ok(())
    }

    fn summarize(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
    ) -> Self::Summary {
        WarningsSummary {
            warnings: warning_map(&self.warnings),
        }
    }

    fn delta(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
        _old_state: &Self::Summary,
    ) -> Option<Self::Delta> {
        if self.warnings.is_empty() {
            None
        } else {
            Some(WarningsDelta {
                warnings: self.warnings.clone(),
            })
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
        for entry in &delta.warnings {
            verify_warning(parent_state, parameters, entry)?;
            if !self
                .warnings
                .iter()
                .any(|existing| existing.id() == entry.id())
            {
                self.warnings.push(entry.clone());
            }
        }
        self.warnings.sort_by_key(|entry| entry.id().0 .0);
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct SuspensionV1 {
    pub target: MemberId,
    pub reason: ReportReason,
    pub until: i64,
    pub created_at: i64,
    pub generation: u64,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedSuspension {
    pub suspension: SuspensionV1,
    pub signature: Signature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<MemberId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_key: Option<VerifyingKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<Box<AuthorityProof>>,
}

impl AuthorizedSuspension {
    pub fn new(suspension: SuspensionV1, signing_key: &SigningKey) -> Self {
        Self {
            signature: sign_struct(&suspension, signing_key),
            suspension,
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

    pub fn verify_signature_with(&self, key: &VerifyingKey) -> Result<(), String> {
        verify_struct(&self.suspension, &self.signature, key)
            .map_err(|e| format!("Invalid suspension signature: {}", e))
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct SuspensionsV1 {
    pub suspensions: Vec<AuthorizedSuspension>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct SuspensionState {
    pub until: i64,
    pub generation: u64,
    #[serde(default)]
    pub digest: i64,
}

fn record_digest<T: serde::Serialize>(value: &T) -> i64 {
    let mut bytes = Vec::new();
    let _ = ciborium::ser::into_writer(value, &mut bytes);
    freenet_scaffold::util::fast_hash(&bytes).0
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct SuspensionsSummary {
    pub suspensions: BTreeMap<MemberId, SuspensionState>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct SuspensionsDelta {
    #[serde(default)]
    pub suspensions: Vec<AuthorizedSuspension>,
}

fn suspension_map(suspensions: &[AuthorizedSuspension]) -> BTreeMap<MemberId, SuspensionState> {
    suspensions
        .iter()
        .map(|entry| {
            (
                entry.suspension.target,
                SuspensionState {
                    until: entry.suspension.until,
                    generation: entry.suspension.generation,
                    digest: record_digest(&entry.suspension),
                },
            )
        })
        .collect()
}

fn verify_suspension(
    state: &ChatBoardStateV1,
    parameters: &ChatBoardParametersV1,
    entry: &AuthorizedSuspension,
) -> Result<(), String> {
    let signer = entry.signer_id(parameters);
    let key = resolve_signer_key(state, parameters, &signer, entry.signer_key.as_ref())?;
    entry.verify_signature_with(&key)?;
    crate::board_state::roles::verify_admin_authority(
        state,
        parameters,
        &signer,
        entry.authority.as_deref(),
        8,
    )
    .map_err(|_| "Only the owner or an admin can suspend a member".to_string())?;
    if entry.suspension.target == parameters.owner_id() {
        return Err("The owner cannot be suspended".to_string());
    }
    if entry.suspension.until <= entry.suspension.created_at {
        return Err("A suspension must end after it starts".to_string());
    }
    if !state
        .members
        .members
        .iter()
        .any(|member| member.member.id() == entry.suspension.target)
    {
        return Err("Suspension targets a member who is not on this board".to_string());
    }
    Ok(())
}

impl SuspensionsV1 {
    /// The end of the active suspension for this member, if any.
    pub fn active_until(&self, member: MemberId, now_ms: i64) -> Option<i64> {
        self.suspensions
            .iter()
            .filter(|entry| entry.suspension.target == member)
            .max_by_key(|entry| entry.suspension.generation)
            .filter(|entry| entry.suspension.until > now_ms)
            .map(|entry| entry.suspension.until)
    }

    pub fn cleanup(&mut self, state: &ChatBoardStateV1, parameters: &ChatBoardParametersV1) {
        self.suspensions.retain(|entry| {
            entry.suspension.target != parameters.owner_id()
                && state
                    .members
                    .members
                    .iter()
                    .any(|member| member.member.id() == entry.suspension.target)
                && verify_suspension(state, parameters, entry).is_ok()
        });
        self.suspensions.sort_by_key(|entry| {
            (
                entry.suspension.target.0 .0,
                entry.suspension.generation,
                entry.signer_id(parameters).0 .0,
            )
        });
        self.suspensions
            .dedup_by_key(|entry| entry.suspension.target);
        self.suspensions
            .sort_by_key(|entry| entry.suspension.target.0 .0);
    }
}

impl ComposableState for SuspensionsV1 {
    type ParentState = ChatBoardStateV1;
    type Summary = SuspensionsSummary;
    type Delta = SuspensionsDelta;
    type Parameters = ChatBoardParametersV1;

    fn verify(
        &self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
    ) -> Result<(), String> {
        let mut targets = HashSet::new();
        for entry in &self.suspensions {
            if !targets.insert(entry.suspension.target) {
                return Err("Duplicate suspension for one member".to_string());
            }
            verify_suspension(parent_state, parameters, entry)?;
        }
        Ok(())
    }

    fn summarize(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
    ) -> Self::Summary {
        SuspensionsSummary {
            suspensions: suspension_map(&self.suspensions),
        }
    }

    fn delta(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
        old_state: &Self::Summary,
    ) -> Option<Self::Delta> {
        let suspensions: Vec<AuthorizedSuspension> = self
            .suspensions
            .iter()
            .filter(|entry| {
                old_state
                    .suspensions
                    .get(&entry.suspension.target)
                    .map(|old| {
                        old.generation < entry.suspension.generation
                            || (old.generation == entry.suspension.generation
                                && old.digest != record_digest(&entry.suspension))
                    })
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        if suspensions.is_empty() {
            None
        } else {
            Some(SuspensionsDelta { suspensions })
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
        for entry in &delta.suspensions {
            verify_suspension(parent_state, parameters, entry)?;
            match self
                .suspensions
                .iter()
                .find(|existing| existing.suspension.target == entry.suspension.target)
            {
                Some(existing)
                    if existing.suspension.generation > entry.suspension.generation
                        || (existing.suspension.generation == entry.suspension.generation
                            && record_digest(&existing.suspension)
                                <= record_digest(&entry.suspension)) => {}
                _ => {
                    self.suspensions
                        .retain(|existing| existing.suspension.target != entry.suspension.target);
                    self.suspensions.push(entry.clone());
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board_state::configuration::{AuthorizedConfigurationV1, Configuration};
    use crate::board_state::member::{AuthorizedMember, Member, MembersV1};
    use crate::board_state::secret::BoardSecretsV1;
    use crate::ChatBoardStateV1;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn board() -> (
        ChatBoardStateV1,
        ChatBoardParametersV1,
        SigningKey,
        SigningKey,
        MemberId,
    ) {
        let owner_sk = SigningKey::generate(&mut OsRng);
        let owner_vk = owner_sk.verifying_key();
        let owner_id = MemberId::from(&owner_vk);
        let parameters = ChatBoardParametersV1 { owner: owner_vk };
        let member_sk = SigningKey::generate(&mut OsRng);
        let member_vk = member_sk.verifying_key();
        let member_id = MemberId::from(&member_vk);
        let member = AuthorizedMember::new(
            Member {
                owner_member_id: owner_id,
                invited_by: owner_id,
                member_vk,
                join_proof: None,
            },
            &owner_sk,
        );
        let state = ChatBoardStateV1 {
            configuration: AuthorizedConfigurationV1::new(Configuration::default(), &owner_sk),
            members: MembersV1 {
                members: vec![member],
            },
            secrets: BoardSecretsV1::default(),
            ..Default::default()
        };
        (state, parameters, owner_sk, member_sk, member_id)
    }

    #[test]
    fn only_owner_or_admin_warn_and_suspend() {
        let (mut state, parameters, owner_sk, member_sk, member_id) = board();
        let warning = WarningV1 {
            target: member_id,
            reason: ReportReason::Spam,
            created_at: 100,
        };
        state
            .warnings
            .warnings
            .push(AuthorizedWarning::new(warning.clone(), &owner_sk));
        state
            .warnings
            .verify(&state, &parameters)
            .expect("the owner can warn a member");

        state.warnings.warnings.clear();
        state
            .warnings
            .warnings
            .push(AuthorizedWarning::new(warning, &member_sk));
        assert!(state.warnings.verify(&state, &parameters).is_err());

        let suspension = SuspensionV1 {
            target: member_id,
            reason: ReportReason::Abuse,
            until: 200,
            created_at: 100,
            generation: 1,
        };
        state
            .suspensions
            .suspensions
            .push(AuthorizedSuspension::new(suspension.clone(), &owner_sk));
        state
            .suspensions
            .verify(&state, &parameters)
            .expect("the owner can suspend a member");
        assert_eq!(state.suspensions.active_until(member_id, 150), Some(200));
        assert_eq!(state.suspensions.active_until(member_id, 250), None);
    }

    #[test]
    fn a_suspension_must_end_after_it_starts() {
        let (mut state, parameters, owner_sk, _member_sk, member_id) = board();
        let suspension = SuspensionV1 {
            target: member_id,
            reason: ReportReason::Spam,
            until: 100,
            created_at: 100,
            generation: 1,
        };
        state
            .suspensions
            .suspensions
            .push(AuthorizedSuspension::new(suspension, &owner_sk));
        assert!(state.suspensions.verify(&state, &parameters).is_err());
    }
}
