//! Post-quantum KEM key records and sealed board/category secrets (v2 prototype).
//!
//! The contract treats the KEM ciphertext as opaque bytes. It verifies the
//! member key records, the set signatures, the recipient membership and the
//! fixed lengths. The client performs ML-KEM encapsulation/decapsulation.
//!
//! Enable with `--features pq-v2`; the field is absent from the default state.

use crate::board_state::member::MemberId;
use crate::board_state::message::MessageId;
use crate::board_state::moderation::is_owner_or_admin;
use crate::board_state::roles::signer_key;
use crate::board_state::ChatBoardParametersV1;
use crate::util::{sign_struct, verify_struct};
use crate::ChatBoardStateV1;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use freenet_scaffold::ComposableState;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

/// FIPS 203 ML-KEM-768 encapsulation key length.
pub const PQ_KEM_EK_LEN: usize = 1184;
/// FIPS 203 ML-KEM-768 ciphertext length.
pub const PQ_KEM_CT_LEN: usize = 1088;
/// XChaCha20-Poly1305 nonce length.
pub const PQ_NONCE_LEN: usize = 24;
/// Smallest sealed payload: a 32-byte secret plus the 16-byte tag.
pub const PQ_MIN_SEALED_LEN: usize = 48;
/// Cap for a sealed payload in a set. Board and category secrets are 32 bytes.
pub const PQ_MAX_SEALED_LEN: usize = 4096;

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum PqScope {
    Board,
    Category(MessageId),
}

impl Default for PqScope {
    fn default() -> Self {
        PqScope::Board
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct PqMemberKey {
    pub member_id: MemberId,
    /// ML-KEM-768 encapsulation key, FIPS 203 encoded.
    pub ek: Vec<u8>,
    pub version: u64,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedPqMemberKey {
    pub key: PqMemberKey,
    pub signature: Signature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<MemberId>,
}

impl AuthorizedPqMemberKey {
    pub fn new(key: PqMemberKey, signing_key: &SigningKey) -> Self {
        Self {
            signature: sign_struct(&key, signing_key),
            key,
            signer: Some(MemberId::from(&signing_key.verifying_key())),
        }
    }

    pub fn signer_id(&self, parameters: &ChatBoardParametersV1) -> MemberId {
        self.signer.unwrap_or_else(|| parameters.owner_id())
    }

    pub fn verify_signature_with(&self, key: &VerifyingKey) -> Result<(), String> {
        verify_struct(&self.key, &self.signature, key)
            .map_err(|e| format!("Invalid PQ member key signature: {}", e))
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum PqSuite {
    /// ML-KEM shared secret alone (records from the first prototype).
    #[default]
    MlKem,
    /// X25519 ephemeral + ML-KEM shared secrets combined.
    Hybrid,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct PqSealedSecret {
    pub member_id: MemberId,
    /// ML-KEM-768 ciphertext, FIPS 203 encoded.
    pub kem_ciphertext: Vec<u8>,
    pub nonce: [u8; PQ_NONCE_LEN],
    /// XChaCha20-Poly1305 output.
    pub sealed: Vec<u8>,
    #[serde(default)]
    pub suite: PqSuite,
    /// Ephemeral X25519 public key for the hybrid suite.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x25519_public: Option<[u8; 32]>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct PqSecretSet {
    pub scope: PqScope,
    /// Generation of this set for the scope; a newer set replaces an older one.
    pub version: u32,
    /// Board or category secret version the sealed payloads belong to.
    pub secret_version: u32,
    pub secrets: Vec<PqSealedSecret>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedPqSecretSet {
    pub set: PqSecretSet,
    pub signature: Signature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<MemberId>,
}

impl AuthorizedPqSecretSet {
    pub fn new(set: PqSecretSet, signing_key: &SigningKey) -> Self {
        Self {
            signature: sign_struct(&set, signing_key),
            set,
            signer: Some(MemberId::from(&signing_key.verifying_key())),
        }
    }

    pub fn signer_id(&self, parameters: &ChatBoardParametersV1) -> MemberId {
        self.signer.unwrap_or_else(|| parameters.owner_id())
    }

    pub fn verify_signature_with(&self, key: &VerifyingKey) -> Result<(), String> {
        verify_struct(&self.set, &self.signature, key)
            .map_err(|e| format!("Invalid PQ secret set signature: {}", e))
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct PqSecretsV1 {
    #[serde(default)]
    pub keys: Vec<AuthorizedPqMemberKey>,
    #[serde(default)]
    pub sets: Vec<AuthorizedPqSecretSet>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct PqSecretsSummary {
    pub keys: BTreeMap<MemberId, u64>,
    pub sets: BTreeMap<PqScope, u32>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct PqSecretsDelta {
    #[serde(default)]
    pub keys: Vec<AuthorizedPqMemberKey>,
    #[serde(default)]
    pub sets: Vec<AuthorizedPqSecretSet>,
}

fn key_map(keys: &[AuthorizedPqMemberKey]) -> BTreeMap<MemberId, u64> {
    keys.iter()
        .map(|entry| (entry.key.member_id, entry.key.version))
        .collect()
}

fn set_map(sets: &[AuthorizedPqSecretSet]) -> BTreeMap<PqScope, u32> {
    sets.iter()
        .map(|entry| (entry.set.scope.clone(), entry.set.version))
        .collect()
}

fn verify_key(
    state: &ChatBoardStateV1,
    parameters: &ChatBoardParametersV1,
    entry: &AuthorizedPqMemberKey,
) -> Result<(), String> {
    let signer = entry.signer_id(parameters);
    if signer != entry.key.member_id {
        return Err("A PQ member key must be signed by its member".to_string());
    }
    let verifying = signer_key(state, parameters, &signer)?;
    entry.verify_signature_with(&verifying)?;
    if entry.key.ek.len() != PQ_KEM_EK_LEN {
        return Err(format!("PQ member key must be {} bytes", PQ_KEM_EK_LEN));
    }
    if entry.key.version == 0 {
        return Err("PQ member key version must be positive".to_string());
    }
    Ok(())
}

fn verify_set(
    state: &ChatBoardStateV1,
    parameters: &ChatBoardParametersV1,
    keys: &BTreeMap<MemberId, &AuthorizedPqMemberKey>,
    entry: &AuthorizedPqSecretSet,
) -> Result<(), String> {
    let signer = entry.signer_id(parameters);
    let verifying = signer_key(state, parameters, &signer)?;
    entry.verify_signature_with(&verifying)?;
    let is_category = matches!(entry.set.scope, PqScope::Category(_));
    let can_sign = is_owner_or_admin(state, parameters, &signer)
        || (is_category && state.roles.can_distribute_keys(&signer));
    if !can_sign {
        return Err("Signer cannot publish PQ secrets for this scope".to_string());
    }
    if entry.set.version == 0 {
        return Err("PQ secret set version must be positive".to_string());
    }
    match &entry.set.scope {
        PqScope::Board => {
            if entry.set.secret_version > state.secrets.current_version {
                return Err("PQ set references a future board secret version".to_string());
            }
        }
        PqScope::Category(category_id) => {
            if !state
                .category_secrets
                .current_version(category_id)
                .map(|version| entry.set.secret_version <= version)
                .unwrap_or(false)
            {
                return Err("PQ set references an unknown category secret version".to_string());
            }
        }
    }
    if let PqScope::Category(category_id) = &entry.set.scope {
        let category = state
            .recent_messages
            .messages
            .iter()
            .find(|message| message.id() == *category_id)
            .ok_or("PQ secret set targets a missing category")?;
        if category.message.content.content_type()
            != crate::board_state::content::CONTENT_TYPE_CATEGORY
        {
            return Err("PQ secret scope is not a category".to_string());
        }
    }

    let mut members = HashSet::new();
    for secret in &entry.set.secrets {
        if !members.insert(secret.member_id) {
            return Err("Duplicate PQ secret for one member".to_string());
        }
        if !state
            .members
            .members
            .iter()
            .any(|member| member.member.id() == secret.member_id)
            && secret.member_id != parameters.owner_id()
        {
            return Err("PQ secret targets a member who is not on this board".to_string());
        }
        if !keys.contains_key(&secret.member_id) {
            return Err("PQ secret targets a member without a KEM key".to_string());
        }
        if secret.kem_ciphertext.len() != PQ_KEM_CT_LEN {
            return Err(format!("PQ KEM ciphertext must be {} bytes", PQ_KEM_CT_LEN));
        }
        if secret.sealed.len() < PQ_MIN_SEALED_LEN || secret.sealed.len() > PQ_MAX_SEALED_LEN {
            return Err("PQ sealed secret has an invalid length".to_string());
        }
        if matches!(secret.suite, PqSuite::Hybrid) && secret.x25519_public.is_none() {
            return Err("Hybrid PQ secret needs an X25519 ephemeral key".to_string());
        }
    }
    Ok(())
}

impl PqSecretsV1 {
    /// The current KEM key for a member, if any.
    pub fn key_for(&self, member: MemberId) -> Option<&PqMemberKey> {
        self.keys
            .iter()
            .filter(|entry| entry.key.member_id == member)
            .max_by_key(|entry| entry.key.version)
            .map(|entry| &entry.key)
    }

    /// The latest sealed set for a scope.
    pub fn set_for(&self, scope: &PqScope) -> Option<&PqSecretSet> {
        self.sets
            .iter()
            .filter(|entry| entry.set.scope == *scope)
            .max_by_key(|entry| entry.set.version)
            .map(|entry| &entry.set)
    }

    pub fn cleanup(&mut self, state: &ChatBoardStateV1, parameters: &ChatBoardParametersV1) {
        self.keys.retain(|entry| {
            (entry.key.member_id == parameters.owner_id()
                || state
                    .members
                    .members
                    .iter()
                    .any(|member| member.member.id() == entry.key.member_id))
                && verify_key(state, parameters, entry).is_ok()
        });
        self.keys.sort_by_key(|entry| {
            (
                entry.key.member_id.0 .0,
                entry.key.version,
                entry.signer_id(parameters).0 .0,
            )
        });
        self.keys.dedup_by_key(|entry| entry.key.member_id);

        self.sets.retain(|entry| {
            verify_set(
                state,
                parameters,
                &self
                    .keys
                    .iter()
                    .map(|key| (key.key.member_id, key))
                    .collect(),
                entry,
            )
            .is_ok()
        });
        self.sets.sort_by_key(|entry| {
            (
                entry.set.scope.clone(),
                entry.set.version,
                entry.signer_id(parameters).0 .0,
            )
        });
        self.sets.dedup_by_key(|entry| entry.set.scope.clone());

        let live_members: HashSet<MemberId> = state
            .members
            .members
            .iter()
            .map(|member| member.member.id())
            .chain(std::iter::once(parameters.owner_id()))
            .collect();
        let keyed: HashSet<MemberId> = self.keys.iter().map(|entry| entry.key.member_id).collect();
        for entry in &mut self.sets {
            entry.set.secrets.retain(|secret| {
                live_members.contains(&secret.member_id) && keyed.contains(&secret.member_id)
            });
        }
        self.sets.retain(|entry| !entry.set.secrets.is_empty());
    }
}

impl ComposableState for PqSecretsV1 {
    type ParentState = ChatBoardStateV1;
    type Summary = PqSecretsSummary;
    type Delta = PqSecretsDelta;
    type Parameters = ChatBoardParametersV1;

    fn verify(
        &self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
    ) -> Result<(), String> {
        let mut member_ids = HashSet::new();
        for entry in &self.keys {
            if !member_ids.insert(entry.key.member_id) {
                return Err("Duplicate PQ member key".to_string());
            }
            verify_key(parent_state, parameters, entry)?;
        }
        let keys: BTreeMap<MemberId, &AuthorizedPqMemberKey> = self
            .keys
            .iter()
            .map(|key| (key.key.member_id, key))
            .collect();
        let mut scopes = HashSet::new();
        for entry in &self.sets {
            if !scopes.insert(entry.set.scope.clone()) {
                return Err("Duplicate PQ secret set".to_string());
            }
            verify_set(parent_state, parameters, &keys, entry)?;
        }
        Ok(())
    }

    fn summarize(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
    ) -> Self::Summary {
        PqSecretsSummary {
            keys: key_map(&self.keys),
            sets: set_map(&self.sets),
        }
    }

    fn delta(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
        old_state: &Self::Summary,
    ) -> Option<Self::Delta> {
        let keys: Vec<AuthorizedPqMemberKey> = self
            .keys
            .iter()
            .filter(|entry| {
                old_state
                    .keys
                    .get(&entry.key.member_id)
                    .map(|old| *old < entry.key.version)
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        let sets: Vec<AuthorizedPqSecretSet> = self
            .sets
            .iter()
            .filter(|entry| {
                old_state
                    .sets
                    .get(&entry.set.scope)
                    .map(|old| *old < entry.set.version)
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        if keys.is_empty() && sets.is_empty() {
            None
        } else {
            Some(PqSecretsDelta { keys, sets })
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
        let mut candidate = self.clone();
        for entry in &delta.keys {
            verify_key(parent_state, parameters, entry)?;
            match candidate
                .keys
                .iter()
                .find(|existing| existing.key.member_id == entry.key.member_id)
            {
                Some(existing) if existing.key.version >= entry.key.version => {}
                _ => {
                    candidate
                        .keys
                        .retain(|existing| existing.key.member_id != entry.key.member_id);
                    candidate.keys.push(entry.clone());
                }
            }
        }
        let keys: BTreeMap<MemberId, &AuthorizedPqMemberKey> = candidate
            .keys
            .iter()
            .map(|key| (key.key.member_id, key))
            .collect();
        for entry in &delta.sets {
            verify_set(parent_state, parameters, &keys, entry)?;
            match candidate
                .sets
                .iter()
                .find(|existing| existing.set.scope == entry.set.scope)
            {
                Some(existing) if existing.set.version >= entry.set.version => {}
                _ => {
                    candidate
                        .sets
                        .retain(|existing| existing.set.scope != entry.set.scope);
                    candidate.sets.push(entry.clone());
                }
            }
        }
        *self = candidate;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board_state::configuration::{AuthorizedConfigurationV1, Configuration};
    use crate::board_state::member::{AuthorizedMember, Member, MembersV1};
    use crate::board_state::secret::BoardSecretsV1;

    fn board() -> (
        ChatBoardStateV1,
        ChatBoardParametersV1,
        SigningKey,
        SigningKey,
        MemberId,
    ) {
        let owner_sk = SigningKey::generate(&mut rand::thread_rng());
        let owner_vk = owner_sk.verifying_key();
        let owner_id = MemberId::from(&owner_vk);
        let parameters = ChatBoardParametersV1 { owner: owner_vk };
        let member_sk = SigningKey::generate(&mut rand::thread_rng());
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

    fn key(member_id: MemberId, sk: &SigningKey) -> AuthorizedPqMemberKey {
        AuthorizedPqMemberKey::new(
            PqMemberKey {
                member_id,
                ek: vec![7u8; PQ_KEM_EK_LEN],
                version: 1,
            },
            sk,
        )
    }

    fn set(member_id: MemberId, sk: &SigningKey) -> AuthorizedPqSecretSet {
        AuthorizedPqSecretSet::new(
            PqSecretSet {
                scope: PqScope::Board,
                version: 1,
                secret_version: 0,
                secrets: vec![PqSealedSecret {
                    member_id,
                    kem_ciphertext: vec![1u8; PQ_KEM_CT_LEN],
                    nonce: [0u8; PQ_NONCE_LEN],
                    sealed: vec![2u8; PQ_MIN_SEALED_LEN],
                    suite: PqSuite::MlKem,
                    x25519_public: None,
                }],
            },
            sk,
        )
    }

    #[test]
    fn owner_can_seal_a_secret_to_a_member_key() {
        let (mut state, parameters, owner_sk, member_sk, member_id) = board();
        state.pq_secrets.keys.push(key(member_id, &member_sk));
        state.pq_secrets.sets.push(set(member_id, &owner_sk));
        state
            .pq_secrets
            .verify(&state, &parameters)
            .expect("owner-signed set with a member key is valid");
    }

    #[test]
    fn only_the_owner_or_admin_can_publish_sets() {
        let (mut state, parameters, _owner_sk, member_sk, member_id) = board();
        state.pq_secrets.keys.push(key(member_id, &member_sk));
        state.pq_secrets.sets.push(set(member_id, &member_sk));
        assert!(state.pq_secrets.verify(&state, &parameters).is_err());
    }

    #[test]
    fn a_secret_needs_a_member_key() {
        let (mut state, parameters, owner_sk, _member_sk, member_id) = board();
        state.pq_secrets.sets.push(set(member_id, &owner_sk));
        assert!(state.pq_secrets.verify(&state, &parameters).is_err());
    }

    #[test]
    fn cleanup_drops_keys_for_missing_members() {
        let (mut state, parameters, owner_sk, member_sk, member_id) = board();
        state.pq_secrets.keys.push(key(member_id, &member_sk));
        state.pq_secrets.sets.push(set(member_id, &owner_sk));
        state.members = MembersV1::default();
        let mut pq = std::mem::take(&mut state.pq_secrets);
        pq.cleanup(&state, &parameters);
        assert!(pq.keys.is_empty());
        assert!(pq.sets.is_empty());
    }

    #[test]
    fn hybrid_sets_need_an_x25519_ephemeral_key() {
        let (mut state, parameters, owner_sk, member_sk, member_id) = board();
        state.pq_secrets.keys.push(key(member_id, &member_sk));
        let mut hybrid_set = set(member_id, &owner_sk).set;
        hybrid_set.secrets[0].suite = PqSuite::Hybrid;
        state
            .pq_secrets
            .sets
            .push(AuthorizedPqSecretSet::new(hybrid_set.clone(), &owner_sk));
        assert!(state.pq_secrets.verify(&state, &parameters).is_err());

        state.pq_secrets.sets.clear();
        hybrid_set.version = 2;
        hybrid_set.secrets[0].x25519_public = Some([9u8; 32]);
        state
            .pq_secrets
            .sets
            .push(AuthorizedPqSecretSet::new(hybrid_set, &owner_sk));
        state
            .pq_secrets
            .verify(&state, &parameters)
            .expect("hybrid set with an ephemeral key is valid");
    }

    #[test]
    fn wrong_key_length_is_rejected() {
        let (mut state, parameters, _owner_sk, member_sk, member_id) = board();
        let mut bad = key(member_id, &member_sk);
        bad.key.ek = vec![0u8; 10];
        bad.signature = sign_struct(&bad.key, &member_sk);
        state.pq_secrets.keys.push(bad);
        assert!(state.pq_secrets.verify(&state, &parameters).is_err());
    }
}
