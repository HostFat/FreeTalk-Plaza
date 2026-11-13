//! Per-category secrets for restricted categories.
//!
//! A restricted category seals its name and its posts with a key that is not the
//! board key. The key is distributed per member with the same ECIES scheme as
//! board secrets, and only the board owner signs the records.
//!
//! Confidentiality comes from the key: a member without a blob for the category
//! cannot decrypt its name or its posts. The contract validates signatures and
//! versions, not who may read.

use crate::board_state::member::MemberId;
use crate::board_state::message::MessageId;
use crate::board_state::privacy::SecretVersion;
use crate::board_state::secret::{
    AuthorizedEncryptedSecretForMember, AuthorizedSecretVersionRecord,
};
use crate::board_state::ChatBoardParametersV1;
use crate::ChatBoardStateV1;
use freenet_scaffold::ComposableState;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct CategorySecretsV1 {
    pub categories: Vec<CategorySecretSet>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct CategorySecretSet {
    pub category_id: MessageId,
    pub current_version: SecretVersion,
    pub versions: Vec<AuthorizedSecretVersionRecord>,
    pub encrypted_secrets: Vec<AuthorizedEncryptedSecretForMember>,
}

/// Key of the member who signed a blob: the owner, or a member of a role with
/// the key-distribution permission.
fn distributor_key(
    state: &ChatBoardStateV1,
    parameters: &ChatBoardParametersV1,
    signer: &MemberId,
) -> Result<ed25519_dalek::VerifyingKey, String> {
    if *signer == parameters.owner_id() {
        return Ok(parameters.owner);
    }
    if !state.roles.can_distribute_keys(signer) {
        return Err("Category key signer cannot distribute keys".to_string());
    }
    state
        .members
        .members
        .iter()
        .find(|member| member.member.id() == *signer)
        .map(|member| member.member.member_vk)
        .ok_or_else(|| "Category key signer is not a board member".to_string())
}

fn is_board_member(
    state: &ChatBoardStateV1,
    parameters: &ChatBoardParametersV1,
    member_id: &MemberId,
) -> bool {
    *member_id == parameters.owner_id()
        || state
            .members
            .members
            .iter()
            .any(|member| member.member.id() == *member_id)
}

fn verify_blob(
    state: &ChatBoardStateV1,
    parameters: &ChatBoardParametersV1,
    blob: &AuthorizedEncryptedSecretForMember,
    current_version: u32,
    category_id: MessageId,
) -> Result<(), String> {
    let signer = blob.signer_id(parameters);
    let signing_key = distributor_key(state, parameters, &signer)?;
    blob.verify_signature_with(&signing_key)?;
    if !is_board_member(state, parameters, &blob.secret.member_id) {
        return Err("Category key recipient is not a board member".to_string());
    }
    if let Some(bound_category) = blob.secret.category_id {
        if bound_category != category_id {
            return Err("Category key blob belongs to another category".to_string());
        }
    }
    if blob.secret.secret_version > current_version {
        return Err("Category key blob references a future version".to_string());
    }
    if blob.secret.ciphertext.is_empty() || blob.secret.ciphertext.len() > 4096 {
        return Err("Category key blob has an invalid ciphertext length".to_string());
    }
    Ok(())
}

/// Deterministic order used when two distributors produce a blob for the same
/// member and version. Lower signer id wins, then the ciphertext bytes.
fn blob_precedes(
    candidate: &AuthorizedEncryptedSecretForMember,
    existing: &AuthorizedEncryptedSecretForMember,
    owner_id: MemberId,
) -> bool {
    let candidate_key = (
        candidate.signer.unwrap_or(owner_id).0 .0,
        candidate.secret.ciphertext.as_slice(),
    );
    let existing_key = (
        existing.signer.unwrap_or(owner_id).0 .0,
        existing.secret.ciphertext.as_slice(),
    );
    candidate_key < existing_key
}

impl ComposableState for CategorySecretsV1 {
    type ParentState = ChatBoardStateV1;
    type Summary = CategorySecretsSummary;
    type Delta = CategorySecretsDelta;
    type Parameters = ChatBoardParametersV1;

    fn verify(
        &self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
    ) -> Result<(), String> {
        let mut seen = std::collections::HashSet::new();
        for set in &self.categories {
            if !seen.insert(set.category_id.clone()) {
                return Err("Duplicate category secret set".to_string());
            }
            for record in &set.versions {
                record.verify_signature(&parameters.owner)?;
                if let Some(bound_category) = record.record.category_id {
                    if bound_category != set.category_id {
                        return Err(
                            "Category version record belongs to another category".to_string()
                        );
                    }
                }
            }
            for secret in &set.encrypted_secrets {
                verify_blob(
                    parent_state,
                    parameters,
                    secret,
                    set.current_version,
                    set.category_id,
                )?;
            }
            if let Some(max) = set.versions.iter().map(|v| v.record.version).max() {
                if set.current_version != max {
                    return Err("Category secret version does not match its records".to_string());
                }
            } else if set.current_version != 0 {
                return Err("Category secret version is set without records".to_string());
            }
        }
        Ok(())
    }

    fn summarize(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
    ) -> Self::Summary {
        let mut versions = BTreeSet::new();
        let mut member_secrets = BTreeMap::new();
        for set in &self.categories {
            for record in &set.versions {
                versions.insert((set.category_id.clone(), record.record.version));
            }
            for secret in &set.encrypted_secrets {
                member_secrets.insert(
                    (
                        set.category_id.clone(),
                        secret.secret.secret_version,
                        secret.secret.member_id,
                    ),
                    blob_digest(secret),
                );
            }
        }
        CategorySecretsSummary {
            versions,
            member_secrets,
        }
    }

    fn delta(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
        old_state_summary: &Self::Summary,
    ) -> Option<Self::Delta> {
        let mut sets = Vec::new();
        for set in &self.categories {
            let versions: Vec<_> = set
                .versions
                .iter()
                .filter(|r| {
                    !old_state_summary
                        .versions
                        .contains(&(set.category_id.clone(), r.record.version))
                })
                .cloned()
                .collect();
            let encrypted_secrets: Vec<_> = set
                .encrypted_secrets
                .iter()
                .filter(|s| {
                    old_state_summary
                        .member_secrets
                        .get(&(
                            set.category_id.clone(),
                            s.secret.secret_version,
                            s.secret.member_id,
                        ))
                        .map(|digest| *digest != blob_digest(*s))
                        .unwrap_or(true)
                })
                .cloned()
                .collect();
            if !versions.is_empty() || !encrypted_secrets.is_empty() {
                sets.push(CategorySecretSetDelta {
                    category_id: set.category_id.clone(),
                    current_version: set.current_version,
                    versions,
                    encrypted_secrets,
                });
            }
        }
        if sets.is_empty() {
            None
        } else {
            Some(CategorySecretsDelta { sets })
        }
    }

    fn apply_delta(
        &mut self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
        delta: &Option<Self::Delta>,
    ) -> Result<(), String> {
        if let Some(delta) = delta {
            for incoming in &delta.sets {
                for record in &incoming.versions {
                    record.verify_signature(&parameters.owner)?;
                    if let Some(bound_category) = record.record.category_id {
                        if bound_category != incoming.category_id {
                            return Err(
                                "Category version record belongs to another category".to_string()
                            );
                        }
                    }
                }
                for secret in &incoming.encrypted_secrets {
                    verify_blob(
                        parent_state,
                        parameters,
                        secret,
                        incoming.current_version,
                        incoming.category_id,
                    )?;
                }

                let set = match self
                    .categories
                    .iter_mut()
                    .find(|s| s.category_id.clone() == incoming.category_id.clone())
                {
                    Some(set) => set,
                    None => {
                        self.categories.push(CategorySecretSet {
                            category_id: incoming.category_id.clone(),
                            current_version: 0,
                            versions: Vec::new(),
                            encrypted_secrets: Vec::new(),
                        });
                        self.categories.last_mut().expect("just pushed")
                    }
                };

                for record in &incoming.versions {
                    if !set
                        .versions
                        .iter()
                        .any(|v| v.record.version == record.record.version)
                    {
                        set.versions.push(record.clone());
                    }
                }
                for secret in &incoming.encrypted_secrets {
                    // One blob per member and version. When two distributors
                    // produce one, keep the lowest (signer, ciphertext) so every
                    // peer converges on the same record.
                    if let Some(existing) = set.encrypted_secrets.iter_mut().find(|s| {
                        s.secret.secret_version == secret.secret.secret_version
                            && s.secret.member_id == secret.secret.member_id
                    }) {
                        if blob_precedes(secret, existing, parameters.owner_id()) {
                            *existing = secret.clone();
                        }
                    } else {
                        set.encrypted_secrets.push(secret.clone());
                    }
                }

                set.versions.sort_by_key(|v| v.record.version);
                set.encrypted_secrets
                    .sort_by_key(|s| (s.secret.secret_version, s.secret.member_id));
                set.current_version = set
                    .versions
                    .iter()
                    .map(|v| v.record.version)
                    .max()
                    .unwrap_or(0);
            }
            self.categories.sort_by_key(|s| s.category_id.clone());
        }
        Ok(())
    }
}

impl CategorySecretsV1 {
    pub fn set(&self, category_id: &MessageId) -> Option<&CategorySecretSet> {
        self.categories
            .iter()
            .find(|s| s.category_id.clone() == *category_id)
    }

    pub fn current_version(&self, category_id: &MessageId) -> Option<SecretVersion> {
        self.set(category_id).map(|s| s.current_version)
    }

    /// The newest blob for this member, if they may read the category.
    pub fn authorized_secret_for(
        &self,
        category_id: &MessageId,
        member: &MemberId,
    ) -> Option<&AuthorizedEncryptedSecretForMember> {
        self.set(category_id).and_then(|set| {
            set.encrypted_secrets
                .iter()
                .filter(|s| s.secret.member_id == *member)
                .max_by_key(|s| s.secret.secret_version)
        })
    }

    /// Members of the category who still need a blob for the current version.
    pub fn members_missing_secret(
        &self,
        category_id: &MessageId,
        members: &[MemberId],
    ) -> Vec<MemberId> {
        let Some(set) = self.set(category_id) else {
            return members.to_vec();
        };
        members
            .iter()
            .filter(|member| {
                !set.encrypted_secrets.iter().any(|s| {
                    s.secret.member_id == **member && s.secret.secret_version == set.current_version
                })
            })
            .copied()
            .collect()
    }

    pub fn versions_by_category(&self) -> HashMap<MessageId, SecretVersion> {
        self.categories
            .iter()
            .map(|s| (s.category_id.clone(), s.current_version))
            .collect()
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct CategorySecretsSummary {
    pub versions: BTreeSet<(MessageId, SecretVersion)>,
    /// Digest of the blob so two distributors' records for the same member and
    /// version are exchanged and converge on the same one.
    pub member_secrets: BTreeMap<(MessageId, SecretVersion, MemberId), i64>,
}

fn blob_digest<T: serde::Serialize>(value: &T) -> i64 {
    let mut bytes = Vec::new();
    let _ = ciborium::ser::into_writer(value, &mut bytes);
    freenet_scaffold::util::fast_hash(&bytes).0
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct CategorySecretsDelta {
    pub sets: Vec<CategorySecretSetDelta>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct CategorySecretSetDelta {
    pub category_id: MessageId,
    pub current_version: SecretVersion,
    pub versions: Vec<AuthorizedSecretVersionRecord>,
    pub encrypted_secrets: Vec<AuthorizedEncryptedSecretForMember>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board_state::configuration::{AuthorizedConfigurationV1, Configuration};
    use crate::board_state::privacy::BoardCipherSpec;
    use crate::board_state::secret::{EncryptedSecretForMemberV1, SecretVersionRecordV1};
    use freenet_scaffold::util::FastHash;
    use freenet_scaffold::ComposableState;
    use std::time::SystemTime;

    fn owner() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[1u8; 32])
    }

    fn params(owner: &ed25519_dalek::SigningKey) -> ChatBoardParametersV1 {
        ChatBoardParametersV1 {
            owner: owner.verifying_key(),
        }
    }

    fn state_with_category(
        owner: &ed25519_dalek::SigningKey,
    ) -> (ChatBoardStateV1, MessageId, MemberId) {
        use crate::board_state::member::{AuthorizedMember, Member};

        let category_id = MessageId(FastHash(7));
        let member_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let member = MemberId::from(&member_key.verifying_key());
        let version = SecretVersionRecordV1 {
            version: 1,
            cipher_spec: BoardCipherSpec::Aes256Gcm,
            created_at: SystemTime::now(),
            category_id: None,
        };
        let blob = EncryptedSecretForMemberV1 {
            member_id: member,
            secret_version: 1,
            ciphertext: vec![1, 2, 3],
            nonce: [0u8; 12],
            sender_ephemeral_public_key: [0u8; 32],
            provider: MemberId::from(&owner.verifying_key()),
            category_id: None,
        };

        let mut state = ChatBoardStateV1 {
            configuration: AuthorizedConfigurationV1::new(Configuration::default(), owner),
            ..Default::default()
        };
        state.members.members.push(AuthorizedMember::new(
            Member {
                owner_member_id: MemberId::from(&owner.verifying_key()),
                invited_by: MemberId::from(&owner.verifying_key()),
                member_vk: member_key.verifying_key(),
                join_proof: None,
            },
            owner,
        ));
        state.category_secrets.categories.push(CategorySecretSet {
            category_id: category_id.clone(),
            current_version: 1,
            versions: vec![AuthorizedSecretVersionRecord::new(version, owner)],
            encrypted_secrets: vec![AuthorizedEncryptedSecretForMember::new(blob, owner)],
        });
        (state, category_id, member)
    }

    #[test]
    fn a_signed_category_secret_set_verifies() {
        let owner = owner();
        let params = params(&owner);
        let (state, category, member) = state_with_category(&owner);

        state.verify(&state.clone(), &params).unwrap();
        assert_eq!(state.category_secrets.current_version(&category), Some(1));
        assert!(state
            .category_secrets
            .authorized_secret_for(&category, &member)
            .is_some());
    }

    #[test]
    fn deltas_carry_category_blobs_to_a_peer() {
        let owner = owner();
        let params = params(&owner);
        let (source, category, member) = state_with_category(&owner);

        // Same board roster, no category secrets yet.
        let mut empty = source.clone();
        empty.category_secrets = CategorySecretsV1::default();

        let summary = empty.category_secrets.summarize(&empty, &params);
        let delta = source
            .category_secrets
            .delta(&source, &params, &summary)
            .expect("there is something to send");
        empty
            .category_secrets
            .apply_delta(&empty.clone(), &params, &Some(delta))
            .unwrap();

        assert!(empty
            .category_secrets
            .authorized_secret_for(&category, &member)
            .is_some());
        assert_eq!(source.category_secrets, empty.category_secrets);
    }

    #[test]
    fn a_member_without_a_blob_is_reported_as_missing() {
        let owner = owner();
        let (state, category, member) = state_with_category(&owner);
        let other = MemberId(FastHash(11));

        let missing = state
            .category_secrets
            .members_missing_secret(&category, &[member, other]);
        assert_eq!(missing, vec![other]);
    }

    /// Delegated distribution: a member of a role with the permission can sign
    /// a blob for another board member.
    #[test]
    fn a_role_with_permission_can_sign_category_blobs() {
        use crate::board_state::member::{AuthorizedMember, Member};
        use crate::board_state::roles::{
            AuthorizedRole, AuthorizedRoleAssignment, Role, RoleAssignment,
        };

        let owner = owner();
        let params = params(&owner);
        let distributor_sk = ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]);
        let recipient_sk = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let distributor = MemberId::from(&distributor_sk.verifying_key());
        let recipient = MemberId::from(&recipient_sk.verifying_key());
        let role_id = [4u8; 16];

        let mut state = ChatBoardStateV1 {
            configuration: AuthorizedConfigurationV1::new(Configuration::default(), &owner),
            ..Default::default()
        };
        for (sk, id) in [
            (distributor_sk.clone(), distributor),
            (recipient_sk.clone(), recipient),
        ] {
            state.members.members.push(AuthorizedMember::new(
                Member {
                    owner_member_id: owner.verifying_key().into(),
                    invited_by: owner.verifying_key().into(),
                    member_vk: sk.verifying_key(),
                    join_proof: None,
                },
                &owner,
            ));
            let _ = id;
        }
        state.roles.roles.push(AuthorizedRole::new(
            Role {
                id: role_id,
                name: "keys".to_string(),
                generation: 1,
                can_manage_access: false,
                can_distribute_keys: true,
                can_edit_posts: false,
                can_delete_posts: false,
                can_close_posts: false,
                can_pin_posts: false,
                can_move_posts: false,
                scope: Vec::new(),
                deleted: false,
            },
            &owner,
        ));
        state.roles.assignments.push(AuthorizedRoleAssignment::new(
            RoleAssignment {
                role_id,
                member_id: distributor,
                generation: 1,
                revoked: false,
            },
            &owner,
        ));

        let category = MessageId(FastHash(21));
        state.category_secrets.categories.push(CategorySecretSet {
            category_id: category.clone(),
            current_version: 0,
            versions: vec![AuthorizedSecretVersionRecord::new(
                SecretVersionRecordV1 {
                    version: 0,
                    cipher_spec: BoardCipherSpec::Aes256Gcm,
                    created_at: SystemTime::now(),
                    category_id: None,
                },
                &owner,
            )],
            encrypted_secrets: vec![AuthorizedEncryptedSecretForMember::signed_by(
                EncryptedSecretForMemberV1 {
                    member_id: recipient,
                    secret_version: 0,
                    ciphertext: vec![7, 8, 9],
                    nonce: [0u8; 12],
                    sender_ephemeral_public_key: [0u8; 32],
                    provider: distributor,
                    category_id: None,
                },
                distributor,
                &distributor_sk,
            )],
        });

        state.category_secrets.verify(&state, &params).unwrap();
        assert!(state
            .category_secrets
            .authorized_secret_for(&category, &recipient)
            .is_some());
    }

    #[test]
    fn an_unauthorized_member_cannot_sign_category_blobs() {
        use crate::board_state::member::{AuthorizedMember, Member};

        let owner = owner();
        let params = params(&owner);
        let signer_sk = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
        let signer = MemberId::from(&signer_sk.verifying_key());
        let recipient =
            MemberId::from(&ed25519_dalek::SigningKey::from_bytes(&[6u8; 32]).verifying_key());

        let mut state = ChatBoardStateV1 {
            configuration: AuthorizedConfigurationV1::new(Configuration::default(), &owner),
            ..Default::default()
        };
        for sk in [
            signer_sk.clone(),
            ed25519_dalek::SigningKey::from_bytes(&[6u8; 32]),
        ] {
            state.members.members.push(AuthorizedMember::new(
                Member {
                    owner_member_id: owner.verifying_key().into(),
                    invited_by: owner.verifying_key().into(),
                    member_vk: sk.verifying_key(),
                    join_proof: None,
                },
                &owner,
            ));
        }

        let category = MessageId(FastHash(21));
        state.category_secrets.categories.push(CategorySecretSet {
            category_id: category,
            current_version: 0,
            versions: vec![AuthorizedSecretVersionRecord::new(
                SecretVersionRecordV1 {
                    version: 0,
                    cipher_spec: BoardCipherSpec::Aes256Gcm,
                    created_at: SystemTime::now(),
                    category_id: None,
                },
                &owner,
            )],
            encrypted_secrets: vec![AuthorizedEncryptedSecretForMember::signed_by(
                EncryptedSecretForMemberV1 {
                    member_id: recipient,
                    secret_version: 0,
                    ciphertext: vec![1],
                    nonce: [0u8; 12],
                    sender_ephemeral_public_key: [0u8; 32],
                    provider: signer,
                    category_id: None,
                },
                signer,
                &signer_sk,
            )],
        });

        let error = state.category_secrets.verify(&state, &params).unwrap_err();
        assert!(error.contains("cannot distribute keys"), "{error}");
    }

    /// Cleanup drops blobs for members who left the board, so the state keeps
    /// verifying after pruning.
    #[test]
    fn cleanup_drops_blobs_of_pruned_members() {
        let owner = owner();
        let params = params(&owner);
        let (mut state, _, _) = state_with_category(&owner);
        assert_eq!(
            state.category_secrets.categories[0].encrypted_secrets.len(),
            1
        );

        state.normalize(&params).unwrap();
        assert!(
            state.members.members.is_empty(),
            "the recipient has no messages and is pruned"
        );
        assert!(
            state.category_secrets.categories[0]
                .encrypted_secrets
                .is_empty(),
            "its blob goes with it"
        );
        state.verify(&state, &params).unwrap();
    }

    /// Two distributors can produce a blob for the same member. Applying the
    /// same two blobs in different orders must converge on one record.
    #[test]
    fn concurrent_distributions_converge() {
        use crate::board_state::member::{AuthorizedMember, Member};
        use crate::board_state::roles::{
            AuthorizedRole, AuthorizedRoleAssignment, Role, RoleAssignment,
        };

        let owner = owner();
        let params = params(&owner);
        let distributor_sk = ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]);
        let recipient_sk = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let distributor = MemberId::from(&distributor_sk.verifying_key());
        let recipient = MemberId::from(&recipient_sk.verifying_key());
        let role_id = [4u8; 16];
        let category = MessageId(FastHash(22));

        let mut base = ChatBoardStateV1 {
            configuration: AuthorizedConfigurationV1::new(Configuration::default(), &owner),
            ..Default::default()
        };
        for sk in [distributor_sk.clone(), recipient_sk.clone()] {
            base.members.members.push(AuthorizedMember::new(
                Member {
                    owner_member_id: owner.verifying_key().into(),
                    invited_by: owner.verifying_key().into(),
                    member_vk: sk.verifying_key(),
                    join_proof: None,
                },
                &owner,
            ));
        }
        base.roles.roles.push(AuthorizedRole::new(
            Role {
                id: role_id,
                name: "keys".to_string(),
                generation: 1,
                can_manage_access: false,
                can_distribute_keys: true,
                can_edit_posts: false,
                can_delete_posts: false,
                can_close_posts: false,
                can_pin_posts: false,
                can_move_posts: false,
                scope: Vec::new(),
                deleted: false,
            },
            &owner,
        ));
        base.roles.assignments.push(AuthorizedRoleAssignment::new(
            RoleAssignment {
                role_id,
                member_id: distributor,
                generation: 1,
                revoked: false,
            },
            &owner,
        ));

        let version = AuthorizedSecretVersionRecord::new(
            SecretVersionRecordV1 {
                version: 0,
                cipher_spec: BoardCipherSpec::Aes256Gcm,
                created_at: SystemTime::now(),
                category_id: None,
            },
            &owner,
        );
        let blob_owner = AuthorizedEncryptedSecretForMember::new(
            EncryptedSecretForMemberV1 {
                member_id: recipient,
                secret_version: 0,
                ciphertext: vec![9, 9, 9],
                nonce: [0u8; 12],
                sender_ephemeral_public_key: [0u8; 32],
                provider: owner.verifying_key().into(),
                category_id: None,
            },
            &owner,
        );
        let blob_delegate = AuthorizedEncryptedSecretForMember::signed_by(
            EncryptedSecretForMemberV1 {
                member_id: recipient,
                secret_version: 0,
                ciphertext: vec![1, 1, 1],
                nonce: [1u8; 12],
                sender_ephemeral_public_key: [1u8; 32],
                provider: distributor,
                category_id: None,
            },
            distributor,
            &distributor_sk,
        );

        let apply = |secrets: Vec<AuthorizedEncryptedSecretForMember>| {
            let mut state = base.clone();
            let delta = CategorySecretsDelta {
                sets: vec![CategorySecretSetDelta {
                    category_id: category.clone(),
                    current_version: 0,
                    versions: vec![version.clone()],
                    encrypted_secrets: secrets,
                }],
            };
            state
                .category_secrets
                .apply_delta(&state.clone(), &params, &Some(delta))
                .unwrap();
            state.category_secrets
        };

        let first = apply(vec![blob_owner.clone(), blob_delegate.clone()]);
        let second = apply(vec![blob_delegate, blob_owner]);
        assert_eq!(first, second, "both orders must keep the same blob");
    }
}
