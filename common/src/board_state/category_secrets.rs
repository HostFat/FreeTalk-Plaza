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
use std::collections::{BTreeSet, HashMap};

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

impl ComposableState for CategorySecretsV1 {
    type ParentState = ChatBoardStateV1;
    type Summary = CategorySecretsSummary;
    type Delta = CategorySecretsDelta;
    type Parameters = ChatBoardParametersV1;

    fn verify(
        &self,
        _parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
    ) -> Result<(), String> {
        let mut seen = std::collections::HashSet::new();
        for set in &self.categories {
            if !seen.insert(set.category_id.clone()) {
                return Err("Duplicate category secret set".to_string());
            }
            for record in &set.versions {
                record.verify_signature(&parameters.owner)?;
            }
            for secret in &set.encrypted_secrets {
                secret.verify_signature(&parameters.owner)?;
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
        let mut member_secrets = BTreeSet::new();
        for set in &self.categories {
            for record in &set.versions {
                versions.insert((set.category_id.clone(), record.record.version));
            }
            for secret in &set.encrypted_secrets {
                member_secrets.insert((
                    set.category_id.clone(),
                    secret.secret.secret_version,
                    secret.secret.member_id,
                ));
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
                    !old_state_summary.member_secrets.contains(&(
                        set.category_id.clone(),
                        s.secret.secret_version,
                        s.secret.member_id,
                    ))
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
        _parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
        delta: &Option<Self::Delta>,
    ) -> Result<(), String> {
        if let Some(delta) = delta {
            for incoming in &delta.sets {
                for record in &incoming.versions {
                    record.verify_signature(&parameters.owner)?;
                }
                for secret in &incoming.encrypted_secrets {
                    secret.verify_signature(&parameters.owner)?;
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
                    if !set.encrypted_secrets.iter().any(|s| {
                        s.secret.secret_version == secret.secret.secret_version
                            && s.secret.member_id == secret.secret.member_id
                    }) {
                        set.encrypted_secrets.push(secret.clone());
                    }
                }

                set.versions.sort_by_key(|v| v.record.version);
                set.encrypted_secrets.sort_by_key(|s| {
                    (s.secret.secret_version, s.secret.member_id)
                });
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
                    s.secret.member_id == **member
                        && s.secret.secret_version == set.current_version
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
    pub member_secrets: BTreeSet<(MessageId, SecretVersion, MemberId)>,
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

    fn state_with_category(owner: &ed25519_dalek::SigningKey) -> (ChatBoardStateV1, MessageId, MemberId) {
        let category_id = MessageId(FastHash(7));
        let member = MemberId(FastHash(9));
        let version = SecretVersionRecordV1 {
            version: 1,
            cipher_spec: BoardCipherSpec::Aes256Gcm,
            created_at: SystemTime::now(),
        };
        let blob = EncryptedSecretForMemberV1 {
            member_id: member,
            secret_version: 1,
            ciphertext: vec![1, 2, 3],
            nonce: [0u8; 12],
            sender_ephemeral_public_key: [0u8; 32],
            provider: MemberId::from(&owner.verifying_key()),
        };

        let mut state = ChatBoardStateV1 {
            configuration: AuthorizedConfigurationV1::new(Configuration::default(), owner),
            ..Default::default()
        };
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

        let mut empty = ChatBoardStateV1 {
            configuration: AuthorizedConfigurationV1::new(Configuration::default(), &owner),
            ..Default::default()
        };

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
}
