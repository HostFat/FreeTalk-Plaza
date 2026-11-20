//! Per-member Freenet Mail addresses published on a board.
//!
//! This is a small dedicated state instead of an append-only action, so a
//! member can clear the address from the current state with a tombstone. The
//! contract keeps one record per member and rejects older versions.

use crate::board_state::member::MemberId;
use crate::board_state::privacy::SealedBytes;
use crate::board_state::ChatBoardParametersV1;
use crate::board_state::ChatBoardStateV1;
use crate::util::{sign_struct, verify_struct};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use freenet_scaffold::ComposableState;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

/// The address is a short string. The cap keeps a member from inflating board
/// state with a huge value.
pub const MAX_MAIL_ADDRESS_BYTES: usize = 256;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct MailAddressesV1 {
    pub records: Vec<AuthorizedMailAddress>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthorizedMailAddress {
    pub record: MailAddressRecord,
    pub signature: Signature,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MailAddressRecord {
    pub member_id: MemberId,
    pub version: u32,
    /// `None` is a tombstone: the member cleared the address. Keeping the
    /// tombstone stops an older record from being replayed.
    pub address: Option<SealedBytes>,
    /// Signed time in milliseconds.
    pub updated_at: i64,
}

impl AuthorizedMailAddress {
    pub fn new(record: MailAddressRecord, signing_key: &SigningKey) -> Self {
        let signature = sign_struct(&record, signing_key);
        Self { record, signature }
    }

    pub fn verify_with_key(&self, verifying_key: &VerifyingKey) -> Result<(), String> {
        verify_struct(&self.record, &self.signature, verifying_key)
            .map_err(|error| format!("Invalid mail address signature: {error}"))
    }
}

impl MailAddressesV1 {
    pub fn record_for(&self, member_id: MemberId) -> Option<&MailAddressRecord> {
        self.records
            .iter()
            .find(|authorized| authorized.record.member_id == member_id)
            .map(|authorized| &authorized.record)
    }

    /// The current address for a member, or `None` when absent or cleared.
    pub fn address_for(&self, member_id: MemberId) -> Option<&SealedBytes> {
        self.record_for(member_id)
            .and_then(|record| record.address.as_ref())
    }

    fn signing_key_for(
        parent_state: &ChatBoardStateV1,
        parameters: &ChatBoardParametersV1,
        member_id: MemberId,
    ) -> Result<VerifyingKey, String> {
        if member_id == parameters.owner_id() {
            return Ok(parameters.owner);
        }
        parent_state
            .members
            .members_by_member_id()
            .get(&member_id)
            .map(|member| member.member.member_vk)
            .ok_or_else(|| format!("Mail address for non-existent member: {member_id:?}"))
    }

    fn validate_record(record: &MailAddressRecord) -> Result<(), String> {
        if let Some(address) = &record.address {
            if address.declared_len() > MAX_MAIL_ADDRESS_BYTES {
                return Err(format!(
                    "Mail address declared length {} exceeds {}",
                    address.declared_len(),
                    MAX_MAIL_ADDRESS_BYTES
                ));
            }
        }
        Ok(())
    }
}

impl ComposableState for MailAddressesV1 {
    type ParentState = ChatBoardStateV1;
    type Summary = BTreeMap<MemberId, u32>;
    type Delta = Vec<AuthorizedMailAddress>;
    type Parameters = ChatBoardParametersV1;

    fn verify(
        &self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
    ) -> Result<(), String> {
        let mut seen = HashSet::new();
        for authorized in &self.records {
            let member_id = authorized.record.member_id;
            if !seen.insert(member_id) {
                return Err(format!("Duplicate mail address for member: {member_id:?}"));
            }
            Self::validate_record(&authorized.record)?;
            let key = Self::signing_key_for(parent_state, parameters, member_id)?;
            authorized.verify_with_key(&key)?;
        }
        Ok(())
    }

    fn summarize(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
    ) -> Self::Summary {
        self.records
            .iter()
            .map(|authorized| (authorized.record.member_id, authorized.record.version))
            .collect()
    }

    fn delta(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
        old_state_summary: &Self::Summary,
    ) -> Option<Self::Delta> {
        let records: Vec<_> = self
            .records
            .iter()
            .filter(|authorized| {
                old_state_summary
                    .get(&authorized.record.member_id)
                    .map(|version| authorized.record.version > *version)
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        if records.is_empty() {
            None
        } else {
            Some(records)
        }
    }

    fn apply_delta(
        &mut self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
        delta: &Option<Self::Delta>,
    ) -> Result<(), String> {
        if let Some(delta) = delta {
            for authorized in delta {
                let member_id = authorized.record.member_id;
                let key = Self::signing_key_for(parent_state, parameters, member_id)?;
                authorized.verify_with_key(&key)?;
                Self::validate_record(&authorized.record)?;

                if let Some(existing) = self
                    .records
                    .iter_mut()
                    .find(|existing| existing.record.member_id == member_id)
                {
                    if authorized.record.version > existing.record.version {
                        *existing = authorized.clone();
                    } else if authorized.record.version == existing.record.version
                        && authorized.record != existing.record
                    {
                        return Err(format!(
                            "Conflicting mail address versions for member: {member_id:?}"
                        ));
                    }
                } else {
                    self.records.push(authorized.clone());
                }
            }
        }

        // Keep only the current owner and members. A record for someone who
        // left is not useful and would let a stale peer keep state alive.
        let owner_id = parameters.owner_id();
        let members = parent_state.members.members_by_member_id();
        self.records.retain(|authorized| {
            let id = authorized.record.member_id;
            id == owner_id || members.contains_key(&id)
        });
        self.records
            .sort_by_key(|authorized| authorized.record.member_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board_state::configuration::{AuthorizedConfigurationV1, Configuration};
    use crate::board_state::member::{AuthorizedMember, Member};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn fixture() -> (
        ChatBoardStateV1,
        ChatBoardParametersV1,
        SigningKey,
        SigningKey,
    ) {
        let owner = SigningKey::generate(&mut OsRng);
        let member = SigningKey::generate(&mut OsRng);
        let owner_vk = owner.verifying_key();
        let member_vk = member.verifying_key();
        let mut state = ChatBoardStateV1::default();
        state.configuration = AuthorizedConfigurationV1::new(
            Configuration {
                owner_member_id: owner_vk.into(),
                ..Configuration::default()
            },
            &owner,
        );
        state.members.members.push(AuthorizedMember::new(
            Member {
                owner_member_id: owner_vk.into(),
                invited_by: owner_vk.into(),
                member_vk,
                join_proof: None,
            },
            &owner,
        ));
        (
            state,
            ChatBoardParametersV1 { owner: owner_vk },
            owner,
            member,
        )
    }

    #[test]
    fn a_member_publishes_and_clears_their_address() {
        let (state, params, _owner, member) = fixture();
        let member_id = MemberId::from(&member.verifying_key());
        let address = SealedBytes::public(b"alice@123456789ABCDEFGHJKLMNPQRSTUVWXYZab".to_vec());
        let record = MailAddressRecord {
            member_id,
            version: 0,
            address: Some(address),
            updated_at: 1,
        };
        let mut mail = MailAddressesV1::default();
        mail.apply_delta(
            &state,
            &params,
            &Some(vec![AuthorizedMailAddress::new(record, &member)]),
        )
        .unwrap();
        assert!(mail.address_for(member_id).is_some());

        let tombstone = MailAddressRecord {
            member_id,
            version: 1,
            address: None,
            updated_at: 2,
        };
        mail.apply_delta(
            &state,
            &params,
            &Some(vec![AuthorizedMailAddress::new(tombstone, &member)]),
        )
        .unwrap();
        assert_eq!(mail.address_for(member_id), None);

        // A stale record cannot bring the address back.
        let stale = MailAddressRecord {
            member_id,
            version: 0,
            address: Some(SealedBytes::public(
                b"old@123456789ABCDEFGHJKLMNPQRSTUVWXYZab".to_vec(),
            )),
            updated_at: 1,
        };
        mail.apply_delta(
            &state,
            &params,
            &Some(vec![AuthorizedMailAddress::new(stale, &member)]),
        )
        .unwrap();
        assert_eq!(mail.address_for(member_id), None);
    }

    #[test]
    fn another_member_cannot_sign_for_this_member() {
        let (state, params, owner, member) = fixture();
        let member_id = MemberId::from(&member.verifying_key());
        let record = MailAddressRecord {
            member_id,
            version: 0,
            address: Some(SealedBytes::public(
                b"spoof@123456789ABCDEFGHJKLMNPQRSTUVWXYZab".to_vec(),
            )),
            updated_at: 1,
        };
        let mut mail = MailAddressesV1::default();
        let error = mail
            .apply_delta(
                &state,
                &params,
                &Some(vec![AuthorizedMailAddress::new(record, &owner)]),
            )
            .expect_err("the owner key cannot sign a member's record");
        assert!(error.contains("signature"), "{error}");
    }

    #[test]
    fn an_oversized_address_is_rejected() {
        let (state, params, _owner, member) = fixture();
        let member_id = MemberId::from(&member.verifying_key());
        let record = MailAddressRecord {
            member_id,
            version: 0,
            address: Some(SealedBytes::public(vec![b'x'; MAX_MAIL_ADDRESS_BYTES + 1])),
            updated_at: 1,
        };
        let mut mail = MailAddressesV1::default();
        let error = mail
            .apply_delta(
                &state,
                &params,
                &Some(vec![AuthorizedMailAddress::new(record, &member)]),
            )
            .expect_err("oversized addresses are rejected");
        assert!(error.contains("exceeds"), "{error}");
    }
}
