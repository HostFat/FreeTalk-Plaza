use crate::board_state::member::MemberId;
use crate::board_state::rate_limit::system_time_from_ms;
use crate::board_state::ChatBoardParametersV1;
use crate::util::{sign_struct, truncated_base64, verify_struct};
use crate::ChatBoardStateV1;
use blake3::Hash;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use freenet_scaffold::ComposableState;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct OptionalUpgradeV1(pub Option<AuthorizedUpgradeV1>);

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct AuthorizedUpgradeV1 {
    pub upgrade: UpgradeV1,
    pub signature: Signature,
    /// Optional signer key for post-transfer / post-succession owners. When
    /// omitted, verification falls back to the owner key resolved from
    /// `OwnershipV1` (or the founding owner).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_key: Option<VerifyingKey>,
}

impl ComposableState for OptionalUpgradeV1 {
    type ParentState = ChatBoardStateV1;
    type Summary = Option<u8>;
    type Delta = AuthorizedUpgradeV1;
    type Parameters = ChatBoardParametersV1;

    fn verify(
        &self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
    ) -> Result<(), String> {
        if let Some(upgrade) = &self.0 {
            upgrade.verify_against(parent_state, parameters)
        } else {
            Ok(())
        }
    }

    fn summarize(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
    ) -> Self::Summary {
        self.0.as_ref().map(|u| u.upgrade.version)
    }

    fn delta(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
        old_state_summary: &Self::Summary,
    ) -> Option<Self::Delta> {
        match &self.0 {
            Some(upgrade) => {
                // If the upgrade has a higher version than the old board_state summary or of the old summary is None
                // then return the upgrade as a delta
                if old_state_summary.is_none_or(|old_version| upgrade.upgrade.version > old_version)
                {
                    Some(upgrade.clone())
                } else {
                    None
                }
            }
            None => None,
        }
    }

    fn apply_delta(
        &mut self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
        delta: &Option<Self::Delta>,
    ) -> Result<(), String> {
        if let Some(delta) = delta {
            // Verify the delta before applying it
            delta.verify_against(parent_state, parameters)?;
            if self
                .0
                .as_ref()
                .is_none_or(|existing| delta.upgrade.version >= existing.upgrade.version)
            {
                *self = OptionalUpgradeV1(Some(delta.clone()));
            }
        }
        Ok(())
    }
}

impl AuthorizedUpgradeV1 {
    pub fn new(upgrade: UpgradeV1, signing_key: &SigningKey) -> Self {
        Self {
            upgrade: upgrade.clone(),
            signature: sign_struct(&upgrade, signing_key),
            signer_key: Some(signing_key.verifying_key()),
        }
    }

    /// Create an AuthorizedUpgradeV1 with a pre-computed signature.
    /// Use this when signing is done externally (e.g., via delegate).
    pub fn with_signature(upgrade: UpgradeV1, signature: Signature) -> Self {
        Self {
            upgrade,
            signature,
            signer_key: None,
        }
    }

    pub fn validate(
        &self,
        verifying_key: &VerifyingKey,
    ) -> Result<(), ed25519_dalek::SignatureError> {
        verify_struct(&self.upgrade, &self.signature, verifying_key)
    }

    /// Verify against the board's current owner (supporting ownership transfer
    /// and admin-quorum succession in addition to the founding owner).
    pub fn verify_against(
        &self,
        parent_state: &ChatBoardStateV1,
        parameters: &ChatBoardParametersV1,
    ) -> Result<(), String> {
        let owner_key = if self.upgrade.created_at > 0 {
            parent_state
                .ownership
                .owner_key_at(parameters, system_time_from_ms(self.upgrade.created_at))
        } else {
            parent_state.ownership.current_owner_key(parameters)
        };
        if let Some(key) = self.signer_key {
            if key != owner_key && key != parameters.owner {
                return Err("upgrade signer key does not match the board owner".to_string());
            }
        }
        if self.validate(&owner_key).is_ok() {
            return Ok(());
        }
        // Preserve compatibility for upgrades signed before a later transfer
        // when `created_at` was omitted (legacy 0).
        if self.upgrade.created_at == 0 && self.validate(&parameters.owner).is_ok() {
            return Ok(());
        }
        Err("Invalid upgrade signature".to_string())
    }
}

impl fmt::Debug for AuthorizedUpgradeV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizedUpgrade")
            .field("upgrade", &self.upgrade)
            .field(
                "signature",
                &format_args!("{}", truncated_base64(self.signature.to_bytes())),
            )
            .finish()
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct UpgradeV1 {
    pub owner_member_id: MemberId,
    pub version: u8,
    pub new_chatboard_address: Hash,
    /// Target `CONTRACT_REVISION` of the upgraded board, if known.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub new_revision: u32,
    /// Client timestamp (ms since epoch) when the pointer was issued.
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub created_at: i64,
}

fn is_zero_u32(value: &u32) -> bool {
    *value == 0
}

fn is_zero_i64(value: &i64) -> bool {
    *value == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board_state::member::MemberId;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn create_test_upgrade(owner_id: MemberId) -> UpgradeV1 {
        UpgradeV1 {
            owner_member_id: owner_id,
            version: 1,
            new_chatboard_address: Hash::from([0; 32]),
            new_revision: 0,
            created_at: 0,
        }
    }

    #[test]
    fn test_authorized_upgrade_new_and_validate() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let owner_id = MemberId::from_bytes([0u8; 32]);

        let upgrade = create_test_upgrade(owner_id);
        let authorized_upgrade = AuthorizedUpgradeV1::new(upgrade.clone(), &signing_key);

        assert_eq!(authorized_upgrade.upgrade, upgrade);
        assert!(authorized_upgrade.validate(&verifying_key).is_ok());

        // Test with wrong key
        let wrong_key = SigningKey::generate(&mut OsRng).verifying_key();
        assert!(authorized_upgrade.validate(&wrong_key).is_err());
    }

    #[test]
    fn test_optional_upgrade_verify() {
        let owner_signing_key = SigningKey::generate(&mut OsRng);
        let owner_verifying_key = owner_signing_key.verifying_key();
        let owner_id = MemberId::from(&owner_verifying_key);

        let upgrade = create_test_upgrade(owner_id);
        let authorized_upgrade = AuthorizedUpgradeV1::new(upgrade, &owner_signing_key);

        let optional_upgrade = OptionalUpgradeV1(Some(authorized_upgrade));

        let parent_state = ChatBoardStateV1::default();
        let parameters = ChatBoardParametersV1 {
            owner: owner_verifying_key,
        };

        // Verify that a valid upgrade passes verification
        assert!(
            optional_upgrade.verify(&parent_state, &parameters).is_ok(),
            "Valid upgrade should pass verification"
        );

        // Test with invalid signature
        let mut invalid_upgrade = optional_upgrade.clone();
        if let Some(ref mut au) = invalid_upgrade.0 {
            au.signature = Signature::from_bytes(&[0; 64]); // Replace with an invalid signature
        }
        assert!(
            invalid_upgrade.verify(&parent_state, &parameters).is_err(),
            "Upgrade with invalid signature should fail verification"
        );

        // Test with None
        let none_upgrade = OptionalUpgradeV1(None);
        assert!(
            none_upgrade.verify(&parent_state, &parameters).is_ok(),
            "None upgrade should pass verification"
        );
    }

    #[test]
    fn test_optional_upgrade_summarize() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let owner_id = MemberId::from_bytes([0u8; 32]);

        let upgrade = create_test_upgrade(owner_id);
        let authorized_upgrade = AuthorizedUpgradeV1::new(upgrade, &signing_key);

        let optional_upgrade = OptionalUpgradeV1(Some(authorized_upgrade));

        let parent_state = ChatBoardStateV1::default();
        let parameters = ChatBoardParametersV1 {
            owner: signing_key.verifying_key(),
        };

        let summary = optional_upgrade.summarize(&parent_state, &parameters);
        assert_eq!(summary, Some(1));

        let none_upgrade = OptionalUpgradeV1(None);
        let none_summary = none_upgrade.summarize(&parent_state, &parameters);
        assert_eq!(none_summary, None);
    }

    #[test]
    fn test_optional_upgrade_delta() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let owner_id = MemberId::from_bytes([0u8; 32]);

        let upgrade = create_test_upgrade(owner_id);
        let authorized_upgrade = AuthorizedUpgradeV1::new(upgrade, &signing_key);

        let optional_upgrade = OptionalUpgradeV1(Some(authorized_upgrade.clone()));

        let parent_state = ChatBoardStateV1::default();
        let parameters = ChatBoardParametersV1 {
            owner: signing_key.verifying_key(),
        };

        let old_summary = None;
        let delta = optional_upgrade.delta(&parent_state, &parameters, &old_summary);

        assert_eq!(delta, Some(authorized_upgrade));

        let none_upgrade = OptionalUpgradeV1(None);
        let none_delta = none_upgrade.delta(&parent_state, &parameters, &old_summary);
        assert_eq!(none_delta, None);
    }

    #[test]
    fn test_optional_upgrade_apply_delta() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let owner_id = MemberId::from_bytes([0u8; 32]);

        let upgrade = create_test_upgrade(owner_id);
        let authorized_upgrade = AuthorizedUpgradeV1::new(upgrade, &signing_key);

        let mut optional_upgrade = OptionalUpgradeV1(None);

        let parent_state = ChatBoardStateV1::default();
        let parameters = ChatBoardParametersV1 {
            owner: signing_key.verifying_key(),
        };

        let delta = authorized_upgrade.clone();
        assert!(optional_upgrade
            .apply_delta(&parent_state, &parameters, &Some(delta.clone()))
            .is_ok());
        assert_eq!(optional_upgrade, OptionalUpgradeV1(Some(delta)));
    }

    #[test]
    fn post_transfer_owner_can_sign_upgrade_pointer() {
        use crate::board_state::member::{AuthorizedMember, Member};
        use crate::board_state::ownership::{
            AuthorizedOwnerTransfer, OutgoingOwnerAction, OwnerTransferV1,
        };

        let mut rng = OsRng;
        let founder = SigningKey::generate(&mut rng);
        let successor = SigningKey::generate(&mut rng);
        let params = ChatBoardParametersV1 {
            owner: founder.verifying_key(),
        };
        let mut parent = ChatBoardStateV1::default();
        let successor_member = AuthorizedMember::new(
            Member {
                owner_member_id: MemberId::from(&founder.verifying_key()),
                invited_by: MemberId::from(&founder.verifying_key()),
                member_vk: successor.verifying_key(),
                join_proof: None,
            },
            &founder,
        );
        parent.members.members.push(successor_member);
        parent.ownership.transfers.push(AuthorizedOwnerTransfer::new(
            OwnerTransferV1 {
                from: MemberId::from(&founder.verifying_key()),
                to: MemberId::from(&successor.verifying_key()),
                to_key: successor.verifying_key(),
                generation: 1,
                transferred_at: system_time_from_ms(1_000),
                outgoing: OutgoingOwnerAction::KeepAdmin,
            },
            &founder,
        ));

        let upgrade = UpgradeV1 {
            owner_member_id: MemberId::from(&founder.verifying_key()),
            version: 2,
            new_chatboard_address: blake3::hash(b"rev38_board"),
            new_revision: 38,
            created_at: 2_000,
        };
        let authorized = AuthorizedUpgradeV1::new(upgrade, &successor);
        let mut state = OptionalUpgradeV1::default();
        state
            .apply_delta(&parent, &params, &Some(authorized))
            .expect("post-transfer owner should be allowed to sign upgrade pointer");
        state.verify(&parent, &params).unwrap();
    }
}
