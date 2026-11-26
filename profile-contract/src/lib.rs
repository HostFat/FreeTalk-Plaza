//! Deterministic sharded per-board profile contract.
//!
//! Nicknames used to live in the board state (and then in a single per-board
//! profile feed that grew to ~3.2 MiB at 10,000 members). Profiles now live in
//! `PROFILE_SHARD_COUNT` fixed buckets addressed by
//! `ProfileShardParametersV1 { owner, bucket }`, matching `member-contract`,
//! with incremental `summarize_state` / `get_state_delta`.

use ciborium::{de::from_reader, ser::into_writer};
use freenet_stdlib::prelude::{
    contract, ContractError, ContractInterface, Parameters, RelatedContracts, State, StateDelta,
    StateSummary, UpdateData, UpdateModification, ValidateResult,
};
use plaza_core::board_state::profiles::{
    ProfileDeltaV1, ProfileShardParametersV1, ProfileStateV1, ProfileSummaryV1,
};

#[allow(dead_code)]
struct ProfileContract;

#[contract]
impl ContractInterface for ProfileContract {
    fn validate_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts<'static>,
    ) -> Result<ValidateResult, ContractError> {
        let params = from_reader::<ProfileShardParametersV1, &[u8]>(parameters.as_ref())
            .map_err(|error| ContractError::Deser(error.to_string()))?;
        params
            .verify()
            .map_err(|error| ContractError::InvalidUpdateWithInfo {
                reason: format!("profile shard parameters do not verify: {error}"),
            })?;
        if state.as_ref().is_empty() {
            return Ok(ValidateResult::Valid);
        }
        let profiles = from_reader::<ProfileStateV1, &[u8]>(state.as_ref())
            .map_err(|error| ContractError::Deser(error.to_string()))?;
        profiles
            .verify(&params)
            .map_err(|error| ContractError::InvalidUpdateWithInfo {
                reason: format!("profile state does not verify: {error}"),
            })?;
        Ok(ValidateResult::Valid)
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let params = from_reader::<ProfileShardParametersV1, &[u8]>(parameters.as_ref())
            .map_err(|error| ContractError::Deser(error.to_string()))?;
        params
            .verify()
            .map_err(|error| ContractError::InvalidUpdateWithInfo {
                reason: format!("profile shard parameters do not verify: {error}"),
            })?;
        let mut profiles = if state.as_ref().is_empty() {
            ProfileStateV1::default()
        } else {
            from_reader::<ProfileStateV1, &[u8]>(state.as_ref())
                .map_err(|error| ContractError::Deser(error.to_string()))?
        };
        for update in data {
            match update {
                UpdateData::State(bytes) => {
                    if bytes.as_ref().is_empty() {
                        continue;
                    }
                    // Additive, so creating or repairing the shard never drops
                    // profiles written by another client.
                    let next = from_reader::<ProfileStateV1, &[u8]>(bytes.as_ref())
                        .map_err(|error| ContractError::Deser(error.to_string()))?;
                    profiles
                        .apply_delta(
                            &params,
                            &ProfileDeltaV1 {
                                entries: next.entries,
                            },
                        )
                        .map_err(|error| ContractError::InvalidUpdateWithInfo {
                            reason: format!("profile state does not verify: {error}"),
                        })?;
                }
                UpdateData::Delta(bytes) => {
                    if bytes.as_ref().is_empty() {
                        continue;
                    }
                    let delta = from_reader::<ProfileDeltaV1, &[u8]>(bytes.as_ref())
                        .map_err(|error| ContractError::Deser(error.to_string()))?;
                    profiles.apply_delta(&params, &delta).map_err(|error| {
                        ContractError::InvalidUpdateWithInfo {
                            reason: format!("profile delta does not verify: {error}"),
                        }
                    })?;
                }
                UpdateData::StateAndDelta {
                    state: state_bytes,
                    delta: delta_bytes,
                } => {
                    if !state_bytes.as_ref().is_empty() {
                        let next = from_reader::<ProfileStateV1, &[u8]>(state_bytes.as_ref())
                            .map_err(|error| ContractError::Deser(error.to_string()))?;
                        profiles
                            .apply_delta(
                                &params,
                                &ProfileDeltaV1 {
                                    entries: next.entries,
                                },
                            )
                            .map_err(|error| ContractError::InvalidUpdateWithInfo {
                                reason: format!("profile state does not verify: {error}"),
                            })?;
                    }
                    if !delta_bytes.as_ref().is_empty() {
                        let delta = from_reader::<ProfileDeltaV1, &[u8]>(delta_bytes.as_ref())
                            .map_err(|error| ContractError::Deser(error.to_string()))?;
                        profiles.apply_delta(&params, &delta).map_err(|error| {
                            ContractError::InvalidUpdateWithInfo {
                                reason: format!("profile delta does not verify: {error}"),
                            }
                        })?;
                    }
                }
                _ => {}
            }
        }
        let mut updated = Vec::new();
        into_writer(&profiles, &mut updated)
            .map_err(|error| ContractError::Deser(error.to_string()))?;
        Ok(UpdateModification::valid(updated.into()))
    }

    fn summarize_state(
        _parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        let profiles = if state.as_ref().is_empty() {
            ProfileStateV1::default()
        } else {
            from_reader::<ProfileStateV1, &[u8]>(state.as_ref())
                .map_err(|error| ContractError::Deser(error.to_string()))?
        };
        let summary = profiles.summarize();
        let mut bytes = Vec::new();
        into_writer(&summary, &mut bytes)
            .map_err(|error| ContractError::Deser(error.to_string()))?;
        Ok(StateSummary::from(bytes))
    }

    fn get_state_delta(
        _parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        if state.as_ref().is_empty() {
            return Ok(StateDelta::from(Vec::new()));
        }
        let profiles = from_reader::<ProfileStateV1, &[u8]>(state.as_ref())
            .map_err(|error| ContractError::Deser(error.to_string()))?;
        let old_summary = if summary.as_ref().is_empty() {
            ProfileSummaryV1::default()
        } else {
            from_reader::<ProfileSummaryV1, &[u8]>(summary.as_ref())
                .map_err(|error| ContractError::Deser(error.to_string()))?
        };
        match profiles.delta(&old_summary) {
            Some(delta) => {
                let mut bytes = Vec::new();
                into_writer(&delta, &mut bytes)
                    .map_err(|error| ContractError::Deser(error.to_string()))?;
                Ok(StateDelta::from(bytes))
            }
            None => Ok(StateDelta::from(Vec::new())),
        }
    }
}

#[no_mangle]
pub extern "C" fn plaza_profile_contract_revision() -> u32 {
    3
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use plaza_core::board_state::member::{AuthorizedMember, Member, MemberId};
    use plaza_core::board_state::member_info::MemberInfo;
    use plaza_core::board_state::member_shards::{MemberProofV1, MemberShardEntryV1};
    use plaza_core::board_state::privacy::SealedBytes;
    use plaza_core::board_state::profiles::{profile_shard_bucket, ProfileEntryV1};

    macro_rules! cbor {
        ($value:expr) => {{
            let mut out = Vec::new();
            into_writer($value, &mut out).unwrap();
            out
        }};
    }

    fn key_for_bucket(target: u16, mut seed: u64) -> (SigningKey, u64) {
        loop {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&seed.to_le_bytes());
            let key = SigningKey::from_bytes(&bytes);
            if profile_shard_bucket(&MemberId::from(&key.verifying_key())) == target {
                return (key, seed + 1);
            }
            seed += 1;
        }
    }

    fn proof_for(owner: &SigningKey, member_sk: &SigningKey) -> MemberProofV1 {
        let owner_id = MemberId::from(&owner.verifying_key());
        MemberProofV1 {
            ownership_transfers: Vec::new(),
            transfer_admins: Vec::new(),
            membership: Some(Box::new(MemberShardEntryV1 {
                member: AuthorizedMember::new(
                    Member {
                        owner_member_id: owner_id,
                        invited_by: owner_id,
                        member_vk: member_sk.verifying_key(),
                        join_proof: None,
                    },
                    owner,
                ),
                invite_chain: Vec::new(),
                invite_token: None,
                ownership_transfers: Vec::new(),
                transfer_admins: Vec::new(),
            })),
        }
    }

    #[test]
    fn summarize_and_get_state_delta_round_trip() {
        let owner_sk = SigningKey::from_bytes(&[1u8; 32]);
        let owner = owner_sk.verifying_key();
        let params_val = ProfileShardParametersV1 { owner, bucket: 0 };
        let params = Parameters::from(cbor!(&params_val));

        let (k1, next) = key_for_bucket(0, 1);
        let (k2, _) = key_for_bucket(0, next);
        let e1 = ProfileEntryV1::new(
            MemberInfo::new_public(MemberId::from(&k1.verifying_key()), 1, "Alice".into()),
            &k1,
        )
        .with_proof(proof_for(&owner_sk, &k1));
        let e2 = ProfileEntryV1::new(
            MemberInfo::new_public(MemberId::from(&k2.verifying_key()), 1, "Bob".into()),
            &k2,
        )
        .with_proof(proof_for(&owner_sk, &k2));
        let e1_v2 = ProfileEntryV1::new(
            MemberInfo {
                member_id: MemberId::from(&k1.verifying_key()),
                version: 2,
                preferred_nickname: SealedBytes::public(b"Alice2".to_vec()),
            },
            &k1,
        )
        .with_proof(proof_for(&owner_sk, &k1));

        let peer_a = ProfileContract::update_state(
            params.clone(),
            State::from(Vec::new()),
            vec![UpdateData::Delta(cbor!(&ProfileDeltaV1 { entries: vec![e1] }).into())],
        )
        .unwrap()
        .new_state
        .unwrap();
        assert_eq!(
            ProfileContract::validate_state(params.clone(), peer_a.clone(), Default::default())
                .unwrap(),
            ValidateResult::Valid
        );

        let peer_b = ProfileContract::update_state(
            params.clone(),
            peer_a.clone(),
            vec![UpdateData::Delta(
                cbor!(&ProfileDeltaV1 {
                    entries: vec![e1_v2, e2],
                })
                .into(),
            )],
        )
        .unwrap()
        .new_state
        .unwrap();

        let summary_a = ProfileContract::summarize_state(params.clone(), peer_a.clone()).unwrap();
        let delta_bytes =
            ProfileContract::get_state_delta(params.clone(), peer_b.clone(), summary_a).unwrap();
        let decoded_delta: ProfileDeltaV1 = from_reader(delta_bytes.as_ref()).unwrap();
        assert_eq!(decoded_delta.entries.len(), 2);

        let synced_a = ProfileContract::update_state(
            params.clone(),
            peer_a,
            vec![UpdateData::Delta(delta_bytes)],
        )
        .unwrap()
        .new_state
        .unwrap();
        assert_eq!(synced_a.as_ref(), peer_b.as_ref());

        let summary_synced = ProfileContract::summarize_state(params.clone(), synced_a).unwrap();
        let empty_delta =
            ProfileContract::get_state_delta(params, peer_b, summary_synced).unwrap();
        assert!(empty_delta.as_ref().is_empty());
    }
}
