//! Deterministic member-directory shard contract.
//!
//! Each board splits its member list across `MEMBER_SHARD_COUNT` contracts
//! addressed by `MemberShardParametersV1 { owner, bucket }`. Every entry
//! carries its invite chain or invite token so the contract verifies incoming
//! deltas without fetching the parent board or the other shards.

use ciborium::{de::from_reader, ser::into_writer};
use freenet_stdlib::prelude::{
    contract, ContractError, ContractInterface, Parameters, RelatedContracts, State, StateDelta,
    StateSummary, UpdateData, UpdateModification, ValidateResult,
};
use plaza_core::board_state::member_shards::{
    MemberShardDeltaV1, MemberShardParametersV1, MemberShardStateV1, MemberShardSummaryV1,
};

#[allow(dead_code)]
struct MemberShardContract;

#[contract]
impl ContractInterface for MemberShardContract {
    fn validate_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts<'static>,
    ) -> Result<ValidateResult, ContractError> {
        let params = from_reader::<MemberShardParametersV1, &[u8]>(parameters.as_ref())
            .map_err(|error| ContractError::Deser(error.to_string()))?;
        params.verify().map_err(|error| ContractError::InvalidUpdateWithInfo {
            reason: format!("member shard parameters do not verify: {error}"),
        })?;
        if state.as_ref().is_empty() {
            return Ok(ValidateResult::Valid);
        }
        let shard = from_reader::<MemberShardStateV1, &[u8]>(state.as_ref())
            .map_err(|error| ContractError::Deser(error.to_string()))?;
        shard
            .verify(&params)
            .map_err(|error| ContractError::InvalidUpdateWithInfo {
                reason: format!("member shard state does not verify: {error}"),
            })?;
        Ok(ValidateResult::Valid)
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let params = from_reader::<MemberShardParametersV1, &[u8]>(parameters.as_ref())
            .map_err(|error| ContractError::Deser(error.to_string()))?;
        params.verify().map_err(|error| ContractError::InvalidUpdateWithInfo {
            reason: format!("member shard parameters do not verify: {error}"),
        })?;
        let mut shard = if state.as_ref().is_empty() {
            MemberShardStateV1::default()
        } else {
            from_reader::<MemberShardStateV1, &[u8]>(state.as_ref())
                .map_err(|error| ContractError::Deser(error.to_string()))?
        };
        for item in data {
            match item {
                UpdateData::State(bytes) => {
                    if bytes.as_ref().is_empty() {
                        continue;
                    }
                    let incoming = from_reader::<MemberShardStateV1, &[u8]>(bytes.as_ref())
                        .map_err(|error| ContractError::Deser(error.to_string()))?;
                    let delta = MemberShardDeltaV1 {
                        entries: incoming.entries,
                    };
                    shard.apply_delta(&params, &delta).map_err(|error| {
                        ContractError::InvalidUpdateWithInfo {
                            reason: format!("member shard state merge failed: {error}"),
                        }
                    })?;
                }
                UpdateData::Delta(bytes) => {
                    if bytes.as_ref().is_empty() {
                        continue;
                    }
                    let delta = from_reader::<MemberShardDeltaV1, &[u8]>(bytes.as_ref())
                        .map_err(|error| ContractError::Deser(error.to_string()))?;
                    shard.apply_delta(&params, &delta).map_err(|error| {
                        ContractError::InvalidUpdateWithInfo {
                            reason: format!("member shard delta does not verify: {error}"),
                        }
                    })?;
                }
                UpdateData::StateAndDelta {
                    state: state_bytes,
                    delta: delta_bytes,
                } => {
                    if !state_bytes.as_ref().is_empty() {
                        let incoming =
                            from_reader::<MemberShardStateV1, &[u8]>(state_bytes.as_ref())
                                .map_err(|error| ContractError::Deser(error.to_string()))?;
                        let delta = MemberShardDeltaV1 {
                            entries: incoming.entries,
                        };
                        shard.apply_delta(&params, &delta).map_err(|error| {
                            ContractError::InvalidUpdateWithInfo {
                                reason: format!("member shard state merge failed: {error}"),
                            }
                        })?;
                    }
                    if !delta_bytes.as_ref().is_empty() {
                        let delta =
                            from_reader::<MemberShardDeltaV1, &[u8]>(delta_bytes.as_ref())
                                .map_err(|error| ContractError::Deser(error.to_string()))?;
                        shard.apply_delta(&params, &delta).map_err(|error| {
                            ContractError::InvalidUpdateWithInfo {
                                reason: format!("member shard delta does not verify: {error}"),
                            }
                        })?;
                    }
                }
                _ => {}
            }
        }
        let mut updated = Vec::new();
        into_writer(&shard, &mut updated)
            .map_err(|error| ContractError::Deser(error.to_string()))?;
        Ok(UpdateModification::valid(updated.into()))
    }

    fn summarize_state(
        _parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        let shard = if state.as_ref().is_empty() {
            MemberShardStateV1::default()
        } else {
            from_reader::<MemberShardStateV1, &[u8]>(state.as_ref())
                .map_err(|error| ContractError::Deser(error.to_string()))?
        };
        let summary = shard.summarize();
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
        let shard = from_reader::<MemberShardStateV1, &[u8]>(state.as_ref())
            .map_err(|error| ContractError::Deser(error.to_string()))?;
        let old_summary = if summary.as_ref().is_empty() {
            MemberShardSummaryV1::default()
        } else {
            from_reader::<MemberShardSummaryV1, &[u8]>(summary.as_ref())
                .map_err(|error| ContractError::Deser(error.to_string()))?
        };
        match shard.delta(&old_summary) {
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
pub extern "C" fn plaza_member_contract_revision() -> u32 {
    plaza_core::CONTRACT_REVISION
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use plaza_core::board_state::member::{AuthorizedMember, Member, MemberId};
    use plaza_core::board_state::member_shards::{member_shard_bucket, MemberShardEntryV1};

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
            if member_shard_bucket(&MemberId::from(&key.verifying_key())) == target {
                return (key, seed + 1);
            }
            seed += 1;
        }
    }

    fn owner_entry(owner: &SigningKey, member_sk: &SigningKey) -> MemberShardEntryV1 {
        let owner_id = MemberId::from(&owner.verifying_key());
        MemberShardEntryV1 {
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
        }
    }

    #[test]
    fn summarize_delta_and_state_and_delta_round_trip() {
        let owner = SigningKey::from_bytes(&[1u8; 32]);
        let params_val = MemberShardParametersV1 {
            owner: owner.verifying_key(),
            bucket: 0,
        };
        let params = Parameters::from(cbor!(&params_val));

        let (k1, next) = key_for_bucket(0, 1);
        let (k2, next) = key_for_bucket(0, next);
        let (k3, _) = key_for_bucket(0, next);
        let e1 = owner_entry(&owner, &k1);
        let e2 = owner_entry(&owner, &k2);
        let e3 = owner_entry(&owner, &k3);

        let peer_a = MemberShardContract::update_state(
            params.clone(),
            State::from(Vec::new()),
            vec![UpdateData::Delta(
                cbor!(&MemberShardDeltaV1 { entries: vec![e1.clone()] }).into(),
            )],
        )
        .unwrap()
        .new_state
        .unwrap();
        assert_eq!(
            MemberShardContract::validate_state(params.clone(), peer_a.clone(), Default::default())
                .unwrap(),
            ValidateResult::Valid
        );

        let peer_b = MemberShardContract::update_state(
            params.clone(),
            peer_a.clone(),
            vec![UpdateData::StateAndDelta {
                state: cbor!(&MemberShardStateV1 { entries: vec![e2] }).into(),
                delta: cbor!(&MemberShardDeltaV1 { entries: vec![e3] }).into(),
            }],
        )
        .unwrap()
        .new_state
        .unwrap();

        let summary_a =
            MemberShardContract::summarize_state(params.clone(), peer_a.clone()).unwrap();
        let delta_bytes =
            MemberShardContract::get_state_delta(params.clone(), peer_b.clone(), summary_a)
                .unwrap();
        let decoded_delta: MemberShardDeltaV1 = from_reader(delta_bytes.as_ref()).unwrap();
        assert_eq!(decoded_delta.entries.len(), 2);

        let synced_a = MemberShardContract::update_state(
            params.clone(),
            peer_a,
            vec![UpdateData::Delta(delta_bytes)],
        )
        .unwrap()
        .new_state
        .unwrap();
        assert_eq!(synced_a.as_ref(), peer_b.as_ref());

        let summary_synced = MemberShardContract::summarize_state(params.clone(), synced_a).unwrap();
        let empty_delta =
            MemberShardContract::get_state_delta(params, peer_b, summary_synced).unwrap();
        assert!(empty_delta.as_ref().is_empty());
    }
}
