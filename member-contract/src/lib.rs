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
