//! Freenet contract entry point for `plaza-topic`.
//!
//! Phase 0: validates the signed header and the state envelope. Participant,
//! post, action and authority records land in Phase 1.

use ciborium::ser::into_writer;
use freenet_stdlib::prelude::*;
use plaza_topic_core::{
    decode_delta, decode_params, decode_state, decode_summary, encode, TopicStateSummaryV1,
    TopicStateV1, MAX_TOPIC_STATE_BYTES,
};

#[allow(dead_code)]
struct Contract;

fn contract_error(error: String) -> ContractError {
    ContractError::InvalidUpdateWithInfo { reason: error }
}

fn state_bytes(state: &TopicStateV1) -> Result<Vec<u8>, ContractError> {
    let bytes = encode(state).map_err(contract_error)?;
    if bytes.len() > MAX_TOPIC_STATE_BYTES {
        return Err(contract_error(format!(
            "state exceeds {} bytes",
            MAX_TOPIC_STATE_BYTES
        )));
    }
    Ok(bytes)
}

#[contract]
impl ContractInterface for Contract {
    fn validate_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts<'static>,
    ) -> Result<ValidateResult, ContractError> {
        if state.as_ref().is_empty() {
            return Ok(ValidateResult::Valid);
        }
        let params = decode_params(parameters.as_ref()).map_err(ContractError::Deser)?;
        let state = decode_state(state.as_ref()).map_err(ContractError::Deser)?;
        state.verify(&params).map_err(contract_error)?;
        let _bytes = state_bytes(&state)?;
        Ok(ValidateResult::Valid)
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let params = decode_params(parameters.as_ref()).map_err(ContractError::Deser)?;
        let mut current = if state.as_ref().is_empty() {
            TopicStateV1::default()
        } else {
            decode_state(state.as_ref()).map_err(ContractError::Deser)?
        };

        let mut full_verify = false;
        for update in data {
            match update {
                UpdateData::State(new_state) => {
                    let incoming =
                        decode_state(new_state.as_ref()).map_err(ContractError::Deser)?;
                    current.merge(&params, &incoming).map_err(contract_error)?;
                    full_verify = true;
                }
                UpdateData::Delta(delta) => {
                    if delta.as_ref().is_empty() {
                        continue;
                    }
                    let delta = decode_delta(delta.as_ref()).map_err(ContractError::Deser)?;
                    current
                        .apply_delta_incremental(&params, &delta)
                        .map_err(contract_error)?;
                }
                UpdateData::RelatedState { .. } => {}
                _ => {}
            }
        }

        if full_verify {
            current.verify(&params).map_err(contract_error)?;
        }
        let bytes = state_bytes(&current)?;
        Ok(UpdateModification::valid(bytes.into()))
    }

    fn summarize_state(
        parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        let _params = decode_params(parameters.as_ref()).map_err(ContractError::Deser)?;
        if state.as_ref().is_empty() {
            return Ok(StateSummary::from(Vec::new()));
        }
        let state = decode_state(state.as_ref()).map_err(ContractError::Deser)?;
        let summary = state.summarize();
        let mut bytes = Vec::new();
        into_writer(&summary, &mut bytes)
            .map_err(|error| ContractError::Deser(error.to_string()))?;
        Ok(StateSummary::from(bytes))
    }

    fn get_state_delta(
        parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        let _params = decode_params(parameters.as_ref()).map_err(ContractError::Deser)?;
        let state = decode_state(state.as_ref()).map_err(ContractError::Deser)?;
        let summary = if summary.as_ref().is_empty() {
            TopicStateSummaryV1::default()
        } else {
            decode_summary(summary.as_ref()).map_err(ContractError::Deser)?
        };
        let delta = state.delta(&summary);
        match delta {
            Some(delta) => {
                let bytes = encode(&delta).map_err(contract_error)?;
                Ok(StateDelta::from(bytes))
            }
            None => Ok(StateDelta::from(Vec::new())),
        }
    }
}

/// Revision marker: a bump changes the wasm hash and therefore the contract key.
#[no_mangle]
pub extern "C" fn plaza_topic_contract_revision() -> u32 {
    1
}
