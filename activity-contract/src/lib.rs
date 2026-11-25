//! A small per-board stream of recent topic activity.
//!
//! The board index no longer changes on every reply. This contract keeps the
//! latest `MAX_ACTIVITY_ENTRIES` topics; the client overlays it on the board
//! index for reply counts, pending approvals and the recent ordering.

use ciborium::{de::from_reader, ser::into_writer};
use freenet_stdlib::prelude::{
    contract, ContractError, ContractInterface, Parameters, RelatedContracts, State, StateDelta,
    StateSummary, UpdateData, UpdateModification, ValidateResult,
};
use plaza_core::board_state::activity::{ActivityDeltaV1, ActivityStateV1};
use plaza_core::board_state::ChatBoardParametersV1;

#[allow(dead_code)]
struct ActivityContract;

#[contract]
impl ContractInterface for ActivityContract {
    fn validate_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts<'static>,
    ) -> Result<ValidateResult, ContractError> {
        let _owner = from_reader::<ChatBoardParametersV1, &[u8]>(parameters.as_ref())
            .map_err(|error| ContractError::Deser(error.to_string()))?;
        if state.as_ref().is_empty() {
            return Ok(ValidateResult::Valid);
        }
        let activity = from_reader::<ActivityStateV1, &[u8]>(state.as_ref())
            .map_err(|error| ContractError::Deser(error.to_string()))?;
        activity
            .verify()
            .map_err(|error| ContractError::InvalidUpdateWithInfo {
                reason: format!("activity state does not verify: {error}"),
            })?;
        Ok(ValidateResult::Valid)
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let _owner = from_reader::<ChatBoardParametersV1, &[u8]>(parameters.as_ref())
            .map_err(|error| ContractError::Deser(error.to_string()))?;
        let mut activity = if state.as_ref().is_empty() {
            ActivityStateV1::default()
        } else {
            from_reader::<ActivityStateV1, &[u8]>(state.as_ref())
                .map_err(|error| ContractError::Deser(error.to_string()))?
        };
        for update in data {
            match update {
                UpdateData::State(bytes) => {
                    // A state update is additive: it lets a client create the
                    // contract or repair it without dropping entries written
                    // by other clients. The recent window caps the result.
                    let next = from_reader::<ActivityStateV1, &[u8]>(bytes.as_ref())
                        .map_err(|error| ContractError::Deser(error.to_string()))?;
                    activity
                        .apply_delta(&ActivityDeltaV1 {
                            entries: next.entries,
                        })
                        .map_err(|error| ContractError::InvalidUpdateWithInfo {
                            reason: format!("activity state does not verify: {error}"),
                        })?;
                }
                UpdateData::Delta(bytes) => {
                    let delta = from_reader::<ActivityDeltaV1, &[u8]>(bytes.as_ref())
                        .map_err(|error| ContractError::Deser(error.to_string()))?;
                    activity.apply_delta(&delta).map_err(|error| {
                        ContractError::InvalidUpdateWithInfo {
                            reason: format!("activity delta does not verify: {error}"),
                        }
                    })?;
                }
                _ => {}
            }
        }
        activity
            .verify()
            .map_err(|error| ContractError::InvalidUpdateWithInfo {
                reason: format!("activity state does not verify: {error}"),
            })?;
        let mut updated = Vec::new();
        into_writer(&activity, &mut updated)
            .map_err(|error| ContractError::Deser(error.to_string()))?;
        Ok(UpdateModification::valid(updated.into()))
    }

    fn summarize_state(
        _parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        let activity = if state.as_ref().is_empty() {
            ActivityStateV1::default()
        } else {
            from_reader::<ActivityStateV1, &[u8]>(state.as_ref())
                .map_err(|error| ContractError::Deser(error.to_string()))?
        };
        let mut bytes = Vec::new();
        into_writer(&activity, &mut bytes)
            .map_err(|error| ContractError::Deser(error.to_string()))?;
        Ok(StateSummary::from(bytes))
    }

    fn get_state_delta(
        _parameters: Parameters<'static>,
        state: State<'static>,
        _summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        Ok(StateDelta::from(state.as_ref().to_vec()))
    }
}
