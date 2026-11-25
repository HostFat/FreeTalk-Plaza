//! A small per-board profile feed.
//!
//! Nicknames used to live in the board state: every join or rename rewrote and
//! re-broadcast the board, and a board with thousands of members carried MiB of
//! profile records. This contract keeps them instead; the client overlays the
//! verified nickname on the board for display.

use ciborium::{de::from_reader, ser::into_writer};
use freenet_stdlib::prelude::{
    contract, ContractError, ContractInterface, Parameters, RelatedContracts, State, StateDelta,
    StateSummary, UpdateData, UpdateModification, ValidateResult,
};
use plaza_core::board_state::profiles::{ProfileDeltaV1, ProfileStateV1};
use plaza_core::board_state::ChatBoardParametersV1;

#[allow(dead_code)]
struct ProfileContract;

#[contract]
impl ContractInterface for ProfileContract {
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
        let profiles = from_reader::<ProfileStateV1, &[u8]>(state.as_ref())
            .map_err(|error| ContractError::Deser(error.to_string()))?;
        profiles
            .verify()
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
        let _owner = from_reader::<ChatBoardParametersV1, &[u8]>(parameters.as_ref())
            .map_err(|error| ContractError::Deser(error.to_string()))?;
        let mut profiles = if state.as_ref().is_empty() {
            ProfileStateV1::default()
        } else {
            from_reader::<ProfileStateV1, &[u8]>(state.as_ref())
                .map_err(|error| ContractError::Deser(error.to_string()))?
        };
        for update in data {
            match update {
                UpdateData::State(bytes) => {
                    // Additive, so creating or repairing the contract never
                    // drops profiles written by another client.
                    let next = from_reader::<ProfileStateV1, &[u8]>(bytes.as_ref())
                        .map_err(|error| ContractError::Deser(error.to_string()))?;
                    profiles
                        .apply_delta(&ProfileDeltaV1 {
                            entries: next.entries,
                        })
                        .map_err(|error| ContractError::InvalidUpdateWithInfo {
                            reason: format!("profile state does not verify: {error}"),
                        })?;
                }
                UpdateData::Delta(bytes) => {
                    let delta = from_reader::<ProfileDeltaV1, &[u8]>(bytes.as_ref())
                        .map_err(|error| ContractError::Deser(error.to_string()))?;
                    profiles.apply_delta(&delta).map_err(|error| {
                        ContractError::InvalidUpdateWithInfo {
                            reason: format!("profile delta does not verify: {error}"),
                        }
                    })?;
                }
                _ => {}
            }
        }
        profiles
            .verify()
            .map_err(|error| ContractError::InvalidUpdateWithInfo {
                reason: format!("profile state does not verify: {error}"),
            })?;
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
        let mut bytes = Vec::new();
        into_writer(&profiles, &mut bytes)
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
