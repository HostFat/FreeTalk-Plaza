//! A small per-board moderation feed.
//!
//! Reports used to rewrite the section page that holds the topic and were
//! broadcast to every reader of that page. This contract keeps reports and
//! their resolutions instead. The client verifies the reporter signature and
//! the resolver authority against the board before showing an entry.

use ciborium::{de::from_reader, ser::into_writer};
use freenet_stdlib::prelude::{
    contract, ContractError, ContractInterface, Parameters, RelatedContracts, State, StateDelta,
    StateSummary, UpdateData, UpdateModification, ValidateResult,
};
use plaza_core::board_state::report_feed::{
    ReportFeedDeltaV1, ReportFeedStateV1,
};
use plaza_core::board_state::ChatBoardParametersV1;

#[allow(dead_code)]
struct ModerationContract;

#[contract]
impl ContractInterface for ModerationContract {
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
        let feed = from_reader::<ReportFeedStateV1, &[u8]>(state.as_ref())
            .map_err(|error| ContractError::Deser(error.to_string()))?;
        feed.verify()
            .map_err(|error| ContractError::InvalidUpdateWithInfo {
                reason: format!("moderation state does not verify: {error}"),
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
        let mut feed = if state.as_ref().is_empty() {
            ReportFeedStateV1::default()
        } else {
            from_reader::<ReportFeedStateV1, &[u8]>(state.as_ref())
                .map_err(|error| ContractError::Deser(error.to_string()))?
        };
        for update in data {
            match update {
                UpdateData::State(bytes) => {
                    // Additive, so creating or repairing the contract never
                    // drops entries written by another client.
                    let next = from_reader::<ReportFeedStateV1, &[u8]>(bytes.as_ref())
                        .map_err(|error| ContractError::Deser(error.to_string()))?;
                    feed.apply_delta(&ReportFeedDeltaV1 {
                        reports: next.reports,
                        resolutions: next.resolutions,
                    })
                    .map_err(|error| ContractError::InvalidUpdateWithInfo {
                        reason: format!("moderation state does not verify: {error}"),
                    })?;
                }
                UpdateData::Delta(bytes) => {
                    let delta = from_reader::<ReportFeedDeltaV1, &[u8]>(bytes.as_ref())
                        .map_err(|error| ContractError::Deser(error.to_string()))?;
                    feed.apply_delta(&delta).map_err(|error| {
                        ContractError::InvalidUpdateWithInfo {
                            reason: format!("moderation delta does not verify: {error}"),
                        }
                    })?;
                }
                _ => {}
            }
        }
        feed.verify()
            .map_err(|error| ContractError::InvalidUpdateWithInfo {
                reason: format!("moderation state does not verify: {error}"),
            })?;
        let mut updated = Vec::new();
        into_writer(&feed, &mut updated)
            .map_err(|error| ContractError::Deser(error.to_string()))?;
        Ok(UpdateModification::valid(updated.into()))
    }

    fn summarize_state(
        _parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        let feed = if state.as_ref().is_empty() {
            ReportFeedStateV1::default()
        } else {
            from_reader::<ReportFeedStateV1, &[u8]>(state.as_ref())
                .map_err(|error| ContractError::Deser(error.to_string()))?
        };
        let mut bytes = Vec::new();
        into_writer(&feed, &mut bytes)
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
