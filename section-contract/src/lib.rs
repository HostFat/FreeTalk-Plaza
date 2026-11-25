//! Contract for a section child board. The state and verification rules are
//! the board's; the parameters add the section id and the contract enforces
//! that the child only indexes its own section.

use ciborium::{de::from_reader, ser::into_writer};
use freenet_scaffold::ComposableState;
use freenet_stdlib::prelude::{
    contract, ContractError, ContractInterface, Parameters, RelatedContracts, State, StateDelta,
    StateSummary, UpdateData, UpdateModification, ValidateResult,
};
use plaza_core::board_state::sections::SectionParametersV1;
use plaza_core::board_state::{
    ChatBoardParametersV1, ChatBoardStateV1Delta, ChatBoardStateV1Summary,
};
use plaza_core::ChatBoardStateV1;

/// Layout rules only. A topics-only delta already verified its records in
/// `apply_topics_delta`; re-verifying every member and topic here would turn
/// each activity refresh back into a full-state verification.
fn verify_section_layout(
    state: &ChatBoardStateV1,
    section: plaza_core::board_state::sections::SectionId,
    page: u32,
) -> Result<(), String> {
    if state.mode != plaza_core::board_state::BoardModeV1::SectionedTopicIndex {
        return Err("a section board must use the sectioned layout".to_string());
    }
    if !state
        .sections
        .sections
        .iter()
        .any(|entry| entry.section.id == section)
    {
        return Err("a section board must contain its own section".to_string());
    }
    if !state.recent_messages.messages.is_empty() {
        return Err("a section board cannot carry legacy messages".to_string());
    }
    if let Some(pages) = &state.topic_pages.0 {
        if page != 0 {
            return Err("only the section manifest can list topic pages".to_string());
        }
        if pages.data.section != section {
            return Err("the topic page list belongs to another section".to_string());
        }
    }
    for entry in &state.topics.entries {
        if entry.entry.section != Some(section) {
            return Err("a section board cannot index topics of another section".to_string());
        }
    }
    Ok(())
}

#[allow(dead_code)]
struct SectionContract;

#[contract]
impl ContractInterface for SectionContract {
    fn validate_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts<'static>,
    ) -> Result<ValidateResult, ContractError> {
        let bytes = state.as_ref();
        if bytes.is_empty() {
            return Ok(ValidateResult::Valid);
        }
        let section_params = from_reader::<SectionParametersV1, &[u8]>(parameters.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        let board_params = ChatBoardParametersV1 {
            owner: section_params.owner,
        };
        let chat_state = from_reader::<ChatBoardStateV1, &[u8]>(bytes)
            .map_err(|e| ContractError::Deser(e.to_string()))?;

        chat_state
            .verify_with_section(&board_params, Some(section_params.section))
            .map_err(|e| ContractError::InvalidUpdateWithInfo {
                reason: format!("State verification failed: {e}"),
            })?;
        verify_section_layout(&chat_state, section_params.section, section_params.page).map_err(|e| {
            ContractError::InvalidUpdateWithInfo {
                reason: format!("Section layout does not verify: {e}"),
            }
        })?;

        let mut normalized = chat_state.clone();
        normalized
            .normalize(&board_params)
            .map_err(|e| ContractError::InvalidUpdateWithInfo {
                reason: format!("State cleanup failed: {e}"),
            })?;
        if normalized != chat_state {
            return Err(ContractError::InvalidUpdateWithInfo {
                reason: "State is not normalized: applying cleanup would change it".to_string(),
            });
        }
        Ok(ValidateResult::Valid)
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let section_params = from_reader::<SectionParametersV1, &[u8]>(parameters.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        let board_params = ChatBoardParametersV1 {
            owner: section_params.owner,
        };
        let mut chat_state = from_reader::<ChatBoardStateV1, &[u8]>(state.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;

        let mut full_verify = false;
        for update in data {
            match update {
                UpdateData::State(new_state) => {
                    let new_state = from_reader::<ChatBoardStateV1, &[u8]>(new_state.as_ref())
                        .map_err(|e| ContractError::Deser(e.to_string()))?;
                    chat_state
                        .merge(&chat_state.clone(), &board_params, &new_state)
                        .map_err(|e| ContractError::InvalidUpdateWithInfo {
                            reason: e.to_string(),
                        })?;
                    full_verify = true;
                }
                UpdateData::Delta(d) => {
                    if d.as_ref().is_empty() {
                        continue;
                    }
                    let delta = from_reader::<ChatBoardStateV1Delta, &[u8]>(d.as_ref())
                        .map_err(|e| ContractError::Deser(e.to_string()))?;
                    if delta.is_topics_only() {
                        if let Some(topic_delta) = delta.topics.as_ref() {
                            chat_state
                                .apply_topics_delta(&board_params, topic_delta)
                                .map_err(|e| ContractError::InvalidUpdateWithInfo {
                                    reason: e.to_string(),
                                })?;
                        }
                        verify_section_layout(&chat_state, section_params.section, section_params.page).map_err(
                            |e| ContractError::InvalidUpdateWithInfo {
                                reason: format!("Section layout does not verify: {e}"),
                            },
                        )?;
                    } else {
                        let delta_verify = delta.version.is_none();
                        chat_state
                            .apply_delta(
                                &chat_state.clone(),
                                &board_params,
                                &Some(delta.clone()),
                            )
                            .map_err(|e| ContractError::InvalidUpdateWithInfo {
                                reason: e.to_string(),
                            })?;
                        if delta_verify {
                            chat_state
                                .verify_delta(&delta, &board_params)
                                .map_err(|e| ContractError::InvalidUpdateWithInfo {
                                    reason: format!("Delta does not verify: {e}"),
                                })?;
                            verify_section_layout(&chat_state, section_params.section, section_params.page)
                                .map_err(|e| ContractError::InvalidUpdateWithInfo {
                                    reason: format!("Section layout does not verify: {e}"),
                                })?;
                        } else {
                            full_verify = true;
                        }
                    }
                }
                UpdateData::RelatedState { .. } => {}
                _ => unreachable!(),
            }
        }

        if full_verify {
            chat_state
                .verify_with_section(&board_params, Some(section_params.section))
                .map_err(|e| ContractError::InvalidUpdateWithInfo {
                    reason: format!("Merged state does not verify: {e}"),
                })?;
            verify_section_layout(&chat_state, section_params.section, section_params.page).map_err(|e| {
                ContractError::InvalidUpdateWithInfo {
                    reason: format!("Section layout does not verify: {e}"),
                }
            })?;
        }

        let mut updated_state = vec![];
        into_writer(&chat_state, &mut updated_state)
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        Ok(UpdateModification::valid(updated_state.into()))
    }

    fn summarize_state(
        parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        let state = state.as_ref();
        if state.is_empty() {
            return Ok(StateSummary::from(vec![]));
        }
        let section_params = from_reader::<SectionParametersV1, &[u8]>(parameters.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        let board_params = ChatBoardParametersV1 {
            owner: section_params.owner,
        };
        let state = from_reader::<ChatBoardStateV1, &[u8]>(state)
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        let summary = state.summarize(&state, &board_params);
        let mut summary_bytes = vec![];
        into_writer(&summary, &mut summary_bytes)
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        Ok(StateSummary::from(summary_bytes))
    }

    fn get_state_delta(
        parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        let chat_state = from_reader::<ChatBoardStateV1, &[u8]>(state.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        let section_params = from_reader::<SectionParametersV1, &[u8]>(parameters.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        let board_params = ChatBoardParametersV1 {
            owner: section_params.owner,
        };
        let summary = from_reader::<ChatBoardStateV1Summary, &[u8]>(summary.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        let delta = chat_state.delta(&chat_state, &board_params, &summary);
        match delta {
            Some(d) => {
                let mut delta_bytes = vec![];
                into_writer(&d, &mut delta_bytes)
                    .map_err(|e| ContractError::Deser(e.to_string()))?;
                Ok(StateDelta::from(delta_bytes))
            }
            None => Ok(StateDelta::from(vec![])),
        }
    }
}

#[no_mangle]
pub extern "C" fn plaza_section_contract_revision() -> u32 {
    plaza_core::CONTRACT_REVISION
}
