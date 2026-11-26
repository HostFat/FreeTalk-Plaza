//! Contract for a section child board and its compact extra topic pages.
//!
//! - `page == 0` (the section manifest): uses `ChatBoardStateV1` with the
//!   section's authority, `topic_pages`, page 0's entries, and all section
//!   flags (including flags targeting topics on extra pages).
//! - `page > 0` (compact extra topic page): uses `SectionPageStateV1`, storing
//!   only an owner-signed page header, topic entries, optional seal, and
//!   (while unsealed) deduplicated author certificates. Sealing drops all
//!   duplicated author/invite/role records and switches verification to 1
//!   Ed25519 signature + 1 BLAKE3 digest.

use ciborium::{de::from_reader, ser::into_writer};
use freenet_scaffold::ComposableState;
use freenet_stdlib::prelude::{
    contract, ContractError, ContractInterface, Parameters, RelatedContracts, State, StateDelta,
    StateSummary, UpdateData, UpdateModification, ValidateResult,
};
use plaza_core::board_state::section_pages::{
    SectionPageDeltaV1, SectionPageStateV1, SectionPageSummaryV1,
};
use plaza_core::board_state::sections::SectionParametersV1;
use plaza_core::board_state::{
    ChatBoardParametersV1, ChatBoardStateV1Delta, ChatBoardStateV1Summary,
};
use plaza_core::ChatBoardStateV1;

/// Layout rules for page 0 (the section manifest). A topics-only delta already
/// verified its records in `apply_topics_delta`; re-verifying every member and
/// topic here would turn each update back into a full-state verification.
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
    if state.topics.entries.len() > plaza_core::board_state::pages::MAX_TOPICS_PER_PAGE {
        return Err("a section page has too many topics".to_string());
    }
    for entry in &state.topics.entries {
        if entry.entry.section != Some(section) {
            return Err("a section board cannot index topics of another section".to_string());
        }
    }
    Ok(())
}

fn validate_compact_page(
    section_params: &SectionParametersV1,
    bytes: &[u8],
) -> Result<ValidateResult, ContractError> {
    let page_state = from_reader::<SectionPageStateV1, &[u8]>(bytes)
        .map_err(|e| ContractError::Deser(e.to_string()))?;
    page_state
        .verify(section_params)
        .map_err(|e| ContractError::InvalidUpdateWithInfo {
            reason: format!("Section page verification failed: {e}"),
        })?;
    let mut normalized = page_state.clone();
    normalized.sort();
    if normalized != page_state {
        return Err(ContractError::InvalidUpdateWithInfo {
            reason: "Section page state is not canonically sorted".to_string(),
        });
    }
    Ok(ValidateResult::Valid)
}

fn update_compact_page(
    section_params: &SectionParametersV1,
    state: State<'static>,
    data: Vec<UpdateData<'static>>,
) -> Result<UpdateModification<'static>, ContractError> {
    let mut page_state = if state.as_ref().is_empty() {
        SectionPageStateV1::default()
    } else {
        from_reader::<SectionPageStateV1, &[u8]>(state.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?
    };

    for update in data {
        match update {
            UpdateData::State(new_state) => {
                if new_state.as_ref().is_empty() {
                    continue;
                }
                let incoming = from_reader::<SectionPageStateV1, &[u8]>(new_state.as_ref())
                    .map_err(|e| ContractError::Deser(e.to_string()))?;
                page_state
                    .merge(section_params, &incoming)
                    .map_err(|e| ContractError::InvalidUpdateWithInfo { reason: e })?;
            }
            UpdateData::Delta(d) => {
                if d.as_ref().is_empty() {
                    continue;
                }
                let delta = from_reader::<SectionPageDeltaV1, &[u8]>(d.as_ref())
                    .map_err(|e| ContractError::Deser(e.to_string()))?;
                page_state
                    .apply_delta(section_params, &delta)
                    .map_err(|e| ContractError::InvalidUpdateWithInfo { reason: e })?;
            }
            UpdateData::StateAndDelta { state, delta } => {
                if !state.as_ref().is_empty() {
                    let incoming = from_reader::<SectionPageStateV1, &[u8]>(state.as_ref())
                        .map_err(|e| ContractError::Deser(e.to_string()))?;
                    page_state
                        .merge(section_params, &incoming)
                        .map_err(|e| ContractError::InvalidUpdateWithInfo { reason: e })?;
                }
                if !delta.as_ref().is_empty() {
                    let delta = from_reader::<SectionPageDeltaV1, &[u8]>(delta.as_ref())
                        .map_err(|e| ContractError::Deser(e.to_string()))?;
                    page_state
                        .apply_delta(section_params, &delta)
                        .map_err(|e| ContractError::InvalidUpdateWithInfo { reason: e })?;
                }
            }
            _ => {}
        }
    }

    let mut updated_state = vec![];
    into_writer(&page_state, &mut updated_state)
        .map_err(|e| ContractError::Deser(e.to_string()))?;
    Ok(UpdateModification::valid(updated_state.into()))
}

fn summarize_compact_page(state: &[u8]) -> Result<StateSummary<'static>, ContractError> {
    if state.is_empty() {
        return Ok(StateSummary::from(vec![]));
    }
    let page_state = from_reader::<SectionPageStateV1, &[u8]>(state)
        .map_err(|e| ContractError::Deser(e.to_string()))?;
    let summary = page_state.summarize();
    let mut bytes = vec![];
    into_writer(&summary, &mut bytes).map_err(|e| ContractError::Deser(e.to_string()))?;
    Ok(StateSummary::from(bytes))
}

fn delta_compact_page(
    state: &[u8],
    summary: &[u8],
) -> Result<StateDelta<'static>, ContractError> {
    if state.is_empty() {
        return Ok(StateDelta::from(vec![]));
    }
    let page_state = from_reader::<SectionPageStateV1, &[u8]>(state)
        .map_err(|e| ContractError::Deser(e.to_string()))?;
    let peer_summary = if summary.is_empty() {
        SectionPageSummaryV1::default()
    } else {
        from_reader::<SectionPageSummaryV1, &[u8]>(summary)
            .map_err(|e| ContractError::Deser(e.to_string()))?
    };
    match page_state.delta(&peer_summary) {
        Some(delta) => {
            let mut bytes = vec![];
            into_writer(&delta, &mut bytes).map_err(|e| ContractError::Deser(e.to_string()))?;
            Ok(StateDelta::from(bytes))
        }
        None => Ok(StateDelta::from(vec![])),
    }
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
        if section_params.page > 0 {
            return validate_compact_page(&section_params, bytes);
        }

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
        verify_section_layout(&chat_state, section_params.section, section_params.page).map_err(
            |e| ContractError::InvalidUpdateWithInfo {
                reason: format!("Section layout does not verify: {e}"),
            },
        )?;

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
        if section_params.page > 0 {
            return update_compact_page(&section_params, state, data);
        }

        let board_params = ChatBoardParametersV1 {
            owner: section_params.owner,
        };
        let mut initialized = !state.as_ref().is_empty();
        let mut chat_state = if initialized {
            from_reader::<ChatBoardStateV1, &[u8]>(state.as_ref())
                .map_err(|e| ContractError::Deser(e.to_string()))?
        } else {
            ChatBoardStateV1::default()
        };

        let mut full_verify = false;
        for update in data {
            match update {
                UpdateData::State(new_state) => {
                    if new_state.as_ref().is_empty() {
                        continue;
                    }
                    let new_state = from_reader::<ChatBoardStateV1, &[u8]>(new_state.as_ref())
                        .map_err(|e| ContractError::Deser(e.to_string()))?;
                    if !initialized {
                        chat_state = new_state;
                        initialized = true;
                    } else {
                        chat_state
                            .merge(&chat_state.clone(), &board_params, &new_state)
                            .map_err(|e| ContractError::InvalidUpdateWithInfo {
                                reason: e.to_string(),
                            })?;
                    }
                    full_verify = true;
                }
                UpdateData::Delta(d) => {
                    if d.as_ref().is_empty() {
                        continue;
                    }
                    let delta = from_reader::<ChatBoardStateV1Delta, &[u8]>(d.as_ref())
                        .map_err(|e| ContractError::Deser(e.to_string()))?;
                    if initialized && delta.is_topics_only() {
                        if let Some(topic_delta) = delta.topics.as_ref() {
                            chat_state
                                .apply_topics_delta(&board_params, topic_delta)
                                .map_err(|e| ContractError::InvalidUpdateWithInfo {
                                    reason: e.to_string(),
                                })?;
                        }
                        verify_section_layout(
                            &chat_state,
                            section_params.section,
                            section_params.page,
                        )
                        .map_err(|e| ContractError::InvalidUpdateWithInfo {
                            reason: format!("Section layout does not verify: {e}"),
                        })?;
                    } else {
                        let delta_verify = initialized && delta.version.is_none();
                        chat_state
                            .apply_delta(
                                &chat_state.clone(),
                                &board_params,
                                &Some(delta.clone()),
                            )
                            .map_err(|e| ContractError::InvalidUpdateWithInfo {
                                reason: e.to_string(),
                            })?;
                        initialized = true;
                        if delta_verify {
                            chat_state
                                .verify_delta(&delta, &board_params)
                                .map_err(|e| ContractError::InvalidUpdateWithInfo {
                                    reason: format!("Delta does not verify: {e}"),
                                })?;
                            verify_section_layout(
                                &chat_state,
                                section_params.section,
                                section_params.page,
                            )
                            .map_err(|e| ContractError::InvalidUpdateWithInfo {
                                reason: format!("Section layout does not verify: {e}"),
                            })?;
                        } else {
                            full_verify = true;
                        }
                    }
                }
                UpdateData::StateAndDelta { state, delta } => {
                    if !state.as_ref().is_empty() {
                        let new_state = from_reader::<ChatBoardStateV1, &[u8]>(state.as_ref())
                            .map_err(|e| ContractError::Deser(e.to_string()))?;
                        if !initialized {
                            chat_state = new_state;
                            initialized = true;
                        } else {
                            chat_state
                                .merge(&chat_state.clone(), &board_params, &new_state)
                                .map_err(|e| ContractError::InvalidUpdateWithInfo {
                                    reason: e.to_string(),
                                })?;
                        }
                        full_verify = true;
                    }
                    if !delta.as_ref().is_empty() {
                        let delta = from_reader::<ChatBoardStateV1Delta, &[u8]>(delta.as_ref())
                            .map_err(|e| ContractError::Deser(e.to_string()))?;
                        chat_state
                            .apply_delta(
                                &chat_state.clone(),
                                &board_params,
                                &Some(delta),
                            )
                            .map_err(|e| ContractError::InvalidUpdateWithInfo {
                                reason: e.to_string(),
                            })?;
                        initialized = true;
                        full_verify = true;
                    }
                }
                _ => {}
            }
        }

        if !initialized {
            return Ok(UpdateModification::valid(Vec::new().into()));
        }

        if full_verify {
            chat_state
                .verify_with_section(&board_params, Some(section_params.section))
                .map_err(|e| ContractError::InvalidUpdateWithInfo {
                    reason: format!("Merged state does not verify: {e}"),
                })?;
            verify_section_layout(&chat_state, section_params.section, section_params.page)
                .map_err(|e| ContractError::InvalidUpdateWithInfo {
                    reason: format!("Section layout does not verify: {e}"),
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
        if section_params.page > 0 {
            return summarize_compact_page(state);
        }

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
        let section_params = from_reader::<SectionParametersV1, &[u8]>(parameters.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        if section_params.page > 0 {
            return delta_compact_page(state.as_ref(), summary.as_ref());
        }
        if state.as_ref().is_empty() {
            return Ok(StateDelta::from(vec![]));
        }

        let chat_state = from_reader::<ChatBoardStateV1, &[u8]>(state.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        let board_params = ChatBoardParametersV1 {
            owner: section_params.owner,
        };
        let summary = if summary.as_ref().is_empty() {
            let empty = ChatBoardStateV1::default();
            empty.summarize(&empty, &board_params)
        } else {
            from_reader::<ChatBoardStateV1Summary, &[u8]>(summary.as_ref())
                .map_err(|e| ContractError::Deser(e.to_string()))?
        };
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use plaza_core::board_state::member::{AuthorizedMember, Member, MemberId};
    use plaza_core::board_state::message::MessageId;
    use plaza_core::board_state::privacy::SealedBytes;
    use plaza_core::board_state::section_pages::{
        AuthorizedSectionPageHeaderV1, AuthorizedSectionPageSealV1, SectionPageHeaderV1,
    };
    use plaza_core::board_state::topics::{AuthorizedTopicEntryV1, TopicEntryV1};

    fn cbor<T: serde::Serialize>(value: &T) -> Vec<u8> {
        let mut bytes = Vec::new();
        into_writer(value, &mut bytes).unwrap();
        bytes
    }

    #[test]
    fn compact_page_contract_round_trip_and_seal() {
        let owner = SigningKey::from_bytes(&[1u8; 32]);
        let alice = SigningKey::from_bytes(&[2u8; 32]);
        let owner_id = MemberId::from(&owner.verifying_key());
        let section = MessageId::from_bytes([0x44u8; 32]);
        let params = SectionParametersV1 {
            owner: owner.verifying_key(),
            section,
            page: 1,
        };
        let params_bytes = Parameters::from(cbor(&params));

        let init = SectionPageStateV1 {
            header: Some(AuthorizedSectionPageHeaderV1::new(
                SectionPageHeaderV1 {
                    board: owner.verifying_key().to_bytes(),
                    section,
                    section_chain: vec![section],
                    page: 1,
                    page_size: 2,
                    allowed_roles: Vec::new(),
                    created_at: 1_000,
                },
                &owner,
            )),
            ..Default::default()
        };
        let init_bytes = State::from(cbor(&init));
        assert_eq!(
            SectionContract::validate_state(
                params_bytes.clone(),
                init_bytes.clone(),
                RelatedContracts::default(),
            )
            .unwrap(),
            ValidateResult::Valid
        );

        let alice_member = AuthorizedMember::new(
            Member {
                owner_member_id: owner_id,
                invited_by: owner_id,
                member_vk: alice.verifying_key(),
                join_proof: None,
            },
            &owner,
        );
        let topic1 = AuthorizedTopicEntryV1::new(
            TopicEntryV1 {
                topic_id: MessageId::from_bytes([0x10u8; 32]),
                part: 0,
                protocol_version: 1,
                author: MemberId::from(&alice.verifying_key()),
                section: Some(section),
                section_chain: vec![section],
                title: SealedBytes::public(b"Hello".to_vec()),
                preview: SealedBytes::public(b"World".to_vec()),
                header_hash: [0x11u8; 32],
                created_at: 2_000,
                generation: 1,
            },
            &alice,
        );
        let delta = SectionPageDeltaV1 {
            authors: vec![alice_member],
            entries: vec![topic1.clone()],
            ..Default::default()
        };
        let mod1 = SectionContract::update_state(
            params_bytes.clone(),
            init_bytes.clone(),
            vec![UpdateData::Delta(cbor(&delta).into())],
        )
        .unwrap();
        let after1 = mod1.new_state.expect("new state after topic 1");
        assert_eq!(
            SectionContract::validate_state(
                params_bytes.clone(),
                after1.clone(),
                RelatedContracts::default(),
            )
            .unwrap(),
            ValidateResult::Valid
        );

        // Seal the page via delta and verify authors are compacted away.
        let seal =
            AuthorizedSectionPageSealV1::new(&params, &[topic1], &owner, 3_000).unwrap();
        let mod2 = SectionContract::update_state(
            params_bytes.clone(),
            after1.clone(),
            vec![UpdateData::Delta(
                cbor(&SectionPageDeltaV1 {
                    seal: Some(seal),
                    ..Default::default()
                })
                .into(),
            )],
        )
        .unwrap();
        let sealed_bytes = mod2.new_state.expect("sealed state");
        assert_eq!(
            SectionContract::validate_state(
                params_bytes.clone(),
                sealed_bytes.clone(),
                RelatedContracts::default(),
            )
            .unwrap(),
            ValidateResult::Valid
        );
        let decoded: SectionPageStateV1 = from_reader(sealed_bytes.as_ref()).unwrap();
        assert!(decoded.is_sealed());
        assert!(decoded.authors.is_empty());

        // Incremental sync: peer on `init` catches up to `sealed_bytes` in one delta.
        let peer_summary =
            SectionContract::summarize_state(params_bytes.clone(), init_bytes.clone()).unwrap();
        let sync_delta = SectionContract::get_state_delta(
            params_bytes.clone(),
            sealed_bytes.clone(),
            peer_summary,
        )
        .unwrap();
        assert!(!sync_delta.as_ref().is_empty());
        let mod3 = SectionContract::update_state(
            params_bytes.clone(),
            init_bytes,
            vec![UpdateData::Delta(sync_delta)],
        )
        .unwrap();
        let synced_bytes = mod3.new_state.expect("synced state");
        let synced_summary =
            SectionContract::summarize_state(params_bytes.clone(), synced_bytes).unwrap();
        let empty_delta = SectionContract::get_state_delta(
            params_bytes,
            sealed_bytes,
            synced_summary,
        )
        .unwrap();
        assert!(empty_delta.as_ref().is_empty());
    }
}
