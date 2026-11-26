//! Freenet contract entry point for `plaza-topic`.
//!
//! Dispatches by `params.part`:
//! - `part == 0`: full topic head (`TopicStateV1`: header, section snapshot,
//!   canonical authority, topic-level actions, page 0 posts, optional
//!   `posts_seal`).
//! - `part > 0`: compact append-only post page (`TopicPageStateV1`: small
//!   signed `TopicPageHeaderV1`, posts, page-local participants/actions,
//!   optional `AuthorizedTopicPageSealV1` + `post_seal_actions`).

use ciborium::ser::into_writer;
use freenet_stdlib::prelude::*;
use plaza_topic_core::{
    decode_delta, decode_page_delta, decode_page_state, decode_page_summary, decode_params,
    decode_state, decode_summary, encode, TopicActionKind, TopicPageStateV1, TopicPageSummaryV1,
    TopicStateSummaryV1, TopicStateV1, MAX_TOPIC_PAGE_BYTES, MAX_TOPIC_STATE_BYTES,
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

fn page_state_bytes(state: &TopicPageStateV1) -> Result<Vec<u8>, ContractError> {
    let bytes = encode(state).map_err(contract_error)?;
    if bytes.len() > MAX_TOPIC_PAGE_BYTES {
        return Err(contract_error(format!(
            "topic page exceeds {} bytes",
            MAX_TOPIC_PAGE_BYTES
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
        if params.part > 0 {
            let page = decode_page_state(state.as_ref()).map_err(ContractError::Deser)?;
            page.verify(&params).map_err(contract_error)?;
            let _bytes = page_state_bytes(&page)?;
            return Ok(ValidateResult::Valid);
        }
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
        if params.part > 0 {
            let mut initialized = !state.as_ref().is_empty();
            let mut current = if initialized {
                decode_page_state(state.as_ref()).map_err(ContractError::Deser)?
            } else {
                TopicPageStateV1::default()
            };
            let mut full_verify = false;
            for update in data {
                match update {
                    UpdateData::State(new_state) => {
                        if new_state.as_ref().is_empty() {
                            continue;
                        }
                        let incoming =
                            decode_page_state(new_state.as_ref()).map_err(ContractError::Deser)?;
                        current.merge(&params, &incoming).map_err(contract_error)?;
                        initialized = true;
                        full_verify = true;
                    }
                    UpdateData::Delta(delta) => {
                        if delta.as_ref().is_empty() {
                            continue;
                        }
                        let delta =
                            decode_page_delta(delta.as_ref()).map_err(ContractError::Deser)?;
                        if !initialized || delta.header.is_some() {
                            full_verify = true;
                        }
                        current
                            .apply_delta_incremental(&params, &delta)
                            .map_err(contract_error)?;
                        initialized = true;
                    }
                    UpdateData::StateAndDelta {
                        state: state_bytes,
                        delta: delta_bytes,
                    } => {
                        if !state_bytes.as_ref().is_empty() {
                            let incoming = decode_page_state(state_bytes.as_ref())
                                .map_err(ContractError::Deser)?;
                            current.merge(&params, &incoming).map_err(contract_error)?;
                            initialized = true;
                            full_verify = true;
                        }
                        if !delta_bytes.as_ref().is_empty() {
                            let delta = decode_page_delta(delta_bytes.as_ref())
                                .map_err(ContractError::Deser)?;
                            if !initialized || delta.header.is_some() {
                                full_verify = true;
                            }
                            current
                                .apply_delta_incremental(&params, &delta)
                                .map_err(contract_error)?;
                            initialized = true;
                        }
                    }
                    UpdateData::RelatedState { .. } => {}
                    _ => {}
                }
            }
            if full_verify {
                current.verify(&params).map_err(contract_error)?;
            }
            let bytes = page_state_bytes(&current)?;
            return Ok(UpdateModification::valid(bytes.into()));
        }

        let mut initialized = !state.as_ref().is_empty();
        let mut current = if initialized {
            decode_state(state.as_ref()).map_err(ContractError::Deser)?
        } else {
            TopicStateV1::default()
        };

        let mut full_verify = false;
        for update in data {
            match update {
                UpdateData::State(new_state) => {
                    if new_state.as_ref().is_empty() {
                        continue;
                    }
                    let incoming =
                        decode_state(new_state.as_ref()).map_err(ContractError::Deser)?;
                    current.merge(&params, &incoming).map_err(contract_error)?;
                    initialized = true;
                    full_verify = true;
                }
                UpdateData::Delta(delta) => {
                    if delta.as_ref().is_empty() {
                        continue;
                    }
                    let delta = decode_delta(delta.as_ref()).map_err(ContractError::Deser)?;
                    if !initialized
                        || delta.header.is_some()
                        || delta
                            .actions
                            .iter()
                            .any(|a| a.action.kind == TopicActionKind::Move)
                    {
                        full_verify = true;
                    }
                    current
                        .apply_delta_incremental(&params, &delta)
                        .map_err(contract_error)?;
                    initialized = true;
                }
                UpdateData::StateAndDelta {
                    state: state_bytes,
                    delta: delta_bytes,
                } => {
                    if !state_bytes.as_ref().is_empty() {
                        let incoming =
                            decode_state(state_bytes.as_ref()).map_err(ContractError::Deser)?;
                        current.merge(&params, &incoming).map_err(contract_error)?;
                        initialized = true;
                        full_verify = true;
                    }
                    if !delta_bytes.as_ref().is_empty() {
                        let delta =
                            decode_delta(delta_bytes.as_ref()).map_err(ContractError::Deser)?;
                        if !initialized
                            || delta.header.is_some()
                            || delta
                                .actions
                                .iter()
                                .any(|a| a.action.kind == TopicActionKind::Move)
                        {
                            full_verify = true;
                        }
                        current
                            .apply_delta_incremental(&params, &delta)
                            .map_err(contract_error)?;
                        initialized = true;
                    }
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
        let params = decode_params(parameters.as_ref()).map_err(ContractError::Deser)?;
        if state.as_ref().is_empty() {
            return Ok(StateSummary::from(Vec::new()));
        }
        if params.part > 0 {
            let page = decode_page_state(state.as_ref()).map_err(ContractError::Deser)?;
            let summary = page.summarize();
            let mut bytes = Vec::new();
            into_writer(&summary, &mut bytes)
                .map_err(|error| ContractError::Deser(error.to_string()))?;
            return Ok(StateSummary::from(bytes));
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
        if state.as_ref().is_empty() {
            return Ok(StateDelta::from(Vec::new()));
        }
        let params = decode_params(parameters.as_ref()).map_err(ContractError::Deser)?;
        if params.part > 0 {
            let page = decode_page_state(state.as_ref()).map_err(ContractError::Deser)?;
            let summary = if summary.as_ref().is_empty() {
                TopicPageSummaryV1::default()
            } else {
                decode_page_summary(summary.as_ref()).map_err(ContractError::Deser)?
            };
            return match page.delta(&summary) {
                Some(delta) => {
                    let bytes = encode(&delta).map_err(contract_error)?;
                    Ok(StateDelta::from(bytes))
                }
                None => Ok(StateDelta::from(Vec::new())),
            };
        }
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
    2
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use plaza_core::board_state::member::{AuthorizedMember, Member, MemberId};
    use plaza_core::board_state::privacy::SealedBytes;
    use plaza_topic_core::{
        AuthorizedParticipantV1, AuthorizedTopicPageHeaderV1, AuthorizedTopicPageSealV1,
        AuthorizedTopicPolicyV1, AuthorizedTopicPostV1, ParticipantCertificateV1,
        ParticipantRecordV1, TopicAuthorityV1, TopicGenerationV1, TopicPageDeltaV1,
        TopicPageHeaderV1, TopicParamsV1, TopicPolicyV1, TopicPostV1, DEFAULT_TOPIC_PAGE_SIZE,
        PROTOCOL_VERSION,
    };

    fn owner() -> SigningKey {
        SigningKey::from_bytes(&[1u8; 32])
    }

    fn member() -> SigningKey {
        SigningKey::from_bytes(&[2u8; 32])
    }

    #[test]
    fn part_gt_zero_dispatches_compact_append_only_page_lifecycle() {
        let params = TopicParamsV1::new(owner().verifying_key(), [9u8; 32], 1);
        let params_bytes = Parameters::from(encode(&params).unwrap());

        let member_record = AuthorizedMember::new(
            Member {
                owner_member_id: MemberId::from(&owner().verifying_key()),
                invited_by: MemberId::from(&owner().verifying_key()),
                member_vk: member().verifying_key(),
                join_proof: None,
            },
            &owner(),
        );
        let participant = AuthorizedParticipantV1::new(
            ParticipantRecordV1 {
                member_id: MemberId::from(&member().verifying_key()),
                member_vk: member().verifying_key(),
                certificate: ParticipantCertificateV1 {
                    member: member_record,
                    chain: Vec::new(),
                    token: None,
                    join_proof: None,
                },
                joined_at: 500,
            },
            &member(),
        );
        let mut policy = TopicPolicyV1::default();
        policy.updated_at = 100;
        let header = TopicPageHeaderV1 {
            topic_id: [9u8; 32],
            part: 1,
            header_hash: [0x11u8; 32],
            previous_hash: [0x22u8; 32],
            topic_author: MemberId::from(&owner().verifying_key()),
            auto_moderated: false,
            section_chain: Vec::new(),
            allowed_roles: Vec::new(),
            images_allowed: true,
            max_posts: DEFAULT_TOPIC_PAGE_SIZE as u32,
            creator: MemberId::from(&owner().verifying_key()),
            created_at: 1_000,
        };
        let initial_page = TopicPageStateV1 {
            version: PROTOCOL_VERSION,
            header: Some(AuthorizedTopicPageHeaderV1::new(header, &owner())),
            authority: TopicAuthorityV1 {
                policy: Some(AuthorizedTopicPolicyV1::new(policy, &owner())),
                ..Default::default()
            },
            participants: vec![participant],
            generation: TopicGenerationV1 {
                part: 1,
                closed_at: None,
                next_part: None,
                previous_hash: Some([0x22u8; 32]),
            },
            ..Default::default()
        };
        let initial_state = State::from(encode(&initial_page).unwrap());
        assert_eq!(
            Contract::validate_state(
                params_bytes.clone(),
                initial_state.clone(),
                RelatedContracts::default(),
            )
            .unwrap(),
            ValidateResult::Valid
        );

        let summary_before =
            Contract::summarize_state(params_bytes.clone(), initial_state.clone()).unwrap();

        let reply = AuthorizedTopicPostV1::new(
            TopicPostV1 {
                author: MemberId::from(&member().verifying_key()),
                parent: None,
                content: SealedBytes::public(b"hello page 1".to_vec()),
                images: Vec::new(),
                created_at: 2_000,
                nonce: [3u8; 16],
            },
            &member(),
        );
        let reply_delta = TopicPageDeltaV1 {
            posts: vec![reply.clone()],
            ..Default::default()
        };
        let updated = Contract::update_state(
            params_bytes.clone(),
            initial_state.clone(),
            vec![UpdateData::Delta(StateDelta::from(
                encode(&reply_delta).unwrap(),
            ))],
        )
        .unwrap();
        let updated_state = State::from(updated.new_state.unwrap().into_bytes());

        // get_state_delta sends only the new reply.
        let diff = Contract::get_state_delta(
            params_bytes.clone(),
            updated_state.clone(),
            summary_before,
        )
        .unwrap();
        let decoded_diff = decode_page_delta(diff.as_ref()).unwrap();
        assert_eq!(decoded_diff.posts.len(), 1);
        assert_eq!(decoded_diff.posts[0].id(), reply.id());

        // Seal the page through update_state.
        let decoded_open = decode_page_state(updated_state.as_ref()).unwrap();
        let seal = AuthorizedTopicPageSealV1::new(
            decoded_open.build_seal(&params, 3_000).unwrap(),
            &owner(),
            None,
        );
        let sealed_mod = Contract::update_state(
            params_bytes.clone(),
            updated_state,
            vec![UpdateData::Delta(StateDelta::from(
                encode(&TopicPageDeltaV1 {
                    seal: Some(seal),
                    ..Default::default()
                })
                .unwrap(),
            ))],
        )
        .unwrap();
        let sealed_state = State::from(sealed_mod.new_state.unwrap().into_bytes());
        assert_eq!(
            Contract::validate_state(
                params_bytes.clone(),
                sealed_state.clone(),
                RelatedContracts::default(),
            )
            .unwrap(),
            ValidateResult::Valid
        );
        let decoded_sealed = decode_page_state(sealed_state.as_ref()).unwrap();
        assert!(decoded_sealed.is_sealed());
        assert!(decoded_sealed.participants.is_empty());
    }
}
