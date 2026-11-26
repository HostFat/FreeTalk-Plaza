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
use plaza_core::board_state::activity::{
    ActivityDeltaV1, ActivityParametersV1, ActivityStateV1, ActivitySummaryV1,
};

#[allow(dead_code)]
struct ActivityContract;

#[contract]
impl ContractInterface for ActivityContract {
    fn validate_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts<'static>,
    ) -> Result<ValidateResult, ContractError> {
        let params = from_reader::<ActivityParametersV1, &[u8]>(parameters.as_ref())
            .map_err(|error| ContractError::Deser(error.to_string()))?;
        if state.as_ref().is_empty() {
            return Ok(ValidateResult::Valid);
        }
        let activity = from_reader::<ActivityStateV1, &[u8]>(state.as_ref())
            .map_err(|error| ContractError::Deser(error.to_string()))?;
        activity
            .verify(&params)
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
        let params = from_reader::<ActivityParametersV1, &[u8]>(parameters.as_ref())
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
                    if bytes.as_ref().is_empty() {
                        continue;
                    }
                    // A state update is additive: it lets a client create the
                    // contract or repair it without dropping entries written
                    // by other clients. The recent window caps the result.
                    let next = from_reader::<ActivityStateV1, &[u8]>(bytes.as_ref())
                        .map_err(|error| ContractError::Deser(error.to_string()))?;
                    activity
                        .apply_delta(
                            &params,
                            &ActivityDeltaV1 {
                                entries: next.entries,
                            },
                        )
                        .map_err(|error| ContractError::InvalidUpdateWithInfo {
                            reason: format!("activity state does not verify: {error}"),
                        })?;
                }
                UpdateData::Delta(bytes) => {
                    if bytes.as_ref().is_empty() {
                        continue;
                    }
                    let delta = from_reader::<ActivityDeltaV1, &[u8]>(bytes.as_ref())
                        .map_err(|error| ContractError::Deser(error.to_string()))?;
                    activity.apply_delta(&params, &delta).map_err(|error| {
                        ContractError::InvalidUpdateWithInfo {
                            reason: format!("activity delta does not verify: {error}"),
                        }
                    })?;
                }
                UpdateData::StateAndDelta {
                    state: state_bytes,
                    delta: delta_bytes,
                } => {
                    if !state_bytes.as_ref().is_empty() {
                        let next = from_reader::<ActivityStateV1, &[u8]>(state_bytes.as_ref())
                            .map_err(|error| ContractError::Deser(error.to_string()))?;
                        activity
                            .apply_delta(
                                &params,
                                &ActivityDeltaV1 {
                                    entries: next.entries,
                                },
                            )
                            .map_err(|error| ContractError::InvalidUpdateWithInfo {
                                reason: format!("activity state does not verify: {error}"),
                            })?;
                    }
                    if !delta_bytes.as_ref().is_empty() {
                        let delta = from_reader::<ActivityDeltaV1, &[u8]>(delta_bytes.as_ref())
                            .map_err(|error| ContractError::Deser(error.to_string()))?;
                        activity.apply_delta(&params, &delta).map_err(|error| {
                            ContractError::InvalidUpdateWithInfo {
                                reason: format!("activity delta does not verify: {error}"),
                            }
                        })?;
                    }
                }
                _ => {}
            }
        }
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
        let summary = activity.summarize();
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
        let activity = from_reader::<ActivityStateV1, &[u8]>(state.as_ref())
            .map_err(|error| ContractError::Deser(error.to_string()))?;
        let old_summary = if summary.as_ref().is_empty() {
            ActivitySummaryV1::default()
        } else {
            from_reader::<ActivitySummaryV1, &[u8]>(summary.as_ref())
                .map_err(|error| ContractError::Deser(error.to_string()))?
        };
        match activity.delta(&old_summary) {
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
pub extern "C" fn plaza_activity_contract_revision() -> u32 {
    3
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use plaza_core::board_state::activity::ActivityEntryV1;
    use plaza_core::board_state::member::MemberId;
    use plaza_core::board_state::message::MessageId;
    use plaza_core::board_state::topics::{AuthorizedTopicActivityV1, TopicActivityV1};
    use plaza_core::util::sign_struct;

    macro_rules! cbor {
        ($value:expr) => {{
            let mut out = Vec::new();
            into_writer($value, &mut out).unwrap();
            out
        }};
    }

    fn make_entry(key: &SigningKey, topic: u8, generation: u64, last: i64) -> ActivityEntryV1 {
        let topic_id = MessageId::from_bytes([topic; 32]);
        let value = TopicActivityV1 {
            topic_id,
            last_activity: last,
            last_post_id: None,
            reply_count: generation as u32,
            pending_approvals: 0,
            generation,
        };
        ActivityEntryV1 {
            topic_id,
            part: 0,
            activity: AuthorizedTopicActivityV1 {
                signature: sign_struct(&value, key),
                activity: value,
                signer: Some(MemberId::from(&key.verifying_key())),
                signer_key: Some(key.verifying_key()),
            },
            proof: None,
        }
    }

    #[test]
    fn summarize_and_get_state_delta_round_trip() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let params = Parameters::from(cbor!(&ActivityParametersV1 {
            owner: key.verifying_key(),
            section: Some(MessageId::from_bytes([9u8; 32])),
        }));

        let peer_a = ActivityContract::update_state(
            params.clone(),
            State::from(Vec::new()),
            vec![UpdateData::Delta(
                cbor!(&ActivityDeltaV1 {
                    entries: vec![make_entry(&key, 1, 1, 100)],
                })
                .into(),
            )],
        )
        .unwrap()
        .new_state
        .unwrap();

        let peer_b = ActivityContract::update_state(
            params.clone(),
            peer_a.clone(),
            vec![UpdateData::Delta(
                cbor!(&ActivityDeltaV1 {
                    entries: vec![make_entry(&key, 1, 2, 200), make_entry(&key, 2, 1, 300)],
                })
                .into(),
            )],
        )
        .unwrap()
        .new_state
        .unwrap();

        let summary_a = ActivityContract::summarize_state(params.clone(), peer_a.clone()).unwrap();
        let delta_bytes =
            ActivityContract::get_state_delta(params.clone(), peer_b.clone(), summary_a).unwrap();
        let decoded_delta: ActivityDeltaV1 = from_reader(delta_bytes.as_ref()).unwrap();
        assert_eq!(decoded_delta.entries.len(), 2);

        let synced_a = ActivityContract::update_state(
            params.clone(),
            peer_a,
            vec![UpdateData::Delta(delta_bytes)],
        )
        .unwrap()
        .new_state
        .unwrap();
        assert_eq!(synced_a.as_ref(), peer_b.as_ref());

        let summary_synced = ActivityContract::summarize_state(params.clone(), synced_a).unwrap();
        let empty_delta =
            ActivityContract::get_state_delta(params, peer_b, summary_synced).unwrap();
        assert!(empty_delta.as_ref().is_empty());
    }
}
