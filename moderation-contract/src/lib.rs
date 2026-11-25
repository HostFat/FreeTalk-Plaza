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
    ReportFeedDeltaV1, ReportFeedStateV1, ReportFeedSummaryV1,
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
                    if bytes.as_ref().is_empty() {
                        continue;
                    }
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
                    if bytes.as_ref().is_empty() {
                        continue;
                    }
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
        let summary = feed.summarize();
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
        let feed = from_reader::<ReportFeedStateV1, &[u8]>(state.as_ref())
            .map_err(|error| ContractError::Deser(error.to_string()))?;
        let old_summary = if summary.as_ref().is_empty() {
            ReportFeedSummaryV1::default()
        } else {
            from_reader::<ReportFeedSummaryV1, &[u8]>(summary.as_ref())
                .map_err(|error| ContractError::Deser(error.to_string()))?
        };
        match feed.delta(&old_summary) {
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
pub extern "C" fn plaza_moderation_contract_revision() -> u32 {
    2
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use plaza_core::board_state::member::MemberId;
    use plaza_core::board_state::message::MessageId;
    use plaza_core::board_state::privacy::SealedBytes;
    use plaza_core::board_state::reports::ReportReason;
    use plaza_core::board_state::topics::{
        AuthorizedTopicReportResolutionV1, AuthorizedTopicReportV1, TopicReportResolutionV1,
        TopicReportV1,
    };
    use plaza_core::util::sign_struct;

    macro_rules! cbor {
        ($value:expr) => {{
            let mut out = Vec::new();
            into_writer($value, &mut out).unwrap();
            out
        }};
    }

    fn make_report(topic: u8, reporter: &SigningKey, generation: u64) -> AuthorizedTopicReportV1 {
        let value = TopicReportV1 {
            topic_id: MessageId::from_bytes([topic; 32]),
            post_id: None,
            reporter: MemberId::from(&reporter.verifying_key()),
            reason: ReportReason::Spam,
            body: SealedBytes::public(b"Spam".to_vec()),
            created_at: 1_000 + generation as i64,
            generation,
        };
        AuthorizedTopicReportV1 {
            signature: sign_struct(&value, reporter),
            report: value,
        }
    }

    fn make_resolution(
        topic: u8,
        reporter: &SigningKey,
        resolver: &SigningKey,
        generation: u64,
    ) -> AuthorizedTopicReportResolutionV1 {
        let value = TopicReportResolutionV1 {
            topic_id: MessageId::from_bytes([topic; 32]),
            post_id: None,
            reporter: MemberId::from(&reporter.verifying_key()),
            resolved_by: MemberId::from(&resolver.verifying_key()),
            created_at: 2_000 + generation as i64,
            generation,
        };
        AuthorizedTopicReportResolutionV1 {
            signature: sign_struct(&value, resolver),
            resolution: value,
            signer_key: Some(resolver.verifying_key()),
            authority: None,
        }
    }

    #[test]
    fn summarize_and_get_state_delta_round_trip() {
        let reporter = SigningKey::from_bytes(&[1u8; 32]);
        let resolver = SigningKey::from_bytes(&[2u8; 32]);
        let params = Parameters::from(cbor!(&ChatBoardParametersV1 {
            owner: resolver.verifying_key(),
        }));

        let peer_a = ModerationContract::update_state(
            params.clone(),
            State::from(Vec::new()),
            vec![UpdateData::Delta(
                cbor!(&ReportFeedDeltaV1 {
                    reports: vec![make_report(1, &reporter, 1)],
                    resolutions: Vec::new(),
                })
                .into(),
            )],
        )
        .unwrap()
        .new_state
        .unwrap();

        let peer_b = ModerationContract::update_state(
            params.clone(),
            peer_a.clone(),
            vec![UpdateData::Delta(
                cbor!(&ReportFeedDeltaV1 {
                    reports: vec![make_report(2, &reporter, 1)],
                    resolutions: vec![make_resolution(1, &reporter, &resolver, 1)],
                })
                .into(),
            )],
        )
        .unwrap()
        .new_state
        .unwrap();

        let summary_a =
            ModerationContract::summarize_state(params.clone(), peer_a.clone()).unwrap();
        let delta_bytes =
            ModerationContract::get_state_delta(params.clone(), peer_b.clone(), summary_a).unwrap();
        let decoded_delta: ReportFeedDeltaV1 = from_reader(delta_bytes.as_ref()).unwrap();
        assert_eq!(decoded_delta.reports.len(), 1);
        assert_eq!(decoded_delta.resolutions.len(), 1);

        let synced_a = ModerationContract::update_state(
            params.clone(),
            peer_a,
            vec![UpdateData::Delta(delta_bytes)],
        )
        .unwrap()
        .new_state
        .unwrap();
        assert_eq!(synced_a.as_ref(), peer_b.as_ref());

        let summary_synced =
            ModerationContract::summarize_state(params.clone(), synced_a).unwrap();
        let empty_delta =
            ModerationContract::get_state_delta(params, peer_b, summary_synced).unwrap();
        assert!(empty_delta.as_ref().is_empty());
    }
}
