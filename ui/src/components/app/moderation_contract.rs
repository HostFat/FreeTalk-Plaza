//! Per-board moderation feed.
//!
//! Reporting a topic used to rewrite the section page that holds it. The
//! client sends a small delta to this contract instead; the moderation queue
//! overlays the verified reports and resolutions on the merged index.

use dioxus::prelude::*;
use ed25519_dalek::VerifyingKey;
use freenet_stdlib::client_api::{ClientRequest, ContractRequest, ContractResponse};
use freenet_stdlib::prelude::{
    ContractCode, ContractContainer, ContractInstanceId, ContractKey, ContractWasmAPIVersion,
    Parameters, UpdateData, WrappedContract, WrappedState,
};
use plaza_core::board_state::report_feed::{
    ReportFeedDeltaV1, ReportFeedStateV1,
};
use plaza_core::board_state::roles::{
    resolve_signer_key, verify_moderation_authority, ModerationPower,
};
use plaza_core::board_state::topics::{
    AuthorizedTopicReportResolutionV1, AuthorizedTopicReportV1, TopicIndexV1,
    TopicReportKey,
};
use plaza_core::board_state::{ChatBoardParametersV1, ChatBoardStateV1};
use plaza_core::util::verify_struct;
use std::collections::HashMap;
use std::sync::Arc;

use crate::components::app::send_client_request;
use crate::constants::MODERATION_CONTRACT_WASM;
use crate::util::to_cbor_vec;

#[derive(Clone)]
pub struct ModerationBoard {
    pub state: ReportFeedStateV1,
    pub synced: bool,
    /// A local report or resolution has not been confirmed by the node yet.
    pub dirty: bool,
}

pub static MODERATION_BOARDS: GlobalSignal<HashMap<ContractInstanceId, ModerationBoard>> =
    Global::new(HashMap::new);

pub fn moderation_key(owner: VerifyingKey) -> ContractKey {
    let parameters = Parameters::from(to_cbor_vec(&ChatBoardParametersV1 { owner }));
    let code = ContractCode::from(MODERATION_CONTRACT_WASM);
    ContractKey::from_params_and_code(parameters, &code)
}

fn moderation_contract(owner: VerifyingKey) -> ContractContainer {
    ContractContainer::from(ContractWasmAPIVersion::V1(WrappedContract::new(
        Arc::new(ContractCode::from(MODERATION_CONTRACT_WASM)),
        Parameters::from(to_cbor_vec(&ChatBoardParametersV1 { owner })),
    )))
}

pub fn is_known_moderation_contract(key: &ContractInstanceId) -> bool {
    MODERATION_BOARDS.read().contains_key(key)
}

pub fn is_moderation_contract_response(response: &ContractResponse) -> bool {
    match response {
        ContractResponse::GetResponse { key, .. }
        | ContractResponse::PutResponse { key }
        | ContractResponse::UpdateResponse { key, .. }
        | ContractResponse::UpdateNotification { key, .. }
        | ContractResponse::SubscribeResponse { key, .. } => {
            is_known_moderation_contract(key.id())
        }
        _ => false,
    }
}

pub async fn load_moderation(owner: VerifyingKey) -> Result<(), String> {
    let key = moderation_key(owner);
    let contract_id = *key.id();
    let already_synced = MODERATION_BOARDS
        .read()
        .get(&contract_id)
        .map(|board| board.synced)
        .unwrap_or(false);
    if already_synced {
        return Ok(());
    }
    MODERATION_BOARDS.with_mut(|boards| {
        boards.entry(contract_id).or_insert(ModerationBoard {
            state: ReportFeedStateV1::default(),
            synced: false,
            dirty: false,
        });
    });
    let put = send_client_request(ClientRequest::ContractOp(ContractRequest::Put {
        contract: moderation_contract(owner),
        state: WrappedState::new(to_cbor_vec(&ReportFeedStateV1::default())),
        related_contracts: Default::default(),
        subscribe: true,
        blocking_subscribe: false,
    }))
    .await;
    if let Err(error) = put {
        dioxus::logger::tracing::warn!(
            "moderation contract put failed for {:?}: {error}",
            owner
        );
    }
    send_client_request(ClientRequest::ContractOp(ContractRequest::Get {
        key: contract_id,
        return_contract_code: false,
        subscribe: true,
        blocking_subscribe: false,
    }))
    .await
    .map_err(|error| format!("get moderation contract: {error}"))
}

pub async fn handle_contract_response(response: ContractResponse) -> Result<(), String> {
    match response {
        ContractResponse::GetResponse { key, state, .. } => {
            let network = if state.as_ref().is_empty() {
                ReportFeedStateV1::default()
            } else {
                ciborium::de::from_reader::<ReportFeedStateV1, _>(state.as_ref())
                    .map_err(|error| format!("decode moderation state: {error}"))?
            };
            network
                .verify()
                .map_err(|error| format!("moderation state does not verify: {error}"))?;
            MODERATION_BOARDS.with_mut(|boards| {
                if let Some(board) = boards.get_mut(key.id()) {
                    // A Get can still carry the state from before our delta.
                    // The feed is additive, so merging keeps the local entry.
                    board.state = if board.dirty {
                        let mut merged = board.state.clone();
                        let delta = ReportFeedDeltaV1 {
                            reports: network.reports.clone(),
                            resolutions: network.resolutions.clone(),
                        };
                        if merged.apply_delta(&delta).is_ok() {
                            merged
                        } else {
                            network
                        }
                    } else {
                        network
                    };
                    board.synced = true;
                }
            });
        }
        ContractResponse::PutResponse { key }
        | ContractResponse::UpdateResponse { key, .. }
        | ContractResponse::SubscribeResponse { key, .. } => {
            MODERATION_BOARDS.with_mut(|boards| {
                if let Some(board) = boards.get_mut(key.id()) {
                    board.synced = true;
                    board.dirty = false;
                }
            });
        }
        ContractResponse::UpdateNotification { key, update } => {
            let mut state = MODERATION_BOARDS
                .read()
                .get(key.id())
                .map(|board| board.state.clone())
                .unwrap_or_default();
            match update {
                UpdateData::State(bytes) => {
                    let network = ciborium::de::from_reader::<ReportFeedStateV1, _>(bytes.as_ref())
                        .map_err(|error| format!("decode moderation update: {error}"))?;
                    let delta = ReportFeedDeltaV1 {
                        reports: network.reports,
                        resolutions: network.resolutions,
                    };
                    state
                        .apply_delta(&delta)
                        .map_err(|error| format!("apply moderation state: {error}"))?;
                }
                UpdateData::Delta(bytes) => {
                    let delta = ciborium::de::from_reader::<ReportFeedDeltaV1, _>(bytes.as_ref())
                        .map_err(|error| format!("decode moderation delta: {error}"))?;
                    state
                        .apply_delta(&delta)
                        .map_err(|error| format!("apply moderation delta: {error}"))?;
                }
                _ => {}
            }
            state
                .verify()
                .map_err(|error| format!("moderation update does not verify: {error}"))?;
            MODERATION_BOARDS.with_mut(|boards| {
                if let Some(board) = boards.get_mut(key.id()) {
                    board.state = state;
                    board.synced = true;
                }
            });
        }
        _ => {}
    }
    Ok(())
}

pub fn state_for(owner: VerifyingKey) -> Option<ReportFeedStateV1> {
    let key = moderation_key(owner);
    MODERATION_BOARDS
        .read()
        .get(key.id())
        .map(|board| board.state.clone())
}

fn report_key(entry: &AuthorizedTopicReportV1) -> TopicReportKey {
    (
        entry.report.topic_id,
        entry.report.post_id,
        entry.report.reporter,
    )
}

fn resolution_key(entry: &AuthorizedTopicReportResolutionV1) -> TopicReportKey {
    (
        entry.resolution.topic_id,
        entry.resolution.post_id,
        entry.resolution.reporter,
    )
}

/// Overlay the verified feed on a merged board index. A report is shown only
/// if its reporter signature checks out against the board authority; a
/// resolution also needs moderation power over the topic's section.
pub fn apply_to_index(
    owner: VerifyingKey,
    state: &ChatBoardStateV1,
    index: &mut TopicIndexV1,
) {
    let Some(feed) = state_for(owner) else {
        return;
    };
    let parameters = ChatBoardParametersV1 { owner };
    for entry in feed.reports {
        if index.entry(&entry.report.topic_id).is_none() {
            continue;
        }
        let Ok(key) = resolve_signer_key(
            state,
            &parameters,
            &entry.report.reporter,
            None,
        ) else {
            continue;
        };
        if verify_struct(&entry.report, &entry.signature, &key).is_err() {
            continue;
        }
        merge_report(index, &entry);
    }
    let reports = index.reports.clone();
    for entry in feed.resolutions {
        let key = resolution_key(&entry);
        if !reports.iter().any(|report| report_key(report) == key) {
            continue;
        }
        let Some(signer_key) = entry.signer_key else {
            continue;
        };
        if plaza_core::board_state::member::MemberId::from(&signer_key)
            != entry.resolution.resolved_by
        {
            continue;
        }
        if verify_struct(&entry.resolution, &entry.signature, &signer_key).is_err() {
            continue;
        }
        let chain = index.section_of(&entry.resolution.topic_id).1;
        if verify_moderation_authority(
            state,
            &parameters,
            &entry.resolution.resolved_by,
            ModerationPower::Delete,
            &chain,
            entry.authority.as_deref(),
            plaza_core::board_state::rate_limit::system_time_from_ms(
                entry.resolution.created_at,
            ),
        )
        .is_err()
        {
            continue;
        }
        merge_resolution(index, &entry);
    }
}

fn merge_report(index: &mut TopicIndexV1, entry: &AuthorizedTopicReportV1) {
    let key = report_key(entry);
    match index.reports.iter_mut().find(|existing| report_key(existing) == key) {
        Some(existing) => {
            if entry.report.generation > existing.report.generation {
                *existing = entry.clone();
            }
        }
        None => index.reports.push(entry.clone()),
    }
}

fn merge_resolution(index: &mut TopicIndexV1, entry: &AuthorizedTopicReportResolutionV1) {
    let key = resolution_key(entry);
    match index
        .report_resolutions
        .iter_mut()
        .find(|existing| resolution_key(existing) == key)
    {
        Some(existing) => {
            if entry.resolution.generation > existing.resolution.generation {
                *existing = entry.clone();
            }
        }
        None => index.report_resolutions.push(entry.clone()),
    }
}

async fn send_delta(owner: VerifyingKey, delta: ReportFeedDeltaV1) -> Result<(), String> {
    let key = moderation_key(owner);
    let contract_id = *key.id();
    MODERATION_BOARDS.with_mut(|boards| {
        let board = boards.entry(contract_id).or_insert(ModerationBoard {
            state: ReportFeedStateV1::default(),
            synced: false,
            dirty: true,
        });
        let _ = board.state.apply_delta(&delta);
        board.dirty = true;
    });
    let update = send_client_request(ClientRequest::ContractOp(ContractRequest::Update {
        key,
        data: UpdateData::Delta(to_cbor_vec(&delta).into()),
    }))
    .await;
    if update.is_ok() {
        return Ok(());
    }
    // The contract may not exist yet on a board opened before the load
    // finished. A state PUT is merged additively by the contract.
    let state = MODERATION_BOARDS
        .read()
        .get(&contract_id)
        .map(|board| board.state.clone())
        .unwrap_or_default();
    send_client_request(ClientRequest::ContractOp(ContractRequest::Put {
        contract: moderation_contract(owner),
        state: WrappedState::new(to_cbor_vec(&state)),
        related_contracts: Default::default(),
        subscribe: true,
        blocking_subscribe: false,
    }))
    .await
    .map_err(|error| {
        format!(
            "send moderation delta failed ({}), put failed: {error}",
            update.err().map(|error| error.to_string()).unwrap_or_default()
        )
    })
}

pub async fn record_report(
    owner: VerifyingKey,
    report: AuthorizedTopicReportV1,
) -> Result<(), String> {
    send_delta(
        owner,
        ReportFeedDeltaV1 {
            reports: vec![report],
            resolutions: Vec::new(),
        },
    )
    .await
}

pub async fn record_resolution(
    owner: VerifyingKey,
    resolution: AuthorizedTopicReportResolutionV1,
) -> Result<(), String> {
    send_delta(
        owner,
        ReportFeedDeltaV1 {
            reports: Vec::new(),
            resolutions: vec![resolution],
        },
    )
    .await
}
