//! Per-board / per-section moderation feed.
//!
//! Reporting a topic no longer rewrites the section page that holds it. On flat
//! `TopicIndex` boards reports live in `ModerationParametersV1 { owner, section: None }`;
//! on `SectionedTopicIndex` boards each section gets its own moderation feed
//! `ModerationParametersV1 { owner, section: Some(section_id) }`.
//!
//! Read-only loads are strictly GET-only with a retry cooldown and never PUT
//! empty feeds. The first write to an unsynced feed uses an additive PUT.

use dioxus::prelude::*;
use ed25519_dalek::VerifyingKey;
use freenet_stdlib::client_api::{ClientRequest, ContractRequest, ContractResponse};
use freenet_stdlib::prelude::{
    ContractCode, ContractContainer, ContractInstanceId, ContractKey, ContractWasmAPIVersion,
    Parameters, UpdateData, WrappedContract, WrappedState,
};
use plaza_core::board_state::member::MemberId;
use plaza_core::board_state::member_shards::verify_member_proof;
use plaza_core::board_state::report_feed::{
    ModerationParametersV1, ReportFeedDeltaV1, ReportFeedStateV1,
};
use plaza_core::board_state::roles::{
    resolve_signer_key, verify_moderation_authority, ModerationPower,
};
use plaza_core::board_state::sections::SectionId;
use plaza_core::board_state::topics::{
    AuthorizedTopicReportResolutionV1, AuthorizedTopicReportV1, TopicIndexV1, TopicReportKey,
};
use plaza_core::board_state::{BoardModeV1, ChatBoardParametersV1, ChatBoardStateV1};
use plaza_core::util::verify_struct;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::components::app::send_client_request;
use crate::constants::MODERATION_CONTRACT_WASM;
use crate::util::to_cbor_vec;

/// Cooldown before retrying a GET for an unsynced (not yet created) feed.
const UNSYNCED_RETRY_COOLDOWN_MS: i64 = 10_000;
/// Maximum moderation feeds kept in RAM across all boards/sections (LRU evicted).
const MAX_CACHED_MODERATION_FEEDS: usize = 32;

fn now_ms() -> i64 {
    plaza_core::board_state::rate_limit::system_time_ms(crate::util::get_current_system_time())
}

fn evict_moderation_boards(protect: ContractInstanceId) {
    let mut evicted = Vec::new();
    MODERATION_BOARDS.with_mut(|boards| {
        while boards.len() > MAX_CACHED_MODERATION_FEEDS {
            let victim = boards
                .iter()
                .filter(|(id, board)| **id != protect && !board.dirty)
                .min_by_key(|(_, board)| board.last_fetch)
                .map(|(id, _)| *id);
            match victim {
                Some(id) => {
                    boards.remove(&id);
                    evicted.push(id);
                }
                None => break,
            }
        }
    });
    for id in evicted {
        crate::components::app::notify_contract_evicted("moderation_feed", id);
    }
}

#[derive(Clone)]
pub struct ModerationBoard {
    pub params: ModerationParametersV1,
    pub state: ReportFeedStateV1,
    pub synced: bool,
    /// A local report or resolution has not been confirmed by the node yet.
    pub dirty: bool,
    pub last_fetch: i64,
}

pub static MODERATION_BOARDS: GlobalSignal<HashMap<ContractInstanceId, ModerationBoard>> =
    Global::new(HashMap::new);

pub fn moderation_key(owner: VerifyingKey, section: Option<SectionId>) -> ContractKey {
    let params = ModerationParametersV1 { owner, section };
    let parameters = Parameters::from(to_cbor_vec(&params));
    let code = ContractCode::from(MODERATION_CONTRACT_WASM);
    ContractKey::from_params_and_code(parameters, &code)
}

fn moderation_contract(owner: VerifyingKey, section: Option<SectionId>) -> ContractContainer {
    let params = ModerationParametersV1 { owner, section };
    ContractContainer::from(ContractWasmAPIVersion::V1(WrappedContract::new(
        Arc::new(ContractCode::from(MODERATION_CONTRACT_WASM)),
        Parameters::from(to_cbor_vec(&params)),
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

pub async fn load_moderation(
    owner: VerifyingKey,
    section: Option<SectionId>,
) -> Result<(), String> {
    let key = moderation_key(owner, section);
    let contract_id = *key.id();
    let now = now_ms();
    // Read-only loads never PUT an empty feed; `record_report`/`record_resolution`
    // create it on first write. Unsynced feeds retry after the cooldown.
    let should_skip = MODERATION_BOARDS.read().get(&contract_id).is_some_and(|board| {
        board.synced || now.saturating_sub(board.last_fetch) < UNSYNCED_RETRY_COOLDOWN_MS
    });
    if should_skip {
        return Ok(());
    }
    let params = ModerationParametersV1 { owner, section };
    MODERATION_BOARDS.with_mut(|boards| {
        let entry = boards.entry(contract_id).or_insert(ModerationBoard {
            params,
            state: ReportFeedStateV1::default(),
            synced: false,
            dirty: false,
            last_fetch: now,
        });
        entry.last_fetch = now;
    });
    evict_moderation_boards(contract_id);
    send_client_request(ClientRequest::ContractOp(ContractRequest::Get {
        key: contract_id,
        return_contract_code: false,
        subscribe: true,
        blocking_subscribe: false,
    }))
    .await
    .map_err(|error| format!("get moderation contract: {error}"))
}

/// Load the moderation feed(s) for a board: the single board-wide feed on flat
/// `TopicIndex` boards, or one feed per active section on `SectionedTopicIndex`
/// boards. Called on demand by the moderation view.
pub async fn load_moderation_for_board(owner: VerifyingKey) {
    let targets: Vec<Option<SectionId>> = {
        let boards = crate::components::app::BOARDS.read();
        let Some(board) = boards.map.get(&owner) else {
            return;
        };
        if board.board_state.mode == BoardModeV1::SectionedTopicIndex {
            board
                .board_state
                .sections
                .sections
                .iter()
                .filter(|entry| !entry.section.deleted && entry.section.contract.is_some())
                .map(|entry| Some(entry.section.id))
                .collect()
        } else {
            vec![None]
        }
    };
    for section in targets {
        let _ = load_moderation(owner, section).await;
    }
}

/// Return the sections whose loaded moderation feed has an open report targeting
/// a topic not yet present in `index.entries` (e.g., living on an unloaded extra
/// section page). Allows the moderation view to load extra pages only for those
/// specific sections instead of every section on the board.
pub fn missing_report_sections(owner: VerifyingKey, index: &TopicIndexV1) -> Vec<SectionId> {
    let boards = MODERATION_BOARDS.read();
    let mut resolved: HashSet<TopicReportKey> = index
        .report_resolutions
        .iter()
        .map(resolution_key)
        .collect();
    for board in boards.values().filter(|board| board.params.owner == owner) {
        for entry in &board.state.resolutions {
            resolved.insert(resolution_key(entry));
        }
    }
    let mut sections = Vec::new();
    let mut seen = HashSet::new();
    for board in boards.values().filter(|board| board.params.owner == owner) {
        let Some(section) = board.params.section else {
            continue;
        };
        if seen.contains(&section) {
            continue;
        }
        let has_missing = board.state.reports.iter().any(|entry| {
            !resolved.contains(&report_key(entry))
                && index.entry(&entry.report.topic_id).is_none()
        });
        if has_missing && seen.insert(section) {
            sections.push(section);
        }
    }
    sections
}

pub async fn handle_contract_response(response: ContractResponse) -> Result<(), String> {
    match response {
        ContractResponse::GetResponse { key, state, .. } => {
            let Some(params) = MODERATION_BOARDS
                .read()
                .get(key.id())
                .map(|board| board.params.clone())
            else {
                return Ok(());
            };
            let network = if state.as_ref().is_empty() {
                ReportFeedStateV1::default()
            } else {
                ciborium::de::from_reader::<ReportFeedStateV1, _>(state.as_ref())
                    .map_err(|error| format!("decode moderation state: {error}"))?
            };
            network
                .verify(&params)
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
                        if merged.apply_delta(&params, &delta).is_ok() {
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
            let Some((params, mut state)) = MODERATION_BOARDS
                .read()
                .get(key.id())
                .map(|board| (board.params.clone(), board.state.clone()))
            else {
                return Ok(());
            };
            match update {
                UpdateData::State(bytes) => {
                    if !bytes.as_ref().is_empty() {
                        let network =
                            ciborium::de::from_reader::<ReportFeedStateV1, _>(bytes.as_ref())
                                .map_err(|error| format!("decode moderation update: {error}"))?;
                        let delta = ReportFeedDeltaV1 {
                            reports: network.reports,
                            resolutions: network.resolutions,
                        };
                        state
                            .apply_delta(&params, &delta)
                            .map_err(|error| format!("apply moderation state: {error}"))?;
                    }
                }
                UpdateData::Delta(bytes) => {
                    if !bytes.as_ref().is_empty() {
                        let delta =
                            ciborium::de::from_reader::<ReportFeedDeltaV1, _>(bytes.as_ref())
                                .map_err(|error| format!("decode moderation delta: {error}"))?;
                        state
                            .apply_delta(&params, &delta)
                            .map_err(|error| format!("apply moderation delta: {error}"))?;
                    }
                }
                UpdateData::StateAndDelta {
                    state: state_bytes,
                    delta: delta_bytes,
                } => {
                    if !delta_bytes.as_ref().is_empty() {
                        let delta = ciborium::de::from_reader::<ReportFeedDeltaV1, _>(
                            delta_bytes.as_ref(),
                        )
                        .map_err(|error| format!("decode moderation delta: {error}"))?;
                        state
                            .apply_delta(&params, &delta)
                            .map_err(|error| format!("apply moderation delta: {error}"))?;
                    } else if !state_bytes.as_ref().is_empty() {
                        let network = ciborium::de::from_reader::<ReportFeedStateV1, _>(
                            state_bytes.as_ref(),
                        )
                        .map_err(|error| format!("decode moderation update: {error}"))?;
                        let delta = ReportFeedDeltaV1 {
                            reports: network.reports,
                            resolutions: network.resolutions,
                        };
                        state
                            .apply_delta(&params, &delta)
                            .map_err(|error| format!("apply moderation state: {error}"))?;
                    }
                }
                _ => {}
            }
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

/// Overlay all loaded moderation feeds (flat and per-section) for `owner` on a
/// merged board index. A report is shown if its reporter signature verifies
/// against the board state OR its embedded `MemberProofV1` (so shard-only
/// reporters appear immediately even before their member shard is fetched);
/// a resolution requires moderation power over the topic's section.
pub fn apply_to_index(
    owner: VerifyingKey,
    state: &ChatBoardStateV1,
    index: &mut TopicIndexV1,
) {
    let (all_reports, all_resolutions) = {
        let boards = MODERATION_BOARDS.read();
        let mut reports = Vec::new();
        let mut resolutions = Vec::new();
        for board in boards.values().filter(|board| board.params.owner == owner) {
            reports.extend(board.state.reports.iter().cloned());
            resolutions.extend(board.state.resolutions.iter().cloned());
        }
        (reports, resolutions)
    };
    if all_reports.is_empty() && all_resolutions.is_empty() {
        return;
    }
    let parameters = ChatBoardParametersV1 { owner };
    for entry in all_reports {
        if index.entry(&entry.report.topic_id).is_none() {
            continue;
        }
        let verified = match resolve_signer_key(state, &parameters, &entry.report.reporter, None) {
            Ok(key) => verify_struct(&entry.report, &entry.signature, &key).is_ok(),
            Err(_) => entry.signer_key.is_some_and(|signer_key| {
                MemberId::from(&signer_key) == entry.report.reporter
                    && verify_struct(&entry.report, &entry.signature, &signer_key).is_ok()
                    && verify_member_proof(
                        &owner,
                        &entry.report.reporter,
                        &signer_key,
                        entry.proof.as_deref(),
                    )
                    .is_ok()
            }),
        };
        if !verified {
            continue;
        }
        merge_report(index, &entry);
    }
    let reports = index.reports.clone();
    for entry in all_resolutions {
        let key = resolution_key(&entry);
        if !reports.iter().any(|report| report_key(report) == key) {
            continue;
        }
        let Some(signer_key) = entry.signer_key else {
            continue;
        };
        if MemberId::from(&signer_key) != entry.resolution.resolved_by {
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

async fn send_delta(
    owner: VerifyingKey,
    section: Option<SectionId>,
    delta: ReportFeedDeltaV1,
) -> Result<(), String> {
    let params = ModerationParametersV1 { owner, section };
    let key = moderation_key(owner, section);
    let contract_id = *key.id();
    let already_synced = MODERATION_BOARDS
        .read()
        .get(&contract_id)
        .map(|board| board.synced)
        .unwrap_or(false);
    let now = now_ms();
    let mut apply_err = None;
    MODERATION_BOARDS.with_mut(|boards| {
        let board = boards.entry(contract_id).or_insert(ModerationBoard {
            params: params.clone(),
            state: ReportFeedStateV1::default(),
            synced: false,
            dirty: true,
            last_fetch: now,
        });
        if let Err(err) = board.state.apply_delta(&params, &delta) {
            apply_err = Some(err);
        } else {
            board.dirty = true;
        }
    });
    if let Some(err) = apply_err {
        return Err(format!("moderation delta failed local verification: {err}"));
    }
    if already_synced {
        send_client_request(ClientRequest::ContractOp(ContractRequest::Update {
            key,
            data: UpdateData::Delta(to_cbor_vec(&delta).into()),
        }))
        .await
        .map_err(|error| format!("send moderation delta failed: {error}"))
    } else {
        // The feed contract has not been confirmed on the node yet (`load_moderation`
        // is GET-only and never PUTs empty feeds). PUT creates it on first write
        // and merges additively if another peer already created it.
        let state = MODERATION_BOARDS
            .read()
            .get(&contract_id)
            .map(|board| board.state.clone())
            .unwrap_or_default();
        send_client_request(ClientRequest::ContractOp(ContractRequest::Put {
            contract: moderation_contract(owner, section),
            state: WrappedState::new(to_cbor_vec(&state)),
            related_contracts: Default::default(),
            subscribe: true,
            blocking_subscribe: false,
        }))
        .await
        .map_err(|error| format!("put moderation feed failed: {error}"))
    }
}

pub async fn record_report(
    owner: VerifyingKey,
    section: Option<SectionId>,
    report: AuthorizedTopicReportV1,
) -> Result<(), String> {
    send_delta(
        owner,
        section,
        ReportFeedDeltaV1 {
            reports: vec![report],
            resolutions: Vec::new(),
        },
    )
    .await
}

pub async fn record_resolution(
    owner: VerifyingKey,
    section: Option<SectionId>,
    resolution: AuthorizedTopicReportResolutionV1,
) -> Result<(), String> {
    send_delta(
        owner,
        section,
        ReportFeedDeltaV1 {
            reports: Vec::new(),
            resolutions: vec![resolution],
        },
    )
    .await
}
