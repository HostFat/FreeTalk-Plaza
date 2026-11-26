//! Per-board / per-section recent activity contract.
//!
//! Replies no longer write the board or section index. On flat `TopicIndex`
//! boards the feed is addressed by `ActivityParametersV1 { owner, section: None }`;
//! on `SectionedTopicIndex` boards each section gets its own feed
//! `ActivityParametersV1 { owner, section: Some(section_id) }`.
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
use plaza_core::board_state::activity::{
    ActivityDeltaV1, ActivityEntryV1, ActivityParametersV1, ActivityStateV1,
};
use plaza_core::board_state::message::MessageId;
use plaza_core::board_state::sections::SectionId;
use plaza_core::board_state::topics::AuthorizedTopicActivityV1;
use std::collections::HashMap;
use std::sync::Arc;

use crate::components::app::send_client_request;
use crate::constants::ACTIVITY_CONTRACT_WASM;
use crate::util::to_cbor_vec;

/// Cooldown before retrying a GET for an unsynced (not yet created) feed.
const UNSYNCED_RETRY_COOLDOWN_MS: i64 = 10_000;
/// Maximum activity feeds kept in RAM across all boards/sections (LRU evicted).
const MAX_CACHED_ACTIVITY_FEEDS: usize = 32;

fn now_ms() -> i64 {
    plaza_core::board_state::rate_limit::system_time_ms(crate::util::get_current_system_time())
}

fn evict_activity_boards(protect: ContractInstanceId) {
    let mut evicted = Vec::new();
    ACTIVITY_BOARDS.with_mut(|boards| {
        while boards.len() > MAX_CACHED_ACTIVITY_FEEDS {
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
        crate::components::app::notify_contract_evicted("activity_feed", id);
    }
}

#[derive(Clone)]
pub struct ActivityBoard {
    pub params: ActivityParametersV1,
    pub state: ActivityStateV1,
    pub synced: bool,
    /// A local activity update has not been confirmed by the node yet.
    pub dirty: bool,
    pub last_fetch: i64,
}

pub static ACTIVITY_BOARDS: GlobalSignal<HashMap<ContractInstanceId, ActivityBoard>> =
    Global::new(HashMap::new);

pub fn activity_key(owner: VerifyingKey, section: Option<SectionId>) -> ContractKey {
    let params = ActivityParametersV1 { owner, section };
    let parameters = Parameters::from(to_cbor_vec(&params));
    let code = ContractCode::from(ACTIVITY_CONTRACT_WASM);
    ContractKey::from_params_and_code(parameters, &code)
}

fn activity_contract(owner: VerifyingKey, section: Option<SectionId>) -> ContractContainer {
    let params = ActivityParametersV1 { owner, section };
    ContractContainer::from(ContractWasmAPIVersion::V1(WrappedContract::new(
        Arc::new(ContractCode::from(ACTIVITY_CONTRACT_WASM)),
        Parameters::from(to_cbor_vec(&params)),
    )))
}

pub fn is_known_activity_contract(key: &ContractInstanceId) -> bool {
    ACTIVITY_BOARDS.read().contains_key(key)
}

pub fn is_activity_contract_response(response: &ContractResponse) -> bool {
    match response {
        ContractResponse::GetResponse { key, .. }
        | ContractResponse::PutResponse { key }
        | ContractResponse::UpdateResponse { key, .. }
        | ContractResponse::UpdateNotification { key, .. }
        | ContractResponse::SubscribeResponse { key, .. } => is_known_activity_contract(key.id()),
        _ => false,
    }
}

pub async fn load_activity(
    owner: VerifyingKey,
    section: Option<SectionId>,
) -> Result<(), String> {
    let key = activity_key(owner, section);
    let contract_id = *key.id();
    let now = now_ms();
    // Read-only loads never PUT an empty feed; `record_activity` creates it
    // on first write. Unsynced feeds retry after the cooldown.
    let should_skip = ACTIVITY_BOARDS.read().get(&contract_id).is_some_and(|board| {
        board.synced || now.saturating_sub(board.last_fetch) < UNSYNCED_RETRY_COOLDOWN_MS
    });
    if should_skip {
        return Ok(());
    }
    let params = ActivityParametersV1 { owner, section };
    ACTIVITY_BOARDS.with_mut(|boards| {
        let entry = boards.entry(contract_id).or_insert(ActivityBoard {
            params,
            state: ActivityStateV1::default(),
            synced: false,
            dirty: false,
            last_fetch: now,
        });
        entry.last_fetch = now;
    });
    evict_activity_boards(contract_id);
    send_client_request(ClientRequest::ContractOp(ContractRequest::Get {
        key: contract_id,
        return_contract_code: false,
        subscribe: true,
        blocking_subscribe: false,
    }))
    .await
    .map_err(|error| format!("get activity contract: {error}"))
}

pub async fn handle_contract_response(response: ContractResponse) -> Result<(), String> {
    match response {
        ContractResponse::GetResponse { key, state, .. } => {
            let Some(params) = ACTIVITY_BOARDS
                .read()
                .get(key.id())
                .map(|board| board.params.clone())
            else {
                return Ok(());
            };
            let network = if state.as_ref().is_empty() {
                ActivityStateV1::default()
            } else {
                ciborium::de::from_reader::<ActivityStateV1, _>(state.as_ref())
                    .map_err(|error| format!("decode activity state: {error}"))?
            };
            network
                .verify(&params)
                .map_err(|error| format!("activity state does not verify: {error}"))?;
            ACTIVITY_BOARDS.with_mut(|boards| {
                if let Some(board) = boards.get_mut(key.id()) {
                    board.state = if board.dirty {
                        let mut merged = board.state.clone();
                        let delta = ActivityDeltaV1 {
                            entries: network.entries.clone(),
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
            ACTIVITY_BOARDS.with_mut(|boards| {
                if let Some(board) = boards.get_mut(key.id()) {
                    board.synced = true;
                    board.dirty = false;
                }
            });
        }
        ContractResponse::UpdateNotification { key, update } => {
            let Some((params, mut activity)) = ACTIVITY_BOARDS
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
                            ciborium::de::from_reader::<ActivityStateV1, _>(bytes.as_ref())
                                .map_err(|error| format!("decode activity update: {error}"))?;
                        let delta = ActivityDeltaV1 {
                            entries: network.entries,
                        };
                        activity
                            .apply_delta(&params, &delta)
                            .map_err(|error| format!("apply activity state: {error}"))?;
                    }
                }
                UpdateData::Delta(bytes) => {
                    if !bytes.as_ref().is_empty() {
                        let delta = ciborium::de::from_reader::<ActivityDeltaV1, _>(bytes.as_ref())
                            .map_err(|error| format!("decode activity delta: {error}"))?;
                        activity
                            .apply_delta(&params, &delta)
                            .map_err(|error| format!("apply activity delta: {error}"))?;
                    }
                }
                UpdateData::StateAndDelta {
                    state: state_bytes,
                    delta: delta_bytes,
                } => {
                    if !delta_bytes.as_ref().is_empty() {
                        let delta =
                            ciborium::de::from_reader::<ActivityDeltaV1, _>(delta_bytes.as_ref())
                                .map_err(|error| format!("decode activity delta: {error}"))?;
                        activity
                            .apply_delta(&params, &delta)
                            .map_err(|error| format!("apply activity delta: {error}"))?;
                    } else if !state_bytes.as_ref().is_empty() {
                        let network =
                            ciborium::de::from_reader::<ActivityStateV1, _>(state_bytes.as_ref())
                                .map_err(|error| format!("decode activity update: {error}"))?;
                        let delta = ActivityDeltaV1 {
                            entries: network.entries,
                        };
                        activity
                            .apply_delta(&params, &delta)
                            .map_err(|error| format!("apply activity state: {error}"))?;
                    }
                }
                _ => {}
            }
            ACTIVITY_BOARDS.with_mut(|boards| {
                if let Some(board) = boards.get_mut(key.id()) {
                    board.state = activity;
                    board.synced = true;
                }
            });
        }
        _ => {}
    }
    Ok(())
}

/// Overlay the recent activity contract entries (board-wide and per-section)
/// on a board index. Legacy activity rows stay as a fallback for topics outside
/// the contract window.
pub fn apply_to_index(
    owner: VerifyingKey,
    members: &std::collections::HashSet<plaza_core::board_state::member::MemberId>,
    index: &mut plaza_core::board_state::topics::TopicIndexV1,
) {
    let mut by_topic: HashMap<MessageId, AuthorizedTopicActivityV1> = index
        .activity
        .iter()
        .cloned()
        .map(|entry| (entry.activity.topic_id, entry))
        .collect();
    for entry in entries_for(owner, members) {
        let topic_id = entry.activity.activity.topic_id;
        let replace = by_topic
            .get(&topic_id)
            .map(|existing| {
                entry.activity.activity.last_activity > existing.activity.last_activity
                    || (entry.activity.activity.last_activity == existing.activity.last_activity
                        && entry.activity.activity.generation
                            > existing.activity.generation)
            })
            .unwrap_or(true);
        if replace {
            by_topic.insert(topic_id, entry.activity);
        }
    }
    index.activity = by_topic.into_values().collect();
}

/// The recent entries across all loaded activity feeds (flat and per-section)
/// for `owner`. Each entry was already verified on ingress against its member
/// proof (or founding owner), so shard-only authors show up even before their
/// member shard is fetched.
fn entries_for(
    owner: VerifyingKey,
    members: &std::collections::HashSet<plaza_core::board_state::member::MemberId>,
) -> Vec<ActivityEntryV1> {
    let owner_id = plaza_core::board_state::member::MemberId::from(&owner);
    let boards = ACTIVITY_BOARDS.read();
    let mut out = Vec::new();
    for board in boards.values().filter(|board| board.params.owner == owner) {
        for entry in &board.state.entries {
            let authorized = entry
                .activity
                .signer
                .map(|signer| {
                    signer == owner_id || members.contains(&signer) || entry.proof.is_some()
                })
                .unwrap_or(false);
            if authorized {
                out.push(entry.clone());
            }
        }
    }
    out
}

pub async fn record_activity(
    owner: VerifyingKey,
    section: Option<SectionId>,
    topic_id: MessageId,
    part: u32,
    activity: AuthorizedTopicActivityV1,
) -> Result<(), String> {
    let proof = activity
        .signer_key
        .and_then(|signer_key| crate::components::app::member_contract::build_member_proof(owner, signer_key))
        .map(Box::new);
    let entry = ActivityEntryV1 {
        topic_id,
        part,
        activity,
        proof,
    };
    let params = ActivityParametersV1 { owner, section };
    entry.verify(&params)?;
    let key = activity_key(owner, section);
    let contract_id = *key.id();
    let already_synced = ACTIVITY_BOARDS
        .read()
        .get(&contract_id)
        .map(|board| board.synced)
        .unwrap_or(false);
    let delta = ActivityDeltaV1 {
        entries: vec![entry],
    };
    let now = now_ms();
    let mut apply_err: Option<String> = None;
    ACTIVITY_BOARDS.with_mut(|boards| {
        let board = boards.entry(contract_id).or_insert(ActivityBoard {
            params: params.clone(),
            state: ActivityStateV1::default(),
            synced: false,
            dirty: true,
            last_fetch: now,
        });
        if let Err(error) = board.state.apply_delta(&params, &delta) {
            apply_err = Some(error);
            return;
        }
        board.dirty = true;
    });
    if let Some(error) = apply_err {
        return Err(format!("apply activity delta failed: {error}"));
    }
    if already_synced {
        send_client_request(ClientRequest::ContractOp(ContractRequest::Update {
            key,
            data: UpdateData::Delta(to_cbor_vec(&delta).into()),
        }))
        .await
        .map_err(|error| format!("send activity delta failed: {error}"))
    } else {
        // The feed contract has not been confirmed on the node yet (`load_activity`
        // is GET-only and never PUTs empty feeds). PUT creates it on first write
        // and merges additively if another peer already created it.
        let state = ACTIVITY_BOARDS
            .read()
            .get(&contract_id)
            .map(|board| board.state.clone())
            .unwrap_or_default();
        send_client_request(ClientRequest::ContractOp(ContractRequest::Put {
            contract: activity_contract(owner, section),
            state: WrappedState::new(to_cbor_vec(&state)),
            related_contracts: Default::default(),
            subscribe: true,
            blocking_subscribe: false,
        }))
        .await
        .map_err(|error| format!("put activity feed failed: {error}"))
    }
}
