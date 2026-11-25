//! Per-board recent activity contract.
//!
//! Replies no longer write the board or section index. The client sends a
//! small activity delta to this contract; the board list overlays the recent
//! entries on the index for reply counts, pending approvals and ordering.

use dioxus::prelude::*;
use ed25519_dalek::VerifyingKey;
use freenet_stdlib::client_api::{ClientRequest, ContractRequest, ContractResponse};
use freenet_stdlib::prelude::{
    ContractCode, ContractContainer, ContractInstanceId, ContractKey, ContractWasmAPIVersion,
    Parameters, UpdateData, WrappedContract, WrappedState,
};
use plaza_core::board_state::activity::{
    ActivityDeltaV1, ActivityEntryV1, ActivityStateV1,
};
use plaza_core::board_state::topics::AuthorizedTopicActivityV1;
use plaza_core::board_state::{ChatBoardParametersV1, message::MessageId};
use std::collections::HashMap;
use std::sync::Arc;

use crate::components::app::send_client_request;
use crate::constants::ACTIVITY_CONTRACT_WASM;
use crate::util::to_cbor_vec;

#[derive(Clone)]
pub struct ActivityBoard {
    pub owner: VerifyingKey,
    pub state: ActivityStateV1,
    pub synced: bool,
}

pub static ACTIVITY_BOARDS: GlobalSignal<HashMap<ContractInstanceId, ActivityBoard>> =
    Global::new(HashMap::new);

pub fn activity_key(owner: VerifyingKey) -> ContractKey {
    let parameters = Parameters::from(to_cbor_vec(&ChatBoardParametersV1 { owner }));
    let code = ContractCode::from(ACTIVITY_CONTRACT_WASM);
    ContractKey::from_params_and_code(parameters, &code)
}

fn activity_contract(owner: VerifyingKey) -> ContractContainer {
    ContractContainer::from(ContractWasmAPIVersion::V1(WrappedContract::new(
        Arc::new(ContractCode::from(ACTIVITY_CONTRACT_WASM)),
        Parameters::from(to_cbor_vec(&ChatBoardParametersV1 { owner })),
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

pub async fn load_activity(owner: VerifyingKey) -> Result<(), String> {
    let key = activity_key(owner);
    let contract_id = *key.id();
    let already_synced = ACTIVITY_BOARDS
        .read()
        .get(&contract_id)
        .map(|board| board.synced)
        .unwrap_or(false);
    if already_synced {
        return Ok(());
    }
    ACTIVITY_BOARDS.with_mut(|boards| {
        boards.entry(contract_id).or_insert(ActivityBoard {
            owner,
            state: ActivityStateV1::default(),
            synced: false,
        });
    });
    // The activity contract is created on first use. The contract merges a
    // state update, so putting an empty state is a no-op when it already
    // exists and never drops entries written by another client.
    let put = send_client_request(ClientRequest::ContractOp(ContractRequest::Put {
        contract: activity_contract(owner),
        state: WrappedState::new(to_cbor_vec(&ActivityStateV1::default())),
        related_contracts: Default::default(),
        subscribe: true,
        blocking_subscribe: false,
    }))
    .await;
    if let Err(error) = put {
        dioxus::logger::tracing::warn!(
            "activity contract put failed for {:?}: {error}",
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
    .map_err(|error| format!("get activity contract: {error}"))
}

pub async fn handle_contract_response(response: ContractResponse) -> Result<(), String> {
    match response {
        ContractResponse::GetResponse { key, state, .. } => {
            let activity = if state.as_ref().is_empty() {
                ActivityStateV1::default()
            } else {
                ciborium::de::from_reader::<ActivityStateV1, _>(state.as_ref())
                    .map_err(|error| format!("decode activity state: {error}"))?
            };
            activity
                .verify()
                .map_err(|error| format!("activity state does not verify: {error}"))?;
            ACTIVITY_BOARDS.with_mut(|boards| {
                if let Some(board) = boards.get_mut(key.id()) {
                    board.state = activity;
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
                }
            });
        }
        ContractResponse::UpdateNotification { key, update } => {
            let Some(owner) = ACTIVITY_BOARDS
                .read()
                .get(key.id())
                .map(|board| board.owner)
            else {
                return Ok(());
            };
            let _ = owner;
            let mut activity = ACTIVITY_BOARDS
                .read()
                .get(key.id())
                .map(|board| board.state.clone())
                .unwrap_or_default();
            match update {
                UpdateData::State(bytes) => {
                    activity = ciborium::de::from_reader::<ActivityStateV1, _>(bytes.as_ref())
                        .map_err(|error| format!("decode activity update: {error}"))?;
                }
                UpdateData::Delta(bytes) => {
                    let delta = ciborium::de::from_reader::<ActivityDeltaV1, _>(bytes.as_ref())
                        .map_err(|error| format!("decode activity delta: {error}"))?;
                    activity
                        .apply_delta(&delta)
                        .map_err(|error| format!("apply activity delta: {error}"))?;
                }
                _ => {}
            }
            activity
                .verify()
                .map_err(|error| format!("activity update does not verify: {error}"))?;
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

pub fn state_for(owner: VerifyingKey) -> Option<ActivityStateV1> {
    let key = activity_key(owner);
    ACTIVITY_BOARDS
        .read()
        .get(key.id())
        .map(|board| board.state.clone())
}

/// Overlay the recent activity contract entries on a board index. Legacy
/// activity rows stay as a fallback for topics outside the contract window.
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

/// The recent entries a board list can overlay on its index. Entries whose
/// signer is not a member of the board are dropped here: the contract is a
/// hint, and the board/topic contracts remain the authority.
fn entries_for(
    owner: VerifyingKey,
    members: &std::collections::HashSet<plaza_core::board_state::member::MemberId>,
) -> Vec<ActivityEntryV1> {
    let state = match state_for(owner) {
        Some(state) => state,
        None => return Vec::new(),
    };
    let owner_id = plaza_core::board_state::member::MemberId::from(&owner);
    state
        .entries
        .into_iter()
        .filter(|entry| {
            entry
                .activity
                .signer
                .map(|signer| signer == owner_id || members.contains(&signer))
                .unwrap_or(false)
        })
        .collect()
}

pub async fn record_activity(
    owner: VerifyingKey,
    topic_id: MessageId,
    part: u32,
    activity: AuthorizedTopicActivityV1,
) -> Result<(), String> {
    let entry = ActivityEntryV1 {
        topic_id,
        part,
        activity,
    };
    let key = activity_key(owner);
    let contract_id = *key.id();
    ACTIVITY_BOARDS.with_mut(|boards| {
        let board = boards.entry(contract_id).or_insert(ActivityBoard {
            owner,
            state: ActivityStateV1::default(),
            synced: false,
        });
        let delta = ActivityDeltaV1 {
            entries: vec![entry.clone()],
        };
        let _ = board.state.apply_delta(&delta);
    });
    let delta = ActivityDeltaV1 {
        entries: vec![entry],
    };
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
    let state = ACTIVITY_BOARDS
        .read()
        .get(&contract_id)
        .map(|board| board.state.clone())
        .unwrap_or_default();
    send_client_request(ClientRequest::ContractOp(ContractRequest::Put {
        contract: activity_contract(owner),
        state: WrappedState::new(to_cbor_vec(&state)),
        related_contracts: Default::default(),
        subscribe: true,
        blocking_subscribe: false,
    }))
    .await
    .map_err(|error| {
        format!(
            "send activity delta failed ({}), put failed: {error}",
            update.err().map(|error| error.to_string()).unwrap_or_default()
        )
    })
}

