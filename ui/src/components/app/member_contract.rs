//! Sharded per-board member directory client.
//!
//! Members live in `MEMBER_SHARD_COUNT` deterministic bucket contracts
//! addressed by `MemberShardParametersV1 { owner, bucket }`. On board open
//! only the current user's bucket is loaded; views that enumerate the full
//! member list (Members, Manage) load the remaining buckets lazily on demand.

use dioxus::prelude::*;
use ed25519_dalek::VerifyingKey;
use freenet_stdlib::client_api::{ClientRequest, ContractRequest, ContractResponse};
use freenet_stdlib::prelude::{
    ContractCode, ContractContainer, ContractInstanceId, ContractKey, ContractWasmAPIVersion,
    Parameters, UpdateData, WrappedContract, WrappedState,
};
use plaza_core::board_state::member::{AuthorizedMember, MemberId, MembersV1};
use plaza_core::board_state::member_shards::{
    member_shard_bucket, merge_into_members, MemberShardDeltaV1, MemberShardEntryV1,
    MemberShardParametersV1, MemberShardStateV1, MEMBER_SHARD_COUNT,
};
use plaza_core::board_state::{ChatBoardParametersV1, ChatBoardStateV1};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::components::app::send_client_request;
use crate::constants::MEMBER_CONTRACT_WASM;
use crate::util::to_cbor_vec;

#[derive(Clone)]
pub struct MemberShardBoard {
    pub params: MemberShardParametersV1,
    pub state: MemberShardStateV1,
    pub synced: bool,
    /// A local member record has not been confirmed by the node yet.
    pub dirty: bool,
}

pub static MEMBER_SHARDS: GlobalSignal<HashMap<ContractInstanceId, MemberShardBoard>> =
    Global::new(HashMap::new);

static LOADED_ALL_BOARDS: std::sync::Mutex<Option<HashSet<VerifyingKey>>> =
    std::sync::Mutex::new(None);

pub fn member_shard_key(owner: VerifyingKey, bucket: u16) -> ContractKey {
    let params = MemberShardParametersV1 { owner, bucket };
    let parameters = Parameters::from(to_cbor_vec(&params));
    let code = ContractCode::from(MEMBER_CONTRACT_WASM);
    ContractKey::from_params_and_code(parameters, &code)
}

fn member_shard_contract(owner: VerifyingKey, bucket: u16) -> ContractContainer {
    let params = MemberShardParametersV1 { owner, bucket };
    ContractContainer::from(ContractWasmAPIVersion::V1(WrappedContract::new(
        Arc::new(ContractCode::from(MEMBER_CONTRACT_WASM)),
        Parameters::from(to_cbor_vec(&params)),
    )))
}

pub fn is_known_member_contract(key: &ContractInstanceId) -> bool {
    MEMBER_SHARDS.read().contains_key(key)
}

pub fn is_member_contract_response(response: &ContractResponse) -> bool {
    match response {
        ContractResponse::GetResponse { key, .. }
        | ContractResponse::PutResponse { key }
        | ContractResponse::UpdateResponse { key, .. }
        | ContractResponse::UpdateNotification { key, .. }
        | ContractResponse::SubscribeResponse { key, .. } => {
            is_known_member_contract(key.id())
        }
        _ => false,
    }
}

pub async fn load_member_shard(owner: VerifyingKey, bucket: u16) -> Result<(), String> {
    if bucket >= MEMBER_SHARD_COUNT {
        return Err(format!("member shard bucket {bucket} out of range"));
    }
    let key = member_shard_key(owner, bucket);
    let contract_id = *key.id();
    // Request each bucket at most once per session. Read-only loads never PUT
    // an empty shard contract; only `record_member` creates a shard on demand.
    if MEMBER_SHARDS.read().contains_key(&contract_id) {
        return Ok(());
    }
    let params = MemberShardParametersV1 { owner, bucket };
    MEMBER_SHARDS.with_mut(|shards| {
        shards.entry(contract_id).or_insert(MemberShardBoard {
            params,
            state: MemberShardStateV1::default(),
            synced: false,
            dirty: false,
        });
    });
    send_client_request(ClientRequest::ContractOp(ContractRequest::Get {
        key: contract_id,
        return_contract_code: false,
        subscribe: true,
        blocking_subscribe: false,
    }))
    .await
    .map_err(|error| format!("get member shard {bucket}: {error}"))
}

/// Load only the buckets that contain the given member ids.
#[allow(dead_code)]
pub async fn load_member_shards_for(
    owner: VerifyingKey,
    ids: impl IntoIterator<Item = MemberId>,
) {
    let buckets: HashSet<u16> = ids
        .into_iter()
        .map(|id| member_shard_bucket(&id))
        .collect();
    for bucket in buckets {
        let _ = load_member_shard(owner, bucket).await;
    }
}

/// Lazily load all buckets of a board once per session (GET-only, no PUT of
/// empty contracts), used by views that display or select from the full member
/// directory.
pub async fn load_all_member_shards(owner: VerifyingKey) {
    {
        let mut guard = LOADED_ALL_BOARDS.lock().unwrap();
        let set = guard.get_or_insert_with(HashSet::new);
        if !set.insert(owner) {
            return;
        }
    }
    for bucket in 0..MEMBER_SHARD_COUNT {
        let _ = load_member_shard(owner, bucket).await;
    }
}

pub async fn handle_contract_response(response: ContractResponse) -> Result<(), String> {
    match response {
        ContractResponse::GetResponse { key, state, .. } => {
            let params = MEMBER_SHARDS
                .read()
                .get(key.id())
                .map(|board| board.params.clone())
                .ok_or_else(|| "unknown member shard key".to_string())?;
            let network = if state.as_ref().is_empty() {
                MemberShardStateV1::default()
            } else {
                ciborium::de::from_reader::<MemberShardStateV1, _>(state.as_ref())
                    .map_err(|error| format!("decode member shard state: {error}"))?
            };
            network
                .verify(&params)
                .map_err(|error| format!("member shard state does not verify: {error}"))?;
            MEMBER_SHARDS.with_mut(|shards| {
                if let Some(board) = shards.get_mut(key.id()) {
                    board.state = if board.dirty {
                        let mut merged = board.state.clone();
                        let delta = MemberShardDeltaV1 {
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
            MEMBER_SHARDS.with_mut(|shards| {
                if let Some(board) = shards.get_mut(key.id()) {
                    board.synced = true;
                    board.dirty = false;
                }
            });
        }
        ContractResponse::UpdateNotification { key, update } => {
            let (params, mut state) = MEMBER_SHARDS
                .read()
                .get(key.id())
                .map(|board| (board.params.clone(), board.state.clone()))
                .ok_or_else(|| "unknown member shard key".to_string())?;
            match update {
                UpdateData::State(bytes) => {
                    if !bytes.as_ref().is_empty() {
                        let network =
                            ciborium::de::from_reader::<MemberShardStateV1, _>(bytes.as_ref())
                                .map_err(|error| format!("decode member shard update: {error}"))?;
                        let delta = MemberShardDeltaV1 {
                            entries: network.entries,
                        };
                        state
                            .apply_delta(&params, &delta)
                            .map_err(|error| format!("apply member shard state: {error}"))?;
                    }
                }
                UpdateData::Delta(bytes) => {
                    if !bytes.as_ref().is_empty() {
                        let delta =
                            ciborium::de::from_reader::<MemberShardDeltaV1, _>(bytes.as_ref())
                                .map_err(|error| format!("decode member shard delta: {error}"))?;
                        state
                            .apply_delta(&params, &delta)
                            .map_err(|error| format!("apply member shard delta: {error}"))?;
                    }
                }
                _ => {}
            }
            MEMBER_SHARDS.with_mut(|shards| {
                if let Some(board) = shards.get_mut(key.id()) {
                    board.state = state;
                    board.synced = true;
                }
            });
        }
        _ => {}
    }
    Ok(())
}

/// Overlay verified entries from all loaded member shards of `owner` onto
/// `target`.
pub fn apply_to_members(
    owner: VerifyingKey,
    board: &ChatBoardStateV1,
    target: &mut MembersV1,
) {
    let entries: Vec<MemberShardEntryV1> = {
        let shards = MEMBER_SHARDS.read();
        shards
            .values()
            .filter(|shard| shard.params.owner == owner)
            .flat_map(|shard| shard.state.entries.iter().cloned())
            .collect()
    };
    if entries.is_empty() {
        return;
    }
    let params = ChatBoardParametersV1 { owner };
    merge_into_members(&entries, board, &params, target);
}

/// Find a specific member entry (with its invite chain and invite token) in
/// the loaded shard for `member_id`.
pub fn find_member_entry(
    owner: VerifyingKey,
    member_id: MemberId,
) -> Option<MemberShardEntryV1> {
    let bucket = member_shard_bucket(&member_id);
    let key = member_shard_key(owner, bucket);
    MEMBER_SHARDS
        .read()
        .get(key.id())
        .and_then(|shard| {
            shard
                .state
                .entries
                .iter()
                .find(|entry| entry.member_id() == member_id)
                .cloned()
        })
}

/// Build the list of `AuthorizedMember` records (target plus any missing
/// invite-chain ancestors) needed to materialize a shard-only member on the
/// parent board (e.g. before promoting them to admin or assigning a role).
pub fn records_for_parent_board(
    owner: VerifyingKey,
    board: &ChatBoardStateV1,
    member_id: MemberId,
) -> Vec<AuthorizedMember> {
    let already_present: HashSet<MemberId> = board
        .members
        .members
        .iter()
        .map(|member| member.member.id())
        .collect();
    if already_present.contains(&member_id) {
        return Vec::new();
    }
    let Some(entry) = find_member_entry(owner, member_id) else {
        return Vec::new();
    };
    let mut records = Vec::new();
    for ancestor in entry.invite_chain {
        if !already_present.contains(&ancestor.member.id()) {
            records.push(ancestor);
        }
    }
    records.push(entry.member);
    records
}

/// Publish one member entry into its deterministic shard contract.
pub async fn record_member(owner: VerifyingKey, entry: MemberShardEntryV1) -> Result<(), String> {
    let bucket = member_shard_bucket(&entry.member_id());
    let params = MemberShardParametersV1 { owner, bucket };
    entry.verify(&params)?;
    let key = member_shard_key(owner, bucket);
    let contract_id = *key.id();
    let delta = MemberShardDeltaV1 {
        entries: vec![entry],
    };
    MEMBER_SHARDS.with_mut(|shards| {
        let board = shards.entry(contract_id).or_insert(MemberShardBoard {
            params: params.clone(),
            state: MemberShardStateV1::default(),
            synced: false,
            dirty: true,
        });
        let _ = board.state.apply_delta(&params, &delta);
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
    let state = MEMBER_SHARDS
        .read()
        .get(&contract_id)
        .map(|board| board.state.clone())
        .unwrap_or_default();
    send_client_request(ClientRequest::ContractOp(ContractRequest::Put {
        contract: member_shard_contract(owner, bucket),
        state: WrappedState::new(to_cbor_vec(&state)),
        related_contracts: Default::default(),
        subscribe: true,
        blocking_subscribe: false,
    }))
    .await
    .map_err(|error| {
        format!(
            "send member shard delta failed ({}), put failed: {error}",
            update.err().map(|error| error.to_string()).unwrap_or_default()
        )
    })
}
