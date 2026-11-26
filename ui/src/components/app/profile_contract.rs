//! Sharded per-board profile directory client.
//!
//! Nicknames live in `PROFILE_SHARD_COUNT` deterministic bucket contracts
//! addressed by `ProfileShardParametersV1 { owner, bucket }`, matching
//! `member_contract`. On board open only the current user's bucket is loaded
//! (`GET`-only); topic and list views load the buckets of visible authors on
//! demand, and directory views (Members, Manage) load all buckets lazily.

use dioxus::prelude::*;
use ed25519_dalek::VerifyingKey;
use freenet_stdlib::client_api::{ClientRequest, ContractRequest, ContractResponse};
use freenet_stdlib::prelude::{
    ContractCode, ContractContainer, ContractInstanceId, ContractKey, ContractWasmAPIVersion,
    Parameters, UpdateData, WrappedContract, WrappedState,
};
use plaza_core::board_state::member::MemberId;
use plaza_core::board_state::member_info::{AuthorizedMemberInfo, MemberInfoV1};
use plaza_core::board_state::profiles::{
    merge_into, profile_shard_bucket, ProfileDeltaV1, ProfileEntryV1, ProfileShardParametersV1,
    ProfileStateV1, PROFILE_SHARD_COUNT,
};
use plaza_core::board_state::{ChatBoardParametersV1, ChatBoardStateV1};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::components::app::send_client_request;
use crate::constants::PROFILE_CONTRACT_WASM;
use crate::util::to_cbor_vec;

/// Cooldown before retrying a GET for an unsynced (previously missing) shard.
const UNSYNCED_RETRY_COOLDOWN_MS: i64 = 10_000;
/// Maximum profile shard buckets kept in RAM across all boards (LRU evicted).
const MAX_CACHED_PROFILE_SHARDS: usize = 32;

fn now_ms() -> i64 {
    plaza_core::board_state::rate_limit::system_time_ms(crate::util::get_current_system_time())
}

fn evict_profile_shards(protect: ContractInstanceId) {
    let mut evicted = Vec::new();
    PROFILE_SHARDS.with_mut(|shards| {
        while shards.len() > MAX_CACHED_PROFILE_SHARDS {
            let victim = shards
                .iter()
                .filter(|(id, board)| **id != protect && !board.dirty)
                .min_by_key(|(_, board)| board.last_fetch)
                .map(|(id, _)| *id);
            match victim {
                Some(id) => {
                    shards.remove(&id);
                    evicted.push(id);
                }
                None => break,
            }
        }
    });
    for id in evicted {
        crate::components::app::notify_contract_evicted("profile_shard", id);
    }
}

#[derive(Clone)]
pub struct ProfileShardBoard {
    pub params: ProfileShardParametersV1,
    pub state: ProfileStateV1,
    pub synced: bool,
    /// A local nickname has not been confirmed by the node yet.
    pub dirty: bool,
    pub last_fetch: i64,
}

pub static PROFILE_SHARDS: GlobalSignal<HashMap<ContractInstanceId, ProfileShardBoard>> =
    Global::new(HashMap::new);

pub fn profile_shard_key(owner: VerifyingKey, bucket: u16) -> ContractKey {
    let params = ProfileShardParametersV1 { owner, bucket };
    let parameters = Parameters::from(to_cbor_vec(&params));
    let code = ContractCode::from(PROFILE_CONTRACT_WASM);
    ContractKey::from_params_and_code(parameters, &code)
}

fn profile_shard_contract(owner: VerifyingKey, bucket: u16) -> ContractContainer {
    let params = ProfileShardParametersV1 { owner, bucket };
    ContractContainer::from(ContractWasmAPIVersion::V1(WrappedContract::new(
        Arc::new(ContractCode::from(PROFILE_CONTRACT_WASM)),
        Parameters::from(to_cbor_vec(&params)),
    )))
}

pub fn is_known_profile_contract(key: &ContractInstanceId) -> bool {
    PROFILE_SHARDS.read().contains_key(key)
}

pub fn is_profile_contract_response(response: &ContractResponse) -> bool {
    match response {
        ContractResponse::GetResponse { key, .. }
        | ContractResponse::PutResponse { key }
        | ContractResponse::UpdateResponse { key, .. }
        | ContractResponse::UpdateNotification { key, .. }
        | ContractResponse::SubscribeResponse { key, .. } => {
            is_known_profile_contract(key.id())
        }
        _ => false,
    }
}

pub async fn load_profile_shard(owner: VerifyingKey, bucket: u16) -> Result<(), String> {
    if bucket >= PROFILE_SHARD_COUNT {
        return Err(format!("profile shard bucket {bucket} out of range"));
    }
    let key = profile_shard_key(owner, bucket);
    let contract_id = *key.id();
    let now = now_ms();
    // Read-only loads never PUT an empty shard contract; only
    // `record_member_info` creates a shard on demand. Skip buckets that are
    // already synced or were requested recently.
    let should_skip = PROFILE_SHARDS.read().get(&contract_id).is_some_and(|board| {
        board.synced || now.saturating_sub(board.last_fetch) < UNSYNCED_RETRY_COOLDOWN_MS
    });
    if should_skip {
        return Ok(());
    }
    let params = ProfileShardParametersV1 { owner, bucket };
    PROFILE_SHARDS.with_mut(|shards| {
        let entry = shards.entry(contract_id).or_insert(ProfileShardBoard {
            params,
            state: ProfileStateV1::default(),
            synced: false,
            dirty: false,
            last_fetch: now,
        });
        entry.last_fetch = now;
    });
    evict_profile_shards(contract_id);
    send_client_request(ClientRequest::ContractOp(ContractRequest::Get {
        key: contract_id,
        return_contract_code: false,
        subscribe: true,
        blocking_subscribe: false,
    }))
    .await
    .map_err(|error| format!("get profile shard {bucket}: {error}"))
}

/// Load only the profile buckets that contain the given member ids.
pub async fn load_profile_shards_for(
    owner: VerifyingKey,
    ids: impl IntoIterator<Item = MemberId>,
) {
    let buckets: HashSet<u16> = ids
        .into_iter()
        .map(|id| profile_shard_bucket(&id))
        .collect();
    for bucket in buckets {
        let _ = load_profile_shard(owner, bucket).await;
    }
}

/// Lazily load all profile buckets of a board (GET-only, no PUT of empty
/// contracts), used by views that enumerate the full member list. Synced and
/// recently attempted unsynced buckets are skipped by `load_profile_shard`.
pub async fn load_all_profile_shards(owner: VerifyingKey) {
    for bucket in 0..PROFILE_SHARD_COUNT {
        let _ = load_profile_shard(owner, bucket).await;
    }
}

pub async fn handle_contract_response(response: ContractResponse) -> Result<(), String> {
    match response {
        ContractResponse::GetResponse { key, state, .. } => {
            let params = PROFILE_SHARDS
                .read()
                .get(key.id())
                .map(|board| board.params.clone())
                .ok_or_else(|| "unknown profile shard key".to_string())?;
            let network = if state.as_ref().is_empty() {
                ProfileStateV1::default()
            } else {
                ciborium::de::from_reader::<ProfileStateV1, _>(state.as_ref())
                    .map_err(|error| format!("decode profile shard state: {error}"))?
            };
            network
                .verify(&params)
                .map_err(|error| format!("profile shard state does not verify: {error}"))?;
            PROFILE_SHARDS.with_mut(|shards| {
                if let Some(board) = shards.get_mut(key.id()) {
                    // A Get can still carry the state from before our delta.
                    // The shard is additive, so merging keeps the local entry.
                    board.state = if board.dirty {
                        let mut merged = board.state.clone();
                        let delta = ProfileDeltaV1 {
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
            PROFILE_SHARDS.with_mut(|shards| {
                if let Some(board) = shards.get_mut(key.id()) {
                    board.synced = true;
                    board.dirty = false;
                }
            });
        }
        ContractResponse::UpdateNotification { key, update } => {
            let (params, mut state) = PROFILE_SHARDS
                .read()
                .get(key.id())
                .map(|board| (board.params.clone(), board.state.clone()))
                .ok_or_else(|| "unknown profile shard key".to_string())?;
            match update {
                UpdateData::State(bytes) => {
                    if !bytes.as_ref().is_empty() {
                        let network =
                            ciborium::de::from_reader::<ProfileStateV1, _>(bytes.as_ref())
                                .map_err(|error| format!("decode profile shard update: {error}"))?;
                        let delta = ProfileDeltaV1 {
                            entries: network.entries,
                        };
                        state
                            .apply_delta(&params, &delta)
                            .map_err(|error| format!("apply profile shard state: {error}"))?;
                    }
                }
                UpdateData::Delta(bytes) => {
                    if !bytes.as_ref().is_empty() {
                        let delta =
                            ciborium::de::from_reader::<ProfileDeltaV1, _>(bytes.as_ref())
                                .map_err(|error| format!("decode profile shard delta: {error}"))?;
                        state
                            .apply_delta(&params, &delta)
                            .map_err(|error| format!("apply profile shard delta: {error}"))?;
                    }
                }
                UpdateData::StateAndDelta {
                    state: state_bytes,
                    delta: delta_bytes,
                } => {
                    if !delta_bytes.as_ref().is_empty() {
                        let delta =
                            ciborium::de::from_reader::<ProfileDeltaV1, _>(delta_bytes.as_ref())
                                .map_err(|error| format!("decode profile shard delta: {error}"))?;
                        state
                            .apply_delta(&params, &delta)
                            .map_err(|error| format!("apply profile shard delta: {error}"))?;
                    } else if !state_bytes.as_ref().is_empty() {
                        let network =
                            ciborium::de::from_reader::<ProfileStateV1, _>(state_bytes.as_ref())
                                .map_err(|error| format!("decode profile shard update: {error}"))?;
                        let delta = ProfileDeltaV1 {
                            entries: network.entries,
                        };
                        state
                            .apply_delta(&params, &delta)
                            .map_err(|error| format!("apply profile shard state: {error}"))?;
                    }
                }
                _ => {}
            }
            PROFILE_SHARDS.with_mut(|shards| {
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

/// Overlay verified entries from all loaded profile shards of `owner` onto
/// the board's legacy member-info list. Only entries belonging to current
/// board members (or the owner) and within `max_nickname_size` are shown.
pub fn apply_to_member_info(
    owner: VerifyingKey,
    state: &ChatBoardStateV1,
    legacy: &mut MemberInfoV1,
) {
    let entries: Vec<ProfileEntryV1> = {
        let shards = PROFILE_SHARDS.read();
        shards
            .values()
            .filter(|shard| shard.params.owner == owner)
            .flat_map(|shard| shard.state.entries.iter().cloned())
            .collect()
    };
    if entries.is_empty() {
        return;
    }
    let parameters = ChatBoardParametersV1 { owner };
    let owner_id = parameters.owner_id();
    let current_owner_id = state.ownership.current_owner(&parameters);
    let max_nickname = state.configuration.configuration.max_nickname_size;
    let members: HashSet<MemberId> = state
        .members
        .members
        .iter()
        .map(|member| member.member.id())
        .collect();
    let mut verified = Vec::new();
    for entry in entries {
        let member_id = entry.member_id();
        if member_id != owner_id
            && member_id != current_owner_id
            && !members.contains(&member_id)
            && crate::components::app::member_contract::find_member_entry(owner, member_id)
                .is_none()
        {
            continue;
        }
        if entry.info.preferred_nickname.declared_len() > max_nickname {
            continue;
        }
        // The contract already checked the signature and the key binding.
        verified.push(entry.authorized());
    }
    merge_into(&mut legacy.member_info, verified);
}

/// Publish one member's nickname into its deterministic profile shard contract.
pub async fn record_member_info(
    owner: VerifyingKey,
    info: AuthorizedMemberInfo,
    signer_key: VerifyingKey,
) -> Result<(), String> {
    let proof = crate::components::app::member_contract::build_member_proof(owner, signer_key);
    let entry = ProfileEntryV1::from_authorized(info, signer_key).with_optional_proof(proof);
    let bucket = profile_shard_bucket(&entry.member_id());
    let params = ProfileShardParametersV1 { owner, bucket };
    entry.verify(&params)?;
    let key = profile_shard_key(owner, bucket);
    let contract_id = *key.id();
    let already_synced = PROFILE_SHARDS
        .read()
        .get(&contract_id)
        .map(|board| board.synced)
        .unwrap_or(false);
    let delta = ProfileDeltaV1 {
        entries: vec![entry],
    };
    let now = now_ms();
    let mut apply_err: Option<String> = None;
    PROFILE_SHARDS.with_mut(|shards| {
        let board = shards.entry(contract_id).or_insert(ProfileShardBoard {
            params: params.clone(),
            state: ProfileStateV1::default(),
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
        return Err(format!("apply profile shard delta failed: {error}"));
    }
    if already_synced {
        send_client_request(ClientRequest::ContractOp(ContractRequest::Update {
            key,
            data: UpdateData::Delta(to_cbor_vec(&delta).into()),
        }))
        .await
        .map_err(|error| format!("send profile shard delta failed: {error}"))
    } else {
        // The shard contract has not been confirmed on the node yet (`load_*`
        // is GET-only and never PUTs empty buckets). PUT creates the contract
        // on first write and is merged additively by the contract if another
        // peer already created it.
        let state = PROFILE_SHARDS
            .read()
            .get(&contract_id)
            .map(|board| board.state.clone())
            .unwrap_or_default();
        send_client_request(ClientRequest::ContractOp(ContractRequest::Put {
            contract: profile_shard_contract(owner, bucket),
            state: WrappedState::new(to_cbor_vec(&state)),
            related_contracts: Default::default(),
            subscribe: true,
            blocking_subscribe: false,
        }))
        .await
        .map_err(|error| format!("put profile shard failed: {error}"))
    }
}
