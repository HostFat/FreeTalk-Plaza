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
use plaza_core::board_state::admin::AuthorizedAdmin;
use plaza_core::board_state::member::{AuthorizedMember, MemberId, MembersV1};
use plaza_core::board_state::member_shards::{
    member_shard_bucket, merge_into_members, MemberProofV1, MemberShardDeltaV1, MemberShardEntryV1,
    MemberShardParametersV1, MemberShardStateV1, MEMBER_SHARD_COUNT,
};
use plaza_core::board_state::ownership::AuthorizedOwnerTransfer;
use plaza_core::board_state::{ChatBoardParametersV1, ChatBoardStateV1};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::components::app::send_client_request;
use crate::constants::MEMBER_CONTRACT_WASM;
use crate::util::to_cbor_vec;

/// Cooldown before retrying a GET for an unsynced (previously missing) shard.
const UNSYNCED_RETRY_COOLDOWN_MS: i64 = 10_000;
/// Maximum member shard buckets kept in RAM across all boards (LRU evicted).
const MAX_CACHED_MEMBER_SHARDS: usize = 32;

fn now_ms() -> i64 {
    plaza_core::board_state::rate_limit::system_time_ms(crate::util::get_current_system_time())
}

fn evict_member_shards(protect: ContractInstanceId) {
    let mut evicted = Vec::new();
    MEMBER_SHARDS.with_mut(|shards| {
        while shards.len() > MAX_CACHED_MEMBER_SHARDS {
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
        crate::components::app::notify_contract_evicted("member_shard", id);
    }
}

#[derive(Clone)]
pub struct MemberShardBoard {
    pub params: MemberShardParametersV1,
    pub state: MemberShardStateV1,
    pub synced: bool,
    /// A local member record has not been confirmed by the node yet.
    pub dirty: bool,
    pub last_fetch: i64,
}

pub static MEMBER_SHARDS: GlobalSignal<HashMap<ContractInstanceId, MemberShardBoard>> =
    Global::new(HashMap::new);

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
    let now = now_ms();
    // Read-only loads never PUT an empty shard contract; only `record_member`
    // creates a shard on demand. Skip buckets that are already synced or were
    // requested recently, while allowing unsynced (initially empty) buckets to
    // be retried after the cooldown.
    let should_skip = MEMBER_SHARDS.read().get(&contract_id).is_some_and(|board| {
        board.synced || now.saturating_sub(board.last_fetch) < UNSYNCED_RETRY_COOLDOWN_MS
    });
    if should_skip {
        return Ok(());
    }
    let params = MemberShardParametersV1 { owner, bucket };
    MEMBER_SHARDS.with_mut(|shards| {
        let entry = shards.entry(contract_id).or_insert(MemberShardBoard {
            params,
            state: MemberShardStateV1::default(),
            synced: false,
            dirty: false,
            last_fetch: now,
        });
        entry.last_fetch = now;
    });
    evict_member_shards(contract_id);
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

/// Lazily load all buckets of a board (GET-only, no PUT of empty contracts),
/// used by views that display or select from the full member directory. Already
/// synced buckets and recently requested unsynced buckets are skipped by
/// `load_member_shard`.
pub async fn load_all_member_shards(owner: VerifyingKey) {
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
                UpdateData::StateAndDelta {
                    state: state_bytes,
                    delta: delta_bytes,
                } => {
                    if !delta_bytes.as_ref().is_empty() {
                        let delta = ciborium::de::from_reader::<MemberShardDeltaV1, _>(
                            delta_bytes.as_ref(),
                        )
                        .map_err(|error| format!("decode member shard delta: {error}"))?;
                        state
                            .apply_delta(&params, &delta)
                            .map_err(|error| format!("apply member shard delta: {error}"))?;
                    } else if !state_bytes.as_ref().is_empty() {
                        let network = ciborium::de::from_reader::<MemberShardStateV1, _>(
                            state_bytes.as_ref(),
                        )
                        .map_err(|error| format!("decode member shard update: {error}"))?;
                        let delta = MemberShardDeltaV1 {
                            entries: network.entries,
                        };
                        state
                            .apply_delta(&params, &delta)
                            .map_err(|error| format!("apply member shard state: {error}"))?;
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

/// Collect the board's ownership transfer chain plus any admin records needed
/// to verify admin-quorum succession transfers inside standalone contracts.
pub fn ownership_proof_for(
    board: &crate::board_data::BoardData,
) -> (Vec<AuthorizedOwnerTransfer>, Vec<AuthorizedAdmin>) {
    let transfers = board.board_state.ownership.transfers.clone();
    if transfers.is_empty() {
        return (Vec::new(), Vec::new());
    }
    let has_succession = transfers
        .iter()
        .any(|transfer| !transfer.succession_approvals.is_empty());
    let transfer_admins = if has_succession {
        board.board_state.admin.admins.clone()
    } else {
        Vec::new()
    };
    (transfers, transfer_admins)
}

/// Build a self-verifying `MemberShardEntryV1` from `board` for `member`,
/// including invite chain, invite token, and any ownership transfer proof.
pub fn build_member_shard_entry(
    board: &crate::board_data::BoardData,
    member: AuthorizedMember,
) -> MemberShardEntryV1 {
    let (ownership_transfers, transfer_admins) = ownership_proof_for(board);
    let invite_token = member.member.join_proof.as_ref().and_then(|proof| {
        board
            .board_state
            .invites
            .tokens
            .iter()
            .find(|token| token.token.id == proof.token_id)
            .cloned()
    });
    let invite_chain = if member.member.join_proof.is_some() {
        Vec::new()
    } else if board
        .self_authorized_member
        .as_ref()
        .is_some_and(|self_m| self_m.member.id() == member.member.id())
        && !board.invite_chain.is_empty()
    {
        board.invite_chain.clone()
    } else {
        board
            .board_state
            .members
            .get_invite_chain(&member, &ChatBoardParametersV1 { owner: board.owner_vk })
            .unwrap_or_default()
    };
    MemberShardEntryV1 {
        member,
        invite_chain,
        invite_token,
        ownership_transfers,
        transfer_admins,
    }
}

/// Build a standalone `MemberProofV1` for `signer_vk` on board `owner`.
/// Returns `None` for the founding board owner (who needs no proof).
pub fn build_member_proof(owner: VerifyingKey, signer_vk: VerifyingKey) -> Option<MemberProofV1> {
    if signer_vk == owner {
        return None;
    }
    let signer_id = MemberId::from(&signer_vk);
    let board = crate::components::app::BOARDS
        .read()
        .map
        .get(&owner)
        .cloned()?;
    let (ownership_transfers, transfer_admins) = ownership_proof_for(&board);
    if ownership_transfers
        .iter()
        .any(|transfer| transfer.transfer.to_key == signer_vk)
    {
        return Some(MemberProofV1 {
            ownership_transfers,
            transfer_admins,
            membership: None,
        });
    }
    let entry = find_member_entry(owner, signer_id)
        .map(|mut existing| {
            if existing.ownership_transfers.is_empty() && !ownership_transfers.is_empty() {
                existing.ownership_transfers = ownership_transfers.clone();
                existing.transfer_admins = transfer_admins.clone();
            }
            existing
        })
        .or_else(|| {
            board
                .self_authorized_member
                .as_ref()
                .filter(|member| member.member.member_vk == signer_vk)
                .cloned()
                .map(|member| build_member_shard_entry(&board, member))
        })
        .or_else(|| {
            board
                .board_state
                .members
                .members
                .iter()
                .find(|member| member.member.member_vk == signer_vk)
                .cloned()
                .map(|member| build_member_shard_entry(&board, member))
        })?;
    Some(MemberProofV1 {
        ownership_transfers,
        transfer_admins,
        membership: Some(Box::new(entry)),
    })
}

/// Whether `member_id` is already present in its local member shard and
/// confirmed by the node.
pub fn is_member_synced_in_shard(owner: VerifyingKey, member_id: MemberId) -> bool {
    let bucket = member_shard_bucket(&member_id);
    let key = member_shard_key(owner, bucket);
    MEMBER_SHARDS.read().get(key.id()).is_some_and(|shard| {
        shard.synced
            && !shard.dirty
            && shard
                .state
                .entries
                .iter()
                .any(|entry| entry.member_id() == member_id)
    })
}

/// Publish one member entry into its deterministic shard contract.
pub async fn record_member(owner: VerifyingKey, entry: MemberShardEntryV1) -> Result<(), String> {
    let bucket = member_shard_bucket(&entry.member_id());
    let params = MemberShardParametersV1 { owner, bucket };
    entry.verify(&params)?;
    let key = member_shard_key(owner, bucket);
    let contract_id = *key.id();
    let already_synced = MEMBER_SHARDS
        .read()
        .get(&contract_id)
        .map(|board| board.synced)
        .unwrap_or(false);
    let delta = MemberShardDeltaV1 {
        entries: vec![entry],
    };
    let now = now_ms();
    let mut apply_err: Option<String> = None;
    MEMBER_SHARDS.with_mut(|shards| {
        let board = shards.entry(contract_id).or_insert(MemberShardBoard {
            params: params.clone(),
            state: MemberShardStateV1::default(),
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
        return Err(format!("apply member shard delta failed: {error}"));
    }
    if already_synced {
        send_client_request(ClientRequest::ContractOp(ContractRequest::Update {
            key,
            data: UpdateData::Delta(to_cbor_vec(&delta).into()),
        }))
        .await
        .map_err(|error| format!("send member shard delta failed: {error}"))
    } else {
        // The shard contract has not been confirmed on the node yet (`load_*`
        // is GET-only and never PUTs empty buckets). PUT creates the contract
        // on first write and is merged additively if another peer already
        // created it.
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
        .map_err(|error| format!("put member shard failed: {error}"))
    }
}
