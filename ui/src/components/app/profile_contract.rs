//! Per-board profile feed.
//!
//! Nicknames used to live in the board state: every join or rename rewrote the
//! board, and a board with thousands of members carried MiB of profile
//! records. The client sends a small delta to this contract instead and
//! overlays the verified nickname on the board for display.

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
    merge_into, ProfileDeltaV1, ProfileEntryV1, ProfileStateV1,
};
use plaza_core::board_state::{ChatBoardParametersV1, ChatBoardStateV1};
use std::collections::HashMap;
use std::sync::Arc;

use crate::components::app::send_client_request;
use crate::constants::PROFILE_CONTRACT_WASM;
use crate::util::to_cbor_vec;

#[derive(Clone)]
pub struct ProfileBoard {
    pub state: ProfileStateV1,
    pub synced: bool,
    /// A local nickname has not been confirmed by the node yet.
    pub dirty: bool,
}

pub static PROFILE_BOARDS: GlobalSignal<HashMap<ContractInstanceId, ProfileBoard>> =
    Global::new(HashMap::new);

pub fn profile_key(owner: VerifyingKey) -> ContractKey {
    let parameters = Parameters::from(to_cbor_vec(&ChatBoardParametersV1 { owner }));
    let code = ContractCode::from(PROFILE_CONTRACT_WASM);
    ContractKey::from_params_and_code(parameters, &code)
}

fn profile_contract(owner: VerifyingKey) -> ContractContainer {
    ContractContainer::from(ContractWasmAPIVersion::V1(WrappedContract::new(
        Arc::new(ContractCode::from(PROFILE_CONTRACT_WASM)),
        Parameters::from(to_cbor_vec(&ChatBoardParametersV1 { owner })),
    )))
}

pub fn is_known_profile_contract(key: &ContractInstanceId) -> bool {
    PROFILE_BOARDS.read().contains_key(key)
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

pub async fn load_profile(owner: VerifyingKey) -> Result<(), String> {
    let key = profile_key(owner);
    let contract_id = *key.id();
    let already_synced = PROFILE_BOARDS
        .read()
        .get(&contract_id)
        .map(|board| board.synced)
        .unwrap_or(false);
    if already_synced {
        return Ok(());
    }
    PROFILE_BOARDS.with_mut(|boards| {
        boards.entry(contract_id).or_insert(ProfileBoard {
            state: ProfileStateV1::default(),
            synced: false,
            dirty: false,
        });
    });
    let put = send_client_request(ClientRequest::ContractOp(ContractRequest::Put {
        contract: profile_contract(owner),
        state: WrappedState::new(to_cbor_vec(&ProfileStateV1::default())),
        related_contracts: Default::default(),
        subscribe: true,
        blocking_subscribe: false,
    }))
    .await;
    if let Err(error) = put {
        dioxus::logger::tracing::warn!(
            "profile contract put failed for {:?}: {error}",
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
    .map_err(|error| format!("get profile contract: {error}"))
}

pub async fn handle_contract_response(response: ContractResponse) -> Result<(), String> {
    match response {
        ContractResponse::GetResponse { key, state, .. } => {
            let network = if state.as_ref().is_empty() {
                ProfileStateV1::default()
            } else {
                ciborium::de::from_reader::<ProfileStateV1, _>(state.as_ref())
                    .map_err(|error| format!("decode profile state: {error}"))?
            };
            network
                .verify()
                .map_err(|error| format!("profile state does not verify: {error}"))?;
            PROFILE_BOARDS.with_mut(|boards| {
                if let Some(board) = boards.get_mut(key.id()) {
                    // A Get can still carry the state from before our delta.
                    // The feed is additive, so merging keeps the local entry.
                    board.state = if board.dirty {
                        let mut merged = board.state.clone();
                        let delta = ProfileDeltaV1 {
                            entries: network.entries.clone(),
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
            PROFILE_BOARDS.with_mut(|boards| {
                if let Some(board) = boards.get_mut(key.id()) {
                    board.synced = true;
                    board.dirty = false;
                }
            });
        }
        ContractResponse::UpdateNotification { key, update } => {
            let mut state = PROFILE_BOARDS
                .read()
                .get(key.id())
                .map(|board| board.state.clone())
                .unwrap_or_default();
            match update {
                UpdateData::State(bytes) => {
                    let network = ciborium::de::from_reader::<ProfileStateV1, _>(bytes.as_ref())
                        .map_err(|error| format!("decode profile update: {error}"))?;
                    let delta = ProfileDeltaV1 {
                        entries: network.entries,
                    };
                    state
                        .apply_delta(&delta)
                        .map_err(|error| format!("apply profile state: {error}"))?;
                }
                UpdateData::Delta(bytes) => {
                    let delta = ciborium::de::from_reader::<ProfileDeltaV1, _>(bytes.as_ref())
                        .map_err(|error| format!("decode profile delta: {error}"))?;
                    state
                        .apply_delta(&delta)
                        .map_err(|error| format!("apply profile delta: {error}"))?;
                }
                _ => {}
            }
            state
                .verify()
                .map_err(|error| format!("profile update does not verify: {error}"))?;
            PROFILE_BOARDS.with_mut(|boards| {
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

pub fn state_for(owner: VerifyingKey) -> Option<ProfileStateV1> {
    let key = profile_key(owner);
    PROFILE_BOARDS
        .read()
        .get(key.id())
        .map(|board| board.state.clone())
}

/// Overlay the verified profile feed on the board's legacy member-info list.
/// Only entries whose signature checks out against the board authority and
/// whose nickname fits the board configuration are shown.
pub fn apply_to_member_info(
    owner: VerifyingKey,
    state: &ChatBoardStateV1,
    legacy: &mut MemberInfoV1,
) {
    let Some(feed) = state_for(owner) else {
        return;
    };
    let parameters = ChatBoardParametersV1 { owner };
    let owner_id = parameters.owner_id();
    let max_nickname = state.configuration.configuration.max_nickname_size;
    let members: std::collections::HashSet<MemberId> = state
        .members
        .members
        .iter()
        .map(|member| member.member.id())
        .collect();
    let mut verified = Vec::new();
    for entry in feed.entries {
        let member_id = entry.member_id();
        if member_id != owner_id && !members.contains(&member_id) {
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

async fn send_delta(owner: VerifyingKey, delta: ProfileDeltaV1) -> Result<(), String> {
    let key = profile_key(owner);
    let contract_id = *key.id();
    PROFILE_BOARDS.with_mut(|boards| {
        let board = boards.entry(contract_id).or_insert(ProfileBoard {
            state: ProfileStateV1::default(),
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
    let state = PROFILE_BOARDS
        .read()
        .get(&contract_id)
        .map(|board| board.state.clone())
        .unwrap_or_default();
    send_client_request(ClientRequest::ContractOp(ContractRequest::Put {
        contract: profile_contract(owner),
        state: WrappedState::new(to_cbor_vec(&state)),
        related_contracts: Default::default(),
        subscribe: true,
        blocking_subscribe: false,
    }))
    .await
    .map_err(|error| {
        format!(
            "send profile delta failed ({}), put failed: {error}",
            update.err().map(|error| error.to_string()).unwrap_or_default()
        )
    })
}

pub async fn record_member_info(
    owner: VerifyingKey,
    info: AuthorizedMemberInfo,
    signer_key: VerifyingKey,
) -> Result<(), String> {
    send_delta(
        owner,
        ProfileDeltaV1 {
            entries: vec![ProfileEntryV1::from_authorized(info, signer_key)],
        },
    )
    .await
}
