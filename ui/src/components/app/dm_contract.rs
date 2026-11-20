//! Client for the `plaza-dm` contract.
//!
//! Creates a conversation contract from the active DM identity/device, keeps a
//! local map of conversation states, sends deltas and routes contract
//! responses. The Messages UI is built on top of this module.

use crate::components::app::{dm_delegate, WEB_API};
use crate::constants::DM_CONTRACT_WASM;
use crate::util::to_cbor_vec;
use dioxus::prelude::*;
use freenet_stdlib::client_api::{ClientRequest, ContractRequest, ContractResponse};
use freenet_stdlib::prelude::{
    ContractCode, ContractContainer, ContractInstanceId, ContractKey, ContractWasmAPIVersion,
    Parameters, UpdateData, WrappedContract, WrappedState,
};
use plaza_dm_core::delegate::{DmDelegateRequestMsg, DmDelegateResponseMsg};
use plaza_dm_core::{
    decode_state, encode, DmParamsV1, DmStateDeltaV1, DmStateV1, PROTOCOL_VERSION,
};
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashMap;
use std::sync::Arc;

pub const DM_PROTOCOL_VERSION: u16 = PROTOCOL_VERSION;

#[derive(Clone)]
pub struct DmConversation {
    pub key: ContractKey,
    pub params: DmParamsV1,
    pub state: DmStateV1,
    pub synced: bool,
}

pub static DM_CONVERSATIONS: GlobalSignal<HashMap<ContractInstanceId, DmConversation>> =
    Global::new(HashMap::new);

pub fn contract_key_for(params: &DmParamsV1) -> ContractKey {
    let parameters = Parameters::from(to_cbor_vec(params));
    let code = ContractCode::from(DM_CONTRACT_WASM);
    ContractKey::from_params_and_code(parameters, &code)
}

pub fn is_known_conversation(key: &ContractInstanceId) -> bool {
    DM_CONVERSATIONS.read().contains_key(key)
}

/// Create a 1:1 conversation contract owned by the active DM identity.
pub async fn create_conversation() -> Result<ContractInstanceId, String> {
    dm_delegate::ensure_identity_and_device().await?;
    let identity = dm_delegate::identity_id_for_active_profile()
        .ok_or_else(|| "no active profile for the DM identity".to_string())?;
    let devices = dm_delegate::list_devices(identity).await?;
    let device = devices
        .into_iter()
        .find(|device| device.revoked_at.is_none())
        .ok_or_else(|| "the DM identity has no active device".to_string())?;

    let mut conversation_id = [0u8; 32];
    let mut contract_secret = [0u8; 32];
    let mut conversation_key = [0u8; 32];
    OsRng.fill_bytes(&mut conversation_id);
    OsRng.fill_bytes(&mut contract_secret);
    OsRng.fill_bytes(&mut conversation_key);
    let created_at = chrono::Utc::now().timestamp_millis();

    let state = match dm_delegate::send_request(DmDelegateRequestMsg::CreateConversation {
        identity,
        device_id: device.device_id,
        conversation_id,
        created_at,
    })
    .await?
    {
        DmDelegateResponseMsg::StateCreated { state } => state,
        DmDelegateResponseMsg::Error { message } => return Err(message),
        other => return Err(format!("unexpected CreateConversation response: {other:?}")),
    };
    if let Err(error) = state.verify(&DmParamsV1 {
        protocol_version: DM_PROTOCOL_VERSION,
        contract_secret,
    }) {
        return Err(format!("creator state does not verify: {error}"));
    }

    let params = DmParamsV1 {
        protocol_version: DM_PROTOCOL_VERSION,
        contract_secret,
    };
    let contract_key = contract_key_for(&params);
    let contract_id = *contract_key.id();
    let key_bytes: [u8; 32] = contract_id
        .as_bytes()
        .try_into()
        .map_err(|_| "contract instance id is not 32 bytes".to_string())?;

    match dm_delegate::send_request(DmDelegateRequestMsg::StoreConversationKey {
        identity,
        contract_key: key_bytes,
        conversation_id,
        key_version: 0,
        key: conversation_key,
        peer: [0u8; 32],
        title: None,
        generation: 0,
        created_at,
    })
    .await?
    {
        DmDelegateResponseMsg::Ok => {}
        DmDelegateResponseMsg::Error { message } => return Err(message),
        other => return Err(format!("unexpected StoreConversationKey response: {other:?}")),
    }

    DM_CONVERSATIONS.with_mut(|conversations| {
        conversations.insert(
            contract_id,
            DmConversation {
                key: contract_key,
                params: params.clone(),
                state: state.clone(),
                synced: false,
            },
        );
    });

    let parameters = Parameters::from(to_cbor_vec(&params));
    let contract = ContractContainer::from(ContractWasmAPIVersion::V1(WrappedContract::new(
        Arc::new(ContractCode::from(DM_CONTRACT_WASM)),
        parameters,
    )));
    let request = ContractRequest::Put {
        contract,
        state: WrappedState::new(to_cbor_vec(&state)),
        related_contracts: Default::default(),
        subscribe: true,
        blocking_subscribe: false,
    };
    if let Err(error) = send_contract_request(request).await {
        DM_CONVERSATIONS.with_mut(|conversations| conversations.remove(&contract_id));
        return Err(error);
    }
    info!("Created DM conversation {contract_id}");
    Ok(contract_id)
}

/// Fetch the latest state for a conversation already present in the map.
pub async fn fetch_conversation(contract_id: ContractInstanceId) -> Result<(), String> {
    let key = DM_CONVERSATIONS
        .read()
        .get(&contract_id)
        .map(|conversation| conversation.key)
        .ok_or_else(|| "unknown DM conversation".to_string())?;
    send_contract_request(ContractRequest::Get {
        key: *key.id(),
        return_contract_code: false,
        subscribe: false,
        blocking_subscribe: false,
    })
    .await
}

pub async fn subscribe_conversation(contract_id: ContractInstanceId) -> Result<(), String> {
    let key = DM_CONVERSATIONS
        .read()
        .get(&contract_id)
        .map(|conversation| conversation.key)
        .ok_or_else(|| "unknown DM conversation".to_string())?;
    send_contract_request(ContractRequest::Subscribe {
        key: *key.id(),
        summary: None,
    })
    .await
}

/// Apply a delta locally and publish it to the conversation contract.
pub async fn publish_delta(
    contract_id: ContractInstanceId,
    delta: DmStateDeltaV1,
) -> Result<(), String> {
    let (key, params, next_state, bytes) = {
        let conversations = DM_CONVERSATIONS.read();
        let conversation = conversations
            .get(&contract_id)
            .ok_or_else(|| "unknown DM conversation".to_string())?;
        let mut next_state = conversation.state.clone();
        next_state
            .apply_delta(&conversation.params, &delta)
            .map_err(|error| format!("apply DM delta: {error}"))?;
        let bytes = encode(&delta).map_err(|error| format!("encode DM delta: {error}"))?;
        (
            conversation.key,
            conversation.params.clone(),
            next_state,
            bytes,
        )
    };

    DM_CONVERSATIONS.with_mut(|conversations| {
        if let Some(conversation) = conversations.get_mut(&contract_id) {
            conversation.state = next_state.clone();
            conversation.synced = false;
        }
    });

    send_contract_request(ContractRequest::Update {
        key,
        data: UpdateData::Delta(bytes.into()),
    })
    .await
    .map_err(|error| {
        let _ = &params;
        error
    })
}

fn is_dm_key(key: &ContractKey) -> bool {
    DM_CONVERSATIONS.read().contains_key(key.id())
}

pub fn is_dm_contract_response(response: &ContractResponse) -> bool {
    match response {
        ContractResponse::GetResponse { key, .. }
        | ContractResponse::PutResponse { key }
        | ContractResponse::UpdateResponse { key, .. }
        | ContractResponse::UpdateNotification { key, .. }
        | ContractResponse::SubscribeResponse { key, .. } => is_dm_key(key),
        _ => false,
    }
}

/// Route a contract response that belongs to a DM conversation.
pub async fn handle_contract_response(response: ContractResponse) -> Result<(), String> {
    match response {
        ContractResponse::GetResponse { key, state, .. } => {
            if !is_dm_key(&key) {
                return Ok(());
            }
            let state = decode_state(state.as_ref())
                .map_err(|error| format!("decode DM state: {error}"))?;
            DM_CONVERSATIONS.with_mut(|conversations| {
                if let Some(conversation) = conversations.get_mut(key.id()) {
                    conversation.state = state;
                    conversation.synced = true;
                }
            });
        }
        ContractResponse::PutResponse { key } => {
            mark_synced(&key);
        }
        ContractResponse::UpdateResponse { key, .. } => {
            mark_synced(&key);
        }
        ContractResponse::UpdateNotification { key, .. } => {
            if is_dm_key(&key) {
                fetch_conversation(*key.id()).await?;
            }
        }
        ContractResponse::SubscribeResponse { key, subscribed } => {
            if subscribed && is_dm_key(&key) {
                fetch_conversation(*key.id()).await?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn mark_synced(key: &ContractKey) {
    DM_CONVERSATIONS.with_mut(|conversations| {
        if let Some(conversation) = conversations.get_mut(key.id()) {
            conversation.synced = true;
        }
    });
}

async fn send_contract_request(request: ContractRequest<'static>) -> Result<(), String> {
    let client_request = ClientRequest::ContractOp(request);
    let mut web_api = WEB_API.write();
    let Some(api) = web_api.as_mut() else {
        return Err("Freenet API is not available".to_string());
    };
    api.send(client_request)
        .await
        .map_err(|error| format!("send DM contract request: {error}"))
}

pub fn conversations() -> Vec<(ContractInstanceId, DmConversation)> {
    let mut values: Vec<_> = DM_CONVERSATIONS
        .read()
        .iter()
        .map(|(id, conversation)| (*id, conversation.clone()))
        .collect();
    values.sort_by_key(|(_, conversation)| {
        std::cmp::Reverse(conversation.state.meta.created_at)
    });
    values
}
