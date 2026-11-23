//! Client for the `plaza-dm` contract.
//!
//! Creates a conversation contract from the active DM identity/device, keeps a
//! local map of conversation states, sends deltas and routes contract
//! responses. The Messages UI is built on top of this module.

use crate::components::app::dm_delegate;
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
    let identity = dm_delegate::active_identity_for_ops()
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
    crate::components::app::send_client_request(client_request)
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

pub struct DmJoinLink {
    pub contract_id: ContractInstanceId,
    pub token: [u8; 32],
    pub key_version: u32,
    pub key: [u8; 32],
}

pub fn parse_join_link(input: &str) -> Result<DmJoinLink, String> {
    let fragment = input.split('#').nth(1).unwrap_or(input);
    let parts: Vec<&str> = fragment
        .trim_start_matches('#')
        .trim_start_matches('/')
        .split('/')
        .collect();
    let parts = if parts.first() == Some(&"dm") {
        parts
    } else {
        return Err("This is not a FreeTalk Plaza DM link.".to_string());
    };
    if parts.len() != 6 || parts[1] != "join" {
        return Err("The DM invite link is incomplete.".to_string());
    }
    let contract_id = parts[2]
        .parse::<ContractInstanceId>()
        .map_err(|_| "The DM contract id is not valid.".to_string())?;
    let token_bytes = bs58::decode(parts[3])
        .into_vec()
        .map_err(|_| "The invite token is not valid.".to_string())?;
    let token: [u8; 32] = token_bytes
        .try_into()
        .map_err(|_| "The invite token is not valid.".to_string())?;
    let key_version = parts[4]
        .parse::<u32>()
        .map_err(|_| "The conversation key version is not valid.".to_string())?;
    let key_bytes = bs58::decode(parts[5])
        .into_vec()
        .map_err(|_| "The conversation key is not valid.".to_string())?;
    let key: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| "The conversation key is not valid.".to_string())?;
    Ok(DmJoinLink {
        contract_id,
        token,
        key_version,
        key,
    })
}

/// Create a signed single-use invite and return the join link.
pub async fn create_invite(contract_id: ContractInstanceId) -> Result<String, String> {
    let (contract_key, identity) = conversation_identity(contract_id)?;
    let key_bytes: [u8; 32] = contract_key
        .id()
        .as_bytes()
        .try_into()
        .map_err(|_| "contract instance id is not 32 bytes".to_string())?;
    let key_version = match dm_delegate::send_request(
        DmDelegateRequestMsg::GetLatestConversationKey {
            identity,
            contract_key: key_bytes,
        },
    )
    .await?
    {
        DmDelegateResponseMsg::ConversationKey {
            key_version: Some(version),
            ..
        } => version,
        DmDelegateResponseMsg::Error { message } => return Err(message),
        _ => return Err("conversation key is not available".to_string()),
    };
    let key = match dm_delegate::send_request(DmDelegateRequestMsg::GetConversationKey {
        identity,
        contract_key: key_bytes,
        key_version,
    })
    .await?
    {
        DmDelegateResponseMsg::ConversationKey { key: Some(key), .. } => key,
        DmDelegateResponseMsg::Error { message } => return Err(message),
        _ => return Err("conversation key is not available".to_string()),
    };

    let mut token = [0u8; 32];
    let mut invite_id = [0u8; 32];
    OsRng.fill_bytes(&mut token);
    OsRng.fill_bytes(&mut invite_id);
    let now = chrono::Utc::now().timestamp_millis();
    let invite = match dm_delegate::send_request(DmDelegateRequestMsg::CreateInvite {
        identity,
        invite_id,
        token,
        created_at: now,
        expires_at: now + 7 * 24 * 60 * 60 * 1000,
        bound_identity: None,
    })
    .await?
    {
        DmDelegateResponseMsg::InviteCreated { invite } => invite,
        DmDelegateResponseMsg::Error { message } => return Err(message),
        other => return Err(format!("unexpected CreateInvite response: {other:?}")),
    };

    publish_delta(
        contract_id,
        DmStateDeltaV1 {
            invites: Some(vec![invite]),
            ..Default::default()
        },
    )
    .await?;

    // Build the link from the outer shell URL, which carries the cache-busting
    // version query. The sandboxed iframe URL does not, and a link without it
    // can load an older cached build on the join page.
    let href = web_sys::window()
        .and_then(|window| window.top().ok().flatten())
        .and_then(|top| top.location().href().ok())
        .or_else(|| {
            web_sys::window().and_then(|window| window.location().href().ok())
        });
    let base = href
        .and_then(|href| href.split('#').next().map(str::to_string))
        .ok_or_else(|| "cannot build the invite link".to_string())?;
    let separator = if base.contains('?') { '&' } else { '?' };
    let base = format!("{base}{separator}nav={now}");
    let token_b58 = bs58::encode(token).into_string();
    let key_b58 = bs58::encode(key).into_string();
    Ok(format!(
        "{base}#/dm/join/{contract_id}/{token_b58}/{key_version}/{key_b58}"
    ))
}

fn conversation_identity(
    contract_id: ContractInstanceId,
) -> Result<(ContractKey, plaza_dm_core::DmIdentityId), String> {
    let key = DM_CONVERSATIONS
        .read()
        .get(&contract_id)
        .map(|conversation| conversation.key)
        .ok_or_else(|| "unknown DM conversation".to_string())?;
    let identity = dm_delegate::active_identity_for_ops()
        .ok_or_else(|| "no active profile for the DM identity".to_string())?;
    Ok((key, identity))
}

/// Register a conversation from a join link and fetch its state.
pub async fn join_conversation(
    contract_id: ContractInstanceId,
    identity: plaza_dm_core::DmIdentityId,
    key_version: u32,
    key: [u8; 32],
) -> Result<(), String> {
    let code = ContractCode::from(DM_CONTRACT_WASM);
    let contract_key = ContractKey::from_id_and_code(contract_id, *code.hash());
    let params = DmParamsV1 {
        protocol_version: DM_PROTOCOL_VERSION,
        contract_secret: [0u8; 32],
    };
    DM_CONVERSATIONS.with_mut(|conversations| {
        conversations.entry(contract_id).or_insert_with(|| DmConversation {
            key: contract_key,
            params: params.clone(),
            state: DmStateV1::default(),
            synced: false,
        });
    });

    let key_bytes: [u8; 32] = contract_id
        .as_bytes()
        .try_into()
        .map_err(|_| "contract instance id is not 32 bytes".to_string())?;
    match dm_delegate::send_request(DmDelegateRequestMsg::StoreConversationKey {
        identity,
        contract_key: key_bytes,
        conversation_id: [0u8; 32],
        key_version,
        key,
        peer: [0u8; 32],
        title: None,
        generation: 0,
        created_at: chrono::Utc::now().timestamp_millis(),
    })
    .await?
    {
        DmDelegateResponseMsg::Ok => {}
        DmDelegateResponseMsg::Error { message } => return Err(message),
        other => return Err(format!("unexpected StoreConversationKey response: {other:?}")),
    }
    fetch_conversation(contract_id).await
}

/// Verify the invite token in the fetched state and add the local member.
pub async fn accept_invite(
    contract_id: ContractInstanceId,
    identity: plaza_dm_core::DmIdentityId,
    token: [u8; 32],
) -> Result<(), String> {
    let state = DM_CONVERSATIONS
        .read()
        .get(&contract_id)
        .map(|conversation| conversation.state.clone())
        .ok_or_else(|| "unknown DM conversation".to_string())?;
    let expected = plaza_dm_core::token_hash(&token);
    if !state
        .invites
        .invites
        .iter()
        .any(|invite| invite.token_hash == expected && invite.used_at.is_none())
    {
        return Err("invite token is missing, expired or already used".to_string());
    }
    if state
        .members
        .members
        .iter()
        .any(|member| member.member.identity == identity)
    {
        dioxus::logger::tracing::info!(
            "DM join: identity {} is already a member",
            bs58::encode(identity).into_string()
        );
        return Ok(());
    }
    dioxus::logger::tracing::info!(
        "DM join: adding identity {}",
        bs58::encode(identity).into_string()
    );
    let devices = dm_delegate::list_devices(identity).await?;
    dioxus::logger::tracing::info!("DM join: {} local device(s)", devices.len());
    let device = devices
        .into_iter()
        .find(|device| device.revoked_at.is_none())
        .ok_or_else(|| "the DM identity has no active device".to_string())?;
    dioxus::logger::tracing::info!("DM join: creating the join member");
    let member = match dm_delegate::send_request(DmDelegateRequestMsg::CreateJoinMember {
        identity,
        device_id: device.device_id,
        conversation_id: state.meta.conversation_id,
        created_at: chrono::Utc::now().timestamp_millis(),
    })
    .await?
    {
        DmDelegateResponseMsg::JoinMemberCreated { member } => member,
        DmDelegateResponseMsg::Error { message } => return Err(message),
        other => return Err(format!("unexpected CreateJoinMember response: {other:?}")),
    };
    dioxus::logger::tracing::info!("DM join: publishing the member delta");
    publish_delta(
        contract_id,
        DmStateDeltaV1 {
            members: Some(vec![member]),
            ..Default::default()
        },
    )
    .await
}

/// Join from a link: register the key, fetch the state, verify the token and
/// add the local member.
pub async fn join_from_link(
    contract_id: ContractInstanceId,
    token: [u8; 32],
    key_version: u32,
    key: [u8; 32],
) -> Result<(), String> {
    dioxus::logger::tracing::info!("DM join: waiting for the active profile");
    // The join route can load before the boards and the active profile. The
    // delegate remembers the last initialized identity, so prefer it.
    let identity = dm_delegate::wait_for_active_identity()
        .await
        .or_else(dm_delegate::identity_id_for_active_profile)
        .ok_or_else(|| "no active DM identity on this device".to_string())?;
    *crate::components::app::dm_delegate::ACTIVE_IDENTITY_OVERRIDE.write() = Some(identity);
    dm_delegate::ensure_device_for_identity(identity).await?;
    dioxus::logger::tracing::info!("DM join: registering the conversation");
    join_conversation(contract_id, identity, key_version, key).await?;
    for _ in 0..120 {
        let loaded = DM_CONVERSATIONS
            .read()
            .get(&contract_id)
            .map(|conversation| !conversation.state.members.members.is_empty())
            .unwrap_or(false);
        if loaded {
            break;
        }
        crate::util::sleep(std::time::Duration::from_millis(250)).await;
    }
    dioxus::logger::tracing::info!("DM join: accepting the invite");
    let result = accept_invite(contract_id, identity, token).await;
    match &result {
        Ok(()) => dioxus::logger::tracing::info!("DM join: accepted"),
        Err(error) => dioxus::logger::tracing::error!("DM join failed: {error}"),
    }
    result
}

pub async fn send_message(
    contract_id: ContractInstanceId,
    text: String,
) -> Result<(), String> {
    let (contract_key, identity) = conversation_identity(contract_id)?;
    let key_bytes: [u8; 32] = contract_key
        .id()
        .as_bytes()
        .try_into()
        .map_err(|_| "contract instance id is not 32 bytes".to_string())?;
    let key_version = match dm_delegate::send_request(
        DmDelegateRequestMsg::GetLatestConversationKey {
            identity,
            contract_key: key_bytes,
        },
    )
    .await?
    {
        DmDelegateResponseMsg::ConversationKey {
            key_version: Some(version),
            ..
        } => version,
        DmDelegateResponseMsg::Error { message } => return Err(message),
        _ => return Err("conversation key is not available".to_string()),
    };
    let devices = dm_delegate::list_devices(identity).await?;
    let device = devices
        .into_iter()
        .find(|device| device.revoked_at.is_none())
        .ok_or_else(|| "the DM identity has no active device".to_string())?;
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let message = match dm_delegate::send_request(DmDelegateRequestMsg::EncryptMessage {
        identity,
        device_id: device.device_id,
        contract_key: key_bytes,
        key_version,
        plaintext: text.into_bytes(),
        content_type: plaza_dm_core::CONTENT_TYPE_TEXT,
        reply_to: None,
        created_at: chrono::Utc::now().timestamp_millis(),
        nonce,
    })
    .await?
    {
        DmDelegateResponseMsg::MessageCreated { message } => message,
        DmDelegateResponseMsg::Error { message } => return Err(message),
        other => return Err(format!("unexpected EncryptMessage response: {other:?}")),
    };
    publish_delta(
        contract_id,
        DmStateDeltaV1 {
            messages: Some(vec![message]),
            ..Default::default()
        },
    )
    .await
}

pub async fn decrypt_message(
    contract_id: ContractInstanceId,
    message: plaza_dm_core::AuthorizedDmMessage,
) -> Result<String, String> {
    let (contract_key, identity) = conversation_identity(contract_id)?;
    let key_bytes: [u8; 32] = contract_key
        .id()
        .as_bytes()
        .try_into()
        .map_err(|_| "contract instance id is not 32 bytes".to_string())?;
    let bytes = dm_delegate::decrypt_message(identity, key_bytes, message).await?;
    Ok(String::from_utf8_lossy(&bytes).to_string())
}

/// Rebuild the local conversation map from the delegate index after a reload
/// or a profile switch, then fetch each state.
pub async fn load_conversations() -> Result<(), String> {
    let identity = dm_delegate::active_identity_for_ops()
        .ok_or_else(|| "no active profile for the DM identity".to_string())?;
    let conversations = match dm_delegate::send_request(
        DmDelegateRequestMsg::ListConversations { identity },
    )
    .await?
    {
        DmDelegateResponseMsg::Conversations { conversations } => conversations,
        DmDelegateResponseMsg::Error { message } => return Err(message),
        other => return Err(format!("unexpected ListConversations response: {other:?}")),
    };
    let code = ContractCode::from(DM_CONTRACT_WASM);
    for conversation in &conversations {
        let key_version = match dm_delegate::send_request(
            DmDelegateRequestMsg::GetLatestConversationKey {
                identity,
                contract_key: conversation.contract_key,
            },
        )
        .await
        {
            Ok(DmDelegateResponseMsg::ConversationKey { key_version, .. }) => key_version,
            Ok(DmDelegateResponseMsg::Error { message }) => {
                dioxus::logger::tracing::warn!(
                    "DM conversation {} has no local key: {message}",
                    bs58::encode(conversation.contract_key).into_string()
                );
                None
            }
            _ => None,
        };
        dioxus::logger::tracing::info!(
            "DM restored conversation {} key version {:?}",
            &bs58::encode(conversation.contract_key).into_string()[..8],
            key_version
        );
    }
    let mut to_fetch = Vec::new();
    for conversation in conversations {
        let contract_id = ContractInstanceId::new(conversation.contract_key);
        if !DM_CONVERSATIONS.read().contains_key(&contract_id) {
            let key = ContractKey::from_id_and_code(contract_id, *code.hash());
            DM_CONVERSATIONS.with_mut(|conversations| {
                conversations.insert(
                    contract_id,
                    DmConversation {
                        key,
                        params: DmParamsV1 {
                            protocol_version: DM_PROTOCOL_VERSION,
                            contract_secret: [0u8; 32],
                        },
                        state: DmStateV1::default(),
                        synced: false,
                    },
                );
            });
            to_fetch.push(contract_id);
        }
    }
    for contract_id in to_fetch {
        let _ = fetch_conversation(contract_id).await;
    }
    Ok(())
}
