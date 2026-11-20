//! Client for the `plaza-dm` delegate.
//!
//! The delegate owns the DM identity seed, device seeds and conversation keys.
//! This module registers it, correlates request/response envelopes and exposes
//! the operations the DM UI will use.

use crate::components::app::{BOARDS, CURRENT_BOARD, WEB_API};
use dioxus::logger::tracing::{error, info, warn};
use dioxus::prelude::{Global, GlobalSignal, ReadableExt};
use freenet_stdlib::client_api::ClientRequest::DelegateOp;
use freenet_stdlib::client_api::DelegateRequest;
use freenet_stdlib::prelude::{
    ApplicationMessage, DelegateCode, DelegateContainer, DelegateKey, DelegateWasmAPIVersion,
    InboundDelegateMsg, Parameters,
};
use futures::channel::oneshot;
use futures::future::{select, Either};
use plaza_dm_core::delegate::{
    DmDelegateEnvelope, DmDelegateRequestMsg, DmDelegateResponseMsg,
};
use plaza_dm_core::{
    AuthorizedDmMessage, AuthorizedSealedDmKey, DmDevice, DmIdentityId, SealedDmKey,
    derive_identity_signing_key,
};
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

// The cipher material is wire-visible and must stay stable across builds so
// the delegate's secret store stays readable. This is the same pair used by
// the board delegate; the delegate key namespaces the storage.
const DEFAULT_CIPHER: [u8; 32] = [
    0, 24, 22, 150, 112, 207, 24, 65, 182, 161, 169, 227, 66, 182, 237, 215, 206, 164, 58, 161, 64,
    108, 157, 195, 0, 0, 0, 0, 0, 0, 0, 0,
];
const DEFAULT_NONCE: [u8; 24] = [
    57, 18, 79, 116, 63, 134, 93, 39, 208, 161, 156, 229, 222, 247, 111, 79, 210, 126, 127, 55,
    224, 150, 139, 80,
];

static REQUEST_ID: AtomicU64 = AtomicU64::new(1);
static ENSURE_RUNNING: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

static PENDING: LazyLock<Mutex<HashMap<u64, oneshot::Sender<DmDelegateResponseMsg>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static LAST_ENSURED_PROFILE: LazyLock<Mutex<Option<[u8; 32]>>> =
    LazyLock::new(|| Mutex::new(None));

static DELEGATE_KEY: LazyLock<DelegateKey> = LazyLock::new(|| {
    match delegate_container() {
        DelegateContainer::Wasm(DelegateWasmAPIVersion::V1(delegate)) => delegate.key().clone(),
        _ => unreachable!("DM delegate is always a Wasm V1 container"),
    }
});

const ACTIVE_IDENTITY_STORAGE_KEY: &str = "plaza_dm_active_identity_v1";

/// The active DM identity survives a reload even when the app opens directly
/// on a join route, where no board is selected. Only the public identity id is
/// stored, never a signing seed.
pub static ACTIVE_IDENTITY_OVERRIDE: GlobalSignal<Option<DmIdentityId>> = Global::new(|| {
    let value = web_sys::window()
        .and_then(|window| window.local_storage().ok().flatten())
        .and_then(|storage| storage.get_item(ACTIVE_IDENTITY_STORAGE_KEY).ok().flatten())?;
    let bytes = bs58::decode(value).into_vec().ok()?;
    <[u8; 32]>::try_from(bytes.as_slice()).ok()
});

pub fn active_identity_for_ops() -> Option<DmIdentityId> {
    identity_id_for_active_profile().or(*ACTIVE_IDENTITY_OVERRIDE.read())
}

fn remember_active_identity(identity: DmIdentityId) {
    *ACTIVE_IDENTITY_OVERRIDE.write() = Some(identity);
    if let Some(storage) = web_sys::window()
        .and_then(|window| window.local_storage().ok().flatten())
    {
        let _ = storage.set_item(
            ACTIVE_IDENTITY_STORAGE_KEY,
            &bs58::encode(identity).into_string(),
        );
    }
}

fn delegate_container() -> DelegateContainer {
    let bytes = include_bytes!("../../../public/contracts/plaza_dm_delegate.wasm");
    let code = DelegateCode::from(bytes.to_vec());
    let params = Parameters::from(Vec::<u8>::new());
    let delegate = freenet_stdlib::prelude::Delegate::from((&code, &params));
    DelegateContainer::Wasm(DelegateWasmAPIVersion::V1(delegate))
}

pub fn is_dm_delegate_key(bytes: &[u8]) -> bool {
    DELEGATE_KEY.bytes() == bytes
}

pub fn complete_dm_pending(request_id: u64, response: DmDelegateResponseMsg) -> bool {
    let Ok(mut pending) = PENDING.lock() else {
        return false;
    };
    let Some(sender) = pending.remove(&request_id) else {
        return false;
    };
    sender.send(response).is_ok()
}

/// Register the delegate. Safe to call on every reconnect; the node treats an
/// existing registration idempotently.
pub async fn set_up_dm_delegate() -> Result<(), String> {
    let delegate = delegate_container();
    let result = {
        let mut web_api = WEB_API.write();
        if let Some(api) = web_api.as_mut() {
            api.send(DelegateOp(DelegateRequest::RegisterDelegate {
                delegate,
                cipher: DEFAULT_CIPHER,
                nonce: DEFAULT_NONCE,
            }))
            .await
        } else {
            Err(freenet_stdlib::client_api::Error::ConnectionClosed)
        }
    };
    result.map_err(|error| format!("register DM delegate: {error}"))?;
    info!("DM delegate registered");

    // The identity depends on the active profile and can only be initialized
    // after the response loop is free; do it in the background.
    wasm_bindgen_futures::spawn_local(async {
        for attempt in 0..6 {
            if attempt > 0 {
                crate::util::sleep(std::time::Duration::from_millis(400)).await;
            }
            match ensure_identity_and_device().await {
                Ok(()) => return,
                Err(error) => warn!("DM delegate not ready (attempt {attempt}): {error}"),
            }
        }
        error!("DM delegate did not become ready");
    });
    Ok(())
}

/// Initialize the identity for the active profile and create one device when
/// the delegate has none.
pub async fn ensure_identity_and_device() -> Result<(), String> {
    let Some(profile_seed) = active_profile_seed() else {
        info!("DM identity: no active profile yet");
        return Ok(());
    };
    if LAST_ENSURED_PROFILE
        .lock()
        .map(|ensured| *ensured == Some(profile_seed))
        .unwrap_or(false)
    {
        return Ok(());
    }
    info!("DM identity: initializing for the active profile");
    let identity_seed = derive_identity_signing_key(&profile_seed).to_bytes();
    let identity = ed25519_dalek::SigningKey::from_bytes(&identity_seed)
        .verifying_key()
        .to_bytes();
    remember_active_identity(identity);
    match send_request(DmDelegateRequestMsg::InitIdentity { identity_seed }).await? {
        DmDelegateResponseMsg::Ok => {}
        DmDelegateResponseMsg::Error { message } => {
            return Err(format!("init DM identity: {message}"));
        }
        other => return Err(format!("unexpected InitIdentity response: {other:?}")),
    }

    let devices = match send_request(DmDelegateRequestMsg::ListDevices { identity }).await? {
        DmDelegateResponseMsg::Devices { devices } => devices,
        DmDelegateResponseMsg::Error { message } => {
            return Err(format!("list DM devices: {message}"));
        }
        other => return Err(format!("unexpected ListDevices response: {other:?}")),
    };
    info!("DM identity: {} device(s) registered", devices.len());
    if devices
        .iter()
        .any(|device| device.device.revoked_at.is_none())
    {
        info!("DM device already present");
        if let Ok(mut ensured) = LAST_ENSURED_PROFILE.lock() {
            *ensured = Some(profile_seed);
        }
        return Ok(());
    }

    let signing = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let signing_seed = signing.to_bytes();
    let mut x25519_seed = [0u8; 32];
    OsRng.fill_bytes(&mut x25519_seed);
    let mut kem_seed = vec![0u8; 64];
    OsRng.fill_bytes(&mut kem_seed);
    let created_at = chrono::Utc::now().timestamp_millis();
    match send_request(DmDelegateRequestMsg::CreateDevice {
        identity,
        label: "This browser".to_string(),
        signing_seed,
        x25519_seed,
        kem_seed,
        created_at,
    })
    .await?
    {
        DmDelegateResponseMsg::DeviceCreated { .. } => {
            info!("DM device created");
            if let Ok(mut ensured) = LAST_ENSURED_PROFILE.lock() {
                *ensured = Some(profile_seed);
            }
            Ok(())
        }
        DmDelegateResponseMsg::Error { message } => Err(format!("create DM device: {message}")),
        other => Err(format!("unexpected CreateDevice response: {other:?}")),
    }
}

fn active_profile_seed() -> Option<[u8; 32]> {
    let boards = BOARDS.read();
    let current = CURRENT_BOARD
        .read()
        .owner_key
        .or(boards.current_board_key);
    let board = current.and_then(|key| boards.map.get(&key));
    let profile = board
        .and_then(|board| boards.profile_for_board(board))
        .cloned()
        .or_else(|| boards.profiles.first().cloned());
    if let Some(profile) = &profile {
        info!("DM active profile: {}", profile.name);
    }
    profile
        .map(|profile| profile.signing_key.to_bytes())
        .or_else(|| board.map(|board| board.self_sk.to_bytes()))
}

/// Send one request and wait for its correlated response.
pub async fn send_request(
    request: DmDelegateRequestMsg,
) -> Result<DmDelegateResponseMsg, String> {
    let request_id = REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    let envelope = DmDelegateEnvelope {
        request_id,
        request,
    };
    let mut payload = Vec::new();
    ciborium::ser::into_writer(&envelope, &mut payload)
        .map_err(|error| format!("serialize DM request: {error}"))?;

    let (sender, receiver) = oneshot::channel();
    {
        let mut pending = PENDING
            .lock()
            .map_err(|error| format!("lock DM pending: {error}"))?;
        pending.insert(request_id, sender);
    }

    let app_msg = ApplicationMessage::new(payload);
    let request = DelegateOp(DelegateRequest::ApplicationMessages {
        key: DELEGATE_KEY.clone(),
        params: Parameters::from(Vec::<u8>::new()),
        inbound: vec![InboundDelegateMsg::ApplicationMessage(app_msg)],
    });
    let send_result = {
        let mut web_api = WEB_API.write();
        if let Some(api) = web_api.as_mut() {
            api.send(request).await
        } else {
            Err(freenet_stdlib::client_api::Error::ConnectionClosed)
        }
    };
    if let Err(error) = send_result {
        if let Ok(mut pending) = PENDING.lock() {
            pending.remove(&request_id);
        }
        return Err(format!("send DM request: {error}"));
    }

    let timeout = Box::pin(crate::util::sleep(std::time::Duration::from_secs(30)));
    match select(receiver, timeout).await {
        Either::Left((response, _)) => response.map_err(|_| "DM response channel cancelled".to_string()),
        Either::Right(_) => {
            if let Ok(mut pending) = PENDING.lock() {
                pending.remove(&request_id);
            }
            Err("DM delegate request timed out".to_string())
        }
    }
}

pub async fn status(identity: DmIdentityId) -> Result<DmDelegateResponseMsg, String> {
    send_request(DmDelegateRequestMsg::GetStatus { identity }).await
}

pub async fn get_active_identity() -> Result<Option<DmIdentityId>, String> {
    match send_request(DmDelegateRequestMsg::GetActiveIdentity).await? {
        DmDelegateResponseMsg::ActiveIdentity { identity } => Ok(identity),
        DmDelegateResponseMsg::Error { message } => Err(message),
        other => Err(format!("unexpected GetActiveIdentity response: {other:?}")),
    }
}

/// Clear all DM delegate material. Used by the local reset flow.
pub async fn reset() -> Result<(), String> {
    match send_request(DmDelegateRequestMsg::Reset { identity: None }).await? {
        DmDelegateResponseMsg::Ok => {
            if let Ok(mut ensured) = LAST_ENSURED_PROFILE.lock() {
                *ensured = None;
            }
            Ok(())
        }
        DmDelegateResponseMsg::Error { message } => Err(message),
        other => Err(format!("unexpected Reset response: {other:?}")),
    }
}

pub async fn list_devices(identity: DmIdentityId) -> Result<Vec<DmDevice>, String> {
    match send_request(DmDelegateRequestMsg::ListDevices { identity }).await? {
        DmDelegateResponseMsg::Devices { devices } => {
            Ok(devices.into_iter().map(|device| device.device).collect())
        }
        DmDelegateResponseMsg::Error { message } => Err(message),
        other => Err(format!("unexpected ListDevices response: {other:?}")),
    }
}

pub async fn sign_identity(
    identity: DmIdentityId,
    bytes: Vec<u8>,
) -> Result<ed25519_dalek::Signature, String> {
    match send_request(DmDelegateRequestMsg::SignIdentity { identity, bytes }).await? {
        DmDelegateResponseMsg::Signature { signature } => Ok(signature),
        DmDelegateResponseMsg::Error { message } => Err(message),
        other => Err(format!("unexpected SignIdentity response: {other:?}")),
    }
}

pub async fn sign_device(
    identity: DmIdentityId,
    device_id: [u8; 32],
    bytes: Vec<u8>,
) -> Result<ed25519_dalek::Signature, String> {
    match send_request(DmDelegateRequestMsg::SignDevice {
        identity,
        device_id,
        bytes,
    })
    .await?
    {
        DmDelegateResponseMsg::Signature { signature } => Ok(signature),
        DmDelegateResponseMsg::Error { message } => Err(message),
        other => Err(format!("unexpected SignDevice response: {other:?}")),
    }
}

pub fn identity_id_for_active_profile() -> Option<DmIdentityId> {
    active_profile_seed().map(|seed| {
        derive_identity_signing_key(&seed)
            .verifying_key()
            .to_bytes()
    })
}

#[allow(clippy::too_many_arguments)]
pub async fn seal_conversation_key(
    identity: DmIdentityId,
    sealer_device: [u8; 32],
    contract_key: [u8; 32],
    key_version: u32,
    target_member: DmIdentityId,
    target_device: [u8; 32],
    target_x25519_pk: [u8; 32],
    target_kem_ek: Vec<u8>,
    ephemeral_seed: [u8; 32],
    kem_seed: [u8; 32],
    nonce: [u8; 24],
    sealed_at: i64,
) -> Result<AuthorizedSealedDmKey, String> {
    match send_request(DmDelegateRequestMsg::SealConversationKey {
        identity,
        sealer_device,
        contract_key,
        key_version,
        target_member,
        target_device,
        target_x25519_pk,
        target_kem_ek,
        ephemeral_seed,
        kem_seed,
        nonce,
        sealed_at,
    })
    .await?
    {
        DmDelegateResponseMsg::SealedKey { key } => Ok(key),
        DmDelegateResponseMsg::Error { message } => Err(message),
        other => Err(format!("unexpected SealConversationKey response: {other:?}")),
    }
}

pub async fn open_conversation_key(
    identity: DmIdentityId,
    device_id: [u8; 32],
    contract_key: [u8; 32],
    record: SealedDmKey,
) -> Result<Option<[u8; 32]>, String> {
    match send_request(DmDelegateRequestMsg::OpenConversationKey {
        identity,
        device_id,
        contract_key,
        record,
    })
    .await?
    {
        DmDelegateResponseMsg::ConversationKey { key, .. } => Ok(key),
        DmDelegateResponseMsg::Error { message } => Err(message),
        other => Err(format!("unexpected OpenConversationKey response: {other:?}")),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn encrypt_message(
    identity: DmIdentityId,
    device_id: [u8; 32],
    contract_key: [u8; 32],
    key_version: u32,
    plaintext: Vec<u8>,
    content_type: u16,
    reply_to: Option<[u8; 32]>,
    created_at: i64,
    nonce: [u8; 24],
) -> Result<AuthorizedDmMessage, String> {
    match send_request(DmDelegateRequestMsg::EncryptMessage {
        identity,
        device_id,
        contract_key,
        key_version,
        plaintext,
        content_type,
        reply_to,
        created_at,
        nonce,
    })
    .await?
    {
        DmDelegateResponseMsg::MessageCreated { message } => Ok(message),
        DmDelegateResponseMsg::Error { message } => Err(message),
        other => Err(format!("unexpected EncryptMessage response: {other:?}")),
    }
}

pub async fn decrypt_message(
    identity: DmIdentityId,
    contract_key: [u8; 32],
    message: AuthorizedDmMessage,
) -> Result<Vec<u8>, String> {
    match send_request(DmDelegateRequestMsg::DecryptMessage {
        identity,
        contract_key,
        message,
    })
    .await?
    {
        DmDelegateResponseMsg::Plaintext { bytes } => Ok(bytes),
        DmDelegateResponseMsg::Error { message } => Err(message),
        other => Err(format!("unexpected DecryptMessage response: {other:?}")),
    }
}

/// Called when a board becomes active, so the DM identity follows the visible
/// profile even if the delegate was registered while no board was selected.
pub fn ensure_identity_for_active_board() {
    if ENSURE_RUNNING.swap(true, Ordering::SeqCst) {
        return;
    }
    info!("DM identity: board became active");
    wasm_bindgen_futures::spawn_local(async {
        for attempt in 0..6 {
            if attempt > 0 {
                crate::util::sleep(std::time::Duration::from_millis(400)).await;
            }
            match ensure_identity_and_device().await {
                Ok(()) => {
                    let _ = crate::components::app::dm_contract::load_conversations().await;
                    ENSURE_RUNNING.store(false, Ordering::SeqCst);
                    return;
                }
                Err(error) => {
                    warn!("DM identity setup after board selection (attempt {attempt}): {error}")
                }
            }
        }
        ENSURE_RUNNING.store(false, Ordering::SeqCst);
    });
}

/// Called after an in-place profile switch. Wait for any in-flight identity
/// setup, then initialize the DM identity of the newly active profile before
/// the switch toast/navigation lets the user leave the page.
pub async fn ensure_identity_after_profile_switch() -> Result<(), String> {
    for _ in 0..40 {
        if !ENSURE_RUNNING.load(Ordering::SeqCst) {
            break;
        }
        crate::util::sleep(std::time::Duration::from_millis(250)).await;
    }
    ensure_identity_and_device().await?;
    let _ = crate::components::app::dm_contract::load_conversations().await;
    Ok(())
}
