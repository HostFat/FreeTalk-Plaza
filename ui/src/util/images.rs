//! Upload and fetch of image blobs.
//!
//! Each image is its own contract. The client puts the bytes as a blob state,
//! then records only the instance id and the hash in the message. Downloads
//! are on demand and verified against the hash in the message.

use crate::components::app::{BOARDS, CURRENT_BOARD, WEB_API};
use crate::constants::BLOB_CONTRACT_WASM;
use crate::util::ecies::{decrypt_with_symmetric_key, encrypt_with_symmetric_key};
use crate::util::to_cbor_vec;
use dioxus::logger::tracing::{info, warn};
use dioxus::prelude::*;
use ed25519_dalek::{SigningKey, VerifyingKey};
use freenet_stdlib::client_api::{ClientRequest, ContractRequest};
use freenet_stdlib::prelude::{
    CodeHash, ContractCode, ContractContainer, ContractInstanceId, ContractKey,
    ContractWasmAPIVersion, Parameters, UpdateData, WrappedContract, WrappedState,
};
use futures::channel::oneshot;
use futures::future::{select, Either};
use plaza_blob_core::{
    manifest_sha256, BlobParametersV1, BlobStateV1, ChunkRef, RetirementRole, CHUNK_BYTES,
    MAX_CHUNKS,
};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

/// State of one on-demand image download.
#[derive(Clone, Debug, PartialEq)]
pub enum ImageStatus {
    Loading,
    Ready(Vec<u8>),
    Failed(String),
}

/// Images requested by the views, keyed by contract instance id.
#[derive(Clone, Debug)]
pub struct ImageFetch {
    pub expected: [u8; 32],
    pub status: ImageStatus,
}

pub static IMAGES: GlobalSignal<HashMap<[u8; 32], ImageFetch>> = Global::new(HashMap::new);

/// Profile preference: load images without asking in every discussion.
pub static AUTO_LOAD_IMAGES: GlobalSignal<bool> = Global::new(|| false);

/// Per-topic choice, which overrides the profile preference in both directions.
pub static AUTO_LOAD_TOPICS: GlobalSignal<HashMap<String, bool>> = Global::new(HashMap::new);

/// Resolved auto-load value for the topic currently on screen. Views set it;
/// the attachments read it so a toggle reaches images already rendered.
pub static AUTO_LOAD_CURRENT: GlobalSignal<bool> = Global::new(|| false);

/// Whether the images of `topic` should open without a click.
pub fn auto_load_for(topic: &str) -> bool {
    AUTO_LOAD_TOPICS
        .read()
        .get(topic)
        .copied()
        .unwrap_or_else(|| *AUTO_LOAD_IMAGES.read())
}

pub fn image_sha256(bytes: &[u8]) -> [u8; 32] {
    plaza_blob_core::sha256(bytes)
}

/// Prepared images already uploaded in this page session, keyed by the
/// plaintext hash. Reusing one avoids a second set of PUTs.
static UPLOADED_IMAGES: LazyLock<Mutex<HashMap<[u8; 32], ([u8; 32], u32)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Blob contracts whose PUT the node has not acknowledged yet. The upload is
/// only removed from the pending queue once the node answers, so a node that
/// dies between the send and the store still leaves a resumable entry.
static PENDING_BLOB_PUTS: LazyLock<Mutex<HashMap<[u8; 32], oneshot::Sender<()>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Blob states a chunk assembler is waiting for.
static PENDING_BLOB_GETS: LazyLock<Mutex<HashMap<[u8; 32], oneshot::Sender<Vec<u8>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Complete a waiting upload when the node acknowledges its PUT. Returns true
/// when the contract belonged to an image upload.
pub fn complete_blob_put(instance: &[u8; 32]) -> bool {
    let sender = PENDING_BLOB_PUTS
        .lock()
        .ok()
        .and_then(|mut waiting| waiting.remove(instance));
    match sender {
        Some(sender) => {
            let _ = sender.send(());
            true
        }
        None => false,
    }
}

pub fn blob_parameters(
    sha256: [u8; 32],
    uploader: &SigningKey,
    owner_founding: VerifyingKey,
    owner_current: VerifyingKey,
) -> BlobParametersV1 {
    BlobParametersV1::new(
        sha256,
        uploader.verifying_key(),
        owner_founding,
        owner_current,
    )
}

pub fn blob_contract_key(parameters: &BlobParametersV1) -> ContractKey {
    let params = Parameters::from(to_cbor_vec(parameters));
    ContractKey::from_params_and_code(params, &ContractCode::from(BLOB_CONTRACT_WASM))
}

/// One uploaded blob's bytes, kept by the caller for renewal.
#[derive(Clone)]
pub struct BlobCopy {
    pub parameters: Vec<u8>,
    pub state: Vec<u8>,
    /// Chunk copies of a manifest.
    pub chunks: Vec<BlobCopy>,
}

/// Upload one image and return its contract instance id and hash.
///
/// The caller stores the returned id in the message; the bytes stay in their
/// own contract. A payload larger than one chunk is split and the returned id
/// points to its manifest. With `secret`, the payload is sealed with the board
/// or section key before it leaves the client.
pub async fn upload_image(
    bytes: Vec<u8>,
    mime: String,
    width: u32,
    height: u32,
    uploader: &SigningKey,
    owner_founding: VerifyingKey,
    owner_current: VerifyingKey,
    secret: Option<([u8; 32], u32)>,
    progress: Option<&dyn Fn(usize, usize)>,
) -> Result<([u8; 32], [u8; 32], u32, Option<BlobCopy>), String> {
    let plaintext_sha = image_sha256(&bytes);
    let size = bytes.len() as u32;
    // The same file attached twice reuses the contract from this session.
    if secret.is_none() {
        if let Some((instance, size)) = UPLOADED_IMAGES
            .lock()
            .ok()
            .and_then(|uploaded| uploaded.get(&plaintext_sha).copied())
        {
            return Ok((instance, plaintext_sha, size, None));
        }
    }
    let (stored, nonce, secret_version) = match secret {
        Some((key, version)) => {
            let (ciphertext, nonce) = encrypt_with_symmetric_key(&key, &bytes, version);
            (ciphertext, Some(nonce), Some(version))
        }
        None => (bytes, None, None),
    };

    if stored.len() <= CHUNK_BYTES {
        let parameters = blob_parameters(
            image_sha256(&stored),
            uploader,
            owner_founding,
            owner_current,
        );
        let mut state = BlobStateV1::live(&parameters, mime, width, height, stored);
        if let (Some(nonce), Some(version)) = (nonce, secret_version) {
            state = state.sealed(nonce, version);
        }
        state.validate(&parameters)?;
        // Unsealed content is content-addressed: if the node already has it,
        // skip the PUT. Sealed ciphertext differs on every upload.
        if secret.is_none() {
            let instance: [u8; 32] = blob_contract_key(&parameters)
                .id()
                .as_bytes()
                .try_into()
                .map_err(|_| "Unexpected contract id length".to_string())?;
            if let Ok(existing) = fetch_blob_state(instance).await {
                if let Ok(blob) = ciborium::de::from_reader::<BlobStateV1, &[u8]>(&existing[..]) {
                    if !blob.retired
                        && blob.data.len() == state.data.len()
                        && image_sha256(&blob.data) == parameters.sha256
                    {
                        info!("Image blob {instance:?} already on the node");
                        if let Some(progress) = progress {
                            progress(size as usize, size as usize);
                        }
                        remember_upload(secret, plaintext_sha, instance, size);
                        return Ok((instance, plaintext_sha, size, None));
                    }
                }
            }
        }
        let copy = BlobCopy {
            parameters: to_cbor_vec(&parameters),
            state: to_cbor_vec(&state),
            chunks: Vec::new(),
        };
        if let Some(progress) = progress {
            progress(0, size as usize);
        }
        let instance = put_blob_with_retry(&parameters, &state).await?;
        if let Some(progress) = progress {
            progress(size as usize, size as usize);
        }
        info!("Uploaded image blob {instance:?} ({} bytes)", state.stored_len());
        remember_upload(secret, plaintext_sha, instance, size);
        return Ok((instance, plaintext_sha, size, Some(copy)));
    }

    let pieces: Vec<&[u8]> = stored.chunks(CHUNK_BYTES).collect();
    if pieces.len() > MAX_CHUNKS {
        return Err(format!(
            "The image needs {} chunks, the limit is {}",
            pieces.len(),
            MAX_CHUNKS
        ));
    }

    // A repeat upload of the same unsealed file has the same manifest key.
    // Read the small manifest first: when it is already there, every chunk is
    // there too, and nothing is uploaded again.
    if secret.is_none() {
        let refs: Vec<ChunkRef> = pieces
            .iter()
            .map(|piece| {
                let chunk_sha = image_sha256(piece);
                let parameters =
                    blob_parameters(chunk_sha, uploader, owner_founding, owner_current);
                let instance: [u8; 32] = blob_contract_key(&parameters)
                    .id()
                    .as_bytes()
                    .try_into()
                    .expect("32-byte contract id");
                ChunkRef {
                    instance,
                    sha256: chunk_sha,
                    bytes: piece.len() as u32,
                }
            })
            .collect();
        let manifest_parameters = blob_parameters(
            manifest_sha256(&refs),
            uploader,
            owner_founding,
            owner_current,
        );
        let manifest_instance: [u8; 32] = blob_contract_key(&manifest_parameters)
            .id()
            .as_bytes()
            .try_into()
            .expect("32-byte contract id");
        if let Ok(state) = fetch_blob_state(manifest_instance).await {
            if let Ok(blob) = ciborium::de::from_reader::<BlobStateV1, &[u8]>(&state[..]) {
                if blob.is_manifest() && blob.chunks == refs {
                    return Ok((manifest_instance, plaintext_sha, size, None));
                }
            }
        }
    }
    // Three PUTs in flight at a time: the socket write is serialized, the
    // confirmation waits overlap. Order inside each batch is preserved.
    let mut chunks = Vec::with_capacity(pieces.len());
    let mut chunk_copies = Vec::with_capacity(pieces.len());
    let mut confirmed = 0usize;
    let total_bytes = stored.len();
    for batch in pieces.chunks(3) {
        let mut in_flight = Vec::new();
        for piece in batch {
            let piece = *piece;
            let chunk_sha = image_sha256(piece);
            let parameters =
                blob_parameters(chunk_sha, uploader, owner_founding, owner_current);
            let state = BlobStateV1::live(
                &parameters,
                mime.clone(),
                width,
                height,
                piece.to_vec(),
            );
            state.validate(&parameters)?;
            let (instance, receiver) = send_blob_with_retry(&parameters, &state).await?;
            in_flight.push((
                ChunkRef {
                    instance,
                    sha256: chunk_sha,
                    bytes: piece.len() as u32,
                },
                receiver,
                BlobCopy {
                    parameters: to_cbor_vec(&parameters),
                    state: to_cbor_vec(&state),
                    chunks: Vec::new(),
                },
            ));
        }
        for (chunk, receiver, copy) in in_flight {
            await_blob_ack(chunk.instance, receiver).await?;
            info!(
                "Uploaded image blob {:?} ({} bytes)",
                chunk.instance, chunk.bytes
            );
            confirmed += chunk.bytes as usize;
            if let Some(progress) = progress {
                progress(confirmed.min(total_bytes), total_bytes);
            }
            chunks.push(chunk);
            chunk_copies.push(copy);
        }
    }

    let parameters = blob_parameters(
        manifest_sha256(&chunks),
        uploader,
        owner_founding,
        owner_current,
    );
    let mut state = BlobStateV1::manifest(&parameters, mime, width, height, chunks);
    if let (Some(nonce), Some(version)) = (nonce, secret_version) {
        state = state.sealed(nonce, version);
    }
    state.validate(&parameters)?;
    let copy = BlobCopy {
        parameters: to_cbor_vec(&parameters),
        state: to_cbor_vec(&state),
        chunks: chunk_copies,
    };
    let instance = put_blob_with_retry(&parameters, &state).await?;
    if let Some(progress) = progress {
        progress(total_bytes, total_bytes);
    }
    info!("Uploaded image manifest {instance:?}");
    remember_upload(secret, plaintext_sha, instance, size);
    Ok((instance, plaintext_sha, size, Some(copy)))
}

fn remember_upload(
    secret: Option<([u8; 32], u32)>,
    plaintext_sha: [u8; 32],
    instance: [u8; 32],
    size: u32,
) {
    if secret.is_some() {
        return;
    }
    if let Ok(mut uploaded) = UPLOADED_IMAGES.lock() {
        uploaded.insert(plaintext_sha, (instance, size));
    }
}

/// PUT with two retries and a short backoff. A transient rejection or a lost
/// response costs a few seconds instead of the whole upload.
async fn put_blob_with_retry(
    parameters: &BlobParametersV1,
    state: &BlobStateV1,
) -> Result<[u8; 32], String> {
    let (instance, receiver) = send_blob_with_retry(parameters, state).await?;
    await_blob_ack(instance, receiver).await?;
    Ok(instance)
}

async fn send_blob_with_retry(
    parameters: &BlobParametersV1,
    state: &BlobStateV1,
) -> Result<([u8; 32], oneshot::Receiver<()>), String> {
    let mut delay = Duration::from_secs(1);
    let mut last = String::new();
    for attempt in 0..3 {
        match send_blob(parameters, state).await {
            Ok(sent) => return Ok(sent),
            Err(error) => {
                last = error;
                if attempt < 2 {
                    crate::util::sleep(delay).await;
                    delay = delay * 2;
                }
            }
        }
    }
    Err(last)
}

/// PUT a stored blob exactly as it was uploaded, used by the renewal task.
pub async fn put_raw_blob(parameters: &[u8], state: &[u8]) -> Result<(), String> {
    let params = Parameters::from(parameters.to_vec());
    let code = ContractCode::from(BLOB_CONTRACT_WASM);
    let key = ContractKey::from_params_and_code(params.clone(), &code);
    let instance: [u8; 32] = key
        .id()
        .as_bytes()
        .try_into()
        .map_err(|_| "Unexpected contract id length".to_string())?;
    let contract = ContractContainer::from(ContractWasmAPIVersion::V1(WrappedContract::new(
        Arc::new(code),
        params,
    )));
    let request = ContractRequest::Put {
        contract,
        state: WrappedState::new(state.to_vec()),
        related_contracts: Default::default(),
        subscribe: false,
        blocking_subscribe: false,
    };

    let (acknowledged, wait_for_node) = oneshot::channel();
    if let Ok(mut waiting) = PENDING_BLOB_PUTS.lock() {
        waiting.insert(instance, acknowledged);
    }
    {
        let mut web_api = WEB_API.write();
        let Some(web_api) = web_api.as_mut() else {
            forget_blob_put(&instance);
            return Err("Not connected to a Freenet node".to_string());
        };
        if let Err(error) = web_api.send(ClientRequest::ContractOp(request)).await {
            forget_blob_put(&instance);
            return Err(error.to_string());
        }
    }
    await_blob_ack(instance, wait_for_node).await
}

/// PUT one blob state and wait for the node to acknowledge it.
async fn put_blob(
    parameters: &BlobParametersV1,
    state: &BlobStateV1,
) -> Result<[u8; 32], String> {
    let (instance, receiver) = send_blob(parameters, state).await?;
    await_blob_ack(instance, receiver).await?;
    Ok(instance)
}

/// Send the PUT but do not wait for the node. The lock is held only for the
/// socket write, so several chunks can be in flight at once.
async fn send_blob(
    parameters: &BlobParametersV1,
    state: &BlobStateV1,
) -> Result<([u8; 32], oneshot::Receiver<()>), String> {
    let key = blob_contract_key(parameters);
    let instance: [u8; 32] = key
        .id()
        .as_bytes()
        .try_into()
        .map_err(|_| "Unexpected contract id length".to_string())?;

    let contract = ContractContainer::from(ContractWasmAPIVersion::V1(WrappedContract::new(
        Arc::new(ContractCode::from(BLOB_CONTRACT_WASM)),
        Parameters::from(to_cbor_vec(parameters)),
    )));
    let request = ContractRequest::Put {
        contract,
        state: WrappedState::new(to_cbor_vec(state)),
        related_contracts: Default::default(),
        subscribe: false,
        blocking_subscribe: false,
    };

    let (acknowledged, wait_for_node) = oneshot::channel();
    if let Ok(mut waiting) = PENDING_BLOB_PUTS.lock() {
        waiting.insert(instance, acknowledged);
    }

    {
        let mut web_api = WEB_API.write();
        let Some(web_api) = web_api.as_mut() else {
            forget_blob_put(&instance);
            return Err("Not connected to a Freenet node".to_string());
        };
        if let Err(error) = web_api.send(ClientRequest::ContractOp(request)).await {
            forget_blob_put(&instance);
            return Err(error.to_string());
        }
    }
    Ok((instance, wait_for_node))
}

async fn await_blob_ack(
    instance: [u8; 32],
    wait_for_node: oneshot::Receiver<()>,
) -> Result<(), String> {
    // A busy node can take a while to compile and store a new contract; the
    // queue keeps the upload if this window passes.
    let timeout = Box::pin(crate::util::sleep(Duration::from_secs(60)));
    match select(wait_for_node, timeout).await {
        Either::Left((Ok(()), _)) => Ok(()),
        Either::Left((Err(_), _)) => {
            forget_blob_put(&instance);
            Err("The upload was cancelled".to_string())
        }
        Either::Right((_, _)) => {
            forget_blob_put(&instance);
            Err(
                "The node did not confirm the image; it stays in the queue for the next try"
                    .to_string(),
            )
        }
    }
}

fn forget_blob_put(instance: &[u8; 32]) {
    if let Ok(mut waiting) = PENDING_BLOB_PUTS.lock() {
        waiting.remove(instance);
    }
}

/// Whether this device refuses an image hash. The list lives in the board
/// store, so it does not depend on any board adopting the same rule.
pub fn is_hash_blocked(hash: &[u8; 32]) -> bool {
    BOARDS
        .read()
        .blocked_image_hashes
        .iter()
        .any(|blocked| blocked == hash)
}

/// Add a hash to the device denylist and persist it.
pub fn block_hash(hash: [u8; 32]) {
    let already = is_hash_blocked(&hash);
    if !already {
        BOARDS.with_mut(|boards| boards.blocked_image_hashes.push(hash));
    }
    crate::util::safe_spawn_local(async {
        if let Err(error) = crate::components::app::chat_delegate::save_boards_to_delegate().await
        {
            warn!("Could not persist the blocked image hash: {error}");
        }
    });
}

/// Add a hash to the device denylist and hide that image now.
pub fn block_image(instance: [u8; 32], hash: [u8; 32]) {
    block_hash(hash);
    IMAGES.with_mut(|images| {
        images.insert(
            instance,
            ImageFetch {
                expected: hash,
                status: ImageStatus::Failed("blocked on this device".to_string()),
            },
        );
    });
}

/// Ask for an image, unless it is already cached or being fetched.
pub fn request_image(instance: [u8; 32], expected_sha256: [u8; 32]) {
    if is_hash_blocked(&expected_sha256) {
        fail_image(instance, "blocked on this device".to_string());
        return;
    }
    {
        let images = IMAGES.read();
        if let Some(existing) = images.get(&instance) {
            if matches!(existing.status, ImageStatus::Loading | ImageStatus::Ready(_)) {
                return;
            }
        }
    }
    IMAGES.with_mut(|images| {
        images.insert(
            instance,
            ImageFetch {
                expected: expected_sha256,
                status: ImageStatus::Loading,
            },
        );
    });

    let request = ContractRequest::Get {
        key: ContractInstanceId::new(instance),
        return_contract_code: false,
        subscribe: false,
        blocking_subscribe: false,
    };
    crate::util::safe_spawn_local(async move {
        let mut web_api = WEB_API.write();
        let Some(web_api) = web_api.as_mut() else {
            fail_image(instance, "Not connected to a Freenet node".to_string());
            return;
        };
        if let Err(error) = web_api.send(ClientRequest::ContractOp(request)).await {
            fail_image(instance, error.to_string());
        }
    });
}

/// Called from the GET response handler for every response whose instance id
/// is a pending image.
pub fn handle_image_response(instance: [u8; 32], state: &[u8]) -> bool {
    // A chunk or manifest fetched by the assembler: hand the raw state over.
    if let Some(sender) = PENDING_BLOB_GETS
        .lock()
        .ok()
        .and_then(|mut waiting| waiting.remove(&instance))
    {
        let _ = sender.send(state.to_vec());
        return true;
    }

    let expected = {
        let images = IMAGES.read();
        match images.get(&instance) {
            Some(entry) => entry.expected,
            None => return false,
        }
    };

    let blob = match ciborium::de::from_reader::<BlobStateV1, &[u8]>(state) {
        Ok(blob) => blob,
        Err(error) => {
            fail_image(instance, error.to_string());
            return true;
        }
    };
    if blob.retired {
        fail_image(instance, "retired".to_string());
        return true;
    }
    if blob.is_manifest() {
        start_chunk_load(instance, expected, blob);
        return true;
    }
    let actual_public = if blob.nonce.is_none() {
        Some(image_sha256(&blob.data))
    } else {
        None
    };
    let data_len = blob.data.len();
    let status = payload_status(blob.data, blob.nonce, blob.secret_version, expected);
    if matches!(&status, ImageStatus::Failed(reason) if reason == "hash mismatch") {
        dioxus::logger::tracing::warn!(
            "Image hash mismatch for {:?}: expected {:?}, actual {:?}, data_len={}, sealed={}",
            instance,
            expected,
            actual_public,
            data_len,
            blob.nonce.is_some()
        );
    }
    set_image_status(instance, status);
    true
}

fn set_image_status(instance: [u8; 32], status: ImageStatus) {
    IMAGES.with_mut(|images| {
        if let Some(entry) = images.get_mut(&instance) {
            entry.status = status;
        }
    });
}

/// Decrypt when sealed, then verify the hash of the plaintext.
fn payload_status(
    mut data: Vec<u8>,
    nonce: Option<[u8; 12]>,
    version: Option<u32>,
    expected: [u8; 32],
) -> ImageStatus {
    if let Some(nonce) = nonce {
        match unlock(&data, &nonce, version) {
            Ok(plain) => data = plain,
            Err(error) => return ImageStatus::Failed(error),
        }
    }
    if image_sha256(&data) != expected {
        return ImageStatus::Failed("hash mismatch".to_string());
    }
    if is_hash_blocked(&expected) {
        return ImageStatus::Failed("blocked on this device".to_string());
    }
    ImageStatus::Ready(data)
}

/// Try the board and section secrets the client holds; the hash check in the
/// caller confirms the right one.
fn unlock(data: &[u8], nonce: &[u8; 12], version: Option<u32>) -> Result<Vec<u8>, String> {
    let candidates = candidate_secrets();
    if let Some(version) = version {
        for (key, _) in &candidates {
            if let Ok(plain) = decrypt_with_symmetric_key(key, data, nonce, version) {
                return Ok(plain);
            }
        }
    }
    for (key, candidate_version) in candidates {
        if let Ok(plain) = decrypt_with_symmetric_key(&key, data, nonce, candidate_version) {
            return Ok(plain);
        }
    }
    Err("the key for this private image is not available".to_string())
}

fn candidate_secrets() -> Vec<([u8; 32], u32)> {
    let Some(key) = CURRENT_BOARD.read().owner_key else {
        return Vec::new();
    };
    BOARDS
        .read()
        .map
        .get(&key)
        .map(|board| board.image_secret_candidates())
        .unwrap_or_default()
}

/// Fetch the manifest's chunks one by one, verify each piece, then reassemble,
/// decrypt and verify the whole image.
fn start_chunk_load(instance: [u8; 32], expected: [u8; 32], manifest: BlobStateV1) {
    crate::util::safe_spawn_local(async move {
        let mut all = Vec::new();
        // Three chunk downloads in flight at a time.
        for batch in manifest.chunks.chunks(3) {
            let futures = batch.iter().map(|chunk| async move {
                let state = fetch_blob_state(chunk.instance).await?;
                Ok::<(&ChunkRef, Vec<u8>), String>((chunk, state))
            });
            for result in futures::future::join_all(futures).await {
                let (chunk, state) = match result {
                    Ok(pair) => pair,
                    Err(error) => {
                        fail_image(instance, error);
                        return;
                    }
                };
                match ciborium::de::from_reader::<BlobStateV1, &[u8]>(&state[..]) {
                    Ok(blob) if blob.retired => {
                        fail_image(instance, "a chunk was retired".to_string());
                        return;
                    }
                    Ok(blob)
                        if blob.data.len() as u32 != chunk.bytes
                            || image_sha256(&blob.data) != chunk.sha256 =>
                    {
                        fail_image(instance, "a chunk does not match its hash".to_string());
                        return;
                    }
                    Ok(blob) => all.extend(blob.data),
                    Err(error) => {
                        fail_image(instance, error.to_string());
                        return;
                    }
                }
            }
        }
        let status = payload_status(all, manifest.nonce, manifest.secret_version, expected);
        set_image_status(instance, status);
    });
}

/// GET one blob state and wait for its response.
async fn fetch_blob_state(instance: [u8; 32]) -> Result<Vec<u8>, String> {
    let (sender, receiver) = oneshot::channel();
    if let Ok(mut waiting) = PENDING_BLOB_GETS.lock() {
        waiting.insert(instance, sender);
    }

    {
        let request = ContractRequest::Get {
            key: ContractInstanceId::new(instance),
            return_contract_code: false,
            subscribe: false,
            blocking_subscribe: false,
        };
        let mut web_api = WEB_API.write();
        let Some(web_api) = web_api.as_mut() else {
            forget_get(instance);
            return Err("Not connected to a Freenet node".to_string());
        };
        if let Err(error) = web_api.send(ClientRequest::ContractOp(request)).await {
            forget_get(instance);
            return Err(error.to_string());
        }
    }

    let timeout = Box::pin(crate::util::sleep(Duration::from_secs(20)));
    match select(receiver, timeout).await {
        Either::Left((Ok(state), _)) => Ok(state),
        Either::Left((Err(_), _)) => Err("The download was cancelled".to_string()),
        Either::Right((_, _)) => {
            forget_get(instance);
            Err("The node did not answer the chunk request".to_string())
        }
    }
}

fn forget_get(instance: [u8; 32]) {
    if let Ok(mut waiting) = PENDING_BLOB_GETS.lock() {
        waiting.remove(&instance);
    }
}

fn fail_image(instance: [u8; 32], reason: String) {
    warn!("Image {instance:?} unavailable: {reason}");
    IMAGES.with_mut(|images| {
        if let Some(entry) = images.get_mut(&instance) {
            entry.status = ImageStatus::Failed(reason.clone());
        } else {
            // The image was never fetched in this session: keep a failed entry
            // so the placeholder shows the reason right away.
            images.insert(
                instance,
                ImageFetch {
                    expected: [0u8; 32],
                    status: ImageStatus::Failed(reason.clone()),
                },
            );
        }
    });
}

/// Retire the blob itself, for its uploader or a board owner. The contract
/// verifies the signer against its parameters; the board record is a separate
/// lever that follows the live admin list.
pub async fn retire_in_contract(instance: [u8; 32]) -> Result<(), String> {
    let state_bytes = fetch_blob_state(instance).await?;
    let state = ciborium::de::from_reader::<BlobStateV1, &[u8]>(&state_bytes[..])
        .map_err(|error| error.to_string())?;
    if state.retired {
        fail_image(instance, "retired".to_string());
        return Ok(());
    }
    let content = if state.is_manifest() {
        manifest_sha256(&state.chunks)
    } else {
        image_sha256(&state.data)
    };

    let Some(board_key) = CURRENT_BOARD.read().owner_key else {
        return Err("No board selected".to_string());
    };
    let Some(board) = BOARDS.read().map.get(&board_key).cloned() else {
        return Err("Board data is not loaded".to_string());
    };
    let self_vk = board.self_sk.verifying_key();
    let owner_vk = board.owner_key().verifying_key();
    // Blob parameters name three keys: the uploader profile, the founding owner
    // and the current owner. Sign each role with the matching key.
    let (signing_key, role) = if state.uploader == self_vk {
        (board.self_sk.clone(), RetirementRole::Uploader)
    } else if owner_vk == board.owner_vk {
        (board.owner_key().clone(), RetirementRole::OwnerFounding)
    } else if owner_vk == board.current_owner_key() {
        (board.owner_key().clone(), RetirementRole::OwnerCurrent)
    } else {
        return Err(
            "Only the uploader or a board owner can retire the contract itself".to_string(),
        );
    };

    let retired = BlobStateV1::retired_by(&state, content, &signing_key, role);
    send_retirement(instance, &retired).await?;

    // A manifest leaves its chunks reachable by key; the same owner keys are
    // in every chunk's parameters, so retire them too.
    if state.is_manifest() {
        for chunk in &state.chunks {
            let Ok(chunk_bytes) = fetch_blob_state(chunk.instance).await else {
                continue;
            };
            let Ok(chunk_state) = ciborium::de::from_reader::<BlobStateV1, &[u8]>(&chunk_bytes[..])
            else {
                continue;
            };
            if chunk_state.retired {
                continue;
            }
            let chunk_content = image_sha256(&chunk_state.data);
            let retired = BlobStateV1::retired_by(
                &chunk_state,
                chunk_content,
                &board.self_sk,
                role,
            );
            if let Err(error) = send_retirement(chunk.instance, &retired).await {
                warn!("Could not retire chunk {:?}: {error}", chunk.instance);
            }
        }
    }

    fail_image(instance, "retired".to_string());
    info!("Sent contract retirement for image {instance:?}");
    Ok(())
}

async fn send_retirement(instance: [u8; 32], retired: &BlobStateV1) -> Result<(), String> {
    let key = ContractKey::from_id_and_code(
        ContractInstanceId::new(instance),
        CodeHash::from_code(BLOB_CONTRACT_WASM),
    );
    let request = ContractRequest::Update {
        key,
        data: UpdateData::State(to_cbor_vec(retired).into()),
    };
    let mut web_api = WEB_API.write();
    let Some(web_api) = web_api.as_mut() else {
        return Err("Not connected to a Freenet node".to_string());
    };
    web_api
        .send(ClientRequest::ContractOp(request))
        .await
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_blob_key_follows_the_parameters() {
        let uploader = SigningKey::from_bytes(&[1u8; 32]);
        let founding = SigningKey::from_bytes(&[2u8; 32]);
        let current = SigningKey::from_bytes(&[3u8; 32]);
        let parameters = blob_parameters(
            [7u8; 32],
            &uploader,
            founding.verifying_key(),
            current.verifying_key(),
        );
        let first = blob_contract_key(&parameters);
        assert_eq!(first, blob_contract_key(&parameters));

        let other = blob_parameters(
            [8u8; 32],
            &uploader,
            founding.verifying_key(),
            current.verifying_key(),
        );
        assert_ne!(first, blob_contract_key(&other));
    }
}
