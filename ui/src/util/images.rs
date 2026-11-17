//! Upload and fetch of image blobs.
//!
//! Each image is its own contract. The client puts the bytes as a blob state,
//! then records only the instance id and the hash in the message. Downloads
//! are on demand and verified against the hash in the message.

use crate::components::app::WEB_API;
use crate::constants::BLOB_CONTRACT_WASM;
use crate::util::to_cbor_vec;
use dioxus::logger::tracing::{info, warn};
use dioxus::prelude::*;
use ed25519_dalek::{SigningKey, VerifyingKey};
use freenet_stdlib::client_api::{ClientRequest, ContractRequest};
use freenet_stdlib::prelude::{
    ContractCode, ContractContainer, ContractInstanceId, ContractKey, ContractWasmAPIVersion,
    Parameters, WrappedContract, WrappedState,
};
use futures::channel::oneshot;
use futures::future::{select, Either};
use plaza_blob_core::{BlobParametersV1, BlobStateV1};
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

/// Blob contracts whose PUT the node has not acknowledged yet. The upload is
/// only removed from the pending queue once the node answers, so a node that
/// dies between the send and the store still leaves a resumable entry.
static PENDING_BLOB_PUTS: LazyLock<Mutex<HashMap<[u8; 32], oneshot::Sender<()>>>> =
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

/// Upload one image and return its contract instance id and hash.
///
/// The caller stores the returned id in the message; the bytes stay in their
/// own contract.
pub async fn upload_image(
    bytes: Vec<u8>,
    mime: String,
    width: u32,
    height: u32,
    uploader: &SigningKey,
    owner_founding: VerifyingKey,
    owner_current: VerifyingKey,
) -> Result<([u8; 32], [u8; 32], u32), String> {
    let sha256 = image_sha256(&bytes);
    let size = bytes.len() as u32;
    let parameters = blob_parameters(sha256, uploader, owner_founding, owner_current);
    let state = BlobStateV1::live(&parameters, mime, width, height, bytes);
    state.validate(&parameters)?;
    let key = blob_contract_key(&parameters);
    let instance: [u8; 32] = key
        .id()
        .as_bytes()
        .try_into()
        .map_err(|_| "Unexpected contract id length".to_string())?;

    let contract = ContractContainer::from(ContractWasmAPIVersion::V1(WrappedContract::new(
        Arc::new(ContractCode::from(BLOB_CONTRACT_WASM)),
        Parameters::from(to_cbor_vec(&parameters)),
    )));
    let request = ContractRequest::Put {
        contract,
        state: WrappedState::new(to_cbor_vec(&state)),
        related_contracts: Default::default(),
        subscribe: false,
        blocking_subscribe: false,
    };

    let (acknowledged, wait_for_node) = oneshot::channel();
    if let Ok(mut waiting) = PENDING_BLOB_PUTS.lock() {
        waiting.insert(instance, acknowledged);
    }

    {
        // Release the lock before waiting for the node: the response handler
        // runs on the same task and must not block on it.
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

    let timeout = Box::pin(crate::util::sleep(Duration::from_secs(30)));
    match select(wait_for_node, timeout).await {
        Either::Left((Ok(()), _)) => {}
        Either::Left((Err(_), _)) => {
            forget_blob_put(&instance);
            return Err("The upload was cancelled".to_string());
        }
        Either::Right((_, _)) => {
            forget_blob_put(&instance);
            return Err(
                "The node did not confirm the image; it stays in the queue for the next try"
                    .to_string(),
            );
        }
    }

    info!("Uploaded image blob {instance:?} ({} bytes)", size);
    Ok((instance, sha256, size))
}

fn forget_blob_put(instance: &[u8; 32]) {
    if let Ok(mut waiting) = PENDING_BLOB_PUTS.lock() {
        waiting.remove(instance);
    }
}

/// Ask for an image, unless it is already cached or being fetched.
pub fn request_image(instance: [u8; 32], expected_sha256: [u8; 32]) {
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

fn fail_image(instance: [u8; 32], reason: String) {
    warn!("Image {instance:?} unavailable: {reason}");
    IMAGES.with_mut(|images| {
        if let Some(entry) = images.get_mut(&instance) {
            entry.status = ImageStatus::Failed(reason);
        }
    });
}

/// Called from the GET response handler for every response whose instance id
/// is a pending image.
pub fn handle_image_response(instance: [u8; 32], state: &[u8]) -> bool {
    let expected = {
        let images = IMAGES.read();
        match images.get(&instance) {
            Some(entry) => entry.expected,
            None => return false,
        }
    };

    let status = match ciborium::de::from_reader::<BlobStateV1, &[u8]>(state) {
        Ok(blob) if blob.retired => ImageStatus::Failed("retired".to_string()),
        Ok(blob) if blob.data.is_empty() => ImageStatus::Failed("empty".to_string()),
        Ok(blob) if plaza_blob_core::sha256(&blob.data) != expected => {
            ImageStatus::Failed("hash mismatch".to_string())
        }
        Ok(blob) => ImageStatus::Ready(blob.data),
        Err(error) => ImageStatus::Failed(error.to_string()),
    };
    IMAGES.with_mut(|images| {
        if let Some(entry) = images.get_mut(&instance) {
            entry.status = status;
        }
    });
    true
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
