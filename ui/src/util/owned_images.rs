//! The images this device uploaded: renewal and reuse.

use crate::board_data::{OwnedChunkCopy, OwnedImage};
use crate::components::app::chat_delegate::{
    save_boards_to_delegate, send_delegate_request, OWNED_IMAGES_STORAGE_KEY,
};
use crate::components::app::{BOARDS, BOARDS_LOADED};
use crate::util::images::{put_raw_blob, BlobCopy};
use dioxus::logger::tracing::{info, warn};
use dioxus::prelude::ReadableExt;
use plaza_core::board_state::images::ImageRef;
use plaza_core::chat_delegate::{
    ChatDelegateKey, ChatDelegateRequestMsg, ChatDelegateResponseMsg,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use wasm_bindgen_futures::spawn_local;

/// Bytes of raw blob state kept for renewal. Older uploads are dropped first.
pub const MAX_OWNED_BYTES: usize = 24 * 1024 * 1024;
/// A blob untouched for this long is put back on the network.
const RENEW_AFTER_MS: i64 = 7 * 24 * 60 * 60 * 1000;

static RENEW_STARTED: AtomicBool = AtomicBool::new(false);
/// The image index changed and its own delegate key has to be rewritten.
static OWNED_IMAGES_DIRTY: AtomicBool = AtomicBool::new(false);
/// The boards blob still carried the index when it was loaded.
static LEGACY_OWNED_IMAGES: AtomicBool = AtomicBool::new(false);

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn persist() {
    spawn_local(async {
        if let Err(error) = save_boards_to_delegate().await {
            warn!("Could not persist the owned images: {error}");
        }
    });
}

/// Note that the board blob carried the image index (older versions).
pub fn note_legacy(has_entries: bool) {
    if has_entries {
        LEGACY_OWNED_IMAGES.store(true, Ordering::SeqCst);
        // Write the entries under the new key before the board map is saved
        // without them.
        OWNED_IMAGES_DIRTY.store(true, Ordering::SeqCst);
    }
}

/// Take the legacy flag, for the load response.
pub fn take_legacy() -> bool {
    LEGACY_OWNED_IMAGES.swap(false, Ordering::SeqCst)
}

/// Mark the index for the next save.
pub fn mark_dirty() {
    OWNED_IMAGES_DIRTY.store(true, Ordering::SeqCst);
}

/// Merge the index loaded from its own key. The freshest copy of an instance
/// wins, so a tab that renewed an image while this one loaded is not undone.
pub fn apply_loaded(loaded: Option<Vec<OwnedImage>>) {
    let Some(loaded) = loaded else { return };
    BOARDS.with_mut(|boards| merge_entries(&mut boards.owned_images, loaded));
    renew_due_entries();
}

/// Pure merge used by the load path and its test.
pub fn merge_entries(current: &mut Vec<OwnedImage>, loaded: Vec<OwnedImage>) {
    for entry in loaded {
        match current
            .iter_mut()
            .find(|existing| existing.image.instance == entry.image.instance)
        {
            Some(existing) => {
                if entry.uploaded_at >= existing.uploaded_at {
                    *existing = entry;
                }
            }
            None => current.push(entry),
        }
    }
    enforce_budget(current);
}

fn enforce_budget(entries: &mut Vec<OwnedImage>) {
    loop {
        let total: usize = entries
            .iter()
            .map(|entry| {
                entry.state.len()
                    + entry.chunks.iter().map(|chunk| chunk.state.len()).sum::<usize>()
            })
            .sum();
        if total <= MAX_OWNED_BYTES || entries.len() <= 1 {
            break;
        }
        entries.remove(0);
    }
}

/// Write the index to its own key when it changed. The caller saves the board
/// map separately.
pub async fn save_if_dirty() -> Result<(), String> {
    if !*BOARDS_LOADED.read() {
        return Ok(());
    }
    if !OWNED_IMAGES_DIRTY.swap(false, Ordering::SeqCst) {
        return Ok(());
    }
    // Another tab may have recorded an image since this one loaded the index.
    // Merge before writing so its entry is not replaced.
    let stored = match send_delegate_request(ChatDelegateRequestMsg::GetRequest {
        key: ChatDelegateKey::new(OWNED_IMAGES_STORAGE_KEY.to_vec()),
    })
    .await
    {
        Ok(ChatDelegateResponseMsg::GetResponse {
            value: Some(bytes), ..
        }) => ciborium::from_reader::<Vec<OwnedImage>, _>(&bytes[..]).ok(),
        _ => None,
    };
    if let Some(stored) = stored {
        BOARDS.with_mut(|boards| merge_entries(&mut boards.owned_images, stored));
    }
    let value = {
        let owned = BOARDS.read().owned_images.clone();
        let mut buffer = Vec::new();
        if let Err(error) = ciborium::ser::into_writer(&owned, &mut buffer) {
            OWNED_IMAGES_DIRTY.store(true, Ordering::SeqCst);
            return Err(format!("Failed to serialize owned images: {error}"));
        }
        buffer
    };
    let request = ChatDelegateRequestMsg::StoreRequest {
        key: ChatDelegateKey::new(OWNED_IMAGES_STORAGE_KEY.to_vec()),
        value,
    };
    match send_delegate_request(request).await {
        Ok(ChatDelegateResponseMsg::StoreResponse { result, .. }) => {
            if result.is_err() {
                OWNED_IMAGES_DIRTY.store(true, Ordering::SeqCst);
            }
            result
        }
        Ok(other) => {
            OWNED_IMAGES_DIRTY.store(true, Ordering::SeqCst);
            Err(format!("Unexpected response: {other:?}"))
        }
        Err(error) => {
            OWNED_IMAGES_DIRTY.store(true, Ordering::SeqCst);
            Err(error)
        }
    }
}

/// Keep the raw state of a fresh upload so it can be renewed and reused.
pub fn record(image: &ImageRef, copy: BlobCopy) {
    if copy.state.is_empty() {
        return;
    }
    let entry = OwnedImage {
        image: image.clone(),
        parameters: copy.parameters,
        state: copy.state,
        chunks: copy
            .chunks
            .into_iter()
            .map(|chunk| OwnedChunkCopy {
                parameters: chunk.parameters,
                state: chunk.state,
            })
            .collect(),
        uploaded_at: now_ms(),
        renewed_at: now_ms(),
    };
    BOARDS.with_mut(|boards| {
        boards
            .owned_images
            .retain(|existing| existing.image.instance != image.instance);
        boards.owned_images.push(entry);
        // Keep the newest entries inside the byte budget.
        enforce_budget(&mut boards.owned_images);
    });
    OWNED_IMAGES_DIRTY.store(true, Ordering::SeqCst);
    persist();
}

/// Newest first.
pub fn list() -> Vec<OwnedImage> {
    let mut owned = BOARDS.read().owned_images.clone();
    owned.sort_by_key(|entry| std::cmp::Reverse(entry.uploaded_at));
    owned
}

/// Plain bytes of a single-contract upload this device made, for editing a
/// reused image. Sealed payloads are decrypted with any board/secret key the
/// client holds. Manifests return `None` (their chunks are not kept locally).
pub fn plaintext_for(instance: &[u8; 32]) -> Option<(Vec<u8>, String)> {
    let owned = BOARDS
        .read()
        .owned_images
        .iter()
        .find(|entry| entry.image.instance == *instance)?
        .clone();
    let state: plaza_blob_core::BlobStateV1 =
        ciborium::from_reader(&owned.state[..]).ok()?;
    if !state.chunks.is_empty() || state.data.is_empty() {
        return None;
    }
    let mut data = state.data.clone();
    if let Some(nonce) = state.nonce {
        let mut candidates = Vec::new();
        for board in BOARDS.read().map.values() {
            candidates.extend(board.image_secret_candidates());
        }
        let mut unlocked = None;
        for (key, version) in candidates {
            let version = state.secret_version.unwrap_or(version);
            if let Ok(plain) =
                crate::util::ecies::decrypt_with_symmetric_key(&key, &data, &nonce, version)
            {
                unlocked = Some(plain);
                break;
            }
        }
        data = unlocked?;
    }
    Some((data, owned.image.mime.clone()))
}

/// Own uploads no board refers to anymore, older than `min_age_ms`.
pub fn unreferenced(min_age_ms: i64) -> Vec<OwnedImage> {
    let mut referenced = std::collections::HashSet::new();
    for board in BOARDS.read().map.values() {
        for message in &board.board_state.recent_messages.messages {
            for image in &message.message.images {
                referenced.insert(image.instance);
                if let Some(thumb) = image.thumb.as_ref() {
                    referenced.insert(thumb.instance);
                }
            }
        }
        for pending in &board.pending_uploads {
            if let Some(image) = pending.image.as_ref() {
                referenced.insert(image.instance);
            }
        }
        if let Some(draft) = board.pending_send.as_ref() {
            for image in &draft.images {
                referenced.insert(image.instance);
            }
        }
    }
    let now = now_ms();
    BOARDS
        .read()
        .owned_images
        .iter()
        .filter(|entry| {
            !referenced.contains(&entry.image.instance)
                && now - entry.uploaded_at >= min_age_ms
        })
        .cloned()
        .collect()
}

/// Retire own uploads no board refers to and drop them from the index.
pub fn retire_unused() {
    let entries = unreferenced(60 * 60 * 1000);
    if entries.is_empty() {
        return;
    }
    spawn_local(async move {
        for entry in entries {
            match crate::util::images::retire_in_contract(entry.image.instance).await {
                Ok(()) => {
                    BOARDS.with_mut(|boards| {
                        boards
                            .owned_images
                            .retain(|owned| owned.image.instance != entry.image.instance);
                    });
                    OWNED_IMAGES_DIRTY.store(true, Ordering::SeqCst);
                }
                Err(error) => {
                    warn!(
                        "Could not retire unused image {:?}: {error}",
                        entry.image.instance
                    );
                }
            }
        }
        persist();
    });
}

/// Renew the uploads that have not been touched for a week. Runs once per load.
pub fn renew_if_due() {
    if RENEW_STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    renew_due_entries();
}

/// Renewal check for the index, also run once it finishes loading.
fn renew_due_entries() {
    let now = now_ms();
    let due: Vec<OwnedImage> = BOARDS
        .read()
        .owned_images
        .iter()
        .filter(|entry| now - entry.renewed_at >= RENEW_AFTER_MS)
        .cloned()
        .collect();
    for entry in due {
        spawn_local(async move {
            renew_one(entry, false).await;
        });
    }
}

/// Renew one upload now, for the manual action.
pub fn renew_now(instance: [u8; 32]) {
    let entry = BOARDS
        .read()
        .owned_images
        .iter()
        .find(|entry| entry.image.instance == instance)
        .cloned();
    if let Some(entry) = entry {
        spawn_local(async move {
            renew_one(entry, true).await;
        });
    }
}

/// Renew one upload. `announce` is set for the manual action; the automatic
/// pass only reports failures, so a page load does not fill the screen with
/// one toast per image.
async fn renew_one(entry: OwnedImage, announce: bool) {
    for chunk in &entry.chunks {
        if let Err(error) = put_raw_blob(&chunk.parameters, &chunk.state).await {
            warn!("Could not renew a chunk of {:?}: {error}", entry.image.instance);
            crate::components::app::toasts::show_error(format!(
                "Could not renew the image: {error}"
            ));
            return;
        }
        // Give the node a moment between contracts.
        crate::util::sleep(Duration::from_millis(200)).await;
    }
    if let Err(error) = put_raw_blob(&entry.parameters, &entry.state).await {
        warn!("Could not renew image {:?}: {error}", entry.image.instance);
        crate::components::app::toasts::show_error(format!(
            "Could not renew the image: {error}"
        ));
        return;
    }
    BOARDS.with_mut(|boards| {
        if let Some(existing) = boards
            .owned_images
            .iter_mut()
            .find(|owned| owned.image.instance == entry.image.instance)
        {
            existing.renewed_at = now_ms();
        }
    });
    OWNED_IMAGES_DIRTY.store(true, Ordering::SeqCst);
    persist();
    info!("Renewed image {:?}", entry.image.instance);
    if announce {
        crate::components::app::toasts::show("Image renewed on the network.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(instance: u8, uploaded_at: i64, state_len: usize) -> OwnedImage {
        OwnedImage {
            image: ImageRef {
                instance: [instance; 32],
                sha256: [0u8; 32],
                mime: "image/png".to_string(),
                width: 1,
                height: 1,
                bytes: 1,
                alt: String::new(),
                display: 0,
                sealed: false,
                animated: false,
                nsfw: false,
                thumb: None,
                placement: Default::default(),
                align: Default::default(),
            },
            parameters: Vec::new(),
            state: vec![0; state_len],
            chunks: Vec::new(),
            uploaded_at,
            renewed_at: uploaded_at,
        }
    }

    #[test]
    fn merging_keeps_one_fresh_copy_per_image() {
        let mut current = vec![entry(1, 10, 4)];
        merge_entries(&mut current, vec![entry(1, 20, 4), entry(2, 5, 4)]);

        assert_eq!(current.len(), 2);
        assert_eq!(current[0].uploaded_at, 20);
        assert_eq!(current[1].image.instance, [2u8; 32]);
    }

    #[test]
    fn the_byte_budget_drops_the_oldest_entries() {
        let half = MAX_OWNED_BYTES / 2;
        let mut current = vec![entry(1, 1, half), entry(2, 2, half)];
        merge_entries(&mut current, vec![entry(3, 3, half)]);

        assert_eq!(current.len(), 2);
        assert_eq!(current[0].image.instance, [2u8; 32]);
        assert_eq!(current[1].image.instance, [3u8; 32]);
    }
}
