//! The images this device uploaded: renewal and reuse.

use crate::board_data::{OwnedChunkCopy, OwnedImage};
use crate::components::app::chat_delegate::save_boards_to_delegate;
use crate::components::app::BOARDS;
use crate::util::images::{put_raw_blob, BlobCopy};
use dioxus::logger::tracing::{info, warn};
use dioxus::prelude::ReadableExt;
use plaza_core::board_state::images::ImageRef;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use wasm_bindgen_futures::spawn_local;

/// Bytes of raw blob state kept for renewal. Older uploads are dropped first.
pub const MAX_OWNED_BYTES: usize = 24 * 1024 * 1024;
/// A blob untouched for this long is put back on the network.
const RENEW_AFTER_MS: i64 = 7 * 24 * 60 * 60 * 1000;

static RENEW_STARTED: AtomicBool = AtomicBool::new(false);

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
        loop {
            let total: usize = boards
                .owned_images
                .iter()
                .map(|owned| {
                    owned.state.len()
                        + owned.chunks.iter().map(|chunk| chunk.state.len()).sum::<usize>()
                })
                .sum();
            if total <= MAX_OWNED_BYTES || boards.owned_images.len() <= 1 {
                break;
            }
            boards.owned_images.remove(0);
        }
    });
    persist();
}

/// Newest first.
pub fn list() -> Vec<OwnedImage> {
    let mut owned = BOARDS.read().owned_images.clone();
    owned.sort_by_key(|entry| std::cmp::Reverse(entry.uploaded_at));
    owned
}

/// Renew the uploads that have not been touched for a week. Runs once per load.
pub fn renew_if_due() {
    if RENEW_STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
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
            renew_one(entry).await;
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
            renew_one(entry).await;
        });
    }
}

async fn renew_one(entry: OwnedImage) {
    for chunk in &entry.chunks {
        if let Err(error) = put_raw_blob(&chunk.parameters, &chunk.state).await {
            warn!("Could not renew a chunk of {:?}: {error}", entry.image.instance);
            return;
        }
        // Give the node a moment between contracts.
        crate::util::sleep(Duration::from_millis(200)).await;
    }
    if let Err(error) = put_raw_blob(&entry.parameters, &entry.state).await {
        warn!("Could not renew image {:?}: {error}", entry.image.instance);
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
    persist();
    info!("Renewed image {:?}", entry.image.instance);
}
