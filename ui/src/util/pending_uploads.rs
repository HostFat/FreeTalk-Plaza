//! The pending image uploads of the current board.
//!
//! The records stay in `BoardData` in memory, but their bytes are stored under
//! `pending_uploads_data` instead of the board map: the sandboxed iframe of the
//! Freenet shell denies IndexedDB and localStorage, and a 24 MiB queue inside
//! `boards_data` would make the board list slow to load.

use crate::board_data::PendingUpload;
use crate::components::app::chat_delegate::{
    save_boards_to_delegate, send_delegate_request, PENDING_UPLOADS_STORAGE_KEY,
};
use crate::components::app::{BOARDS, BOARDS_LOADED, CURRENT_BOARD};
use dioxus::logger::tracing::{info, warn};
use dioxus::prelude::*;
use ed25519_dalek::VerifyingKey;
use plaza_core::chat_delegate::{
    ChatDelegateKey, ChatDelegateRequestMsg, ChatDelegateResponseMsg,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use wasm_bindgen_futures::spawn_local;

/// Bytes we keep in the delegate for pending uploads, per board. Larger
/// uploads stay in memory only and are reported to the composer.
pub const MAX_PENDING_BYTES: usize = 24 * 1024 * 1024;

/// The queue changed and `pending_uploads_data` has to be rewritten.
static PENDING_UPLOADS_DIRTY: AtomicBool = AtomicBool::new(false);
/// The board map still carried the queue when it was loaded.
static LEGACY_PENDING: AtomicBool = AtomicBool::new(false);
/// The separate key has been read at least once.
static PENDING_LOADED: AtomicBool = AtomicBool::new(false);

pub fn mark_dirty() {
    PENDING_UPLOADS_DIRTY.store(true, Ordering::SeqCst);
}

/// Note that the board blob carried a queue (older versions).
pub fn note_legacy(has_entries: bool) {
    if has_entries {
        LEGACY_PENDING.store(true, Ordering::SeqCst);
        mark_dirty();
    }
}

pub fn take_legacy() -> bool {
    LEGACY_PENDING.swap(false, Ordering::SeqCst)
}

/// Merge the queues loaded from their own key into the boards. Existing
/// records win; entries from another tab are added when the cap allows.
pub fn apply_loaded(loaded: Option<HashMap<VerifyingKey, Vec<PendingUpload>>>) {
    PENDING_LOADED.store(true, Ordering::SeqCst);
    let Some(loaded) = loaded else { return };
    let entry_count: usize = loaded.values().map(Vec::len).sum();
    info!(
        "Loading {entry_count} pending upload(s) for {} board(s)",
        loaded.len()
    );
    BOARDS.with_mut(|boards| {
        for (key, entries) in loaded {
            let Some(board) = boards.map.get_mut(&key) else {
                continue;
            };
            for entry in entries {
                if board
                    .pending_uploads
                    .iter()
                    .any(|pending| pending.id == entry.id)
                {
                    continue;
                }
                let total: usize = board.pending_uploads.iter().map(|p| p.bytes.len()).sum();
                if total + entry.bytes.len() <= MAX_PENDING_BYTES {
                    board.pending_uploads.push(entry);
                }
            }
        }
    });
    let total: usize = BOARDS
        .read()
        .map
        .values()
        .map(|board| board.pending_uploads.len())
        .sum();
    info!("Pending upload queue now holds {total} record(s)");
}

/// Read the queue on demand. The composer calls this before opening so a
/// missed background load (or a queue written by another tab) does not hide
/// the uploads.
pub async fn ensure_loaded() {
    if PENDING_LOADED.load(Ordering::SeqCst) {
        return;
    }
    match send_delegate_request(ChatDelegateRequestMsg::GetRequest {
        key: ChatDelegateKey::new(PENDING_UPLOADS_STORAGE_KEY.to_vec()),
    })
    .await
    {
        Ok(ChatDelegateResponseMsg::GetResponse { value, .. }) => {
            let loaded = value.and_then(|bytes| {
                match ciborium::from_reader::<HashMap<VerifyingKey, Vec<PendingUpload>>, _>(
                    &bytes[..],
                ) {
                    Ok(queues) => Some(queues),
                    Err(error) => {
                        warn!("Could not decode the pending uploads: {error}");
                        None
                    }
                }
            });
            apply_loaded(loaded);
        }
        Ok(other) => warn!("Unexpected response for pending uploads: {other:?}"),
        Err(error) => warn!("Could not load the pending uploads: {error}"),
    }
}

/// Write the composer queues to their own key when they changed. The caller
/// saves the board map separately.
pub async fn save_if_dirty() -> Result<(), String> {
    if !*BOARDS_LOADED.read() {
        return Ok(());
    }
    if !PENDING_UPLOADS_DIRTY.swap(false, Ordering::SeqCst) {
        return Ok(());
    }
    // Another tab may have queued an image since this one loaded the store.
    let stored = match send_delegate_request(ChatDelegateRequestMsg::GetRequest {
        key: ChatDelegateKey::new(PENDING_UPLOADS_STORAGE_KEY.to_vec()),
    })
    .await
    {
        Ok(ChatDelegateResponseMsg::GetResponse {
            value: Some(bytes), ..
        }) => ciborium::from_reader::<HashMap<VerifyingKey, Vec<PendingUpload>>, _>(&bytes[..]).ok(),
        _ => None,
    };
    if let Some(stored) = stored {
        apply_loaded(Some(stored));
    }

    let value = {
        let queues: HashMap<VerifyingKey, Vec<PendingUpload>> = BOARDS
            .read()
            .map
            .iter()
            .filter(|(_, board)| !board.pending_uploads.is_empty())
            .map(|(key, board)| (*key, board.pending_uploads.clone()))
            .collect();
        let mut buffer = Vec::new();
        if let Err(error) = ciborium::ser::into_writer(&queues, &mut buffer) {
            mark_dirty();
            return Err(format!("Failed to serialize pending uploads: {error}"));
        }
        buffer
    };
    let request = ChatDelegateRequestMsg::StoreRequest {
        key: ChatDelegateKey::new(PENDING_UPLOADS_STORAGE_KEY.to_vec()),
        value,
    };
    match send_delegate_request(request).await {
        Ok(ChatDelegateResponseMsg::StoreResponse { result, .. }) => {
            if result.is_err() {
                mark_dirty();
            }
            result
        }
        Ok(other) => {
            mark_dirty();
            Err(format!("Unexpected response: {other:?}"))
        }
        Err(error) => {
            mark_dirty();
            Err(error)
        }
    }
}

/// Insert the placeholder for a new attachment immediately, before the file is
/// prepared, so a Send during preparation still has a record to point at.
pub fn insert(record: PendingUpload) {
    let Some(key) = CURRENT_BOARD.read().owner_key else {
        return;
    };
    BOARDS.with_mut(|boards| {
        let Some(board) = boards.map.get_mut(&key) else {
            return;
        };
        if board
            .pending_uploads
            .iter()
            .any(|pending| pending.id == record.id)
        {
            return;
        }
        let total: usize = board
            .pending_uploads
            .iter()
            .map(|pending| pending.bytes.len())
            .sum();
        if total + record.bytes.len() <= MAX_PENDING_BYTES {
            board.pending_uploads.push(record);
            crate::components::app::PENDING_QUEUE_FULL.with_mut(|full| *full = false);
        } else {
            warn!("Pending image kept in memory only: the delegate queue is full");
            crate::components::app::PENDING_QUEUE_FULL.with_mut(|full| *full = true);
        }
    });
    mark_dirty();
}

/// Fill in the prepared bytes of a placeholder.
pub fn update(id: &str, change: impl FnOnce(&mut PendingUpload)) {
    let Some(key) = CURRENT_BOARD.read().owner_key else {
        return;
    };
    BOARDS.with_mut(|boards| {
        if let Some(board) = boards.map.get_mut(&key) {
            if let Some(pending) = board.pending_uploads.iter_mut().find(|pending| pending.id == id) {
                change(pending);
            }
        }
    });
    mark_dirty();
}

/// Write the current board, including the pending uploads, to the delegate.
pub async fn persist_now() -> Result<(), String> {
    save_boards_to_delegate().await
}

pub fn remove(id: &str) {
    let Some(key) = CURRENT_BOARD.read().owner_key else {
        return;
    };
    BOARDS.with_mut(|boards| {
        if let Some(board) = boards.map.get_mut(&key) {
            board.pending_uploads.retain(|pending| pending.id != id);
        }
    });
    mark_dirty();
    persist();
}

/// Drop several queued uploads after their post is published.
pub fn remove_many(ids: &[String]) {
    let Some(key) = CURRENT_BOARD.read().owner_key else {
        return;
    };
    BOARDS.with_mut(|boards| {
        if let Some(board) = boards.map.get_mut(&key) {
            board
                .pending_uploads
                .retain(|pending| !ids.iter().any(|id| id == &pending.id));
        }
    });
    mark_dirty();
    persist();
}

/// Drop one queued upload of a board that is not necessarily current, used by
/// the background resume.
pub fn remove_for(key: &ed25519_dalek::VerifyingKey, id: &str) {
    BOARDS.with_mut(|boards| {
        if let Some(board) = boards.map.get_mut(key) {
            board.pending_uploads.retain(|pending| pending.id != id);
        }
    });
    mark_dirty();
    persist();
}

/// Remember the blob of a queued upload of any board, used by the resume.
pub fn set_image_for(
    key: &ed25519_dalek::VerifyingKey,
    id: &str,
    image: &plaza_core::board_state::images::ImageRef,
) {
    BOARDS.with_mut(|boards| {
        if let Some(board) = boards.map.get_mut(key) {
            if let Some(pending) = board.pending_uploads.iter_mut().find(|pending| pending.id == id) {
                pending.image = Some(image.clone());
            }
        }
    });
    mark_dirty();
    persist();
}

/// Remember the blob of a queued upload so a reload does not PUT it again.
pub fn set_image(id: &str, image: &plaza_core::board_state::images::ImageRef) {
    let Some(key) = CURRENT_BOARD.read().owner_key else {
        return;
    };
    BOARDS.with_mut(|boards| {
        if let Some(board) = boards.map.get_mut(&key) {
            if let Some(pending) = board.pending_uploads.iter_mut().find(|pending| pending.id == id) {
                pending.image = Some(image.clone());
            }
        }
    });
    mark_dirty();
    persist();
}

pub fn list() -> Vec<PendingUpload> {
    let Some(key) = CURRENT_BOARD.read().owner_key else {
        return Vec::new();
    };
    BOARDS
        .read()
        .map
        .get(&key)
        .map(|board| board.pending_uploads.clone())
        .unwrap_or_default()
}

fn persist() {
    spawn_local(async {
        if let Err(error) = save_boards_to_delegate().await {
            warn!("Could not persist the pending image queue: {error}");
        }
    });
}
