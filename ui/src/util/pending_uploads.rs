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
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Mutex};
use wasm_bindgen_futures::spawn_local;

/// The stored value of `pending_uploads_data`.
///
/// `removed` are tombstones: the cross-tab merge must not re-add an upload a
/// tab deleted. They are cheap and kept, so a tab that still has the record in
/// memory cannot put it back after another tab removed it.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct PendingUploadsStoreV1 {
    #[serde(default)]
    pub queues: HashMap<VerifyingKey, Vec<PendingUpload>>,
    #[serde(default)]
    pub removed: HashMap<VerifyingKey, Vec<String>>,
}

/// Deleted ids, in memory, until they are written with the rest of the store.
static REMOVED: LazyLock<Mutex<HashMap<VerifyingKey, HashSet<String>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn lock_removed() -> std::sync::MutexGuard<'static, HashMap<VerifyingKey, HashSet<String>>> {
    REMOVED.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn is_removed(board: &VerifyingKey, id: &str) -> bool {
    lock_removed()
        .get(board)
        .is_some_and(|ids| ids.contains(id))
}

fn note_removed(board: &VerifyingKey, id: &str) {
    lock_removed()
        .entry(*board)
        .or_default()
        .insert(id.to_string());
}

fn clear_removed(board: &VerifyingKey, id: &str) {
    if let Some(ids) = lock_removed().get_mut(board) {
        ids.remove(id);
    }
}

/// Decode the current envelope, or the raw map written before tombstones.
///
/// Try the old raw map first: a struct decode accepts a map whose fields are
/// missing because both fields default, so the envelope would silently swallow
/// an old value.
pub fn decode_store(bytes: &[u8]) -> Option<PendingUploadsStoreV1> {
    if let Ok(queues) =
        ciborium::from_reader::<HashMap<VerifyingKey, Vec<PendingUpload>>, _>(bytes)
    {
        return Some(PendingUploadsStoreV1 {
            queues,
            removed: HashMap::new(),
        });
    }
    match ciborium::from_reader::<PendingUploadsStoreV1, _>(bytes) {
        Ok(store) => Some(store),
        Err(error) => {
            warn!("Could not decode the pending uploads: {error}");
            None
        }
    }
}

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

/// Merge the stored queues and tombstones into the boards. Existing records
/// win; entries from another tab are added when the cap allows.
pub fn apply_store(store: Option<PendingUploadsStoreV1>) {
    PENDING_LOADED.store(true, Ordering::SeqCst);
    let Some(store) = store else { return };
    let entry_count: usize = store.queues.values().map(Vec::len).sum();
    info!(
        "Loading {entry_count} pending upload(s) for {} board(s)",
        store.queues.len()
    );
    // Remember the tombstones first, then use them to drop records that are
    // still in this tab's memory.
    {
        let mut removed = lock_removed();
        for (key, ids) in &store.removed {
            let set = removed.entry(*key).or_default();
            for id in ids {
                set.insert(id.clone());
            }
        }
    }
    BOARDS.with_mut(|boards| {
        for (key, entries) in &store.queues {
            let Some(board) = boards.map.get_mut(key) else {
                continue;
            };
            board.pending_uploads.retain(|pending| !is_removed(key, &pending.id));
            for entry in entries {
                if board
                    .pending_uploads
                    .iter()
                    .any(|pending| pending.id == entry.id)
                {
                    continue;
                }
                if is_removed(key, &entry.id) {
                    continue;
                }
                let total: usize = board.pending_uploads.iter().map(|p| p.bytes.len()).sum();
                if total + entry.bytes.len() <= MAX_PENDING_BYTES {
                    board.pending_uploads.push(entry.clone());
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
            let store = value.and_then(|bytes| decode_store(&bytes));
            apply_store(store);
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
        }) => decode_store(&bytes),
        _ => None,
    };
    if stored.is_some() {
        apply_store(stored);
    }

    let value = {
        let removed: HashMap<VerifyingKey, Vec<String>> = lock_removed()
            .iter()
            .map(|(key, ids)| (*key, ids.iter().cloned().collect()))
            .collect();
        let queues: HashMap<VerifyingKey, Vec<PendingUpload>> = BOARDS
            .read()
            .map
            .iter()
            .filter_map(|(key, board)| {
                let gone = removed.get(key);
                let entries: Vec<PendingUpload> = board
                    .pending_uploads
                    .iter()
                    .filter(|pending| gone.map_or(true, |ids| !ids.contains(&pending.id)))
                    .cloned()
                    .collect();
                if entries.is_empty() {
                    None
                } else {
                    Some((*key, entries))
                }
            })
            .collect();
        let store = PendingUploadsStoreV1 { queues, removed };
        let mut buffer = Vec::new();
        if let Err(error) = ciborium::ser::into_writer(&store, &mut buffer) {
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
    clear_removed(&key, &record.id);
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
    note_removed(&key, id);
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
    for id in ids {
        note_removed(&key, id);
    }
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
    note_removed(key, id);
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn entry(id: &str) -> PendingUpload {
        PendingUpload {
            id: id.to_string(),
            name: "photo.png".to_string(),
            alt: "photo".to_string(),
            nsfw: false,
            mime: "image/png".to_string(),
            width: 2,
            height: 2,
            animated: false,
            bytes: vec![1, 2, 3],
            secret: None,
            image: None,
        }
    }

    #[test]
    fn decode_reads_the_envelope_and_the_old_map() {
        let board = SigningKey::generate(&mut rand::thread_rng()).verifying_key();
        let envelope = PendingUploadsStoreV1 {
            queues: HashMap::from([(board, vec![entry("queued")])]),
            removed: HashMap::from([(board, vec!["gone".to_string()])]),
        };
        let mut buffer = Vec::new();
        ciborium::ser::into_writer(&envelope, &mut buffer).unwrap();
        let decoded = decode_store(&buffer).expect("envelope decodes");
        assert_eq!(decoded.queues[&board].len(), 1);
        assert_eq!(decoded.removed[&board], vec!["gone".to_string()]);

        // Before tombstones the value was a raw board -> queue map.
        let raw: HashMap<VerifyingKey, Vec<PendingUpload>> =
            HashMap::from([(board, vec![entry("old")])]);
        let mut raw_buffer = Vec::new();
        ciborium::ser::into_writer(&raw, &mut raw_buffer).unwrap();
        let decoded = decode_store(&raw_buffer).expect("old map decodes");
        assert_eq!(decoded.queues[&board].len(), 1);
        assert!(decoded.removed.is_empty());
    }
}
