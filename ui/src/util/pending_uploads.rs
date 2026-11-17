//! The pending image uploads of the current board.
//!
//! They live in `BoardData` and therefore in the delegate store: the sandboxed
//! iframe of the Freenet shell denies IndexedDB and localStorage, so the
//! delegate is the only storage that survives a reload here.

use crate::board_data::PendingUpload;
use crate::components::app::chat_delegate::save_boards_to_delegate;
use crate::components::app::{BOARDS, CURRENT_BOARD};
use dioxus::logger::tracing::warn;
use dioxus::prelude::*;
use wasm_bindgen_futures::spawn_local;

/// Bytes we keep in the delegate for pending uploads. Larger uploads stay in
/// memory only, to keep the board entry small.
pub const MAX_PENDING_BYTES: usize = 24 * 1024 * 1024;

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
