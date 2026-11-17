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
pub const MAX_PENDING_BYTES: usize = 4 * 1024 * 1024;

pub fn queue(record: PendingUpload) {
    let Some(key) = CURRENT_BOARD.read().owner_key else {
        return;
    };
    let mut stored = false;
    BOARDS.with_mut(|boards| {
        let Some(board) = boards.map.get_mut(&key) else {
            return;
        };
        let total: usize = board
            .pending_uploads
            .iter()
            .map(|pending| pending.bytes.len())
            .sum();
        if total + record.bytes.len() <= MAX_PENDING_BYTES {
            board.pending_uploads.push(record);
            stored = true;
        }
    });
    if stored {
        persist();
    } else {
        warn!("Pending image kept in memory only: the delegate queue is full");
    }
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
