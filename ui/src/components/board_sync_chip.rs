//! Board-level sync state, visible on every page of the board.
//!
//! The chip waits for the node's answer: a local change keeps it on screen
//! until an UpdateResponse or PutResponse confirms the revision. A failed
//! request leaves a red chip with a retry that republishes the board.

use crate::components::app::sync_info::{retry_board_sync, BoardSyncStatus, SYNC_INFO};
use dioxus::prelude::*;
use ed25519_dalek::VerifyingKey;

#[component]
pub fn BoardSyncChip(board: VerifyingKey) -> Element {
    // Subscribe to the periodic tick: the "Syncing" window ends on time even
    // when no signal carrying the board changes.
    let _tick = crate::components::app::SYNC_TICK.read();
    let (status, syncing) = {
        let info = SYNC_INFO.read();
        (info.sync_status_of(&board), info.is_syncing(&board))
    };

    match status {
        Some(BoardSyncStatus::Error(message)) => rsx! {
            div {
                class: "flex items-center gap-2 rounded-lg border border-red-500/40 bg-red-500/10 px-2.5 py-1 text-xs text-red-300",
                span { title: "{message}", "Sync failed" }
                button {
                    r#type: "button",
                    class: "rounded bg-red-500/20 px-2 py-0.5 font-medium text-red-200 hover:bg-red-500/30 transition-colors",
                    onclick: move |_| retry_board_sync(board),
                    "Retry"
                }
            }
        },
        _ if syncing => rsx! {
            div {
                class: "flex items-center gap-2 rounded-lg border border-border bg-surface px-2.5 py-1 text-xs text-text-muted",
                title: "Waiting for the node to confirm the last change",
                span { class: "h-3 w-3 flex-shrink-0 animate-spin rounded-full border-2 border-text-muted border-t-transparent" }
                span { "Syncing…" }
            }
        },
        _ => rsx! {},
    }
}
