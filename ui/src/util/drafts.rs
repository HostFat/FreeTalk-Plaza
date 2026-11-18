//! The composer's unsent post, kept in the local `BoardData` and persisted to
//! the delegate store so a reload does not lose it.

use crate::board_data::ComposerDraft;
use crate::components::app::{chat_delegate::save_boards_to_delegate, BOARDS, CURRENT_BOARD};
use crate::util::messaging::ReplyContext;
use dioxus::prelude::*;
use wasm_bindgen_futures::spawn_local;

/// The saved draft for the current board, if any.
pub fn load() -> Option<ComposerDraft> {
    let key = CURRENT_BOARD.read().owner_key?;
    let draft = BOARDS.read().map.get(&key)?.draft.clone();
    draft.filter(|draft| !draft.title.is_empty() || !draft.text.is_empty())
}

/// Replace the saved draft. Returns true when the stored value changed.
pub fn store(title: &str, text: &str, reply: Option<&ReplyContext>) -> bool {
    let Some(key) = CURRENT_BOARD.read().owner_key else {
        return false;
    };
    let draft = if title.is_empty() && text.is_empty() {
        None
    } else {
        Some(ComposerDraft {
            title: title.to_string(),
            text: text.to_string(),
            reply_to: reply.map(|reply| reply.message_id),
            reply_author: reply
                .map(|reply| reply.author_name.clone())
                .unwrap_or_default(),
            reply_preview: reply
                .map(|reply| reply.content_preview.clone())
                .unwrap_or_default(),
            updated_at: chrono::Utc::now().timestamp_millis(),
        })
    };

    let mut changed = false;
    BOARDS.with_mut(|boards| {
        if let Some(board) = boards.map.get_mut(&key) {
            if board.draft != draft {
                board.draft = draft;
                changed = true;
            }
        }
    });
    changed
}

/// Drop the saved draft, for example after the post was sent.
pub fn clear() {
    store("", "", None);
}

/// The drafts saved for later, newest first.
pub fn list() -> Vec<ComposerDraft> {
    let Some(key) = CURRENT_BOARD.read().owner_key else {
        return Vec::new();
    };
    BOARDS
        .read()
        .map
        .get(&key)
        .map(|board| board.drafts.clone())
        .unwrap_or_default()
}

/// Add the current composer content to the saved list. The working draft keeps
/// being updated as usual; this is a snapshot the user can return to.
pub fn save_current(title: &str, text: &str, reply: Option<&ReplyContext>) -> bool {
    if title.is_empty() && text.is_empty() {
        return false;
    }
    let Some(key) = CURRENT_BOARD.read().owner_key else {
        return false;
    };
    let draft = ComposerDraft {
        title: title.to_string(),
        text: text.to_string(),
        reply_to: reply.map(|reply| reply.message_id),
        reply_author: reply
            .map(|reply| reply.author_name.clone())
            .unwrap_or_default(),
        reply_preview: reply
            .map(|reply| reply.content_preview.clone())
            .unwrap_or_default(),
        updated_at: chrono::Utc::now().timestamp_millis(),
    };
    let mut changed = false;
    BOARDS.with_mut(|boards| {
        if let Some(board) = boards.map.get_mut(&key) {
            board.drafts.insert(0, draft);
            board.drafts.truncate(20);
            changed = true;
        }
    });
    changed
}

/// Read one saved draft without removing it.
pub fn get(index: usize) -> Option<ComposerDraft> {
    list().get(index).cloned()
}

/// Remove one saved draft.
pub fn remove(index: usize) {
    let Some(key) = CURRENT_BOARD.read().owner_key else {
        return;
    };
    BOARDS.with_mut(|boards| {
        if let Some(board) = boards.map.get_mut(&key) {
            if index < board.drafts.len() {
                board.drafts.remove(index);
            }
        }
    });
}

/// Write the delegate store. Call after `store` when the edit should survive a
/// reload; the composer debounces this while typing.
pub fn persist() {
    spawn_local(async {
        let _ = save_boards_to_delegate().await;
    });
}
