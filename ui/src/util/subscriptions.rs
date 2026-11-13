//! Section subscriptions. A followed section lists new topics in the local
//! notifications view.

use crate::components::app::{chat_delegate::save_boards_to_delegate, BOARDS, CURRENT_BOARD};
use dioxus::prelude::*;
use plaza_core::board_state::message::MessageId;
use wasm_bindgen_futures::spawn_local;

/// Sections followed on the current board.
pub fn followed() -> Vec<MessageId> {
    let Some(key) = CURRENT_BOARD.read().owner_key else {
        return Vec::new();
    };
    BOARDS
        .read()
        .map
        .get(&key)
        .map(|board| board.subscribed_categories.clone())
        .unwrap_or_default()
}

pub fn is_followed(category_id: MessageId) -> bool {
    followed().contains(&category_id)
}

/// Follow or unfollow a section and persist the local preference.
pub fn set_followed(category_id: MessageId, follow: bool) {
    let Some(key) = CURRENT_BOARD.read().owner_key else {
        return;
    };
    let mut changed = false;
    BOARDS.with_mut(|boards| {
        let Some(board) = boards.map.get_mut(&key) else {
            return;
        };
        let already = board.subscribed_categories.contains(&category_id);
        if follow && !already {
            board.subscribed_categories.push(category_id);
            changed = true;
        } else if !follow && already {
            board.subscribed_categories.retain(|id| *id != category_id);
            changed = true;
        }
    });
    if changed {
        spawn_local(async {
            let _ = save_boards_to_delegate().await;
        });
    }
}
