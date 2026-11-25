//! Clear the boards and the image index stored on this device.
//!
//! The boards stay on the network. This is the recovery path when the stored
//! blob cannot be loaded, and the deliberate cleanup for a device that should
//! forget everything.

use crate::components::app::chat_delegate::reset_local_data;
use crate::components::app::{toasts, BOARDS, CURRENT_BOARD};
use std::time::Duration;

/// Ask for confirmation, then delete the local stores and reload.
pub fn confirm_and_reset(skip_legacy: bool) {
    let Some(window) = web_sys::window() else {
        return;
    };
    let confirmed = window
        .confirm_with_message(
            "Clear all boards and uploaded image data from this device? The boards stay online. To come back you need the identity token of each board or an invitation.",
        )
        .ok()
        .unwrap_or(false);
    if !confirmed {
        return;
    }

    wasm_bindgen_futures::spawn_local(async move {
        // Clear the chat delegate and write the skip-legacy marker first so a
        // slow or unreachable DM delegate cannot prevent the board reset.
        match reset_local_data(skip_legacy).await {
            Ok(()) => {
                if let Err(error) = crate::components::app::dm_delegate::reset().await {
                    dioxus::logger::tracing::warn!("Could not reset the DM delegate: {error}");
                }
                BOARDS.with_mut(|boards| {
                    boards.map.clear();
                    boards.owned_images.clear();
                    boards.removed.clear();
                    boards.blocked_image_hashes.clear();
                    boards.current_board_key = None;
                });
                crate::components::app::select_board(None);
                toasts::show("Local data cleared. Reloading…");
                // Let the delete requests and the toast reach the screen.
                crate::util::sleep(Duration::from_millis(1000)).await;
                if let Some(window) = web_sys::window() {
                    let _ = window.location().set_hash("/");
                    let _ = window.location().reload();
                }
            }
            Err(error) => {
                toasts::show_error(format!("Could not clear the local data: {error}"));
            }
        }
    });
}
