//! Browser notification support for new chat messages.
//!
//! Sends desktop notifications when:
//! - Document is not visible (tab hidden or window not focused)
//! - Message is from another user (not self)
//! - Board is not currently active
//! - Permission has been granted

use crate::components::app::{BOARDS, CURRENT_BOARD};
use dioxus::logger::tracing::{debug, info, warn};
use dioxus::prelude::*;
use ed25519_dalek::VerifyingKey;
use plaza_core::board_state::member::MemberId;
use std::collections::HashSet;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Notification, NotificationOptions, NotificationPermission, VisibilityState};

const NOTIFICATION_PROMPTED_KEY: &str = "river_notification_prompted";

/// Test function to verify browser notifications work at all.
/// Can be called from browser console via: river_test_notification()
#[wasm_bindgen]
pub fn river_test_notification() {
    web_sys::console::log_1(&wasm_bindgen::JsValue::from_str(
        "[River] Testing notification system...",
    ));

    let permission = get_permission();
    web_sys::console::log_1(&wasm_bindgen::JsValue::from_str(&format!(
        "[River] Current permission: {:?}",
        permission
    )));

    if permission == NotificationPermission::Granted {
        let options = NotificationOptions::new();
        options.set_body("If you see this, notifications are working!");

        match Notification::new_with_options("River Test Notification", &options) {
            Ok(_notification) => {
                web_sys::console::log_1(&wasm_bindgen::JsValue::from_str(
                    "[River] Test notification created successfully! You should see it now.",
                ));
            }
            Err(e) => {
                web_sys::console::error_1(&wasm_bindgen::JsValue::from_str(&format!(
                    "[River] Failed to create test notification: {:?}",
                    e
                )));
            }
        }
    } else if permission == NotificationPermission::Default {
        web_sys::console::log_1(&wasm_bindgen::JsValue::from_str(
            "[River] Permission not yet granted. Requesting permission...",
        ));
        wasm_bindgen_futures::spawn_local(async {
            let granted = request_permission().await;
            if granted {
                web_sys::console::log_1(&wasm_bindgen::JsValue::from_str(
                    "[River] Permission granted! Run riverTestNotification() again to test.",
                ));
            } else {
                web_sys::console::log_1(&wasm_bindgen::JsValue::from_str(
                    "[River] Permission denied or dismissed.",
                ));
            }
        });
    } else {
        web_sys::console::log_1(&wasm_bindgen::JsValue::from_str(
            "[River] Notifications are denied. Please enable them in browser settings.",
        ));
    }
}

/// Tracks which boards have completed initial sync (don't notify for initial message load)
pub static INITIAL_SYNC_COMPLETE: GlobalSignal<HashSet<VerifyingKey>> = Global::new(HashSet::new);

/// Check if the document is currently visible and focused
pub fn is_document_visible() -> bool {
    if let Some(window) = web_sys::window() {
        if let Some(document) = window.document() {
            let is_visible = document.visibility_state() == VisibilityState::Visible;
            let has_focus = document.has_focus().unwrap_or(false);
            return is_visible && has_focus;
        }
    }
    // Default to visible to avoid spurious notifications
    true
}

/// Get current notification permission status
pub fn get_permission() -> NotificationPermission {
    Notification::permission()
}

/// Request notification permission from the user
/// Returns true if permission was granted
pub async fn request_permission() -> bool {
    match Notification::request_permission() {
        Ok(promise) => match JsFuture::from(promise).await {
            Ok(result) => {
                let permission_str = result.as_string().unwrap_or_default();
                info!("Notification permission result: {}", permission_str);
                permission_str == "granted"
            }
            Err(e) => {
                warn!("Failed to request notification permission: {:?}", e);
                false
            }
        },
        Err(e) => {
            warn!("Failed to request notification permission: {:?}", e);
            false
        }
    }
}

/// Check if we've already prompted the user for notification permission
fn has_prompted_for_permission() -> bool {
    if let Some(window) = web_sys::window() {
        if let Ok(Some(storage)) = window.local_storage() {
            return storage
                .get_item(NOTIFICATION_PROMPTED_KEY)
                .ok()
                .flatten()
                .is_some();
        }
    }
    false
}

/// Mark that we've prompted the user for notification permission
fn mark_prompted_for_permission() {
    if let Some(window) = web_sys::window() {
        if let Ok(Some(storage)) = window.local_storage() {
            let _ = storage.set_item(NOTIFICATION_PROMPTED_KEY, "true");
        }
    }
}

/// Request notification permission on first user message.
///
/// This follows best practices:
/// - Only prompts once per browser (persisted in localStorage)
/// - Respects if user already granted or denied permission
/// - Triggered by user action (sending a message) for better UX
pub fn request_permission_on_first_message() {
    let permission = get_permission();

    // Already have a definitive answer - don't prompt
    if permission == NotificationPermission::Granted {
        debug!("Notification permission already granted");
        return;
    }

    if permission == NotificationPermission::Denied {
        debug!("Notification permission already denied");
        return;
    }

    // Permission is "default" (not yet asked) - check if we've prompted before
    if has_prompted_for_permission() {
        debug!("Already prompted for notification permission previously");
        return;
    }

    // First time - request permission
    info!("Requesting notification permission on first message");
    mark_prompted_for_permission();

    wasm_bindgen_futures::spawn_local(async {
        let granted = request_permission().await;
        if granted {
            info!("User granted notification permission");
        } else {
            info!("User did not grant notification permission");
        }
    });
}

/// Show a notification for new messages in a board
///
/// # Arguments
/// * `board_key` - The board's owner verifying key
/// * `board_name` - Display name of the board
/// * `sender_name` - Name of the message sender
/// * `message_preview` - Truncated message content
pub fn show_notification(
    board_key: VerifyingKey,
    board_name: &str,
    sender_name: &str,
    message_preview: &str,
) {
    // Check permission
    let permission = get_permission();
    info!(
        "show_notification called for board '{}', permission: {:?}",
        board_name, permission
    );

    if permission == NotificationPermission::Denied {
        info!("Notifications denied by browser, skipping");
        return;
    }

    // If permission is default (not yet asked), request it first
    if permission == NotificationPermission::Default {
        let board_name = board_name.to_string();
        let sender_name = sender_name.to_string();
        let message_preview = message_preview.to_string();
        wasm_bindgen_futures::spawn_local(async move {
            let granted = request_permission().await;
            if granted {
                // Try again after permission granted
                create_notification_internal(
                    board_key,
                    &board_name,
                    &sender_name,
                    &message_preview,
                );
            }
        });
        return;
    }

    // Permission is granted, show notification
    create_notification_internal(board_key, board_name, sender_name, message_preview);
}

fn create_notification_internal(
    board_key: VerifyingKey,
    board_name: &str,
    sender_name: &str,
    message_preview: &str,
) {
    let body = format!("{}: {}", sender_name, message_preview);

    let options = NotificationOptions::new();
    options.set_body(&body);
    // Could add icon here: options.icon("/assets/plaza_logo.svg");

    match Notification::new_with_options(board_name, &options) {
        Ok(notification) => {
            // Set up click handler to focus window and switch to board
            let onclick = Closure::wrap(Box::new(move || {
                info!("Notification clicked, switching to board");

                // Switch to the board
                crate::components::app::select_board(Some(board_key));

                // Focus the window
                if let Some(window) = web_sys::window() {
                    let _ = window.focus();
                }
            }) as Box<dyn Fn()>);

            notification.set_onclick(Some(onclick.as_ref().unchecked_ref()));

            // Prevent the closure from being dropped
            onclick.forget();
        }
        Err(e) => {
            warn!("Failed to create notification: {:?}", e);
        }
    }
}

/// Mark a board as having completed initial sync
/// Should be called after first successful state load
pub fn mark_initial_sync_complete(board_key: &VerifyingKey) {
    INITIAL_SYNC_COMPLETE.write().insert(*board_key);
    info!(
        "Marked initial sync complete for board: {:?}",
        MemberId::from(*board_key)
    );
}
