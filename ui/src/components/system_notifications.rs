//! Browser/system notifications for new replies and mentions.
//!
//! The in-app list is filtered by each board's notification mode. This bridge
//! shows the same notices as OS notifications when the tab is hidden, honours
//! the mode, and marks existing notices as seen on the first run so a reload
//! does not replay the whole list.

use crate::board_data::NotificationMode;
use crate::components::app::{BOARDS, BOARDS_LOADED, CURRENT_BOARD};
use crate::components::conversation::get_all_messages;
use crate::util::notifications::{self, NoticeKind};
use dioxus::prelude::*;
use plaza_core::board_state::member::MemberId;
use plaza_core::board_state::message::MessageId;
use std::collections::HashSet;

#[component]
pub fn SystemNotificationsBridge() -> Element {
    let mut seen = use_signal(HashSet::<MessageId>::new);
    let mut initialized = use_signal(|| false);

    use_effect(move || {
        if !*BOARDS_LOADED.read() {
            return;
        }
        let Some(key) = CURRENT_BOARD.read().owner_key else {
            return;
        };
        let board = BOARDS.read().map.get(&key).cloned();
        let Some(board) = board else {
            return;
        };
        let self_id = MemberId::from(&board.self_sk.verifying_key());
        let messages = get_all_messages(
            &board.board_state,
            self_id,
            &board.secrets,
            &board.category_secrets,
            &board.old_category_secrets,
        );
        let nickname = notifications::self_nickname(&board, self_id);
        // Collect everything for the seen set; the board mode only decides
        // which new notices become an OS notification.
        let notices = notifications::collect(
            &messages,
            self_id,
            &nickname,
            board.last_visit,
            &board.subscribed_categories,
            &board.read_categories,
            NotificationMode::All,
        );

        let first_run = !*initialized.peek();
        if first_run {
            *initialized.write() = true;
        }
        let mut known = seen.peek().clone();
        let mut pending: Vec<(String, String, MessageId)> = Vec::new();
        for notice in &notices {
            if !known.insert(notice.message.message_id) {
                continue;
            }
            let notify = !first_run
                && notifications::mode_allows(board.notification_mode, notice.kind);
            if notify {
                let title = match notice.kind {
                    NoticeKind::Reply => {
                        format!("New reply from {}", notice.message.author_name)
                    }
                    NoticeKind::Mention => {
                        format!("{} mentioned you", notice.message.author_name)
                    }
                    NoticeKind::Section => format!(
                        "New topic in {}",
                        notice.message.title_text
                    ),
                };
                let body = if notice.message.title_text.is_empty() {
                    notice.message.content_text.clone()
                } else {
                    notice.message.title_text.clone()
                };
                pending.push((title, body, notice.message.message_id));
            }
        }
        *seen.write() = known;

        #[cfg(target_arch = "wasm32")]
        {
            let Some(window) = web_sys::window() else {
                return;
            };
            let hidden = window
                .document()
                .map(|document| {
                    document.visibility_state() == web_sys::VisibilityState::Hidden
                })
                .unwrap_or(false);
            if !hidden {
                return;
            }
            let board_id = bs58::encode(key.as_bytes()).into_string();
            for (title, body, id) in pending {
                show_notification(&title, &body, &id.to_string(), &board_id, &id.to_string());
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = pending;
        }
    });

    rsx! {}
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn show_notification(
    title: &str,
    body: &str,
    tag: &str,
    board_id: &str,
    post_id: &str,
) {
    use wasm_bindgen::JsCast;

    if web_sys::Notification::permission() != web_sys::NotificationPermission::Granted {
        return;
    }
    let options = web_sys::NotificationOptions::new();
    options.set_body(body);
    options.set_tag(tag);
    let Ok(notification) = web_sys::Notification::new_with_options(title, &options) else {
        return;
    };
    let board_id = board_id.to_string();
    let post_id = post_id.to_string();
    let callback = wasm_bindgen::closure::Closure::wrap(Box::new(move || {
        let Some(window) = web_sys::window() else {
            return;
        };
        let base = window
            .location()
            .href()
            .ok()
            .and_then(|href| href.split('#').next().map(str::to_string))
            .unwrap_or_default();
        if base.is_empty() {
            return;
        }
        let href = format!("{base}#/board/{board_id}/post/{post_id}");
        if !crate::util::navigate_in_shell(&href) {
            let location = window.location();
            let _ = location.set_hash(&format!("/board/{board_id}/post/{post_id}"));
            let _ = location.reload();
        }
        let _ = window.focus();
    }) as Box<dyn FnMut()>);
    notification.set_onclick(Some(callback.as_ref().unchecked_ref()));
    callback.forget();
}
