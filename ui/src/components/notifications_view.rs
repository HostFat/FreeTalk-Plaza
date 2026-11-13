//! Local notifications: replies to my posts and mentions since the last visit.

use crate::components::app::chat_delegate::save_boards_to_delegate;
use crate::components::app::{Route, BOARDS, CURRENT_BOARD};
use crate::components::conversation::{get_all_messages, MessageData};
use crate::util::format_utc_as_local_time;
use dioxus::prelude::*;
use plaza_core::board_state::member::MemberId;
use std::collections::HashMap;
use wasm_bindgen_futures::spawn_local;

#[component]
pub fn NotificationsView() -> Element {
    let board = use_memo(move || {
        let current = CURRENT_BOARD.read().owner_key?;
        let boards = BOARDS.read();
        let board = boards.map.get(&current)?.clone();
        let self_id = MemberId::from(&board.self_sk.verifying_key());
        let messages = get_all_messages(
            &board.board_state.recent_messages,
            &board.board_state.member_info,
            self_id,
            &board.secrets,
            &board.category_secrets,
            &board.board_state.moderation,
        );
        let nickname = board
            .board_state
            .member_info
            .member_info
            .iter()
            .find(|info| info.member_info.member_id == self_id)
            .map(|info| info.member_info.preferred_nickname.to_string_lossy())
            .unwrap_or_default();
        Some((
            board.owner_vk,
            board.last_visit,
            self_id,
            nickname,
            messages,
        ))
    });

    let board_id = CURRENT_BOARD
        .read()
        .owner_key
        .map(|key| bs58::encode(key.as_bytes()).into_string())
        .unwrap_or_default();

    let Some((owner_vk, last_visit, self_id, nickname, messages)) = board.read().clone() else {
        return rsx! {};
    };

    let authors: HashMap<_, _> = messages
        .iter()
        .map(|message| (message.message_id, message.author_id))
        .collect();
    let mention = format!("@{}", nickname.to_lowercase());
    let mut notices: Vec<&MessageData> = messages
        .iter()
        .filter(|message| !message.is_category && message.author_id != self_id)
        .filter(|message| {
            let is_reply_to_me = message
                .reply_to_message_id
                .as_ref()
                .and_then(|target| authors.get(target))
                .map(|author| *author == self_id)
                .unwrap_or(false);
            let is_mention = !mention.trim().is_empty()
                && !nickname.is_empty()
                && message.content_text.to_lowercase().contains(&mention);
            (is_reply_to_me || is_mention) && message.time.timestamp_millis() > last_visit
        })
        .collect();
    notices.sort_by_key(|message| std::cmp::Reverse(message.time));

    rsx! {
        div { class: "flex-1 flex flex-col min-w-0 min-h-0 bg-bg",
            div { class: "flex items-center gap-2 px-6 py-3 border-b border-border",
                button {
                    r#type: "button",
                    class: "text-accent hover:text-accent/80 text-sm font-medium",
                    onclick: move |_| {
                        let target = format!("/board/{board_id}");
                        if let Some(window) = web_sys::window() {
                            let _ = window.location().set_hash(&target);
                        }
                    },
                    "← Back to posts"
                }
                h1 { class: "text-lg font-semibold text-text ml-2", "Notifications" }
                button {
                    r#type: "button",
                    class: "ml-auto px-3 py-1.5 bg-surface hover:bg-surface-hover text-text text-xs rounded-lg",
                    onclick: move |_| {
                        let now = chrono::Utc::now().timestamp_millis();
                        BOARDS.with_mut(|boards| {
                            if let Some(board) = boards.map.get_mut(&owner_vk) {
                                board.last_visit = now;
                            }
                        });
                        spawn_local(async {
                            let _ = save_boards_to_delegate().await;
                        });
                    },
                    "Mark all read"
                }
            }
            div { class: "flex-1 overflow-y-auto",
                div { class: "max-w-4xl mx-auto px-4 py-6",
                    if notices.is_empty() {
                        p { class: "text-text-muted text-sm", "No new notifications." }
                    } else {
                        div { class: "space-y-2",
                            for notice in notices.iter() {
                                {
                                    let post_id = notice.id_string();
                                    let board_id = board_id.clone();
                                    let nav = navigator();
                                    let timestamp = notice.time.timestamp_millis();
                                    rsx! {
                                        button {
                                            key: "{post_id}",
                                            r#type: "button",
                                            class: "w-full text-left bg-panel border border-border rounded-lg px-4 py-3 hover:border-accent/50 transition-colors",
                                            onclick: move |_| {
                                                nav.push(Route::Post {
                                                    board_id: board_id.clone(),
                                                    post_id: post_id.clone(),
                                                });
                                            },
                                            div { class: "flex items-baseline gap-2 flex-wrap",
                                                span { class: "text-base font-semibold text-text", "{notice.title_text}" }
                                                span { class: "text-xs text-text-muted", "by {notice.author_name}" }
                                                span { class: "text-xs text-text-muted", "· {format_utc_as_local_time(timestamp)}" }
                                            }
                                            if !notice.content_text.is_empty() {
                                                p { class: "text-xs text-text-muted mt-1 line-clamp-2", "{notice.content_text}" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
