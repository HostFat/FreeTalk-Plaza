//! Local notifications: replies to my posts, mentions and new topics in
//! followed sections since the last visit.

use crate::components::app::chat_delegate::save_boards_to_delegate;
use crate::components::app::{Route, BOARDS, CURRENT_BOARD};
use crate::components::conversation::get_all_messages;
use crate::util::format_utc_as_local_time;
use crate::util::notifications::{self, NoticeKind};
use crate::util::subscriptions;
use dioxus::prelude::*;
use plaza_core::board_state::member::MemberId;
use wasm_bindgen_futures::spawn_local;

#[component]
pub fn NotificationsView() -> Element {
    let board = use_memo(move || {
        let current = CURRENT_BOARD.read().owner_key?;
        let boards = BOARDS.read();
        let board = boards.map.get(&current)?.clone();
        let self_id = MemberId::from(&board.self_sk.verifying_key());
        let messages = get_all_messages(
            &board.board_state,
            self_id,
            &board.secrets,
            &board.category_secrets,
        );
        let nickname = notifications::self_nickname(&board, self_id);
        Some((
            board.owner_vk,
            board.last_visit,
            self_id,
            nickname,
            messages,
            board.subscribed_categories.clone(),
            board.read_categories.clone(),
        ))
    });

    let board_id = CURRENT_BOARD
        .read()
        .owner_key
        .map(|key| bs58::encode(key.as_bytes()).into_string())
        .unwrap_or_default();

    let Some((owner_vk, last_visit, self_id, nickname, messages, subscribed, read_categories)) =
        board.read().clone()
    else {
        return rsx! {};
    };

    let notices = notifications::collect(
        &messages,
        self_id,
        &nickname,
        last_visit,
        &subscribed,
        &read_categories,
    );
    let mut followed_names: Vec<(_, String)> = messages
        .iter()
        .filter(|message| message.is_category && subscribed.contains(&message.message_id))
        .map(|message| {
            (
                message.message_id,
                message
                    .category_name
                    .clone()
                    .unwrap_or_else(|| "Section".to_string()),
            )
        })
        .collect();
    followed_names.sort_by(|a, b| a.1.cmp(&b.1));

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
                                // Followed sections use their own timestamps.
                                for index in 0..board.subscribed_categories.len() {
                                    let section = board.subscribed_categories[index];
                                    board.read_categories.insert(section, now);
                                }
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
                    div { class: "flex flex-wrap items-center gap-2 mb-5 text-xs",
                        span { class: "text-text-muted", "Following:" }
                        if followed_names.is_empty() {
                            span { class: "text-text-muted",
                                "open a section and press Follow to see its new topics here"
                            }
                        } else {
                            for (section_id, name) in followed_names.iter() {
                                button {
                                    key: "{section_id.0 .0}",
                                    r#type: "button",
                                    class: "flex items-center gap-1 px-2 py-1 bg-surface border border-border rounded-full text-text hover:border-accent/50 transition-colors",
                                    title: "Unfollow this section",
                                    onclick: {
                                        let section_id = *section_id;
                                        move |_| subscriptions::set_followed(section_id, false)
                                    },
                                    "{name}"
                                    span { class: "text-text-muted", "×" }
                                }
                            }
                        }
                    }
                    if notices.is_empty() {
                        p { class: "text-text-muted text-sm", "No new notifications." }
                    } else {
                        div { class: "space-y-2",
                            for notice in notices.iter() {
                                {
                                    let post_id = notice.message.id_string();
                                    let board_id = board_id.clone();
                                    let nav = navigator();
                                    let timestamp = notice.message.time.timestamp_millis();
                                    let kind = match notice.kind {
                                        NoticeKind::Reply => "reply",
                                        NoticeKind::Mention => "mention",
                                        NoticeKind::Section => "new topic",
                                    };
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
                                                span { class: "text-base font-semibold text-text", "{notice.message.title_text}" }
                                                span { class: "text-xs text-text-muted", "by {notice.message.author_name}" }
                                                span { class: "text-[10px] uppercase tracking-wide text-accent", "{kind}" }
                                                span { class: "text-xs text-text-muted", "· {format_utc_as_local_time(timestamp)}" }
                                            }
                                            if !notice.message.content_text.is_empty() {
                                                p { class: "text-xs text-text-muted mt-1 line-clamp-2", "{notice.message.content_text}" }
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
