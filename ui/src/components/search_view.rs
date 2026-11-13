//! Local full-text search over the messages this client already holds.

use crate::components::app::{Route, BOARDS, CURRENT_BOARD};
use crate::components::conversation::{get_all_messages, MessageData};
use crate::util::format_utc_as_local_time;
use dioxus::prelude::*;
use plaza_core::board_state::member::MemberId;

#[component]
pub fn SearchView() -> Element {
    let mut query = use_signal(String::new);
    let mut author = use_signal(String::new);

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
            &board.old_category_secrets,
        );
        Some((board.owner_vk, messages))
    });

    let results: Vec<MessageData> = {
        let snapshot = board.read().clone();
        let Some((_, messages)) = snapshot.as_ref() else {
            return rsx! {};
        };
        let needle = query.read().trim().to_lowercase();
        let author_needle = author.read().trim().to_lowercase();
        if needle.is_empty() && author_needle.is_empty() {
            Vec::new()
        } else {
            let mut hits: Vec<MessageData> = messages
                .iter()
                .filter(|message| !message.is_category)
                .filter(|message| {
                    (needle.is_empty()
                        || message.title_text.to_lowercase().contains(&needle)
                        || message.content_text.to_lowercase().contains(&needle))
                        && (author_needle.is_empty()
                            || message.author_name.to_lowercase().contains(&author_needle))
                })
                .cloned()
                .collect();
            hits.sort_by_key(|message| std::cmp::Reverse(message.time));
            hits.truncate(100);
            hits
        }
    };

    let board_id = CURRENT_BOARD
        .read()
        .owner_key
        .map(|key| bs58::encode(key.as_bytes()).into_string())
        .unwrap_or_default();

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
                    "← Back to topics"
                }
                h1 { class: "text-lg font-semibold text-text ml-2", "Search" }
            }

            div { class: "flex-1 overflow-y-auto",
                div { class: "max-w-4xl mx-auto px-4 py-6",
                    div { class: "flex flex-wrap gap-2 mb-4",
                        input {
                            class: "flex-1 min-w-48 px-3 py-2 bg-panel border border-border rounded-lg text-text placeholder-text-muted",
                            placeholder: "Search title and text",
                            value: "{query}",
                            oninput: move |evt| query.set(evt.value()),
                        }
                        input {
                            class: "w-44 px-3 py-2 bg-panel border border-border rounded-lg text-text placeholder-text-muted",
                            placeholder: "Author",
                            value: "{author}",
                            oninput: move |evt| author.set(evt.value()),
                        }
                    }

                    if query.read().trim().is_empty() && author.read().trim().is_empty() {
                        p { class: "text-text-muted text-sm", "Type something to search the board." }
                    } else if results.is_empty() {
                        p { class: "text-text-muted text-sm", "No results." }
                    } else {
                        p { class: "text-xs text-text-muted mb-2", "{results.len()} result(s)" }
                        div { class: "space-y-2",
                            for result in results.iter() {
                                {
                                    let post_id = result.id_string();
                                    let board_id = board_id.clone();
                                    let nav = navigator();
                                    let timestamp = result.time.timestamp_millis();
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
                                                span { class: "text-base font-semibold text-text", "{result.title_text}" }
                                                span { class: "text-xs text-text-muted", "by {result.author_name}" }
                                                span { class: "text-xs text-text-muted", "· {format_utc_as_local_time(timestamp)}" }
                                            }
                                            if !result.content_text.is_empty() {
                                                p { class: "text-xs text-text-muted mt-1 line-clamp-2", "{result.content_text}" }
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
