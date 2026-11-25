//! Local full-text search over the messages this client already holds.

use crate::components::app::topic_contract;
use crate::components::app::{Route, BOARDS, CURRENT_BOARD};
use crate::components::conversation::{get_all_messages, MessageData};
use crate::util::format_utc_as_local_time;
use dioxus::prelude::*;
use plaza_core::board_state::member::MemberId;
use plaza_core::board_state::BoardModeV1;

#[component]
pub fn SearchView() -> Element {
    let index_mode = use_memo(move || {
        CURRENT_BOARD
            .read()
            .owner_key
            .and_then(|key| {
                BOARDS
                    .read()
                    .map
                    .get(&key)
                    .map(|board| board.board_state.mode.is_topic_index())
            })
            .unwrap_or(false)
    });
    if index_mode() {
        rsx! { TopicSearchView {} }
    } else {
        rsx! { LegacySearchView {} }
    }
}

#[component]
fn LegacySearchView() -> Element {
    let mut query = use_signal(String::new);
    let mut author = use_signal(String::new);
    let mut section_index = use_signal(|| 0usize);
    let mut from_date = use_signal(String::new);
    let mut to_date = use_signal(String::new);
    let mut oldest_first = use_signal(|| false);

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

    let (results, sections): (Vec<MessageData>, Vec<(plaza_core::board_state::message::MessageId, String)>) = {
        let snapshot = board.read().clone();
        let Some((_, messages)) = snapshot.as_ref() else {
            return rsx! {};
        };
        let mut sections: Vec<_> = messages
            .iter()
            .filter(|message| message.is_category)
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
        sections.sort_by(|a, b| a.1.cmp(&b.1));

        let needle = query.read().trim().to_lowercase();
        let author_needle = author.read().trim().to_lowercase();
        if needle.is_empty() && author_needle.is_empty() {
            (Vec::new(), sections)
        } else {
            let selected = *section_index.read();
            let section_target = if selected > 0 {
                sections.get(selected - 1).map(|(id, _)| *id)
            } else {
                None
            };
            let from = from_date.read().clone();
            let to = to_date.read().clone();
            let mut hits: Vec<MessageData> = messages
                .iter()
                .filter(|message| !message.is_category)
                .filter(|message| {
                    section_target
                        .map(|target| message.category_id == Some(target))
                        .unwrap_or(true)
                })
                .filter(|message| {
                    let date = message
                        .time
                        .with_timezone(&chrono::Local)
                        .format("%Y-%m-%d")
                        .to_string();
                    (from.is_empty() || date >= from) && (to.is_empty() || date <= to)
                })
                .filter(|message| {
                    (needle.is_empty()
                        || message.title_text.to_lowercase().contains(&needle)
                        || message.content_text.to_lowercase().contains(&needle))
                        && (author_needle.is_empty()
                            || message.author_name.to_lowercase().contains(&author_needle))
                })
                .cloned()
                .collect();
            if *oldest_first.read() {
                hits.sort_by_key(|message| message.time);
            } else {
                hits.sort_by_key(|message| std::cmp::Reverse(message.time));
            }
            hits.truncate(100);
            (hits, sections)
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
                    div { class: "flex flex-wrap items-center gap-2 mb-4 text-xs",
                        select {
                            class: "px-2 py-1.5 bg-panel border border-border rounded-lg text-text",
                            value: "{section_index}",
                            onchange: move |evt| {
                                section_index.set(evt.value().parse::<usize>().unwrap_or(0));
                            },
                            option { value: "0", "All sections" }
                            for (index, (_, name)) in sections.iter().enumerate() {
                                option { value: "{index + 1}", "{name}" }
                            }
                        }
                        label { class: "flex items-center gap-1 text-text-muted",
                            "From"
                            input {
                                r#type: "date",
                                class: "px-2 py-1.5 bg-panel border border-border rounded-lg text-text",
                                value: "{from_date}",
                                oninput: move |evt| from_date.set(evt.value()),
                            }
                        }
                        label { class: "flex items-center gap-1 text-text-muted",
                            "To"
                            input {
                                r#type: "date",
                                class: "px-2 py-1.5 bg-panel border border-border rounded-lg text-text",
                                value: "{to_date}",
                                oninput: move |evt| to_date.set(evt.value()),
                            }
                        }
                        button {
                            r#type: "button",
                            class: "px-2 py-1.5 bg-panel border border-border rounded-lg text-text hover:border-accent/50",
                            onclick: move |_| oldest_first.set(!oldest_first()),
                            if oldest_first() { "Oldest first" } else { "Newest first" }
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

#[component]
fn TopicSearchView() -> Element {
    let mut query = use_signal(String::new);
    let mut author = use_signal(String::new);
    let mut section_index = use_signal(|| 0usize);
    let mut from_date = use_signal(String::new);
    let mut to_date = use_signal(String::new);
    let mut oldest_first = use_signal(|| false);

    let board = use_memo(move || {
        let current = CURRENT_BOARD.read().owner_key?;
        BOARDS
            .read()
            .map
            .get(&current)
            .cloned()
            .map(|board| board.with_merged_topics())
    });
    // Search scans the whole index, so every page of every section is needed
    // here even though the board list loads pages on demand.
    use_effect(move || {
        let Some(owner) = CURRENT_BOARD.read().owner_key else {
            return;
        };
        spawn(async move {
            let _ = crate::components::app::section_contract::load_all_section_pages_for_board(
                owner,
            )
            .await;
            crate::components::app::member_contract::load_all_member_shards(owner).await;
            crate::components::app::profile_contract::load_all_profile_shards(owner).await;
        });
    });
    let Some(board_data) = board.read().clone() else {
        return rsx! {};
    };

    let mut sections: Vec<_> = board_data
        .board_state
        .sections
        .sections
        .iter()
        .filter(|entry| !entry.section.deleted)
        .map(|entry| {
            let id = entry.section.id;
            let name = topic_contract::section_name(&board_data, &id)
                .unwrap_or_else(|| "Section".to_string());
            (id, name)
        })
        .collect();
    sections.sort_by(|a, b| a.1.cmp(&b.1));

    let needle = query.read().trim().to_lowercase();
    let author_needle = author.read().trim().to_lowercase();
    let selected_section = *section_index.read();
    let section_target = selected_section
        .checked_sub(1)
        .and_then(|index| sections.get(index).map(|(id, _)| *id));
    let from = from_date.read().clone();
    let to = to_date.read().clone();

    let mut hits: Vec<_> = if needle.is_empty() && author_needle.is_empty() {
        Vec::new()
    } else {
        board_data
            .board_state
            .topics
            .entries
            .iter()
            .filter(|entry| {
                !board_data.board_state.topics.is_hidden(&entry.entry.topic_id)
                    && board_data
                        .board_state
                        .topics
                        .merged_into(&entry.entry.topic_id)
                        .is_none()
            })
            .filter_map(|entry| {
                let topic_id = entry.entry.topic_id;
                let (section, _) = board_data.board_state.topics.section_of(&topic_id);
                if section_target.is_some() && section != section_target {
                    return None;
                }
                let title = topic_contract::read_text(&board_data, &entry.entry.title)
                    .unwrap_or_else(|| "Untitled".to_string());
                let preview = topic_contract::read_text(&board_data, &entry.entry.preview)
                    .unwrap_or_default();
                let author_name = board_data
                    .display_nickname(entry.entry.author)
                    .unwrap_or_else(|| entry.entry.author.to_string());
                if !needle.is_empty()
                    && !title.to_lowercase().contains(&needle)
                    && !preview.to_lowercase().contains(&needle)
                {
                    return None;
                }
                if !author_needle.is_empty()
                    && !author_name.to_lowercase().contains(&author_needle)
                    && !entry.entry.author.to_string().to_lowercase().contains(&author_needle)
                {
                    return None;
                }
                let date = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(entry.entry.created_at)
                    .map(|time| time.with_timezone(&chrono::Local).format("%Y-%m-%d").to_string())
                    .unwrap_or_default();
                if !from.is_empty() && date < from {
                    return None;
                }
                if !to.is_empty() && date > to {
                    return None;
                }
                let section_name = section.and_then(|id| {
                    topic_contract::section_name(&board_data, &id)
                });
                let last_at = board_data
                    .board_state
                    .topics
                    .activity_for(&topic_id)
                    .map(|activity| activity.activity.last_activity)
                    .unwrap_or(entry.entry.created_at);
                Some((topic_id, title, preview, author_name, last_at, section_name))
            })
            .collect()
    };
    if *oldest_first.read() {
        hits.sort_by_key(|hit| hit.4);
    } else {
        hits.sort_by_key(|hit| std::cmp::Reverse(hit.4));
    }
    hits.truncate(100);

    let board_id = bs58::encode(board_data.owner_vk.as_bytes()).into_string();
    let navigator = navigator();

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
                            placeholder: "Search titles and previews",
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
                    div { class: "flex flex-wrap items-center gap-2 mb-4 text-xs",
                        select {
                            class: "px-2 py-1.5 bg-panel border border-border rounded-lg text-text",
                            value: "{section_index}",
                            onchange: move |evt| {
                                section_index.set(evt.value().parse::<usize>().unwrap_or(0));
                            },
                            option { value: "0", "All sections" }
                            for (index, (_, name)) in sections.iter().enumerate() {
                                option { value: "{index + 1}", "{name}" }
                            }
                        }
                        label { class: "flex items-center gap-1 text-text-muted",
                            "From"
                            input {
                                r#type: "date",
                                class: "px-2 py-1.5 bg-panel border border-border rounded-lg text-text",
                                value: "{from_date}",
                                oninput: move |evt| from_date.set(evt.value()),
                            }
                        }
                        label { class: "flex items-center gap-1 text-text-muted",
                            "To"
                            input {
                                r#type: "date",
                                class: "px-2 py-1.5 bg-panel border border-border rounded-lg text-text",
                                value: "{to_date}",
                                oninput: move |evt| to_date.set(evt.value()),
                            }
                        }
                        button {
                            r#type: "button",
                            class: "px-2 py-1.5 bg-panel border border-border rounded-lg text-text hover:border-accent/50",
                            onclick: move |_| {
                                let next = !*oldest_first.read();
                                oldest_first.set(next);
                            },
                            if oldest_first() { "Oldest first" } else { "Newest first" }
                        }
                    }

                    p { class: "text-[11px] text-text-muted mb-3",
                        "Searches topic titles and previews. Open a topic to search its full text."
                    }

                    if query.read().trim().is_empty() && author.read().trim().is_empty() {
                        p { class: "text-text-muted text-sm", "Type something to search the topic index." }
                    } else if hits.is_empty() {
                        p { class: "text-text-muted text-sm", "No results." }
                    } else {
                        p { class: "text-xs text-text-muted mb-2", "{hits.len()} result(s)" }
                        div { class: "space-y-2",
                            for (topic_id, title, preview, author_name, last_at, section_name) in hits {
                                {
                                    let topic = bs58::encode(topic_id.as_bytes()).into_string();
                                    let nav = navigator.clone();
                                    let nav_board = board_id.clone();
                                    rsx! {
                                        button {
                                            key: "{topic}",
                                            r#type: "button",
                                            class: "w-full text-left bg-panel border border-border rounded-lg px-4 py-3 hover:border-accent/50 transition-colors",
                                            onclick: move |_| {
                                                nav.push(Route::Topic {
                                                    board_id: nav_board.clone(),
                                                    topic_id: topic.clone(),
                                                });
                                            },
                                            div { class: "flex items-baseline gap-2 flex-wrap",
                                                span { class: "text-base font-semibold text-text", "{title}" }
                                                span { class: "text-xs text-text-muted", "by {author_name}" }
                                                span { class: "text-xs text-text-muted", "· {format_utc_as_local_time(last_at)}" }
                                                if let Some(section) = section_name {
                                                    span { class: "text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-surface border border-border text-text-muted", "{section}" }
                                                }
                                            }
                                            if !preview.is_empty() {
                                                p { class: "text-xs text-text-muted mt-1 line-clamp-2", "{preview}" }
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
