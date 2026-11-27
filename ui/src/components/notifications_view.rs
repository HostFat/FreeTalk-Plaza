//! Local notifications: unread topics and per-board notification settings.

use crate::components::app::chat_delegate::save_boards_to_delegate;
use crate::components::app::{Route, BOARDS, CURRENT_BOARD};
use crate::util::format_utc_as_local_time;
use dioxus::prelude::*;
use plaza_core::board_state::member::MemberId;
use wasm_bindgen_futures::spawn_local;

#[component]
pub fn NotificationsView() -> Element {
    rsx! { TopicNotificationsView {} }
}

#[component]
fn NotificationPermissionStatus() -> Element {
    let mut label = use_signal(current_permission_label);
    let request = move |_| {
        #[cfg(target_arch = "wasm32")]
        {
            if let Ok(promise) = web_sys::Notification::request_permission() {
                spawn_local(async move {
                    let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
                    label.set(current_permission_label());
                });
            }
        }
    };

    rsx! {
        div { class: "flex items-center gap-2",
            span { class: "text-[11px] text-text-muted", "{label}" }
            if label() == "System notifications not enabled" {
                button {
                    r#type: "button",
                    class: "px-2 py-1 text-[11px] rounded-md bg-accent/10 text-accent hover:bg-accent/20",
                    onclick: request,
                    "Enable"
                }
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn current_permission_label() -> String {
    match web_sys::Notification::permission() {
        web_sys::NotificationPermission::Granted => {
            "System notifications allowed".to_string()
        }
        web_sys::NotificationPermission::Denied => {
            "System notifications blocked by the browser".to_string()
        }
        _ => "System notifications not enabled".to_string(),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn current_permission_label() -> String {
    "System notifications unavailable".to_string()
}

#[component]
fn TopicNotificationsView() -> Element {
    let mut loading_pages = use_signal(|| false);
    let board = use_memo(move || {
        let current = CURRENT_BOARD.read().owner_key?;
        BOARDS
            .read()
            .map
            .get(&current)
            .cloned()
            .map(|board| board.with_merged_topics())
    });
    let Some(board_data) = board.read().clone() else {
        return rsx! {};
    };
    let owner = board_data.owner_vk;
    let mode = board_data.notification_mode;
    let mode_value = mode.as_str();

    let mut unread: Vec<_> = if mode == crate::board_data::NotificationMode::Muted {
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
                let last_at = board_data
                    .board_state
                    .topics
                    .activity_for(&topic_id)
                    .map(|activity| activity.activity.last_activity)
                    .unwrap_or(entry.entry.created_at);
                if last_at <= board_data.topic_last_read(&topic_id) {
                    return None;
                }
                let title = crate::components::app::topic_contract::read_text(
                    &board_data,
                    &entry.entry.title,
                )
                .unwrap_or_else(|| "Untitled".to_string());
                let author = board_data
                    .display_nickname(entry.entry.author)
                    .unwrap_or_else(|| entry.entry.author.to_string());
                let (section, _) = board_data.board_state.topics.section_of(&topic_id);
                let section = section.and_then(|id| {
                    crate::components::app::topic_contract::section_name(&board_data, &id)
                });
                Some((topic_id, title, author, last_at, section, entry.entry.author))
            })
            .collect()
    };
    unread.sort_by_key(|entry| std::cmp::Reverse(entry.3));

    // Lazily fetch member/profile shards only for authors of visible unread topics.
    {
        let unread_authors: Vec<MemberId> = unread.iter().map(|entry| entry.5).collect();
        if !unread_authors.is_empty() {
            crate::util::safe_spawn_local(async move {
                crate::components::app::member_contract::load_member_shards_for(
                    owner,
                    unread_authors.iter().copied(),
                )
                .await;
                crate::components::app::profile_contract::load_profile_shards_for(
                    owner,
                    unread_authors,
                )
                .await;
            });
        }
    }

    let has_more_pages = crate::components::app::section_contract::has_more_pages(owner);
    let board_id = bs58::encode(board_data.owner_vk.as_bytes()).into_string();
    let result_board = board_id.clone();
    let navigator = navigator();
    let mark_all = {
        let entries = board_data.board_state.topics.entries.clone();
        move |_| {
            BOARDS.with_mut(|boards| {
                if let Some(board) = boards.map.get_mut(&owner) {
                    for entry in &entries {
                        let last_at = board
                            .board_state
                            .topics
                            .activity_for(&entry.entry.topic_id)
                            .map(|activity| activity.activity.last_activity)
                            .unwrap_or(entry.entry.created_at);
                        board.mark_topic_read(entry.entry.topic_id, last_at);
                    }
                }
            });
            spawn(async {
                let _ = save_boards_to_delegate().await;
            });
        }
    };

    rsx! {
        div { class: "flex-1 flex flex-col min-w-0 min-h-0 bg-bg",
            div { class: "flex flex-wrap items-center gap-2 px-6 py-3 border-b border-border",
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
                h1 { class: "text-lg font-semibold text-text ml-2", "Notifications" }
                div { class: "ml-auto flex flex-wrap items-center gap-2",
                    label { class: "text-xs text-text-muted", r#for: "notification-mode",
                        "Notify"
                    }
                    select {
                        id: "notification-mode",
                        class: "px-2 py-1.5 bg-surface border border-border text-text text-xs rounded-lg",
                        value: "{mode_value}",
                        onchange: move |event| {
                            let mode = crate::board_data::NotificationMode::from_str(&event.value());
                            BOARDS.with_mut(|boards| {
                                if let Some(board) = boards.map.get_mut(&owner) {
                                    board.notification_mode = mode;
                                }
                            });
                            spawn_local(async {
                                let _ = save_boards_to_delegate().await;
                            });
                        },
                        option { value: "all", "All activity" }
                        option { value: "mentions", "Mentions & replies" }
                        option { value: "muted", "Muted" }
                    }
                    NotificationPermissionStatus {}
                    if has_more_pages {
                        button {
                            r#type: "button",
                            disabled: *loading_pages.read(),
                            class: "px-3 py-1.5 bg-surface border border-border rounded-lg text-xs text-accent hover:border-accent/50 disabled:opacity-50",
                            onclick: move |_| {
                                loading_pages.set(true);
                                spawn(async move {
                                    let _ = crate::components::app::section_contract::load_next_pages(
                                        owner, 4,
                                    )
                                    .await;
                                    loading_pages.set(false);
                                });
                            },
                            if *loading_pages.read() {
                                "Loading older pages…"
                            } else {
                                "Check older pages"
                            }
                        }
                    }
                    if !unread.is_empty() {
                        button {
                            r#type: "button",
                            class: "px-3 py-1.5 bg-surface border border-border rounded-lg text-xs text-text",
                            onclick: mark_all,
                            "Mark all read"
                        }
                    }
                }
            }
            div { class: "flex-1 overflow-y-auto",
                div { class: "max-w-4xl mx-auto px-4 py-6",
                    if mode == crate::board_data::NotificationMode::Muted {
                        p { class: "text-text-muted text-sm", "Notifications are muted for this board." }
                    } else if unread.is_empty() {
                        p { class: "text-text-muted text-sm", "No unread topics." }
                    } else {
                        p { class: "text-xs text-text-muted mb-2", "{unread.len()} unread topic(s)" }
                        div { class: "space-y-2",
                            for (topic_id, title, author, last_at, section, _) in unread {
                                {
                                    let topic = bs58::encode(topic_id.as_bytes()).into_string();
                                    let nav = navigator.clone();
                                    let nav_board = result_board.clone();
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
                                                span { class: "text-xs text-text-muted", "by {author}" }
                                                span { class: "text-xs text-text-muted", "· {format_utc_as_local_time(last_at)}" }
                                                if let Some(section) = section {
                                                    span { class: "text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-surface border border-border text-text-muted", "{section}" }
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
}
