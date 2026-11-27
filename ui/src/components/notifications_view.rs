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
use plaza_core::board_state::BoardModeV1;
use wasm_bindgen_futures::spawn_local;

#[component]
pub fn NotificationsView() -> Element {
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
        rsx! { TopicNotificationsView {} }
    } else {
        rsx! { LegacyNotificationsView {} }
    }
}

#[component]
fn LegacyNotificationsView() -> Element {
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
        let nickname = notifications::self_nickname(&board, self_id);
        Some((
            board.owner_vk,
            board.last_visit,
            self_id,
            nickname,
            messages,
            board.subscribed_categories.clone(),
            board.read_categories.clone(),
            board.notification_mode,
        ))
    });

    let board_id = CURRENT_BOARD
        .read()
        .owner_key
        .map(|key| bs58::encode(key.as_bytes()).into_string())
        .unwrap_or_default();

    let Some((
        owner_vk,
        last_visit,
        self_id,
        nickname,
        messages,
        subscribed,
        read_categories,
        mode,
    )) = board.read().clone()
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
        mode,
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
    let mode_value = mode.as_str();

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
                h1 { class: "text-lg font-semibold text-text ml-2", "Notifications" }
                div { class: "ml-auto flex items-center gap-2",
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
                                if let Some(board) = boards.map.get_mut(&owner_vk) {
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
                    button {
                        r#type: "button",
                        class: "px-3 py-1.5 bg-surface hover:bg-surface-hover text-text text-xs rounded-lg",
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
                                    key: "{section_id}",
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
                        p { class: "text-text-muted text-sm",
                            if mode == crate::board_data::NotificationMode::Muted {
                                "Notifications are muted for this board."
                            } else {
                                "No new notifications."
                            }
                        }
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
