//! Topic list for index boards. The discussions live in separate contracts,
//! so this view only reads the board index.

use crate::components::app::topic_contract;
use crate::components::app::{Route, BOARDS, CURRENT_BOARD};
use dioxus::prelude::*;
use plaza_core::board_state::message::MessageId;
use plaza_core::board_state::BoardModeV1;

#[component]
pub fn TopicIndexView(board_id: String) -> Element {
    let mut page = use_signal(|| 0usize);
    let mut title = use_signal(String::new);
    let mut body = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let mut section_choice = use_signal(|| None::<Option<MessageId>>);
    let mut new_section_name = use_signal(String::new);
    let mut section_busy = use_signal(|| false);
    let mut section_error = use_signal(|| None::<String>);
    let mut loading_more = use_signal(|| false);
    let navigator = navigator();

    let board = use_memo(move || {
        let current = CURRENT_BOARD.read();
        let Some(key) = current.owner_key else {
            return None;
        };
        BOARDS
            .read()
            .map
            .get(&key)
            .cloned()
            .map(|board| board.with_merged_topics())
    });

    // Lazily load only the member and profile shard buckets for authors visible
    // in the loaded topic index, and keep the persistent local search archive
    // updated with every loaded page.
    use_effect(move || {
        let Some(board_data) = board.read().clone() else {
            return;
        };
        crate::components::app::search_index::record_board_topics(&board_data);
        let owner = board_data.owner_vk;
        let authors: Vec<plaza_core::board_state::member::MemberId> = board_data
            .board_state
            .topics
            .entries
            .iter()
            .map(|entry| entry.entry.author)
            .collect();
        if authors.is_empty() {
            return;
        }
        crate::util::safe_spawn_local(async move {
            crate::components::app::member_contract::load_member_shards_for(
                owner,
                authors.iter().copied(),
            )
            .await;
            crate::components::app::profile_contract::load_profile_shards_for(owner, authors).await;
        });
    });

    let Some(board_data) = board.read().clone() else {
        return rsx! {
            div { class: "max-w-4xl mx-auto px-4 py-8 text-text-muted", "Loading board…" }
        };
    };
    if board_data.board_state.mode != BoardModeV1::SectionedTopicIndex {
        return rsx! {
            div { class: "max-w-4xl mx-auto px-4 py-8 text-text-muted",
                "This board uses the legacy message layout."
            }
        };
    }

    let mut topics: Vec<_> = board_data
        .board_state
        .topics
        .entries
        .iter()
        .filter(|entry| !board_data.board_state.topics.is_hidden(&entry.entry.topic_id))
        .filter(|entry| {
            board_data
                .board_state
                .topics
                .merged_into(&entry.entry.topic_id)
                .is_none()
        })
        .cloned()
        .collect();

    let is_owner = board_data.is_current_owner();
    let sections: Vec<_> = board_data
        .board_state
        .sections
        .sections
        .iter()
        .filter(|entry| !entry.section.deleted)
        .cloned()
        .collect();
    let default_section = sections.first().map(|entry| entry.section.id);
    let selected_section = section_choice.read().unwrap_or(default_section);
    let selected_value = selected_section
        .map(|id| bs58::encode(id.as_bytes()).into_string())
        .unwrap_or_default();
    topics.sort_by(|left, right| {
        let left_pinned = board_data.board_state.topics.is_pinned(&left.entry.topic_id);
        let right_pinned = board_data.board_state.topics.is_pinned(&right.entry.topic_id);
        right_pinned
            .cmp(&left_pinned)
            .then_with(|| {
                let left_at = board_data
                    .board_state
                    .topics
                    .activity_for(&left.entry.topic_id)
                    .map(|activity| activity.activity.last_activity)
                    .unwrap_or(left.entry.created_at);
                let right_at = board_data
                    .board_state
                    .topics
                    .activity_for(&right.entry.topic_id)
                    .map(|activity| activity.activity.last_activity)
                    .unwrap_or(right.entry.created_at);
                right_at.cmp(&left_at)
            })
            .then_with(|| left.entry.topic_id.cmp(&right.entry.topic_id))
    });

    let total = topics.len();
    let pages = total.div_ceil(20).max(1);
    let current_page = (*page.read()).min(pages.saturating_sub(1));
    let visible: Vec<_> = topics
        .iter()
        .skip(current_page * 20)
        .take(20)
        .cloned()
        .collect();

    let owner = board_data.owner_vk;
    let submit_title = title.clone();
    let submit_body = body.clone();

    rsx! {
        div { class: "max-w-4xl mx-auto px-4 py-6 flex flex-col gap-5",
            div { class: "flex items-center justify-between gap-3 flex-wrap",
                h1 { class: "text-xl font-semibold text-text", "Topics" }
                span { class: "text-xs text-text-muted", "{total} discussions" }
            }

            if is_owner {
                div { class: "bg-surface border border-border rounded-xl p-4 flex flex-col gap-3",
                    h2 { class: "text-sm font-semibold text-text", "Sections" }
                    div { class: "flex flex-wrap items-center gap-2",
                        input {
                            class: "flex-1 min-w-40 px-3 py-2 bg-panel border border-border rounded-lg text-text",
                            placeholder: "New section name",
                            value: "{new_section_name}",
                            oninput: move |event| new_section_name.set(event.value()),
                        }
                        button {
                            r#type: "button",
                            class: "px-3 py-2 rounded-lg bg-accent text-white text-sm disabled:opacity-50",
                            disabled: *section_busy.read() || new_section_name.read().trim().is_empty(),
                            onclick: move |_| {
                                if *section_busy.read() {
                                    return;
                                }
                                let name = new_section_name.read().trim().to_string();
                                section_busy.set(true);
                                section_error.set(None);
                                let owner = board_data.owner_vk;
                                spawn(async move {
                                    match topic_contract::create_section(owner, name).await {
                                        Ok(id) => {
                                            new_section_name.set(String::new());
                                            section_choice.set(Some(Some(id)));
                                        }
                                        Err(message) => section_error.set(Some(message)),
                                    }
                                    section_busy.set(false);
                                });
                            },
                            if *section_busy.read() { "Creating…" } else { "Create section" }
                        }
                    }
                    if let Some(message) = section_error.read().as_ref() {
                        p { class: "text-sm text-red-400", "{message}" }
                    }
                }
            }

            div { class: "bg-surface border border-border rounded-xl p-4 flex flex-col gap-3",
                h2 { class: "text-sm font-semibold text-text", "New topic" }
                select {
                    class: "w-full px-3 py-2 bg-panel border border-border rounded-lg text-text",
                    value: "{selected_value}",
                    onchange: move |event| {
                        let value = event.value();
                        let parsed = if value.is_empty() {
                            None
                        } else {
                            bs58::decode(&value)
                                .into_vec()
                                .ok()
                                .and_then(|bytes| bytes.try_into().ok())
                                .map(MessageId::from_bytes)
                        };
                        section_choice.set(Some(parsed));
                    },
                    for section in sections.iter() {
                        {
                            let id = section.section.id;
                            let value = bs58::encode(id.as_bytes()).into_string();
                            let label = topic_contract::section_name(&board_data, &id)
                                .unwrap_or_else(|| "Section".to_string());
                            rsx! {
                                option {
                                    value: "{value}",
                                    "data-contract": section
                                        .section
                                        .contract
                                        .map(|id| id.to_string())
                                        .unwrap_or_default(),
                                    "data-pages": crate::components::app::section_contract::pages_for(
                                        board_data.owner_vk,
                                        id,
                                    )
                                    .len()
                                    .to_string(),
                                    "data-page-size": crate::components::app::section_contract::page_size_for(
                                        board_data.owner_vk,
                                        id,
                                    )
                                    .map(|size| size.to_string())
                                    .unwrap_or_default(),
                                    "{label}"
                                }
                            }
                        }
                    }
                }
                input {
                    class: "w-full px-3 py-2 bg-panel border border-border rounded-lg text-text",
                    placeholder: "Title",
                    maxlength: 200,
                    value: "{title}",
                    oninput: move |event| title.set(event.value()),
                }
                textarea {
                    class: "w-full min-h-24 px-3 py-2 bg-panel border border-border rounded-lg text-text",
                    placeholder: "Write the first message…",
                    value: "{body}",
                    oninput: move |event| body.set(event.value()),
                }
                if let Some(message) = error.read().as_ref() {
                    p { class: "text-sm text-red-400", "{message}" }
                }
                div { class: "flex justify-end",
                    button {
                        r#type: "button",
                        disabled: *busy.read() || title.read().trim().is_empty(),
                        class: "px-4 py-2 rounded-lg bg-accent hover:bg-accent-hover disabled:opacity-50 text-white text-sm",
                        onclick: move |_| {
                            if *busy.read() {
                                return;
                            }
                            busy.set(true);
                            error.set(None);
                            let title = submit_title.read().trim().to_string();
                            let body = submit_body.read().clone();
                            let section = selected_section;
                            let navigator = navigator.clone();
                            let board_id = board_id.clone();
                            spawn(async move {
                                match topic_contract::create_topic(owner, title, body, section).await {
                                    Ok(topic_id) => {
                                        let topic = bs58::encode(topic_id.as_bytes()).into_string();
                                        navigator.push(Route::Topic {
                                            board_id,
                                            topic_id: topic,
                                        });
                                    }
                                    Err(message) => error.set(Some(message)),
                                }
                                busy.set(false);
                            });
                        },
                        if *busy.read() { "Publishing…" } else { "Create topic" }
                    }
                }
            }

            if visible.is_empty() {
                p { class: "text-text-muted text-sm", "No topics yet. Write the first one above." }
            } else {
                div { class: "flex flex-col gap-2",
                    for entry in visible {
                        {
                            let entry_value = entry.entry.clone();
                            let topics = board_data.board_state.topics.clone();
                            let board = &board_data;
                            let title = topic_contract::read_text(board, &entry_value.title)
                                .unwrap_or_else(|| "Untitled".to_string());
                            let preview = topic_contract::read_text(board, &entry_value.preview)
                                .unwrap_or_default();
                            let author = board
                                .display_nickname(entry_value.author)
                                .unwrap_or_else(|| short_id(entry_value.author));
                            let section_label = topics
                                .section_of(&entry_value.topic_id)
                                .0
                                .and_then(|id| topic_contract::section_name(board, &id));
                            let pinned = topics.is_pinned(&entry_value.topic_id);
                            let closed = topics.is_closed(&entry_value.topic_id);
                            let reply_count = topics
                                .activity_for(&entry_value.topic_id)
                                .map(|activity| activity.activity.reply_count)
                                .unwrap_or(0);
                            let pending = topics
                                .activity_for(&entry_value.topic_id)
                                .map(|activity| activity.activity.pending_approvals)
                                .unwrap_or(0);
                            let last_at = topics
                                .activity_for(&entry_value.topic_id)
                                .map(|activity| activity.activity.last_activity)
                                .unwrap_or(entry_value.created_at);
                            let unread =
                                last_at > board.topic_last_read(&entry_value.topic_id);
                            let topic_id = bs58::encode(entry_value.topic_id.as_bytes()).into_string();
                            let board_id = board_id.clone();
                            let navigator = navigator.clone();
                            rsx! {
                                button {
                                    key: "{topic_id}",
                                    r#type: "button",
                                    class: "w-full text-left bg-surface border border-border rounded-xl px-4 py-3 hover:border-accent/60 transition-colors",
                                    onclick: move |_| {
                                        navigator.push(Route::Topic {
                                            board_id: board_id.clone(),
                                            topic_id: topic_id.clone(),
                                        });
                                    },
                                    div { class: "flex items-center gap-2 flex-wrap",
                                        if pinned {
                                            span { class: "text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-accent/20 text-accent", "Pinned" }
                                        }
                                        if closed {
                                            span { class: "text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-red-500/20 text-red-300", "Closed" }
                                        }
                                        span { class: "text-text font-medium flex-1 min-w-40", "{title}" }
                                        if unread {
                                            span { class: "text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-accent/20 text-accent", "New" }
                                        }
                                        if pending > 0 {
                                            span { class: "text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300", "{pending} pending" }
                                        }
                                        span { class: "text-xs text-text-muted", "{reply_count} replies" }
                                    }
                                    if let Some(section) = section_label.as_ref() {
                                        span {
                                            class: "inline-block mt-1 text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-surface border border-border text-text-muted",
                                            "{section}"
                                        }
                                    }
                                    if !preview.trim().is_empty() {
                                        p { class: "mt-1 text-sm text-text-muted line-clamp-2", "{preview}" }
                                    }
                                    div { class: "mt-1 flex items-center gap-2 text-[11px] text-text-muted",
                                        span { "{author}" }
                                        span { "·" }
                                        span { "{format_time(last_at)}" }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if pages > 1 {
                div { class: "flex items-center justify-center gap-3",
                    button {
                        r#type: "button",
                        class: "px-3 py-1.5 rounded-lg border border-border text-sm text-text disabled:opacity-40",
                        disabled: current_page == 0,
                        onclick: move |_| page.set(current_page.saturating_sub(1)),
                        "Previous"
                    }
                    span { class: "text-xs text-text-muted", "Page {current_page + 1} of {pages}" }
                    button {
                        r#type: "button",
                        class: "px-3 py-1.5 rounded-lg border border-border text-sm text-text disabled:opacity-40",
                        disabled: current_page + 1 >= pages,
                        onclick: move |_| page.set((current_page + 1).min(pages - 1)),
                        "Next"
                    }
                }
            }

            // Extra index pages load on demand; page 0 is enough for the
            // first topics of every section.
            if crate::components::app::section_contract::has_more_pages(owner) {
                div { class: "flex items-center justify-center",
                    button {
                        r#type: "button",
                        class: "px-4 py-2 rounded-lg border border-border text-sm text-text disabled:opacity-50",
                        disabled: *loading_more.read(),
                        onclick: move |_| {
                            if *loading_more.read() {
                                return;
                            }
                            loading_more.set(true);
                            spawn(async move {
                                let _ = crate::components::app::section_contract::load_next_pages(
                                    owner, 4,
                                )
                                .await;
                                loading_more.set(false);
                            });
                        },
                        if *loading_more.read() { "Loading older topics…" } else { "Load older topics" }
                    }
                }
            }
        }
    }
}

fn short_id(id: plaza_core::board_state::member::MemberId) -> String {
    let text = id.to_string();
    text.chars().take(8).collect()
}

fn format_time(ms: i64) -> String {
    if ms <= 0 {
        return String::new();
    }
    let seconds = ms / 1000;
    format!("{}", seconds)
}
