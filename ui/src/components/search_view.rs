//! Local full-text search over the topics and cached pages this client holds.

use crate::components::app::topic_contract;
use crate::components::app::{Route, BOARDS, CURRENT_BOARD};
use crate::util::format_utc_as_local_time;
use dioxus::prelude::*;
use plaza_core::board_state::member::MemberId;

#[component]
pub fn SearchView() -> Element {
    rsx! { TopicSearchView {} }
}

#[component]
fn TopicSearchView() -> Element {
    let mut query = use_signal(String::new);
    let mut author = use_signal(String::new);
    let mut section_index = use_signal(|| 0usize);
    let mut from_date = use_signal(String::new);
    let mut to_date = use_signal(String::new);
    let mut oldest_first = use_signal(|| false);

    let mut loading_pages = use_signal(|| false);
    let mut indexing_archive = use_signal(|| false);

    let board = use_memo(move || {
        let current = CURRENT_BOARD.read().owner_key?;
        BOARDS
            .read()
            .map
            .get(&current)
            .cloned()
            .map(|board| board.with_merged_topics())
    });
    // Search scans loaded topic manifests/pages plus the persisted delegate
    // archive index without fetching every page or member/profile shard up
    // front. Only when the user types an Author filter do we load profile
    // shards to resolve nicknames across the board.
    use_effect(move || {
        let Some(owner) = CURRENT_BOARD.read().owner_key else {
            return;
        };
        if author.read().trim().is_empty() {
            return;
        }
        spawn(async move {
            crate::components::app::profile_contract::load_all_profile_shards(owner).await;
        });
    });
    let Some(board_data) = board.read().clone() else {
        return rsx! {};
    };
    let owner = board_data.owner_vk;
    // Keep the persistent local archive index up to date with every loaded page.
    crate::components::app::search_index::record_board_topics(&board_data);
    let archived_count = crate::components::app::search_index::count_for(owner);

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
        let mut seen_ids = std::collections::HashSet::new();
        let mut combined: Vec<_> = board_data
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
                seen_ids.insert(topic_id);
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
                Some((
                    topic_id,
                    title,
                    preview,
                    author_name,
                    last_at,
                    section_name,
                    entry.entry.author,
                ))
            })
            .collect();
        // Also search persisted archive entries for evicted or previously
        // indexed older section pages stored in the encrypted delegate.
        for archived in crate::components::app::search_index::entries_for(owner) {
            if archived.hidden || archived.merged || !seen_ids.insert(archived.topic_id) {
                continue;
            }
            if section_target.is_some() && archived.section != section_target {
                continue;
            }
            let author_name = board_data
                .display_nickname(archived.author)
                .unwrap_or_else(|| archived.author.to_string());
            if !needle.is_empty()
                && !archived.title.to_lowercase().contains(&needle)
                && !archived.preview.to_lowercase().contains(&needle)
            {
                continue;
            }
            if !author_needle.is_empty()
                && !author_name.to_lowercase().contains(&author_needle)
                && !archived.author.to_string().to_lowercase().contains(&author_needle)
            {
                continue;
            }
            let date = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(archived.created_at)
                .map(|time| time.with_timezone(&chrono::Local).format("%Y-%m-%d").to_string())
                .unwrap_or_default();
            if !from.is_empty() && date < from {
                continue;
            }
            if !to.is_empty() && date > to {
                continue;
            }
            let section_name = archived
                .section
                .and_then(|id| topic_contract::section_name(&board_data, &id));
            combined.push((
                archived.topic_id,
                archived.title,
                archived.preview,
                author_name,
                archived.last_activity,
                section_name,
                archived.author,
            ));
        }
        combined
    };
    if *oldest_first.read() {
        hits.sort_by_key(|hit| hit.4);
    } else {
        hits.sort_by_key(|hit| std::cmp::Reverse(hit.4));
    }
    hits.truncate(100);

    // Lazily fetch member/profile shards only for authors of visible hits.
    {
        let hit_authors: Vec<MemberId> = hits.iter().map(|hit| hit.6).collect();
        if !hit_authors.is_empty() {
            crate::util::safe_spawn_local(async move {
                crate::components::app::member_contract::load_member_shards_for(
                    owner,
                    hit_authors.iter().copied(),
                )
                .await;
                crate::components::app::profile_contract::load_profile_shards_for(
                    owner,
                    hit_authors,
                )
                .await;
            });
        }
    }

    let has_more_pages = crate::components::app::section_contract::has_more_pages(owner);
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

                    div { class: "flex flex-wrap items-center gap-3 mb-3",
                        p { class: "text-[11px] text-text-muted",
                            "Searches loaded topics and local archive ({archived_count} indexed). Open a topic to search its full text."
                        }
                        if has_more_pages {
                            button {
                                r#type: "button",
                                disabled: *loading_pages.read() || *indexing_archive.read(),
                                class: "px-2.5 py-1 text-xs rounded-lg bg-surface border border-border text-accent hover:border-accent/50 disabled:opacity-50",
                                onclick: move |_| {
                                    loading_pages.set(true);
                                    spawn(async move {
                                        if let Some(section) = section_target {
                                            let _ = crate::components::app::section_contract::load_section_pages(
                                                owner, section,
                                            )
                                            .await;
                                        } else {
                                            let _ = crate::components::app::section_contract::load_next_pages(
                                                owner, 4,
                                            )
                                            .await;
                                        }
                                        loading_pages.set(false);
                                    });
                                },
                                if *loading_pages.read() {
                                    "Loading older pages…"
                                } else {
                                    "Load older pages to expand search"
                                }
                            }
                            button {
                                r#type: "button",
                                disabled: *indexing_archive.read() || *loading_pages.read(),
                                class: "px-2.5 py-1 text-xs rounded-lg bg-surface border border-border text-text hover:border-accent/50 disabled:opacity-50",
                                onclick: move |_| {
                                    indexing_archive.set(true);
                                    spawn(async move {
                                        let _ = crate::components::app::section_contract::load_all_section_pages_for_board(
                                            owner,
                                        )
                                        .await;
                                        indexing_archive.set(false);
                                    });
                                },
                                if *indexing_archive.read() {
                                    "Indexing full archive…"
                                } else {
                                    "Index full archive locally"
                                }
                            }
                        }
                    }

                    if query.read().trim().is_empty() && author.read().trim().is_empty() {
                        p { class: "text-text-muted text-sm", "Type something to search the topic index." }
                    } else if hits.is_empty() {
                        p { class: "text-text-muted text-sm", "No results." }
                    } else {
                        p { class: "text-xs text-text-muted mb-2", "{hits.len()} result(s)" }
                        div { class: "space-y-2",
                            for (topic_id, title, preview, author_name, last_at, section_name, _) in hits {
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
