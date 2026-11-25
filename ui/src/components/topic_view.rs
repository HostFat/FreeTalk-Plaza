//! One discussion backed by a `plaza-topic` contract.

use crate::components::app::topic_contract;
use crate::components::app::{Route, BOARDS, CURRENT_BOARD};
use dioxus::prelude::*;
use plaza_core::board_state::content::PollContentV1;
use plaza_core::board_state::message::MessageId;
use plaza_core::board_state::reports::ReportReason;
use plaza_core::board_state::topics::TopicFlagKind;
use plaza_topic_core::TopicPostContentV1;

const REACTIONS: [&str; 5] = ["👍", "❤️", "😂", "🎉", "🤔"];

#[component]
pub fn TopicView(board_id: String, topic_id: String) -> Element {
    let Ok(bytes) = bs58::decode(&topic_id).into_vec() else {
        return rsx! {
            div { class: "max-w-3xl mx-auto px-4 py-8 text-red-400",
                "The topic id in this link is not valid."
            }
        };
    };
    let Ok(bytes): Result<[u8; 32], _> = bytes.try_into() else {
        return rsx! {
            div { class: "max-w-3xl mx-auto px-4 py-8 text-red-400",
                "The topic id in this link is not valid."
            }
        };
    };
    let topic_id_value = MessageId::from_bytes(bytes);

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
    let Some(board_data) = board.read().clone() else {
        return rsx! {
            div { class: "max-w-3xl mx-auto px-4 py-8 text-text-muted", "Loading board…" }
        };
    };

    let owner = board_data.owner_vk;
    let part = crate::components::app::section_contract::merged_index(
        owner,
        &board_data.board_state.topics,
    )
    .part_of(&topic_id_value);
    let mut error = use_signal(|| None::<String>);
    let mut reply = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let mut loaded_part = use_signal(|| None::<u32>);
    let mut marked_read = use_signal(|| 0i64);
    let mut draft_loaded = use_signal(|| false);
    let mut earlier_part = use_signal(|| None::<u32>);
    let mut editing_topic = use_signal(|| false);
    let mut edit_title = use_signal(String::new);
    let mut edit_body = use_signal(String::new);
    let editing_post = use_signal(|| None::<MessageId>);
    let edit_reply = use_signal(String::new);
    let mut poll_mode = use_signal(|| false);
    let mut poll_question = use_signal(String::new);
    let mut poll_option_1 = use_signal(String::new);
    let mut poll_option_2 = use_signal(String::new);
    let mut poll_busy = use_signal(|| false);
    let mut move_target = use_signal(|| None::<MessageId>);
    let mut merge_target = use_signal(|| None::<MessageId>);

    use_effect(move || {
        let _ = BOARDS.read().map.len();
        let owner = board_data.owner_vk;
        let (last_read, at) = {
            let boards = BOARDS.read();
            let Some(board) = boards.map.get(&owner) else {
                return;
            };
            let last_read = board.topic_last_read(&topic_id_value);
            // A topic with no activity row yet must not fall back to the wall
            // clock: every render would then look newer than the stored mark,
            // write the board again, and re-render forever.
            let topics = board.clone().with_merged_topics().board_state.topics;
            let at = topics
                .activity_for(&topic_id_value)
                .map(|activity| activity.activity.last_activity)
                .or_else(|| {
                    topics
                        .entries
                        .iter()
                        .find(|entry| entry.entry.topic_id == topic_id_value)
                        .map(|entry| entry.entry.created_at)
                })
                .unwrap_or(last_read);
            (last_read, at)
        };
        if at <= last_read || *marked_read.read() >= at {
            return;
        }
        marked_read.set(at);
        BOARDS.with_mut(|boards| {
            if let Some(board) = boards.map.get_mut(&owner) {
                board.mark_topic_read(topic_id_value, at);
            }
        });
        spawn(async {
            let _ =
                crate::components::app::chat_delegate::save_boards_to_delegate()
                    .await;
        });
    });

    use_effect(move || {
        if *draft_loaded.read() {
            return;
        }
        let draft = BOARDS
            .read()
            .map
            .get(&board_data.owner_vk)
            .map(|board| board.topic_draft(&topic_id_value))
            .unwrap_or_default();
        if !draft.is_empty() {
            reply.set(draft);
        }
        draft_loaded.set(true);
    });

    use_effect(move || {
        let _ = BOARDS.read().map.len();
        let owner = board_data.owner_vk;
        let index = BOARDS
            .read()
            .map
            .get(&owner)
            .map(|board| {
                crate::components::app::section_contract::merged_index(
                    owner,
                    &board.board_state.topics,
                )
            })
            .unwrap_or_default();
        let part_now = index.part_of(&topic_id_value);
        if *loaded_part.read() == Some(part_now) {
            return;
        }
        loaded_part.set(Some(part_now));
        spawn(async move {
            for attempt in 0..3 {
                match topic_contract::load_topic(owner, topic_id_value, part_now).await {
                    Ok(_) => {
                        if let Err(message) = topic_contract::sync_topic_authority(
                            owner,
                            topic_id_value,
                            part_now,
                        )
                        .await
                        {
                            error.set(Some(message));
                        }
                        return;
                    }
                    Err(message) => {
                        dioxus::logger::tracing::warn!(
                            "load_topic failed for part {part_now} (attempt {}): {message}",
                            attempt + 1
                        );
                        if attempt + 1 == 3 {
                            error.set(Some(message));
                            return;
                        }
                        crate::util::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            }
        });
    });

    // Lazily load only the member and profile shard buckets for authors and
    // participants present in this topic.
    use_effect(move || {
        let Some(topic_state) = topic_contract::topic_state(owner, topic_id_value, part) else {
            return;
        };
        let mut ids: Vec<plaza_core::board_state::member::MemberId> = Vec::new();
        if let Some(header) = &topic_state.header {
            ids.push(header.header.author);
        }
        for post in topic_state.posts.values() {
            ids.push(post.post.author);
        }
        for participant in &topic_state.participants {
            ids.push(participant.record.member_id);
        }
        if ids.is_empty() {
            return;
        }
        crate::util::safe_spawn_local(async move {
            crate::components::app::member_contract::load_member_shards_for(
                owner,
                ids.iter().copied(),
            )
            .await;
            crate::components::app::profile_contract::load_profile_shards_for(owner, ids).await;
        });
    });

    let state = topic_contract::topic_state(owner, topic_id_value, part);
    let Some(state) = state else {
        return rsx! {
            div { class: "max-w-3xl mx-auto px-4 py-8 text-text-muted", "Loading topic…" }
        };
    };
    let Some(header) = state.header.as_ref() else {
        return rsx! {
            div { class: "max-w-3xl mx-auto px-4 py-8 text-text-muted", "Loading topic…" }
        };
    };

    let self_id = plaza_core::board_state::member::MemberId::from(
        &board_data.self_sk.verifying_key(),
    );
    let (header_title, header_body) =
        topic_contract::effective_topic_content(&board_data, &state)
            .unwrap_or((header.header.title.clone(), header.header.body.clone()));
    let title = topic_contract::read_text(&board_data, &header_title)
        .unwrap_or_else(|| "Untitled".to_string());
    let body = topic_contract::read_text(&board_data, &header_body)
        .unwrap_or_default();
    let can_edit_topic = header.header.author == self_id;
    let author = board_data
        .display_nickname(header.header.author)
        .unwrap_or_else(|| short_id(header.header.author));
    let closed = state.is_closed();
    let deleted = state.is_deleted(header.header.id());
    let pinned = state.is_pinned();
    let announced = state.is_announced();
    let hidden = state.is_hidden();
    let is_owner = board_data.is_current_owner();
    let now_ms = plaza_core::board_state::rate_limit::system_time_ms(
        crate::util::get_current_system_time(),
    );
    let banned = state.is_banned_member(self_id, now_ms);
    let suspended = state.is_suspended_member(self_id, now_ms);
    let effective_section = state.effective_section();
    let effective_section_id = effective_section.as_ref().map(|section| section.section);
    let scope_chain = effective_section
        .as_ref()
        .map(|section| section.chain.clone())
        .unwrap_or_default();
    let can_moderate = is_owner || board_data.can_moderate(&scope_chain);
    let merged_into = state.merged_into();
    let topic_for_flags = topic_id_value;
    let owner_for_flags = board_data.owner_vk;

    let mut posts: Vec<_> = state.posts.values().cloned().collect();
    posts.sort_by_key(|post| (post.post.created_at, *post.id().as_bytes()));
    let visible_posts: Vec<_> = posts
        .into_iter()
        .filter(|post| !state.is_deleted(post.id()))
        .filter(|post| !state.is_split(post.id()))
        .filter(|post| {
            state.post_is_visible(post)
                || post.post.author == self_id
                || is_owner
        })
        .collect();

    let reply_text = reply.clone();
    let board_for_reply = board_data.clone();
    let topic_for_reply = topic_id_value;
    let navigator = navigator();
    let split_navigator = navigator.clone();
    let branch = board_id.clone();

    rsx! {
        div { class: "max-w-3xl mx-auto px-4 py-6 flex flex-col gap-5",
            if let Some(message) = error.read().as_ref() {
                p { class: "text-sm text-red-400", "{message}" }
            }
            div { class: "flex items-center gap-3 flex-wrap",
                button {
                    r#type: "button",
                    class: "text-sm text-accent hover:underline",
                    onclick: move |_| {
                        navigator.push(Route::Posts { board_id: branch.clone() });
                    },
                    "← Back to topics"
                }
                if closed {
                    span { class: "text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-red-500/20 text-red-300", "Closed" }
                }
                if pinned {
                    span { class: "text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-accent/20 text-accent", "Pinned" }
                }
                if announced {
                    span { class: "text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300", "Announced" }
                }
                if hidden {
                    span { class: "text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-red-500/20 text-red-300", "Hidden" }
                }
            }

            if is_owner {
                div { class: "flex items-center gap-2 flex-wrap",
                    {[
                        ("Pin", TopicFlagKind::Pinned, pinned),
                        ("Close", TopicFlagKind::Closed, closed),
                        ("Announce", TopicFlagKind::Announced, announced),
                        ("Hide", TopicFlagKind::Hidden, hidden),
                        ("Approve", TopicFlagKind::Approved, false),
                    ]
                    .into_iter()
                    .map(|(label, kind, current)| {
                        let owner = owner_for_flags;
                        let topic = topic_for_flags;
                        rsx! {
                            button {
                                key: "{label}",
                                r#type: "button",
                                class: "px-2.5 py-1 rounded-lg border border-border text-xs text-text hover:bg-surface",
                                onclick: move |_| {
                                    spawn(async move {
                                        if let Err(message) =
                                            topic_contract::set_flag(owner, topic, part, kind, !current)
                                                .await
                                        {
                                            error.set(Some(message));
                                        }
                                    });
                                },
                                "{label}"
                            }
                        }
                    })}
                }
            }

            article { class: "bg-surface border border-border rounded-xl p-5",
                h1 { class: "text-2xl font-semibold text-text", "{title}" }
                p { class: "mt-1 text-xs text-text-muted", "{author}" }
                if let Some(section) = effective_section.as_ref() {
                    if let Some(name) = topic_contract::section_name(&board_data, &section.section) {
                        span {
                            class: "inline-block mt-1 text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-surface border border-border text-text-muted",
                            "{name}"
                        }
                    }
                }
                button {
                    r#type: "button",
                    class: "mt-3 ml-2 text-xs text-text-muted hover:text-text",
                    onclick: move |_| {
                        let reason = web_sys::window()
                            .and_then(|window| {
                                window.prompt_with_message("Why are you reporting this topic?").ok().flatten()
                            });
                        let Some(reason) = reason else { return; };
                        let owner = board_data.owner_vk;
                        spawn(async move {
                            let _ = topic_contract::report_post(
                                owner,
                                topic_id_value,
                                None,
                                ReportReason::Other,
                                reason,
                            ).await;
                        });
                    },
                    "Report"
                }
                if let Some(destination) = merged_into {
                    span {
                        class: "inline-block mt-1 ml-1 text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300",
                        "Merged into {destination}"
                    }
                }
                if part > 0 {
                    p { class: "mt-2 text-[11px] text-text-muted",
                        "Part {part + 1}. Earlier posts are in the previous parts."
                    }
                    button {
                        r#type: "button",
                        class: "mt-1 text-xs text-accent hover:underline",
                        onclick: move |_| {
                            let owner = board_data.owner_vk;
                            let previous = part.saturating_sub(1);
                            spawn(async move {
                                match topic_contract::load_topic(owner, topic_id_value, previous).await {
                                    Ok(_) => earlier_part.set(Some(previous)),
                                    Err(message) => error.set(Some(message)),
                                }
                            });
                        },
                        "Load earlier posts"
                    }
                }
                if !body.trim().is_empty() {
                    p { class: "mt-4 whitespace-pre-wrap text-text", "{body}" }
                }
                if deleted {
                    p { class: "mt-3 text-sm text-red-400", "This topic was deleted." }
                }
                if can_edit_topic {
                    if *editing_topic.read() {
                        div { class: "mt-4 flex flex-col gap-2",
                            input {
                                class: "w-full px-3 py-2 bg-panel border border-border rounded-lg text-text",
                                placeholder: "Topic title",
                                value: "{edit_title}",
                                oninput: move |event| edit_title.set(event.value()),
                            }
                            textarea {
                                class: "w-full min-h-24 px-3 py-2 bg-panel border border-border rounded-lg text-text",
                                placeholder: "Topic body",
                                value: "{edit_body}",
                                oninput: move |event| edit_body.set(event.value()),
                            }
                            div { class: "flex justify-end gap-2",
                                button {
                                    r#type: "button",
                                    class: "px-3 py-1.5 rounded-lg border border-border text-sm text-text",
                                    onclick: move |_| editing_topic.set(false),
                                    "Cancel"
                                }
                                button {
                                    r#type: "button",
                                    class: "px-3 py-1.5 rounded-lg bg-accent text-white text-sm",
                                    onclick: move |_| {
                                        let title = edit_title.read().clone();
                                        let body = edit_body.read().clone();
                                        let owner = owner;
                                        spawn(async move {
                                            match topic_contract::edit_topic(
                                                owner,
                                                topic_id_value,
                                                part,
                                                title,
                                                body,
                                            )
                                            .await
                                            {
                                                Ok(()) => editing_topic.set(false),
                                                Err(message) => error.set(Some(message)),
                                            }
                                        });
                                    },
                                    "Save topic"
                                }
                            }
                        }
                    } else {
                        button {
                            r#type: "button",
                            class: "mt-3 text-xs text-accent hover:underline",
                            onclick: move |_| {
                                edit_title.set(title.clone());
                                edit_body.set(body.clone());
                                editing_topic.set(true);
                            },
                            "Edit topic"
                        }
                    }
                }
                {reaction_bar(
                    &board_data,
                    &state,
                    topic_id_value,
                    part,
                    header.header.id(),
                    board_data.owner_vk,
                    self_id,
                )}
                if is_owner {
                    div { class: "mt-3 flex flex-wrap items-center gap-2",
                        select {
                            class: "px-2 py-1 bg-panel border border-border rounded-lg text-xs text-text",
                            value: "{(*move_target.read()).or(effective_section_id).map(|id| bs58::encode(id.as_bytes()).into_string()).unwrap_or_default()}",
                            onchange: move |event| {
                                let parsed = bs58::decode(event.value())
                                    .into_vec()
                                    .ok()
                                    .and_then(|bytes| bytes.try_into().ok())
                                    .map(MessageId::from_bytes);
                                move_target.set(parsed);
                            },
                            for entry in board_data.board_state.sections.sections.iter().filter(|entry| !entry.section.deleted) {
                                {
                                    let id = entry.section.id;
                                    let value = bs58::encode(id.as_bytes()).into_string();
                                    let label = topic_contract::section_name(&board_data, &id)
                                        .unwrap_or_else(|| "Section".to_string());
                                    rsx! { option { value: "{value}", "{label}" } }
                                }
                            }
                        }
                        button {
                            r#type: "button",
                            class: "px-2.5 py-1 rounded-lg border border-border text-xs text-text hover:bg-surface",
                            onclick: move |_| {
                                let Some(section) = (*move_target
                                    .read())
                                    .or(effective_section.as_ref().map(|section| section.section))
                                else {
                                    return;
                                };
                                let owner = board_data.owner_vk;
                                spawn(async move {
                                    if let Err(message) = topic_contract::move_topic(
                                        owner,
                                        topic_id_value,
                                        part,
                                        section,
                                    )
                                    .await
                                    {
                                        error.set(Some(message));
                                    }
                                });
                            },
                            "Move"
                        }
                        if board_data.board_state.topics.entries.len() > 1 {
                            select {
                                class: "px-2 py-1 bg-panel border border-border rounded-lg text-xs text-text",
                                value: "{(*merge_target.read()).map(|id| bs58::encode(id.as_bytes()).into_string()).unwrap_or_default()}",
                                onchange: move |event| {
                                    let parsed = if event.value().is_empty() {
                                        None
                                    } else {
                                        bs58::decode(event.value())
                                            .into_vec()
                                            .ok()
                                            .and_then(|bytes| bytes.try_into().ok())
                                            .map(MessageId::from_bytes)
                                    };
                                    merge_target.set(parsed);
                                },
                                option { value: "", "Merge into…" }
                                for entry in board_data.board_state.topics.entries.iter().filter(|entry| entry.entry.topic_id != topic_id_value) {
                                    {
                                        let id = entry.entry.topic_id;
                                        let value = bs58::encode(id.as_bytes()).into_string();
                                        rsx! { option { value: "{value}", "Topic {short_topic(id)}" } }
                                    }
                                }
                            }
                            button {
                                r#type: "button",
                                class: "px-2.5 py-1 rounded-lg border border-border text-xs text-text hover:bg-surface",
                                onclick: move |_| {
                                    let Some(destination) = *merge_target.read() else {
                                        return;
                                    };
                                    let owner = board_data.owner_vk;
                                    spawn(async move {
                                        if let Err(message) = topic_contract::merge_topic(
                                            owner,
                                            topic_id_value,
                                            part,
                                            destination,
                                        )
                                        .await
                                        {
                                            error.set(Some(message));
                                        }
                                    });
                                },
                                "Merge"
                            }
                        }
                        button {
                            r#type: "button",
                            class: "px-2.5 py-1 rounded-lg border border-border text-xs text-text hover:bg-surface",
                            onclick: move |_| {
                                let owner = board_data.owner_vk;
                                spawn(async move {
                                    if let Err(message) = topic_contract::continue_topic(
                                        owner,
                                        topic_id_value,
                                        part,
                                    )
                                    .await
                                    {
                                        error.set(Some(message));
                                    }
                                });
                            },
                            "Continue"
                        }
                    }
                }
            }

            if let Some(previous) = *earlier_part.read() {
                if let Some(previous_state) =
                    topic_contract::topic_state(owner, topic_id_value, previous)
                {
                    div { class: "bg-surface border border-border rounded-xl p-4",
                        h3 { class: "text-sm font-semibold text-text",
                            "Part {previous + 1}"
                        }
                        div { class: "mt-2 flex flex-col gap-2",
                            {
                                let mut previous_posts: Vec<_> = previous_state
                                    .posts
                                    .values()
                                    .filter(|post| {
                                        !previous_state.is_deleted(post.id())
                                            && !previous_state.is_split(post.id())
                                    })
                                    .cloned()
                                    .collect();
                                previous_posts.sort_by_key(|post| post.post.created_at);
                                rsx! {
                                    for post in previous_posts {
                                        {
                                            let author = board_data
                                                .display_nickname(post.post.author)
                                                .unwrap_or_else(|| short_id(post.post.author));
                                            let text = topic_contract::read_post_content(
                                                &board_data,
                                                &post.post.content,
                                            )
                                            .and_then(|content| match content {
                                                TopicPostContentV1::Text(text) => Some(text),
                                                _ => None,
                                            })
                                            .unwrap_or_else(|| "[poll]".to_string());
                                            rsx! {
                                                div { class: "bg-panel border border-border rounded-lg px-3 py-2",
                                                    div { class: "flex items-center gap-2",
                                                        span { class: "text-sm font-medium text-text", "{author}" }
                                                        span { class: "text-[11px] text-text-muted", "{format_time(post.post.created_at)}" }
                                                    }
                                                    p { class: "mt-1 whitespace-pre-wrap text-text", "{text}" }
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

            div { class: "flex flex-col gap-3",
                if visible_posts.is_empty() {
                    p { class: "text-sm text-text-muted", "No replies yet." }
                } else {
                    for post in visible_posts {
                        {
                            let post_value = post.post.clone();
                            let id = post.id();
                            let author = board_for_reply
                                .display_nickname(post_value.author)
                                .unwrap_or_else(|| short_id(post_value.author));
                            let sealed_content = topic_contract::effective_post_content(
                                &board_for_reply,
                                &state,
                                id,
                            );
                            let decoded = sealed_content.as_ref().and_then(|sealed| {
                                topic_contract::read_post_content(&board_for_reply, sealed)
                            });
                            let content = match &decoded {
                                Some(TopicPostContentV1::Text(text)) => text.clone(),
                                _ => String::new(),
                            };
                            let poll = match &decoded {
                                Some(TopicPostContentV1::Poll(poll)) => Some(poll.clone()),
                                _ => None,
                            };
                            let has_poll = poll.is_some();
                            let can_delete = post_value.author == self_id || is_owner;
                            let can_edit = post_value.author == self_id || is_owner;
                            let pending = !state.post_is_visible(&post);
                            let author_banned =
                                state.is_banned_member(post_value.author, now_ms);
                            let owner = board_for_reply.owner_vk;
                            let mut editing_post = editing_post;
                            let mut edit_reply = edit_reply;
                            let content_for_edit = content.clone();
                            let navigator = split_navigator.clone();
                            let split_board = board_id.clone();
                            rsx! {
                                div {
                                    key: "{id}",
                                    class: "bg-panel border border-border rounded-lg px-4 py-3",
                                    div { class: "flex items-center gap-2",
                                        span { class: "text-sm font-medium text-text", "{author}" }
                                        span { class: "text-[11px] text-text-muted", "{format_time(post_value.created_at)}" }
                                        if pending {
                                            span { class: "text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300", "Pending approval" }
                                        }
                                        if author_banned {
                                            span { class: "text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-red-500/20 text-red-300", "Banned author" }
                                        }
                                        div { class: "flex-1" }
                                        if pending && can_moderate {
                                            button {
                                                r#type: "button",
                                                class: "text-xs text-emerald-400 hover:underline mr-2",
                                                onclick: move |_| {
                                                    let owner = owner;
                                                    spawn(async move {
                                                        if let Err(message) =
                                                            topic_contract::approve_post(
                                                                owner,
                                                                topic_id_value,
                                                                part,
                                                                id,
                                                                true,
                                                            )
                                                            .await
                                                        {
                                                            error.set(Some(message));
                                                        }
                                                    });
                                                },
                                                "Approve"
                                            }
                                            button {
                                                r#type: "button",
                                                class: "text-xs text-red-400 hover:underline mr-2",
                                                onclick: move |_| {
                                                    let owner = owner;
                                                    spawn(async move {
                                                        if let Err(message) =
                                                            topic_contract::approve_post(
                                                                owner,
                                                                topic_id_value,
                                                                part,
                                                                id,
                                                                false,
                                                            )
                                                            .await
                                                        {
                                                            error.set(Some(message));
                                                        }
                                                    });
                                                },
                                                "Reject"
                                            }
                                        }
                                        if can_edit {
                                            button {
                                                r#type: "button",
                                                class: "text-xs text-accent hover:underline mr-2",
                                                onclick: move |_| {
                                                    edit_reply.set(content_for_edit.clone());
                                                    editing_post.set(Some(id));
                                                },
                                                "Edit reply"
                                            }
                                        }
                                        if can_delete {
                                            button {
                                                r#type: "button",
                                                class: "text-xs text-red-400 hover:underline",
                                                onclick: move |_| {
                                                    let owner = owner;
                                                    spawn(async move {
                                                        let _ = topic_contract::delete_post(
                                                            owner,
                                                            topic_id_value,
                                                            part,
                                                            id,
                                                        )
                                                        .await;
                                                    });
                                                },
                                                "Delete"
                                            }
                                        }
                                        if is_owner && !has_poll {
                                            button {
                                                r#type: "button",
                                                class: "text-xs text-accent hover:underline ml-2",
                                                onclick: move |_| {
                                                    let title = web_sys::window()
                                                        .and_then(|window| {
                                                            window
                                                                .prompt_with_message(
                                                                    "New topic title",
                                                                )
                                                                .ok()
                                                                .flatten()
                                                        });
                                                    let Some(title) = title else {
                                                        return;
                                                    };
                                                    let owner = board_for_reply.owner_vk;
                                                    let section = effective_section_id;
                                                    let navigator = navigator.clone();
                                                    let board_id = split_board.clone();
                                                    spawn(async move {
                                                        match topic_contract::split_reply(
                                                            owner,
                                                            topic_id_value,
                                                            part,
                                                            id,
                                                            title,
                                                            section,
                                                        )
                                                        .await
                                                        {
                                                            Ok(new_topic) => {
                                                                navigator.push(Route::Topic {
                                                                    board_id,
                                                                    topic_id: bs58::encode(
                                                                        new_topic.as_bytes(),
                                                                    )
                                                                    .into_string(),
                                                                });
                                                            }
                                                            Err(message) => {
                                                                error.set(Some(message))
                                                            }
                                                        }
                                                    });
                                                },
                                                "Split"
                                            }
                                        }
                                        button {
                                            r#type: "button",
                                            class: "text-xs text-text-muted hover:text-text ml-2",
                                            onclick: move |_| {
                                                let reason = web_sys::window()
                                                    .and_then(|window| {
                                                        window.prompt_with_message(
                                                            "Why are you reporting this reply?",
                                                        )
                                                        .ok()
                                                        .flatten()
                                                    });
                                                let Some(reason) = reason else {
                                                    return;
                                                };
                                                let owner = owner;
                                                spawn(async move {
                                                    let _ = topic_contract::report_post(
                                                        owner,
                                                        topic_id_value,
                                                        Some(id),
                                                        ReportReason::Other,
                                                        reason,
                                                    )
                                                    .await;
                                                });
                                            },
                                            "Report"
                                        }
                                    }
                                    if !content.trim().is_empty() {
                                        p { class: "mt-2 whitespace-pre-wrap text-text", "{content}" }
                                    }
                                    if let Some(poll) = poll {
                                        {poll_block(
                                            &board_for_reply,
                                            &state,
                                            topic_id_value,
                                            part,
                                            id,
                                            poll,
                                            board_for_reply.owner_vk,
                                            self_id,
                                        )}
                                    }
                                    {reaction_bar(
                                        &board_for_reply,
                                        &state,
                                        topic_id_value,
                                        part,
                                        id,
                                        board_for_reply.owner_vk,
                                        self_id,
                                    )}
                                    if *editing_post.read() == Some(id) {
                                        div { class: "mt-3 flex flex-col gap-2",
                                            textarea {
                                                class: "w-full min-h-20 px-3 py-2 bg-surface border border-border rounded-lg text-text",
                                                placeholder: "Edit reply",
                                                value: "{edit_reply}",
                                                oninput: move |event| edit_reply.set(event.value()),
                                            }
                                            div { class: "flex justify-end gap-2",
                                                button {
                                                    r#type: "button",
                                                    class: "px-3 py-1.5 rounded-lg border border-border text-sm text-text",
                                                    onclick: move |_| editing_post.set(None),
                                                    "Cancel"
                                                }
                                                button {
                                                    r#type: "button",
                                                    class: "px-3 py-1.5 rounded-lg bg-accent text-white text-sm",
                                                    onclick: move |_| {
                                                        let text = edit_reply.read().clone();
                                                        let owner = owner;
                                                        spawn(async move {
                                                            match topic_contract::edit_post(
                                                                owner,
                                                                topic_id_value,
                                                                part,
                                                                id,
                                                                text,
                                                            )
                                                            .await
                                                            {
                                                                Ok(()) => editing_post.set(None),
                                                                Err(message) => error.set(Some(message)),
                                                            }
                                                        });
                                                    },
                                                    "Save reply"
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

            if banned {
                div { class: "bg-red-500/10 border border-red-500/30 rounded-xl p-4 text-sm text-red-300",
                    "You are banned from this board. You can read the topic but not reply."
                }
            } else if suspended {
                div { class: "bg-amber-500/10 border border-amber-500/30 rounded-xl p-4 text-sm text-amber-300",
                    "You are suspended. You can read the topic but not reply until the suspension ends."
                }
            }

            if let Some(destination) = merged_into {
                div { class: "bg-amber-500/10 border border-amber-500/30 rounded-xl p-4 text-sm text-amber-300",
                    "This topic was merged into {destination}. Replies stay in the original contract."
                }
            }

            if !closed && !banned && !suspended && merged_into.is_none() {
                div { class: "bg-surface border border-border rounded-xl p-4 flex flex-col gap-3",
                    div { class: "flex items-center gap-2",
                        button {
                            r#type: "button",
                            class: "px-2.5 py-1 rounded-lg border border-border text-xs text-text hover:bg-surface",
                            onclick: move |_| {
                                let next = !*poll_mode.read();
                                poll_mode.set(next);
                            },
                            "Poll"
                        }
                    }
                    if *poll_mode.read() {
                        div { class: "flex flex-col gap-2",
                            input {
                                class: "w-full px-3 py-2 bg-panel border border-border rounded-lg text-text",
                                placeholder: "Poll question",
                                value: "{poll_question}",
                                oninput: move |event| poll_question.set(event.value()),
                            }
                            input {
                                class: "w-full px-3 py-2 bg-panel border border-border rounded-lg text-text",
                                placeholder: "Option 1",
                                value: "{poll_option_1}",
                                oninput: move |event| poll_option_1.set(event.value()),
                            }
                            input {
                                class: "w-full px-3 py-2 bg-panel border border-border rounded-lg text-text",
                                placeholder: "Option 2",
                                value: "{poll_option_2}",
                                oninput: move |event| poll_option_2.set(event.value()),
                            }
                            div { class: "flex justify-end gap-2",
                                button {
                                    r#type: "button",
                                    class: "px-3 py-1.5 rounded-lg border border-border text-sm text-text",
                                    onclick: move |_| poll_mode.set(false),
                                    "Cancel"
                                }
                                button {
                                    r#type: "button",
                                    class: "px-3 py-1.5 rounded-lg bg-accent text-white text-sm disabled:opacity-50",
                                    disabled: *poll_busy.read(),
                                    onclick: move |_| {
                                        if *poll_busy.read() {
                                            return;
                                        }
                                        let question = poll_question.read().clone();
                                        let options = vec![
                                            poll_option_1.read().clone(),
                                            poll_option_2.read().clone(),
                                        ];
                                        let owner = owner;
                                        poll_busy.set(true);
                                        error.set(None);
                                        spawn(async move {
                                            match topic_contract::send_poll_reply(
                                                owner,
                                                topic_for_reply,
                                                part,
                                                question,
                                                options,
                                                false,
                                            )
                                            .await
                                            {
                                                Ok(()) => {
                                                    poll_question.set(String::new());
                                                    poll_option_1.set(String::new());
                                                    poll_option_2.set(String::new());
                                                    poll_mode.set(false);
                                                }
                                                Err(message) => error.set(Some(message)),
                                            }
                                            poll_busy.set(false);
                                        });
                                    },
                                    if *poll_busy.read() { "Creating…" } else { "Create poll" }
                                }
                            }
                        }
                    } else {
                        textarea {
                            class: "w-full min-h-24 px-3 py-2 bg-panel border border-border rounded-lg text-text",
                            placeholder: "Write a reply…",
                            value: "{reply}",
                            oninput: move |event| {
                                let value = event.value();
                                reply.set(value.clone());
                                BOARDS.with_mut(|boards| {
                                    if let Some(board) = boards.map.get_mut(&owner) {
                                        board.set_topic_draft(topic_id_value, &value);
                                    }
                                });
                                spawn(async {
                                    let _ = crate::components::app::chat_delegate::save_boards_to_delegate().await;
                                });
                            },
                        }
                        if let Some(message) = error.read().as_ref() {
                            p { class: "text-sm text-red-400", "{message}" }
                        }
                        div { class: "flex justify-end",
                            button {
                                r#type: "button",
                                disabled: *busy.read() || reply.read().trim().is_empty(),
                                class: "px-4 py-2 rounded-lg bg-accent hover:bg-accent-hover disabled:opacity-50 text-white text-sm",
                                onclick: move |_| {
                                    if *busy.read() {
                                        return;
                                    }
                                    busy.set(true);
                                    error.set(None);
                                    let text = reply_text.read().clone();
                                    let owner = owner;
                                    spawn(async move {
                                        match topic_contract::send_reply(
                                            owner,
                                            topic_for_reply,
                                            part,
                                            text,
                                        )
                                        .await
                                        {
                                            Ok(()) => {
                                            reply.set(String::new());
                                            BOARDS.with_mut(|boards| {
                                                if let Some(board) = boards.map.get_mut(&owner) {
                                                    board.set_topic_draft(topic_id_value, "");
                                                }
                                            });
                                            spawn(async {
                                                let _ = crate::components::app::chat_delegate::save_boards_to_delegate().await;
                                            });
                                        }
                                            Err(message) => error.set(Some(message)),
                                        }
                                        busy.set(false);
                                    });
                                },
                                if *busy.read() { "Sending…" } else { "Reply" }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn short_id(id: plaza_core::board_state::member::MemberId) -> String {
    id.to_string().chars().take(8).collect()
}

fn short_topic(id: MessageId) -> String {
    id.to_string().chars().take(8).collect()
}

fn format_time(ms: i64) -> String {
    if ms <= 0 {
        return String::new();
    }
    format!("{}", ms / 1000)
}

fn reaction_bar(
    board: &crate::board_data::BoardData,
    state: &plaza_topic_core::TopicStateV1,
    topic_id: MessageId,
    part: u32,
    target: MessageId,
    owner: ed25519_dalek::VerifyingKey,
    self_id: plaza_core::board_state::member::MemberId,
) -> Element {
    if !state.authority.policy().reactions_enabled {
        return rsx! {};
    }
    let reactions = topic_contract::reactions_for(board, state, target);
    rsx! {
        div { class: "mt-2 flex items-center gap-1.5 flex-wrap",
            for emoji in REACTIONS {
                {
                    let members = reactions.get(emoji).cloned().unwrap_or_default();
                    let count = members.len();
                    let mine = members.contains(&self_id);
                    let value = emoji.to_string();
                    let class = if mine {
                        "px-2 py-0.5 rounded-full border border-accent/60 bg-accent/15 text-xs text-accent"
                    } else {
                        "px-2 py-0.5 rounded-full border border-border bg-surface text-xs text-text-muted hover:border-accent/50"
                    };
                    rsx! {
                        button {
                            r#type: "button",
                            class: "{class}",
                            onclick: move |_| {
                                let value = value.clone();
                                spawn(async move {
                                    let _ = topic_contract::toggle_reaction(
                                        owner,
                                        topic_id,
                                        part,
                                        target,
                                        value,
                                        !mine,
                                    )
                                    .await;
                                });
                            },
                            "{emoji}"
                            if count > 0 {
                                span { class: "ml-1", "{count}" }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn poll_block(
    board: &crate::board_data::BoardData,
    state: &plaza_topic_core::TopicStateV1,
    topic_id: MessageId,
    part: u32,
    poll_id: MessageId,
    poll: PollContentV1,
    owner: ed25519_dalek::VerifyingKey,
    _self_id: plaza_core::board_state::member::MemberId,
) -> Element {
    let counts = topic_contract::poll_votes(board, state, poll_id);
    let total: usize = counts.iter().map(|members| members.len()).sum();
    let now = plaza_core::board_state::rate_limit::system_time_ms(
        crate::util::get_current_system_time(),
    );
    let closed = poll.closes_at.is_some_and(|closes| closes <= now);
    rsx! {
        div { class: "mt-2 rounded-lg border border-border bg-surface p-3",
            p { class: "text-sm font-medium text-text", "{poll.title}" }
            if !poll.description.trim().is_empty() {
                p { class: "mt-1 text-xs text-text-muted", "{poll.description}" }
            }
            div { class: "mt-2 flex flex-col gap-1.5",
                for (index, option) in poll.options.iter().enumerate() {
                    {
                        let count = counts
                            .get(index)
                            .map(|members| members.len())
                            .unwrap_or(0);
                        let owner = owner;
                        let option = option.clone();
                        let index = index as u16;
                        rsx! {
                            button {
                                r#type: "button",
                                class: "flex items-center justify-between gap-3 px-3 py-1.5 rounded-lg border border-border text-sm text-text hover:bg-panel disabled:opacity-60",
                                disabled: closed,
                                onclick: move |_| {
                                    spawn(async move {
                                        let _ = topic_contract::vote(
                                            owner,
                                            topic_id,
                                            part,
                                            poll_id,
                                            vec![index],
                                        )
                                        .await;
                                    });
                                },
                                span { "{option}" }
                                span { class: "text-xs text-text-muted", "{count}" }
                            }
                        }
                    }
                }
            }
            p { class: "mt-2 text-[11px] text-text-muted",
                "{total} votes"
                if closed { " · closed" }
            }
        }
    }
}
