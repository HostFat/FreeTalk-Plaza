//! One discussion backed by a `plaza-topic` contract.

mod helpers;
mod widgets;

use helpers::{
    attach_topic_files, format_full_time, format_time, open_topic_image_picker,
    reactor_names_map, refresh_topic_reply_mentions, selected_topic_files, short_id, short_topic,
};
use widgets::{PollBlock, ReactionBar};

use crate::board_data::PendingUpload;
use crate::components::app::topic_contract;
use crate::components::app::{Route, BOARDS, CURRENT_BOARD};
use crate::components::conversation::emoji_picker::EmojiPicker;
use crate::components::conversation::image_attachment::ImageAttachment;
use crate::util::image_processing::{prepare_image, ImageMode};
use crate::util::mentions::{MentionAutocomplete, MentionDirectory};
use dioxus::prelude::*;
use plaza_core::board_state::content::PollContentV1;
use plaza_core::board_state::images::ImageRef;
use plaza_core::board_state::member::MemberId;
use plaza_core::board_state::message::MessageId;
use plaza_core::board_state::reports::ReportReason;
use plaza_core::board_state::topics::TopicFlagKind;
use plaza_topic_core::{TopicPostContentV1, MAX_IMAGES_PER_POST};
use std::collections::{BTreeMap, HashMap};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;

const REACTIONS: [&str; 5] = ["👍", "❤️", "😂", "🎉", "🤔"];
const TOPIC_REPLY_INPUT_ID: &str = "topic-reply-input";
const TOPIC_IMAGE_INPUT_ID: &str = "topic-image-file-input";

#[derive(Clone, Debug, PartialEq)]
enum TopicAttachmentState {
    Uploading,
    Ready(ImageRef),
    Failed(String),
}

#[derive(Clone, Debug, PartialEq)]
struct TopicAttachment {
    id: String,
    name: String,
    state: TopicAttachmentState,
}

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
    let mut synced_authority = use_signal(|| None::<(u32, i64)>);
    let mut marked_read = use_signal(|| 0i64);
    let mut draft_loaded = use_signal(|| false);
    let mut earlier_parts = use_signal(Vec::<u32>::new);
    let mut editing_topic = use_signal(|| false);
    let mut edit_title = use_signal(String::new);
    let mut edit_body = use_signal(String::new);
    let editing_post = use_signal(|| None::<MessageId>);
    let edit_reply = use_signal(String::new);
    let mut poll_mode = use_signal(|| false);
    let mut poll_question = use_signal(String::new);
    let mut poll_options = use_signal(|| vec![String::new(), String::new()]);
    let mut poll_multiselect = use_signal(|| false);
    let mut poll_busy = use_signal(|| false);
    let mut move_target = use_signal(|| None::<MessageId>);
    let mut merge_target = use_signal(|| None::<MessageId>);
    let mut attachments = use_signal(Vec::<TopicAttachment>::new);
    let next_attachment_id = use_signal(|| 0u64);
    let mut mention_autocomplete = use_signal(|| None::<MentionAutocomplete>);
    let mut autoscrolled = use_signal(|| false);

    // Pin long topics to the latest reply on initial open.
    use_effect(move || {
        if *autoscrolled.read() {
            return;
        }
        let has_posts = topic_contract::topic_head(owner, topic_id_value)
            .is_some_and(|head| !head.posts.is_empty());
        if !has_posts {
            return;
        }
        autoscrolled.set(true);
        #[cfg(target_arch = "wasm32")]
        {
            spawn_local(async {
                crate::util::sleep(std::time::Duration::from_millis(60)).await;
                crate::util::scroll_conversation_to_bottom("message-scroll");
                crate::util::sleep(std::time::Duration::from_millis(120)).await;
                crate::util::scroll_conversation_to_bottom("message-scroll");
            });
        }
    });

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
            let _ = crate::components::app::chat_delegate::save_boards_to_delegate().await;
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
            // Always load part 0 (topic head: title, body, section, flags).
            // When part_now > 0, also load the active append-only post page.
            let parts_to_load: Vec<u32> = if part_now == 0 {
                vec![0]
            } else {
                vec![0, part_now]
            };
            for target_part in parts_to_load {
                for attempt in 0..3 {
                    match topic_contract::load_topic(owner, topic_id_value, target_part).await {
                        Ok(_) => {
                            if let Err(message) = topic_contract::sync_topic_authority(
                                owner,
                                topic_id_value,
                                target_part,
                            )
                            .await
                            {
                                error.set(Some(message));
                            }
                            break;
                        }
                        Err(message) => {
                            dioxus::logger::tracing::warn!(
                                "load_topic failed for part {target_part} (attempt {}): {message}",
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
            }
        });
    });

    // On-demand authority sync: whenever this topic finishes loading OR the
    // board's authority snapshot changes while this topic is open, push the
    // updated root/proofs to this topic's head (and active page) in O(1).
    use_effect(move || {
        let Some(auth_hash) = BOARDS
            .read()
            .map
            .get(&owner)
            .map(topic_contract::authority_hash)
        else {
            return;
        };
        let head_ready = topic_contract::topic_head(owner, topic_id_value)
            .is_some_and(|head| head.header.is_some());
        if !head_ready {
            return;
        }
        let part_now = (*loaded_part.read()).unwrap_or(0);
        if part_now > 0 {
            let page_ready = topic_contract::topic_state(owner, topic_id_value, part_now)
                .is_some_and(|page| page.is_loaded());
            if !page_ready {
                return;
            }
        }
        if *synced_authority.peek() == Some((part_now, auth_hash)) {
            return;
        }
        synced_authority.set(Some((part_now, auth_hash)));
        spawn(async move {
            let _ = topic_contract::sync_topic_authority(owner, topic_id_value, 0).await;
            if part_now > 0 {
                let _ =
                    topic_contract::sync_topic_authority(owner, topic_id_value, part_now).await;
            }
        });
    });

    // Lazily load only the member and profile shard buckets for authors and
    // participants present in this topic head, active page, and loaded earlier
    // parts.
    use_effect(move || {
        let mut ids: Vec<MemberId> = Vec::new();
        if let Some(head) = topic_contract::topic_head(owner, topic_id_value) {
            if let Some(header) = &head.header {
                ids.push(header.header.author);
            }
            for post in head.posts.values() {
                ids.push(post.post.author);
            }
            for participant in &head.participants {
                ids.push(participant.record.member_id);
            }
        }
        if part > 0 {
            if let Some(active) = topic_contract::topic_state(owner, topic_id_value, part) {
                for post in active.posts().values() {
                    ids.push(post.post.author);
                }
                for participant in active.participants() {
                    ids.push(participant.record.member_id);
                }
            }
        }
        for earlier in earlier_parts.read().iter().copied() {
            if let Some(prev) = topic_contract::topic_state(owner, topic_id_value, earlier) {
                for post in prev.posts().values() {
                    ids.push(post.post.author);
                }
            }
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

    let head = topic_contract::topic_head(owner, topic_id_value);
    let Some(head) = head else {
        return rsx! {
            div { class: "max-w-3xl mx-auto px-4 py-8 text-text-muted", "Loading topic…" }
        };
    };
    let Some(header) = head.header.as_ref() else {
        return rsx! {
            div { class: "max-w-3xl mx-auto px-4 py-8 text-text-muted", "Loading topic…" }
        };
    };
    let head_part_state = topic_contract::TopicPartState::Head(head.clone());
    let state = if part == 0 {
        head_part_state.clone()
    } else {
        let Some(page_state) = topic_contract::topic_state(owner, topic_id_value, part) else {
            return rsx! {
                div { class: "max-w-3xl mx-auto px-4 py-8 text-text-muted", "Loading topic…" }
            };
        };
        if !page_state.is_loaded() {
            return rsx! {
                div { class: "max-w-3xl mx-auto px-4 py-8 text-text-muted", "Loading topic…" }
            };
        }
        page_state
    };

    let self_id = MemberId::from(&board_data.self_sk.verifying_key());
    let (header_title, header_body) =
        topic_contract::effective_topic_content(&board_data, &head)
            .unwrap_or((header.header.title.clone(), header.header.body.clone()));
    let title =
        topic_contract::read_text(&board_data, &header_title).unwrap_or_else(|| "Untitled".to_string());
    let body = topic_contract::read_text(&board_data, &header_body).unwrap_or_default();
    let topic_edited = topic_contract::is_topic_edited(&head);
    let can_edit_topic = header.header.author == self_id;
    let author = board_data
        .display_nickname(header.header.author)
        .unwrap_or_else(|| short_id(header.header.author));
    let closed = head.is_closed();
    let deleted = head.is_deleted(header.header.id());
    let pinned = head.is_pinned();
    let announced = head.is_announced();
    let hidden = head.is_hidden();
    let is_owner = !crate::components::app::view_as_member()
        && !board_data.spectator
        && board_data.is_active_owner();
    let now_ms = plaza_core::board_state::rate_limit::system_time_ms(
        crate::util::get_current_system_time(),
    );
    let is_banned_on_board = |member: MemberId| {
        board_data.board_state.bans.0.iter().any(|ban| {
            ban.ban.banned_user == member
                && !board_data.board_state.ban_revocations.revoked(&ban.id())
        })
    };
    let banned = head.is_banned_member(self_id, now_ms)
        || state.is_banned_member(self_id, now_ms)
        || is_banned_on_board(self_id);
    let suspended = head.is_suspended_member(self_id, now_ms)
        || state.is_suspended_member(self_id, now_ms);
    let effective_section = head.effective_section();
    let effective_section_id = effective_section.as_ref().map(|section| section.section);
    let scope_chain = effective_section
        .as_ref()
        .map(|section| section.chain.clone())
        .unwrap_or_default();
    let can_moderate = is_owner || board_data.can_moderate(&scope_chain);
    let merged_into = head.merged_into();
    let topic_for_flags = topic_id_value;
    let owner_for_flags = board_data.owner_vk;

    let images_allowed = head
        .section
        .as_ref()
        .map(|section| section.snapshot.images_allowed)
        .unwrap_or(true)
        && head.authority.policy().images_allowed
        && board_data.may_write_content();
    let reactions_enabled = state.authority().policy().reactions_enabled;
    let head_reactions_enabled = head_part_state.authority().policy().reactions_enabled;

    let mention_dir = MentionDirectory::from_board(&board_data);
    let mention_context = mention_autocomplete.read().clone();
    let mention_items = mention_context
        .as_ref()
        .map(|ctx| mention_dir.search(&ctx.query))
        .unwrap_or_default();

    let body_html = if body.trim().is_empty() {
        String::new()
    } else {
        mention_dir.render_html(&body, Some(self_id))
    };

    let mut posts: Vec<_> = state.posts().values().cloned().collect();
    posts.sort_by_key(|post| (post.post.created_at, *post.id().as_bytes()));
    let visible_posts: Vec<_> = posts
        .into_iter()
        .filter(|post| !state.is_deleted(post.id()))
        .filter(|post| !state.is_split(post.id()))
        .filter(|post| {
            let head_trusted = head.is_trusted(post.post.author);
            state.post_is_visible(post, head_trusted)
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

    let has_uploading = attachments
        .read()
        .iter()
        .any(|att| matches!(att.state, TopicAttachmentState::Uploading));
    let has_ready_images = attachments
        .read()
        .iter()
        .any(|att| matches!(att.state, TopicAttachmentState::Ready(_)));

    let head_reactions = topic_contract::reactions_for(&board_data, &head_part_state, header.header.id());
    let head_reactor_names = reactor_names_map(&board_data, &head_reactions);

    rsx! {
        div {
            id: "message-scroll",
            class: "flex-1 min-h-0 w-full overflow-y-auto",
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
                if header.header.auto_moderated {
                    span { class: "text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300", "Auto-moderated" }
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
                div { class: "mt-1 flex items-center gap-2 text-xs text-text-muted flex-wrap",
                    span { "{author}" }
                    if header.header.created_at > 0 {
                        span { "·" }
                        span {
                            title: "{format_full_time(header.header.created_at)}",
                            "{format_time(header.header.created_at)}"
                        }
                    }
                    if topic_edited {
                        span { class: "italic", "· edited" }
                    }
                }
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
                    {
                        let next_earlier = (0..part)
                            .rev()
                            .find(|candidate| !earlier_parts.read().contains(candidate));
                        if let Some(previous) = next_earlier {
                            rsx! {
                                button {
                                    r#type: "button",
                                    class: "mt-1 text-xs text-accent hover:underline",
                                    onclick: move |_| {
                                        let owner = board_data.owner_vk;
                                        spawn(async move {
                                            match topic_contract::load_topic(owner, topic_id_value, previous).await {
                                                Ok(_) => {
                                                    earlier_parts.with_mut(|parts| {
                                                        if !parts.contains(&previous) {
                                                            parts.push(previous);
                                                            parts.sort_unstable();
                                                        }
                                                    });
                                                }
                                                Err(message) => error.set(Some(message)),
                                            }
                                        });
                                    },
                                    "Load earlier posts"
                                }
                            }
                        } else {
                            rsx! {}
                        }
                    }
                }
                if !body_html.is_empty() {
                    div {
                        class: "mt-4 prose-message text-text",
                        dangerous_inner_html: "{body_html}",
                    }
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
                        div { class: "mt-3 flex items-center gap-3",
                            button {
                                r#type: "button",
                                class: "text-xs text-accent hover:underline",
                                onclick: move |_| {
                                    edit_title.set(title.clone());
                                    edit_body.set(body.clone());
                                    editing_topic.set(true);
                                },
                                "Edit topic"
                            }
                            if !deleted {
                                button {
                                    r#type: "button",
                                    class: "text-xs text-red-400 hover:underline",
                                    onclick: {
                                        let header_id = header.header.id();
                                        let delete_nav = split_navigator.clone();
                                        let delete_board = board_id.clone();
                                        move |_| {
                                            let delete_nav = delete_nav.clone();
                                            let delete_board = delete_board.clone();
                                            spawn(async move {
                                                match topic_contract::delete_post(
                                                    owner,
                                                    topic_id_value,
                                                    0,
                                                    header_id,
                                                )
                                                .await
                                                {
                                                    Ok(()) => {
                                                        delete_nav.push(Route::Posts {
                                                            board_id: delete_board,
                                                        });
                                                    }
                                                    Err(message) => error.set(Some(message)),
                                                }
                                            });
                                        }
                                    },
                                    "Delete topic"
                                }
                            }
                        }
                    }
                }
                ReactionBar {
                    reactions: head_reactions,
                    member_names: head_reactor_names,
                    reactions_enabled: head_reactions_enabled,
                    owner: board_data.owner_vk,
                    topic_id: topic_id_value,
                    part: 0,
                    target: header.header.id(),
                    self_id,
                }
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

            for previous in earlier_parts.read().iter().copied().filter(|&p| p < part) {
                if let Some(previous_state) =
                    topic_contract::topic_state(owner, topic_id_value, previous)
                {
                    div {
                        key: "earlier-part-{previous}",
                        class: "bg-surface border border-border rounded-xl p-4",
                        div { class: "flex items-center gap-2",
                            h3 { class: "text-sm font-semibold text-text",
                                "Part {previous + 1}"
                            }
                            if previous_state.is_sealed() {
                                span { class: "text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-panel border border-border text-text-muted",
                                    "Sealed"
                                }
                            }
                        }
                        div { class: "mt-2 flex flex-col gap-2",
                            {
                                let mut previous_posts: Vec<_> = previous_state
                                    .posts()
                                    .values()
                                    .filter(|post| {
                                        !previous_state.is_deleted(post.id())
                                            && !previous_state.is_split(post.id())
                                    })
                                    .cloned()
                                    .collect();
                                previous_posts.sort_by_key(|post| (post.post.created_at, *post.id().as_bytes()));
                                rsx! {
                                    for post in previous_posts {
                                        {
                                            let author = board_data
                                                .display_nickname(post.post.author)
                                                .unwrap_or_else(|| short_id(post.post.author));
                                            let sealed_content = topic_contract::effective_post_content(
                                                &board_data,
                                                &previous_state,
                                                post.id(),
                                            );
                                            let decoded = sealed_content.as_ref().and_then(|sealed| {
                                                topic_contract::read_post_content(&board_data, sealed)
                                            });
                                            let (html, poll_title) = match &decoded {
                                                Some(TopicPostContentV1::Text(text)) if !text.trim().is_empty() => {
                                                    (mention_dir.render_html(text, Some(self_id)), None)
                                                }
                                                Some(TopicPostContentV1::Poll(poll)) => {
                                                    (String::new(), Some(poll.title.clone()))
                                                }
                                                _ => (String::new(), None),
                                            };
                                            let post_images = post.post.images.clone();
                                            rsx! {
                                                div { class: "bg-panel border border-border rounded-lg px-3 py-2",
                                                    div { class: "flex items-center gap-2",
                                                        span { class: "text-sm font-medium text-text", "{author}" }
                                                        span {
                                                            class: "text-[11px] text-text-muted",
                                                            title: "{format_full_time(post.post.created_at)}",
                                                            "{format_time(post.post.created_at)}"
                                                        }
                                                    }
                                                    if !html.is_empty() {
                                                        div {
                                                            class: "mt-1 prose-message text-text",
                                                            dangerous_inner_html: "{html}",
                                                        }
                                                    } else if let Some(poll_title) = poll_title {
                                                        div { class: "mt-1 prose-message text-text",
                                                            p { "[Poll: {poll_title}]" }
                                                        }
                                                    }
                                                    if !post_images.is_empty() {
                                                        div { class: "mt-2 flex flex-wrap gap-2",
                                                            for (img_idx, img) in post_images.iter().enumerate() {
                                                                ImageAttachment {
                                                                    key: "prev-img-{img_idx}",
                                                                    image: img.clone(),
                                                                    gallery: post_images.clone(),
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
                            let content_html = if content.trim().is_empty() {
                                String::new()
                            } else {
                                mention_dir.render_html(&content, Some(self_id))
                            };
                            let poll = match &decoded {
                                Some(TopicPostContentV1::Poll(poll)) => Some(poll.clone()),
                                _ => None,
                            };
                            let has_poll = poll.is_some();
                            let post_edited = topic_contract::is_post_edited(&state, id);
                            let post_images = post_value.images.clone();
                            let can_delete = post_value.author == self_id || is_owner;
                            let can_edit = post_value.author == self_id || is_owner;
                            let pending = !state.post_is_visible(&post, head.is_trusted(post_value.author));
                            let author_banned =
                                head.is_banned_member(post_value.author, now_ms)
                                    || state.is_banned_member(post_value.author, now_ms)
                                    || board_for_reply.board_state.bans.0.iter().any(|ban| {
                                        ban.ban.banned_user == post_value.author
                                            && !board_for_reply
                                                .board_state
                                                .ban_revocations
                                                .revoked(&ban.id())
                                    });
                            let owner = board_for_reply.owner_vk;
                            let mut editing_post = editing_post;
                            let mut edit_reply = edit_reply;
                            let content_for_edit = content.clone();
                            let navigator = split_navigator.clone();
                            let split_board = board_id.clone();
                            let post_reactions = topic_contract::reactions_for(&board_for_reply, &state, id);
                            let post_reactor_names = reactor_names_map(&board_for_reply, &post_reactions);
                            rsx! {
                                div {
                                    key: "{id}",
                                    class: "bg-panel border border-border rounded-lg px-4 py-3",
                                    div { class: "flex items-center gap-2 flex-wrap",
                                        span { class: "text-sm font-medium text-text", "{author}" }
                                        span {
                                            class: "text-[11px] text-text-muted",
                                            title: "{format_full_time(post_value.created_at)}",
                                            "{format_time(post_value.created_at)}"
                                        }
                                        if post_edited {
                                            span { class: "text-[11px] text-text-muted italic", "· edited" }
                                        }
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
                                        if can_edit && !has_poll {
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
                                    if !content_html.is_empty() {
                                        div {
                                            class: "mt-2 prose-message text-text",
                                            dangerous_inner_html: "{content_html}",
                                        }
                                    }
                                    if !post_images.is_empty() {
                                        div { class: "mt-2 flex flex-wrap gap-2",
                                            for (img_idx, img) in post_images.iter().enumerate() {
                                                ImageAttachment {
                                                    key: "post-img-{img_idx}",
                                                    image: img.clone(),
                                                    gallery: post_images.clone(),
                                                }
                                            }
                                        }
                                    }
                                    if let Some(poll) = poll {
                                        PollBlock {
                                            poll,
                                            counts: topic_contract::poll_votes(&board_for_reply, &state, id),
                                            owner: board_for_reply.owner_vk,
                                            topic_id: topic_id_value,
                                            part,
                                            poll_id: id,
                                            self_id,
                                            can_edit,
                                            edited: post_edited,
                                        }
                                    }
                                    ReactionBar {
                                        reactions: post_reactions,
                                        member_names: post_reactor_names,
                                        reactions_enabled,
                                        owner: board_for_reply.owner_vk,
                                        topic_id: topic_id_value,
                                        part,
                                        target: id,
                                        self_id,
                                    }
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
                    div { class: "flex items-center gap-2 flex-wrap",
                        button {
                            r#type: "button",
                            class: "px-2.5 py-1 rounded-lg border border-border text-xs text-text hover:bg-panel",
                            onclick: move |_| {
                                let next = !*poll_mode.read();
                                poll_mode.set(next);
                            },
                            "Poll"
                        }
                        if images_allowed && !*poll_mode.read() {
                            input {
                                id: "{TOPIC_IMAGE_INPUT_ID}",
                                r#type: "file",
                                accept: "image/*",
                                multiple: true,
                                class: "hidden",
                                onchange: move |_| {
                                    if let Some(files) = selected_topic_files() {
                                        attach_topic_files(
                                            files,
                                            owner,
                                            effective_section_id,
                                            attachments,
                                            next_attachment_id,
                                        );
                                    }
                                },
                            }
                            button {
                                r#type: "button",
                                class: "px-2.5 py-1 rounded-lg border border-border text-xs text-text hover:bg-panel disabled:opacity-50",
                                disabled: attachments.read().len() >= MAX_IMAGES_PER_POST,
                                onclick: move |_| open_topic_image_picker(),
                                "Attach image"
                            }
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
                            for (index, option) in poll_options.read().iter().enumerate() {
                                div {
                                    key: "poll-opt-{index}",
                                    class: "flex items-center gap-2",
                                    input {
                                        class: "flex-1 px-3 py-2 bg-panel border border-border rounded-lg text-text",
                                        placeholder: "Option {index + 1}",
                                        value: "{option}",
                                        oninput: move |event| {
                                            let value = event.value();
                                            poll_options.with_mut(|list| {
                                                if let Some(slot) = list.get_mut(index) {
                                                    *slot = value;
                                                }
                                            });
                                        },
                                    }
                                    if poll_options.read().len() > 2 {
                                        button {
                                            r#type: "button",
                                            class: "px-2 py-1 text-xs text-text-muted hover:text-red-400",
                                            onclick: move |_| {
                                                poll_options.with_mut(|list| {
                                                    if list.len() > 2 && index < list.len() {
                                                        list.remove(index);
                                                    }
                                                });
                                            },
                                            "×"
                                        }
                                    }
                                }
                            }
                            div { class: "flex items-center justify-between gap-2 flex-wrap",
                                button {
                                    r#type: "button",
                                    class: "text-xs text-accent hover:underline",
                                    onclick: move |_| {
                                        poll_options.with_mut(|list| {
                                            if list.len() < 10 {
                                                list.push(String::new());
                                            }
                                        });
                                    },
                                    "+ Add option"
                                }
                                label { class: "flex items-center gap-1.5 text-xs text-text-muted cursor-pointer select-none",
                                    input {
                                        r#type: "checkbox",
                                        checked: *poll_multiselect.read(),
                                        onchange: move |event| poll_multiselect.set(event.checked()),
                                    }
                                    "Allow multiple choices"
                                }
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
                                        let options = poll_options.read().clone();
                                        let multiselect = *poll_multiselect.read();
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
                                                multiselect,
                                            )
                                            .await
                                            {
                                                Ok(()) => {
                                                    poll_question.set(String::new());
                                                    poll_options.set(vec![String::new(), String::new()]);
                                                    poll_multiselect.set(false);
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
                        if !attachments.read().is_empty() {
                            div { class: "flex flex-wrap gap-2",
                                for att in attachments.read().iter() {
                                    {
                                        let att_id = att.id.clone();
                                        let status_label = match &att.state {
                                            TopicAttachmentState::Uploading => "Uploading…".to_string(),
                                            TopicAttachmentState::Ready(_) => "Ready".to_string(),
                                            TopicAttachmentState::Failed(msg) => format!("Failed: {msg}"),
                                        };
                                        let chip_class = match &att.state {
                                            TopicAttachmentState::Failed(_) => {
                                                "flex items-center gap-2 px-2.5 py-1 rounded-lg border border-red-500/40 bg-red-500/10 text-xs text-red-300"
                                            }
                                            _ => {
                                                "flex items-center gap-2 px-2.5 py-1 rounded-lg border border-border bg-panel text-xs text-text"
                                            }
                                        };
                                        rsx! {
                                            div {
                                                key: "{att_id}",
                                                class: "{chip_class}",
                                                span { class: "truncate max-w-44", "{att.name}" }
                                                span { class: "text-[11px] text-text-muted", "{status_label}" }
                                                button {
                                                    r#type: "button",
                                                    class: "text-text-muted hover:text-red-400",
                                                    onclick: move |_| {
                                                        attachments.with_mut(|list| {
                                                            list.retain(|item| item.id != att_id);
                                                        });
                                                    },
                                                    "×"
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        div { class: "relative",
                            textarea {
                                id: "{TOPIC_REPLY_INPUT_ID}",
                                class: "w-full min-h-24 px-3 py-2 bg-panel border border-border rounded-lg text-text",
                                placeholder: "Write a reply…",
                                value: "{reply}",
                                oninput: move |event| {
                                    let value = event.value();
                                    reply.set(value.clone());
                                    refresh_topic_reply_mentions(mention_autocomplete);
                                    BOARDS.with_mut(|boards| {
                                        if let Some(board) = boards.map.get_mut(&owner) {
                                            board.set_topic_draft(topic_id_value, &value);
                                        }
                                    });
                                    spawn(async {
                                        let _ = crate::components::app::chat_delegate::save_boards_to_delegate().await;
                                    });
                                },
                                onclick: move |_| refresh_topic_reply_mentions(mention_autocomplete),
                                onkeyup: move |event| {
                                    if !matches!(
                                        event.key(),
                                        Key::ArrowDown | Key::ArrowUp | Key::Enter | Key::Tab | Key::Escape
                                    ) {
                                        refresh_topic_reply_mentions(mention_autocomplete);
                                    }
                                },
                                onkeydown: {
                                    let items = mention_items.clone();
                                    move |event: KeyboardEvent| {
                                        let current_ctx = mention_autocomplete.read().clone();
                                        if let Some(ctx) = current_ctx {
                                            if !items.is_empty() {
                                                match event.key() {
                                                    Key::ArrowDown => {
                                                        event.prevent_default();
                                                        let mut next = ctx;
                                                        next.selected = (next.selected + 1) % items.len();
                                                        mention_autocomplete.set(Some(next));
                                                        return;
                                                    }
                                                    Key::ArrowUp => {
                                                        event.prevent_default();
                                                        let mut next = ctx;
                                                        next.selected = if next.selected == 0 {
                                                            items.len() - 1
                                                        } else {
                                                            next.selected - 1
                                                        };
                                                        mention_autocomplete.set(Some(next));
                                                        return;
                                                    }
                                                    Key::Enter | Key::Tab => {
                                                        if let Some(member) = items.get(ctx.selected) {
                                                            event.prevent_default();
                                                            let value = crate::util::mentions::replace_context(
                                                                TOPIC_REPLY_INPUT_ID,
                                                                &ctx,
                                                                member,
                                                            );
                                                            reply.set(value);
                                                            mention_autocomplete.set(None);
                                                            return;
                                                        }
                                                    }
                                                    Key::Escape => {
                                                        event.prevent_default();
                                                        mention_autocomplete.set(None);
                                                        return;
                                                    }
                                                    _ => {}
                                                }
                                            } else if event.key() == Key::Escape {
                                                mention_autocomplete.set(None);
                                            }
                                        }
                                    }
                                },
                            }
                            if let Some(context) = mention_context.clone() {
                                if !mention_items.is_empty() {
                                    div {
                                        class: "mention-autocomplete absolute left-0 right-0 top-full z-50 mt-1 max-h-64 overflow-y-auto rounded-lg border border-border bg-panel shadow-xl",
                                        for (index, member) in mention_items.iter().enumerate() {
                                            button {
                                                r#type: "button",
                                                class: if index == context.selected {
                                                    "mention-option flex w-full items-center px-3 py-2 text-left text-sm bg-accent text-white"
                                                } else {
                                                    "mention-option flex w-full items-center px-3 py-2 text-left text-sm text-text hover:bg-surface-hover"
                                                },
                                                onmousedown: move |evt| evt.prevent_default(),
                                                onclick: {
                                                    let member = member.clone();
                                                    let context = context.clone();
                                                    move |_| {
                                                        let value = crate::util::mentions::replace_context(
                                                            TOPIC_REPLY_INPUT_ID,
                                                            &context,
                                                            &member,
                                                        );
                                                        reply.set(value);
                                                        mention_autocomplete.set(None);
                                                    }
                                                },
                                                "@{member.name}"
                                            }
                                        }
                                        div { class: "px-3 py-1.5 text-[10px] text-text-muted border-t border-border",
                                            "↑↓ select · Enter insert · Esc close"
                                        }
                                    }
                                }
                            }
                        }
                        if let Some(message) = error.read().as_ref() {
                            p { class: "text-sm text-red-400", "{message}" }
                        }
                        div { class: "flex justify-end",
                            button {
                                r#type: "button",
                                disabled: *busy.read()
                                    || has_uploading
                                    || (reply.read().trim().is_empty() && !has_ready_images),
                                class: "px-4 py-2 rounded-lg bg-accent hover:bg-accent-hover disabled:opacity-50 text-white text-sm",
                                onclick: move |_| {
                                    if *busy.read() {
                                        return;
                                    }
                                    busy.set(true);
                                    error.set(None);
                                    let text = reply_text.read().clone();
                                    let ready_images: Vec<ImageRef> = attachments
                                        .read()
                                        .iter()
                                        .filter_map(|att| match &att.state {
                                            TopicAttachmentState::Ready(img) => Some(img.clone()),
                                            _ => None,
                                        })
                                        .collect();
                                    let owner = owner;
                                    spawn(async move {
                                        match topic_contract::send_reply_with_images(
                                            owner,
                                            topic_for_reply,
                                            part,
                                            text,
                                            ready_images,
                                        )
                                        .await
                                        {
                                            Ok(()) => {
                                                reply.set(String::new());
                                                attachments.set(Vec::new());
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
}
