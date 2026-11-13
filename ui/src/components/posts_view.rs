use crate::components::app::chat_delegate::save_boards_to_delegate;
use crate::components::app::{
    CurrentCategoryContext, CurrentPostContext, Route, BOARDS, CURRENT_BOARD, CURRENT_CATEGORY,
    CURRENT_POST,
};
use crate::components::category_create_modal::CREATE_CATEGORY_MODAL;
use crate::components::category_view::{CategoryCard, CategoryEditData};
use crate::components::conversation::{
    get_all_messages, get_category_posts, get_subcategories, get_top_level_categories,
    get_top_level_posts, MessageCard, MessageCardVariant, MessageData,
};
use crate::util::avatar::get_avatar;
use crate::util::format_utc_as_local_time;
use crate::util::message_actions::{self, ActionContext};
use dioxus::prelude::*;
use plaza_core::board_state::member::MemberId;
use plaza_core::board_state::message::MessageId;
use plaza_core::board_state::moderation::category_chain;
use plaza_core::board_state::roles::ModerationPower;
use std::collections::{HashMap, HashSet};
use wasm_bindgen::JsCast;

use wasm_bindgen_futures::spawn_local;

/// Breadcrumb item for category navigation
#[derive(Clone, PartialEq)]
struct BreadcrumbItem {
    id: Option<String>, // None = root
    name: String,
    icon: Option<String>,
    is_group: bool,
}

/// Build breadcrumb trail from root to current category
fn build_breadcrumbs(
    category_id: Option<&String>,
    all_messages: &[MessageData],
) -> Vec<BreadcrumbItem> {
    let mut crumbs = vec![BreadcrumbItem {
        id: None,
        name: "Home".to_string(),
        icon: Some("🏠".to_string()),
        is_group: false,
    }];

    if let Some(cat_id) = category_id {
        // Build chain from current category up to root
        let mut chain = Vec::new();
        let mut current_id = Some(cat_id.clone());

        while let Some(cid) = current_id {
            if let Some(cat) = all_messages
                .iter()
                .find(|m| m.id_string() == cid && m.is_category)
            {
                chain.push(BreadcrumbItem {
                    id: Some(cat.id_string()),
                    name: cat
                        .category_name
                        .clone()
                        .unwrap_or_else(|| "Unnamed".to_string()),
                    icon: None,
                    is_group: cat.is_group,
                });
                current_id = cat.parent_category_id.as_ref().map(|id| id.to_string());
            } else {
                break;
            }
        }

        // Reverse to get root-to-current order
        chain.reverse();
        crumbs.extend(chain);
    }

    crumbs
}

/// Get content (subcategories and posts) for a category or root
fn get_content(
    category_id: Option<&String>,
    all_messages: &[MessageData],
) -> (Vec<MessageData>, Vec<MessageData>) {
    if let Some(cat_id_str) = category_id {
        // Parse category_id to MessageId
        if let Some(cat_msg_id) = cat_id_str.parse::<MessageId>().ok() {
            let categories = get_subcategories(all_messages, &cat_msg_id);
            let posts = get_category_posts(all_messages, &cat_msg_id);
            return (categories, posts);
        }
    }
    // Root level
    let categories = get_top_level_categories(all_messages);
    let posts = get_top_level_posts(all_messages);
    (categories, posts)
}

/// Posts newer than `read_upto` in a category subtree.
fn unread_in_category(
    id: &MessageId,
    children: &HashMap<MessageId, Vec<&MessageData>>,
    read_upto: i64,
) -> usize {
    let mut count = 0usize;
    let mut stack: Vec<&MessageId> = vec![id];
    while let Some(parent) = stack.pop() {
        let Some(replies) = children.get(parent) else {
            continue;
        };
        for reply in replies {
            stack.push(&reply.message_id);
            if !reply.is_category
                && reply.merged_into.is_none()
                && reply.time.timestamp_millis() > read_upto
            {
                count += 1;
            }
        }
    }
    count
}

/// Mark a section as read up to now and persist the local preference.
fn mark_category_read(category_id: MessageId) {
    let now = chrono::Utc::now().timestamp_millis();
    let mut changed = false;
    BOARDS.with_mut(|boards| {
        if let Some(owner) = CURRENT_BOARD.read().owner_key {
            if let Some(board) = boards.map.get_mut(&owner) {
                board.read_categories.insert(category_id, now);
                changed = true;
            }
        }
    });
    if changed {
        spawn_local(async {
            let _ = save_boards_to_delegate().await;
        });
    }
}

/// Posts and newest post below a category, descending into subcategories.
fn category_stats(
    id: &MessageId,
    children: &HashMap<MessageId, Vec<&MessageData>>,
) -> (usize, Option<(String, String)>) {
    let mut count = 0usize;
    let mut latest: Option<(String, String, i64)> = None;
    let mut stack: Vec<&MessageId> = vec![id];
    while let Some(parent) = stack.pop() {
        let Some(replies) = children.get(parent) else {
            continue;
        };
        for reply in replies {
            stack.push(&reply.message_id);
            if reply.is_category || reply.merged_into.is_some() {
                continue;
            }
            count += 1;
            let timestamp = reply.time.timestamp_millis();
            if latest
                .as_ref()
                .map_or(true, |(_, _, newest)| timestamp > *newest)
            {
                latest = Some((
                    reply.author_name.clone(),
                    format_utc_as_local_time(timestamp),
                    timestamp,
                ));
            }
        }
    }
    (count, latest.map(|(author, time, _)| (author, time)))
}

/// Walk up the reply chain to the category a post belongs to.
fn category_of(post: &MessageData, all: &[MessageData]) -> Option<MessageId> {
    let mut target = post.reply_to_message_id.clone();
    let mut depth = 0;
    while let Some(id) = target {
        if depth > 64 {
            break;
        }
        depth += 1;
        let parent = all.iter().find(|message| message.message_id == id)?;
        if parent.is_category {
            return Some(parent.message_id.clone());
        }
        target = parent.reply_to_message_id.clone();
    }
    None
}

/// Count every reply below `id` and find the newest one.
fn thread_stats(
    id: &MessageId,
    children: &HashMap<MessageId, Vec<&MessageData>>,
) -> (usize, Option<(String, String)>, i64) {
    let mut count = 0usize;
    let mut latest: Option<(String, String, i64)> = None;
    let mut stack: Vec<&MessageId> = vec![id];
    while let Some(parent) = stack.pop() {
        let Some(replies) = children.get(parent) else {
            continue;
        };
        for reply in replies {
            if reply.merged_into.is_some() {
                continue;
            }
            count += 1;
            let timestamp = reply.time.timestamp_millis();
            if latest
                .as_ref()
                .map_or(true, |(_, _, newest)| timestamp > *newest)
            {
                latest = Some((
                    reply.author_name.clone(),
                    format_utc_as_local_time(timestamp),
                    timestamp,
                ));
            }
            stack.push(&reply.message_id);
        }
    }
    let newest = latest
        .as_ref()
        .map(|(_, _, timestamp)| *timestamp)
        .unwrap_or(0);
    (
        count,
        latest.map(|(author, time, _)| (author, time)),
        newest,
    )
}

/// One compact forum row: avatar, title, author, creation time, replies and
/// last reply all on one horizontal line.
#[component]
fn PostRow(
    post: MessageData,
    board_id: String,
    reply_count: usize,
    last_reply: Option<(String, String)>,
    #[props(default)] can_pin: bool,
    #[props(default)] can_close: bool,
    #[props(default)] can_announce: bool,
    #[props(default)] on_pin: Option<EventHandler<bool>>,
    #[props(default)] on_close: Option<EventHandler<bool>>,
    #[props(default)] on_announce: Option<EventHandler<bool>>,
    on_click: EventHandler<()>,
) -> Element {
    let title = if post.title_text.trim().is_empty() {
        "Untitled".to_string()
    } else {
        post.title_text.clone()
    };
    let created = format_utc_as_local_time(post.time.timestamp_millis());
    let post_id = post.id_string();
    let avatar = get_avatar(&post.author_id);
    let preview = {
        let mut text: String = post.content_text.chars().take(400).collect();
        if post.content_text.chars().count() > 400 {
            text.push('…');
        }
        text
    };
    let quoted = crate::components::app::QUOTE_COLLECTION
        .read()
        .iter()
        .any(|quote| quote.target == post.message_id);

    rsx! {
        div {
            class: "bg-panel border border-border rounded-lg px-4 py-3 hover:border-accent/50 hover:bg-surface/30 transition-colors cursor-pointer",
            title: preview,
            onclick: move |_| on_click.call(()),
            div { class: "flex items-center gap-4",
                img {
                    src: "{avatar}",
                    class: "w-8 h-8 rounded-full flex-shrink-0",
                    alt: "",
                }
                div { class: "flex-1 min-w-0 flex flex-wrap items-baseline gap-x-3 gap-y-1",
                    if post.is_pinned {
                        span { title: "Pinned", "📌" }
                    }
                    if post.is_closed {
                        span { title: "Closed", "🔒" }
                    }
                    if post.is_announced {
                        span { title: "Announcement", "📢" }
                    }
                    if post.is_pending {
                        span { class: "text-amber-400", title: "Waiting for a moderator", "Pending" }
                    }
                    span { class: "text-base font-semibold text-text truncate", "{title}" }
                    span { class: "text-xs text-text-muted", "·" }
                    span { class: "text-xs text-text-muted", "by {post.author_name}" }
                    span { class: "text-xs text-text-muted", "· {created}" }
                    span { class: "text-xs text-text-muted",
                        if reply_count == 1 {
                            "· 1 reply"
                        } else {
                            "· {reply_count} replies"
                        }
                    }
                    if let Some((author, time)) = last_reply {
                        span { class: "text-xs text-text-muted", "· last {time} by {author}" }
                    }
                }
                div { class: "flex items-center gap-1 flex-shrink-0",
                    button {
                        r#type: "button",
                        class: if quoted {
                            "px-1.5 py-1 text-xs rounded bg-accent/20 text-accent"
                        } else {
                            "px-1.5 py-1 text-xs rounded hover:bg-surface"
                        },
                        title: if quoted { "Remove from quote" } else { "Add to quote" },
                        onclick: {
                            let target = post.message_id;
                            let author = post.author_name.clone();
                            let text: String = post.content_text.chars().take(1000).collect();
                            let preview = post.content_text.chars().take(200).collect::<String>();
                            move |evt| {
                                evt.stop_propagation();
                                crate::components::app::QUOTE_COLLECTION.with_mut(|quotes| {
                                    if let Some(index) = quotes.iter().position(|q| q.target == target) {
                                        quotes.remove(index);
                                    } else {
                                        quotes.push(crate::components::app::QuoteRequest {
                                            target,
                                            author: author.clone(),
                                            preview: preview.clone(),
                                            text: text.clone(),
                                        });
                                    }
                                });
                            }
                        },
                        "❝"
                    }
                    button {
                        r#type: "button",
                        class: "px-1.5 py-1 text-xs rounded hover:bg-surface",
                        title: "Copy link",
                        onclick: {
                            let board = board_id.clone();
                            let post_id = post_id.clone();
                            move |evt| {
                                evt.stop_propagation();
                                if let Some(window) = web_sys::window() {
                                    if let Ok(href) = window.location().href() {
                                        let base = href.split('#').next().unwrap_or("");
                                        let link = format!(
                                            "{base}#/board/{board}/post/{post_id}"
                                        );
                                        let _ = crate::util::copy_to_clipboard(&link);
                                    }
                                }
                            }
                        },
                        "🔗"
                    }
                    button {
                        r#type: "button",
                        class: "px-1.5 py-1 text-xs rounded hover:bg-surface",
                        title: "Report post",
                        onclick: {
                            let target = post.message_id;
                            move |evt| {
                                evt.stop_propagation();
                                crate::components::app::REPORT_TARGET
                                    .with_mut(|current| *current = Some(target));
                            }
                        },
                        "🚩"
                    }
                }
                if can_pin || can_close || can_announce {
                    div { class: "flex items-center gap-1 flex-shrink-0",
                        onclick: move |evt| evt.stop_propagation(),
                        if can_announce {
                            if let Some(handler) = on_announce.as_ref() {
                                button {
                                    r#type: "button",
                                    class: "px-1.5 py-1 text-xs rounded hover:bg-surface",
                                    title: if post.is_announced { "Remove announcement" } else { "Announce board-wide" },
                                    onclick: {
                                        let handler = handler.clone();
                                        let next = !post.is_announced;
                                        move |_| handler.call(next)
                                    },
                                    if post.is_announced { "🔔" } else { "📢" }
                                }
                            }
                        }
                        if can_pin {
                            if let Some(handler) = on_pin.as_ref() {
                                button {
                                    r#type: "button",
                                    class: "px-1.5 py-1 text-xs rounded hover:bg-surface",
                                    title: if post.is_pinned { "Unpin" } else { "Pin" },
                                    onclick: {
                                        let handler = handler.clone();
                                        let next = !post.is_pinned;
                                        move |_| handler.call(next)
                                    },
                                    if post.is_pinned { "📌" } else { "📍" }
                                }
                            }
                        }
                        if can_close {
                            if let Some(handler) = on_close.as_ref() {
                                button {
                                    r#type: "button",
                                    class: "px-1.5 py-1 text-xs rounded hover:bg-surface",
                                    title: if post.is_closed { "Reopen" } else { "Close" },
                                    onclick: {
                                        let handler = handler.clone();
                                        let next = !post.is_closed;
                                        move |_| handler.call(next)
                                    },
                                    if post.is_closed { "🔓" } else { "🔒" }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// A section row, used under a group, in Ungrouped, and in a section page.
#[component]
fn SectionRow(
    category: MessageData,
    self_member_id: MemberId,
    is_owner: bool,
    is_admin: bool,
    post_count: usize,
    last_activity: Option<(String, String)>,
    #[props(default)] unread_count: usize,
    #[props(default)] groups: Vec<(MessageId, String)>,
    #[props(default)] allow_group_change: bool,
    /// Child boards shown as a compact line under the row (home page)
    #[props(default)]
    child_boards: Vec<(MessageId, String)>,
    on_edit: EventHandler<CategoryEditData>,
    on_delete: EventHandler<MessageId>,
    board_id: String,
) -> Element {
    let category_id = category.id_string();
    let read_id = category.message_id;
    let nav = navigator();
    let nav_board = board_id.clone();
    let nav_category = category_id.clone();
    let child_nav = navigator();
    let child_board = board_id.clone();
    let on_child_click = EventHandler::new(move |child_id: MessageId| {
        mark_category_read(child_id);
        child_nav.push(Route::PostsInCategory {
            board_id: child_board.clone(),
            category_id: child_id.to_string(),
        });
    });
    rsx! {
        CategoryCard {
            key: "{category_id}",
            category: category,
            self_member_id: self_member_id,
            is_owner: is_owner,
            is_admin: is_admin,
            post_count: post_count,
            last_activity: last_activity,
            unread_count: unread_count,
            groups: groups,
            allow_group_change: allow_group_change,
            on_click: move |_| {
                mark_category_read(read_id);
                nav.push(Route::PostsInCategory {
                    board_id: nav_board.clone(),
                    category_id: nav_category.clone(),
                });
            },
            on_edit: move |data| on_edit.call(data),
            on_request_delete: move |id| on_delete.call(id),
            child_boards: child_boards,
            on_child_click: Some(on_child_click),
        }
    }
}

#[component]
pub fn PostsView(#[props(default)] category_id: Option<String>) -> Element {
    let announcement_nav = navigator();
    let mut pending_delete: Signal<Option<MessageId>> = use_signal(|| None);
    let mut pending_delete_group = use_signal(|| false);
    let mut pending_group_children: Signal<Vec<MessageId>> = use_signal(Vec::new);
    let mut recent_first = use_signal(|| false);
    let initial_collapsed: HashSet<MessageId> = CURRENT_BOARD
        .read()
        .owner_key
        .and_then(|key| {
            BOARDS
                .read()
                .map
                .get(&key)
                .map(|board| board.collapsed_groups.iter().cloned().collect())
        })
        .unwrap_or_default();
    let mut collapsed_groups = use_signal(|| initial_collapsed);
    use_effect(move || {
        let groups: HashSet<MessageId> = CURRENT_BOARD
            .read()
            .owner_key
            .and_then(|key| {
                BOARDS
                    .read()
                    .map
                    .get(&key)
                    .map(|board| board.collapsed_groups.iter().cloned().collect())
            })
            .unwrap_or_default();
        collapsed_groups.set(groups);
    });

    // Returning to the home page from a group breadcrumb scrolls that group
    // into view, after the home DOM has been painted.
    use_effect(move || {
        if CURRENT_CATEGORY.read().category_id.is_some() {
            return;
        }
        let target = crate::components::app::SCROLL_TO_GROUP.read().clone();
        let Some(group_id) = target else {
            return;
        };
        crate::components::app::SCROLL_TO_GROUP.with_mut(|target| *target = None);
        if let Some(window) = web_sys::window() {
            let callback = wasm_bindgen::closure::Closure::once_into_js(move || {
                if let Some(window) = web_sys::window() {
                    if let Some(document) = window.document() {
                        if let Some(element) =
                            document.get_element_by_id(&format!("group-{group_id}"))
                        {
                            element.scroll_into_view();
                        }
                    }
                }
            });
            if let Some(function) = callback.dyn_ref::<js_sys::Function>() {
                let _ = window.request_animation_frame(function);
            }
        }
    });
    // Page of posts (20 per page).
    let mut page = use_signal(|| 0usize);
    let category_for_reset = category_id.clone();
    use_effect(move || {
        // Reset the page when the user opens another category.
        let _ = category_for_reset.clone();
        page.set(0);
    });

    // Get current board data
    let board_data_memo = use_memo(move || {
        let current_board = CURRENT_BOARD.read();
        if let Some(key) = current_board.owner_key {
            let boards = BOARDS.read();
            boards.map.get(&key).cloned()
        } else {
            None
        }
    });

    let current_board_data = board_data_memo.read().clone();
    let has_board_selected = current_board_data.is_some();

    // Get all messages
    let all_messages: Vec<MessageData> = if let Some(ref board_data) = current_board_data {
        let self_member_id = MemberId::from(&board_data.self_sk.verifying_key());
        get_all_messages(
            &board_data.board_state,
            self_member_id,
            &board_data.secrets,
            &board_data.category_secrets,
            &board_data.old_category_secrets,
        )
    } else {
        Vec::new()
    };

    // Get current category if viewing one
    let current_category: Option<MessageData> = if let Some(ref cat_id) = category_id {
        all_messages
            .iter()
            .find(|m| m.id_string() == *cat_id && m.is_category)
            .cloned()
    } else {
        None
    };

    // Build breadcrumbs
    let breadcrumbs = build_breadcrumbs(category_id.as_ref(), &all_messages);

    // Get content
    let (categories, posts) = get_content(category_id.as_ref(), &all_messages);

    // Board-wide announcements, shown above the breadcrumbs on every list.
    let announcements: Vec<&MessageData> = all_messages
        .iter()
        .filter(|message| message.is_announced && !message.is_category)
        .collect();

    // A restricted category we cannot open stays read-only: it gets no reply
    // context, so the composer cannot post into it.
    let category_is_locked = current_category
        .as_ref()
        .map(|cat| cat.category_locked)
        .unwrap_or(false);
    // Shared parent -> direct replies map for headers and post summaries.
    let reply_children: HashMap<MessageId, Vec<&MessageData>> = {
        let mut map: HashMap<MessageId, Vec<&MessageData>> = HashMap::new();
        for message in &all_messages {
            if let Some(parent) = message.reply_to_message_id.as_ref() {
                map.entry(parent.clone()).or_default().push(message);
            } else if !message.is_category {
                if let Some(category) = message.category_id.as_ref() {
                    // A new topic belongs to its section even though it is not
                    // a reply. Categories also carry their own id as
                    // `category_id`; only topics are attached, or the stats
                    // walk would loop on the category itself.
                    map.entry(category.clone()).or_default().push(message);
                }
            }
        }
        map
    };

    // Used by the category header button, before board_info is destructured.
    let can_manage_structure = current_board_data
        .as_ref()
        .map(|board| {
            let self_id = MemberId::from(&board.self_sk.verifying_key());
            self_id == MemberId::from(&board.owner_vk)
                || board
                    .board_state
                    .admin
                    .admins
                    .iter()
                    .any(|admin| admin.admin.id() == self_id)
        })
        .unwrap_or(false);

    // Update CURRENT_CATEGORY for auto-parenting posts/categories
    // Compare before writing to avoid unnecessary updates
    {
        let new_context =
            if let Some(cat) = current_category.as_ref().filter(|_| !category_is_locked) {
                CurrentCategoryContext {
                    category_id: Some(cat.message_id.clone()),
                    category_name: cat.category_name.clone(),
                    author_name: Some(cat.author_name.clone()),
                }
            } else {
                CurrentCategoryContext::default()
            };

        let current = CURRENT_CATEGORY.read();
        if current.category_id != new_context.category_id {
            drop(current);
            *CURRENT_CATEGORY.write() = new_context;
        }
    }

    // Clear CURRENT_CATEGORY when leaving
    use_drop(|| {
        *CURRENT_CATEGORY.write() = CurrentCategoryContext::default();
    });

    // Handler for deleting messages
    let handle_delete_message = move |target_message_id: MessageId| {
        if let Some(ctx) = ActionContext::from_current_board() {
            spawn_local(async move {
                message_actions::delete_message(ctx, target_message_id).await;
            });
        }
    };
    // Deleting a group first moves its sections to Ungrouped.
    let handle_delete_group = move |group_id: MessageId, children: Vec<MessageId>| {
        if let Some(ctx) = ActionContext::from_current_board() {
            spawn_local(async move {
                if let Err(e) = message_actions::delete_group(ctx, group_id, children).await {
                    dioxus::logger::tracing::error!("Failed to delete group: {}", e);
                }
            });
        }
    };

    // Open the shared create modal in the three modes.
    let open_group_modal = move |_| {
        CREATE_CATEGORY_MODAL.with_mut(|modal| {
            modal.show = true;
            modal.is_group = true;
            modal.parent_is_group = false;
            modal.parent_category_id = None;
        });
    };
    let open_section_modal = move |_| {
        let parent = CURRENT_CATEGORY.read().category_id.clone();
        CREATE_CATEGORY_MODAL.with_mut(|modal| {
            modal.show = true;
            modal.is_group = false;
            modal.parent_is_group = false;
            modal.parent_category_id = parent;
        });
    };
    let open_section_in_group = move |group_id: MessageId| {
        CREATE_CATEGORY_MODAL.with_mut(|modal| {
            modal.show = true;
            modal.is_group = false;
            modal.parent_is_group = true;
            modal.parent_category_id = Some(group_id);
        });
    };
    let open_subsection = move |_| {
        let parent = CURRENT_CATEGORY.read().category_id.clone();
        CREATE_CATEGORY_MODAL.with_mut(|modal| {
            modal.show = true;
            modal.is_group = false;
            modal.parent_is_group = false;
            modal.parent_category_id = parent;
        });
    };

    // Handler for editing categories
    let handle_edit_category = move |edit_data: CategoryEditData| {
        if let Some(ctx) = ActionContext::from_current_board() {
            spawn_local(async move {
                message_actions::edit_category(
                    ctx,
                    edit_data.message_id,
                    edit_data.new_name,
                    edit_data.new_description,
                    edit_data.new_icon,
                    edit_data.new_color,
                    edit_data.new_parent,
                )
                .await;
            });
        }
    };

    // Get current board_id for navigation
    let current_board_id = use_memo(move || {
        CURRENT_BOARD
            .read()
            .owner_key
            .map(|key| bs58::encode(key.as_bytes()).into_string())
            .unwrap_or_default()
    });

    let viewing_category = category_id.is_some();

    // Follow/Unfollow applies to sections, never to homepage groups.
    let current_section_id = current_category
        .as_ref()
        .filter(|section| !section.is_group)
        .map(|section| section.message_id);
    let section_followed = current_section_id
        .map(|id| {
            current_board_data
                .as_ref()
                .map(|board| board.subscribed_categories.contains(&id))
                .unwrap_or(false)
        })
        .unwrap_or(false);

    rsx! {
        div { class: "flex-1 flex flex-col min-w-0 min-h-0 bg-bg",
            // Show no-board-selected message or header with user info
            if !has_board_selected {
                div { class: "flex flex-col items-center justify-center h-64 text-text-muted",
                    p { class: "text-xl", "Select a board from the sidebar above or create one" }
                    p { class: "text-sm mt-2", "Posts will appear here" }
                }
            } else {
                // Categories and Posts list
                div { class: "flex-1 overflow-y-auto",
                    div { class: "max-w-6xl mx-auto px-4 py-6",
                        if !announcements.is_empty() {
                            div { class: "space-y-2 mb-5",
                                for announcement in announcements.iter() {
                                    {
                                        let post_id = announcement.id_string();
                                        let board_id = current_board_id.read().clone();
                                        let nav = announcement_nav;
                                        rsx! {
                                            button {
                                                key: "{post_id}",
                                                r#type: "button",
                                                class: "w-full text-left bg-accent/10 border border-accent/40 rounded-lg px-4 py-2.5 hover:bg-accent/15 transition-colors",
                                                onclick: move |_| {
                                                    nav.push(Route::Post {
                                                        board_id: board_id.clone(),
                                                        post_id: post_id.clone(),
                                                    });
                                                },
                                                div { class: "flex items-baseline gap-2 flex-wrap",
                                                    span { "📢" }
                                                    span { class: "text-sm font-semibold text-text",
                                                        if announcement.title_text.trim().is_empty() {
                                                            "Announcement"
                                                        } else {
                                                            "{announcement.title_text}"
                                                        }
                                                    }
                                                    span { class: "text-xs text-text-muted",
                                                        "by {announcement.author_name}"
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        // Breadcrumb navigation (only show when viewing a category)
                        if viewing_category {
                            div { class: "flex items-center gap-2 mb-6 text-sm flex-wrap",
                                {breadcrumbs.iter().enumerate().map(|(i, crumb)| {
                                    let is_last = i == breadcrumbs.len() - 1;
                                    let board_id = current_board_id.read().clone();
                                    let crumb_id = crumb.id.clone();
                                    let crumb_name = crumb.name.clone();
                                    let crumb_icon = crumb.icon.clone();
                                    let crumb_is_group = crumb.is_group;

                                    rsx! {
                                        if i > 0 {
                                            span { class: "text-text-muted", "/" }
                                        }
                                        if is_last {
                                            span { class: "flex items-center gap-1 text-text font-medium",
                                                if let Some(icon) = crumb_icon {
                                                    span { "{icon}" }
                                                }
                                                "{crumb_name}"
                                            }
                                        } else {
                                            // A real link here would navigate the sandboxed
                                            // iframe and reload the app; set the hash instead.
                                            {
                                                let target = match crumb_id.clone() {
                                                    Some(id) if !crumb_is_group => {
                                                        format!("/board/{board_id}/category/{id}")
                                                    }
                                                    _ => format!("/board/{board_id}"),
                                                };
                                                let scroll_target = crumb_id.clone().filter(|_| crumb_is_group);
                                                rsx! {
                                                    button {
                                                        r#type: "button",
                                                        class: "flex items-center gap-1 text-accent hover:text-accent/80 transition-colors",
                                                        onclick: move |_| {
                                                            if let Some(group_id) = scroll_target.clone() {
                                                                crate::components::app::SCROLL_TO_GROUP
                                                                    .with_mut(|target| *target = Some(group_id));
                                                            }
                                                            if let Some(win) = web_sys::window() {
                                                                let _ = win.location().set_hash(&target);
                                                            }
                                                        },
                                                        if let Some(icon) = crumb_icon {
                                                            span { "{icon}" }
                                                        }
                                                        "{crumb_name}"
                                                    }
                                                }
                                            }
                                        }
                                    }
                                })}
                                if !category_is_locked {
                                    div { class: "ml-auto flex items-center gap-2 flex-shrink-0",
                                        button {
                                            r#type: "button",
                                            class: "flex items-center gap-1.5 px-3 py-1.5 bg-accent hover:bg-accent/80 text-white text-xs font-medium rounded-lg transition-colors",
                                            title: "Write a new post in this section",
                                            onclick: move |_| {
                                                *crate::components::app::COMPOSE_REQUEST.write() += 1;
                                            },
                                            span { "✏️" }
                                            span { "New post" }
                                        }
                                        if let Some(section_id) = current_section_id {
                                            button {
                                                r#type: "button",
                                                class: if section_followed {
                                                    "px-3 py-1.5 bg-surface text-accent text-xs rounded-lg transition-colors"
                                                } else {
                                                    "px-3 py-1.5 bg-surface hover:bg-surface-hover text-text text-xs rounded-lg transition-colors"
                                                },
                                                title: if section_followed {
                                                    "Stop following this section"
                                                } else {
                                                    "Show new topics in this section under Notifications"
                                                },
                                                onclick: move |_| {
                                                    crate::util::subscriptions::set_followed(
                                                        section_id,
                                                        !section_followed,
                                                    );
                                                },
                                                if section_followed { "✓ Following" } else { "+ Follow" }
                                            }
                                        }
                                        if can_manage_structure {
                                            button {
                                                r#type: "button",
                                                class: "px-3 py-1.5 bg-surface hover:bg-surface-hover text-text text-xs rounded-lg transition-colors",
                                                title: "Create a subsection inside this section",
                                                onclick: {
                                                    let handler = open_subsection.clone();
                                                    move |_| handler(())
                                                },
                                                "+ Subsection"
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // Locked restricted category: show the notice instead
                        // of posts this member cannot read.
                        if category_is_locked {
                            div { class: "flex flex-col items-center justify-center h-56 text-text-muted text-center",
                                div { class: "text-4xl mb-3", "🔒" }
                                p { class: "text-lg font-medium text-text", "Restricted category" }
                                p { class: "text-sm mt-1 max-w-md",
                                    "Only members with the right role can read the name and the posts here."
                                }
                            }
                        }

                        // Content
                        if !category_is_locked {
                            {
                            let board_info = current_board_data.as_ref()
                                .map(|bd| {
                                    let self_member_id = MemberId::from(&bd.self_sk.verifying_key());
                                    let owner_id = MemberId::from(&bd.owner_vk);
                                    let is_owner = self_member_id == owner_id;
                                    let is_admin = bd.board_state.admin.admins.iter()
                                        .any(|a| a.admin.id() == self_member_id);
                                    (self_member_id, is_owner, is_admin)
                                });

                            let has_posts = !posts.is_empty();
                            let (viewer_is_owner, viewer_is_admin) = current_board_data
                                .as_ref()
                                .map(|board| {
                                    let self_id = MemberId::from(&board.self_sk.verifying_key());
                                    (
                                        self_id == MemberId::from(&board.owner_vk),
                                        board
                                            .board_state
                                            .admin
                                            .admins
                                            .iter()
                                            .any(|admin| admin.admin.id() == self_id),
                                    )
                                })
                                .unwrap_or((false, false));

                            // Groups are homepage-only headings. Sections in a
                            // group are their children; top-level sections with
                            // no group go under Ungrouped.
                            let root_groups: Vec<MessageData> = if viewing_category {
                                Vec::new()
                            } else {
                                all_messages
                                    .iter()
                                    .filter(|message| {
                                        message.is_category
                                            && message.is_group
                                            && message.parent_category_id.is_none()
                                    })
                                    .cloned()
                                    .collect()
                            };
                            let mut sections_by_group: HashMap<MessageId, Vec<MessageData>> =
                                HashMap::new();
                            let ungrouped_sections: Vec<MessageData> = if viewing_category {
                                Vec::new()
                            } else {
                                all_messages
                                    .iter()
                                    .filter(|message| {
                                        message.is_category
                                            && !message.is_group
                                            && !(message.category_hidden
                                                && message.category_locked)
                                    })
                                    .filter(|message| {
                                        if let Some(parent) = message.parent_category_id.as_ref() {
                                            sections_by_group
                                                .entry(parent.clone())
                                                .or_default()
                                                .push((*message).clone());
                                            false
                                        } else {
                                            true
                                        }
                                    })
                                    .cloned()
                                    .collect()
                            };
                            let groups: Vec<MessageData> = root_groups
                                .into_iter()
                                .filter(|group| {
                                    viewer_is_owner
                                        || viewer_is_admin
                                        || sections_by_group
                                            .get(&group.message_id)
                                            .map(|sections| !sections.is_empty())
                                            .unwrap_or(false)
                                })
                                .collect();
                            // The root always shows the Groups block, so the
                            // owner can create the first group on a new board.
                            let has_categories = if viewing_category {
                                !categories.is_empty()
                            } else {
                                true
                            };
                            let group_options: Vec<(MessageId, String)> = groups
                                .iter()
                                .map(|group| {
                                    (
                                        group.message_id.clone(),
                                        group
                                            .category_name
                                            .clone()
                                            .unwrap_or_else(|| "Unnamed".to_string()),
                                    )
                                })
                                .collect();

                            // Child boards by parent, for the names shown under
                            // a section on the home page.
                            let mut child_boards_by_parent: HashMap<
                                MessageId,
                                Vec<(MessageId, String)>,
                            > = HashMap::new();
                            for message in &all_messages {
                                if !message.is_category || message.is_group {
                                    continue;
                                }
                                if let Some(parent) = message.parent_category_id.as_ref() {
                                    child_boards_by_parent
                                        .entry(parent.clone())
                                        .or_default()
                                        .push((
                                            message.message_id.clone(),
                                            message
                                                .category_name
                                                .clone()
                                                .unwrap_or_else(|| "Unnamed".to_string()),
                                        ));
                                }
                            }

                            let children = &reply_children;

                            // Whole-thread reply count and latest reply per post,
                            // so the list can show activity without opening it.
                            let post_stats: HashMap<
                                MessageId,
                                (usize, Option<(String, String)>, i64),
                            > = posts
                                .iter()
                                .map(|post| {
                                    (
                                        post.message_id.clone(),
                                        thread_stats(&post.message_id, &children),
                                    )
                                })
                                .collect();

                            // Newest first, or most recently active thread first.
                            let mut displayed_posts = posts.clone();
                            if *recent_first.read() {
                                displayed_posts.sort_by(|a, b| {
                                    let activity = |post: &MessageData| {
                                        post_stats
                                            .get(&post.message_id)
                                            .map(|stats| stats.2)
                                            .filter(|timestamp| *timestamp > 0)
                                            .unwrap_or_else(|| post.time.timestamp_millis())
                                    };
                                    b.is_pinned
                                        .cmp(&a.is_pinned)
                                        .then_with(|| activity(b).cmp(&activity(a)))
                                });
                            } else {
                                // Pinned posts first, keeping newest first inside
                                // each group.
                                displayed_posts.sort_by_key(|post| !post.is_pinned);
                            }
                            let total_pages = displayed_posts.len().div_ceil(20).max(1);
                            let current_page = (*page.read()).min(total_pages - 1);

                            // Posts and latest activity inside each category,
                            // including its subcategories.
                            let stats_targets: Vec<&MessageData> = if viewing_category {
                                categories.iter().collect()
                            } else {
                                ungrouped_sections
                                    .iter()
                                    .chain(sections_by_group.values().flatten())
                                    .collect()
                            };
                            let category_summaries: HashMap<
                                MessageId,
                                (usize, Option<(String, String)>),
                            > = stats_targets
                                .iter()
                                .map(|category| {
                                    (
                                        category.message_id.clone(),
                                        category_stats(&category.message_id, &children),
                                    )
                                })
                                .collect();
                            let read_categories = current_board_data
                                .as_ref()
                                .map(|board| board.read_categories.clone())
                                .unwrap_or_default();
                            let unread_counts: HashMap<MessageId, usize> = stats_targets
                                .iter()
                                .map(|category| {
                                    (
                                        category.message_id,
                                        unread_in_category(
                                            &category.message_id,
                                            &children,
                                            read_categories
                                                .get(&category.message_id)
                                                .copied()
                                                .unwrap_or(i64::MAX),
                                        ),
                                    )
                                })
                                .collect();

                            if let Some((self_member_id, is_owner, is_admin)) = board_info {
                                let viewer_roles = current_board_data
                                    .as_ref()
                                    .map(|board| board.board_state.roles.clone())
                                    .unwrap_or_default();
                                let scope_chain = current_board_data
                                    .as_ref()
                                    .and_then(|board| {
                                        current_category.as_ref().map(|category| {
                                            category_chain(
                                                &board.board_state.moderation.routes_map(),
                                                &category.message_id,
                                            )
                                        })
                                    })
                                    .unwrap_or_default();
                                if !has_categories && !has_posts {
                                    rsx! {
                                        div { class: "flex flex-col items-center justify-center h-64 text-text-muted",
                                            p { class: "text-xl", "No content yet." }
                                            p { class: "text-sm mt-2", "Be the first to share something!" }
                                        }
                                    }
                                } else {
                                    rsx! {
                                        // Homepage: groups with their sections,
                                        // then sections without a group.
                                        if !viewing_category {
                                            div { class: "mb-8",
                                                div { class: "flex items-center justify-between mb-3",
                                                    h2 { class: "text-lg font-semibold text-text-muted", "Groups" }
                                                    if is_owner || is_admin {
                                                        div { class: "flex items-center gap-2",
                                                            button {
                                                                r#type: "button",
                                                                class: "px-3 py-1.5 text-xs rounded-md bg-surface hover:bg-surface-hover text-text",
                                                                onclick: open_group_modal,
                                                                "+ Group"
                                                            }
                                                            button {
                                                                r#type: "button",
                                                                class: "px-3 py-1.5 text-xs rounded-md bg-surface hover:bg-surface-hover text-text",
                                                                onclick: open_section_modal,
                                                                "+ Section"
                                                            }
                                                        }
                                                    }
                                                }

                                                for group in groups.iter() {
                                                    {
                                                        let group_id = group.message_id.clone();
                                                        let group_key = group.id_string();
                                                        let sections = sections_by_group
                                                            .get(&group_id)
                                                            .cloned()
                                                            .unwrap_or_default();
                                                        let section_count = sections.len();
                                                        let board_id = current_board_id.read().clone();
                                                        let open_group_section =
                                                            open_section_in_group.clone();
                                                        let edit_handler = handle_edit_category.clone();
                                                        let is_collapsed = collapsed_groups
                                                            .read()
                                                            .contains(&group_id);
                                                        let toggle_group = {
                                                            let group_id = group_id.clone();
                                                            let owner = CURRENT_BOARD.read().owner_key;
                                                            move |_| {
                                                                let mut set = collapsed_groups.read().clone();
                                                                if set.contains(&group_id) {
                                                                    set.remove(&group_id);
                                                                } else {
                                                                    set.insert(group_id.clone());
                                                                }
                                                                collapsed_groups.set(set.clone());
                                                                if let Some(owner) = owner {
                                                                    BOARDS.with_mut(|boards| {
                                                                        if let Some(board) =
                                                                            boards.map.get_mut(&owner)
                                                                        {
                                                                            board.collapsed_groups = set
                                                                                .iter()
                                                                                .cloned()
                                                                                .collect();
                                                                        }
                                                                    });
                                                                    spawn_local(async {
                                                                        if let Err(e) =
                                                                            save_boards_to_delegate().await
                                                                        {
                                                                            dioxus::logger::tracing::error!(
                                                                                "Failed to save collapsed groups: {}",
                                                                                e
                                                                            );
                                                                        }
                                                                    });
                                                                }
                                                            }
                                                        };
                                                        rsx! {
                                                            div {
                                                                key: "group-{group_key}",
                                                                id: "group-{group_key}",
                                                                class: "mb-5",
                                                                CategoryCard {
                                                                    category: group.clone(),
                                                                    self_member_id: self_member_id,
                                                                    is_owner: is_owner,
                                                                    is_admin: is_admin,
                                                                    post_count: section_count,
                                                                    last_activity: None,
                                                                    collapsed: is_collapsed,
                                                                    on_toggle_collapsed: Some(EventHandler::new(toggle_group)),
                                                                    on_click: move |_| {},
                                                                    on_new_section: move |_| {
                                                                        open_group_section(group_id.clone())
                                                                    },
                                                                    on_edit: move |data| edit_handler(data),
                                                                    on_request_delete: {
                                                                        let children: Vec<MessageId> = sections
                                                                            .iter()
                                                                            .map(|section| section.message_id.clone())
                                                                            .collect();
                                                                        move |id| {
                                                                            pending_delete.set(Some(id));
                                                                            pending_delete_group.set(true);
                                                                            pending_group_children.set(children.clone());
                                                                        }
                                                                    },
                                                                }
                                                                if !is_collapsed && !sections.is_empty() {
                                                                    div { class: "mt-2 ml-4 pl-4 border-l border-border space-y-2",
                                                                        for section in sections.iter() {
                                                                            {
                                                                                let (count, last) = category_summaries
                                                                                    .get(&section.message_id)
                                                                                    .cloned()
                                                                                    .unwrap_or_default();
                                                                                let child_boards = child_boards_by_parent
                                                                                    .get(&section.message_id)
                                                                                    .cloned()
                                                                                    .unwrap_or_default();
                                                                                let edit_handler = handle_edit_category.clone();
                                                                                rsx! {
                                                                                    SectionRow {
                                                                                        category: section.clone(),
                                                                                        self_member_id: self_member_id,
                                                                                        is_owner: is_owner,
                                                                                        is_admin: is_admin,
                                                                                        post_count: count,
                                                                                        unread_count: unread_counts.get(&section.message_id).copied().unwrap_or(0),
                                                                                        last_activity: last,
                                                                                        groups: group_options.clone(),
                                                                                        allow_group_change: true,
                                                                                        child_boards: child_boards,
                                                                                        board_id: board_id.clone(),
                                                                                        on_edit: move |data| edit_handler(data),
                                                                                        on_delete: move |id| {
                                                                            pending_delete.set(Some(id));
                                                                            pending_delete_group.set(false);
                                                                        },
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

                                                if !ungrouped_sections.is_empty() {
                                                    h2 { class: "text-lg font-semibold text-text-muted mb-3 mt-6", "Ungrouped" }
                                                    div { class: "space-y-2",
                                                        for section in ungrouped_sections.iter() {
                                                            {
                                                                let (count, last) = category_summaries
                                                                    .get(&section.message_id)
                                                                    .cloned()
                                                                    .unwrap_or_default();
                                                                let child_boards = child_boards_by_parent
                                                                    .get(&section.message_id)
                                                                    .cloned()
                                                                    .unwrap_or_default();
                                                                let edit_handler = handle_edit_category.clone();
                                                                let board_id = current_board_id.read().clone();
                                                                rsx! {
                                                                    SectionRow {
                                                                        category: section.clone(),
                                                                        self_member_id: self_member_id,
                                                                        is_owner: is_owner,
                                                                        is_admin: is_admin,
                                                                        post_count: count,
                                                                        unread_count: unread_counts.get(&section.message_id).copied().unwrap_or(0),
                                                                        last_activity: last,
                                                                        groups: group_options.clone(),
                                                                        allow_group_change: true,
                                                                        child_boards: child_boards,
                                                                        board_id: board_id,
                                                                        on_edit: move |data| edit_handler(data),
                                                                        on_delete: move |id| {
                                                                            pending_delete.set(Some(id));
                                                                            pending_delete_group.set(false);
                                                                        },
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        // Child boards as full cards under the
                                        // breadcrumb, before the posts.
                                        if viewing_category && !categories.is_empty() {
                                            div { class: "mb-8",
                                                h2 { class: "text-lg font-semibold text-text-muted mb-3", "Child Boards" }
                                                div { class: "space-y-2",
                                                    for category in categories.iter() {
                                                        {
                                                            let (count, last) = category_summaries
                                                                .get(&category.message_id)
                                                                .cloned()
                                                                .unwrap_or_default();
                                                            let edit_handler = handle_edit_category.clone();
                                                            let board_id = current_board_id.read().clone();
                                                            rsx! {
                                                                SectionRow {
                                                                    category: category.clone(),
                                                                    self_member_id: self_member_id,
                                                                    is_owner: is_owner,
                                                                    is_admin: is_admin,
                                                                    post_count: count,
                                                                    unread_count: unread_counts.get(&category.message_id).copied().unwrap_or(0),
                                                                    last_activity: last,
                                                                    allow_group_change: false,
                                                                    child_boards: Vec::new(),
                                                                    board_id: board_id,
                                                                    on_edit: move |data| edit_handler(data),
                                                                    on_delete: move |id| {
                                                                        pending_delete.set(Some(id));
                                                                        pending_delete_group.set(false);
                                                                    },
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        // Posts section
                                        if has_posts {
                                            if has_categories {
                                                h2 { class: "text-lg font-semibold text-text-muted mb-4 flex items-center gap-2",
                                                    "Posts"
                                                }
                                            }
                                            div { class: "flex items-center gap-2 mb-4",
                                                span { class: "text-sm text-text-muted", "Sort:" }
                                                button {
                                                    r#type: "button",
                                                    class: if !*recent_first.read() {
                                                        "px-3 py-1 text-xs rounded-md bg-accent text-white"
                                                    } else {
                                                        "px-3 py-1 text-xs rounded-md bg-surface text-text-muted hover:text-text"
                                                    },
                                                    onclick: move |_| recent_first.set(false),
                                                    "Newest"
                                                }
                                                button {
                                                    r#type: "button",
                                                    class: if *recent_first.read() {
                                                        "px-3 py-1 text-xs rounded-md bg-accent text-white"
                                                    } else {
                                                        "px-3 py-1 text-xs rounded-md bg-surface text-text-muted hover:text-text"
                                                    },
                                                    onclick: move |_| recent_first.set(true),
                                                    "Recent activity"
                                                }
                                            }
                                            div { class: "space-y-2",
                                                {displayed_posts.iter().skip(current_page * 20).take(20).map({
                                                    let board_id = current_board_id.read().clone();
                                                    let roles = viewer_roles.clone();
                                                    let scope_chain = scope_chain.clone();
                                                    move |post| {
                                                        let post_id = post.id_string();
                                                        let board_id = board_id.clone();
                                                        let nav = navigator();
                                                        let (reply_count, last_reply, _) =
                                                            post_stats.get(&post.message_id).cloned().unwrap_or_default();
                                                        let is_author = post.author_id == self_member_id;
                                                        let can_pin = is_owner
                                                            || is_admin
                                                            || roles.has_moderation_power(
                                                                &self_member_id,
                                                                ModerationPower::Pin,
                                                                &scope_chain,
                                                            );
                                                        let can_close = is_owner
                                                            || is_admin
                                                            || is_author
                                                            || roles.has_moderation_power(
                                                                &self_member_id,
                                                                ModerationPower::Close,
                                                                &scope_chain,
                                                            );
                                                        let can_announce = is_owner || is_admin;
                                                        let pin_target = post.message_id.clone();
                                                        let close_target = post.message_id.clone();
                                                        let announce_target = post.message_id.clone();
                                                        rsx! {
                                                            PostRow {
                                                                key: "{post_id}",
                                                                post: post.clone(),
                                                                board_id: board_id.clone(),
                                                                reply_count: reply_count,
                                                                last_reply: last_reply,
                                                                can_pin: can_pin,
                                                                can_close: can_close,
                                                                can_announce: can_announce,
                                                                on_announce: move |value| {
                                                                    let target = announce_target.clone();
                                                                    if let Some(ctx) = ActionContext::from_current_board() {
                                                                        let _ = message_actions::set_post_flag(
                                                                            ctx,
                                                                            target,
                                                                            None,
                                                                            None,
                                                                            Some(value),
                                                                        );
                                                                    }
                                                                },
                                                                on_pin: move |value| {
                                                                    let target = pin_target.clone();
                                                                    if let Some(ctx) = ActionContext::from_current_board() {
                                                                        let _ = message_actions::set_post_flag(
                                                                            ctx,
                                                                            target,
                                                                            Some(value),
                                                                            None,
                                                                            None,
                                                                        );
                                                                    }
                                                                },
                                                                on_close: move |value| {
                                                                    let target = close_target.clone();
                                                                    if let Some(ctx) = ActionContext::from_current_board() {
                                                                        let _ = message_actions::set_post_flag(
                                                                            ctx,
                                                                            target,
                                                                            None,
                                                                            Some(value),
                                                                            None,
                                                                        );
                                                                    }
                                                                },
                                                                on_click: move |_| {
                                                                    nav.push(Route::Post {
                                                                        board_id: board_id.clone(),
                                                                        post_id: post_id.clone(),
                                                                    });
                                                                },
                                                            }
                                                        }
                                                    }
                                                })}
                                                if displayed_posts.len() > 20 {
                                                    div { class: "flex items-center justify-center gap-3 mt-4 text-sm",
                                                        button {
                                                            r#type: "button",
                                                            class: if current_page == 0 {
                                                                "px-3 py-1.5 rounded bg-surface text-text-muted opacity-50 cursor-default"
                                                            } else {
                                                                "px-3 py-1.5 rounded bg-surface hover:bg-surface-hover text-text"
                                                            },
                                                            disabled: current_page == 0,
                                                            onclick: move |_| {
                                                                let next = page.read().saturating_sub(1);
                                                                page.set(next);
                                                            },
                                                            "← Previous"
                                                        }
                                                        span { class: "text-text-muted",
                                                            "Page {current_page + 1} of {total_pages}"
                                                        }
                                                        button {
                                                            r#type: "button",
                                                            class: if current_page + 1 >= total_pages {
                                                                "px-3 py-1.5 rounded bg-surface text-text-muted opacity-50 cursor-default"
                                                            } else {
                                                                "px-3 py-1.5 rounded bg-surface hover:bg-surface-hover text-text"
                                                            },
                                                            disabled: current_page + 1 >= total_pages,
                                                            onclick: move |_| {
                                                                let next = (*page.read()).saturating_add(1);
                                                                page.set(next);
                                                            },
                                                            "Next →"
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            } else {
                                rsx! {
                                    div { class: "flex flex-col items-center justify-center h-64 text-text-muted",
                                        p { class: "text-xl", "No content yet." }
                                        p { class: "text-sm mt-2", "Be the first to share something!" }
                                    }
                                }
                            }
                            }
                        }
                    }
                }

                // Delete confirmation modal
                if pending_delete.read().is_some() {
                    div {
                        class: "fixed inset-0 bg-black/50 flex items-center justify-center z-50",
                        onclick: move |_| pending_delete.set(None),
                        div {
                            class: "bg-panel rounded-lg shadow-xl p-6 max-w-sm mx-4",
                            onclick: move |e| e.stop_propagation(),
                            h3 { class: "text-lg font-semibold text-text mb-2",
                                if *pending_delete_group.read() {
                                    "Delete Group?"
                                } else {
                                    "Delete Post?"
                                }
                            }
                            p { class: "text-text-muted text-sm mb-4",
                                if *pending_delete_group.read() {
                                    "The group is removed and its sections are moved to Ungrouped."
                                } else {
                                    "This action cannot be undone."
                                }
                            }
                            div { class: "flex gap-3 justify-end",
                                button {
                                    class: "px-4 py-2 rounded-lg bg-surface hover:bg-surface/80 text-text transition-colors",
                                    onclick: move |_| {
                                        pending_delete.set(None);
                                        pending_delete_group.set(false);
                                        pending_group_children.set(Vec::new());
                                    },
                                    "Cancel"
                                }
                                button {
                                    class: "px-4 py-2 rounded-lg bg-red-500 hover:bg-red-600 text-white transition-colors",
                                    onclick: move |_| {
                                        let msg_id_opt = pending_delete.read().clone();
                                        let is_group = *pending_delete_group.read();
                                        if let Some(msg_id) = msg_id_opt {
                                            if is_group {
                                                handle_delete_group(
                                                    msg_id,
                                                    pending_group_children.read().clone(),
                                                );
                                            } else {
                                                handle_delete_message(msg_id);
                                            }
                                        }
                                        pending_delete.set(None);
                                        pending_delete_group.set(false);
                                        pending_group_children.set(Vec::new());
                                    },
                                    "Delete"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Single post view - displays a single post by ID with replies
#[component]
pub fn SinglePostView(post_id: String) -> Element {
    let mut pending_delete: Signal<Option<MessageId>> = use_signal(|| None);

    // Get current board_id for navigation
    let current_board_id = use_memo(move || {
        CURRENT_BOARD
            .read()
            .owner_key
            .map(|key| bs58::encode(key.as_bytes()).into_string())
            .unwrap_or_default()
    });

    // Find the post, self_member_id, and config
    let post_data = use_memo(move || {
        let current_board = CURRENT_BOARD.read();
        if let Some(key) = current_board.owner_key {
            let boards = BOARDS.read();
            if let Some(board_data) = boards.map.get(&key) {
                let self_member_id = MemberId::from(&board_data.self_sk.verifying_key());
                let config = &board_data.board_state.configuration.configuration;
                let max_title_size = config.max_title_size;
                let max_message_size = config.max_message_size;
                let all_messages = get_all_messages(
                    &board_data.board_state,
                    self_member_id,
                    &board_data.secrets,
                    &board_data.category_secrets,
                    &board_data.old_category_secrets,
                );
                let post = all_messages
                    .iter()
                    .find(|m| m.id_string() == post_id)
                    .cloned();
                let category = post
                    .as_ref()
                    .and_then(|post| category_of(post, &all_messages));
                let can_moderate = post
                    .as_ref()
                    .map(|_post| {
                        let is_privileged = board_data.self_sk.verifying_key()
                            == board_data.owner_vk
                            || board_data
                                .board_state
                                .admin
                                .admins
                                .iter()
                                .any(|admin| admin.admin.id() == self_member_id);
                        if is_privileged {
                            return true;
                        }
                        let mut chain = category
                            .as_ref()
                            .map(|cat| {
                                category_chain(&board_data.board_state.moderation.routes_map(), cat)
                            })
                            .unwrap_or_default();
                        if chain.is_empty() {
                            if let Some(cat) = category.as_ref() {
                                chain.push(cat.clone());
                            }
                        }
                        board_data.board_state.roles.has_moderation_power(
                            &self_member_id,
                            ModerationPower::Edit,
                            &chain,
                        ) || board_data.board_state.roles.has_moderation_power(
                            &self_member_id,
                            ModerationPower::Delete,
                            &chain,
                        )
                    })
                    .unwrap_or(false);
                return post.map(|p| {
                    (
                        p,
                        self_member_id,
                        max_title_size,
                        max_message_size,
                        category,
                        can_moderate,
                    )
                });
            }
        }
        None
    });

    // Publish the opened post as the top-bar reply target.
    use_effect(move || {
        let next = post_data
            .read()
            .as_ref()
            .map(|(post, ..)| CurrentPostContext {
                message_id: Some(post.message_id),
                author_name: Some(post.author_name.clone()),
                preview: Some(
                    format!("{} {}", post.title_text, post.content_text)
                        .trim()
                        .chars()
                        .take(120)
                        .collect(),
                ),
            })
            .unwrap_or_default();
        if *CURRENT_POST.read() != next {
            *CURRENT_POST.write() = next;
        }
    });
    use_drop(|| *CURRENT_POST.write() = CurrentPostContext::default());

    // Handler for toggling reactions
    let handle_toggle_reaction = move |target_message_id: MessageId, emoji: String| {
        if let Some(ctx) = ActionContext::from_current_board() {
            spawn_local(async move {
                message_actions::toggle_reaction(ctx, target_message_id, emoji).await;
            });
        }
    };

    // Handler for deleting messages
    let handle_delete_message = move |target_message_id: MessageId| {
        if let Some(ctx) = ActionContext::from_current_board() {
            spawn_local(async move {
                message_actions::delete_message(ctx, target_message_id).await;
            });
        }
    };

    // Handler for editing messages
    let handle_edit_message = move |target_message_id: MessageId,
                                    new_title: String,
                                    new_text: String| {
        if let Some(ctx) = ActionContext::from_current_board() {
            spawn_local(async move {
                message_actions::edit_message(ctx, target_message_id, new_title, new_text).await;
            });
        }
    };

    let category_id = post_data
        .read()
        .as_ref()
        .and_then(|(_, _, _, _, category, _)| category.clone());
    let has_category = category_id.is_some();
    let back_target = match category_id {
        Some(category) => format!("/board/{}/category/{}", current_board_id.read(), category),
        None => format!("/board/{}", current_board_id.read()),
    };
    let back_label = if has_category {
        "← Back to category"
    } else {
        "← Back to posts"
    };

    rsx! {
        div { class: "flex-1 flex flex-col min-w-0 min-h-0 bg-bg",
            // Back button header
            div { class: "flex items-center gap-4 px-6 py-3 border-b border-border",
                button {
                    r#type: "button",
                    class: "text-accent hover:text-accent/80 transition-colors text-sm font-medium",
                    onclick: {
                        let target = back_target.clone();
                        move |_| {
                            if let Some(win) = web_sys::window() {
                                let _ = win.location().set_hash(&target);
                            }
                        }
                    },
                    "{back_label}"
                }
            }

            // Post content and replies
            div { class: "flex-1 overflow-y-auto",
                {
                    match post_data.read().as_ref() {
                        Some((post, self_member_id, max_title_size, max_message_size, _, can_moderate)) => {
                            rsx! {
                                div { class: "max-w-5xl mx-auto px-4 py-6",
                                    MessageCard {
                                        message: post.clone(),
                                        variant: MessageCardVariant::Card,
                                        self_member_id: *self_member_id,
                                        expanded: true,
                                        show_replies: true,
                                        max_title_size: *max_title_size,
                                        max_message_size: *max_message_size,
                                        on_react: move |(msg_id, emoji)| {
                                            handle_toggle_reaction(msg_id, emoji);
                                        },
                                        on_request_delete: move |msg_id| {
                                            pending_delete.set(Some(msg_id));
                                        },
                                        on_edit: move |(msg_id, new_title, new_text)| {
                                            handle_edit_message(msg_id, new_title, new_text);
                                        },
                                        can_moderate: *can_moderate,
                                    }
                                }
                            }
                        }
                        None => {
                            rsx! {
                                div { class: "flex-1 flex flex-col items-center justify-center h-64 text-text-muted",
                                    p { class: "text-xl", "Post not found." }
                                    button {
                                        r#type: "button",
                                        class: "mt-4 text-accent hover:text-accent/80 transition-colors",
                                        onclick: move |_| {
                                            let target = format!("/board/{}", current_board_id.read());
                                            if let Some(win) = web_sys::window() {
                                                let _ = win.location().set_hash(&target);
                                            }
                                        },
                                        "← Back to posts"
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Delete confirmation modal
            if pending_delete.read().is_some() {
                div {
                    class: "fixed inset-0 bg-black/50 flex items-center justify-center z-50",
                    onclick: move |_| pending_delete.set(None),
                    div {
                        class: "bg-panel rounded-lg shadow-xl p-6 max-w-sm mx-4",
                        onclick: move |e| e.stop_propagation(),
                        h3 { class: "text-lg font-semibold text-text mb-2",
                            "Delete Post?"
                        }
                        p { class: "text-text-muted text-sm mb-4",
                            "This action cannot be undone."
                        }
                        div { class: "flex gap-3 justify-end",
                            button {
                                class: "px-4 py-2 rounded-lg bg-surface hover:bg-surface/80 text-text transition-colors",
                                onclick: move |_| pending_delete.set(None),
                                "Cancel"
                            }
                            button {
                                class: "px-4 py-2 rounded-lg bg-red-500 hover:bg-red-600 text-white transition-colors",
                                onclick: move |_| {
                                    let msg_id_opt = pending_delete.read().clone();
                                    if let Some(msg_id) = msg_id_opt {
                                        handle_delete_message(msg_id);
                                    }
                                    pending_delete.set(None);
                                },
                                "Delete"
                            }
                        }
                    }
                }
            }
        }
    }
}
