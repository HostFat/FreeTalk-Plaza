//! Top bar component showing user profile, admin controls, and post input.

use crate::board_data::SendMessageError;
use crate::components::app::{
    BOARDS, COMPOSE_REQUEST, CURRENT_BOARD, CURRENT_CATEGORY, CURRENT_HASH, CURRENT_POST,
    MEMBER_INFO_MODAL, QUOTE_COLLECTION,
};
use crate::components::conversation::message_input::PostInput;
use crate::util::avatar::get_avatar;
use crate::util::ecies::unseal_bytes_with_secrets;
use crate::util::messaging::{send_message, PollDraft, ReplyContext};
use dioxus::prelude::*;
use dioxus_free_icons::{icons::fa_solid_icons::FaBars, Icon};
use plaza_core::board_state::member::MemberId;
use plaza_core::board_state::privacy::PrivacyMode;

/// Top bar component displaying the current user's profile, admin controls, and post input.
#[component]
pub fn TopBar() -> Element {
    let replying_to = use_signal(|| None::<ReplyContext>);
    let mut menu_open = use_signal(|| false);

    // Housekeeping for bans: the owner lifts expired bans, and a member who is
    // no longer banned puts its stored membership back. Both are idempotent.
    use_effect(move || {
        spawn(async move {
            loop {
                crate::components::members::member_info_modal::ban_button::auto_lift_expired_bans();
                crate::util::membership::restore_self_membership();
                crate::util::pq::housekeeping();
                futures_timer::Delay::new(std::time::Duration::from_secs(60)).await;
            }
        });
    });

    // Get current board data
    let current_board_data = use_memo(move || {
        CURRENT_BOARD
            .read()
            .owner_key
            .and_then(|key| BOARDS.read().map.get(&key).cloned())
    });

    // Quotes belong to the board they were picked on.
    let mut quote_board = use_signal(|| CURRENT_BOARD.read().owner_key);
    use_effect(move || {
        let current = CURRENT_BOARD.read().owner_key;
        if current != *quote_board.peek() {
            quote_board.set(current);
            QUOTE_COLLECTION.write().clear();
        }
    });

    // Unread notifications for the bell badge.
    let unread_notifications = use_memo(move || {
        let Some(key) = CURRENT_BOARD.read().owner_key else {
            return 0;
        };
        BOARDS
            .read()
            .map
            .get(&key)
            .map(crate::util::notifications::unread_count)
            .unwrap_or(0)
    });

    // Get category context for default reply (when viewing a category)
    let category_reply_context = use_memo(move || {
        let cat_ctx = CURRENT_CATEGORY.read();
        if let (Some(cat_id), Some(cat_name), Some(author)) = (
            cat_ctx.category_id.clone(),
            cat_ctx.category_name.clone(),
            cat_ctx.author_name.clone(),
        ) {
            Some(ReplyContext {
                message_id: cat_id,
                author_name: author,
                content_preview: format!("[Category] {}", cat_name),
            })
        } else {
            None
        }
    });

    // When a single post is open, the top-bar composer replies to it.
    let post_reply_context = use_memo(move || {
        let post = CURRENT_POST.read();
        post.message_id.map(|message_id| ReplyContext {
            message_id,
            author_name: post.author_name.clone().unwrap_or_default(),
            content_preview: post.preview.clone().unwrap_or_default(),
        })
    });

    // Message sending handler
    let handle_send_message = move |(title_text, message_text, reply_ctx, poll): (
        String,
        String,
        Option<ReplyContext>,
        Option<PollDraft>,
    )| {
        if message_text.is_empty() {
            return;
        }

        // Get board data for sending
        let board_info = {
            let current_board = CURRENT_BOARD.read();
            if let Some(key) = current_board.owner_key {
                let boards = BOARDS.read();
                if let Some(board_data) = boards.map.get(&key) {
                    let is_private = board_data
                        .board_state
                        .configuration
                        .configuration
                        .privacy_mode
                        == PrivacyMode::Private;
                    let secret_opt = if is_private {
                        board_data
                            .secrets
                            .iter()
                            .max_by_key(|(v, _)| *v)
                            .map(|(v, s)| (*s, *v))
                    } else {
                        None
                    };
                    Some((
                        key,
                        board_data.board_key(),
                        board_data.self_sk.clone(),
                        board_data.board_state.clone(),
                        is_private,
                        secret_opt,
                        board_data.clone(),
                    ))
                } else {
                    None
                }
            } else {
                None
            }
        };

        if let Some((
            current_board,
            board_key,
            self_sk,
            board_state_clone,
            is_private,
            secret_opt,
            snapshot,
        )) = board_info
        {
            // A composer opened inside a restricted category carries its id.
            let category_secret = reply_ctx
                .as_ref()
                .and_then(|reply| snapshot.posting_secret_for(&reply.message_id));
            let category_id = CURRENT_CATEGORY.read().category_id.clone();
            spawn(async move {
                send_message(
                    current_board,
                    board_key,
                    self_sk,
                    board_state_clone,
                    is_private,
                    secret_opt,
                    category_secret,
                    category_id,
                    title_text,
                    message_text,
                    reply_ctx,
                    poll,
                )
                .await;
            });
        }
    };

    // Don't render if no board is selected
    let Some(board_data) = current_board_data.read().clone() else {
        return rsx! {};
    };

    let self_member_id = MemberId::from(&board_data.self_sk.verifying_key());
    let owner_id = MemberId::from(&board_data.owner_vk);
    let is_owner = self_member_id == owner_id;
    let is_admin = board_data
        .board_state
        .admin
        .admins
        .iter()
        .any(|a| a.admin.id() == self_member_id);
    let can_participate = board_data.can_participate();

    let self_nickname = board_data
        .board_state
        .member_info
        .member_info
        .iter()
        .find(|ami| ami.member_info.member_id == self_member_id)
        .map(|ami| {
            match unseal_bytes_with_secrets(
                &ami.member_info.preferred_nickname,
                &board_data.secrets,
            ) {
                Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
                Err(_) => ami.member_info.preferred_nickname.to_string_lossy(),
            }
        })
        .unwrap_or_else(|| "You".to_string());

    let self_avatar = get_avatar(&self_member_id);
    let suspended_until = board_data
        .board_state
        .suspensions
        .active_until(self_member_id, chrono::Utc::now().timestamp_millis());
    let board_id = bs58::encode(board_data.owner_vk.as_bytes()).into_string();

    // Target hashes for the tab links. The links prevent the browser's default
    // navigation and set the hash instead: inside the Freenet gateway's sandboxed
    // iframe a real anchor navigation reloads the whole app (white flash).
    let nav_posts = format!("/board/{board_id}");
    let nav_members = format!("/board/{board_id}/members");
    let nav_search = format!("/board/{board_id}/search");
    let nav_notifications = format!("/board/{board_id}/notifications");
    let nav_admin = format!("/board/{board_id}/admin");
    let nav_posts_mobile = nav_posts.clone();
    let nav_members_mobile = nav_members.clone();
    let nav_search_mobile = nav_search.clone();
    let nav_notifications_mobile = nav_notifications.clone();

    // Highlight the tab matching the current hash route.
    let active_hash = CURRENT_HASH.read().trim_start_matches('#').to_string();
    let board_active = active_hash == nav_posts
        || (active_hash.starts_with(&format!("/board/{board_id}"))
            && !active_hash.contains("/admin")
            && !active_hash.contains("/members")
            && !active_hash.contains("/search")
            && !active_hash.contains("/notifications"));
    let notifications_active = active_hash.contains("/notifications");
    let search_active = active_hash.contains("/search");
    let members_active = active_hash.contains("/members");
    let admin_active = active_hash.contains("/admin");
    let tab_class = move |active: bool| {
        if active {
            "flex items-center gap-2 px-4 py-2.5 bg-accent hover:bg-accent/80 text-white font-medium rounded-xl transition-colors"
        } else {
            "flex items-center gap-2 px-4 py-2.5 bg-surface hover:bg-surface-hover text-text font-medium rounded-xl transition-colors"
        }
    };
    let nav_admin_mobile = nav_admin.clone();

    rsx! {
        div { class: "flex justify-between",
            // User profile
            div { class: "flex items-center min-w-0",
                // User profile header
                div {
                    class: "flex items-center gap-3 px-4 md:px-6 py-4 cursor-pointer hover:bg-surface/50 transition-colors",
                onclick: move |_| {
                    MEMBER_INFO_MODAL.with_mut(|signal| {
                        signal.member = Some(self_member_id);
                    });
                },
                img {
                    src: "{self_avatar}",
                    alt: "Your avatar",
                    class: "w-16 h-16 rounded-full"
                }
                span { class: "text-3xl font-medium text-text",
                    "{self_nickname}"
                }
                if is_owner {
                    span { class: "text-lg", title: "Board Owner", "👑" }
                } else if is_admin {
                    span { class: "text-lg", title: "Admin", "👑" }
                }
                }
            }

            // Right side: navigation buttons and post input
            div { class: "flex items-center gap-3 pr-4",
                // Desktop navigation buttons (hidden on mobile)
                div { class: "hidden md:flex items-center gap-3",
                    // Board button
                    button {
                        r#type: "button",
                        class: tab_class(board_active),
                        title: "View Board",
                        onclick: move |ev: MouseEvent| {
                            ev.prevent_default();
                            if let Some(win) = web_sys::window() {
                                let _ = win.location().set_hash(&nav_posts);
                            }
                        },
                        span { "📝" }
                        span { "Board" }
                    }
                    // Notifications button
                    button {
                        r#type: "button",
                        title: "Notifications",
                        class: tab_class(notifications_active),
                        onclick: move |ev: MouseEvent| {
                            ev.prevent_default();
                            if let Some(win) = web_sys::window() {
                                let _ = win.location().set_hash(&nav_notifications);
                            }
                        },
                        span { class: "relative",
                            span { "🔔" }
                            if unread_notifications() > 0 {
                                span {
                                    class: "absolute -top-2 -right-2 min-w-4 h-4 px-1 rounded-full bg-accent text-white text-[10px] leading-4 text-center",
                                    "{unread_notifications()}"
                                }
                            }
                        }
                        span { "Notifications" }
                    }
                    // Search button
                    button {
                        r#type: "button",
                        title: "Search this board",
                        class: tab_class(search_active),
                        onclick: move |ev: MouseEvent| {
                            ev.prevent_default();
                            if let Some(win) = web_sys::window() {
                                let _ = win.location().set_hash(&nav_search);
                            }
                        },
                        span { "🔍" }
                        span { "Search" }
                    }
                    // Members button
                    button {
                        r#type: "button",
                        title: "View Members",
                        class: tab_class(members_active),
                        onclick: move |ev: MouseEvent| {
                            ev.prevent_default();
                            if let Some(win) = web_sys::window() {
                                let _ = win.location().set_hash(&nav_members);
                            }
                        },
                        span { "👥" }
                        span { "Members" }
                    }
                    // Admin button for owners or admins
                    if is_owner || is_admin {
                        button {
                            r#type: "button",
                                title: "Manage Admins",
                            class: tab_class(admin_active),
                            onclick: move |ev: MouseEvent| {
                                ev.prevent_default();
                                if let Some(win) = web_sys::window() {
                                    let _ = win.location().set_hash(&nav_admin);
                                }
                            },
                            span { "⚙" }
                            span { "Admin" }
                        }
                    }
                }

                // Mobile hamburger menu (hidden on desktop)
                div { class: "relative md:hidden",
                    button {
                        class: "p-3 bg-surface hover:bg-surface-hover text-text rounded-xl transition-colors",
                        onclick: move |_| menu_open.set(!menu_open()),
                        Icon { width: 24, height: 24, icon: FaBars }
                    }

                    // Mobile dropdown menu
                    if menu_open() {
                        // Backdrop
                        div {
                            class: "fixed inset-0 z-10",
                            onclick: move |_| menu_open.set(false)
                        }
                        // Menu
                        div { class: "absolute right-0 top-full mt-2 bg-panel shadow-lg rounded-xl overflow-hidden z-20 min-w-48",
                            button {
                                r#type: "button",
                                class: "flex items-center gap-3 px-4 py-3 text-text hover:bg-surface transition-colors w-full text-left",
                                onclick: move |_| {
                                    menu_open.set(false);
                                    if let Some(win) = web_sys::window() {
                                        let _ = win.location().set_hash(&nav_posts_mobile);
                                    }
                                },
                                span { "📝" }
                                span { "Board" }
                            }
                            button {
                                r#type: "button",
                                class: "flex items-center gap-3 px-4 py-3 text-text hover:bg-surface transition-colors w-full text-left",
                                onclick: move |_| {
                                    menu_open.set(false);
                                    if let Some(win) = web_sys::window() {
                                        let _ = win.location().set_hash(&nav_notifications_mobile);
                                    }
                                },
                                span { "🔔" }
                                span { "Notifications" }
                                if unread_notifications() > 0 {
                                    span {
                                        class: "ml-auto min-w-5 h-5 px-1.5 rounded-full bg-accent text-white text-[11px] leading-5 text-center",
                                        "{unread_notifications()}"
                                    }
                                }
                            }
                            button {
                                r#type: "button",
                                class: "flex items-center gap-3 px-4 py-3 text-text hover:bg-surface transition-colors w-full text-left",
                                onclick: move |_| {
                                    menu_open.set(false);
                                    if let Some(win) = web_sys::window() {
                                        let _ = win.location().set_hash(&nav_search_mobile);
                                    }
                                },
                                span { "🔍" }
                                span { "Search" }
                            }
                            button {
                                r#type: "button",
                                class: "flex items-center gap-3 px-4 py-3 text-text hover:bg-surface transition-colors w-full text-left",
                                onclick: move |_| {
                                    menu_open.set(false);
                                    if let Some(win) = web_sys::window() {
                                        let _ = win.location().set_hash(&nav_members_mobile);
                                    }
                                },
                                span { "👥" }
                                span { "Members" }
                            }
                            if is_owner || is_admin {
                                button {
                                    r#type: "button",
                                    class: "flex items-center gap-3 px-4 py-3 text-text hover:bg-surface transition-colors w-full text-left",
                                    onclick: move |_| {
                                        menu_open.set(false);
                                        if let Some(win) = web_sys::window() {
                                            let _ = win.location().set_hash(&nav_admin_mobile);
                                        }
                                    },
                                    span { "⚙" }
                                    span { "Admin" }
                                }
                            }
                        }
                    }
                }

                // Post input
                match can_participate {
                    Ok(()) => {
                        if let Some(until) = suspended_until {
                            rsx! {
                                div { class: "px-4 py-2 bg-error-bg text-red-700 dark:text-red-400 rounded-lg text-sm",
                                    "You are suspended until {crate::util::format_utc_as_local_time(until)} and cannot post."
                                }
                            }
                        } else {
                            let max_title = current_board_data.read().as_ref()
                                .map(|bd| bd.board_state.configuration.configuration.max_title_size)
                                .unwrap_or(100);
                            let max_message = current_board_data.read().as_ref()
                                .map(|bd| bd.board_state.configuration.configuration.max_message_size)
                                .unwrap_or(10000);
                            let in_post = CURRENT_POST.read().message_id.is_some();
                            let in_category = category_reply_context.read().is_some() && !in_post;
                            // A category starts a new topic, so its context is
                            // already carried by CURRENT_CATEGORY. Only an open
                            // post presets a reply target.
                            let default_reply = post_reply_context.read().clone();
                            rsx! {
                                PostInput {
                                    in_category,
                                    in_post,
                                    handle_send_message: move |msg: (
                                        String,
                                        String,
                                        Option<ReplyContext>,
                                        Option<PollDraft>,
                                    )| { handle_send_message(msg) },
                                    replying_to: replying_to,
                                    on_request_edit_last: move |_| {},
                                    default_reply_to: default_reply,
                                    max_title_size: max_title,
                                    max_message_size: max_message,
                                }
                            }
                        }
                    },
                    Err(SendMessageError::UserNotMember) => rsx! {},
                    Err(SendMessageError::UserSuspended) => rsx! {
                        div { class: "px-4 py-2 bg-error-bg text-red-700 dark:text-red-400 rounded-lg text-sm",
                            "You are suspended and cannot post."
                        }
                    },
                    Err(SendMessageError::UserBanned) => rsx! {
                        div { class: "px-4 py-2 bg-error-bg text-red-700 dark:text-red-400 rounded-lg text-sm",
                            "You have been banned from this board."
                        }
                    },
                }
            }

            // Quotes picked from the post list wait here until the user opens
            // the composer. Several posts can be collected before replying.
            if !QUOTE_COLLECTION.read().is_empty() {
                {
                    let count = QUOTE_COLLECTION.read().len();
                    rsx! {
                        div { class: "fixed bottom-5 right-5 z-40 flex items-center gap-3 bg-panel border border-border shadow-xl rounded-xl px-4 py-3",
                            span { class: "text-sm text-text", "❝ {count} quoted" }
                            button {
                                r#type: "button",
                                class: "px-3 py-1.5 bg-accent hover:bg-accent-hover text-white text-xs font-medium rounded-lg transition-colors",
                                onclick: move |_| {
                                    *COMPOSE_REQUEST.write() += 1;
                                },
                                "Quote in reply"
                            }
                            button {
                                r#type: "button",
                                class: "px-2 py-1.5 text-text-muted hover:text-text text-xs transition-colors",
                                onclick: move |_| {
                                    QUOTE_COLLECTION.write().clear();
                                },
                                "Clear"
                            }
                        }
                    }
                }
            }

            crate::components::report_modal::ReportModal {}
        }
    }
}
