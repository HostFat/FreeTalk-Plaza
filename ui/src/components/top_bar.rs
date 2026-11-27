//! Top bar component showing user profile, admin controls, and post input.

use crate::board_data::SendMessageError;
use crate::components::app::{ABOUT_MODAL, BOARDS, CURRENT_BOARD, CURRENT_HASH};
use crate::components::board_sync_chip::BoardSyncChip;
use crate::components::device_drawer::{open as open_device, DeviceTab};
use crate::components::messages_view::MESSAGES_OPEN;
use crate::util::avatar::get_avatar;
use dioxus::prelude::*;
use dioxus_free_icons::{icons::fa_solid_icons::FaBars, Icon};
use plaza_core::board_state::member::MemberId;

/// Top bar component displaying the current user's profile and navigation controls.
#[component]
pub fn TopBar() -> Element {
    let mut menu_open = use_signal(|| false);

    // Housekeeping for bans: the owner lifts expired bans, and a member who is
    // no longer banned puts its stored membership back. Both are idempotent.
    use_effect(move || {
        // Dioxus `spawn` has been unreliable for long-running loops in this
        // wasm app; use the browser task scheduler instead.
        wasm_bindgen_futures::spawn_local(async move {
            loop {
                crate::components::members::member_info_modal::ban_button::auto_lift_expired_bans();
                crate::util::membership::restore_self_membership();
                crate::util::pq::housekeeping();
                crate::components::app::flush_pending_sync();
                crate::components::app::SYNC_TICK.with_mut(|tick| *tick += 1);
                crate::util::spectator::fetch_pending_spectator_boards().await;
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

    // Bans, roles, suspensions and the policy are mirrored inside each topic
    // contract. When the board authority changes, push a snapshot to the
    // topics in the index. The hash stops this from running on ordinary board
    // changes such as a new message.
    let authority_stamp = use_memo(move || {
        let board = current_board_data.read().clone()?;
        if !board.board_state.mode.is_topic_index() {
            return None;
        }
        Some((
            board.owner_vk,
            crate::components::app::topic_contract::authority_hash(&board),
        ))
    });
    use_effect(move || {
        let Some((owner, hash)) = authority_stamp() else {
            return;
        };
        if crate::components::app::topic_contract::mark_authority_seen(owner, hash) {
            spawn(async move {
                let _ =
                    crate::components::app::topic_contract::propagate_authority(owner)
                        .await;
            });
        }
    });

    // Unread notifications for the bell badge.
    let unread_notifications = use_memo(move || {
        let Some(key) = CURRENT_BOARD.read().owner_key else {
            return 0;
        };
        let boards = BOARDS.read();
        let Some(board) = boards.map.get(&key) else {
            return 0;
        };
        let board = board.clone().with_merged_topics();
        if board.board_state.mode.is_topic_index() {
            board
                .board_state
                .topics
                .entries
                .iter()
                .filter(|entry| {
                    !board.board_state.topics.is_hidden(&entry.entry.topic_id)
                        && board
                            .board_state
                            .topics
                            .merged_into(&entry.entry.topic_id)
                            .is_none()
                })
                .filter(|entry| {
                    let last_at = board
                        .board_state
                        .topics
                        .activity_for(&entry.entry.topic_id)
                        .map(|activity| activity.activity.last_activity)
                        .unwrap_or(entry.entry.created_at);
                    last_at > board.topic_last_read(&entry.entry.topic_id)
                })
                .count()
        } else {
            crate::util::notifications::unread_count(&board)
        }
    });

    // Don't render if no board is selected
    let Some(board_data) = current_board_data.read().clone() else {
        return rsx! {};
    };

    let self_member_id = MemberId::from(&board_data.self_sk.verifying_key());
    // A spectator has no management surface, whatever the board state says.
    let as_member = crate::components::app::view_as_member();
    let is_owner = !as_member && !board_data.spectator && board_data.is_active_owner();
    let is_admin = !as_member
        && !board_data.spectator
        && board_data
            .board_state
            .admin
            .admins
            .iter()
            .any(|a| a.admin.id() == self_member_id);
    let can_participate = board_data.can_participate();
    let can_manage_trash = !as_member
        && !board_data.spectator
        && crate::board_data::can_manage_trash(&board_data.board_state, self_member_id);
    let can_open_manage = is_owner || is_admin || can_manage_trash;

    let self_nickname = if board_data.spectator {
        "Spectator".to_string()
    } else {
        board_data
            .display_nickname(self_member_id)
            .unwrap_or_else(|| "You".to_string())
    };

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
            // Profile header. Clicking it opens the identities drawer, the
            // place where profiles are switched and managed.
            button {
                r#type: "button",
                class: "flex items-center gap-3 px-4 md:px-6 py-4 cursor-pointer hover:bg-surface/50 transition-colors text-left",
                title: "Identities and backup",
                aria_label: "Open identities",
                onclick: move |_| open_device(DeviceTab::Identities),
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
                span { class: "text-text-muted text-xl ml-1", "›" }
            }

            // Right side: navigation buttons and post input
            div { class: "flex items-center gap-3 pr-4",
                BoardSyncChip { board: board_data.owner_vk }
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
                    // Direct messages
                    button {
                        r#type: "button",
                        title: "Messages",
                        aria_label: "Messages",
                        class: tab_class(false),
                        onclick: move |_| *MESSAGES_OPEN.write() = true,
                        span { "💬" }
                        span { "Messages" }
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
                    // Manage button for owners, admins and trash managers.
                    if can_open_manage {
                        button {
                            r#type: "button",
                            title: "Manage",
                            class: tab_class(admin_active),
                            onclick: move |ev: MouseEvent| {
                                ev.prevent_default();
                                if let Some(win) = web_sys::window() {
                                    let _ = win.location().set_hash(&nav_admin);
                                }
                            },
                            span { "⚙" }
                            span { "Manage" }
                        }
                    }
                    // About and build details. Visible for every member.
                    button {
                        r#type: "button",
                        title: "About, build and backup",
                        aria_label: "About FreeTalk Plaza",
                        class: tab_class(false),
                        onclick: move |_| *ABOUT_MODAL.write() = true,
                        span { "ⓘ" }
                        span { "About" }
                    }
                }

                // Mobile hamburger menu (hidden on desktop)
                div { class: "relative md:hidden",
                    button {
                        class: "p-3 bg-surface hover:bg-surface-hover text-text rounded-xl transition-colors",
                        title: "Menu",
                        aria_label: "Menu",
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
                                    *MESSAGES_OPEN.write() = true;
                                },
                                span { "💬" }
                                span { "Messages" }
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
                            if can_open_manage {
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
                                    span { "Manage" }
                                }
                            }
                            div { class: "border-t border-border",
                                button {
                                    r#type: "button",
                                    class: "flex items-center gap-3 px-4 py-3 text-text hover:bg-surface transition-colors w-full text-left",
                                    onclick: move |_| {
                                        menu_open.set(false);
                                        open_device(DeviceTab::Identities);
                                    },
                                    span { "👤" }
                                    span { "Identities and backup" }
                                }
                                button {
                                    r#type: "button",
                                    class: "flex items-center gap-3 px-4 py-3 text-text hover:bg-surface transition-colors w-full text-left",
                                    onclick: move |_| {
                                        menu_open.set(false);
                                        *ABOUT_MODAL.write() = true;
                                    },
                                    span { "ⓘ" }
                                    span { "About FreeTalk Plaza" }
                                }
                            }
                        }
                    }
                }

                // Participation status hint
                match can_participate {
                    Ok(()) => {
                        if let Some(until) = suspended_until {
                            rsx! {
                                div { class: "px-4 py-2 bg-error-bg text-red-700 dark:text-red-400 rounded-lg text-sm",
                                    "You are suspended until {crate::util::format_utc_as_local_time(until)} and cannot post."
                                }
                            }
                        } else {
                            rsx! {
                                div { class: "px-4 py-2 bg-surface border border-border rounded-lg text-xs text-text-muted",
                                    "Open a topic to reply, or create one from the board page."
                                }
                            }
                        }
                    }
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

            crate::components::report_modal::ReportModal {}
        }
    }
}
