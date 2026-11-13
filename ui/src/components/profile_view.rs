//! Public member profile: nickname, roles, post count and recent posts.
//! No avatar for now.

use crate::components::app::{Route, BOARDS, CURRENT_BOARD};
use crate::components::conversation::get_all_messages;
use crate::util::format_utc_as_local_time;
use dioxus::prelude::*;
use plaza_core::board_state::member::MemberId;
use std::str::FromStr;

#[component]
pub fn ProfileView(member_key: String) -> Element {
    let member_id = MemberId::from_str(&member_key).ok();

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

    let board_id = CURRENT_BOARD
        .read()
        .owner_key
        .map(|key| bs58::encode(key.as_bytes()).into_string())
        .unwrap_or_default();

    let Some(target) = member_id else {
        return rsx! {};
    };
    let Some((owner_vk, messages)) = board.read().clone() else {
        return rsx! {};
    };

    let nickname = {
        let boards = BOARDS.read();
        boards
            .map
            .get(&owner_vk)
            .and_then(|board| {
                board
                    .board_state
                    .member_info
                    .member_info
                    .iter()
                    .find(|info| info.member_info.member_id == target)
                    .map(|info| info.member_info.preferred_nickname.to_string_lossy())
            })
            .unwrap_or_else(|| target.to_string())
    };

    let roles: Vec<String> = {
        let boards = BOARDS.read();
        boards
            .map
            .get(&owner_vk)
            .map(|board| {
                board
                    .board_state
                    .roles
                    .roles
                    .iter()
                    .filter(|role| !role.role.deleted)
                    .filter(|role| {
                        board
                            .board_state
                            .roles
                            .members_of_role(&role.role.id)
                            .contains(&target)
                    })
                    .map(|role| role.role.name.clone())
                    .collect()
            })
            .unwrap_or_default()
    };

    let mut posts: Vec<_> = messages
        .iter()
        .filter(|message| !message.is_category && message.author_id == target)
        .cloned()
        .collect();
    posts.sort_by_key(|post| std::cmp::Reverse(post.time));
    let post_count = posts.len();
    posts.truncate(30);

    let (warnings, suspension, can_view_warnings) = {
        let boards = BOARDS.read();
        match boards.map.get(&owner_vk) {
            Some(board) => {
                let self_id = MemberId::from(&board.self_sk.verifying_key());
                let owner_id = MemberId::from(&board.owner_vk);
                let is_moderator = self_id == owner_id
                    || board
                        .board_state
                        .admin
                        .admins
                        .iter()
                        .any(|admin| admin.admin.id() == self_id);
                let notices: Vec<(String, i64)> = board
                    .board_state
                    .warnings
                    .for_member(target)
                    .iter()
                    .map(|entry| {
                        (
                            entry.warning.reason.label().to_string(),
                            entry.warning.created_at,
                        )
                    })
                    .collect();
                let suspension = board
                    .board_state
                    .suspensions
                    .active_until(target, chrono::Utc::now().timestamp_millis());
                (notices, suspension, self_id == target || is_moderator)
            }
            None => (Vec::new(), None, false),
        }
    };

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
                h1 { class: "text-lg font-semibold text-text ml-2", "{nickname}" }
            }
            div { class: "flex-1 overflow-y-auto",
                div { class: "max-w-4xl mx-auto px-4 py-6",
                    div { class: "bg-panel border border-border rounded-lg p-4 mb-6",
                        p { class: "text-sm text-text", "Member {target}" }
                        if !roles.is_empty() {
                            div { class: "flex flex-wrap gap-2 mt-2",
                                for role in roles.iter() {
                                    span { class: "text-xs px-2 py-0.5 rounded-full bg-surface border border-border text-text-muted", "{role}" }
                                }
                            }
                        }
                        p { class: "text-xs text-text-muted mt-2",
                            "{post_count} post(s)"
                        }
                    }
                    if can_view_warnings && (!warnings.is_empty() || suspension.is_some()) {
                        div { class: "bg-panel border border-border rounded-lg p-4 mb-6 space-y-2",
                            if let Some(until) = suspension {
                                p { class: "text-sm text-amber-400",
                                    "Suspended until {format_utc_as_local_time(until)}"
                                }
                            }
                            if !warnings.is_empty() {
                                h2 { class: "text-sm font-semibold text-text", "Warnings" }
                                for (reason, created_at) in warnings.iter() {
                                    p { class: "text-xs text-text-muted",
                                        "{reason} · {format_utc_as_local_time(*created_at)}"
                                    }
                                }
                            }
                        }
                    }
                    h2 { class: "text-lg font-semibold text-text-muted mb-3", "Recent posts" }
                    if posts.is_empty() {
                        p { class: "text-text-muted text-sm", "No posts yet." }
                    } else {
                        div { class: "space-y-2",
                            for post in posts.iter() {
                                {
                                    let post_id = post.id_string();
                                    let board_id = board_id.clone();
                                    let nav = navigator();
                                    let timestamp = post.time.timestamp_millis();
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
                                                span { class: "text-base font-semibold text-text", "{post.title_text}" }
                                                span { class: "text-xs text-text-muted", "· {format_utc_as_local_time(timestamp)}" }
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
