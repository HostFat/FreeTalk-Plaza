//! Public member profile: nickname, roles, topic count and recent topics.
//! No avatar for now.

use crate::components::app::{Route, BOARDS, CURRENT_BOARD};
use crate::util::format_utc_as_local_time;
use dioxus::prelude::*;
use plaza_core::board_state::member::MemberId;
use std::str::FromStr;

#[component]
pub fn ProfileView(member_key: String) -> Element {
    let member_id = MemberId::from_str(&member_key).ok();

    use_effect(move || {
        let (Some(owner), Some(target)) = (CURRENT_BOARD.read().owner_key, member_id) else {
            return;
        };
        crate::util::safe_spawn_local(async move {
            crate::components::app::member_contract::load_member_shards_for(owner, [target]).await;
            crate::components::app::profile_contract::load_profile_shards_for(owner, [target])
                .await;
        });
    });

    let board = use_memo(move || {
        let current = CURRENT_BOARD.read().owner_key?;
        let boards = BOARDS.read();
        let board = boards.map.get(&current)?.clone().with_merged_topics();
        let nickname = member_id
            .and_then(|target| board.display_nickname(target))
            .unwrap_or_else(|| member_id.map(|t| t.to_string()).unwrap_or_default());
        let topics: Vec<(String, String, i64)> = member_id
            .map(|target| {
                let mut authored: Vec<(String, String, i64)> = board
                    .board_state
                    .topics
                    .entries
                    .iter()
                    .filter(|entry| {
                        entry.entry.author == target
                            && !board.board_state.topics.is_hidden(&entry.entry.topic_id)
                            && board
                                .board_state
                                .topics
                                .merged_into(&entry.entry.topic_id)
                                .is_none()
                    })
                    .map(|entry| {
                        let id = bs58::encode(entry.entry.topic_id.as_bytes()).into_string();
                        let title = crate::components::app::topic_contract::read_text(
                            &board,
                            &entry.entry.title,
                        )
                        .unwrap_or_else(|| "Untitled".to_string());
                        (id, title, entry.entry.created_at)
                    })
                    .collect();
                authored.sort_by_key(|entry| std::cmp::Reverse(entry.2));
                authored
            })
            .unwrap_or_default();
        Some((board.owner_vk, topics, nickname))
    });

    let board_id = CURRENT_BOARD
        .read()
        .owner_key
        .map(|key| bs58::encode(key.as_bytes()).into_string())
        .unwrap_or_default();

    let Some(target) = member_id else {
        return rsx! {};
    };
    let Some((owner_vk, mut topics, nickname)) = board.read().clone() else {
        return rsx! {};
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

    let topic_count = topics.len();
    topics.truncate(30);

    let mail_address = {
        let boards = BOARDS.read();
        boards
            .map
            .get(&owner_vk)
            .and_then(|board| board.mail_address_for(target))
    };

    let (warnings, suspension, can_view_warnings) = {
        let boards = BOARDS.read();
        match boards
            .map
            .get(&owner_vk)
            .map(|board| board.clone().with_merged_topics())
        {
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
                            "{topic_count} topic(s)"
                        }
                        if let Some(address) = mail_address {
                            div { class: "mt-3 flex flex-wrap items-center gap-2",
                                span { class: "text-xs text-text-muted", "Freenet Mail" }
                                code { class: "text-xs text-text font-mono break-all", "{address}" }
                                a {
                                    href: "{crate::util::mail::app_url()}",
                                    target: "_blank",
                                    rel: "noopener noreferrer",
                                    class: "px-2 py-1 bg-surface hover:bg-surface-hover text-text text-xs rounded-lg transition-colors",
                                    "Open Mail"
                                }
                                button {
                                    r#type: "button",
                                    class: "px-2 py-1 bg-surface hover:bg-surface-hover text-text text-xs rounded-lg transition-colors",
                                    onclick: move |_| {
                                        crate::util::copy_to_clipboard(&address);
                                        crate::components::app::toasts::show("Mail address copied.");
                                    },
                                    "Copy"
                                }
                            }
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
                    h2 { class: "text-lg font-semibold text-text-muted mb-3", "Recent topics" }
                    if topics.is_empty() {
                        p { class: "text-text-muted text-sm", "No topics yet." }
                    } else {
                        div { class: "space-y-2",
                            for (topic_id, title, timestamp) in topics.iter() {
                                {
                                    let topic_id = topic_id.clone();
                                    let board_id = board_id.clone();
                                    let nav = navigator();
                                    let timestamp = *timestamp;
                                    rsx! {
                                        button {
                                            key: "{topic_id}",
                                            r#type: "button",
                                            class: "w-full text-left bg-panel border border-border rounded-lg px-4 py-3 hover:border-accent/50 transition-colors",
                                            onclick: move |_| {
                                                nav.push(Route::Topic {
                                                    board_id: board_id.clone(),
                                                    topic_id: topic_id.clone(),
                                                });
                                            },
                                            div { class: "flex items-baseline gap-2 flex-wrap",
                                                span { class: "text-base font-semibold text-text", "{title}" }
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
