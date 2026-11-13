//! Moderation queue: reports and posts waiting for approval.

use crate::board_data::BoardData;
use crate::components::app::{BOARDS, CURRENT_BOARD};
use crate::components::conversation::{get_all_messages, MessageData};
use crate::util::ecies::unseal_bytes_with_secrets;
use crate::util::format_utc_as_local_time;
use crate::util::message_actions::ActionContext;
use crate::util::moderation_queue;
use dioxus::prelude::*;
use plaza_core::board_state::member::MemberId;
use plaza_core::board_state::reports::ReportStatus;
use std::collections::HashMap;
use wasm_bindgen_futures::spawn_local;

fn nickname(board: &BoardData, member_id: MemberId) -> String {
    board
        .board_state
        .member_info
        .member_info
        .iter()
        .find(|info| info.member_info.member_id == member_id)
        .map(|info| {
            match unseal_bytes_with_secrets(&info.member_info.preferred_nickname, &board.secrets) {
                Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
                Err(_) => info.member_info.preferred_nickname.to_string_lossy(),
            }
        })
        .unwrap_or_else(|| "Unknown".to_string())
}

fn post_label(message: &MessageData) -> String {
    if message.title_text.trim().is_empty() {
        "Untitled".to_string()
    } else {
        message.title_text.clone()
    }
}

#[component]
pub fn ModerationView() -> Element {
    let mut error = use_signal(|| None::<String>);
    let board = use_memo(move || {
        CURRENT_BOARD
            .read()
            .owner_key
            .and_then(|key| BOARDS.read().map.get(&key).cloned())
    });

    let Some(board) = board.read().clone() else {
        return rsx! {};
    };
    let self_id = MemberId::from(&board.self_sk.verifying_key());
    let owner_id = MemberId::from(&board.owner_vk);
    let is_owner = self_id == owner_id;
    let messages = get_all_messages(
        &board.board_state,
        self_id,
        &board.secrets,
        &board.category_secrets,
        &board.old_category_secrets,
    );
    let by_id: HashMap<_, _> = messages
        .iter()
        .map(|message| (message.message_id, message))
        .collect();

    let mut pending: Vec<&MessageData> = messages
        .iter()
        .filter(|message| message.is_pending && !message.is_category)
        .collect();
    pending.sort_by_key(|message| std::cmp::Reverse(message.time));

    let mut reports: Vec<_> = board.board_state.reports.reports.iter().collect();
    reports.sort_by_key(|report| {
        let open = board.board_state.reports.status_of(&report.id()) == ReportStatus::Open;
        (
            std::cmp::Reverse(open),
            std::cmp::Reverse(report.report.created_at),
        )
    });

    let approval_required = board
        .board_state
        .configuration
        .configuration
        .approval_required;
    let restricted = board.restricted_categories();
    let board_key = board.owner_vk;

    rsx! {
        div { class: "flex flex-col gap-6",
            if let Some(message) = error.read().as_ref() {
                div { class: "bg-red-500/10 border border-red-500/30 rounded-lg p-3 text-red-300 text-sm",
                    "{message}"
                }
            }

            // Approval setting
            div { class: "bg-surface rounded-lg p-4",
                h2 { class: "text-lg font-semibold text-text mb-1", "New member posts" }
                p { class: "text-text-muted text-sm mb-3",
                    "When enabled, posts by members without an approved post wait here. The author and moderators still see them; other members do not."
                }
                if is_owner {
                    button {
                        r#type: "button",
                        class: if approval_required {
                            "px-3 py-1.5 bg-accent hover:bg-accent-hover text-white text-sm rounded-lg transition-colors"
                        } else {
                            "px-3 py-1.5 bg-surface hover:bg-surface-hover text-text text-sm rounded-lg border border-border transition-colors"
                        },
                        onclick: move |_| {
                            if let Some(ctx) = ActionContext::from_current_board() {
                                if let Err(e) = moderation_queue::set_approval_required(
                                    &ctx,
                                    !approval_required,
                                ) {
                                    error.set(Some(e));
                                } else {
                                    error.set(None);
                                }
                            }
                        },
                        if approval_required {
                            "Approval queue is on"
                        } else {
                            "Approval queue is off"
                        }
                    }
                } else {
                    p { class: "text-text-muted text-sm",
                        "Only the board owner can change this setting."
                    }
                }
            }

            // Pending posts
            div { class: "bg-surface rounded-lg p-4",
                h2 { class: "text-lg font-semibold text-text mb-3",
                    "Waiting for approval ({pending.len()})"
                }
                if pending.is_empty() {
                    p { class: "text-text-muted text-sm", "No posts are waiting." }
                } else {
                    div { class: "space-y-2",
                        for message in pending.iter() {
                            {
                                let target = message.message_id;
                                let title = post_label(message);
                                let author = message.author_name.clone();
                                let time = format_utc_as_local_time(message.time.timestamp_millis());
                                rsx! {
                                    div {
                                        key: "{target.0 .0}",
                                        class: "flex flex-wrap items-center gap-3 bg-panel border border-border rounded-lg px-3 py-2",
                                        div { class: "flex-1 min-w-48",
                                            p { class: "text-text font-medium", "{title}" }
                                            p { class: "text-xs text-text-muted", "by {author} · {time}" }
                                        }
                                        button {
                                            r#type: "button",
                                            class: "px-3 py-1.5 bg-accent hover:bg-accent-hover text-white text-xs rounded-lg transition-colors",
                                            onclick: move |_| {
                                                if let Some(ctx) = ActionContext::from_current_board() {
                                                    if let Err(e) = moderation_queue::approve_post(
                                                        &ctx, target, true,
                                                    ) {
                                                        error.set(Some(e));
                                                    } else {
                                                        error.set(None);
                                                    }
                                                }
                                            },
                                            "Approve"
                                        }
                                        button {
                                            r#type: "button",
                                            class: "px-3 py-1.5 bg-surface hover:bg-surface-hover text-red-400 text-xs rounded-lg transition-colors",
                                            onclick: move |_| {
                                                if let Some(ctx) = ActionContext::from_current_board() {
                                                    if let Err(e) = moderation_queue::approve_post(
                                                        &ctx, target, false,
                                                    ) {
                                                        error.set(Some(e));
                                                    } else {
                                                        error.set(None);
                                                    }
                                                }
                                            },
                                            "Reject"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Category key rotation
            if is_owner && !restricted.is_empty() {
                div { class: "bg-surface rounded-lg p-4 space-y-2",
                    h2 { class: "text-lg font-semibold text-text", "Restricted category keys" }
                    p { class: "text-text-muted text-xs",
                        "A new version protects future posts. Old posts stay readable with the key kept on your device; the section name is re-sealed with the new key automatically."
                    }
                    for (category_id, category) in restricted.iter() {
                        {
                            let category_id = *category_id;
                            let version = board
                                .board_state
                                .category_secrets
                                .current_version(&category_id);
                            rsx! {
                                div { class: "flex flex-wrap items-center gap-3 text-sm",
                                    span { class: "text-text flex-1 min-w-32",
                                        {
                                            by_id
                                                .get(&category_id)
                                                .and_then(|message| message.category_name.clone())
                                                .unwrap_or_else(|| category.name.clone())
                                        }
                                    }
                                    span { class: "text-xs text-text-muted",
                                        "v{version.unwrap_or(0)}"
                                    }
                                    button {
                                        r#type: "button",
                                        class: "px-3 py-1.5 bg-surface hover:bg-surface-hover text-text text-xs rounded-lg",
                                        onclick: move |_| {
                                            let mut changed = false;
                                            let mut failure = None;
                                            BOARDS.with_mut(|boards| {
                                                if let Some(board) = boards.map.get_mut(&board_key) {
                                                    match board.rotate_category_secret(&category_id) {
                                                        Ok(_) => changed = true,
                                                        Err(e) => failure = Some(e),
                                                    }
                                                }
                                            });
                                            if let Some(e) = failure {
                                                error.set(Some(e));
                                                return;
                                            }
                                            if changed {
                                                error.set(None);
                                                crate::components::app::mark_needs_sync(board_key);
                                                spawn_local(async move {
                                                    let _ = crate::components::app::chat_delegate::save_boards_to_delegate().await;
                                                    crate::util::message_actions::reseal_category_name(category_id).await;
                                                });
                                            }
                                        },
                                        "Rotate key"
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Reports
            div { class: "bg-surface rounded-lg p-4",
                h2 { class: "text-lg font-semibold text-text mb-3",
                    "Reports ({reports.len()})"
                }
                if reports.is_empty() {
                    p { class: "text-text-muted text-sm", "No reports." }
                } else {
                    div { class: "space-y-2",
                        for report in reports.iter() {
                            {
                                let report_id = report.id();
                                let status = board.board_state.reports.status_of(&report_id);
                                let target = report.report.target;
                                let target_title = by_id
                                    .get(&target)
                                    .map(|message| post_label(message))
                                    .unwrap_or_else(|| "Deleted post".to_string());
                                let reporter = nickname(&board, report.report.reporter);
                                let time = format_utc_as_local_time(report.report.created_at);
                                let status_class = match status {
                                    ReportStatus::Open => "text-amber-400",
                                    ReportStatus::Resolved => "text-emerald-400",
                                    ReportStatus::Dismissed => "text-text-muted",
                                };
                                rsx! {
                                    div {
                                        key: "{report_id.0 .0}",
                                        class: "bg-panel border border-border rounded-lg px-3 py-2",
                                        div { class: "flex flex-wrap items-center gap-2",
                                            span { class: "text-xs uppercase tracking-wide text-accent",
                                                "{report.report.reason.label()}"
                                            }
                                            span { class: "text-text font-medium flex-1 min-w-40 truncate", "{target_title}" }
                                            span { class: "text-xs {status_class}", "{status.label()}" }
                                        }
                                        p { class: "text-xs text-text-muted mt-1",
                                            "reported by {reporter} · {time}"
                                        }
                                        div { class: "flex gap-2 mt-2",
                                            if status != ReportStatus::Resolved {
                                                button {
                                                    r#type: "button",
                                                    class: "px-2.5 py-1 bg-surface hover:bg-surface-hover text-emerald-400 text-xs rounded",
                                                    onclick: move |_| {
                                                        if let Some(ctx) = ActionContext::from_current_board() {
                                                            if let Err(e) = moderation_queue::resolve_report(
                                                                &ctx, report_id, ReportStatus::Resolved,
                                                            ) {
                                                                error.set(Some(e));
                                                            } else {
                                                                error.set(None);
                                                            }
                                                        }
                                                    },
                                                    "Resolve"
                                                }
                                            }
                                            if status != ReportStatus::Dismissed {
                                                button {
                                                    r#type: "button",
                                                    class: "px-2.5 py-1 bg-surface hover:bg-surface-hover text-text-muted text-xs rounded",
                                                    onclick: move |_| {
                                                        if let Some(ctx) = ActionContext::from_current_board() {
                                                            if let Err(e) = moderation_queue::resolve_report(
                                                                &ctx, report_id, ReportStatus::Dismissed,
                                                            ) {
                                                                error.set(Some(e));
                                                            } else {
                                                                error.set(None);
                                                            }
                                                        }
                                                    },
                                                    "Dismiss"
                                                }
                                            }
                                            if status != ReportStatus::Open {
                                                button {
                                                    r#type: "button",
                                                    class: "px-2.5 py-1 bg-surface hover:bg-surface-hover text-text text-xs rounded",
                                                    onclick: move |_| {
                                                        if let Some(ctx) = ActionContext::from_current_board() {
                                                            if let Err(e) = moderation_queue::resolve_report(
                                                                &ctx, report_id, ReportStatus::Open,
                                                            ) {
                                                                error.set(Some(e));
                                                            } else {
                                                                error.set(None);
                                                            }
                                                        }
                                                    },
                                                    "Reopen"
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
