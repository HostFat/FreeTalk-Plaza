//! Moderation queue: topic reports, pending topic approvals, approval settings,
//! and restricted section key rotation.

use crate::components::app::{BOARDS, CURRENT_BOARD};
use crate::util::message_actions::ActionContext;
use crate::util::moderation_queue;
use dioxus::prelude::*;
use plaza_core::board_state::member::MemberId;
use wasm_bindgen_futures::spawn_local;

#[component]
pub fn ModerationView() -> Element {
    let mut error = use_signal(|| None::<String>);
    let board = use_memo(move || {
        CURRENT_BOARD.read().owner_key.and_then(|key| {
            BOARDS
                .read()
                .map
                .get(&key)
                .cloned()
                .map(|board| board.with_merged_topics())
        })
    });
    // Load only the board/section moderation feeds on entry instead of pulling
    // every section page and every member/profile shard up front.
    use_effect(move || {
        let Some(owner) = CURRENT_BOARD.read().owner_key else {
            return;
        };
        spawn(async move {
            crate::components::app::moderation_contract::load_moderation_for_board(owner).await;
        });
    });

    let Some(board) = board.read().clone() else {
        return rsx! {};
    };
    let is_owner = board.is_current_owner();
    let approval_required = board
        .board_state
        .configuration
        .configuration
        .approval_required;
    let restricted = board.restricted_categories();
    let board_key = board.owner_vk;
    let owner_vk = board.owner_vk;
    let topic_approvals: Vec<_> = board
        .board_state
        .topics
        .entries
        .iter()
        .filter_map(|entry| {
            let count = board
                .board_state
                .topics
                .activity_for(&entry.entry.topic_id)
                .map(|activity| activity.activity.pending_approvals)
                .unwrap_or(0);
            if count == 0 {
                return None;
            }
            let title = crate::components::app::topic_contract::read_text(
                &board,
                &entry.entry.title,
            )
            .unwrap_or_else(|| "Untitled".to_string());
            Some((entry.entry.topic_id, title, count))
        })
        .collect();
    let resolved_reports: std::collections::HashSet<_> = board
        .board_state
        .topics
        .report_resolutions
        .iter()
        .map(|entry| {
            (
                entry.resolution.topic_id,
                entry.resolution.post_id,
                entry.resolution.reporter,
            )
        })
        .collect();
    let topic_reports: Vec<_> = board
        .board_state
        .topics
        .reports
        .iter()
        .filter(|entry| {
            !resolved_reports.contains(&(
                entry.report.topic_id,
                entry.report.post_id,
                entry.report.reporter,
            ))
        })
        .collect();

    // Load extra pages only for sections whose loaded moderation feed reports a
    // topic not yet in the loaded manifests, and fetch member/profile shards
    // only for reporters visible in the queue.
    {
        let missing_sections =
            crate::components::app::moderation_contract::missing_report_sections(
                owner_vk,
                &board.board_state.topics,
            );
        let queue_members: Vec<MemberId> = topic_reports
            .iter()
            .map(|entry| entry.report.reporter)
            .collect();
        if !missing_sections.is_empty() || !queue_members.is_empty() {
            crate::util::safe_spawn_local(async move {
                for section in missing_sections {
                    let _ = crate::components::app::section_contract::load_section_pages(
                        owner_vk, section,
                    )
                    .await;
                }
                if !queue_members.is_empty() {
                    crate::components::app::member_contract::load_member_shards_for(
                        owner_vk,
                        queue_members.iter().copied(),
                    )
                    .await;
                    crate::components::app::profile_contract::load_profile_shards_for(
                        owner_vk,
                        queue_members,
                    )
                    .await;
                }
            });
        }
    }

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

            // Reports filed from topic contracts.
            div { class: "bg-surface rounded-lg p-4",
                h2 { class: "text-lg font-semibold text-text mb-3",
                    "Topic reports ({topic_reports.len()})"
                }
                if topic_reports.is_empty() {
                    p { class: "text-text-muted text-sm", "No topic reports." }
                } else {
                    div { class: "space-y-2",
                        for entry in topic_reports.iter() {
                            {
                                let report = entry.report.clone();
                                let title = board
                                    .board_state
                                    .topics
                                    .entry(&report.topic_id)
                                    .and_then(|topic| {
                                        crate::components::app::topic_contract::read_text(
                                            &board,
                                            &topic.entry.title,
                                        )
                                    })
                                    .unwrap_or_else(|| "Untitled".to_string());
                                let reporter = board
                                    .display_nickname(report.reporter)
                                    .unwrap_or_else(|| report.reporter.to_string());
                                let body = crate::components::app::topic_contract::report_body(
                                    &board, &report,
                                );
                                let reason = format!("{:?}", report.reason);
                                let topic = bs58::encode(report.topic_id.as_bytes()).into_string();
                                let board_key = bs58::encode(board.owner_vk.as_bytes()).into_string();
                                let link = format!("#/board/{board_key}/topic/{topic}");
                                rsx! {
                                    div { class: "bg-panel border border-border rounded-lg px-3 py-2",
                                        div { class: "flex flex-wrap items-center gap-3",
                                            div { class: "flex-1 min-w-48",
                                                p { class: "text-text font-medium", "{title}" }
                                                p { class: "text-xs text-text-muted",
                                                    "by {reporter} · {reason}"
                                                    if let Some(post) = report.post_id {
                                                        " · reply {post}"
                                                    }
                                                }
                                            }
                                            button {
                                                r#type: "button",
                                                class: "px-3 py-1.5 bg-surface hover:bg-surface-hover text-text text-xs rounded-lg",
                                                onclick: move |_| {
                                                    if let Some(window) = web_sys::window() {
                                                        let _ = window.location().set_hash(&link);
                                                    }
                                                },
                                                "Open"
                                            }
                                            button {
                                                r#type: "button",
                                                class: "px-3 py-1.5 bg-emerald-500/20 text-emerald-300 text-xs rounded-lg",
                                                onclick: move |_| {
                                                    let owner = owner_vk;
                                                    let topic_id = report.topic_id;
                                                    let post_id = report.post_id;
                                                    let reporter = report.reporter;
                                                    spawn(async move {
                                                        if let Err(message) =
                                                            crate::components::app::topic_contract::resolve_report(
                                                                owner, topic_id, post_id, reporter,
                                                            )
                                                            .await
                                                        {
                                                            error.set(Some(message));
                                                        }
                                                    });
                                                },
                                                "Resolve"
                                            }
                                        }
                                        if !body.trim().is_empty() {
                                            p { class: "mt-2 text-sm text-text-muted", "{body}" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Topic approvals for index boards.
            div { class: "bg-surface rounded-lg p-4",
                h2 { class: "text-lg font-semibold text-text mb-3",
                    "Topic approvals ({topic_approvals.len()})"
                }
                if topic_approvals.is_empty() {
                    p { class: "text-text-muted text-sm", "No topic replies are waiting." }
                } else {
                    div { class: "space-y-2",
                        for (topic_id, title, count) in topic_approvals.iter() {
                            {
                                let topic = bs58::encode(topic_id.as_bytes()).into_string();
                                let board_key = bs58::encode(board.owner_vk.as_bytes()).into_string();
                                let link = format!("#/board/{board_key}/topic/{topic}");
                                let title = title.clone();
                                let count = *count;
                                rsx! {
                                    div { class: "flex flex-wrap items-center gap-3 bg-panel border border-border rounded-lg px-3 py-2",
                                        div { class: "flex-1 min-w-48",
                                            p { class: "text-text font-medium", "{title}" }
                                            p { class: "text-xs text-text-muted", "{count} pending reply(ies)" }
                                        }
                                        button {
                                            r#type: "button",
                                            class: "px-3 py-1.5 bg-surface hover:bg-surface-hover text-text text-xs rounded-lg",
                                            onclick: move |_| {
                                                if let Some(window) = web_sys::window() {
                                                    let _ = window.location().set_hash(&link);
                                                }
                                            },
                                            "Open"
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
                    h2 { class: "text-lg font-semibold text-text", "Restricted section keys" }
                    p { class: "text-text-muted text-xs",
                        "A new version protects future posts. Old posts stay readable with the key kept on your device."
                    }
                    for (category_id, category) in restricted.iter() {
                        {
                            let category_id = *category_id;
                            let version = board
                                .board_state
                                .category_secrets
                                .current_version(&category_id);
                            let section_label = crate::components::app::topic_contract::section_name(
                                &board,
                                &category_id,
                            )
                            .unwrap_or_else(|| category.name.clone());
                            rsx! {
                                div { class: "flex flex-wrap items-center gap-3 text-sm",
                                    span { class: "text-text flex-1 min-w-32", "{section_label}" }
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
        }
    }
}
