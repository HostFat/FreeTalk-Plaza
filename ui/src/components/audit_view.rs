//! Public moderation history assembled from the state records.

use crate::components::app::{BOARDS, CURRENT_BOARD};
use crate::components::conversation::get_all_messages;
use crate::util::ecies::unseal_bytes_with_secrets;
use crate::util::format_utc_as_local_time;
use dioxus::prelude::*;
use plaza_core::board_state::member::MemberId;
use plaza_core::board_state::message::MessageId;
use std::collections::HashMap;
use std::time::UNIX_EPOCH;

fn millis(time: std::time::SystemTime) -> i64 {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

#[component]
pub fn AuditView() -> Element {
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
    let messages = get_all_messages(
        &board.board_state,
        self_id,
        &board.secrets,
        &board.category_secrets,
        &board.old_category_secrets,
    );
    let names: HashMap<MemberId, String> = board
        .board_state
        .member_info
        .member_info
        .iter()
        .map(|info| {
            let nickname = match unseal_bytes_with_secrets(
                &info.member_info.preferred_nickname,
                &board.secrets,
            ) {
                Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
                Err(_) => info.member_info.preferred_nickname.to_string_lossy(),
            };
            (info.member_info.member_id, nickname)
        })
        .collect();
    let titles: HashMap<MessageId, String> = messages
        .iter()
        .map(|message| {
            let title = if message.title_text.trim().is_empty() {
                if message.is_category {
                    message.category_name.clone().unwrap_or_default()
                } else {
                    "Untitled".to_string()
                }
            } else {
                message.title_text.clone()
            };
            (message.message_id, title)
        })
        .collect();
    let name = |id: &MemberId| names.get(id).cloned().unwrap_or_else(|| id.to_string());
    let title = |id: &MessageId| {
        titles
            .get(id)
            .cloned()
            .unwrap_or_else(|| "a deleted post".to_string())
    };

    let mut entries: Vec<(i64, String)> = Vec::new();
    for ban in &board.board_state.bans.0 {
        entries.push((
            millis(ban.ban.banned_at),
            format!(
                "Banned {} (by {})",
                name(&ban.ban.banned_user),
                name(&ban.banned_by)
            ),
        ));
    }
    for revocation in &board.board_state.ban_revocations.revocations {
        entries.push((
            millis(revocation.revocation.revoked_at),
            format!(
                "Lifted the ban on {}",
                name(&revocation.revocation.banned_user)
            ),
        ));
    }
    for warning in &board.board_state.warnings.warnings {
        entries.push((
            warning.warning.created_at,
            format!(
                "Warned {} for {} (by {})",
                name(&warning.warning.target),
                warning.warning.reason.label(),
                name(
                    &warning.signer_id(&plaza_core::board_state::ChatBoardParametersV1 {
                        owner: board.owner_vk,
                    })
                )
            ),
        ));
    }
    for suspension in &board.board_state.suspensions.suspensions {
        entries.push((
            suspension.suspension.created_at,
            format!(
                "Suspended {} until {} for {}",
                name(&suspension.suspension.target),
                format_utc_as_local_time(suspension.suspension.until),
                suspension.suspension.reason.label()
            ),
        ));
    }
    for report in &board.board_state.reports.reports {
        entries.push((
            report.report.created_at,
            format!(
                "Reported {} for {} (by {})",
                title(&report.report.target),
                report.report.reason.label(),
                name(&report.report.reporter)
            ),
        ));
    }
    for resolution in &board.board_state.reports.resolutions {
        let target = board
            .board_state
            .reports
            .reports
            .iter()
            .find(|report| report.id() == resolution.resolution.report_id)
            .map(|report| title(&report.report.target))
            .unwrap_or_else(|| "a deleted post".to_string());
        entries.push((
            0,
            format!(
                "Report on {} marked {}",
                target,
                resolution.resolution.status.label()
            ),
        ));
    }
    for approval in &board.board_state.approvals.approvals {
        entries.push((
            0,
            format!(
                "{} {}",
                if approval.approval.approved {
                    "Approved"
                } else {
                    "Rejected"
                },
                title(&approval.approval.target)
            ),
        ));
    }
    for file in &board.board_state.moderation.flags {
        let mut actions = Vec::new();
        if file.flag.pinned {
            actions.push("pinned");
        }
        if file.flag.closed {
            actions.push("closed");
        }
        if file.flag.announced {
            actions.push("announced");
        }
        if file.flag.merged_into.is_some() {
            actions.push("merged");
        }
        if actions.is_empty() {
            continue;
        }
        entries.push((
            0,
            format!("{}: {}", title(&file.flag.target), actions.join(", ")),
        ));
    }
    for change in &board.board_state.moderation.moves {
        entries.push((
            change.change.created_at,
            format!(
                "Moved {} to {}",
                title(&change.change.target),
                change
                    .change
                    .new_parent
                    .map(|id| title(&id))
                    .unwrap_or_else(|| "the board root".to_string())
            ),
        ));
    }
    for role in board
        .board_state
        .roles
        .roles
        .iter()
        .filter(|role| !role.role.deleted)
    {
        entries.push((0, format!("Role {} defined", role.role.name)));
    }

    entries.sort_by_key(|(timestamp, _)| std::cmp::Reverse(*timestamp));
    entries.truncate(100);

    rsx! {
        div { class: "bg-surface rounded-lg p-4",
            h2 { class: "text-lg font-semibold text-text mb-3", "Moderation history" }
            p { class: "text-text-muted text-xs mb-3",
                "Built from the signed records in board state. Records without a timestamp appear at the end."
            }
            if entries.is_empty() {
                p { class: "text-text-muted text-sm", "Nothing yet." }
            } else {
                div { class: "space-y-1",
                    for (timestamp, text) in entries.iter() {
                        div { class: "flex gap-3 text-xs border-b border-border/50 py-1 last:border-0",
                            span { class: "text-text-muted w-32 flex-shrink-0",
                                if *timestamp > 0 {
                                    "{format_utc_as_local_time(*timestamp)}"
                                }
                            }
                            span { class: "text-text", "{text}" }
                        }
                    }
                }
            }
        }
    }
}
