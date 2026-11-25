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
use wasm_bindgen_futures::spawn_local;

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
            .and_then(|key| {
                BOARDS
                    .read()
                    .map
                    .get(&key)
                    .cloned()
                    .map(|board| board.with_merged_topics())
            })
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
    for flag in &board.board_state.moderation.feature_flags {
        if !flag.flag.value {
            continue;
        }
        let action = match flag.flag.kind {
            plaza_core::board_state::moderation::FeatureKind::Pinned => "pinned",
            plaza_core::board_state::moderation::FeatureKind::Closed => "closed",
            plaza_core::board_state::moderation::FeatureKind::Announced => "announced",
            plaza_core::board_state::moderation::FeatureKind::Merged => "merged",
        };
        entries.push((
            flag.flag.created_at,
            format!("{}: {}", title(&flag.flag.target), action),
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
    for retirement in &board.board_state.image_retirements.retirements {
        let instance: String = retirement
            .retirement
            .instance
            .iter()
            .take(4)
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let hash: String = retirement
            .retirement
            .sha256
            .iter()
            .take(4)
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let signer = retirement
            .signer
            .map(|id| {
                names
                    .get(&id)
                    .cloned()
                    .unwrap_or_else(|| format!("{:?}", id))
            })
            .unwrap_or_else(|| "the owner".to_string());
        entries.push((
            retirement.retirement.created_at,
            format!(
                "Retired image {instance} (hash {hash}) · {} · by {signer}",
                retirement.retirement.reason
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

    let mut purge_filter = use_signal(String::new);
    let blocked_hashes = BOARDS.read().blocked_image_hashes.clone();
    let unblock = move |hash: [u8; 32]| {
        BOARDS.with_mut(|boards| {
            boards.blocked_image_hashes.retain(|blocked| blocked != &hash);
        });
        spawn_local(async {
            let _ = crate::components::app::chat_delegate::save_boards_to_delegate().await;
        });
    };
    let mut purges: Vec<(i64, String, String)> = board
        .board_state
        .moderation
        .illegal_purges
        .iter()
        .map(|entry| {
            let code = format!("{:?}", entry.purge.reason_code).to_lowercase();
            (
                entry.purge.acted_at,
                code.clone(),
                format!(
                    "Purged illegal thread {} · {} messages · {}{}",
                    title(&entry.purge.topic),
                    entry.purge.message_ids.len(),
                    entry.purge.reason,
                    entry
                        .purge
                        .content_hash
                        .map(|hash| format!(
                            " · hash {}",
                            hash.iter()
                                .take(4)
                                .map(|byte| format!("{byte:02x}"))
                                .collect::<String>()
                        ))
                        .unwrap_or_default()
                ),
            )
        })
        .collect();
    purges.sort_by_key(|(timestamp, _, _)| std::cmp::Reverse(*timestamp));

    entries.sort_by_key(|(timestamp, _)| std::cmp::Reverse(*timestamp));
    entries.truncate(100);

    rsx! {
        div { class: "bg-surface rounded-lg p-4",
            h2 { class: "text-lg font-semibold text-text mb-3", "Moderation history" }
            div { class: "bg-panel border border-border rounded-lg p-3 mb-4 space-y-2",
                div { class: "flex items-center justify-between",
                    h3 { class: "text-sm font-semibold text-text", "Illegal purges" }
                    select {
                        class: "bg-panel border border-border rounded-md px-2 py-1 text-xs text-text",
                        onchange: move |event| purge_filter.set(event.value()),
                        option { value: "", "All reasons" }
                        option { value: "severe", "Severe rule violation" }
                        option { value: "spam", "Spam" }
                        option { value: "harassment", "Harassment" }
                        option { value: "off_topic", "Off-topic" }
                        option { value: "rules", "Other rule violation" }
                        option { value: "other", "Other" }
                    }
                }
                if purges.is_empty() {
                    p { class: "text-xs text-text-muted", "No illegal purges on record." }
                } else {
                    for (timestamp, code, text) in purges.iter() {
                        if purge_filter.read().is_empty() || purge_filter.read().as_str() == code {
                            div { class: "flex gap-3 text-xs border-b border-border/50 py-1 last:border-0",
                                span { class: "text-text-muted w-32 flex-shrink-0", "{format_utc_as_local_time(*timestamp)}" }
                                span { class: "text-text", "{text}" }
                            }
                        }
                    }
                }
            }
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

        div { class: "bg-surface rounded-lg p-4 mt-4",
            h2 { class: "text-lg font-semibold text-text mb-3", "Blocked images on this device" }
            p { class: "text-text-muted text-xs mb-3",
                "Hashes this device refuses to download or show, independent of any board."
            }
            if blocked_hashes.is_empty() {
                p { class: "text-text-muted text-sm", "No blocked images." }
            } else {
                div { class: "space-y-1",
                    for hash in blocked_hashes.iter() {
                        div {
                            key: "{hash:?}",
                            class: "flex items-center justify-between gap-3 text-xs border-b border-border/50 py-1 last:border-0",
                            span { class: "font-mono text-text-muted",
                                {
                                    hash.iter()
                                        .take(8)
                                        .map(|byte| format!("{byte:02x}"))
                                        .collect::<String>()
                                }
                            }
                            button {
                                r#type: "button",
                                class: "px-2 py-1 bg-surface hover:bg-surface-hover border border-border rounded text-text",
                                onclick: {
                                    let hash = *hash;
                                    move |_| unblock(hash)
                                },
                                "Unblock"
                            }
                        }
                    }
                }
            }
        }
        div { class: "bg-surface rounded-lg p-4 mt-4",
            h2 { class: "text-lg font-semibold text-text mb-3", "Your uploaded images" }
            div { class: "flex flex-wrap items-center justify-between gap-3 mb-3",
                label { class: "flex items-center gap-2 text-sm text-text",
                    input {
                        r#type: "checkbox",
                        checked: BOARDS.read().auto_renew_images,
                        onchange: move |event| {
                            let enabled = event.checked();
                            BOARDS.with_mut(|boards| {
                                boards.auto_renew_images = enabled;
                                // A fresh opt-in runs now instead of waiting a day.
                                boards.last_auto_renew_at = 0;
                            });
                            spawn_local(async {
                                if let Err(error) =
                                    crate::components::app::chat_delegate::save_boards_to_delegate()
                                        .await
                                {
                                    crate::components::app::toasts::show_error(format!(
                                        "Could not save the renewal setting: {error}"
                                    ));
                                }
                            });
                            if enabled {
                                crate::util::owned_images::renew_if_due();
                            }
                            crate::components::app::toasts::show(if enabled {
                                "Automatic renewal on: up to 10 images a day."
                            } else {
                                "Automatic renewal off."
                            });
                        },
                    }
                    span { "Auto-renew old images" }
                }
                span { class: "text-xs text-text-muted",
                    "Off by default; at most 10 images per day."
                }
            }
            {
                let unused = crate::util::owned_images::unreferenced(60 * 60 * 1000).len();
                rsx! {
                    p { class: "text-text-muted text-xs mb-3",
                        "Images this device uploaded that no board references anymore."
                    }
                    if unused == 0 {
                        p { class: "text-text-muted text-sm", "Nothing to clean up." }
                    } else {
                        div { class: "flex items-center justify-between gap-3",
                            span { class: "text-sm text-text", "{unused} unused" }
                            button {
                                r#type: "button",
                                class: "px-3 py-1.5 bg-surface hover:bg-surface-hover border border-border rounded-lg text-xs text-red-300",
                                onclick: move |_| crate::util::owned_images::retire_unused(true),
                                "Retire unused"
                            }
                        }
                    }
                    details { class: "mt-3",
                        summary { class: "text-xs text-text-muted cursor-pointer", "Developer" }
                        p { class: "text-xs text-text-muted mt-1 mb-2",
                            "Test hook: backdates the newest uploaded image by two hours so Retire unused can be exercised."
                        }
                        button {
                            r#type: "button",
                            class: "px-3 py-1.5 bg-surface hover:bg-surface-hover border border-border rounded-lg text-xs text-amber-300",
                            onclick: move |_| {
                                if crate::util::owned_images::backdate_newest_image() {
                                    crate::components::app::toasts::show(
                                        "Newest image backdated by two hours.",
                                    );
                                } else {
                                    crate::components::app::toasts::show_error(
                                        "No uploaded images to backdate.",
                                    );
                                }
                            },
                            "Backdate newest image"
                        }
                    }
                }
            }
        }
        div { class: "bg-surface rounded-lg p-4 mt-4",
            h2 { class: "text-lg font-semibold text-text mb-1", "Storage on this device" }
            p { class: "text-text-muted text-xs mb-3",
                "Estimated from the local copy. The network keeps its own copy of the boards."
            }
            {
                let sizes = crate::util::storage::sizes();
                rsx! {
                    dl { class: "grid grid-cols-[1fr_auto] gap-x-4 gap-y-1 text-sm",
                        dt { class: "text-text-muted", "Board map" }
                        dd { class: "text-text text-right", "{crate::util::storage::format_bytes(sizes.boards)}" }
                        dt { class: "text-text-muted", "Image index" }
                        dd { class: "text-text text-right",
                            "{crate::util::storage::format_bytes(sizes.images)} · {sizes.image_count} image(s)"
                        }
                        dt { class: "text-text-muted", "Composer queues" }
                        dd { class: "text-text text-right",
                            "{crate::util::storage::format_bytes(sizes.queues)} · {sizes.queued_count} upload(s)"
                        }
                    }
                }
            }
        }
    }
}
