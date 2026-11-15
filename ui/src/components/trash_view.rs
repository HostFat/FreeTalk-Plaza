//! Moderator trash list. Content preview needs the trash key and is added with
//! the full hide flow; this view already exposes the metadata and the signed
//! restore/purge actions.

use crate::components::app::{BOARDS, CURRENT_BOARD};
use crate::util::message_actions::ActionContext;
use dioxus::prelude::*;
use plaza_core::board_state::message::MessageId;
use plaza_core::board_state::moderation::category_chain;
use plaza_core::board_state::roles::ModerationPower;
use plaza_core::board_state::trash::AuthorizedTrashItem;
use std::collections::{HashMap, HashSet};

#[component]
pub fn TrashView() -> Element {
    let board_data = use_memo(move || {
        CURRENT_BOARD
            .read()
            .owner_key
            .as_ref()
            .and_then(|key| BOARDS.read().map.get(key).cloned())
    });

    let Some(data) = board_data.read().clone() else {
        return rsx! { p { class: "text-text-muted", "Select a board." } };
    };

    let mut error = use_signal(|| None::<String>);
    let mut preview = use_signal(|| {
        None::<(
            plaza_core::board_state::message::MessageId,
            Vec<(String, String)>,
        )>
    });
    let self_id = plaza_core::board_state::member::MemberId::from(&data.self_sk.verifying_key());
    let can_purge = self_id == plaza_core::board_state::member::MemberId::from(&data.owner_vk)
        || data
            .board_state
            .admin
            .admins
            .iter()
            .any(|admin| admin.admin.id() == self_id);
    let mut restore_targets = use_signal(HashMap::<MessageId, MessageId>::new);
    let mut purge_target = use_signal(|| None::<AuthorizedTrashItem>);
    let mut handled = use_signal(std::collections::HashSet::<MessageId>::new);
    let mut purge_reason_open = use_signal(|| false);
    let mut grant_target = use_signal(|| None::<plaza_core::board_state::member::MemberId>);
    let routes = data.board_state.moderation.routes_map();
    let is_owner_or_admin = self_id
        == plaza_core::board_state::member::MemberId::from(&data.owner_vk)
        || data
            .board_state
            .admin
            .admins
            .iter()
            .any(|admin| admin.admin.id() == self_id);
    let categories = data
        .board_state
        .recent_messages
        .messages
        .iter()
        .filter(|message| message.message.content.is_category())
        .map(|message| {
            let id = message.id();
            let chain = category_chain(&routes, &id);
            let can_move = is_owner_or_admin
                || data.board_state.roles.has_moderation_power(
                    &self_id,
                    ModerationPower::Move,
                    &chain,
                );
            (
                id,
                message
                    .message
                    .content
                    .title()
                    .unwrap_or_else(|| "Section".to_string()),
                can_move,
            )
        })
        .collect::<Vec<_>>();
    let sealed_members: HashSet<_> = data
        .board_state
        .pq_secrets
        .sets
        .iter()
        .filter(|entry| {
            matches!(
                entry.set.scope,
                plaza_core::board_state::pq_secrets::PqScope::Trash
            )
        })
        .flat_map(|entry| entry.set.secrets.iter().map(|secret| secret.member_id))
        .collect();
    let mut grant_candidates: Vec<_> = data
        .board_state
        .admin
        .admins
        .iter()
        .map(|admin| admin.admin.id())
        .chain(
            data.board_state
                .roles
                .assignments
                .iter()
                .filter(|assignment| {
                    !assignment.assignment.revoked
                        && data.board_state.roles.roles.iter().any(|role| {
                            role.role.id == assignment.assignment.role_id
                                && role.role.can_manage_trash
                                && !role.role.deleted
                        })
                })
                .map(|assignment| assignment.assignment.member_id),
        )
        .filter(|member| *member != self_id && !sealed_members.contains(member))
        .collect();
    grant_candidates.sort();
    grant_candidates.dedup();
    let has_trash_key = data.trash_secret.is_some();
    let mut items = data
        .board_state
        .trash
        .items
        .iter()
        .filter(|item| data.board_state.trash.active_item(&item.item.id).is_some())
        .filter(|item| !handled.read().contains(&item.item.id))
        .cloned()
        .collect::<Vec<_>>();
    items.sort_by_key(|item| std::cmp::Reverse(item.item.hidden_at));
    let purge_confirm_word = purge_target
        .read()
        .as_ref()
        .filter(|item| item.item.messages.len() >= 10)
        .map(|_| "PURGE".to_string());

    rsx! {
        div { class: "space-y-3",
            div { class: "flex items-center justify-between",
                h2 { class: "text-lg font-semibold text-text", "Trash" }
                span { class: "text-sm text-text-muted", "{items.len()} items" }
            }
            p { class: "text-sm text-text-muted",
                "Hidden topics stay encrypted here until a moderator restores or purges them. Purge is reserved for the owner and admins."
            }
            if !has_trash_key {
                p { class: "text-sm text-amber-400 border border-amber-600/40 rounded-md p-2",
                    "You do not have the trash key. Preview and Restore are disabled until a trash manager grants it to you."
                }
            }
            if let Some(message) = error.read().as_ref() {
                p { class: "text-sm text-red-400", "{message}" }
            }
            if let Some((_, messages)) = preview.read().as_ref() {
                div { class: "border border-accent/40 rounded-lg p-3 bg-panel space-y-2 max-h-80 overflow-y-auto",
                    div { class: "flex items-center justify-between",
                        h3 { class: "text-sm font-semibold text-text", "Preview" }
                        button {
                            r#type: "button",
                            class: "text-xs text-text-muted hover:text-text",
                            onclick: move |_| preview.set(None),
                            "Close"
                        }
                    }
                    for (title, body) in messages {
                        div { class: "border-t border-border pt-2",
                            p { class: "text-sm font-medium text-text", "{title}" }
                            p { class: "text-xs text-text-muted whitespace-pre-wrap", "{body}" }
                        }
                    }
                }
            }
            crate::components::reason_dialog::ReasonDialog {
                open: purge_reason_open,
                title: "Purge permanently".to_string(),
                confirm_word: purge_confirm_word,
                on_confirm: move |(code, reason): (String, String)| {
                    let Some(item) = purge_target.read().clone() else {
                        return;
                    };
                    let Some(ctx) = ActionContext::from_current_board() else {
                        return;
                    };
                    let code = crate::util::trash_actions::parse_reason_code(&code);
                    spawn(async move {
                        if let Err(message) =
                            crate::util::trash_actions::purge_item(&ctx, &item, &reason, code).await
                        {
                            if is_stale(&message) {
                                handled.write().insert(item.item.id);
                                error.set(Some("This item was already handled. The list was refreshed.".to_string()));
                            } else {
                                error.set(Some(message));
                            }
                        }
                    });
                },
            }
            if has_trash_key && !grant_candidates.is_empty() {
                div { class: "border border-border rounded-lg p-3 bg-panel space-y-2",
                    p { class: "text-sm text-text", "Grant trash access" }
                    p { class: "text-xs text-text-muted",
                        "A new manager needs the trash key before preview and restore work."
                    }
                    div { class: "flex items-center gap-2",
                        select {
                            class: "flex-1 bg-panel border border-border rounded-md px-2 py-1 text-xs text-text",
                            onchange: move |event| {
                                if let Ok(member) = event.value().parse() {
                                    grant_target.set(Some(member));
                                }
                            },
                            option { value: "", "Choose a member" }
                            for member in &grant_candidates {
                                option { value: "{member}", "{member}" }
                            }
                        }
                        button {
                            r#type: "button",
                            class: "px-3 py-1.5 text-xs rounded-md bg-accent hover:bg-accent/80 text-white",
                            onclick: move |_| {
                                let Some(member) = *grant_target.read() else {
                                    error.set(Some("Choose a member".to_string()));
                                    return;
                                };
                                let Some(ctx) = ActionContext::from_current_board() else {
                                    return;
                                };
                                spawn(async move {
                                    if let Err(message) =
                                        crate::util::trash_actions::grant_trash_access(&ctx, member).await
                                    {
                                        error.set(Some(message));
                                    }
                                });
                            },
                            "Grant"
                        }
                    }
                }
            }
            if items.is_empty() {
                p { class: "text-sm text-text-muted", "The trash is empty." }
            }
            for item in items {
                div {
                    key: "{item.item.id}",
                    class: "border border-border rounded-lg p-3 bg-panel space-y-2",
                    div { class: "flex items-center justify-between gap-3",
                        div { class: "min-w-0",
                            p { class: "text-sm text-text truncate", "Topic {item.item.root}" }
                            p { class: "text-xs text-text-muted",
                                "{item.item.messages.len()} messages · {item.item.reason}"
                            }
                            if item.item.section.map(|section| {
                                data.board_state.moderation.routes_map().get(&section).is_none()
                            }).unwrap_or(false) {
                                select {
                                    class: "mt-2 w-full bg-panel border border-border rounded-md px-2 py-1 text-xs text-text",
                                    onchange: {
                                        let item_id = item.item.id;
                                        move |event| {
                                            if let Ok(section) = event.value().parse::<MessageId>() {
                                                restore_targets.write().insert(item_id, section);
                                            }
                                        }
                                    },
                                    option { value: "", "Original section deleted — choose one" }
                                    for (id, name, enabled) in &categories {
                                        option {
                                            value: "{id}",
                                            disabled: !*enabled,
                                            if *enabled { "{name}" } else { "{name} (no Move permission)" }
                                        }
                                    }
                                }
                            }
                        }
                        div { class: "flex items-center gap-2",
                            button {
                                r#type: "button",
                                class: "px-3 py-1.5 text-xs rounded-md bg-surface hover:bg-surface-hover text-text",
                                onclick: {
                                    let item = item.clone();
                                    move |_| {
                                        let Some(ctx) = ActionContext::from_current_board() else {
                                            return;
                                        };
                                        match crate::util::trash_actions::preview_item(&ctx, &item) {
                                            Ok(messages) => preview.set(Some((item.item.id, messages))),
                                            Err(message) => error.set(Some(message)),
                                        }
                                    }
                                },
                                "Preview"
                            }
                            button {
                                r#type: "button",
                                class: "px-3 py-1.5 text-xs rounded-md bg-surface hover:bg-surface-hover text-text",
                                onclick: {
                                    let item = item.clone();
                                    move |_| {
                                        if !has_trash_key {
                                            error.set(Some("You do not have the trash key".to_string()));
                                            return;
                                        }
                                        let Some(ctx) = ActionContext::from_current_board() else {
                                            return;
                                        };
                                        let item = item.clone();
                                        let section_missing = item.item.section.map(|section| {
                                            ctx.board_state.moderation.routes_map().get(&section).is_none()
                                        }).unwrap_or(false);
                                        let destination = if section_missing {
                                            restore_targets.read().get(&item.item.id).copied()
                                        } else {
                                            None
                                        };
                                        if section_missing && destination.is_none() {
                                            error.set(Some("Choose a section for the restored topic".to_string()));
                                            return;
                                        }
                                        spawn(async move {
                                            if let Err(message) =
                                                crate::util::trash_actions::restore_item(&ctx, &item, destination)
                                                    .await
                                            {
                                                if is_stale(&message) {
                                                    handled.write().insert(item.item.id);
                                                    error.set(Some("This item was already handled. The list was refreshed.".to_string()));
                                                } else {
                                                    error.set(Some(message));
                                                }
                                            }
                                        });
                                    }
                                },
                                "Restore"
                            }
                            if can_purge {
                                button {
                                    r#type: "button",
                                    class: "px-3 py-1.5 text-xs rounded-md bg-red-600 hover:bg-red-500 text-white",
                                    onclick: {
                                        let item = item.clone();
                                        move |_| {
                                            purge_target.set(Some(item.clone()));
                                            purge_reason_open.set(true);
                                        }
                                    },
                                    "Purge"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn is_stale(message: &str) -> bool {
    let message = message.to_lowercase();
    message.contains("missing item") || message.contains("older") || message.contains("already")
}
