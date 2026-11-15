//! Moderator trash list. Content preview needs the trash key and is added with
//! the full hide flow; this view already exposes the metadata and the signed
//! restore/purge actions.

use crate::components::app::{BOARDS, CURRENT_BOARD};
use crate::util::message_actions::{apply_state_delta, ActionContext};
use dioxus::prelude::*;
use plaza_core::board_state::message::MessageId;
use plaza_core::board_state::trash::{
    AuthorizedTrashAction, TrashActionKind, TrashActionV1, TrashDelta,
};
use plaza_core::board_state::ChatBoardStateV1Delta;
use std::collections::HashMap;

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
    let mut restore_targets = use_signal(HashMap::<MessageId, MessageId>::new);
    let categories = data
        .board_state
        .recent_messages
        .messages
        .iter()
        .filter(|message| message.message.content.is_category())
        .map(|message| {
            (
                message.id(),
                message
                    .message
                    .content
                    .title()
                    .unwrap_or_else(|| "Section".to_string()),
            )
        })
        .collect::<Vec<_>>();
    let items = data
        .board_state
        .trash
        .items
        .iter()
        .filter(|item| data.board_state.trash.active_item(&item.item.id).is_some())
        .cloned()
        .collect::<Vec<_>>();

    rsx! {
        div { class: "space-y-3",
            div { class: "flex items-center justify-between",
                h2 { class: "text-lg font-semibold text-text", "Trash" }
                span { class: "text-sm text-text-muted", "{items.len()} items" }
            }
            p { class: "text-sm text-text-muted",
                "Hidden topics stay encrypted here until a moderator restores or purges them. Purge is reserved for the owner and admins."
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
                                    for (id, name) in &categories {
                                        option { value: "{id}", "{name}" }
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
                                                error.set(Some(message));
                                            }
                                        });
                                    }
                                },
                                "Restore"
                            }
                            button {
                                r#type: "button",
                                class: "px-3 py-1.5 text-xs rounded-md bg-red-600 hover:bg-red-500 text-white",
                                onclick: {
                                    let id = item.item.id;
                                    let generation = item.item.generation + 1;
                                    move |_| {
                                        let Some(ctx) = ActionContext::from_current_board() else {
                                            return;
                                        };
                                        let action = AuthorizedTrashAction::new(
                                            TrashActionV1 {
                                                item_id: id,
                                                kind: TrashActionKind::Purge,
                                                generation,
                                                acted_at: chrono::Utc::now().timestamp(),
                                                reason: "purged by admin".to_string(),
                                                content_hash: None,
                                            },
                                            &ctx.self_sk,
                                        );
                                        let delta = ChatBoardStateV1Delta {
                                            trash: Some(TrashDelta {
                                                items: Vec::new(),
                                                actions: vec![action],
                                            }),
                                            ..Default::default()
                                        };
                                        if let Err(message) = apply_state_delta(&ctx, delta) {
                                            error.set(Some(message));
                                        }
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
