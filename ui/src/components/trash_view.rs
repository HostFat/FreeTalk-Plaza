//! Moderator trash list. Content preview needs the trash key and is added with
//! the full hide flow; this view already exposes the metadata and the signed
//! restore/purge actions.

use crate::components::app::{BOARDS, CURRENT_BOARD};
use crate::util::message_actions::{apply_state_delta, ActionContext};
use dioxus::prelude::*;
use plaza_core::board_state::trash::{
    AuthorizedTrashAction, TrashActionKind, TrashActionV1, TrashDelta,
};
use plaza_core::board_state::ChatBoardStateV1Delta;

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
                        }
                        div { class: "flex items-center gap-2",
                            button {
                                r#type: "button",
                                class: "px-3 py-1.5 text-xs rounded-md bg-surface hover:bg-surface-hover text-text",
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
                                                kind: TrashActionKind::Restore,
                                                generation,
                                                acted_at: chrono::Utc::now().timestamp(),
                                                reason: "restored by moderator".to_string(),
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
