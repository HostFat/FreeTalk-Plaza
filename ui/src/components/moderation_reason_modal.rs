//! In-page reason dialog mounted at the App root.
//!
//! It is intentionally outside the post/trash views so its event handlers are
//! attached to the top-level tree.

use crate::components::app::PENDING_MODERATION;
use crate::util::message_actions::{apply_state_delta, ActionContext};
use dioxus::prelude::*;
use plaza_core::board_state::trash::{
    AuthorizedTrashAction, AuthorizedTrashItem, ReasonCode, TrashActionKind, TrashActionV1,
    TrashDelta,
};
use plaza_core::board_state::ChatBoardStateV1Delta;

const PRESETS: &[(&str, ReasonCode, &str)] = &[
    ("severe", ReasonCode::Severe, "Severe rule violation"),
    ("spam", ReasonCode::Spam, "Spam"),
    ("harassment", ReasonCode::Harassment, "Harassment"),
    ("off_topic", ReasonCode::OffTopic, "Off-topic"),
    ("rules", ReasonCode::Rules, "Other rule violation"),
];

#[component]
pub fn ModerationReasonModal() -> Element {
    // Hooks must run unconditionally; the early return comes after them.
    let request = PENDING_MODERATION.read().clone();
    let mut selected = use_signal(|| ReasonCode::Severe);
    let mut custom = use_signal(String::new);
    let mut error = use_signal(|| None::<String>);
    let Some(request) = request else {
        return rsx! {};
    };

    let confirm_word = match &request {
        crate::components::app::PendingModerationAction::Hide(_) => None,
        crate::components::app::PendingModerationAction::Purge(_) => Some("PURGE".to_string()),
        crate::components::app::PendingModerationAction::PurgeTrash(item) => {
            if item.item.messages.len() >= 10 {
                Some("PURGE".to_string())
            } else {
                None
            }
        }
    };

    let action = request.clone();
    rsx! {
        div { class: "fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4",
            div { class: "w-full max-w-md bg-panel border border-border rounded-xl shadow-xl p-4 space-y-3",
                h2 { class: "text-lg font-semibold text-text",
                    match &action {
                        crate::components::app::PendingModerationAction::Hide(_) => "Hide topic",
                        crate::components::app::PendingModerationAction::Purge(_) => "Purge content",
                        crate::components::app::PendingModerationAction::PurgeTrash(_) => "Purge permanently",
                    }
                }
                div { class: "flex flex-wrap gap-2",
                    for (_, code, label) in PRESETS {
                        button {
                            r#type: "button",
                            class: if *selected.read() == *code {
                                "px-3 py-1.5 text-xs rounded-md bg-accent text-white"
                            } else {
                                "px-3 py-1.5 text-xs rounded-md bg-surface hover:bg-surface-hover text-text"
                            },
                            onclick: {
                                let code = *code;
                                move |_| {
                                    selected.set(code);
                                    custom.set(String::new());
                                }
                            },
                            "{label}"
                        }
                    }
                }
                textarea {
                    class: "w-full min-h-20 bg-panel border border-border rounded-md px-3 py-2 text-sm text-text",
                    placeholder: "Optional details",
                    value: "{custom}",
                    oninput: move |event| custom.set(event.value()),
                }
                if let Some(message) = error.read().as_ref() {
                    p { class: "text-xs text-red-400", "{message}" }
                }
                div { class: "flex justify-end gap-2",
                    button {
                        r#type: "button",
                        class: "px-3 py-2 text-sm rounded-md bg-surface hover:bg-surface-hover text-text",
                        onclick: move |_| *PENDING_MODERATION.write() = None,
                        "Cancel"
                    }
                    button {
                        r#type: "button",
                        class: "px-3 py-2 text-sm rounded-md bg-red-600 hover:bg-red-500 text-white",
                        onclick: move |_| {
                            if let Some(word) = confirm_word.as_ref() {
                                if !crate::util::trash_actions::ask_confirmation_word(word) {
                                    return;
                                }
                            }
                            let reason_text = custom.read().trim().to_string();
                            let reason = if reason_text.is_empty() {
                                match *selected.read() {
                                    ReasonCode::Severe => "severe rule violation",
                                    ReasonCode::Spam => "spam",
                                    ReasonCode::Harassment => "harassment",
                                    ReasonCode::OffTopic => "off-topic",
                                    ReasonCode::Rules => "other rule violation",
                                    ReasonCode::Other => "other",
                                }
                                .to_string()
                            } else {
                                reason_text
                            };
                            let code = *selected.read();
                            let action = action.clone();
                            // Close first: a synchronous prompt has just returned,
                            // so do not mutate the global later inside the spawn.
                            *PENDING_MODERATION.write() = None;
                            spawn(async move {
                                let Some(ctx) = ActionContext::from_current_board() else {
                                    return;
                                };
                                let result = match action {
                                    crate::components::app::PendingModerationAction::Hide(id) => {
                                        crate::util::trash_actions::hide_topic(&ctx, id, &reason, code).await
                                    }
                                    crate::components::app::PendingModerationAction::Purge(id) => {
                                        crate::util::trash_actions::purge_illegal(&ctx, id, &reason, code).await
                                    }
                                    crate::components::app::PendingModerationAction::PurgeTrash(item) => {
                                        purge_trash(&ctx, &item, &reason, code)
                                    }
                                };
                                if let Err(message) = result {
                                    error.set(Some(message));
                                }
                            });
                        },
                        "Confirm"
                    }
                }
            }
        }
    }
}

fn purge_trash(
    ctx: &ActionContext,
    item: &AuthorizedTrashItem,
    reason: &str,
    code: ReasonCode,
) -> Result<(), String> {
    let action = AuthorizedTrashAction::new(
        TrashActionV1 {
            item_id: item.item.id,
            kind: TrashActionKind::Purge,
            reason_code: code,
            generation: item.item.generation + 1,
            acted_at: chrono::Utc::now().timestamp(),
            reason: reason.to_string(),
            content_hash: None,
        },
        &ctx.self_sk,
    );
    apply_state_delta(
        ctx,
        ChatBoardStateV1Delta {
            trash: Some(TrashDelta {
                items: Vec::new(),
                actions: vec![action],
            }),
            ..Default::default()
        },
    )
}
