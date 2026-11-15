//! Dedicated purge route. Keeping the action on its own page avoids the
//! overlay/event issues of the in-page reason modal.

use crate::util::message_actions::ActionContext;
use dioxus::prelude::*;
use plaza_core::board_state::message::MessageId;
use plaza_core::board_state::trash::ReasonCode;

#[component]
pub fn PurgeView(board_id: String, post_id: String) -> Element {
    let mut reason = use_signal(|| ReasonCode::Severe);
    let mut details = use_signal(String::new);
    let mut typed = use_signal(String::new);
    let mut error = use_signal(|| None::<String>);

    let board = board_id.clone();
    let cancel_board = board_id.clone();
    let confirm_board = board_id.clone();

    rsx! {
        form {
            class: "max-w-2xl mx-auto p-6 space-y-4",
            onsubmit: move |event| {
                event.prevent_default();
                if typed.read().trim() != "PURGE" {
                    error.set(Some("Type PURGE to confirm".to_string()));
                    return;
                }
                let Ok(id) = post_id.parse::<MessageId>() else {
                    error.set(Some("Invalid post id".to_string()));
                    return;
                };
                let code = *reason.read();
                let text = details.read().clone();
                let reason_text = if text.trim().is_empty() {
                    "severe rule violation".to_string()
                } else {
                    text
                };
                let Some(ctx) = ActionContext::from_current_board() else {
                    error.set(Some("Board context is not available".to_string()));
                    return;
                };
                let board = confirm_board.clone();
                wasm_bindgen_futures::spawn_local(async move {
                    match crate::util::trash_actions::purge_illegal(&ctx, id, &reason_text, code).await {
                        Ok(()) => {
                            if let Some(window) = web_sys::window() {
                                let _ = window.location().set_hash(&format!("/board/{board}"));
                            }
                        }
                        Err(message) => error.set(Some(message)),
                    }
                });
            },
            h1 { class: "text-2xl font-bold text-text", "Purge content" }
            p { class: "text-sm text-text-muted",
                "This removes the topic and all replies from the board. There is no trash copy."
            }
            div { class: "flex flex-wrap gap-2",
                for (code, label) in [
                    (ReasonCode::Severe, "Severe rule violation"),
                    (ReasonCode::Spam, "Spam"),
                    (ReasonCode::Harassment, "Harassment"),
                    (ReasonCode::OffTopic, "Off-topic"),
                    (ReasonCode::Rules, "Other rule violation"),
                ] {
                    button {
                        r#type: "button",
                        class: if *reason.read() == code {
                            "px-3 py-1.5 text-xs rounded-md bg-accent text-white"
                        } else {
                            "px-3 py-1.5 text-xs rounded-md bg-surface hover:bg-surface-hover text-text"
                        },
                        onclick: move |_| reason.set(code),
                        "{label}"
                    }
                }
            }
            textarea {
                class: "w-full min-h-24 bg-panel border border-border rounded-md px-3 py-2 text-sm text-text",
                placeholder: "Optional details",
                value: "{details}",
                oninput: move |event| details.set(event.value()),
            }
            div { class: "space-y-1",
                p { class: "text-xs text-text-muted", "Type PURGE to confirm." }
                input {
                    class: "w-full bg-panel border border-border rounded-md px-3 py-2 text-sm text-text",
                    value: "{typed}",
                    oninput: move |event| typed.set(event.value()),
                }
            }
            if let Some(message) = error.read().as_ref() {
                p { class: "text-sm text-red-400", "{message}" }
            }
            div { class: "flex justify-end gap-2",
                button {
                    r#type: "button",
                    class: "px-3 py-2 text-sm rounded-md bg-surface hover:bg-surface-hover text-text",
                    onclick: move |_| {
                        if let Some(window) = web_sys::window() {
                            let _ = window.location().set_hash(&format!("/board/{cancel_board}"));
                        }
                    },
                    "Cancel"
                }
                button {
                    r#type: "submit",
                    class: "px-3 py-2 text-sm rounded-md bg-red-600 hover:bg-red-500 text-white",
                    "Confirm purge"
                }
            }
            button {
                r#type: "button",
                class: "text-xs text-text-muted hover:text-text",
                onclick: move |_| {
                    if let Some(window) = web_sys::window() {
                        let _ = window.location().set_hash(&format!("/board/{board}"));
                    }
                },
                "Back to board"
            }
        }
    }
}
