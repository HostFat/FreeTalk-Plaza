//! Minimal Messages entry point. Lists DM conversations and creates the first
//! 1:1 contract from the active DM identity/device. The chat view and invite
//! flow build on the same contract client.

use crate::components::app::dm_contract;
use dioxus::prelude::*;

pub static MESSAGES_OPEN: GlobalSignal<bool> = Global::new(|| false);

#[component]
pub fn MessagesModal() -> Element {
    if !*MESSAGES_OPEN.read() {
        return rsx! {};
    }

    let mut creating = use_signal(|| false);
    let conversations = dm_contract::conversations();

    rsx! {
        div {
            class: "fixed inset-0 z-50 flex items-center justify-center p-4",
            div {
                class: "absolute inset-0 bg-black/50",
                onclick: move |_| *MESSAGES_OPEN.write() = false,
            }
            div {
                class: "relative z-10 w-full max-w-lg bg-panel rounded-xl shadow-xl border border-border max-h-[85vh] flex flex-col",
                onclick: move |event| event.stop_propagation(),
                div { class: "flex items-center justify-between px-5 py-4 border-b border-border",
                    div {
                        h2 { class: "text-lg font-semibold text-text", "Messages" }
                        p { class: "text-xs text-text-muted",
                            "Private 1:1 conversations. Encryption keys stay in the delegate."
                        }
                    }
                    button {
                        r#type: "button",
                        class: "px-3 py-1.5 bg-surface hover:bg-surface-hover text-text text-xs rounded-lg transition-colors",
                        onclick: move |_| *MESSAGES_OPEN.write() = false,
                        "Close"
                    }
                }

                div { class: "px-5 py-3 border-b border-border",
                    button {
                        r#type: "button",
                        class: "w-full px-4 py-2 bg-accent hover:bg-accent-hover disabled:opacity-60 text-white text-sm rounded-lg transition-colors",
                        disabled: *creating.read(),
                        onclick: move |_| {
                            if *creating.read() {
                                return;
                            }
                            creating.set(true);
                            wasm_bindgen_futures::spawn_local(async move {
                                match dm_contract::create_conversation().await {
                                    Ok(id) => crate::components::app::toasts::show(format!(
                                        "Conversation created: {}",
                                        &id.to_string()[..8.min(id.to_string().len())]
                                    )),
                                    Err(error) => crate::components::app::toasts::show_error(format!(
                                        "Could not create the conversation: {error}"
                                    )),
                                }
                                crate::util::defer(move || creating.set(false));
                            });
                        },
                        if *creating.read() { "Creating…" } else { "New conversation" }
                    }
                }

                div { class: "flex-1 overflow-y-auto px-5 py-4 space-y-2",
                    if conversations.is_empty() {
                        p { class: "text-sm text-text-muted",
                            "No conversations yet. Create one to publish a new DM contract."
                        }
                    }
                    for (id, conversation) in conversations {
                        div {
                            key: "{id}",
                            class: "dm-conversation-row rounded-xl border border-border bg-surface/40 p-3",
                            div { class: "flex items-center justify-between gap-2",
                                span { class: "text-sm font-medium text-text font-mono",
                                    "{&id.to_string()[..8.min(id.to_string().len())]}"
                                }
                                span {
                                    class: if conversation.synced { "text-[11px] text-accent" } else { "text-[11px] text-amber-300" },
                                    if conversation.synced { "Synced" } else { "Syncing…" }
                                }
                            }
                            p { class: "text-[11px] text-text-muted mt-1",
                                "Created {conversation.state.meta.created_at} · members {conversation.state.members.members.len()} · generation {conversation.state.generation.generation}"
                            }
                        }
                    }
                }
            }
        }
    }
}
