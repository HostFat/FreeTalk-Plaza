//! Messages: conversation list, chat view, invite link creation and sending.

use crate::components::app::dm_contract;
use dioxus::prelude::*;
use freenet_stdlib::prelude::ContractInstanceId;
use plaza_dm_core::DmMessageId;
use std::collections::HashMap;

pub static MESSAGES_OPEN: GlobalSignal<bool> = Global::new(|| false);
pub static DM_SELECTED: GlobalSignal<Option<ContractInstanceId>> = Global::new(|| None);

fn short_id(bytes: &[u8]) -> String {
    bs58::encode(bytes)
        .into_string()
        .chars()
        .take(8)
        .collect()
}

#[component]
pub fn MessagesModal() -> Element {
    if !*MESSAGES_OPEN.read() {
        return rsx! {};
    }

    let selected = *DM_SELECTED.read();
    rsx! {
        div {
            class: "fixed inset-0 z-50 flex items-center justify-center p-4",
            div {
                class: "absolute inset-0 bg-black/50",
                onclick: move |_| {
                    *MESSAGES_OPEN.write() = false;
                    *DM_SELECTED.write() = None;
                },
            }
            div {
                class: "relative z-10 w-full max-w-2xl bg-panel rounded-xl shadow-xl border border-border max-h-[88vh] flex flex-col",
                onclick: move |event| event.stop_propagation(),
                if let Some(contract_id) = selected {
                    ChatView { contract_id }
                } else {
                    ConversationList {}
                }
            }
        }
    }
}

#[component]
fn ConversationList() -> Element {
    let mut creating = use_signal(|| false);
    let conversations = dm_contract::conversations();

    rsx! {
        div { class: "flex items-center justify-between px-5 py-4 border-b border-border",
            div {
                h2 { class: "text-lg font-semibold text-text", "Messages" }
                p { class: "text-xs text-text-muted",
                    "Private 1:1 conversations. Keys stay in the delegate."
                }
            }
            button {
                r#type: "button",
                class: "px-3 py-1.5 bg-surface hover:bg-surface-hover text-text text-xs rounded-lg",
                onclick: move |_| {
                    *MESSAGES_OPEN.write() = false;
                    *DM_SELECTED.write() = None;
                },
                "Close"
            }
        }

        div { class: "px-5 py-3 border-b border-border",
            button {
                r#type: "button",
                class: "w-full px-4 py-2 bg-accent hover:bg-accent-hover disabled:opacity-60 text-white text-sm rounded-lg",
                disabled: *creating.read(),
                onclick: move |_| {
                    if *creating.read() {
                        return;
                    }
                    creating.set(true);
                    wasm_bindgen_futures::spawn_local(async move {
                            match dm_contract::create_conversation().await {
                            Ok(id) => {
                                crate::util::defer(move || *DM_SELECTED.write() = Some(id));
                            }
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
                    "No conversations yet. Create one, or open an invite link."
                }
            }
            for (id, conversation) in conversations {
                button {
                    key: "{id}",
                    r#type: "button",
                    class: "dm-conversation-row w-full text-left rounded-xl border border-border bg-surface/40 hover:bg-surface p-3 transition-colors",
                    onclick: move |_| {
                        *DM_SELECTED.write() = Some(id);
                        wasm_bindgen_futures::spawn_local(async move {
                            let _ = dm_contract::fetch_conversation(id).await;
                        });
                    },
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
                        "members {conversation.state.members.members.len()} · messages {conversation.state.messages.messages.len()} · generation {conversation.state.generation.generation}"
                    }
                }
            }
        }
    }
}

#[component]
fn ChatView(contract_id: ContractInstanceId) -> Element {
    let conversation = dm_contract::DM_CONVERSATIONS
        .read()
        .get(&contract_id)
        .cloned();
    let Some(conversation) = conversation else {
        return rsx! {
            div { class: "p-6 text-sm text-text-muted", "Conversation not found." }
        };
    };

    let mut plaintexts = use_signal(HashMap::<DmMessageId, String>::new);
    let mut draft = use_signal(String::new);
    let mut sending = use_signal(|| false);
    let mut invite = use_signal(|| None::<String>);
    let mut error = use_signal(|| None::<String>);

    // Decrypt messages as the state changes. Plaintexts are cached by id; the
    // effect reads the conversation signal, and `peek` avoids a feedback loop.
    use_effect(move || {
        let messages = dm_contract::DM_CONVERSATIONS
            .read()
            .get(&contract_id)
            .map(|conversation| conversation.state.messages.messages.clone())
            .unwrap_or_default();
        let pending: Vec<_> = messages
            .into_iter()
            .filter(|message| !plaintexts.peek().contains_key(&message.message.id))
            .collect();
        if pending.is_empty() {
            return;
        }
        wasm_bindgen_futures::spawn_local(async move {
            for message in pending {
                if let Ok(text) = dm_contract::decrypt_message(contract_id, message.clone()).await {
                    let id = message.message.id;
                    crate::util::defer(move || {
                        plaintexts.with_mut(|cache| {
                            cache.insert(id, text);
                        });
                    });
                }
            }
        });
    });

    let messages = conversation.state.messages.messages.clone();
    let members = conversation.state.members.members.len();

    rsx! {
        div { class: "flex items-center justify-between gap-2 px-5 py-3 border-b border-border",
            div { class: "flex items-center gap-2 min-w-0",
                button {
                    r#type: "button",
                    class: "px-2 py-1 bg-surface hover:bg-surface-hover text-text text-xs rounded-lg",
                    onclick: move |_| *DM_SELECTED.write() = None,
                    "Back"
                }
                div { class: "min-w-0",
                    h2 { class: "text-sm font-semibold text-text font-mono truncate",
                        "{&contract_id.to_string()[..12.min(contract_id.to_string().len())]}"
                    }
                    p { class: "text-[11px] text-text-muted", "{members} member(s)" }
                }
            }
            div { class: "flex items-center gap-2",
                button {
                    r#type: "button",
                    class: "px-3 py-1.5 bg-surface hover:bg-surface-hover text-text text-xs rounded-lg",
                    onclick: move |_| {
                        wasm_bindgen_futures::spawn_local(async move {
                            match dm_contract::create_invite(contract_id).await {
                                Ok(link) => {
                                    crate::util::copy_to_clipboard(&link);
                                    let link_for_state = link.clone();
                                    crate::util::defer(move || invite.set(Some(link_for_state)));
                                    crate::components::app::toasts::show("Invite link copied.");
                                }
                                Err(error) => crate::components::app::toasts::show_error(format!(
                                    "Could not create the invite: {error}"
                                )),
                            }
                        });
                    },
                    "Invite"
                }
                button {
                    r#type: "button",
                    class: "px-3 py-1.5 bg-surface hover:bg-surface-hover text-text text-xs rounded-lg",
                    onclick: move |_| {
                        *MESSAGES_OPEN.write() = false;
                        *DM_SELECTED.write() = None;
                    },
                    "Close"
                }
            }
        }

        if let Some(link) = invite.read().as_ref() {
            div { class: "px-5 py-2 border-b border-border",
                p { class: "text-[11px] text-text-muted mb-1", "Invite link (single use):" }
                input {
                    id: "dm-invite-link",
                    class: "w-full px-2 py-1.5 bg-surface border border-border rounded-lg text-[11px] text-text font-mono",
                    readonly: true,
                    value: "{link}"
                }
            }
        }

        div { id: "dm-message-scroll", class: "flex-1 overflow-y-auto px-5 py-4 space-y-3",
            if messages.is_empty() {
                p { class: "text-sm text-text-muted", "No messages yet. Say hello." }
            }
            for message in messages {
                div { key: "{bs58::encode(message.message.id).into_string()}", class: "rounded-xl border border-border bg-surface/40 p-3",
                    div { class: "flex items-center justify-between gap-2 text-[11px] text-text-muted",
                        span { class: "font-mono", "{short_id(&message.message.author)}" }
                        span { "{message.message.created_at}" }
                    }
                    p { class: "text-sm text-text mt-1 whitespace-pre-wrap break-words",
                        if let Some(text) = plaintexts.read().get(&message.message.id) {
                            "{text}"
                        } else {
                            "Decrypting…"
                        }
                    }
                }
            }
        }

        if let Some(message) = error.read().as_ref() {
            p { class: "px-5 pb-2 text-xs text-red-400", "{message}" }
        }

        div { class: "px-5 py-3 border-t border-border flex items-center gap-2",
            input {
                class: "flex-1 px-3 py-2 bg-surface border border-border rounded-lg text-sm text-text",
                placeholder: "Write a message…",
                value: "{draft}",
                oninput: move |event| draft.set(event.value()),
            }
            button {
                r#type: "button",
                class: "px-4 py-2 bg-accent hover:bg-accent-hover disabled:opacity-60 text-white text-sm rounded-lg",
                disabled: *sending.read(),
                onclick: move |_| {
                    let text = draft.read().trim().to_string();
                    if text.is_empty() || *sending.read() {
                        return;
                    }
                    sending.set(true);
                    error.set(None);
                    wasm_bindgen_futures::spawn_local(async move {
                        match dm_contract::send_message(contract_id, text).await {
                            Ok(()) => {
                                crate::util::defer(move || {
                                    draft.set(String::new());
                                    sending.set(false);
                                });
                            }
                            Err(message) => {
                                crate::util::defer(move || {
                                    error.set(Some(message));
                                    sending.set(false);
                                });
                            }
                        }
                    });
                },
                if *sending.read() { "Sending…" } else { "Send" }
            }
        }
    }
}
