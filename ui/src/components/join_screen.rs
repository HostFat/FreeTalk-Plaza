//! Screen for opening a reusable invite link.

use crate::components::app::{Route, BOARDS};
use crate::util::access::JoinLink;
use dioxus::prelude::*;

#[component]
pub fn JoinScreen(token: String) -> Element {
    let decoded = use_memo(move || JoinLink::decode(&token));
    let decoded_value = decoded.read().clone();
    let mut nickname = use_signal(String::new);
    let mut error = use_signal(|| None::<String>);
    let mut joining = use_signal(|| false);

    let board_key = decoded_value.as_ref().ok().map(|link| link.board);

    // Once the board state arrives, go to it.
    let board_ready = use_memo(move || {
        board_key
            .map(|key| BOARDS.read().map.contains_key(&key))
            .unwrap_or(false)
    });
    use_effect(move || {
        if *board_ready.read() {
            if let Some(key) = board_key {
                let board_id = bs58::encode(key.as_bytes()).into_string();
                navigator().push(Route::Posts { board_id });
            }
        }
    });

    match decoded_value.as_ref() {
        Err(e) => rsx! {
            div { class: "flex-1 flex flex-col items-center justify-center h-64 text-text-muted",
                p { class: "text-xl text-red-300", "Invalid invite link" }
                p { class: "text-sm mt-2", "{e}" }
                button {
                    r#type: "button",
                    class: "mt-4 px-4 py-2 bg-accent hover:bg-accent/80 text-white rounded-lg",
                    onclick: move |_| { navigator().push(Route::Home); },
                    "Go to Home"
                }
            }
        },
        Ok(link) => {
            let link = link.clone();
            rsx! {
                div { class: "flex-1 flex items-center justify-center",
                    div { class: "bg-panel border border-border rounded-xl p-6 max-w-md w-full",
                        h1 { class: "text-xl font-semibold text-text mb-1", "Join this board" }
                        p { class: "text-sm text-text-muted mb-4",
                            "Choose the nickname other members will see."
                        }
                        if let Some(err) = error.read().as_ref() {
                            div { class: "bg-red-500/10 border border-red-500/30 rounded-lg p-3 mb-3 text-red-300 text-sm",
                                "{err}"
                            }
                        }
                        input {
                            class: "w-full px-3 py-2 bg-surface border border-border rounded-lg text-text placeholder-text-muted mb-3",
                            placeholder: "Your nickname",
                            value: "{nickname}",
                            oninput: move |evt| nickname.set(evt.value()),
                        }
                        button {
                            r#type: "button",
                            class: "w-full px-4 py-2 bg-accent hover:bg-accent/80 text-white rounded-lg disabled:opacity-50",
                            disabled: *joining.read() || nickname.read().trim().is_empty(),
                            onclick: move |_| {
                                match crate::util::access::join_with_token(&link, nickname.read().clone()) {
                                    Ok(()) => { joining.set(true); error.set(None); }
                                    Err(e) => error.set(Some(e)),
                                }
                            },
                            if *joining.read() { "Joining..." } else { "Join" }
                        }
                        if *joining.read() {
                            p { class: "text-xs text-text-muted mt-3",
                                "Fetching the board state. You will be taken there as soon as it arrives."
                            }
                        }
                    }
                }
            }
        }
    }
}
