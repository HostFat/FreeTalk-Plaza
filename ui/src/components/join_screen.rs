//! Screen for opening a reusable invite link.

use crate::components::app::{Route, BOARDS};
use crate::util::access::JoinLink;
use dioxus::prelude::*;

#[component]
pub fn JoinScreen(token: String) -> Element {
    let decoded = use_memo(move || JoinLink::decode(&token));
    let decoded_value = decoded.read().clone();
    let mut nickname = use_signal(String::new);
    let mut selected_profile = use_signal(|| 0usize);
    let mut error = use_signal(|| None::<String>);
    let mut joining = use_signal(|| false);
    let mut joined = use_signal(|| false);
    let mut timed_out = use_signal(|| false);
    let profiles = use_memo(move || BOARDS.read().profiles.clone());

    let board_key = decoded_value.as_ref().ok().map(|link| link.board);

    // Once the invite is accepted and the board state is available, go to it.
    // A board already present as a spectator must not skip the nickname step:
    // the membership only exists after Join.
    let board_ready = use_memo(move || {
        board_key
            .map(|key| BOARDS.read().map.contains_key(&key))
            .unwrap_or(false)
    });
    use_effect(move || {
        if *joined.read() && *board_ready.read() {
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
                        if !profiles.read().is_empty() {
                            label { class: "block text-sm font-medium text-text mb-1", "Identity" }
                            select {
                                class: "w-full px-3 py-2 bg-surface border border-border rounded-lg text-text text-sm mb-1",
                                value: "{selected_profile}",
                                onchange: move |evt| {
                                    let index = evt.value().parse::<usize>().unwrap_or(0);
                                    selected_profile.set(index);
                                    if index > 0 {
                                        if let Some(profile) = profiles.read().get(index - 1) {
                                            nickname.set(profile.name.clone());
                                        }
                                    }
                                },
                                option { value: "0", "New identity (unlinkable)" }
                                for (index, profile) in profiles.read().iter().enumerate() {
                                    option { value: "{index + 1}", "{profile.name} (same identity)" }
                                }
                            }
                            p { class: "text-xs text-text-muted mb-3",
                                "Reusing a profile shows the same member id on this board too. A new identity keeps the boards apart."
                            }
                        }
                        input {
                            class: "w-full px-3 py-2 bg-surface border border-border rounded-lg text-text placeholder-text-muted mb-3",
                            dir: "auto",
                            placeholder: "Your nickname",
                            value: "{nickname}",
                            oninput: move |evt| nickname.set(evt.value()),
                        }
                        button {
                            r#type: "button",
                            class: "w-full px-4 py-2 bg-accent hover:bg-accent/80 text-white rounded-lg disabled:opacity-50",
                            disabled: *joining.read() || nickname.read().trim().is_empty(),
                            onclick: move |_| {
                                let profile_key = {
                                    let index = *selected_profile.read();
                                    profiles
                                        .read()
                                        .get(index.saturating_sub(1))
                                        .filter(|_| index > 0)
                                        .map(|profile| profile.signing_key.clone())
                                };
                                match crate::util::access::join_with_token(
                                    &link,
                                    nickname.read().clone(),
                                    profile_key,
                                ) {
                                    Ok(()) => {
                                        joining.set(true);
                                        joined.set(true);
                                        timed_out.set(false);
                                        error.set(None);
                                        if let Some(key) = board_key {
                                            wasm_bindgen_futures::spawn_local(async move {
                                                futures_timer::Delay::new(std::time::Duration::from_secs(25)).await;
                                                if !BOARDS.read().map.contains_key(&key) {
                                                    timed_out.set(true);
                                                }
                                            });
                                        }
                                    }
                                    Err(e) => error.set(Some(e)),
                                }
                            },
                            if *joining.read() { "Joining..." } else { "Join" }
                        }
                        if *joining.read() && !*timed_out.read() {
                            p { class: "text-xs text-text-muted mt-3",
                                "Fetching the board state. You will be taken there as soon as it arrives."
                            }
                        }
                        if *timed_out.read() {
                            div { class: "mt-3 space-y-2",
                                p { class: "text-sm text-amber-400",
                                    "The board did not arrive from your Freenet node. Check that the node has peers, then retry."
                                }
                                p { class: "text-xs text-text-muted",
                                    "Node dashboard: 127.0.0.1:7509 · version and peer count are on the home page."
                                }
                                button {
                                    r#type: "button",
                                    class: "px-3 py-2 text-sm rounded-md bg-surface hover:bg-surface-hover text-text",
                                    onclick: move |_| {
                                        joining.set(false);
                                        timed_out.set(false);
                                        error.set(Some("Retry: enter the nickname and press Join again.".to_string()));
                                    },
                                    "Retry"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
