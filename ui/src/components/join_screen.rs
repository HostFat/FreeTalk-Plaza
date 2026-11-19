//! Screen for opening a reusable invite link.

use crate::components::app::{Route, BOARDS};
use crate::util::access::JoinLink;
use dioxus::prelude::*;
use wasm_bindgen::JsCast;

#[component]
pub fn JoinScreen(token: String) -> Element {
    let decoded = use_memo(move || JoinLink::decode(&token));
    let decoded_value = decoded.read().clone();
    let mut nickname = use_signal(String::new);
    let mut selected_profile = use_signal(|| 0usize);
    // The board's privacy is unknown before joining, so a separate identity is
    // the safe default. Unchecking links this board to the profile's others.
    let mut separate_identity = use_signal(|| true);
    let mut error = use_signal(|| None::<String>);
    let mut joining = use_signal(|| false);
    let mut joined = use_signal(|| false);
    let mut timed_out = use_signal(|| false);
    let mut pasted_link = use_signal(String::new);
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
        Err(e) => {
            let typed = pasted_link.read().clone();
            rsx! {
                div { class: "flex-1 flex items-center justify-center",
                    div { class: "bg-panel border border-border rounded-xl p-6 max-w-md w-full",
                        h1 { class: "text-xl font-semibold text-text mb-1", "This invite link did not work" }
                        p { class: "text-sm text-text-muted mb-4", "{e}" }
                        label { class: "block text-sm font-medium text-text mb-1",
                            "Paste the invite link again"
                        }
                        textarea {
                            id: "invite-recovery-input",
                            class: "w-full h-24 px-3 py-2 bg-surface border border-border rounded-lg text-xs font-mono text-text resize-none",
                            placeholder: "https://…/#/join/…",
                            value: "{typed}",
                            oninput: move |evt| pasted_link.set(evt.value()),
                        }
                        div { class: "flex gap-2 mt-3",
                            button {
                                r#type: "button",
                                class: "flex-1 px-4 py-2 bg-accent hover:bg-accent/80 text-white rounded-lg disabled:opacity-50",
                                disabled: typed.trim().is_empty(),
                                onclick: move |_| {
                                    // Read the field itself: this screen exists
                                    // because the original link failed, so a
                                    // stale signal must not block the retry.
                                    let value = web_sys::window()
                                        .and_then(|window| window.document())
                                        .and_then(|document| {
                                            document.get_element_by_id("invite-recovery-input")
                                        })
                                        .and_then(|element| {
                                            element.dyn_into::<web_sys::HtmlTextAreaElement>().ok()
                                        })
                                        .map(|element| element.value())
                                        .unwrap_or_default();
                                    let token = crate::util::access::token_from_input(&value);
                                    if token.is_empty() {
                                        return;
                                    }
                                    // A hash-router push to the same route with a
                                    // different token does not re-render here, so
                                    // have the shell load the frame at the new URL.
                                    let base = web_sys::window()
                                        .and_then(|window| window.location().href().ok())
                                        .map(|href| {
                                            href.split('#').next().unwrap_or("").to_string()
                                        })
                                        .unwrap_or_default();
                                    if base.is_empty() {
                                        return;
                                    }
                                    let href = format!("{base}#/join/{token}");
                                    if !crate::util::navigate_in_shell(&href) {
                                        // Outside the gateway shell there is no
                                        // auth bootstrap to lose: reload locally.
                                        if let Some(window) = web_sys::window() {
                                            let location = window.location();
                                            let _ =
                                                location.set_hash(&format!("/join/{token}"));
                                            let _ = location.reload();
                                        }
                                    }
                                },
                                "Open link"
                            }
                            button {
                                r#type: "button",
                                class: "px-4 py-2 bg-surface hover:bg-surface-hover text-text rounded-lg",
                                onclick: move |_| { navigator().push(Route::Home); },
                                "Home"
                            }
                        }
                    }
                }
            }
        }
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
                                    option { value: "{index + 1}", "{profile.name}" }
                                }
                            }
                            if *selected_profile.read() > 0 {
                                label { class: "flex items-start gap-3 cursor-pointer mb-2",
                                    input {
                                        r#type: "checkbox",
                                        class: "mt-0.5 w-4 h-4 rounded border-border text-accent focus:ring-accent/50",
                                        checked: *separate_identity.read(),
                                        onchange: move |evt| separate_identity.set(evt.checked()),
                                    }
                                    div { class: "flex flex-col",
                                        span { class: "text-sm text-text",
                                            "Use a separate identity on this board (recommended for private boards)"
                                        }
                                        span { class: "text-xs text-text-muted",
                                            "A key derived from the profile signs here, so this board's member id cannot be linked to your other boards. Uncheck only when this is a public board where you want the same identity."
                                        }
                                    }
                                }
                            }
                            p { class: "text-xs text-text-muted mb-3",
                                "The board's privacy is not known before you join, so the separate identity is the safe default. A new identity is unlinkable. Note that the same nickname on a public board can still link you, and your node, IP address, timing and device can correlate activity."
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
                                let selected = {
                                    let index = *selected_profile.read();
                                    profiles
                                        .read()
                                        .get(index.saturating_sub(1))
                                        .filter(|_| index > 0)
                                        .cloned()
                                };
                                match crate::util::access::join_with_token(
                                    &link,
                                    nickname.read().clone(),
                                    selected,
                                    *separate_identity.read(),
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
