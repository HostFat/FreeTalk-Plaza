//! Small reusable reason picker for hide, purge and illegal purge.

use dioxus::prelude::*;

const PRESETS: &[(&str, &str)] = &[
    ("illegal", "Severe rule violation"),
    ("spam", "Spam"),
    ("harassment", "Harassment"),
    ("off_topic", "Off-topic"),
    ("rules", "Other rule violation"),
];

#[component]
pub fn ReasonDialog(
    open: Signal<bool>,
    title: String,
    on_confirm: EventHandler<(String, String)>,
    /// When set, the user must type this word to confirm.
    #[props(default)]
    confirm_word: Option<String>,
) -> Element {
    let mut selected = use_signal(|| PRESETS[0].0.to_string());
    let mut custom = use_signal(String::new);
    let mut typed = use_signal(String::new);
    let mut mismatch = use_signal(|| false);
    let reason = custom.read().trim().to_string();
    let final_reason = if reason.is_empty() {
        selected.read().clone()
    } else {
        reason
    };

    rsx! {
        if *open.read() {
        div {
            class: "fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 pointer-events-auto",
            div { class: "w-full max-w-md bg-panel border border-border rounded-xl shadow-xl p-4 space-y-3 pointer-events-auto",
                h2 { class: "text-lg font-semibold text-text", "{title}" }
                div { class: "flex flex-wrap gap-2",
                    for (code, label) in PRESETS {
                        button {
                            r#type: "button",
                            class: if selected.read().as_str() == *code {
                                "px-3 py-1.5 text-xs rounded-md bg-accent text-white"
                            } else {
                                "px-3 py-1.5 text-xs rounded-md bg-surface hover:bg-surface-hover text-text"
                            },
                            onclick: move |_| {
                                selected.set(code.to_string());
                                custom.set(String::new());
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
                if let Some(word) = confirm_word.as_ref() {
                    div { class: "space-y-1",
                        p { class: "text-xs text-text-muted", "Type {word} to confirm this large action." }
                        input {
                            class: "w-full bg-panel border border-border rounded-md px-3 py-2 text-sm text-text",
                            value: "{typed}",
                            oninput: move |event| {
                                typed.set(event.value());
                                mismatch.set(false);
                            },
                        }
                        if *mismatch.read() {
                            p { class: "text-xs text-red-400", "The confirmation word does not match." }
                        }
                    }
                }
                div { class: "flex justify-end gap-2",
                    button {
                        r#type: "button",
                        class: "px-3 py-2 text-sm rounded-md bg-surface hover:bg-surface-hover text-text",
                        onclick: move |_| open.set(false),
                        onmousedown: move |_| open.set(false),
                        "Cancel"
                    }
                    button {
                        r#type: "button",
                        class: "px-3 py-2 text-sm rounded-md bg-red-600 hover:bg-red-500 text-white",
                        onmousedown: {
                            let confirm_word = confirm_word.clone();
                            move |_| {
                            if let Some(word) = confirm_word.as_ref() {
                                if typed.read().trim() != word {
                                    mismatch.set(true);
                                    return;
                                }
                            }
                            on_confirm.call((selected.read().clone(), final_reason.clone()));
                            open.set(false);
                            }
                        },
                        "Confirm"
                    }
                }
            }
        }
        }
    }
}
