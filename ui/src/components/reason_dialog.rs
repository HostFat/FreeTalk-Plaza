//! Small reusable reason picker for hide, purge and illegal purge.

use dioxus::prelude::*;

const PRESETS: &[&str] = &[
    "Illegal content",
    "Spam",
    "Harassment",
    "Off-topic",
    "Rules violation",
];

#[component]
pub fn ReasonDialog(
    open: Signal<bool>,
    title: String,
    on_confirm: EventHandler<String>,
) -> Element {
    let mut selected = use_signal(|| PRESETS[0].to_string());
    let mut custom = use_signal(String::new);
    if !*open.read() {
        return rsx! {};
    }

    let reason = custom.read().trim().to_string();
    let final_reason = if reason.is_empty() {
        selected.read().clone()
    } else {
        reason
    };

    rsx! {
        div {
            class: "fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4",
            div { class: "w-full max-w-md bg-panel border border-border rounded-xl shadow-xl p-4 space-y-3",
                h2 { class: "text-lg font-semibold text-text", "{title}" }
                div { class: "flex flex-wrap gap-2",
                    for preset in PRESETS {
                        button {
                            r#type: "button",
                            class: if selected.read().as_str() == *preset {
                                "px-3 py-1.5 text-xs rounded-md bg-accent text-white"
                            } else {
                                "px-3 py-1.5 text-xs rounded-md bg-surface hover:bg-surface-hover text-text"
                            },
                            onclick: move |_| {
                                selected.set(preset.to_string());
                                custom.set(String::new());
                            },
                            "{preset}"
                        }
                    }
                }
                textarea {
                    class: "w-full min-h-20 bg-panel border border-border rounded-md px-3 py-2 text-sm text-text",
                    placeholder: "Optional details",
                    value: "{custom}",
                    oninput: move |event| custom.set(event.value()),
                }
                div { class: "flex justify-end gap-2",
                    button {
                        r#type: "button",
                        class: "px-3 py-2 text-sm rounded-md bg-surface hover:bg-surface-hover text-text",
                        onclick: move |_| open.set(false),
                        "Cancel"
                    }
                    button {
                        r#type: "button",
                        class: "px-3 py-2 text-sm rounded-md bg-red-600 hover:bg-red-500 text-white",
                        onclick: move |_| {
                            on_confirm.call(final_reason.clone());
                            open.set(false);
                        },
                        "Confirm"
                    }
                }
            }
        }
    }
}
