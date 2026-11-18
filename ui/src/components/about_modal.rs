//! "About FreeTalk Plaza" panel: name, what the app is, and the build/deployment
//! details a user needs when reporting a problem.

use crate::components::app::{ABOUT_MODAL, BOARDS};
use dioxus::prelude::*;
use web_sys::window;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const BUILD_TIMESTAMP: &str = env!("BUILD_TIMESTAMP_ISO");
const COMMIT: &str = env!("GIT_COMMIT_HASH");
const COMMIT_COUNT: &str = env!("GIT_COMMIT_COUNT");
const COMMIT_DATE: &str = env!("GIT_COMMIT_DATE");

/// `id` of the web-container contract when the app is served by a Freenet node,
/// i.e. from `/v1/contract/web/<id>/...`; `None` for a local dev build.
fn site_contract_id() -> Option<String> {
    let path = window()?.location().pathname().ok()?;
    let rest = path.split("/v1/contract/web/").nth(1)?;
    let id: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric())
        .collect();
    if id.is_empty() {
        None
    } else {
        Some(id)
    }
}

/// Profile edits are local state; write them before a reload can drop them.
fn persist_profiles() {
    crate::util::safe_spawn_local(async {
        if let Err(error) =
            crate::components::app::chat_delegate::save_boards_and_wait().await
        {
            crate::components::app::toasts::show_error(format!(
                "Could not save the profile: {error}"
            ));
        }
    });
}

#[component]
pub fn AboutModal() -> Element {
    if !*ABOUT_MODAL.read() {
        return rsx! {};
    }

    let node = window()
        .and_then(|w| w.location().host().ok())
        .unwrap_or_else(|| "unknown".to_string());
    let site = site_contract_id();
    let site_label = site.clone().unwrap_or_else(|| "local".to_string());
    let mut renaming = use_signal(|| None::<String>);
    let mut rename_text = use_signal(String::new);

    rsx! {
        div {
            class: "fixed inset-0 z-50 flex items-center justify-center p-4",
            tabindex: "0",
            onkeydown: move |evt: KeyboardEvent| {
                if evt.key() == Key::Escape {
                    evt.prevent_default();
                    *ABOUT_MODAL.write() = false;
                }
            },
            div {
                class: "absolute inset-0 bg-black/50",
                onclick: move |_| *ABOUT_MODAL.write() = false,
            }
            div {
                class: "relative bg-panel rounded-xl shadow-xl max-w-md w-full",
                onclick: move |e| e.stop_propagation(),

                div { class: "flex items-center gap-3 px-6 py-5 border-b border-border",
                    img {
                        src: asset!("/assets/plaza_logo.svg"),
                        class: "w-12 h-12",
                        alt: "",
                    }
                    div { class: "flex flex-col",
                        span { class: "text-lg font-semibold text-text", "FreeTalk Plaza" }
                        span { class: "text-xs tracking-wide text-text-muted",
                            "Forums on Freenet"
                        }
                    }
                }

                div { class: "px-6 py-5 space-y-3 text-sm text-text-muted",
                    p { "Boards, categories, topics and posts live in Freenet contracts, so no server holds them and no account is needed." }
                    p { class: "text-amber-200",
                        "Development preview: things can break and data can be lost without notice. Do not rely on it for long-term content."
                    }
                    dl { class: "grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 font-mono text-xs",
                        dt { class: "text-text-muted", "Version" }
                        dd { class: "text-text", "{VERSION}" }
                        dt { class: "text-text-muted", "Build" }
                        dd { class: "text-text", "#{COMMIT_COUNT} · {COMMIT} · {COMMIT_DATE}" }
                        dt { class: "text-text-muted", "Built" }
                        dd { class: "text-text", "{BUILD_TIMESTAMP}" }
                        dt { class: "text-text-muted", "Node" }
                        dd { class: "text-text break-all", "{node}" }
                        if let Some(site) = site {
                            dt { class: "text-text-muted", "Site" }
                            dd { class: "text-text break-all", "{site}" }
                        }
                    }
                    p { class: "text-xs",
                        "To check whether this site is current, compare the commit above with the latest commit in the repository."
                    }
                    div { class: "border-t border-border pt-3 space-y-2",
                        p { class: "text-sm text-text", "Your identities" }
                        p { class: "text-xs",
                            "A profile is a local key. Reusing it on several boards shows the same member id on each; a separate profile keeps them unlinked. Keys never leave this device."
                        }
                        for profile in BOARDS.read().profiles.clone() {
                            div { key: "{profile.id}", class: "flex items-center gap-2 flex-wrap",
                                if renaming.read().as_deref() == Some(profile.id.as_str()) {
                                    input {
                                        class: "flex-1 min-w-24 px-2 py-1 bg-surface border border-border rounded text-text text-xs",
                                        dir: "auto",
                                        value: "{rename_text}",
                                        oninput: move |evt| rename_text.set(evt.value()),
                                    }
                                    button {
                                        r#type: "button",
                                        class: "px-2 py-1 bg-accent text-white text-xs rounded",
                                        onclick: {
                                            let id = profile.id.clone();
                                            move |_| {
                                                let name = rename_text.read().trim().to_string();
                                                if !name.is_empty() {
                                                    BOARDS.with_mut(|boards| {
                                                        boards.rename_profile(&id, name)
                                                    });
                                                    persist_profiles();
                                                }
                                                renaming.set(None);
                                            }
                                        },
                                        "Save"
                                    }
                                    button {
                                        r#type: "button",
                                        class: "px-2 py-1 bg-surface text-text text-xs rounded",
                                        onclick: move |_| renaming.set(None),
                                        "Cancel"
                                    }
                                } else {
                                    span { class: "text-text text-xs", "{profile.name}" }
                                    span { class: "text-text-muted text-[10px] font-mono",
                                        "{profile.id.chars().take(8).collect::<String>()}"
                                    }
                                    button {
                                        r#type: "button",
                                        class: "px-2 py-1 bg-surface hover:bg-surface-hover text-text text-xs rounded",
                                        onclick: {
                                            let id = profile.id.clone();
                                            let name = profile.name.clone();
                                            move |_| {
                                                rename_text.set(name.clone());
                                                renaming.set(Some(id.clone()));
                                            }
                                        },
                                        "Rename"
                                    }
                                    button {
                                        r#type: "button",
                                        class: "px-2 py-1 bg-surface hover:bg-surface-hover text-text-muted text-xs rounded",
                                        onclick: {
                                            let id = profile.id.clone();
                                            move |_| {
                                                BOARDS.with_mut(|boards| boards.forget_profile(&id));
                                                persist_profiles();
                                            }
                                        },
                                        "Forget"
                                    }
                                }
                            }
                        }
                        if BOARDS.read().profiles.is_empty() {
                            p { class: "text-xs", "No profiles yet. Create one with a board or an invite." }
                        }
                    }
                    div { class: "border-t border-border pt-3 space-y-2",
                        p { class: "text-xs",
                            "A backup contains the identities, private-board secrets, drafts and settings stored on this device. Board content stays on Freenet; uploaded image bytes and composer queues are not included. Keep it private."
                        }
                        div { class: "flex flex-wrap gap-2",
                            button {
                                r#type: "button",
                                class: "px-3 py-1.5 bg-surface hover:bg-surface-hover text-text text-xs rounded-lg transition-colors",
                                onclick: move |_| match crate::util::backup::download() {
                                    Ok(()) => crate::components::app::toasts::show(
                                        "Backup downloaded.",
                                    ),
                                    Err(error) => crate::components::app::toasts::show_error(format!(
                                        "Could not create the backup: {error}"
                                    )),
                                },
                                "Download backup"
                            }
                            label {
                                class: "flex flex-col gap-1 text-xs text-text-muted",
                                span { "Restore backup" }
                                input {
                                    id: "plaza-backup-file",
                                    r#type: "file",
                                    accept: ".cbor",
                                    class: "block w-full text-xs text-text-muted",
                                    onchange: move |_| {
                                        wasm_bindgen_futures::spawn_local(async move {
                                            let Some(file) = crate::util::backup::selected_file() else {
                                                return;
                                            };
                                            let Ok(buffer) = wasm_bindgen_futures::JsFuture::from(
                                                file.array_buffer(),
                                            )
                                            .await
                                            else {
                                                crate::components::app::toasts::show_error(
                                                    "Could not read the backup file.",
                                                );
                                                return;
                                            };
                                            let bytes = js_sys::Uint8Array::new(&buffer).to_vec();
                                            match crate::util::backup::import_bytes(&bytes).await {
                                                Ok(count) => {
                                                    crate::components::app::toasts::show(format!(
                                                        "Restored {count} board(s). Reloading…"
                                                    ));
                                                    crate::util::sleep(std::time::Duration::from_millis(800)).await;
                                                    if let Some(window) = window() {
                                                        let _ = window.location().reload();
                                                    }
                                                }
                                                Err(error) => {
                                                    crate::components::app::toasts::show_error(format!(
                                                        "Could not restore: {error}"
                                                    ));
                                                }
                                            }
                                        });
                                    },
                                }
                                "Restore backup"
                            }
                        }
                    }
                    p { class: "text-xs",
                        "Source code: "
                        a {
                            href: "https://github.com/HostFat/FreeTalk-Plaza",
                            target: "_blank",
                            rel: "noopener noreferrer",
                            class: "text-accent hover:underline break-all",
                            "github.com/HostFat/FreeTalk-Plaza"
                        }
                    }
                }

                div { class: "px-6 py-4 border-t border-border flex items-center justify-between gap-3",
                    button {
                        class: "px-4 py-2 bg-surface hover:bg-surface-hover text-text text-sm rounded-lg transition-colors",
                        onclick: move |_| {
                            let details = format!(
                                "FreeTalk Plaza {VERSION}\nBuild #{COMMIT_COUNT} · {COMMIT} · {COMMIT_DATE}\nBuilt {BUILD_TIMESTAMP}\nNode {node}\nSite {site_label}"
                            );
                            crate::util::copy_to_clipboard(&details);
                        },
                        "Copy details"
                    }
                    button {
                        class: "px-4 py-2 bg-surface hover:bg-surface-hover text-text text-sm rounded-lg transition-colors",
                        onclick: move |_| *ABOUT_MODAL.write() = false,
                        "Close"
                    }
                }
            }
        }
    }
}
