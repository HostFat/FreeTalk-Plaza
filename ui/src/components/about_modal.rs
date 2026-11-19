//! "About FreeTalk Plaza" panel: name, what the app is, and the build/deployment
//! details a user needs when reporting a problem.

use crate::components::app::{ABOUT_MODAL, BOARDS, CURRENT_BOARD};
use crate::util::ecies::unseal_bytes_with_secrets;
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

fn board_display_name(board: &crate::board_data::BoardData) -> String {
    unseal_bytes_with_secrets(
        &board.board_state.configuration.configuration.display.name,
        &board.secrets,
    )
    .ok()
    .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
    .filter(|name| !name.trim().is_empty())
    .unwrap_or_else(|| {
        format!(
            "{}…",
            bs58::encode(board.owner_vk.as_bytes())
                .into_string()
                .chars()
                .take(8)
                .collect::<String>()
        )
    })
}

/// Board names where this profile is the posting identity on this device.
fn profile_boards(profile: &crate::board_data::IdentityProfile) -> Vec<String> {
    let profiles_key = profile.signing_key.verifying_key();
    BOARDS
        .read()
        .map
        .values()
        .filter(|board| board.self_sk.verifying_key() == profiles_key)
        .map(board_display_name)
        .collect()
}

/// Whether the profile can be selected on the board that is open now.
fn switch_state(profile: &crate::board_data::IdentityProfile) -> (bool, bool) {
    let Some(current) = CURRENT_BOARD.read().owner_key else {
        return (false, false);
    };
    let boards = BOARDS.read();
    let Some(board) = boards.map.get(&current) else {
        return (false, false);
    };
    let vk = profile.signing_key.verifying_key();
    let is_current = board.self_sk.verifying_key() == vk;
    let is_member = board
        .board_state
        .members
        .members
        .iter()
        .any(|member| {
            member.member.member_vk == vk
                && !board
                    .board_state
                    .ownership
                    .is_deactivated_now(&member.member.id())
        });
    (is_member && !is_current, is_current)
}

/// Read one selected file and merge it into the local store, then reload.
async fn restore_file(file: web_sys::File) {
    let Ok(buffer) = wasm_bindgen_futures::JsFuture::from(file.array_buffer()).await else {
        crate::components::app::toasts::show_error("Could not read the backup file.");
        return;
    };
    let bytes = js_sys::Uint8Array::new(&buffer).to_vec();
    use std::sync::atomic::Ordering;
    crate::components::app::chat_delegate::IMPORT_IN_PROGRESS
        .store(true, Ordering::SeqCst);
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
            crate::components::app::chat_delegate::IMPORT_IN_PROGRESS
                .store(false, Ordering::SeqCst);
            crate::components::app::toasts::show_error(format!(
                "Could not restore: {error}"
            ));
        }
    }
}

fn persist_and_reload() {
    crate::util::safe_spawn_local(async {
        if let Err(error) =
            crate::components::app::chat_delegate::save_boards_and_wait().await
        {
            crate::components::app::toasts::show_error(format!(
                "Could not save the new identity: {error}"
            ));
            return;
        }
        if let Some(window) = web_sys::window() {
            let _ = window.location().reload();
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
                        p { class: "text-xs",
                            "Two different profiles cannot be merged: merging would link their keys and defeat the separation. To use one identity on another board, join or rejoin that board with it."
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
                                    div { class: "w-full text-[10px] text-text-muted",
                                        {
                                            let boards = profile_boards(&profile);
                                            if boards.is_empty() {
                                                "Not used by any board on this device.".to_string()
                                            } else {
                                                format!("Used by: {}", boards.join(", "))
                                            }
                                        }
                                    }
                                    if switch_state(&profile).0 {
                                        button {
                                            r#type: "button",
                                            class: "px-2 py-1 bg-accent/20 hover:bg-accent/30 text-accent text-xs rounded",
                                            onclick: {
                                                let key = profile.signing_key.clone();
                                                move |_| {
                                                    let current = CURRENT_BOARD.read().owner_key;
                                                    let switched = current.is_some_and(|current| {
                                                        BOARDS.with_mut(|boards| {
                                                            boards
                                                                .map
                                                                .get_mut(&current)
                                                                .is_some_and(|board| {
                                                                    board
                                                                        .switch_profile(&key)
                                                                        .is_ok()
                                                                })
                                                        })
                                                    });
                                                    if switched {
                                                        persist_and_reload();
                                                    } else {
                                                        crate::components::app::toasts::show_error(
                                                            "Could not switch to that profile on this board.",
                                                        );
                                                    }
                                                }
                                            },
                                            "Use on this board"
                                        }
                                    }
                                    if switch_state(&profile).1 {
                                        span { class: "text-[10px] text-accent", "current here" }
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
                    details { class: "border-t border-border pt-3",
                        summary { class: "text-sm text-text cursor-pointer",
                            "Contract versions and rekey"
                        }
                        div { class: "mt-2 space-y-2 text-xs text-text-muted",
                            p {
                                "The app bundle and each board contract are separate. A new build updates the web container state, so the site id above stays the same while the version and commit change."
                            }
                            ul { class: "list-disc pl-4 space-y-1",
                                li {
                                    "A board contract key comes from its wasm plus the board owner. Changing the board contract creates a new key; this client records the migration and the owner sends a signed upgrade pointer to the old contract."
                                }
                                li {
                                    "Profile and owner keys are local and are not part of the contract key, so they survive a rekey."
                                }
                                li {
                                    "Download a backup before deploying. After deploying, open the app once as the owner, let the sync chip settle, and check that the board opens from the new key."
                                }
                            }
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
                                    // Selection only; "Restore now" applies it.
                                    // Importing on change made a second attempt
                                    // impossible and raced the button.
                                }
                                "Restore backup"
                            }
                            button {
                                r#type: "button",
                                class: "px-3 py-1.5 bg-accent hover:bg-accent-hover text-white text-xs rounded-lg transition-colors",
                                onclick: move |_| {
                                    wasm_bindgen_futures::spawn_local(async move {
                                        match crate::util::backup::selected_file() {
                                            Some(file) => restore_file(file).await,
                                            None => crate::components::app::toasts::show_error(
                                                "Choose a backup file first.",
                                            ),
                                        }
                                    });
                                },
                                "Restore now"
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
                        title: "Test only: hides owner and admin controls in this tab until reload",
                        onclick: move |_| {
                            *crate::components::app::TEST_VIEW_MEMBER.write() = true;
                            *ABOUT_MODAL.write() = false;
                        },
                        "Test member view"
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
