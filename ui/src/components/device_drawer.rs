//! "This device" drawer: the identities stored by this browser and the local
//! backup. About stays informational; these are actions on device data.

use crate::components::app::{BOARDS, CURRENT_BOARD};
use crate::util::ecies::unseal_bytes_with_secrets;
use crate::util::mail::{self, MailVisibility};
use crate::util::message_actions::ActionContext;
use dioxus::logger::tracing::warn;
use dioxus::prelude::*;
use plaza_core::board_state::member::MemberId;
use web_sys::window;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DeviceTab {
    Identities,
    Mail,
    Backup,
}

pub static DEVICE_DRAWER: GlobalSignal<Option<DeviceTab>> = Global::new(|| None);

pub fn open(tab: DeviceTab) {
    *DEVICE_DRAWER.write() = Some(tab);
}

pub fn close() {
    *DEVICE_DRAWER.write() = None;
}

/// Profile edits are local state; write them before a reload can drop them.
fn persist_profiles() {
    crate::util::safe_spawn_local(async {
        if let Err(error) = crate::components::app::chat_delegate::save_boards_and_wait().await {
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

/// Boards where this profile is the posting identity on this device: name,
/// whether the board is private, and whether a derived key signs there.
fn profile_boards(profile: &crate::board_data::IdentityProfile) -> Vec<(String, bool, bool)> {
    let boards = BOARDS.read();
    let linkability = boards.profile_linkability(profile);
    let mut rows = Vec::new();
    for key in &linkability.public_boards {
        if let Some(board) = boards.map.get(key) {
            rows.push((board_display_name(board), false, false));
        }
    }
    for key in &linkability.private_boards {
        if let Some(board) = boards.map.get(key) {
            rows.push((board_display_name(board), true, false));
        }
    }
    for key in &linkability.derived_boards {
        if let Some(board) = boards.map.get(key) {
            rows.push((board_display_name(board), true, true));
        }
    }
    rows
}

/// Whether forgetting this profile would remove the root key that a board
/// relies on for future derivations.
fn profile_is_a_board_root(id: &str) -> bool {
    let boards = BOARDS.read();
    boards.map.values().any(|board| {
        boards
            .profile_for_board(board)
            .is_some_and(|profile| profile.id == id)
    })
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
    let is_owner = board.owner_vk == vk;
    let is_member = board.board_state.members.members.iter().any(|member| {
        member.member.member_vk == vk
            && !board
                .board_state
                .ownership
                .is_deactivated_now(&member.member.id())
    });
    ((is_owner || is_member) && !is_current, is_current)
}

/// Read one selected file and merge it into the local store, then reload.
async fn restore_file(file: web_sys::File) {
    let Ok(buffer) = wasm_bindgen_futures::JsFuture::from(file.array_buffer()).await else {
        crate::components::app::toasts::show_error("Could not read the backup file.");
        return;
    };
    let bytes = js_sys::Uint8Array::new(&buffer).to_vec();
    use std::sync::atomic::Ordering;
    crate::components::app::chat_delegate::IMPORT_IN_PROGRESS.store(true, Ordering::SeqCst);
    match crate::util::backup::import_bytes(&bytes).await {
        Ok(count) => {
            crate::components::app::toasts::show(format!("Restored {count} board(s). Reloading…"));
            crate::util::sleep(std::time::Duration::from_millis(800)).await;
            if let Some(window) = window() {
                let _ = window.location().reload();
            }
        }
        Err(error) => {
            crate::components::app::chat_delegate::IMPORT_IN_PROGRESS
                .store(false, Ordering::SeqCst);
            crate::components::app::toasts::show_error(format!("Could not restore: {error}"));
        }
    }
}

fn persist_and_reload() {
    crate::util::safe_spawn_local(async {
        if let Err(error) = crate::components::app::chat_delegate::save_boards_and_wait().await {
            crate::components::app::toasts::show_error(format!(
                "Could not save the new identity: {error}"
            ));
            return;
        }
        // Stay on the board. Reloading here raced the delegate load and left
        // the board on "Loading board…"; the in-memory signals already carry
        // the new identity.
        // The DM identity follows the active profile; initialize it before the
        // switch completes so a join link opened right after uses this profile.
        if let Err(error) =
            crate::components::app::dm_delegate::ensure_identity_after_profile_switch().await
        {
            warn!("Could not initialize the DM identity for the new profile: {error}");
        }
        crate::components::app::toasts::show("Identity switched.");
        close();
    });
}

fn tab_class(active: bool) -> &'static str {
    if active {
        "flex-1 px-3 py-2 rounded-lg bg-accent text-white text-sm font-medium transition-colors"
    } else {
        "flex-1 px-3 py-2 rounded-lg bg-surface hover:bg-surface-hover text-text-muted text-sm font-medium transition-colors"
    }
}

#[component]
pub fn DeviceDrawer() -> Element {
    let mut renaming = use_signal(|| None::<String>);
    let mut rename_text = use_signal(String::new);
    let mut forget_confirm = use_signal(|| None::<String>);
    let mut backup_name = use_signal(|| None::<String>);
    let mut backup_error = use_signal(|| None::<String>);

    let Some(active) = *DEVICE_DRAWER.read() else {
        return rsx! {};
    };

    let mut dismiss = move || {
        renaming.set(None);
        forget_confirm.set(None);
        backup_error.set(None);
        close();
    };

    let mail_profile_id = {
        let boards = BOARDS.read();
        let current = CURRENT_BOARD.read().owner_key;
        current
            .and_then(|key| boards.map.get(&key))
            .and_then(|board| boards.profile_for_board(board))
            .map(|profile| profile.id.clone())
    };

    rsx! {
        div {
            class: "fixed inset-0 z-50 bg-black/50",
            onclick: move |_| dismiss(),
        }
        div {
            class: "device-drawer fixed inset-y-0 right-0 z-50 w-full sm:max-w-xl bg-bg shadow-2xl flex flex-col",
            role: "dialog",
            aria_modal: "true",
            aria_label: "This device",
            tabindex: "0",
            onkeydown: move |evt: KeyboardEvent| {
                if evt.key() == Key::Escape {
                    evt.prevent_default();
                    dismiss();
                }
            },
            onclick: move |event| event.stop_propagation(),

            div { class: "flex items-start justify-between gap-4 px-5 py-4 border-b border-border",
                div { class: "min-w-0",
                    h2 { class: "text-lg font-semibold text-text", "This device" }
                    p { class: "text-xs text-text-muted mt-0.5",
                        "Identities, Freenet Mail and backups stored by this browser."
                    }
                }
                button {
                    r#type: "button",
                    class: "px-3 py-1.5 bg-surface hover:bg-surface-hover text-text text-xs rounded-lg transition-colors",
                    aria_label: "Close",
                    onclick: move |_| dismiss(),
                    "Close"
                }
            }

            div { class: "flex gap-2 px-5 py-3 border-b border-border", role: "tablist",
                button {
                    r#type: "button",
                    role: "tab",
                    aria_selected: if active == DeviceTab::Identities { "true" } else { "false" },
                    class: tab_class(active == DeviceTab::Identities),
                    onclick: move |_| open(DeviceTab::Identities),
                    "Identities"
                }
                button {
                    r#type: "button",
                    role: "tab",
                    aria_selected: if active == DeviceTab::Mail { "true" } else { "false" },
                    class: tab_class(active == DeviceTab::Mail),
                    onclick: move |_| open(DeviceTab::Mail),
                    "Mail"
                }
                button {
                    r#type: "button",
                    role: "tab",
                    aria_selected: if active == DeviceTab::Backup { "true" } else { "false" },
                    class: tab_class(active == DeviceTab::Backup),
                    onclick: move |_| open(DeviceTab::Backup),
                    "Backup"
                }
            }

            div { class: "flex-1 min-h-0 overflow-y-auto px-5 py-4",
                match active {
                    DeviceTab::Identities => rsx! {
                        section { class: "space-y-4",
                            div { class: "rounded-xl border border-border bg-panel p-4 space-y-2",
                                h3 { class: "text-sm font-semibold text-text", "Your identities" }
                                p { class: "text-xs text-text-muted",
                                    "A profile is a local key. Reusing it on several boards shows the same member on each; a separate profile keeps the boards unlinked."
                                }
                                details { class: "text-xs text-text-muted",
                                    summary { class: "cursor-pointer text-text", "How links work" }
                                    div { class: "mt-2 space-y-2",
                                        p {
                                            "Two different profiles cannot be merged: merging would link their keys and defeat the separation. To use one identity on another board, join or rejoin that board with it."
                                        }
                                        p {
                                            "Keys and nicknames are separate: the same nickname on two boards can still link you even when the keys differ. On a private board a derived key keeps the key link hidden."
                                        }
                                    }
                                }
                            }

                            for profile in BOARDS.read().profiles.clone() {
                                div {
                                    key: "{profile.id}",
                                    class: "profile-row rounded-xl border border-border bg-panel p-4 space-y-3",
                                    div { class: "flex items-start justify-between gap-3",
                                        div { class: "min-w-0",
                                            div { class: "flex items-center gap-2 flex-wrap",
                                                span { class: "text-sm font-medium text-text", "{profile.name}" }
                                                span { class: "text-text-muted text-[10px] font-mono",
                                                    "{profile.id.chars().take(8).collect::<String>()}"
                                                }
                                                if switch_state(&profile).1 {
                                                    span { class: "text-[10px] text-accent", "current here" }
                                                }
                                            }
                                            div { class: "text-[11px] text-text-muted mt-1",
                                                {
                                                    let rows = profile_boards(&profile);
                                                    if rows.is_empty() {
                                                        "Not used by any board on this device.".to_string()
                                                    } else {
                                                        let boards = rows
                                                            .iter()
                                                            .map(|(name, private, derived)| {
                                                                let kind =
                                                                    if *private { "private" } else { "public" };
                                                                let mode = if *derived {
                                                                    ", derived here"
                                                                } else {
                                                                    ", same identity here"
                                                                };
                                                                format!("{name} ({kind}{mode})")
                                                            })
                                                            .collect::<Vec<_>>()
                                                            .join(", ");
                                                        format!("Used by: {boards}")
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    if BOARDS.read().profile_linkability(&profile).linked_across {
                                        p { class: "text-[11px] text-amber-300",
                                            "This profile links public and private boards."
                                        }
                                    }
                                    if forget_confirm.read().as_deref()
                                        == Some(profile.id.as_str())
                                    {
                                        p { class: "text-[11px] text-amber-300",
                                            "Boards that used this profile keep working, but no new derivation from it is possible. Press Forget again to confirm."
                                        }
                                    }

                                    if renaming.read().as_deref() == Some(profile.id.as_str()) {
                                        div { class: "flex items-center gap-2",
                                            input {
                                                class: "flex-1 min-w-24 px-2 py-1.5 bg-surface border border-border rounded-lg text-text text-xs",
                                                dir: "auto",
                                                value: "{rename_text}",
                                                oninput: move |evt| rename_text.set(evt.value()),
                                            }
                                            button {
                                                r#type: "button",
                                                class: "px-3 py-1.5 bg-accent text-white text-xs rounded-lg",
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
                                                class: "px-3 py-1.5 bg-surface text-text text-xs rounded-lg",
                                                onclick: move |_| renaming.set(None),
                                                "Cancel"
                                            }
                                        }
                                    } else {
                                        div { class: "flex flex-wrap items-center gap-2",
                                            if switch_state(&profile).0 {
                                                button {
                                                    r#type: "button",
                                                    class: "px-3 py-1.5 bg-accent/20 hover:bg-accent/30 text-accent text-xs rounded-lg",
                                                    onclick: {
                                                        let key = profile.signing_key.clone();
                                                        let profile_id = profile.id.clone();
                                                        move |_| {
                                                            let current = CURRENT_BOARD.read().owner_key;
                                                            let switched = current.is_some_and(|current| {
                                                                BOARDS.with_mut(|boards| {
                                                                    let profile_id = profile_id.clone();
                                                                    boards
                                                                        .map
                                                                        .get_mut(&current)
                                                                        .is_some_and(|board| {
                                                                            if board
                                                                                .switch_profile(&key)
                                                                                .is_err()
                                                                            {
                                                                                return false;
                                                                            }
                                                                            board.profile_id =
                                                                                Some(profile_id);
                                                                            board.backfill_owner_profile();
                                                                            true
                                                                        })
                                                                })
                                                            });
                                                            if switched {
                                                                // The delegate signs every message
                                                                // for this board. Without this update
                                                                // it keeps the previous profile's key
                                                                // and produces signatures the
                                                                // contract rejects.
                                                                if let Some(board_key) = current {
                                                                    let delegate_key = key.clone();
                                                                    wasm_bindgen_futures::spawn_local(
                                                                        async move {
                                                                            let _ = crate::signing::migrate_signing_key(
                                                                                board_key.to_bytes(),
                                                                                &delegate_key,
                                                                            )
                                                                            .await;
                                                                        },
                                                                    );
                                                                }
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
                                            button {
                                                r#type: "button",
                                                class: "px-3 py-1.5 bg-surface hover:bg-surface-hover text-text text-xs rounded-lg",
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
                                                class: "px-3 py-1.5 bg-surface hover:bg-surface-hover text-text-muted text-xs rounded-lg",
                                                onclick: {
                                                    let id = profile.id.clone();
                                                    move |_| {
                                                        if profile_is_a_board_root(&id)
                                                            && forget_confirm.read().as_deref()
                                                                != Some(id.as_str())
                                                        {
                                                            forget_confirm.set(Some(id.clone()));
                                                            return;
                                                        }
                                                        BOARDS.with_mut(|boards| boards.forget_profile(&id));
                                                        forget_confirm.set(None);
                                                        persist_profiles();
                                                    }
                                                },
                                                "Forget"
                                            }
                                        }
                                    }
                                }
                            }

                            if BOARDS.read().profiles.is_empty() {
                                p { class: "text-xs text-text-muted",
                                    "No profiles yet. Create one with a board or an invite."
                                }
                            }

                            div { class: "rounded-xl border border-border bg-panel p-4",
                                label { class: "flex items-start gap-3 text-sm text-text cursor-pointer",
                                    input {
                                        r#type: "checkbox",
                                        class: "mt-0.5",
                                        checked: BOARDS.read().client_features.show_member_ids,
                                        onchange: move |event| {
                                            let show = event.checked();
                                            BOARDS.with_mut(|boards| {
                                                boards.client_features.show_member_ids = show;
                                            });
                                            persist_profiles();
                                        },
                                    }
                                    div { class: "flex flex-col",
                                        span { "Show member IDs in the member list" }
                                        span { class: "text-[11px] text-text-muted",
                                            "Useful when comparing identities across boards."
                                        }
                                    }
                                }
                            }

                            details { class: "rounded-xl border border-border bg-panel p-4",
                                summary { class: "text-sm text-text cursor-pointer", "Developer" }
                                p { class: "text-xs text-text-muted mt-2",
                                    "Local developer controls for this tab."
                                }
                                div { class: "flex flex-wrap gap-2 mt-2",
                                    button {
                                        r#type: "button",
                                        class: "px-3 py-1.5 bg-surface hover:bg-surface-hover text-text text-xs rounded-lg transition-colors",
                                        onclick: move |_| {
                                            *crate::components::app::TEST_VIEW_MEMBER.write() = true;
                                            close();
                                            crate::components::app::toasts::show(
                                                "Member preview enabled. Use Exit preview in the banner to return.",
                                            );
                                        },
                                        "Preview member view"
                                    }
                                    button {
                                        r#type: "button",
                                        class: "px-3 py-1.5 bg-surface hover:bg-surface-hover text-text text-xs rounded-lg transition-colors",
                                        onclick: move |_| {
                                            let Some(window) = window() else { return; };
                                            let confirmed = window
                                                .confirm_with_message(
                                                    "Reset the DM delegate identity, devices and conversation keys on this device?",
                                                )
                                                .ok()
                                                .unwrap_or(false);
                                            if !confirmed {
                                                return;
                                            }
                                            wasm_bindgen_futures::spawn_local(async {
                                                match crate::components::app::dm_delegate::reset().await {
                                                    Ok(()) => crate::components::app::toasts::show(
                                                        "DM delegate reset. Select a board to initialize the active profile.",
                                                    ),
                                                    Err(error) => crate::components::app::toasts::show_error(
                                                        format!("Could not reset the DM delegate: {error}"),
                                                    ),
                                                }
                                            });
                                        },
                                        "Reset DM delegate"
                                    }
                                }
                            }
                        }
                    },
                    DeviceTab::Mail => rsx! {
                        if let Some(profile_id) = mail_profile_id.clone() {
                            MailTab { key: "{profile_id}", profile_id }
                        } else {
                            section { class: "space-y-4",
                                div { class: "rounded-xl border border-border bg-panel p-4 space-y-2",
                                    h3 { class: "text-sm font-semibold text-text", "Freenet Mail" }
                                    p { class: "text-xs text-text-muted",
                                        "Open a board and choose the active profile to set its Freenet Mail address."
                                    }
                                }
                            }
                        }
                    },
                    DeviceTab::Backup => rsx! {
                        section { class: "space-y-4",
                            div { class: "rounded-xl border border-border bg-panel p-4 space-y-2",
                                h3 { class: "text-sm font-semibold text-text", "Backup and restore" }
                                p { class: "text-xs text-text-muted",
                                    "The backup contains identities, private-board keys, DM identities and conversation keys, drafts and settings stored on this device. Board content stays on Freenet; uploaded image bytes and composer queues are not included."
                                }
                                p { class: "text-xs text-amber-300",
                                    "Keep the file private: it can open every private board and DM saved here."
                                }
                            }

                            div { class: "rounded-xl border border-border bg-panel p-4 space-y-3",
                                h3 { class: "text-sm font-semibold text-text", "Save a copy" }
                                p { class: "text-xs text-text-muted",
                                    "Download a file with the identities, private-board keys, DM identities and DM conversation keys held by this browser."
                                }
                                button {
                                    r#type: "button",
                                    class: "px-4 py-2 bg-accent hover:bg-accent-hover text-white text-sm rounded-lg transition-colors",
                                    onclick: move |_| {
                                        wasm_bindgen_futures::spawn_local(async {
                                            match crate::util::backup::download().await {
                                                Ok(()) => crate::components::app::toasts::show(
                                                    "Backup downloaded.",
                                                ),
                                                Err(error) => crate::components::app::toasts::show_error(format!(
                                                    "Could not create the backup: {error}"
                                                )),
                                            }
                                        });
                                    },
                                    "Download backup"
                                }
                            }

                            div { class: "rounded-xl border border-border bg-panel p-4 space-y-3",
                                h3 { class: "text-sm font-semibold text-text", "Restore from a file" }
                                p { class: "text-xs text-text-muted",
                                    "Boards and DM identities in the file are merged into this device. Existing boards with the same key are replaced by the copy in the backup."
                                }
                                label { class: "flex flex-col gap-1 text-xs text-text-muted",
                                    span { "Backup file" }
                                    input {
                                        id: "plaza-backup-file",
                                        r#type: "file",
                                        accept: ".cbor",
                                        class: "block w-full text-xs text-text-muted",
                                        onchange: move |_| {
                                            backup_error.set(None);
                                            let name = crate::util::backup::peek_selected_file()
                                                .map(|file| file.name());
                                            backup_name.set(name);
                                        },
                                    }
                                }
                                if let Some(name) = backup_name.read().as_ref() {
                                    p { class: "text-xs text-text", "Selected: {name}" }
                                }
                                if let Some(error) = backup_error.read().as_ref() {
                                    p { class: "text-xs text-red-400", "{error}" }
                                }
                                button {
                                    r#type: "button",
                                    class: "px-4 py-2 bg-surface hover:bg-surface-hover text-text text-sm rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed",
                                    disabled: backup_name.read().is_none(),
                                    onclick: move |_| {
                                        wasm_bindgen_futures::spawn_local(async move {
                                            match crate::util::backup::selected_file() {
                                                Some(file) => restore_file(file).await,
                                                None => backup_error.set(Some(
                                                    "Choose a backup file first.".to_string(),
                                                )),
                                            }
                                        });
                                    },
                                    "Restore now"
                                }
                            }
                        }
                    },
                }
            }
        }
    }
}

/// Publish or clear the address on the current board. The action is signed by
/// the active profile and sealed with the board key on private boards.
fn publish_mail_address(value: Option<String>) {
    let Some(ctx) = ActionContext::from_current_board() else {
        crate::components::app::toasts::show_error(
            "Could not publish the mail address on this board.",
        );
        return;
    };
    wasm_bindgen_futures::spawn_local(async move {
        crate::util::message_actions::set_mail_address(ctx, value).await;
    });
}

fn change_mail_visibility(
    profile_id: String,
    board_key: ed25519_dalek::VerifyingKey,
    next: MailVisibility,
    is_private: bool,
    raw: String,
) {
    let next = if is_private && next == MailVisibility::Public {
        MailVisibility::Board
    } else {
        next
    };
    let value = if next == MailVisibility::Hidden {
        None
    } else {
        match mail::normalize_address(&raw) {
            Ok(value) => Some(value),
            Err(error) => {
                crate::components::app::toasts::show_error(error);
                return;
            }
        }
    };
    BOARDS.with_mut(|boards| {
        boards.set_profile_mail_address(&profile_id, value.clone());
        if let Some(board) = boards.map.get_mut(&board_key) {
            board.mail_visibility = next;
        }
    });
    persist_profiles();
    publish_mail_address(value);
}

#[component]
fn MailTab(profile_id: String) -> Element {
    let (
        local_address,
        legacy_address,
        board_key,
        board_name,
        is_private,
        visibility,
        published,
    ) = {
        let boards = BOARDS.read();
        let profile = boards
            .profiles
            .iter()
            .find(|profile| profile.id == profile_id)
            .cloned();
        let current = CURRENT_BOARD.read().owner_key;
        let board = current.and_then(|key| boards.map.get(&key));
        let member = board.map(|board| MemberId::from(&board.self_sk.verifying_key()));
        let published = board
            .zip(member)
            .and_then(|(board, member)| board.mail_address_for(member));
        // If the state has no record yet, offer the address from the old
        // append-only action as a one-time migration.
        let legacy = board.zip(member).and_then(|(board, member)| {
            if board.mail_address_for(member).is_none() {
                board.legacy_mail_address_for(member)
            } else {
                None
            }
        });
        (
            profile
                .and_then(|profile| profile.mail_address)
                .or_else(|| legacy.clone()),
            legacy,
            current,
            board.map(board_display_name).unwrap_or_default(),
            board.map(|board| board.is_private()).unwrap_or(false),
            board.map(|board| board.mail_visibility).unwrap_or_default(),
            published,
        )
    };
    let mut address = use_signal(|| local_address.clone().unwrap_or_default());
    let mut error = use_signal(|| None::<String>);

    let save = {
        let profile_id = profile_id.clone();
        move |_| {
            let raw = address.read().clone();
            match mail::normalize_address(&raw) {
                Ok(value) => {
                    address.set(value.clone());
                    error.set(None);
                    BOARDS.with_mut(|boards| {
                        boards.set_profile_mail_address(&profile_id, Some(value.clone()));
                    });
                    persist_profiles();
                    if board_key.is_some() && visibility != MailVisibility::Hidden {
                        publish_mail_address(Some(value));
                    } else {
                        crate::components::app::toasts::show("Mail address saved.");
                    }
                }
                Err(message) => error.set(Some(message.to_string())),
            }
        }
    };

    let open = crate::util::mail::app_url();

    rsx! {
        section { class: "space-y-4",
            div { class: "rounded-xl border border-border bg-panel p-4 space-y-2",
                h3 { class: "text-sm font-semibold text-text", "Freenet Mail" }
                p { class: "text-xs text-text-muted",
                    "Freenet Mail is a separate app on Freenet. It has its own identity, recovery key and inbox. FreeTalk Plaza stores only the address; messages stay in Mail."
                }
                a {
                    href: "{open}",
                    target: "_blank",
                    rel: "noopener noreferrer",
                    class: "inline-flex items-center gap-1 text-xs text-accent hover:underline",
                    "Open Freenet Mail →"
                }
            }

            div { class: "rounded-xl border border-border bg-panel p-4 space-y-3",
                label { class: "block text-sm font-medium text-text", "Address on this profile" }
                p { class: "text-xs text-text-muted",
                    "Paste the address Mail shows in its share dialog: name@address, or the bare inbox address."
                }
                input {
                    id: "mail-address",
                    class: "w-full px-3 py-2 bg-surface border border-border rounded-lg text-text font-mono text-sm",
                    dir: "auto",
                    placeholder: "name@address",
                    value: "{address}",
                    oninput: move |event| address.set(event.value()),
                }
                if let Some(legacy) = legacy_address {
                    p { class: "text-[11px] text-amber-300",
                        "Found {legacy} in the previous format. Press Save to publish it in the new state."
                    }
                }
                if let Some(message) = error.read().as_ref() {
                    p { class: "text-xs text-red-400", "{message}" }
                }
                div { class: "flex flex-wrap items-center gap-2",
                    button {
                        r#type: "button",
                        class: "px-3 py-1.5 bg-accent hover:bg-accent-hover text-white text-xs rounded-lg transition-colors",
                        onclick: save,
                        "Save address"
                    }
                    button {
                        r#type: "button",
                        class: "px-3 py-1.5 bg-surface hover:bg-surface-hover text-text text-xs rounded-lg transition-colors",
                        onclick: move |_| {
                            let value = address.read().clone();
                            if !value.trim().is_empty() {
                                crate::util::copy_to_clipboard(&value);
                                crate::components::app::toasts::show("Mail address copied.");
                            }
                        },
                        "Copy address"
                    }
                }
            }

            div { class: "rounded-xl border border-border bg-panel p-4 space-y-3",
                h3 { class: "text-sm font-semibold text-text", "Show on this board" }
                if let Some(board_key) = board_key {
                    p { class: "text-xs text-text-muted",
                        "Board: {board_name}"
                    }
                    div { class: "flex flex-wrap gap-2",
                        button {
                            r#type: "button",
                            class: if visibility == MailVisibility::Hidden {
                                "px-3 py-1.5 bg-accent text-white text-xs rounded-lg"
                            } else {
                                "px-3 py-1.5 bg-surface hover:bg-surface-hover text-text text-xs rounded-lg"
                            },
                            onclick: {
                                let profile_id = profile_id.clone();
                                move |_| change_mail_visibility(
                                    profile_id.clone(),
                                    board_key,
                                    MailVisibility::Hidden,
                                    is_private,
                                    address.read().clone(),
                                )
                            },
                            "Hidden"
                        }
                        button {
                            r#type: "button",
                            class: if visibility != MailVisibility::Hidden {
                                "px-3 py-1.5 bg-accent text-white text-xs rounded-lg"
                            } else {
                                "px-3 py-1.5 bg-surface hover:bg-surface-hover text-text text-xs rounded-lg"
                            },
                            onclick: {
                                let profile_id = profile_id.clone();
                                let next = if is_private { MailVisibility::Board } else { MailVisibility::Public };
                                move |_| change_mail_visibility(
                                    profile_id.clone(),
                                    board_key,
                                    next,
                                    is_private,
                                    address.read().clone(),
                                )
                            },
                            if is_private { "Board members" } else { "Public" }
                        }
                    }
                    p { class: "text-xs text-text-muted",
                        if is_private {
                            "Sealed with the board key: only members of this board can read it."
                        } else {
                            "Visible to anyone who can read this board. Board members only cannot be enforced on a public board."
                        }
                    }
                    if let Some(published) = published {
                        p { class: "text-xs text-text",
                            "Published on this board: {published}"
                        }
                    }
                } else {
                    p { class: "text-xs text-text-muted",
                        "Open a board to publish the address. It stays on this device until you choose a visibility."
                    }
                }
            }

            div { class: "rounded-xl border border-border bg-panel p-4 space-y-2",
                h3 { class: "text-sm font-semibold text-text", "What Plaza keeps" }
                p { class: "text-xs text-text-muted",
                    "Only the address and the visibility choice. Plaza never asks for the Mail recovery key and does not read the inbox."
                }
            }
        }
    }
}
