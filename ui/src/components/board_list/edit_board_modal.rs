use super::board_name_field::BoardNameField;
use crate::components::app::chat_delegate::save_boards_to_delegate;
use crate::components::app::{mark_needs_sync, BOARDS, CURRENT_BOARD, EDIT_BOARD_MODAL};
use dioxus::logger::tracing::{error, info};
use dioxus::prelude::*;
use dioxus_free_icons::icons::fa_solid_icons::FaRotate;
use dioxus_free_icons::Icon;
use freenet_scaffold::ComposableState;
use plaza_core::board_state::privacy::PrivacyMode;
use plaza_core::board_state::{ChatBoardParametersV1, ChatBoardStateV1Delta};
use std::ops::Deref;

#[component]
pub fn EditBoardModal() -> Element {
    // State for leave confirmation
    let mut show_leave_confirmation = use_signal(|| false);

    // Memoize the board being edited
    let editing_board = use_memo(move || {
        EDIT_BOARD_MODAL.read().board.and_then(|editing_board_vk| {
            BOARDS.read().map.iter().find_map(|(board_vk, board_data)| {
                if &editing_board_vk == board_vk {
                    Some(board_data.clone())
                } else {
                    None
                }
            })
        })
    });

    // Memoize the board configuration
    let board_config = use_memo(move || {
        editing_board
            .read()
            .as_ref()
            .map(|board_data| board_data.board_state.configuration.configuration.clone())
    });

    // Memoize if the current user is the owner of the board being edited
    let user_is_owner = use_memo(move || {
        editing_board.read().as_ref().is_some_and(|board_data| {
            let user_vk = board_data.owner_key().verifying_key();
            let board_vk = EDIT_BOARD_MODAL.read().board.unwrap();
            user_vk == board_vk
        })
    });

    // Render the modal if board configuration is available
    if let Some(config) = board_config.clone().read().deref() {
        rsx! {
            // Modal backdrop
            div {
                class: "fixed inset-0 z-50 flex items-center justify-center",
                // Overlay
                div {
                    class: "absolute inset-0 bg-black/50",
                    onclick: move |_| {
                        EDIT_BOARD_MODAL.write().board = None;
                    }
                }
                // Modal content
                div {
                    class: "relative z-10 w-full max-w-md mx-4 bg-panel rounded-xl shadow-xl border border-border max-h-[90vh] overflow-y-auto",
                    div {
                        class: "p-6",
                        h1 { class: "text-xl font-semibold text-text mb-4", "Board Details" }

                        BoardNameField {
                            config: config.clone(),
                            is_owner: *user_is_owner.read()
                        }

                        super::read_only_field::ReadOnlyField {
                            config: config.clone(),
                            is_owner: *user_is_owner.read()
                        }

                        super::image_limits_field::ImageLimitsField {
                            config: config.clone(),
                            is_owner: *user_is_owner.read()
                        }

                        // Read-only board info
                        if let Some(board_data) = editing_board.read().as_ref() {
                            // Board Public Key
                            div {
                                class: "mt-4",
                                label {
                                    class: "block text-sm font-medium text-text-muted mb-1",
                                    title: "Ed25519 public key (Curve25519 elliptic curve)",
                                    "Board Public Key"
                                }
                                input {
                                    r#type: "text",
                                    readonly: true,
                                    title: "Ed25519 public key (Curve25519 elliptic curve)",
                                    class: "w-full px-3 py-2 bg-surface border border-border rounded-lg text-text-muted text-sm font-mono cursor-text select-all",
                                    value: "{bs58::encode(board_data.owner_vk.as_bytes()).into_string()}"
                                }
                            }
                            // Contract ID
                            div {
                                class: "mt-4",
                                label {
                                    class: "block text-sm font-medium text-text-muted mb-1",
                                    "Contract ID"
                                }
                                input {
                                    r#type: "text",
                                    readonly: true,
                                    class: "w-full px-3 py-2 bg-surface border border-border rounded-lg text-text-muted text-sm font-mono cursor-text select-all",
                                    value: "{board_data.contract_key.id()}"
                                }
                            }

                            // Read-only demo link: reading needs no membership.
                            if *user_is_owner.read() {
                                {
                                    let demo_link = {
                                        let base = web_sys::window()
                                            .and_then(|window| window.location().href().ok())
                                            .unwrap_or_default();
                                        let base = base.split('#').next().unwrap_or("").to_string();
                                        format!(
                                            "{base}#/view/{}",
                                            bs58::encode(board_data.owner_vk.as_bytes()).into_string()
                                        )
                                    };
                                    rsx! {
                                        div {
                                            class: "mt-4",
                                            label {
                                                class: "block text-sm font-medium text-text-muted mb-1",
                                                "Demo link (read-only)"
                                            }
                                            div { class: "flex gap-2",
                                                input {
                                                    r#type: "text",
                                                    readonly: true,
                                                    class: "flex-1 px-3 py-2 bg-surface border border-border rounded-lg text-text-muted text-xs font-mono cursor-text select-all",
                                                    value: "{demo_link}"
                                                }
                                                button {
                                                    r#type: "button",
                                                    class: "px-3 py-2 bg-surface hover:bg-surface-hover text-text text-xs rounded-lg border border-border transition-colors",
                                                    onclick: move |_| {
                                                        let _ = crate::util::copy_to_clipboard(&demo_link);
                                                    },
                                                    "Copy"
                                                }
                                            }
                                            p { class: "mt-1 text-xs text-text-muted",
                                                "Anyone with this link reads the board without joining, so the contract does not grow. Works on public boards."
                                            }
                                        }
                                    }
                                }
                            }

                            // Secret Version (only for private boards)
                            {
                                let is_private = board_data.board_state.configuration.configuration.privacy_mode == PrivacyMode::Private;
                                let is_owner = board_data.is_current_owner();
                                let secret_version = board_data.board_state.secrets.current_version;

                                if is_private {
                                    Some(rsx! {
                                        div {
                                            class: "mt-4",
                                            label {
                                                class: "block text-sm font-medium text-text-muted mb-1",
                                                "Secret Version"
                                            }
                                            div {
                                                class: "flex items-center gap-2",
                                                input {
                                                    r#type: "text",
                                                    readonly: true,
                                                    class: "flex-1 px-3 py-2 bg-surface border border-border rounded-lg text-text-muted text-sm font-mono cursor-text select-all",
                                                    value: "{secret_version}"
                                                }
                                                {
                                                    if is_owner {
                                                        Some(rsx! {
                                                            button {
                                                                class: "px-3 py-2 bg-surface hover:bg-surface-hover border border-border rounded-lg text-text-muted hover:text-text transition-colors flex items-center gap-2",
                                                                title: "Rotate board secret - generates a new encryption key for future messages",
                                                                onclick: move |_| {
                                                                    if let Some(current_board) = EDIT_BOARD_MODAL.read().board {
                                                                        info!("Rotating secret for board");
                                                                        BOARDS.with_mut(|boards| {
                                                                            if let Some(board_data) = boards.map.get_mut(&current_board) {
                                                                                match board_data.rotate_secret() {
                                                                                    Ok(secrets_delta) => {
                                                                                        info!("Secret rotated successfully");
                                                                                        let current_state = board_data.board_state.clone();
                                                                                        let delta = ChatBoardStateV1Delta {
                                                                                            secrets: Some(secrets_delta),
                                                                                            ..Default::default()
                                                                                        };
                                                                                        if let Err(e) = board_data.board_state.apply_delta(
                                                                                            &current_state,
                                                                                            &ChatBoardParametersV1 { owner: current_board },
                                                                                            &Some(delta),
                                                                                        ) {
                                                                                            error!("Failed to apply rotation delta: {}", e);
                                                                                            crate::components::app::toasts::show_error(format!(
                                                                                                "Could not rotate the secret: {e}"
                                                                                            ));
                                                                                        } else {
                                                                                            board_data.generate_missing_pq_secrets();
                                                                                            mark_needs_sync(current_board);
                                                                                            crate::components::app::toasts::show(
                                                                                                "Secret rotated. Syncing with the network…",
                                                                                            );
                                                                                        }
                                                                                    }
                                                                                    Err(e) => {
                                                                                        error!("Failed to rotate secret: {}", e);
                                                                                        crate::components::app::toasts::show_error(format!(
                                                                                            "Could not rotate the secret: {e}"
                                                                                        ));
                                                                                    }
                                                                                }
                                                                            }
                                                                        });
                                                                    }
                                                                },
                                                                Icon { icon: FaRotate, width: 14, height: 14 }
                                                                span { "Rotate" }
                                                            }
                                                        })
                                                    } else {
                                                        None
                                                    }
                                                }
                                            }
                                        }
                                    })
                                } else {
                                    None
                                }
                            }
                        }

                        // Remove from this device
                        if *show_leave_confirmation.read() {
                            div {
                                class: "bg-yellow-500/10 border border-yellow-500/20 rounded-lg p-4 mt-4",
                                p {
                                    class: "text-yellow-400 mb-3",
                                    if *user_is_owner.read() {
                                        "Warning: you are the owner of this board. Removing it from this device does not remove it from the network: the board keeps working for its members. Keep the identity token to come back."
                                    } else {
                                        "Remove this board from this device? Your membership stays on the board; import its identity token to bring it back."
                                    }
                                }
                                div {
                                    class: "flex gap-3",
                                    button {
                                        class: "px-4 py-2 bg-red-500 hover:bg-red-600 text-white font-medium rounded-lg transition-colors",
                                        onclick: move |_| {
                                            // Read the board_vk first and drop the read borrow
                                            let board_vk_to_remove = EDIT_BOARD_MODAL.read().board;

                                            if let Some(board_vk) = board_vk_to_remove {
                                                // Perform writes *after* the read borrow is dropped
                                                {
                                                    let mut boards = BOARDS.write();
                                                    boards.map.remove(&board_vk);
                                                    if !boards.removed.contains(&board_vk) {
                                                        boards.removed.push(board_vk);
                                                    }
                                                }

                                                // Check and potentially clear CURRENT_BOARD
                                                if CURRENT_BOARD.read().owner_key == Some(board_vk) {
                                                    CURRENT_BOARD.write().owner_key = None;
                                                }

                                                // Close the modal *last*
                                                EDIT_BOARD_MODAL.write().board = None;

                                                // Save updated boards to delegate storage
                                                info!("Board removed, saving to delegate");
                                                crate::components::app::toasts::show(
                                                    "Board removed from this device.",
                                                );
                                                spawn(async move {
                                                    if let Err(e) = save_boards_to_delegate().await {
                                                        error!("Failed to save boards after removal: {}", e);
                                                        crate::components::app::toasts::show_error(format!(
                                                            "The removal was not saved: {e}"
                                                        ));
                                                    }
                                                });
                                            }
                                            // Reset confirmation state regardless
                                            show_leave_confirmation.set(false);
                                        },
                                        "Confirm Remove"
                                    }
                                    button {
                                        class: "px-4 py-2 bg-surface hover:bg-surface-hover text-text rounded-lg transition-colors",
                                        onclick: move |_| show_leave_confirmation.set(false),
                                        "Cancel"
                                    }
                                }
                            }
                        } else {
                            // Only show the remove button if not confirming
                            div {
                                class: "mt-4",
                                button {
                                    class: "px-4 py-2 border border-red-500 text-red-500 hover:bg-red-500/10 rounded-lg transition-colors",
                                    onclick: move |_| show_leave_confirmation.set(true),
                                    "Remove from this device"
                                }
                            }
                        }
                    }
                    div { class: "mt-4 pt-4 border-t border-border",
                        p { class: "text-xs text-text-muted mb-2",
                            "Clear every board and image stored on this device. The boards stay online; you need their identity token to come back."
                        }
                        button {
                            class: "px-4 py-2 border border-red-500/50 text-red-400 hover:bg-red-500/10 rounded-lg transition-colors text-sm",
                            onclick: move |_| crate::util::reset::confirm_and_reset(),
                            "Reset all local data"
                        }
                    }
                    details { class: "mt-4 pt-4 border-t border-border",
                        summary { class: "text-xs text-text-muted cursor-pointer", "Developer" }
                        p { class: "text-xs text-text-muted mt-2 mb-2",
                            "Test hook: shows the Sync failed chip and its Retry without a network failure."
                        }
                        button {
                            r#type: "button",
                            class: "px-3 py-1.5 bg-surface border border-border rounded-lg text-xs text-amber-300 hover:bg-surface-hover transition-colors",
                            onclick: move |_| {
                                if let Some(board) = EDIT_BOARD_MODAL.read().board {
                                    crate::components::app::sync_info::simulate_board_error(board);
                                }
                            },
                            "Simulate sync error"
                        }
                    }
                    // Close button
                    button {
                        class: "absolute top-3 right-3 p-1 text-text-muted hover:text-text transition-colors",
                        onclick: move |_| {
                            EDIT_BOARD_MODAL.write().board = None;
                        },
                        "✕"
                    }
                }
            }
        }
    } else {
        rsx! {}
    }
}
