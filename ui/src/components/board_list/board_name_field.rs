use crate::components::app::{mark_needs_sync, BOARDS, CURRENT_BOARD};
use crate::util::ecies::{seal_bytes, unseal_bytes_with_secrets};
use dioxus::logger::tracing::*;
use dioxus::prelude::*;
use dioxus_core::Event;
use freenet_scaffold::ComposableState;
use plaza_core::board_state::configuration::{AuthorizedConfigurationV1, Configuration};
use plaza_core::board_state::privacy::{BoardDisplayMetadata, SealedBytes};
use plaza_core::board_state::{ChatBoardParametersV1, ChatBoardStateV1Delta};
use wasm_bindgen_futures::spawn_local;

#[component]
pub fn BoardNameField(config: Configuration, is_owner: bool) -> Element {
    // Extract and decrypt the board name using version-aware decryption
    let initial_name = {
        let owner_key = CURRENT_BOARD.read().owner_key;
        let boards = BOARDS.read();
        let secrets = owner_key
            .and_then(|key| boards.map.get(&key))
            .map(|board_data| board_data.secrets.clone())
            .unwrap_or_default();
        match unseal_bytes_with_secrets(&config.display.name, &secrets) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
            Err(_) => config.display.name.to_string_lossy(),
        }
    };
    let mut board_name = use_signal(|| initial_name);
    let max_board_name = config.max_board_name;

    let update_board_name = move |evt: Event<FormData>| {
        if !is_owner {
            return;
        }

        info!("Updating board name");
        let new_name = evt.value().to_string();
        if new_name.len() > max_board_name {
            crate::components::app::toasts::show_error(format!(
                "The board name is too long: {}/{} bytes",
                new_name.len(),
                max_board_name
            ));
            return;
        }
        if !new_name.is_empty() {
            board_name.set(new_name.clone());

            // Get the owner key first
            let owner_key = CURRENT_BOARD.read().owner_key.expect("No owner key");

            // Get signing data and encryption info from board
            let signing_data = BOARDS.with(|boards| {
                if let Some(board_data) = boards.map.get(&owner_key) {
                    Some((
                        board_data.owner_key().clone(),
                        board_data.board_state.clone(),
                        board_data.get_secret().map(|(s, v)| (*s, v)),
                    ))
                } else {
                    error!("Board state not found for current board");
                    None
                }
            });

            let Some((self_sk, board_state_clone, board_secret_opt)) = signing_data
            else {
                return;
            };

            // Encrypt name if board is private and we have a secret
            let sealed_name = match board_secret_opt {
                Some((secret, version)) => seal_bytes(new_name.as_bytes(), &secret, version),
                _ => SealedBytes::public(new_name.clone().into_bytes()),
            };

            let mut new_config = config.clone();
            new_config.display = BoardDisplayMetadata {
                name: sealed_name,
                description: new_config.display.description.clone(),
            };
            new_config.configuration_version += 1;

            spawn_local(async move {
                // Sign locally with the owner key; the delegate may hold a
                // profile key, which the contract rejects.
                let new_authorized_config =
                    AuthorizedConfigurationV1::new(new_config, &self_sk);

                let delta = ChatBoardStateV1Delta {
                    configuration: Some(new_authorized_config),
                    ..Default::default()
                };

                BOARDS.with_mut(|boards| {
                    if let Some(board_data) = boards.map.get_mut(&owner_key) {
                        info!("Applying delta to board state");
                        match ComposableState::apply_delta(
                            &mut board_data.board_state,
                            &board_state_clone,
                            &ChatBoardParametersV1 { owner: owner_key },
                            &Some(delta),
                        ) {
                            Ok(_) => {
                                info!("Delta applied successfully");
                                // Mark board as needing sync after name change (deferred)
                                mark_needs_sync(owner_key);
                                crate::components::app::toasts::show(
                                    "Board name saved. Syncing with the network…",
                                );
                            }
                            Err(e) => {
                                error!("Failed to apply delta: {:?}", e);
                                crate::components::app::toasts::show_error(format!(
                                    "Board name: {e}"
                                ));
                            }
                        }
                    }
                });
            });
        } else {
            error!("Board name is empty");
            crate::components::app::toasts::show_error("A board name is required");
        }
    };

    rsx! {
        div { class: "mb-4",
            div { class: "flex items-center justify-between mb-2",
                label { class: "block text-sm font-medium text-text-muted", "Board Name" }
                span {
                    class: if board_name.read().len() > max_board_name { "text-xs text-red-400" } else { "text-xs text-text-muted" },
                    "{board_name.read().len()}/{max_board_name} bytes"
                }
            }
            input {
                class: "w-full px-3 py-2 bg-surface border border-border rounded-lg text-text placeholder-text-muted focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent disabled:opacity-50 disabled:cursor-not-allowed",
                dir: "auto",
                value: "{board_name}",
                readonly: !is_owner,
                disabled: !is_owner,
                oninput: move |evt| board_name.set(evt.value().to_string()),
                onchange: update_board_name,
            }
        }
    }
}
