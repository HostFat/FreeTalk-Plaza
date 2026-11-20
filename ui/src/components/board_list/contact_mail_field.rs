use crate::components::app::{mark_needs_sync, BOARDS, CURRENT_BOARD};
use crate::util::ecies::{seal_bytes, unseal_bytes_with_secrets};
use dioxus::prelude::*;
use freenet_scaffold::ComposableState;
use plaza_core::board_state::configuration::{AuthorizedConfigurationV1, Configuration};
use plaza_core::board_state::privacy::SealedBytes;
use plaza_core::board_state::{ChatBoardParametersV1, ChatBoardStateV1Delta};

/// Owner-editable Freenet Mail contact for the board. Visible read-only to
/// members; only the owner can save it.
#[component]
pub fn ContactMailField(config: Configuration, is_owner: bool) -> Element {
    let initial = {
        let owner_key = CURRENT_BOARD.read().owner_key;
        let boards = BOARDS.read();
        let secrets = owner_key
            .and_then(|key| boards.map.get(&key))
            .map(|board| board.secrets.clone())
            .unwrap_or_default();
        config
            .contact_mail
            .as_ref()
            .and_then(|contact| {
                unseal_bytes_with_secrets(contact, &secrets)
                    .ok()
                    .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
            })
            .unwrap_or_default()
    };
    let mut contact = use_signal(|| initial);
    let mut error = use_signal(|| None::<String>);

    let save = move |_| {
        if !is_owner {
            return;
        }
        let raw = contact.read().trim().to_string();
        let normalized = if raw.is_empty() {
            None
        } else {
            match crate::util::mail::normalize_address(&raw) {
                Ok(value) => Some(value),
                Err(message) => {
                    error.set(Some(message.to_string()));
                    return;
                }
            }
        };
        error.set(None);

        let Some(owner_key) = CURRENT_BOARD.read().owner_key else {
            return;
        };
        let signing = BOARDS.with(|boards| {
            boards.map.get(&owner_key).map(|board| {
                (
                    board.owner_key().clone(),
                    board.board_state.clone(),
                    board
                        .get_secret()
                        .map(|(secret, version)| (*secret, version)),
                )
            })
        });
        let Some((owner_sk, board_state_clone, secret)) = signing else {
            crate::components::app::toasts::show_error("Board state not available.");
            return;
        };

        let sealed = match normalized {
            Some(value) => match secret {
                Some((secret, version)) => Some(seal_bytes(value.as_bytes(), &secret, version)),
                None => Some(SealedBytes::public(value.into_bytes())),
            },
            None => None,
        };
        let mut new_config = config.clone();
        new_config.contact_mail = sealed;
        new_config.configuration_version += 1;
        let authorized = AuthorizedConfigurationV1::new(new_config, &owner_sk);
        let delta = ChatBoardStateV1Delta {
            configuration: Some(authorized),
            ..Default::default()
        };
        let mut applied = false;
        BOARDS.with_mut(|boards| {
            if let Some(board_data) = boards.map.get_mut(&owner_key) {
                let params = ChatBoardParametersV1 { owner: owner_key };
                if board_data
                    .board_state
                    .apply_delta(&board_state_clone, &params, &Some(delta))
                    .is_ok()
                {
                    mark_needs_sync(owner_key);
                    applied = true;
                }
            }
        });
        if applied {
            crate::components::app::toasts::show(
                "Board Mail contact saved. Syncing with the network…",
            );
        } else {
            crate::components::app::toasts::show_error("Could not save the board Mail contact.");
        }
    };

    rsx! {
        div { class: "mb-4",
            label { class: "block text-sm font-medium text-text-muted mb-2",
                "Freenet Mail contact"
            }
            input {
                id: "board-contact-mail",
                class: "w-full px-3 py-2 bg-surface border border-border rounded-lg text-text font-mono text-sm disabled:opacity-50",
                dir: "auto",
                placeholder: "name@address",
                value: "{contact}",
                readonly: !is_owner,
                disabled: !is_owner,
                oninput: move |event| contact.set(event.value()),
            }
            if let Some(message) = error.read().as_ref() {
                p { class: "text-xs text-red-400 mt-1", "{message}" }
            }
            if is_owner {
                div { class: "flex items-center gap-2 mt-2",
                    button {
                        r#type: "button",
                        class: "px-3 py-1.5 bg-accent hover:bg-accent-hover text-white text-xs rounded-lg transition-colors",
                        onclick: save,
                        "Save contact"
                    }
                    p { class: "text-[11px] text-text-muted",
                        "For reports and appeals. This is not a Plaza DM."
                    }
                }
            } else {
                p { class: "text-[11px] text-text-muted mt-1",
                    "Set by the board owner. This is not a Plaza DM."
                }
            }
        }
    }
}
