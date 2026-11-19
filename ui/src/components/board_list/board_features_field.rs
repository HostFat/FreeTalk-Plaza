use crate::components::app::{mark_needs_sync, BOARDS, CURRENT_BOARD};
use dioxus::logger::tracing::*;
use dioxus::prelude::*;
use freenet_scaffold::ComposableState;
use plaza_core::board_state::configuration::{AuthorizedConfigurationV1, Configuration};
use plaza_core::board_state::{ChatBoardParametersV1, ChatBoardStateV1Delta};
use wasm_bindgen_futures::spawn_local;

/// Owner switches for reactions and the auto-moderated topic capability.
#[component]
pub fn BoardFeaturesField(config: Configuration, is_owner: bool) -> Element {
    let mut busy = use_signal(|| false);
    let reactions_enabled = config.reactions_enabled;
    let auto_moderated_topics = config.auto_moderated_topics;

    let apply = move |change: fn(&mut Configuration)| {
        if !is_owner || *busy.read() {
            return;
        }
        let Some(owner_key) = CURRENT_BOARD.read().owner_key else {
            return;
        };
        let signing_data = BOARDS.with(|boards| {
            boards.map.get(&owner_key).map(|board| {
                (
                    board.board_key(),
                    board.owner_key().clone(),
                    board.board_state.clone(),
                )
            })
        });
        let Some((board_key, self_sk, parent_state)) = signing_data else {
            error!("Board state not found for current board");
            return;
        };

        let mut new_config = config.clone();
        change(&mut new_config);
        new_config.configuration_version += 1;
        busy.set(true);

        spawn_local(async move {
            let mut config_bytes = Vec::new();
            if let Err(error) = ciborium::ser::into_writer(&new_config, &mut config_bytes) {
                error!("Failed to serialize config for signing: {error:?}");
                busy.set(false);
                return;
            }
            let signature =
                crate::signing::sign_config_with_fallback(board_key, config_bytes, &self_sk).await;
            let authorized = AuthorizedConfigurationV1::with_signature(new_config, signature);
            let delta = ChatBoardStateV1Delta {
                configuration: Some(authorized),
                ..Default::default()
            };
            let result = BOARDS.with_mut(|boards| {
                let Some(board_data) = boards.map.get_mut(&owner_key) else {
                    return Err("Board state not found for current board".to_string());
                };
                ComposableState::apply_delta(
                    &mut board_data.board_state,
                    &parent_state,
                    &ChatBoardParametersV1 { owner: owner_key },
                    &Some(delta),
                )
            });
            match result {
                Ok(()) => {
                    crate::components::app::toasts::show(
                        "Board settings saved. Syncing with the network…",
                    );
                    mark_needs_sync(owner_key);
                }
                Err(error) => {
                    error!("Failed to change board features: {error}");
                    crate::components::app::toasts::show_error(format!(
                        "Board settings: {error}"
                    ));
                }
            }
            busy.set(false);
        });
    };

    let mut apply_reactions = apply.clone();
    let mut apply_auto_moderated = apply;

    rsx! {
        div { class: "mt-4 space-y-3",
            label { class: "flex items-start gap-3 cursor-pointer",
                input {
                    r#type: "checkbox",
                    checked: reactions_enabled,
                    disabled: !is_owner || busy(),
                    class: "mt-1",
                    onchange: move |_| apply_reactions(|config| {
                        let next = !config.reactions_enabled;
                        config.reactions_enabled = next;
                    }),
                }
                div {
                    span { class: "block text-sm font-medium text-text", "Reactions" }
                    span { class: "block text-xs text-text-muted",
                        "Posts and replies accept emoji reactions. Turning it off hides the picker and every existing reaction; the actions stay in the board and come back when it is turned on again."
                    }
                }
            }
            label { class: "flex items-start gap-3 cursor-pointer",
                input {
                    r#type: "checkbox",
                    checked: auto_moderated_topics,
                    disabled: !is_owner || busy(),
                    class: "mt-1",
                    onchange: move |_| apply_auto_moderated(|config| {
                        let next = !config.auto_moderated_topics;
                        config.auto_moderated_topics = next;
                    }),
                }
                div {
                    span { class: "block text-sm font-medium text-text", "Auto-moderated topics by default" }
                    span { class: "block text-xs text-text-muted",
                        "Sections allow topic authors to delete replies unless they override this. The composer option stays unchecked by default, and the contract rejects a flagged topic where the setting is off."
                    }
                }
            }
        }
    }
}
