use crate::components::app::{mark_needs_sync, BOARDS, CURRENT_BOARD};
use dioxus::logger::tracing::*;
use dioxus::prelude::*;
use freenet_scaffold::ComposableState;
use plaza_core::board_state::configuration::{AuthorizedConfigurationV1, Configuration};
use plaza_core::board_state::{ChatBoardParametersV1, ChatBoardStateV1Delta};
use wasm_bindgen_futures::spawn_local;

/// Owner switch for a demo board: everyone reads, only owner and admins write.
#[component]
pub fn ReadOnlyField(config: Configuration, is_owner: bool) -> Element {
    let mut busy = use_signal(|| false);
    let read_only = config.read_only;

    let toggle = move |_| {
        if !is_owner || *busy.read() {
            return;
        }
        let Some(owner_key) = CURRENT_BOARD.read().owner_key else {
            return;
        };
        let signing_data = BOARDS.with(|boards| {
            boards
                .map
                .get(&owner_key)
                .map(|board| (board.board_key(), board.owner_key().clone(), board.board_state.clone()))
        });
        let Some((board_key, self_sk, parent_state)) = signing_data else {
            error!("Board state not found for current board");
            return;
        };

        let mut new_config = config.clone();
        new_config.read_only = !new_config.read_only;
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
                    info!("Read-only mode toggled");
                    crate::components::app::toasts::show(
                        "Board mode saved. Syncing with the network…",
                    );
                    mark_needs_sync(owner_key);
                }
                Err(error) => {
                    error!("Failed to change read-only mode: {error}");
                    crate::components::app::toasts::show_error(format!(
                        "Board mode: {error}"
                    ));
                }
            }
            busy.set(false);
        });
    };

    rsx! {
        div { class: "mt-4",
            label { class: "flex items-start gap-3 cursor-pointer",
                input {
                    r#type: "checkbox",
                    checked: read_only,
                    disabled: !is_owner || busy(),
                    class: "mt-1",
                    onchange: toggle,
                }
                div {
                    span { class: "block text-sm font-medium text-text", "Demo mode (read-only)" }
                    span { class: "block text-xs text-text-muted",
                        "Only the owner and admins can post, edit, react or report. Everyone else reads the board. The switch stays off for normal boards."
                    }
                }
            }
        }
    }
}
