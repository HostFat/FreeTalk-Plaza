//! Owner fields for the image limits.

use crate::components::app::{mark_needs_sync, BOARDS, EDIT_BOARD_MODAL};
use dioxus::logger::tracing::{error, info};
use dioxus::prelude::*;
use freenet_scaffold::ComposableState;
use plaza_core::board_state::configuration::{AuthorizedConfigurationV1, Configuration};
use plaza_core::board_state::{ChatBoardParametersV1, ChatBoardStateV1Delta};
use wasm_bindgen_futures::spawn_local;

/// Images per message and the byte ceilings for static and animated images.
#[component]
pub fn ImageLimitsField(config: Configuration, is_owner: bool) -> Element {
    let mut images = use_signal(|| config.images_per_message());
    let mut static_mib = use_signal(|| (config.image_byte_limit() / (1024 * 1024)).max(1));
    let mut animated_mib =
        use_signal(|| (config.animated_image_byte_limit() / (1024 * 1024)).max(1));
    let mut busy = use_signal(|| false);
    let mut error_message = use_signal(|| None::<String>);

    let save = move |_| {
        if !is_owner || *busy.read() {
            return;
        }
        let Some(owner_key) = EDIT_BOARD_MODAL.read().board else {
            return;
        };
        let signing_data = BOARDS.with(|boards| {
            boards
                .map
                .get(&owner_key)
                .map(|board| (board.board_key(), board.owner_key().clone(), board.board_state.clone()))
        });
        let Some((board_key, self_sk, parent_state)) = signing_data else {
            error_message.set(Some("Board state not found".to_string()));
            return;
        };

        let mut new_config = config.clone();
        new_config.max_images_per_message = *images.read();
        new_config.max_image_bytes = *static_mib.read() * 1024 * 1024;
        new_config.max_animated_image_bytes = *animated_mib.read() * 1024 * 1024;
        new_config.configuration_version += 1;
        new_config.updated_at = crate::util::get_current_system_time();
        busy.set(true);
        error_message.set(None);

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
                    return Err("Board state not found".to_string());
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
                    info!("Image limits updated");
                    crate::components::app::toasts::show(
                        "Image limits saved. Syncing with the network…",
                    );
                    mark_needs_sync(owner_key);
                }
                Err(error) => {
                    error!("Failed to change the image limits: {error}");
                    crate::components::app::toasts::show_error(format!(
                        "Image limits: {error}"
                    ));
                    error_message.set(Some(error));
                }
            }
            busy.set(false);
        });
    };

    rsx! {
        div { class: "mt-4 border-t border-border pt-4",
            p { class: "text-sm font-medium text-text", "Image limits" }
            p { class: "text-xs text-text-muted mb-2",
                "Applies to new posts. The contract refuses anything above these values."
            }
            div { class: "grid grid-cols-3 gap-2",
                label { class: "text-xs text-text-muted",
                    "Per post"
                    input {
                        r#type: "number",
                        min: "1",
                        max: "8",
                        class: "mt-1 w-full px-2 py-1 bg-background border border-border rounded text-text",
                        value: "{images}",
                        disabled: !is_owner || busy(),
                        oninput: move |event| {
                            if let Ok(value) = event.value().parse::<u32>() {
                                images.set(value.clamp(1, 8));
                            }
                        },
                    }
                }
                label { class: "text-xs text-text-muted",
                    "Static MiB"
                    input {
                        r#type: "number",
                        min: "1",
                        max: "8",
                        class: "mt-1 w-full px-2 py-1 bg-background border border-border rounded text-text",
                        value: "{static_mib}",
                        disabled: !is_owner || busy(),
                        oninput: move |event| {
                            if let Ok(value) = event.value().parse::<u32>() {
                                static_mib.set(value.clamp(1, 8));
                            }
                        },
                    }
                }
                label { class: "text-xs text-text-muted",
                    "Animated MiB"
                    input {
                        r#type: "number",
                        min: "1",
                        max: "20",
                        class: "mt-1 w-full px-2 py-1 bg-background border border-border rounded text-text",
                        value: "{animated_mib}",
                        disabled: !is_owner || busy(),
                        oninput: move |event| {
                            if let Ok(value) = event.value().parse::<u32>() {
                                animated_mib.set(value.clamp(1, 20));
                            }
                        },
                    }
                }
            }
            if let Some(message) = error_message.read().as_ref() {
                p { class: "text-xs text-red-400 mt-1", "{message}" }
            }
            button {
                r#type: "button",
                class: "mt-2 px-3 py-1.5 bg-surface hover:bg-surface-hover border border-border rounded-lg text-xs text-text disabled:opacity-50",
                disabled: !is_owner || busy(),
                onclick: save,
                if busy() { "Saving..." } else { "Save limits" }
            }
        }
    }
}
