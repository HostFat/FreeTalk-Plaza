//! One image attached to a message.
//!
//! Nothing is fetched until the reader asks for it: the placeholder carries the
//! type, the size and the NSFW and animated labels, and the click starts the
//! download. The bytes are verified against the hash before being shown.

use crate::components::app::{BOARDS, CURRENT_BOARD};
use crate::util::images::{request_image, ImageStatus, IMAGES};
use dioxus::prelude::*;
use plaza_core::board_state::images::ImageRef;
use wasm_bindgen_futures::spawn_local;

fn kilobytes(bytes: u32) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{} KB", (bytes / 1024).max(1))
    }
}

fn object_url(bytes: &[u8], mime: &str) -> Option<String> {
    let array = js_sys::Uint8Array::from(bytes);
    let parts = js_sys::Array::new();
    parts.push(&array.buffer());
    let options = web_sys::BlobPropertyBag::new();
    options.set_type(mime);
    let blob = web_sys::Blob::new_with_buffer_source_sequence_and_options(&parts, &options).ok()?;
    web_sys::Url::create_object_url_with_blob(&blob).ok()
}

#[component]
pub fn ImageAttachment(image: ImageRef, #[props(default)] auto_load: bool) -> Element {
    let mut opened = use_signal(|| false);
    let mut url = use_signal(|| None::<String>);
    let instance = image.instance;
    let expected = image.sha256;
    let mime = image.mime.clone();
    let mime_for_url = mime.clone();
    let nsfw = image.nsfw;
    let animated = image.animated;
    let display = if image.display == 0 { 100 } else { image.display };
    let width = image.width;
    let height = image.height;
    let bytes = image.bytes;
    let alt = if image.alt.trim().is_empty() {
        "Attached image".to_string()
    } else {
        image.alt.clone()
    };

    let status = IMAGES
        .read()
        .get(&instance)
        .map(|entry| entry.status.clone());

    // A board-level retirement hides the image even if its contract still has
    // the bytes; the hash entry also blocks the same file under another key.
    let retired = use_memo(move || {
        let Some(key) = CURRENT_BOARD.read().owner_key else {
            return false;
        };
        BOARDS
            .read()
            .map
            .get(&key)
            .map(|board| {
                board.board_state.image_retirements.is_retired(&instance)
                    || board.board_state.image_retirements.is_hash_denied(&expected)
            })
            .unwrap_or(false)
    });
    let can_retire = use_memo(move || {
        let Some(key) = CURRENT_BOARD.read().owner_key else {
            return false;
        };
        BOARDS
            .read()
            .map
            .get(&key)
            .map(|board| board.may_retire_images())
            .unwrap_or(false)
    });
    // The device denylist wins over any cached or fetched copy.
    let blocked = use_memo(move || crate::util::images::is_hash_blocked(&expected));
    // The contract kill switch belongs to the uploader and the board owners.
    let is_board_owner = use_memo(move || {        let Some(key) = CURRENT_BOARD.read().owner_key else {
            return false;
        };
        BOARDS
            .read()
            .map
            .get(&key)
            .map(|board| {
                let self_vk = board.self_sk.verifying_key();
                self_vk == board.owner_vk || self_vk == board.current_owner_key()
            })
            .unwrap_or(false)
    });
    let retire_contract = move |_| {
        let confirmed = web_sys::window()
            .and_then(|window| {
                window
                    .confirm_with_message(
                        "Retire this image contract? Nodes that apply the update drop the bytes. Copies already on other nodes can persist.",
                    )
                    .ok()
            })
            .unwrap_or(false);
        if !confirmed {
            return;
        }
        spawn_local(async move {
            match crate::util::images::retire_in_contract(instance).await {
                Ok(()) => {
                    crate::components::app::toasts::show(
                        "Contract retirement sent to the network.",
                    );
                }
                Err(error) => {
                    crate::components::app::toasts::show_error(format!(
                        "Could not retire the contract: {error}"
                    ));
                    crate::components::app::toasts::show_error(format!(
                        "Could not retire the contract: {error}"
                    ));
                }
            }
        });
    };
    let block = move |_| {
        crate::util::images::block_image(instance, expected);
        crate::components::app::toasts::show("Image blocked on this device.");
    };
    let retire = move |_| {
        let Some(ctx) = crate::util::message_actions::ActionContext::from_current_board() else {
            return;
        };
        let reason = web_sys::window()
            .and_then(|window| {
                window
                    .prompt_with_message("Reason for retiring this image")
                    .ok()
                    .flatten()
            })
            .unwrap_or_default();
        let reason = if reason.trim().is_empty() {
            "Retired by a moderator".to_string()
        } else {
            reason
        };
        spawn_local(async move {
            if let Err(error) =
                crate::util::image_retire::retire_image(&ctx, instance, expected, reason)
            {
                dioxus::logger::tracing::warn!("Could not retire the image: {error}");
                crate::components::app::toasts::show_error(format!(
                    "Could not retire the image: {error}"
                ));
            } else {
                crate::components::app::toasts::show(
                    "Image retired. Syncing with the network…",
                );
            }
        });
    };
    let _ready_bytes = match &status {
        Some(ImageStatus::Ready(bytes)) if opened() => Some(bytes.clone()),
        _ => None,
    };

    use_effect(move || {
        // NSFW images always need a click, even when auto-load is on.
        let auto = *crate::util::images::AUTO_LOAD_CURRENT.read();
        if auto && !nsfw && !opened() {
            opened.set(true);
            request_image(instance, expected);
        }
    });

    use_effect(move || {
        if let Some(bytes) = ready_bytes_for(&instance) {
            if url.peek().is_none() {
                if let Some(created) = object_url(&bytes, &mime_for_url) {
                    url.set(Some(created));
                }
            }
        }
    });
    let current_url = url.read().clone();
    use_drop(move || {
        let created = url.peek().clone();
        if let Some(created) = created {
            let _ = web_sys::Url::revoke_object_url(&created);
        }
    });

    rsx! {
        figure { class: "my-2 rounded-lg border border-border bg-background p-3",
            if blocked() {
                div { class: "flex items-center justify-between gap-3 text-xs text-text-muted",
                    div {
                        div { "Blocked on this device" }
                        div { class: "text-[10px] text-text-muted/80",
                            "This device will not download or show this image."
                        }
                    }
                    span { class: "text-text-muted", "{width}x{height} · {kilobytes(bytes)}" }
                }
            } else if retired() {
                div { class: "flex items-center justify-between gap-3 text-xs text-text-muted",
                    div {
                        div { "Image retired by moderation" }
                        div { class: "text-[10px] text-text-muted/80",
                            "This forum stops serving it. Copies already on other nodes can persist."
                        }
                    }
                    span { class: "text-text-muted", "{width}x{height} · {kilobytes(bytes)}" }
                }
            } else {
            {match status {
                Some(ImageStatus::Ready(_)) if opened() => rsx! {
                    if let Some(created) = current_url.clone() {
                        img {
                            src: "{created}",
                            alt: "{alt}",
                            class: "rounded-md max-h-[70vh] object-contain mx-auto cursor-zoom-in",
                            style: "width: {display}%",
                            onclick: {
                                let src = created.clone();
                                let alt = alt.clone();
                                move |event: MouseEvent| {
                                    event.stop_propagation();
                                    *crate::components::app::LIGHTBOX.write() = Some(
                                        crate::components::app::LightboxState {
                                            src: src.clone(),
                                            alt: alt.clone(),
                                        },
                                    );
                                }
                            },
                        }
                    } else {
                        div { class: "flex items-center gap-2 text-xs text-text-muted",
                            div { class: "animate-spin w-3 h-3 border-2 border-text-muted border-t-transparent rounded-full" }
                            "Preparing image..."
                        }
                    }
                },
                Some(ImageStatus::Loading) if opened() => rsx! {
                    div { class: "flex items-center gap-2 text-xs text-text-muted",
                        div { class: "animate-spin w-3 h-3 border-2 border-text-muted border-t-transparent rounded-full" }
                        "Downloading image..."
                    }
                },
                Some(ImageStatus::Failed(reason)) => rsx! {
                    div { class: "text-xs text-red-400",
                        "Image unavailable"
                        if !reason.is_empty() { " ({reason})" }
                    }
                },
                _ => rsx! {
                    div { class: "flex items-center justify-between gap-3",
                        div { class: "text-xs text-text-muted",
                            span { class: "text-text", "{alt}" }
                            span { class: "ml-2", "{width}x{height} · {kilobytes(bytes)} · {mime}" }
                            if animated {
                                span { class: "ml-2 px-1.5 py-0.5 rounded bg-accent/20 text-accent uppercase text-[10px]", "animated" }
                            }
                            if nsfw {
                                span { class: "ml-2 px-1.5 py-0.5 rounded bg-red-500/20 text-red-300 uppercase text-[10px]", "NSFW" }
                            }
                        }
                        button {
                            r#type: "button",
                            class: "px-3 py-1.5 bg-surface hover:bg-surface-hover border border-border rounded-lg text-xs text-text",
                            onclick: move |_| {
                                if !opened() {
                                    opened.set(true);
                                    request_image(instance, expected);
                                }
                            },
                            if nsfw { "Show NSFW image" } else { "Open image" }
                        }
                        if can_retire() {
                            button {
                                r#type: "button",
                                class: "px-2 py-1.5 text-xs text-red-400 hover:bg-red-500/10 border border-border rounded-lg",
                                title: "Hide this image for everyone on the board and block its hash",
                                onclick: retire,
                                "Retire"
                            }
                        }
                        if is_board_owner() {
                            button {
                                r#type: "button",
                                class: "px-2 py-1.5 text-xs text-red-400 hover:bg-red-500/10 border border-border rounded-lg",
                                title: "Empty the image contract itself (uploader and board owners)",
                                onclick: retire_contract,
                                "Retire blob"
                            }
                        }
                        button {
                            r#type: "button",
                            class: "px-2 py-1.5 text-xs text-text-muted hover:bg-surface-hover border border-border rounded-lg",
                            title: "Never download or show this hash on this device",
                            onclick: block,
                            "Block"
                        }
                    }
                },
            }}
            }
        }
    }
}

fn ready_bytes_for(instance: &[u8; 32]) -> Option<Vec<u8>> {
    match IMAGES.read().get(instance).map(|entry| entry.status.clone()) {
        Some(ImageStatus::Ready(bytes)) => Some(bytes),
        _ => None,
    }
}
