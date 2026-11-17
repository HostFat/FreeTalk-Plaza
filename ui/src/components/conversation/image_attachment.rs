//! One image attached to a message.
//!
//! Nothing is fetched until the reader asks for it: the placeholder carries the
//! type, the size and the NSFW and animated labels, and the click starts the
//! download. The bytes are verified against the hash before being shown.

use crate::util::images::{request_image, ImageStatus, IMAGES};
use dioxus::prelude::*;
use plaza_core::board_state::images::ImageRef;

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
pub fn ImageAttachment(image: ImageRef) -> Element {
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
    let ready_bytes = match &status {
        Some(ImageStatus::Ready(bytes)) if opened() => Some(bytes.clone()),
        _ => None,
    };

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
            {match status {
                Some(ImageStatus::Ready(_)) if opened() => rsx! {
                    if let Some(created) = current_url.clone() {
                        img {
                            src: "{created}",
                            alt: "{alt}",
                            class: "rounded-md max-h-[70vh] object-contain mx-auto",
                            style: "width: {display}%",
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
                    }
                },
            }}
        }
    }
}

fn ready_bytes_for(instance: &[u8; 32]) -> Option<Vec<u8>> {
    match IMAGES.read().get(instance).map(|entry| entry.status.clone()) {
        Some(ImageStatus::Ready(bytes)) => Some(bytes),
        _ => None,
    }
}
