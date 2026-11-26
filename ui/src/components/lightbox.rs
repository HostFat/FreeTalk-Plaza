//! Full-screen image view for one message. Click the image to zoom; use the
//! arrows or the keyboard to move between its images; Escape or the backdrop
//! closes it.

use crate::components::app::LIGHTBOX;
use crate::util::images::{image_object_url, request_image, ImageStatus, IMAGES};
use dioxus::prelude::*;

/// Move the open index inside the message's gallery, wrapping at both ends.
fn move_lightbox(delta: isize) {
    let mut state = LIGHTBOX.write();
    if let Some(state) = state.as_mut() {
        let len = state.images.len();
        if len > 0 {
            state.index = (state.index as isize + delta).rem_euclid(len as isize) as usize;
        }
    }
}

#[component]
pub fn Lightbox() -> Element {
    let mut zoomed = use_signal(|| false);
    let mut url = use_signal(|| None::<String>);

    // Download the open image and keep exactly one object URL alive.
    use_effect(move || {
        let state = LIGHTBOX.read().clone();
        let Some(state) = state else {
            let previous = url.peek().clone();
            if let Some(previous) = previous {
                url.set(None);
                let _ = web_sys::Url::revoke_object_url(&previous);
            }
            return;
        };
        let Some(image) = state.images.get(state.index) else {
            return;
        };
        request_image(image.instance, image.sha256);
        let bytes = IMAGES.read().get(&image.instance).and_then(|fetch| {
            if let ImageStatus::Ready(bytes) = &fetch.status {
                Some(bytes.clone())
            } else {
                None
            }
        });
        if let Some(bytes) = bytes {
            let previous = url.peek().clone();
            if let Some(created) = image_object_url(&bytes, &image.mime) {
                url.set(Some(created));
            }
            if let Some(previous) = previous {
                let _ = web_sys::Url::revoke_object_url(&previous);
            }
        }
    });
    use_drop(move || {
        let created = url.peek().clone();
        if let Some(created) = created {
            let _ = web_sys::Url::revoke_object_url(&created);
        }
    });

    let state = LIGHTBOX.read().clone();
    let Some(state) = state else {
        return rsx! {};
    };
    if state.images.is_empty() {
        return rsx! {};
    }

    let images_len = state.images.len();
    let index = state.index.min(images_len - 1);
    let current = state.images[index].clone();

    let failed_reason = IMAGES.read().get(&current.instance).and_then(|fetch| {
        if let ImageStatus::Failed(reason) = &fetch.status {
            Some(reason.clone())
        } else {
            None
        }
    });
    let close = move || *LIGHTBOX.write() = None;

    rsx! {
        div {
            class: "fixed inset-0 z-[120] bg-black/95 flex items-center justify-center p-4 overflow-auto",
            tabindex: "0",
            autofocus: true,
            onkeydown: move |event: KeyboardEvent| match event.key() {
                Key::Escape => {
                    event.prevent_default();
                    close();
                }
                Key::ArrowLeft => {
                    event.prevent_default();
                    zoomed.set(false);
                    move_lightbox(-1);
                }
                Key::ArrowRight => {
                    event.prevent_default();
                    zoomed.set(false);
                    move_lightbox(1);
                }
                _ => {}
            },
            onclick: move |_| close(),
            if let Some(created) = url.read().clone() {
                img {
                    src: "{created}",
                    alt: "{current.alt}",
                    class: if zoomed() {
                        "max-w-none cursor-zoom-out"
                    } else {
                        "max-w-full max-h-[90vh] object-contain cursor-zoom-in"
                    },
                    style: if zoomed() { "transform: scale(1.8);" } else { "" },
                    onclick: move |event: MouseEvent| {
                        event.stop_propagation();
                        zoomed.set(!zoomed());
                    },
                }
            } else {
                div { class: "flex flex-col items-center gap-3 text-white/70 text-sm",
                    if let Some(reason) = failed_reason {
                        "Image unavailable"
                        if !reason.is_empty() {
                            span { class: "text-white/50", " ({reason})" }
                        }
                    } else {
                        div { class: "animate-spin w-6 h-6 border-2 border-white/30 border-t-white rounded-full" }
                        "Loading image…"
                    }
                }
            }
            if images_len > 1 {
                button {
                    r#type: "button",
                    class: "absolute left-4 top-1/2 -translate-y-1/2 w-11 h-11 rounded-full bg-white/10 hover:bg-white/20 text-white text-2xl",
                    onclick: move |event: MouseEvent| {
                        event.stop_propagation();
                        zoomed.set(false);
                        move_lightbox(-1);
                    },
                    "‹"
                }
                span { class: "absolute bottom-5 left-1/2 -translate-x-1/2 px-3 py-1 rounded-full bg-black/60 text-white/80 text-xs",
                    "{index + 1} / {images_len}"
                }
                button {
                    r#type: "button",
                    class: "absolute right-4 top-1/2 -translate-y-1/2 w-11 h-11 rounded-full bg-white/10 hover:bg-white/20 text-white text-2xl",
                    onclick: move |event: MouseEvent| {
                        event.stop_propagation();
                        zoomed.set(false);
                        move_lightbox(1);
                    },
                    "›"
                }
            }
            button {
                r#type: "button",
                class: "absolute top-4 right-4 px-3 py-1.5 rounded-lg bg-white/10 text-white hover:bg-white/20 text-sm",
                onclick: move |_| close(),
                "✕"
            }
        }
    }
}
