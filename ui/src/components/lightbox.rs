//! Full-screen image view. Click the image to zoom, click the backdrop or
//! press Escape to close.

use crate::components::app::LIGHTBOX;
use dioxus::prelude::*;

#[component]
pub fn Lightbox() -> Element {
    let state = LIGHTBOX.read().clone();
    let Some(state) = state else {
        return rsx! {};
    };
    let mut zoomed = use_signal(|| false);

    rsx! {
        div {
            class: "fixed inset-0 z-[120] bg-black/95 flex items-center justify-center p-4 overflow-auto",
            tabindex: "0",
            autofocus: true,
            onkeydown: move |event: KeyboardEvent| {
                if event.key() == Key::Escape {
                    event.prevent_default();
                    *LIGHTBOX.write() = None;
                }
            },
            onclick: move |_| *LIGHTBOX.write() = None,
            img {
                src: "{state.src}",
                alt: "{state.alt}",
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
            button {
                r#type: "button",
                class: "absolute top-4 right-4 px-3 py-1.5 rounded-lg bg-white/10 text-white hover:bg-white/20 text-sm",
                onclick: move |_| *LIGHTBOX.write() = None,
                "✕"
            }
        }
    }
}
