//! Document-level click delegation for invite links in message HTML.
//!
//! Following a `#/join/<token>` anchor normally reloads the gateway frame and
//! loses the open topic and composer. Intercept same-origin invite anchors and
//! route them through the SPA instead.

use crate::components::app::INTERCEPTED_JOIN_TOKEN;
use crate::util::access::token_from_input;
use dioxus::logger::tracing::warn;
use std::sync::atomic::{AtomicBool, Ordering};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

static INSTALLED: AtomicBool = AtomicBool::new(false);

/// Idempotent: installs one listener per page load.
pub fn install_invite_click_interceptor() {
    if INSTALLED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }

    let callback = Closure::wrap(Box::new(move |event: web_sys::Event| {
        if let Some(mouse) = event.dyn_ref::<web_sys::MouseEvent>() {
            if mouse.button() != 0
                || mouse.ctrl_key()
                || mouse.meta_key()
                || mouse.shift_key()
                || mouse.alt_key()
            {
                return;
            }
        }

        let Some(target) = event.target() else {
            return;
        };
        let mut node = target.dyn_into::<web_sys::Element>().ok();
        while let Some(element) = node {
            if element.tag_name().eq_ignore_ascii_case("a") {
                let Ok(anchor) = element.dyn_into::<web_sys::HtmlAnchorElement>() else {
                    return;
                };
                let href = anchor.href();
                let Some(location) = web_sys::window().map(|window| window.location()) else {
                    return;
                };
                let Ok(origin) = location.origin() else {
                    return;
                };
                // Foreign gateway links are left alone: joining them on this
                // node is not what the link means.
                if !href.starts_with(&origin) {
                    return;
                }
                if !href.contains("/join/") {
                    return;
                }
                let token = token_from_input(&href);
                if token.is_empty() {
                    return;
                }
                event.prevent_default();
                event.stop_propagation();
                crate::util::defer(move || {
                    INTERCEPTED_JOIN_TOKEN.with_mut(|slot| *slot = Some(token));
                });
                return;
            }
            node = element.parent_element();
        }
    }) as Box<dyn FnMut(web_sys::Event)>);

    if let Some(document) = web_sys::window().and_then(|window| window.document()) {
        if let Err(error) =
            document.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref())
        {
            warn!("invite click interceptor failed: {error:?}");
            INSTALLED.store(false, Ordering::SeqCst);
            return;
        }
        callback.forget();
    }
}
