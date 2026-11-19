//! Document-level click delegation for `@mention` chips.
//!
//! Chips live inside message HTML injected with `dangerous_inner_html`, so
//! Dioxus cannot put an `onclick` on them. Walk up from the click target to
//! the nearest `[data-member-id]` and open the member-info modal.

use crate::components::app::MEMBER_INFO_MODAL;
use dioxus::logger::tracing::warn;
use plaza_core::board_state::member::MemberId;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

static INSTALLED: AtomicBool = AtomicBool::new(false);

/// Idempotent: installs one listener per page load.
pub fn install_mention_click_interceptor() {
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
            if let Some(id) = element.get_attribute("data-member-id") {
                if let Ok(member_id) = MemberId::from_str(&id) {
                    event.prevent_default();
                    event.stop_propagation();
                    crate::util::defer(move || {
                        MEMBER_INFO_MODAL.with_mut(|signal| {
                            signal.member = Some(member_id);
                        });
                    });
                }
                return;
            }
            node = element.parent_element();
        }
    }) as Box<dyn FnMut(web_sys::Event)>);

    if let Some(document) = web_sys::window().and_then(|window| window.document()) {
        if let Err(error) =
            document.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref())
        {
            warn!("mention click interceptor failed: {error:?}");
            INSTALLED.store(false, Ordering::SeqCst);
            return;
        }
        callback.forget();
    }
}
