//! Playwright test hooks for the `example-data` build.
//!
//! Exposes `window.__plazaTest` with a few state mutations that would
//! otherwise need a node, a delegate or a long UI sequence. Compiled only with
//! the `example-data` feature and installed once per page.

#![cfg(feature = "example-data")]

use crate::board_data::NotificationMode;
use crate::components::app::{BOARDS, BOARDS_LOADED, CURRENT_BOARD};
use dioxus::prelude::*;
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
pub fn install() {
    use js_sys::Reflect;

    let Some(window) = web_sys::window() else {
        return;
    };
    if Reflect::has(&window, &JsValue::from_str("__plazaTest")).unwrap_or(false) {
        return;
    }

    let api = js_sys::Object::new();

    let set_mode = Closure::wrap(Box::new(|value: JsValue| {
        let mode = NotificationMode::from_str(&value.as_string().unwrap_or_default());
        let key = CURRENT_BOARD.read().owner_key;
        crate::util::defer(move || {
            if let Some(key) = key {
                BOARDS.with_mut(|boards| {
                    if let Some(board) = boards.map.get_mut(&key) {
                        board.notification_mode = mode;
                    }
                });
            }
        });
    }) as Box<dyn FnMut(JsValue)>);
    let _ = Reflect::set(&api, &"setNotificationMode".into(), set_mode.as_ref());
    set_mode.forget();

    let set_loaded = Closure::wrap(Box::new(|value: JsValue| {
        let loaded = value.as_bool().unwrap_or(false);
        crate::util::defer(move || *BOARDS_LOADED.write() = loaded);
    }) as Box<dyn FnMut(JsValue)>);
    let _ = Reflect::set(&api, &"setBoardsLoaded".into(), set_loaded.as_ref());
    set_loaded.forget();

    let clear = Closure::wrap(Box::new(|_value: JsValue| {
        crate::util::defer(move || {
            BOARDS.with_mut(|boards| {
                boards.map.clear();
                boards.current_board_key = None;
            });
            *BOARDS_LOADED.write() = false;
            *CURRENT_BOARD.write() = crate::board_data::CurrentBoard { owner_key: None };
        });
    }) as Box<dyn FnMut(JsValue)>);
    let _ = Reflect::set(&api, &"clearBoards".into(), clear.as_ref());
    clear.forget();

    let archive = Closure::wrap(Box::new(|index: JsValue, archived: JsValue| {
        let index = index.as_f64().unwrap_or(-1.0) as usize;
        let archived = archived.as_bool().unwrap_or(false);
        crate::util::defer(move || {
            let key = BOARDS.read().ordered_keys().get(index).copied();
            if let Some(key) = key {
                BOARDS.with_mut(|boards| boards.set_archived(key, archived));
            }
        });
    }) as Box<dyn FnMut(JsValue, JsValue)>);
    let _ = Reflect::set(&api, &"archiveBoard".into(), archive.as_ref());
    archive.forget();

    let reorder = Closure::wrap(Box::new(|index: JsValue, delta: JsValue| {
        let index = index.as_f64().unwrap_or(-1.0) as usize;
        let delta = delta.as_f64().unwrap_or(0.0) as isize;
        crate::util::defer(move || {
            let key = BOARDS.read().ordered_keys().get(index).copied();
            if let Some(key) = key {
                BOARDS.with_mut(|boards| boards.move_board(key, delta));
            }
        });
    }) as Box<dyn FnMut(JsValue, JsValue)>);
    let _ = Reflect::set(&api, &"moveBoard".into(), reorder.as_ref());
    reorder.forget();

    let notify = Closure::wrap(Box::new(|title: JsValue, body: JsValue| {
        crate::components::system_notifications::show_notification(
            &title.as_string().unwrap_or_default(),
            &body.as_string().unwrap_or_default(),
            "plaza-test",
            "test-board",
            "test-post",
        );
    }) as Box<dyn FnMut(JsValue, JsValue)>);
    let _ = Reflect::set(&api, &"notify".into(), notify.as_ref());
    notify.forget();

    let names = Closure::wrap(Box::new(|| -> JsValue {
        let boards = BOARDS.read();
        let result = js_sys::Array::new();
        for key in boards.ordered_keys() {
            let Some(board) = boards.map.get(&key) else {
                continue;
            };
            let name = crate::util::ecies::unseal_bytes_with_secrets(
                &board.board_state.configuration.configuration.display.name,
                &board.secrets,
            )
            .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
            .unwrap_or_else(|_| {
                bs58::encode(key.as_bytes()).into_string()
            });
            let entry = js_sys::Array::new();
            entry.push(&JsValue::from_str(&name));
            entry.push(&JsValue::from_bool(boards.is_archived(key)));
            result.push(&entry);
        }
        result.into()
    }) as Box<dyn FnMut() -> JsValue>);
    let _ = Reflect::set(&api, &"boardNames".into(), names.as_ref());
    names.forget();

    let _ = Reflect::set(&window, &JsValue::from_str("__plazaTest"), &api);
}

#[cfg(not(target_arch = "wasm32"))]
pub fn install() {}
