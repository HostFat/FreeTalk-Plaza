use crate::components::app::{BOARDS, COMPOSE_REQUEST, CURRENT_BOARD};
use crate::util::message_actions::{self, ActionContext};
use dioxus::prelude::*;
use dioxus_free_icons::icons::fa_solid_icons::FaPencil;
use dioxus_free_icons::Icon;
use plaza_core::board_state::member::MemberId;
use plaza_core::board_state::member_info::AuthorizedMemberInfo;
use std::rc::Rc;
use wasm_bindgen_futures::spawn_local;

#[component]
pub fn NicknameField(member_info: AuthorizedMemberInfo) -> Element {
    let member_id = member_info.member_info.member_id;

    let board = CURRENT_BOARD
        .read()
        .owner_key
        .and_then(|key| BOARDS.read().map.get(&key).cloned());

    let Some(board) = board else {
        return rsx! {};
    };

    let viewer_id = MemberId::from(&board.self_sk.verifying_key());
    let is_owner = board.is_current_owner();
    let is_admin = board
        .board_state
        .admin
        .admins
        .iter()
        .any(|admin| admin.admin.id() == viewer_id);
    // Normal members cannot change their own name; the owner and admins can,
    // for any member. The override leaves the member's own record untouched.
    let can_edit = is_owner || is_admin;
    let is_self = viewer_id == member_id;

    let initial_nickname = board
        .display_nickname(member_id)
        .unwrap_or_else(|| "Unknown".to_string());
    let original_nickname = initial_nickname.clone();
    let mut temp_nickname = use_signal(|| initial_nickname);
    let mut input_element = use_signal(|| None as Option<Rc<MountedData>>);

    let saved_nickname = original_nickname.clone();
    let save_changes = move |new_value: String| {
        let trimmed = new_value.trim().to_string();
        if trimmed.is_empty() || trimmed == saved_nickname {
            return;
        }
        let Some(ctx) = ActionContext::from_current_board() else {
            return;
        };
        spawn_local(async move {
            message_actions::set_nickname(ctx, member_id, trimmed).await;
        });
    };

    let request_change = move |_| {
        let request_title = "Nickname change request".to_string();
        let current = original_nickname.clone();
        let request_text = format!(
            "Could an owner or admin change my nickname? Current name: {current}.\nRequested name: "
        );
        if crate::util::drafts::store(&request_title, &request_text, None) {
            crate::util::drafts::persist();
        }
        *COMPOSE_REQUEST.write() += 1;
    };

    let on_input = move |evt: dioxus_core::Event<FormData>| {
        temp_nickname.set(evt.value().clone());
    };

    let save_on_blur = save_changes.clone();
    let on_blur = move |_| {
        if can_edit {
            save_on_blur(temp_nickname());
        }
    };

    let on_keydown = move |evt: dioxus_core::Event<KeyboardData>| {
        if evt.key() == Key::Enter {
            if can_edit {
                save_changes(temp_nickname());
            }
            if let Some(element) = input_element() {
                wasm_bindgen_futures::spawn_local(async move {
                    let _ = element.set_focus(false).await;
                });
            }
        }
    };

    rsx! {
        div { class: "mb-4",
            label { class: "block text-sm font-medium text-text-muted mb-2", "Nickname" }
            div {
                class: "relative",
                input {
                    class: "w-full px-3 py-2 bg-surface border border-border rounded-lg text-text placeholder-text-muted focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent",
                    value: "{temp_nickname}",
                    readonly: !can_edit,
                    oninput: on_input,
                    onblur: on_blur,
                    onkeydown: on_keydown,
                    onmounted: move |cx| input_element.set(Some(cx.data())),
                }
                if can_edit {
                    span {
                        class: "absolute right-3 top-1/2 -translate-y-1/2 text-text-muted",
                        Icon { icon: FaPencil, width: 14, height: 14 }
                    }
                }
            }
            if can_edit {
                p { class: "mt-1 text-xs text-text-muted",
                    "Only owners and admins can change a nickname. The member's own record stays as it is."
                }
            } else if is_self {
                div { class: "mt-2 flex items-center gap-2",
                    button {
                        r#type: "button",
                        class: "px-3 py-1.5 text-xs rounded-lg bg-surface hover:bg-surface-hover text-text border border-border",
                        title: "Open a message to the owners and admins with your request",
                        onclick: request_change,
                        "Request change"
                    }
                    span { class: "text-xs text-text-muted",
                        "Nicknames are set by the board owner and admins."
                    }
                }
            }
        }
    }
}
