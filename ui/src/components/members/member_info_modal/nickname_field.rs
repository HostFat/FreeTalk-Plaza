use crate::board_data::NicknameRequestStatus;
use crate::components::app::chat_delegate::save_boards_to_delegate;
use crate::components::app::{BOARDS, CURRENT_BOARD};
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
    let is_owner = board.is_active_owner();
    let is_admin = board
        .board_state
        .admin
        .admins
        .iter()
        .any(|admin| admin.admin.id() == viewer_id);
    // Normal members cannot change their own name; the owner and admins can,
    // for any member. The override leaves the member's own record untouched.
    let can_edit =
        !crate::components::app::view_as_member() && (is_owner || is_admin);
    let is_self = viewer_id == member_id;

    let initial_nickname = board
        .display_nickname(member_id)
        .unwrap_or_else(|| "Unknown".to_string());
    let original_nickname = initial_nickname.clone();
    let mut temp_nickname = use_signal(|| initial_nickname);
    let mut input_element = use_signal(|| None as Option<Rc<MountedData>>);
    let mut requesting = use_signal(|| false);
    let mut requested_name = use_signal(String::new);
    let pending_request = board.pending_nickname_request(member_id).cloned();
    let latest_request = board.latest_nickname_request(member_id).cloned();

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

    let send_request = {
        let current_name = original_nickname.clone();
        move |_| {
            let requested = requested_name.read().trim().to_string();
            if requested.is_empty() {
                return;
            }
            let Some(key) = CURRENT_BOARD.read().owner_key else {
                return;
            };
            BOARDS.with_mut(|boards| {
                if let Some(board) = boards.map.get_mut(&key) {
                    board.add_nickname_request(
                        member_id,
                        current_name.clone(),
                        requested,
                    );
                }
            });
            requesting.set(false);
            requested_name.set(String::new());
            crate::components::app::toasts::show(
                "Nickname request sent to the owners and admins.",
            );
            spawn_local(async {
                let _ = save_boards_to_delegate().await;
            });
        }
    };

    let decide_request = {
        let pending = pending_request.clone();
        move |approve: bool| {
            let Some(request) = pending.clone() else {
                return;
            };
            let Some(key) = CURRENT_BOARD.read().owner_key else {
                return;
            };
            if approve {
                if let Some(ctx) = ActionContext::from_current_board() {
                    let requested = request.requested_name.clone();
                    spawn_local(async move {
                        message_actions::set_nickname(ctx, member_id, requested).await;
                    });
                }
            }
            BOARDS.with_mut(|boards| {
                if let Some(board) = boards.map.get_mut(&key) {
                    board.decide_nickname_request(
                        &request.id,
                        if approve {
                            NicknameRequestStatus::Approved
                        } else {
                            NicknameRequestStatus::Rejected
                        },
                    );
                }
            });
            crate::components::app::toasts::show(if approve {
                "Nickname request approved."
            } else {
                "Nickname request rejected."
            });
            spawn_local(async {
                let _ = save_boards_to_delegate().await;
            });
        }
    };
    let decide_request = Rc::new(decide_request);

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
                if let Some(request) = pending_request.clone() {
                    div { class: "mt-2 rounded-lg border border-border bg-surface p-3",
                        p { class: "text-sm text-text",
                            "Requested nickname: "
                            span { class: "font-semibold", "{request.requested_name}" }
                        }
                        p { class: "text-xs text-text-muted mb-2", "Current: {request.current_name}" }
                        div { class: "flex gap-2",
                            button {
                                r#type: "button",
                                class: "px-3 py-1.5 text-xs rounded-lg bg-accent text-white hover:bg-accent/80",
                                onclick: {
                                    let decide = decide_request.clone();
                                    move |_| decide(true)
                                },
                                "Approve"
                            }
                            button {
                                r#type: "button",
                                class: "px-3 py-1.5 text-xs rounded-lg bg-surface border border-border text-text",
                                onclick: {
                                    let decide = decide_request.clone();
                                    move |_| decide(false)
                                },
                                "Reject"
                            }
                        }
                    }
                } else {
                    p { class: "mt-1 text-xs text-text-muted",
                        "Only owners and admins can change a nickname. The member's own record stays as it is."
                    }
                }
            } else if is_self {
                if let Some(request) = pending_request.clone() {
                    p { class: "mt-2 text-xs text-text-muted",
                        "Pending request: "
                        span { class: "font-medium text-text", "{request.requested_name}" }
                    }
                } else if let Some(request) = latest_request.clone() {
                    p { class: "mt-2 text-xs text-text-muted",
                        "Last request {status_label(request.status)}: "
                        span { class: "text-text", "{request.requested_name}" }
                    }
                }
                if !requesting() {
                    div { class: "mt-2 flex items-center gap-2",
                        button {
                            r#type: "button",
                            class: "px-3 py-1.5 text-xs rounded-lg bg-surface hover:bg-surface-hover text-text border border-border",
                            title: "Ask the owners and admins for a nickname",
                            onclick: move |_| {
                                requested_name.set(String::new());
                                requesting.set(true);
                            },
                            "Request change"
                        }
                        span { class: "text-xs text-text-muted",
                            "Nicknames are set by the board owner and admins."
                        }
                    }
                } else {
                    div { class: "mt-2 flex items-center gap-2",
                        input {
                            class: "flex-1 px-3 py-1.5 text-sm bg-surface border border-border rounded-lg text-text",
                            placeholder: "New nickname",
                            value: "{requested_name}",
                            oninput: move |event| requested_name.set(event.value()),
                        }
                        button {
                            r#type: "button",
                            class: "px-3 py-1.5 text-xs rounded-lg bg-accent text-white hover:bg-accent/80",
                            onclick: send_request,
                            "Send"
                        }
                        button {
                            r#type: "button",
                            class: "px-3 py-1.5 text-xs rounded-lg bg-surface border border-border text-text",
                            onclick: move |_| requesting.set(false),
                            "Cancel"
                        }
                    }
                }
            }
        }
    }
}

fn status_label(status: NicknameRequestStatus) -> &'static str {
    match status {
        NicknameRequestStatus::Pending => "pending",
        NicknameRequestStatus::Approved => "approved",
        NicknameRequestStatus::Rejected => "rejected",
    }
}
