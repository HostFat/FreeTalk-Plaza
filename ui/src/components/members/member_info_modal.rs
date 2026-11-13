pub mod ban_button;
mod invited_by_field;
mod nickname_field;

use crate::components::app::{BOARDS, CURRENT_BOARD, MEMBER_INFO_MODAL};
use crate::components::members::member_info_modal::ban_button::BanButton;
use crate::components::members::member_info_modal::invited_by_field::InvitedByField;
use crate::components::members::member_info_modal::nickname_field::NicknameField;
use crate::util::ecies::unseal_bytes_with_secrets;
use crate::util::format_utc_as_local_time;
use crate::util::member_moderation as member_actions;
use crate::util::message_actions::ActionContext;
use dioxus::logger::tracing::*;
use dioxus::prelude::*;
use plaza_core::board_state::member::MemberId;
use plaza_core::board_state::reports::ReportReason;
use plaza_core::board_state::ChatBoardParametersV1;

#[component]
pub fn MemberInfoModal() -> Element {
    // Memos
    let current_board_data_signal = use_memo(move || {
        CURRENT_BOARD
            .read()
            .owner_key
            .as_ref()
            .and_then(|key| BOARDS.read().map.get(key).cloned())
    });
    let self_member_id: Memo<Option<MemberId>> = use_memo(move || {
        BOARDS
            .read()
            .map
            .get(&CURRENT_BOARD.read().owner_key?)
            .map(|r| MemberId::from(&r.self_sk.verifying_key()))
    });

    // Memoized values
    let owner_key_signal = use_memo(move || CURRENT_BOARD.read().owner_key);

    // This component is mounted unconditionally in app.rs, so anything returned
    // while the modal is closed becomes part of the page layout. Every other
    // modal returns an empty tree when idle; do the same here. All hooks above
    // have run, so the hook order stays stable.
    if MEMBER_INFO_MODAL.read().member.is_none() {
        return rsx! {};
    }

    // Event handlers
    let handle_close_modal = {
        move |_| {
            MEMBER_INFO_MODAL.with_mut(|signal| {
                signal.member = None;
            });
        }
    };

    // Board state - create a longer-lived binding
    let current_board_data = current_board_data_signal.read();
    let board_state = match current_board_data.as_ref() {
        Some(state) => state,
        None => {
            // The modal is open but the board state is not in memory yet: show
            // the message inside a real dialog instead of dumping a bare div
            // into the page flow.
            return rsx! {
                div { class: "fixed inset-0 z-50 flex items-center justify-center",
                    div { class: "absolute inset-0 bg-black/50", onclick: handle_close_modal }
                    div { class: "relative bg-surface border border-border rounded-lg p-4 text-text-muted",
                        "Board state not available"
                    }
                }
            };
        }
    };

    // Extract member info and members list
    let member_info_list = &board_state.board_state.member_info.member_info;
    let members_list = &board_state.board_state.members.members;

    let modal_content = if let Some(member_id) = MEMBER_INFO_MODAL.read().member {
        // Find the AuthorizedMemberInfo for the given member_id
        let member_info = match member_info_list
            .iter()
            .find(|mi| mi.member_info.member_id == member_id)
        {
            Some(mi) => mi,
            None => {
                error!("Member info not found for member {member_id}");
                return rsx! {
                    div {
                        class: "p-4 bg-red-500/10 border border-red-500/20 rounded-lg text-red-400",
                        "Member information is missing or corrupted"
                    }
                };
            }
        };

        // Try to find the AuthorizedMember for the given member_id
        let member = members_list.iter().find(|m| m.member.id() == member_id);

        // Determine if the member is the board owner
        let is_owner = owner_key_signal
            .as_ref()
            .is_some_and(|k| MemberId::from(&*k) == member_id);

        // Determine if the member is an admin
        let is_admin = board_state
            .board_state
            .admin
            .admins
            .iter()
            .any(|a| a.admin.id() == member_id);

        // Only show error if member isn't found AND isn't the owner
        if member.is_none() && !is_owner {
            error!("Member {member_id} not found in members list and is not owner");
            return rsx! {
                div {
                    class: "p-4 bg-red-500/10 border border-red-500/20 rounded-lg text-red-400",
                    "Member not found in board members list"
                }
            };
        }

        // Determine if the current user can ban this member
        let is_downstream = member
            .and_then(|m| {
                owner_key_signal.as_ref().map(|owner| {
                    let params = ChatBoardParametersV1 { owner: *owner };
                    // Get the invite chain for this member
                    let invite_chain = board_state.board_state.members.get_invite_chain(m, &params);

                    let self_member_id =
                        self_member_id().expect("Self member ID should be available");

                    // Check if current user is an admin
                    let is_self_admin = board_state
                        .board_state
                        .admin
                        .admins
                        .iter()
                        .any(|a| a.admin.id() == self_member_id);

                    // Member can be banned if:
                    // 1. Current user is owner (owner can ban anyone), or
                    // 2. Current user is admin (admins can ban anyone), or
                    // 3. Current user appears in their invite chain (upstream of target)
                    invite_chain.is_ok_and(|chain| {
                        self_member_id == CURRENT_BOARD.read().owner_id().unwrap()
                            || is_self_admin
                            || chain.iter().any(|m| m.member.id() == self_member_id)
                    })
                })
            })
            .unwrap_or(false);

        info!(
            "Rendering MemberInfoModal for member_id: {:?} is_owner: {:?} is_downstream: {:?}",
            member_id, is_owner, is_downstream
        );

        // Get the inviter's nickname and ID
        let (invited_by, inviter_id) = match (member, is_owner) {
            (_, true) => ("N/A (Board Owner)".to_string(), None),
            (Some(m), false) => {
                let inviter_id = m.member.invited_by;
                let nickname = member_info_list
                    .iter()
                    .find(|mi| mi.member_info.member_id == inviter_id)
                    .map(|mi| {
                        match unseal_bytes_with_secrets(
                            &mi.member_info.preferred_nickname,
                            &board_state.secrets,
                        ) {
                            Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
                            Err(_) => mi.member_info.preferred_nickname.to_string_lossy(),
                        }
                    })
                    .unwrap_or_else(|| "Unknown".to_string());
                (nickname, Some(inviter_id))
            }
            _ => ("Unknown".to_string(), None),
        };

        // Get the member ID string to display
        let member_id_str = member_id.to_string();

        rsx! {
            // Modal backdrop
            div {
                class: "fixed inset-0 z-50 flex items-center justify-center",
                tabindex: "0",
                onmounted: move |cx| {
                    let element = cx.data();
                    wasm_bindgen_futures::spawn_local(async move {
                        let _ = element.set_focus(true).await;
                    });
                },
                onkeydown: move |evt: KeyboardEvent| {
                    if evt.key() == Key::Escape || evt.key() == Key::Enter {
                        evt.prevent_default();
                        MEMBER_INFO_MODAL.with_mut(|signal| {
                            signal.member = None;
                        });
                    }
                },
                // Overlay
                div {
                    class: "absolute inset-0 bg-black/50",
                    onclick: handle_close_modal
                }
                // Modal content
                div {
                    class: "relative z-10 w-full max-w-md mx-4 bg-panel rounded-xl shadow-xl border border-border",
                    div {
                        class: "p-6",
                        h1 { class: "text-xl font-semibold text-text mb-4", "Member Info" }

                        // Show tags for owner, self, and relationships
                        div { class: "flex flex-wrap gap-2 mb-4",
                            if is_owner {
                                span {
                                    class: "inline-flex items-center px-2.5 py-0.5 rounded-full text-sm font-medium bg-blue-500/20 text-blue-400",
                                    "👑 Board Owner"
                                }
                            } else if is_admin {
                                span {
                                    class: "inline-flex items-center px-2.5 py-0.5 rounded-full text-sm font-medium bg-purple-500/20 text-purple-400",
                                    "👑 Admin"
                                }
                            }
                            if member_id == self_member_id.unwrap() {
                                span {
                                    class: "inline-flex items-center px-2.5 py-0.5 rounded-full text-sm font-medium bg-cyan-500/20 text-cyan-400",
                                    "⭐ You"
                                }
                            }
                            if is_downstream {
                                span {
                                    class: "inline-flex items-center px-2.5 py-0.5 rounded-full text-sm font-medium bg-green-500/20 text-green-400",
                                    "🔑 Invited by You"
                                }
                            }
                            // Check if this member invited the current user
                            if let Some(self_member) = members_list.iter().find(|m| m.member.id() == self_member_id.unwrap()) {
                                if self_member.member.invited_by == member_id {
                                    span {
                                        class: "inline-flex items-center px-2.5 py-0.5 rounded-full text-sm font-medium bg-yellow-500/20 text-yellow-400",
                                        "🎪 Invited You"
                                    }
                                }
                            }
                        }

                        NicknameField {
                            member_info: member_info.clone()
                        }

                        div {
                            class: "mb-4",
                            label { class: "block text-sm font-medium text-text-muted mb-2", "Member ID" }
                            input {
                                class: "w-full px-3 py-2 bg-surface border border-border rounded-lg text-text font-mono text-sm",
                                value: "{member_id_str}",
                                readonly: true
                            }
                        }

                        if !is_owner {
                            InvitedByField {
                                invited_by: invited_by.clone(),
                                inviter_id: inviter_id,
                            }

                            // Check if member is downstream of current user
                            {
                                let _current_user_id = {
                                    current_board_data_signal.read().as_ref()
                                        .map(|r| r.self_sk.verifying_key())
                                        .map(|k| MemberId::from(&k))
                                };

                                rsx! {
                                    button {
                                        r#type: "button",
                                        class: "mt-3 mr-2 px-3 py-1.5 bg-surface hover:bg-surface-hover text-text text-sm rounded-lg",
                                        onclick: move |_| {
                                            let board = CURRENT_BOARD
                                                .read()
                                                .owner_key
                                                .map(|key| bs58::encode(key.as_bytes()).into_string())
                                                .unwrap_or_default();
                                            let target = format!(
                                                "/board/{board}/member/{}",
                                                member_id.0 .0
                                            );
                                            MEMBER_INFO_MODAL.with_mut(|signal| signal.member = None);
                                            if let Some(window) = web_sys::window() {
                                                let _ = window.location().set_hash(&target);
                                            }
                                        },
                                        "View profile"
                                    }
                                    BanButton {
                                        member_to_ban: member_id,
                                        show_trigger: is_downstream,
                                        nickname: member_info.member_info.preferred_nickname.clone()
                                    }
                                    ""
                                }
                            }

                            if member_id != self_member_id().unwrap_or(member_id) {
                                MemberModerationPanel {
                                    member_id: member_id,
                                    is_owner: is_owner,
                                }
                            }
                        }
                    }
                    // Close button
                    button {
                        class: "absolute top-3 right-3 p-1 text-text-muted hover:text-text transition-colors",
                        onclick: handle_close_modal,
                        "✕"
                    }
                }
            }
        }
    } else {
        rsx! {}
    };

    modal_content
}

#[component]
fn MemberModerationPanel(member_id: MemberId, is_owner: bool) -> Element {
    let board = use_memo(move || {
        CURRENT_BOARD
            .read()
            .owner_key
            .and_then(|key| BOARDS.read().map.get(&key).cloned())
    });
    let mut reason_index = use_signal(|| 0usize);
    let mut error = use_signal(|| None::<String>);
    let reasons = [
        ReportReason::Spam,
        ReportReason::Abuse,
        ReportReason::OffTopic,
        ReportReason::Illegal,
        ReportReason::Other,
    ];

    let Some(board) = board.read().clone() else {
        return rsx! {};
    };
    if is_owner {
        return rsx! {};
    }
    let self_id = MemberId::from(&board.self_sk.verifying_key());
    let owner_id = MemberId::from(&board.owner_vk);
    let can_moderate = self_id == owner_id
        || board
            .board_state
            .admin
            .admins
            .iter()
            .any(|admin| admin.admin.id() == self_id);
    if !can_moderate {
        return rsx! {};
    }

    let now = chrono::Utc::now().timestamp_millis();
    let active_until = board.board_state.suspensions.active_until(member_id, now);
    let warnings = board.board_state.warnings.for_member(member_id);

    rsx! {
        div { class: "mt-3 border-t border-border pt-3 space-y-2",
            div { class: "flex flex-wrap items-center gap-2 text-xs",
                span { class: "text-text-muted", "Reason" }
                select {
                    class: "px-2 py-1 bg-panel border border-border rounded text-text",
                    value: "{*reason_index.read()}",
                    onchange: move |evt| {
                        if let Ok(index) = evt.value().parse::<usize>() {
                            reason_index.set(index);
                        }
                    },
                    for (index, reason) in reasons.iter().enumerate() {
                        option { value: "{index}", "{reason.label()}" }
                    }
                }
                button {
                    r#type: "button",
                    class: "px-2 py-1 bg-surface hover:bg-surface-hover text-text rounded",
                    onclick: move |_| {
                        let reason = reasons
                            .get(*reason_index.read())
                            .copied()
                            .unwrap_or(ReportReason::Other);
                        if let Some(ctx) = ActionContext::from_current_board() {
                            match member_actions::warn_member(&ctx, member_id, reason) {
                                Ok(()) => error.set(None),
                                Err(e) => error.set(Some(e)),
                            }
                        }
                    },
                    "Warn"
                }
                if let Some(until) = active_until {
                    span { class: "text-amber-400",
                        "Suspended until {format_utc_as_local_time(until)}"
                    }
                    button {
                        r#type: "button",
                        class: "px-2 py-1 bg-surface hover:bg-surface-hover text-text rounded",
                        onclick: move |_| {
                            if let Some(ctx) = ActionContext::from_current_board() {
                                match member_actions::lift_suspension(&ctx, member_id) {
                                    Ok(()) => error.set(None),
                                    Err(e) => error.set(Some(e)),
                                }
                            }
                        },
                        "Lift"
                    }
                } else {
                    for days in [1i64, 7, 30] {
                        button {
                            r#type: "button",
                            class: "px-2 py-1 bg-surface hover:bg-surface-hover text-red-400 rounded",
                            onclick: move |_| {
                                let reason = reasons
                                    .get(*reason_index.read())
                                    .copied()
                                    .unwrap_or(ReportReason::Other);
                                if let Some(ctx) = ActionContext::from_current_board() {
                                    match member_actions::suspend_member(&ctx, member_id, reason, days) {
                                        Ok(()) => error.set(None),
                                        Err(e) => error.set(Some(e)),
                                    }
                                }
                            },
                            "Suspend {days}d"
                        }
                    }
                }
            }
            if let Some(message) = error.read().as_ref() {
                p { class: "text-xs text-red-400", "{message}" }
            }
            if warnings.is_empty() {
                p { class: "text-xs text-text-muted", "No warnings." }
            } else {
                div { class: "space-y-1",
                    for warning in warnings.iter() {
                        p { class: "text-xs text-text-muted",
                            "{warning.warning.reason.label()} · {format_utc_as_local_time(warning.warning.created_at)}"
                        }
                    }
                }
            }
        }
    }
}
