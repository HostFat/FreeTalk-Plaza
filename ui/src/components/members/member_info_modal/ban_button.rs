use crate::components::app::{mark_needs_sync, BOARDS, CURRENT_BOARD, MEMBER_INFO_MODAL};
use crate::util::get_current_system_time;
use dioxus::logger::tracing::{error, info};
use dioxus::prelude::*;
use freenet_scaffold::ComposableState;
use plaza_core::board_state::ban::{AuthorizedUserBan, UserBan};
use plaza_core::board_state::member::MemberId;
use plaza_core::board_state::{ChatBoardParametersV1, ChatBoardStateV1Delta};
use wasm_bindgen_futures::spawn_local;

/// Ban a member and, on a private board owned by us, rotate the board secret.
pub async fn ban_member(member_to_ban: MemberId) -> Result<(), String> {
    let (current_board, board_data) = {
        let current = CURRENT_BOARD.read().owner_key.ok_or("No board selected")?;
        let boards = BOARDS.read();
        let data = boards.map.get(&current).ok_or("Board not found")?.clone();
        (current, data)
    };

    let board_key = board_data.board_key();
    let self_sk = board_data.self_sk.clone();
    let board_state_clone = board_data.board_state.clone();
    let banned_by = MemberId::from(&self_sk.verifying_key());
    let params = ChatBoardParametersV1 {
        owner: current_board,
    };

    let ban = UserBan {
        owner_member_id: MemberId::from(&current_board),
        banned_at: get_current_system_time(),
        banned_user: member_to_ban,
    };

    let mut ban_bytes = Vec::new();
    ciborium::ser::into_writer(&ban, &mut ban_bytes)
        .map_err(|e| format!("Failed to serialize ban for signing: {:?}", e))?;

    let signature = crate::signing::sign_ban_with_fallback(board_key, ban_bytes, &self_sk).await;
    let authorized_ban = AuthorizedUserBan::with_signature(ban, banned_by, signature);
    let delta = ChatBoardStateV1Delta {
        bans: Some(vec![authorized_ban]),
        ..Default::default()
    };

    let mut apply_error: Option<String> = None;
    BOARDS.with_mut(|boards| {
        let Some(data) = boards.map.get_mut(&current_board) else {
            return;
        };
        if let Err(e) = data
            .board_state
            .apply_delta(&board_state_clone, &params, &Some(delta))
        {
            apply_error = Some(format!("Failed to apply ban: {:?}", e));
            return;
        }
        info!(
            "Successfully applied ban delta for member {:?}",
            member_to_ban
        );

        // On a private board, rotate the secret so the banned member cannot
        // decrypt messages sent after the ban.
        if data.is_private() && data.owner_vk == data.self_sk.verifying_key() {
            match data.rotate_secret() {
                Ok(secrets_delta) => {
                    let current_state = data.board_state.clone();
                    let rotation_delta = ChatBoardStateV1Delta {
                        secrets: Some(secrets_delta),
                        ..Default::default()
                    };
                    if let Err(e) =
                        data.board_state
                            .apply_delta(&current_state, &params, &Some(rotation_delta))
                    {
                        apply_error = Some(format!("Failed to apply secret rotation: {:?}", e));
                    }
                }
                Err(e) => error!("Failed to rotate secret after ban: {}", e),
            }
        }
    });

    if let Some(e) = apply_error {
        return Err(e);
    }
    mark_needs_sync(current_board);
    info!("Marked board for synchronization after ban");
    Ok(())
}

#[component]
pub fn BanButton(
    member_to_ban: MemberId,
    /// Whether to render the trigger. The member modal hides it for members
    /// that are not downstream of the viewer.
    #[props(default = true)]
    show_trigger: bool,
    nickname: String,
) -> Element {
    let mut show_confirmation = use_signal(|| false);

    let execute_ban = move |_| {
        // Close the member modal immediately for better UX
        MEMBER_INFO_MODAL.with_mut(|modal| {
            modal.member = None;
        });
        spawn_local(async move {
            if let Err(e) = ban_member(member_to_ban).await {
                error!("Failed to ban member: {}", e);
            }
        });
    };

    if show_trigger {
        rsx! {
            div { class: "mt-4",
                button {
                    class: "px-4 py-2 bg-red-500 hover:bg-red-600 text-white font-medium rounded-lg transition-colors",
                    onclick: move |_| show_confirmation.set(true),
                    "Ban User"
                }

                if *show_confirmation.read() {
                    // Confirmation modal
                    div {
                        class: "fixed inset-0 z-50 flex items-center justify-center",
                        // Overlay
                        div {
                            class: "absolute inset-0 bg-black/50",
                            onclick: move |_| show_confirmation.set(false)
                        }
                        // Modal content
                        div {
                            class: "relative z-10 w-full max-w-md mx-4 bg-panel rounded-xl shadow-xl border border-border",
                            // Header
                            div {
                                class: "px-6 py-4 border-b border-border flex items-center justify-between",
                                h2 { class: "text-lg font-semibold text-text", "Confirm Ban" }
                                button {
                                    class: "p-1 text-text-muted hover:text-text transition-colors",
                                    onclick: move |_| show_confirmation.set(false),
                                    "✕"
                                }
                            }

                            // Body
                            div {
                                class: "px-6 py-4",
                                p { class: "text-text",
                                    "Are you sure you want to ban "
                                    span { class: "font-semibold", "{nickname}" }
                                    " (ID: "
                                    code { class: "text-sm bg-surface px-1 rounded", "{member_to_ban}" }
                                    ")? This action cannot be undone."
                                }
                            }

                            // Footer
                            div {
                                class: "px-6 py-4 border-t border-border flex justify-end gap-3",
                                button {
                                    class: "px-4 py-2 bg-surface hover:bg-surface-hover text-text rounded-lg transition-colors",
                                    onclick: move |_| show_confirmation.set(false),
                                    "Cancel"
                                }
                                button {
                                    class: "px-4 py-2 bg-red-500 hover:bg-red-600 text-white font-medium rounded-lg transition-colors",
                                    onclick: execute_ban,
                                    "Yes, Ban User"
                                }
                            }
                        }
                    }
                }
            }
        }
    } else {
        rsx! { "" }
    }
}
