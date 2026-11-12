//! Admin management view for viewing and adding admins.

mod add_admin_modal;

use add_admin_modal::AddAdminModal;

use crate::board_data::BoardData;
use crate::components::access_section::{InviteLinksSection, RolesSection};
use crate::components::app::{BOARDS, CURRENT_BOARD, EDIT_BOARD_MODAL};
use crate::components::members::member_info_modal::ban_button::BanButton;
use dioxus::prelude::*;
use plaza_core::board_state::member::MemberId;
use wasm_bindgen_futures::spawn_local;

#[component]
pub fn AdminView(#[props(default)] tab: String) -> Element {
    /// Tabs live in the URL so a refresh lands on the same one.
    fn navigate_admin_tab(board_id: &str, tab: &str) {
        let path = match tab {
            "bans" => format!("/board/{board_id}/admin/banned"),
            "roles" => format!("/board/{board_id}/admin/roles"),
            "links" => format!("/board/{board_id}/admin/links"),
            _ => format!("/board/{board_id}/admin"),
        };
        if let Some(win) = web_sys::window() {
            let _ = win.location().set_hash(&path);
        }
    }
    let current_board_data: Memo<Option<BoardData>> = use_memo(move || {
        CURRENT_BOARD
            .read()
            .owner_key
            .as_ref()
            .and_then(|key| BOARDS.read().map.get(key).cloned())
    });

    let active = if tab.is_empty() {
        "admins".to_string()
    } else {
        tab.clone()
    };
    let board_id_for_tabs = CURRENT_BOARD
        .read()
        .owner_key
        .map(|key| bs58::encode(key.as_bytes()).into_string())
        .unwrap_or_default();

    let mut show_add_admin_modal = use_signal(|| false);
    let mut admin_error = use_signal(|| None::<String>);
    let mut ban_index = use_signal(|| 0usize);

    // Check if current user is the owner
    let is_owner = use_memo(move || {
        current_board_data
            .read()
            .as_ref()
            .map_or(false, |board_data| {
                board_data.owner_vk == board_data.self_sk.verifying_key()
            })
    });

    // Get list of current admins
    let admins = use_memo(move || {
        current_board_data
            .read()
            .as_ref()
            .map(|board_data| board_data.board_state.admin.admins.clone())
            .unwrap_or_default()
    });

    // Get list of banned users
    let banned_users = use_memo(move || {
        current_board_data
            .read()
            .as_ref()
            .map(|board_data| board_data.board_state.bans.0.clone())
            .unwrap_or_default()
    });

    // Members that can still be banned: everyone except the owner and the
    // already-banned users.
    let ban_candidates = use_memo(move || {
        current_board_data
            .read()
            .as_ref()
            .map(|board_data| {
                let owner_id = MemberId::from(&board_data.owner_vk);
                let banned: std::collections::HashSet<MemberId> = board_data
                    .board_state
                    .bans
                    .0
                    .iter()
                    .map(|ban| ban.ban.banned_user)
                    .collect();
                board_data
                    .board_state
                    .members
                    .members
                    .iter()
                    .map(|member| member.member.id())
                    .filter(|id| *id != owner_id && !banned.contains(id))
                    .map(|id| {
                        let name = board_data
                            .board_state
                            .member_info
                            .member_info
                            .iter()
                            .find(|info| info.member_info.member_id == id)
                            .map(|info| info.member_info.preferred_nickname.to_string_lossy())
                            .unwrap_or_else(|| format!("{id}"));
                        (id, name)
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    });

    // Helper to get nickname for a member
    let get_nickname = move |member_id: MemberId| -> String {
        current_board_data
            .read()
            .as_ref()
            .and_then(|board_data| {
                board_data
                    .board_state
                    .member_info
                    .member_info
                    .iter()
                    .find(|info| info.member_info.member_id == member_id)
                    .map(|info| info.member_info.preferred_nickname.to_string_lossy())
            })
            .unwrap_or_else(|| format!("{}", member_id))
    };

    // If no board selected, show message
    if current_board_data.read().is_none() {
        return rsx! {
            div { class: "flex-1 flex items-center justify-center p-4",
                p { class: "text-text-muted", "Select a board to manage admins" }
            }
        };
    }

    let tab_board_admins = board_id_for_tabs.clone();
    let tab_board_bans = board_id_for_tabs.clone();
    let tab_board_roles = board_id_for_tabs.clone();
    let tab_board_links = board_id_for_tabs.clone();
    rsx! {
        div { class: "flex-1 flex flex-col p-6 overflow-y-auto",
            // Header
            h1 { class: "text-2xl font-bold text-text mb-4", "Admin Management" }

            // Tabs and admin actions on one row
            div { class: "flex flex-wrap items-center justify-between gap-3 mb-6",
                div { class: "flex gap-1 bg-surface rounded-lg p-1 w-fit",
                    button {
                        r#type: "button",
                        class: if active == "admins" {
                            "px-4 py-2 rounded-md text-sm bg-accent text-white"
                        } else {
                            "px-4 py-2 rounded-md text-sm text-text-muted hover:text-text"
                        },
                        onclick: move |_| navigate_admin_tab(&tab_board_admins, "admins"),
                        "Admins"
                    }
                    button {
                        r#type: "button",
                        class: if active == "bans" {
                            "px-4 py-2 rounded-md text-sm bg-accent text-white"
                        } else {
                            "px-4 py-2 rounded-md text-sm text-text-muted hover:text-text"
                        },
                        onclick: move |_| navigate_admin_tab(&tab_board_bans, "bans"),
                        "Banned"
                    }
                    button {
                        r#type: "button",
                        class: if active == "roles" {
                            "px-4 py-2 rounded-md text-sm bg-accent text-white"
                        } else {
                            "px-4 py-2 rounded-md text-sm text-text-muted hover:text-text"
                        },
                        onclick: move |_| navigate_admin_tab(&tab_board_roles, "roles"),
                        "Roles"
                    }
                    button {
                        r#type: "button",
                        class: if active == "links" {
                            "px-4 py-2 rounded-md text-sm bg-accent text-white"
                        } else {
                            "px-4 py-2 rounded-md text-sm text-text-muted hover:text-text"
                        },
                        onclick: move |_| navigate_admin_tab(&tab_board_links, "links"),
                        "Invite links"
                    }
                }

                if *is_owner.read() {
                    div { class: "flex gap-3",
                        button {
                            class: "px-4 py-2 bg-surface hover:bg-surface-hover text-text rounded-lg transition-colors flex items-center gap-2",
                            onclick: move |_| {
                                if let Some(owner_key) = CURRENT_BOARD.read().owner_key {
                                    EDIT_BOARD_MODAL.write().board = Some(owner_key);
                                }
                            },
                            span { "⚙" }
                            span { "Board Settings" }
                        }
                        button {
                            class: "px-4 py-2 bg-accent hover:bg-accent-hover text-white rounded-lg transition-colors flex items-center gap-2",
                            onclick: move |_| show_add_admin_modal.set(true),
                            span { "+" }
                            span { "Add Admin" }
                        }
                    }
                }
            }

            if active == "admins" {

            // Action buttons row (owner only)
            // (kept in the tab row above)

            // Current admins section
            div { class: "mb-6",
                h2 { class: "text-lg font-semibold text-text mb-3", "Current Admins" }

                if let Some(err) = admin_error.read().as_ref() {
                    div { class: "bg-red-500/10 border border-red-500/30 rounded-lg p-3 mb-3 text-red-300 text-sm",
                        "{err}"
                    }
                }

                if admins.read().is_empty() {
                    div { class: "bg-surface rounded-lg p-4 text-text-muted",
                        "No admins have been added yet. The board owner has full admin privileges by default."
                    }
                } else {
                    div { class: "space-y-2",
                        for admin in admins.read().iter() {
                            {
                            let member_id = admin.admin.member_id;
                            let nickname = get_nickname(member_id);
                            let initial = nickname.chars().next().unwrap_or('?').to_string();
                            rsx! {
                            div { class: "bg-surface rounded-lg p-3 flex items-center gap-3",
                                div { class: "w-8 h-8 bg-accent/20 rounded-full flex items-center justify-center text-accent text-sm",
                                    "{initial}"
                                }
                                div { class: "flex-1",
                                    p { class: "text-text font-medium", "{nickname}" }
                                    p { class: "text-text-muted text-xs", "{member_id}" }
                                }
                                if *is_owner.read() {
                                    button {
                                        r#type: "button",
                                        class: "px-3 py-1.5 text-xs text-red-400 hover:bg-red-500/10 rounded-lg transition-colors",
                                        onclick: move |_| {
                                            spawn_local(async move {
                                                if let Err(e) =
                                                    crate::util::messaging::revoke_admin(member_id).await
                                                {
                                                    admin_error.set(Some(e));
                                                } else {
                                                    admin_error.set(None);
                                                }
                                            });
                                        },
                                        "Remove"
                                    }
                                }
                            }
                            }
                            }
                        }
                    }
                }
            }

            // Non-owner message
            if !*is_owner.read() {
                div { class: "bg-surface rounded-lg p-4",
                    p { class: "text-text-muted text-sm",
                        "Only the board owner can add admins and modify board settings."
                    }
                }
            }
            } else if active == "bans" {
                {
                    let candidates = ban_candidates.read().clone();
                    let selected = candidates
                        .get(*ban_index.read())
                        .cloned()
                        .or_else(|| candidates.first().cloned());
                    rsx! {
                        div { class: "bg-surface rounded-lg p-3 mb-6",
                            h2 { class: "text-lg font-semibold text-text mb-1", "Ban a member" }
                            p { class: "text-text-muted text-sm mb-3",
                                "Choose one of the members currently on this board. Banned members lose access immediately."
                            }
                            if candidates.is_empty() {
                                p { class: "text-text-muted text-sm",
                                    "No members are available to ban. The owner cannot be banned, and already-banned members are not listed."
                                }
                            } else {
                                div { class: "flex flex-wrap items-center gap-2",
                                    select {
                                        class: "flex-1 min-w-48 px-3 py-2 bg-panel border border-border rounded-lg text-text text-sm",
                                        value: "{(*ban_index.read()).min(candidates.len().saturating_sub(1))}",
                                        onchange: move |evt| {
                                            if let Ok(index) = evt.value().parse::<usize>() {
                                                ban_index.set(index);
                                            }
                                        },
                                        for (index, (member_id, name)) in candidates.iter().enumerate() {
                                            option { value: "{index}", "{name} ({member_id})" }
                                        }
                                    }
                                    if let Some((member_id, name)) = selected {
                                        BanButton {
                                            member_to_ban: member_id,
                                            show_trigger: true,
                                            nickname: name,
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                div { class: "mb-6",
                    h2 { class: "text-lg font-semibold text-text mb-3", "Banned Users" }

                    if banned_users.read().is_empty() {
                        div { class: "bg-surface rounded-lg p-4 text-text-muted",
                            "No users have been banned."
                        }
                    } else {
                        div { class: "space-y-2",
                            for ban in banned_users.read().iter() {
                                div { class: "bg-surface rounded-lg p-3 flex items-center gap-3",
                                    div { class: "w-8 h-8 bg-red-500/20 rounded-full flex items-center justify-center text-red-400 text-sm",
                                        {get_nickname(ban.ban.banned_user).chars().next().unwrap_or('?').to_string()}
                                    }
                                    div { class: "flex-1",
                                        p { class: "text-text font-medium", "{get_nickname(ban.ban.banned_user)}" }
                                        p { class: "text-text-muted text-xs", "{ban.ban.banned_user}" }
                                    }
                                    div { class: "text-right text-xs text-text-muted",
                                        p { "Banned by: {get_nickname(ban.banned_by)}" }
                                    }
                                }
                            }
                        }
                    }
                }
            } else if active == "roles" {
                RolesSection {}
            } else {
                InviteLinksSection {}
            }
        }

        // Add Admin Modal
        if *show_add_admin_modal.read() {
            AddAdminModal {
                on_close: move |_| show_add_admin_modal.set(false)
            }
        }
    }
}
