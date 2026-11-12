//! Roles and invite links, shown inside the admin view.

use crate::board_data::BoardData;
use crate::components::app::{BOARDS, CURRENT_BOARD};
use crate::util::access;
use dioxus::prelude::*;
use plaza_core::board_state::member::MemberId;
use plaza_core::board_state::roles::RoleId;

fn nickname_of(data: &BoardData, id: MemberId) -> String {
    data.board_state
        .member_info
        .member_info
        .iter()
        .find(|info| info.member_info.member_id == id)
        .map(|info| info.member_info.preferred_nickname.to_string_lossy())
        .unwrap_or_else(|| format!("{id}"))
}

fn role_id_of(text: &str) -> Option<RoleId> {
    let bytes = bs58::decode(text).into_vec().ok()?;
    if bytes.len() != 16 {
        return None;
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&bytes);
    Some(id)
}

#[component]
pub fn AccessSection() -> Element {
    let board = use_memo(move || {
        CURRENT_BOARD
            .read()
            .owner_key
            .as_ref()
            .and_then(|key| BOARDS.read().map.get(key).cloned())
    });

    let mut role_name = use_signal(String::new);
    let mut role_manages = use_signal(|| false);
    let mut link_role = use_signal(String::new);
    let mut link_max = use_signal(String::new);
    let mut error = use_signal(|| None::<String>);
    let mut created_link = use_signal(|| None::<String>);
    let mut assign_index = use_signal(|| 0usize);

    let Some(data) = board.read().clone() else {
        return rsx! {};
    };

    let is_owner = data.owner_vk == data.self_sk.verifying_key();
    if !is_owner {
        return rsx! {
            div { class: "bg-surface rounded-lg p-4",
                p { class: "text-text-muted text-sm",
                    "Roles and invite links are managed by the board owner for now."
                }
            }
        };
    }

    let roles = data.board_state.roles.roles.clone();
    let tokens = data.board_state.invites.active_tokens().into_iter().cloned().collect::<Vec<_>>();
    let members: Vec<MemberId> = data
        .board_state
        .members
        .members
        .iter()
        .map(|m| m.member.id())
        .collect();
    let selected_member = members.get(*assign_index.read()).copied();

    rsx! {
        div { class: "mb-6",
            h2 { class: "text-lg font-semibold text-text mb-3", "Roles" }

            if let Some(err) = error.read().as_ref() {
                div { class: "bg-red-500/10 border border-red-500/30 rounded-lg p-3 mb-3 text-red-300 text-sm",
                    "{err}"
                }
            }

            div { class: "bg-surface rounded-lg p-3 mb-3 flex flex-wrap items-center gap-2",
                input {
                    class: "flex-1 min-w-40 px-3 py-2 bg-panel border border-border rounded-lg text-text placeholder-text-muted",
                    placeholder: "New role name",
                    value: "{role_name}",
                    oninput: move |evt| role_name.set(evt.value()),
                }
                label { class: "flex items-center gap-2 text-sm text-text-muted",
                    input {
                        r#type: "checkbox",
                        checked: *role_manages.read(),
                        onchange: move |evt| role_manages.set(evt.checked()),
                    }
                    "can manage access"
                }
                button {
                    r#type: "button",
                    class: "px-3 py-2 bg-accent hover:bg-accent/80 text-white text-sm rounded-lg",
                    onclick: move |_| {
                        let name = role_name.read().clone();
                        let manages = *role_manages.read();
                        match access::create_role(name, manages) {
                            Ok(()) => { role_name.set(String::new()); role_manages.set(false); error.set(None); }
                            Err(e) => error.set(Some(e)),
                        }
                    },
                    "Create"
                }
            }

            if roles.is_empty() {
                p { class: "text-text-muted text-sm", "No roles yet." }
            } else {
                div { class: "space-y-2",
                    for role in roles.iter() {
                        {
                            let role_id = role.role.id;
                            let role_id_text = bs58::encode(role_id).into_string();
                            let role_name = role.role.name.clone();
                            let manages = role.role.can_manage_access;
                            let assigned = data.board_state.roles.members_of_role(&role_id);
                            rsx! {
                                div { class: "bg-surface rounded-lg p-3",
                                    div { class: "flex items-center gap-2 mb-2",
                                        span { class: "text-text font-medium", "{role_name}" }
                                        if manages {
                                            span { class: "text-xs text-accent", "manages access" }
                                        }
                                        span { class: "text-xs text-text-muted",
                                            "{assigned.len()} members"
                                        }
                                        button {
                                            r#type: "button",
                                            class: "ml-auto text-xs text-red-400 hover:bg-red-500/10 rounded px-2 py-1",
                                            onclick: move |_| {
                                                let _ = access::remove_role(role_id);
                                            },
                                            "Delete role"
                                        }
                                    }
                                    div { class: "flex flex-wrap gap-1 mb-2",
                                        for member_id in assigned.iter() {
                                            {
                                                let mid = *member_id;
                                                rsx! {
                                                    span { class: "flex items-center gap-1 bg-panel rounded px-2 py-0.5 text-xs text-text-muted",
                                                        "{nickname_of(&data, mid)}"
                                                        button {
                                                            r#type: "button",
                                                            class: "text-red-400",
                                                            onclick: move |_| { let _ = access::set_role_member(role_id, mid, false); },
                                                            "×"
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    div { class: "flex items-center gap-2",
                                        select {
                                            class: "flex-1 px-2 py-1 bg-panel border border-border rounded text-sm text-text",
                                            onchange: move |evt| {
                                                if let Ok(index) = evt.value().parse::<usize>() {
                                                    assign_index.set(index);
                                                }
                                            },
                                            for (index, member_id) in members.iter().enumerate() {
                                                option { value: "{index}", "{nickname_of(&data, *member_id)}" }
                                            }
                                        }
                                        button {
                                            r#type: "button",
                                            class: "px-3 py-1 bg-accent hover:bg-accent/80 text-white text-xs rounded",
                                            onclick: move |_| {
                                                if let Some(member_id) = selected_member {
                                                    match access::set_role_member(role_id, member_id, true) {
                                                        Ok(()) => error.set(None),
                                                        Err(e) => error.set(Some(e)),
                                                    }
                                                }
                                            },
                                            "Add"
                                        }
                                    }
                                    input {
                                        r#type: "hidden",
                                        value: "{role_id_text}",
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        div { class: "mb-6",
            h2 { class: "text-lg font-semibold text-text mb-3", "Invite links" }

            div { class: "bg-surface rounded-lg p-3 mb-3 flex flex-wrap items-center gap-2",
                select {
                    class: "flex-1 min-w-40 px-3 py-2 bg-panel border border-border rounded-lg text-text text-sm",
                    value: "{link_role}",
                    onchange: move |evt| link_role.set(evt.value()),
                    option { value: "", "Choose a role" }
                    for role in roles.iter() {
                        option {
                            value: "{bs58::encode(role.role.id).into_string()}",
                            "{role.role.name}"
                        }
                    }
                }
                input {
                    class: "w-32 px-3 py-2 bg-panel border border-border rounded-lg text-text text-sm",
                    placeholder: "Max uses (blank = ∞)",
                    value: "{link_max}",
                    oninput: move |evt| link_max.set(evt.value()),
                }
                button {
                    r#type: "button",
                    class: "px-3 py-2 bg-accent hover:bg-accent/80 text-white text-sm rounded-lg",
                    onclick: move |_| {
                        let role_text = link_role.read().clone();
                        let Some(role_id) = role_id_of(&role_text) else {
                            error.set(Some("Choose a role for the link".to_string()));
                            return;
                        };
                        let max = link_max.read().trim().parse::<u32>().ok();
                        match access::create_invite_link(role_id, max) {
                            Ok(link) => { created_link.set(Some(link)); error.set(None); }
                            Err(e) => error.set(Some(e)),
                        }
                    },
                    "Create link"
                }
            }

            if let Some(link) = created_link.read().as_ref() {
                div { class: "bg-panel border border-accent/40 rounded-lg p-3 mb-3",
                    p { class: "text-sm text-text mb-1",
                        "New link. Copy it now: the key is not stored in the board."
                    }
                    input {
                        class: "w-full px-2 py-1 bg-surface border border-border rounded text-xs font-mono text-text",
                        readonly: true,
                        value: "{link}",
                        onfocus: move |evt| { let _ = evt; },
                    }
                }
            }

            if tokens.is_empty() {
                p { class: "text-text-muted text-sm", "No invite links yet." }
            } else {
                div { class: "space-y-2",
                    for token in tokens.iter() {
                        {
                            let token_id = token.id;
                            let role_name = data.board_state.roles.role(&token.role_id)
                                .map(|r| r.name.clone())
                                .unwrap_or_else(|| "(role deleted)".to_string());
                            let uses = plaza_core::board_state::invites::members_joined_via(
                                &data.board_state.members.members,
                                &token_id,
                            ).len();
                            let max_text = token.max_uses
                                .map(|m| m.to_string())
                                .unwrap_or_else(|| "∞".to_string());
                            rsx! {
                                div { class: "bg-surface rounded-lg p-3 flex items-center gap-3",
                                    div { class: "flex-1",
                                        p { class: "text-text text-sm", "Role: {role_name}" }
                                        p { class: "text-text-muted text-xs", "{uses} / {max_text} uses" }
                                    }
                                    button {
                                        r#type: "button",
                                        class: "text-xs text-red-400 hover:bg-red-500/10 rounded px-2 py-1",
                                        onclick: move |_| {
                                            let _ = access::revoke_invite_link(token_id);
                                        },
                                        "Revoke"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
