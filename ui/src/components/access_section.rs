//! Roles and invite links, shown as separate tabs in the admin view.

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

fn current_board() -> Option<BoardData> {
    CURRENT_BOARD
        .read()
        .owner_key
        .as_ref()
        .and_then(|key| BOARDS.read().map.get(key).cloned())
}

#[component]
pub fn RolesSection() -> Element {
    let board = use_memo(move || current_board());
    let mut role_name = use_signal(String::new);
    let mut role_manages = use_signal(|| false);
    let mut role_distributes = use_signal(|| false);
    let mut assign_index = use_signal(|| 0usize);
    let mut error = use_signal(|| None::<String>);

    let Some(data) = board.read().clone() else {
        return rsx! {};
    };
    let is_owner = data.owner_vk == data.self_sk.verifying_key();
    let self_id = MemberId::from(&data.self_sk.verifying_key());
    let can_manage = is_owner || data.board_state.roles.can_manage_access(&self_id);
    if !can_manage {
        return rsx! {
            div { class: "bg-surface rounded-lg p-4",
                p { class: "text-text-muted text-sm",
                    "Only the board owner and members with the access-management role can manage roles."
                }
            }
        };
    }

    let roles = data.board_state.roles.roles.clone();
    let members: Vec<MemberId> = data
        .board_state
        .members
        .members
        .iter()
        .map(|m| m.member.id())
        .collect();
    let selected_member = members.get(*assign_index.read()).copied();

    rsx! {
        if let Some(err) = error.read().as_ref() {
            div { class: "bg-red-500/10 border border-red-500/30 rounded-lg p-3 mb-3 text-red-300 text-sm",
                "{err}"
            }
        }

        if is_owner {
            div { class: "bg-surface rounded-lg p-3 mb-3 flex flex-wrap items-center gap-2",
                input {
                    class: "flex-1 min-w-40 px-3 py-2 bg-panel border border-border rounded-lg text-text placeholder-text-muted",
                    placeholder: "New role name",
                    value: "{role_name}",
                    oninput: move |evt| role_name.set(evt.value()),
                }
                label {
                    class: "flex items-center gap-2 text-sm text-text-muted",
                    title: "Members with this role can create invite links and assign roles to other members.",
                    input {
                        r#type: "checkbox",
                        checked: *role_manages.read(),
                        onchange: move |evt| role_manages.set(evt.checked()),
                    }
                    "can manage access"
                }
                label {
                    class: "flex items-center gap-2 text-sm text-text-muted",
                    title: "Members with this role can send the keys of restricted categories to members who lack them, even when the owner is offline.",
                    input {
                        r#type: "checkbox",
                        checked: *role_distributes.read(),
                        onchange: move |evt| role_distributes.set(evt.checked()),
                    }
                    "can distribute category keys"
                }
                button {
                    r#type: "button",
                    class: "px-3 py-2 bg-accent hover:bg-accent/80 text-white text-sm rounded-lg",
                    onclick: move |_| {
                        let name = role_name.read().clone();
                        let manages = *role_manages.read();
                        let distributes = *role_distributes.read();
                        match access::create_role(name, manages, distributes) {
                            Ok(()) => {
                                role_name.set(String::new());
                                role_manages.set(false);
                                role_distributes.set(false);
                                error.set(None);
                            }
                            Err(e) => error.set(Some(e)),
                        }
                    },
                    "Create"
                }
            }
        }

        if roles.is_empty() {
            p { class: "text-text-muted text-sm", "No roles yet." }
        } else {
            div { class: "space-y-2",
                for role in roles.iter() {
                    {
                        let role_id = role.role.id;
                        let role_name = role.role.name.clone();
                        let manages = role.role.can_manage_access;
                        let distributes = role.role.can_distribute_keys;
                        let assigned = data.board_state.roles.members_of_role(&role_id);
                        rsx! {
                            div { class: "bg-surface rounded-lg p-3",
                                div { class: "flex items-center gap-2 mb-2",
                                    span { class: "text-text font-medium", "{role_name}" }
                                    if manages {
                                        span { class: "text-xs text-accent", "manages access" }
                                    }
                                    if distributes {
                                        span { class: "text-xs text-accent", "distributes keys" }
                                    }
                                    span { class: "text-xs text-text-muted",
                                        "{assigned.len()} members"
                                    }
                                    if is_owner {
                                        label {
                                            class: "ml-auto flex items-center gap-1 text-xs text-text-muted",
                                            title: "Allow this role's members to distribute the keys of restricted categories to new members. The owner can always do it.",
                                            input {
                                                r#type: "checkbox",
                                                checked: distributes,
                                                onchange: move |evt| {
                                                    let _ = access::set_role_can_distribute_keys(
                                                        role_id,
                                                        evt.checked(),
                                                    );
                                                },
                                            }
                                            "keys"
                                        }
                                        button {
                                            r#type: "button",
                                            class: "text-xs text-red-400 hover:bg-red-500/10 rounded px-2 py-1",
                                            onclick: move |_| {
                                                let _ = access::remove_role(role_id);
                                            },
                                            "Delete role"
                                        }
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
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
pub fn InviteLinksSection() -> Element {
    let board = use_memo(move || current_board());
    let mut link_role = use_signal(String::new);
    let mut link_max = use_signal(String::new);
    let mut link_includes_keys = use_signal(|| false);
    let mut created_link = use_signal(|| None::<(String, bool, usize)>);
    let mut error = use_signal(|| None::<String>);

    let Some(data) = board.read().clone() else {
        return rsx! {};
    };
    let is_owner = data.owner_vk == data.self_sk.verifying_key();
    let self_id = MemberId::from(&data.self_sk.verifying_key());
    let can_manage = is_owner || data.board_state.roles.can_manage_access(&self_id);
    if !can_manage {
        return rsx! {
            div { class: "bg-surface rounded-lg p-4",
                p { class: "text-text-muted text-sm",
                    "Only the board owner and members with the access-management role can create invite links."
                }
            }
        };
    }

    let roles = data.board_state.roles.roles.clone();
    let tokens = data
        .board_state
        .invites
        .active_tokens()
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();

    rsx! {
        if let Some(err) = error.read().as_ref() {
            div { class: "bg-red-500/10 border border-red-500/30 rounded-lg p-3 mb-3 text-red-300 text-sm",
                "{err}"
            }
        }

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
            label {
                class: "flex items-center gap-2 text-sm text-text-muted w-full",
                title: "Put the keys of the restricted categories this role can read into the link itself. The new member can open them even if no key holder is online; anyone with the link can read them.",
                input {
                    r#type: "checkbox",
                    checked: *link_includes_keys.read(),
                    onchange: move |evt| link_includes_keys.set(evt.checked()),
                }
                "Include the category keys this role can read (works while key holders are offline)"
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
                    let include_keys = *link_includes_keys.read();
                    match access::create_invite_link(role_id, max, include_keys) {
                        Ok(link) => {
                            let key_count = access::JoinLink::decode(&link)
                                .map(|parsed| parsed.category_keys.len())
                                .unwrap_or(0);
                            created_link.set(Some((link, include_keys, key_count)));
                            error.set(None);
                        }
                        Err(e) => error.set(Some(e)),
                    }
                },
                "Create link"
            }
        }

        if let Some((link, includes_keys, key_count)) = created_link.read().as_ref() {
            div { class: "bg-panel border border-accent/40 rounded-lg p-3 mb-3",
                p { class: "text-sm text-text mb-1",
                    "New link. Copy it now: the key is not stored in the board."
                }
                if *includes_keys {
                    p { class: "text-xs text-yellow-400 mb-2",
                        "This link carries {key_count} category key(s). Treat it as a stronger secret than a link without keys."
                    }
                }
                input {
                    class: "w-full px-2 py-1 bg-surface border border-border rounded text-xs font-mono text-text",
                    readonly: true,
                    value: "{link}",
                }
            }
        }

        p { class: "text-text-muted text-xs mb-2",
            "The full link is shown only right after you create it. The board stores the token, not the link: if you lose a link, revoke it and create a new one."
        }

        if tokens.is_empty() {
            p { class: "text-text-muted text-sm", "No invite links yet." }
        } else {
            div { class: "space-y-2",
                for token in tokens.iter() {
                    {
                        let token_id = token.id;
                        let token_code = bs58::encode(token_id).into_string();
                        let short_id = token_code.chars().take(8).collect::<String>();
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
                            div {
                                class: "bg-surface rounded-lg p-3 flex items-center gap-3",
                                title: "Link {token_code}: the board stores only this token, not the URL with its signing key.",
                                div { class: "flex-1",
                                    p { class: "text-text text-sm", "Role: {role_name}" }
                                    p { class: "text-text-muted text-xs",
                                        "Link #{short_id} · {uses} / {max_text} uses"
                                    }
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
