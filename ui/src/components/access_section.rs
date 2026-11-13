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

fn format_created_at(created: Option<std::time::SystemTime>) -> Option<String> {
    let millis = created?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_millis() as i64;
    Some(crate::util::format_utc_as_local_time(millis))
}

fn current_board() -> Option<BoardData> {
    CURRENT_BOARD
        .read()
        .owner_key
        .as_ref()
        .and_then(|key| BOARDS.read().map.get(key).cloned())
}

/// Small "?" that works with a tap, not only with a mouse hover.
#[component]
fn InfoHint(text: String) -> Element {
    let mut open = use_signal(|| false);
    rsx! {
        span { class: "relative inline-flex items-center",
            button {
                r#type: "button",
                class: "w-4 h-4 rounded-full border border-border text-[10px] leading-none text-text-muted hover:text-text flex items-center justify-center",
                title: "{text}",
                onclick: move |evt| {
                    evt.stop_propagation();
                    let next = !*open.read();
                    open.set(next);
                },
                "?"
            }
            if *open.read() {
                div {
                    class: "absolute z-40 left-1/2 -translate-x-1/2 top-full mt-1 w-64 p-2 rounded-lg bg-panel border border-border shadow-lg text-xs text-text-muted",
                    onclick: move |evt| evt.stop_propagation(),
                    "{text}"
                }
            }
        }
    }
}

#[component]
pub fn RolesSection() -> Element {
    let board = use_memo(move || current_board());
    let mut role_name = use_signal(String::new);
    let mut role_manages = use_signal(|| false);
    let mut role_distributes = use_signal(|| false);
    let mut role_edit = use_signal(|| false);
    let mut role_delete = use_signal(|| false);
    let mut role_close = use_signal(|| false);
    let mut role_pin = use_signal(|| false);
    let mut role_move = use_signal(|| false);
    let mut role_scope = use_signal(|| Vec::<plaza_core::board_state::message::MessageId>::new());
    let mut assign_index = use_signal(|| 0usize);
    let mut error = use_signal(|| None::<String>);

    let Some(data) = board.read().clone() else {
        return rsx! {};
    };
    let is_owner = data.owner_vk == data.self_sk.verifying_key();
    let self_id = MemberId::from(&data.self_sk.verifying_key());
    let is_admin = data
        .board_state
        .admin
        .admins
        .iter()
        .any(|admin| admin.admin.id() == self_id);
    // Admins do not get role definition or assignment powers implicitly. The
    // owner enables them per person through a role with can_manage_access.
    let can_define_roles = is_owner;
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

    // Sections and groups available as moderation scope. Selecting a group
    // covers all of its sections through the category chain.
    let scope_options: Vec<(plaza_core::board_state::message::MessageId, String)> = data
        .board_state
        .recent_messages
        .messages
        .iter()
        .filter_map(|message| {
            let category = data.readable_category(&message.id(), &message.message.content)?;
            let label = if category.is_group {
                format!("{} (group)", category.name)
            } else {
                category.name.clone()
            };
            Some((message.id(), label))
        })
        .collect();

    rsx! {
        if let Some(err) = error.read().as_ref() {
            div { class: "bg-red-500/10 border border-red-500/30 rounded-lg p-3 mb-3 text-red-300 text-sm",
                "{err}"
            }
        }

        if can_define_roles {
            div { class: "bg-surface rounded-lg p-3 mb-3 flex flex-wrap items-center gap-2",
                input {
                    class: "flex-1 min-w-40 px-3 py-2 bg-panel border border-border rounded-lg text-text placeholder-text-muted",
                    placeholder: "New role name",
                    value: "{role_name}",
                    oninput: move |evt| role_name.set(evt.value()),
                }
                div { class: "flex items-center gap-1",
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
                    InfoHint {
                        text: "Members with this role can create invite links and assign roles to other members.".to_string(),
                    }
                }
                div { class: "flex items-center gap-1",
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
                    InfoHint {
                        text: "Members with this role can send the keys of restricted categories to members who lack them, even when the owner is offline.".to_string(),
                    }
                }
                div { class: "w-full flex flex-wrap items-center gap-3 text-sm text-text-muted",
                    label { class: "flex items-center gap-1",
                        input { r#type: "checkbox", checked: *role_edit.read(), onchange: move |e| role_edit.set(e.checked()) }
                        "edit posts"
                    }
                    label { class: "flex items-center gap-1",
                        input { r#type: "checkbox", checked: *role_delete.read(), onchange: move |e| role_delete.set(e.checked()) }
                        "delete posts"
                    }
                    label { class: "flex items-center gap-1",
                        input { r#type: "checkbox", checked: *role_close.read(), onchange: move |e| role_close.set(e.checked()) }
                        "close posts"
                    }
                    label { class: "flex items-center gap-1",
                        input { r#type: "checkbox", checked: *role_pin.read(), onchange: move |e| role_pin.set(e.checked()) }
                        "pin posts"
                    }
                    label { class: "flex items-center gap-1",
                        input { r#type: "checkbox", checked: *role_move.read(), onchange: move |e| role_move.set(e.checked()) }
                        "move posts"
                    }
                }
                div { class: "w-full",
                    p { class: "text-xs text-text-muted mb-1",
                        "Powers apply to these sections and their subsections. No selection = whole board."
                    }
                    div { class: "max-h-32 overflow-y-auto border border-border rounded p-2 space-y-1",
                        if scope_options.is_empty() {
                            p { class: "text-xs text-text-muted", "No sections yet." }
                        }
                        for (scope_id, scope_name) in scope_options.iter() {
                            {
                                let scope_id = *scope_id;
                                let checked = role_scope.read().contains(&scope_id);
                                rsx! {
                                    label { key: "{scope_id:?}", class: "flex items-center gap-2 text-xs text-text-muted",
                                        input {
                                            r#type: "checkbox",
                                            checked: checked,
                                            onchange: move |e| {
                                                let mut selected = role_scope.read().clone();
                                                if e.checked() {
                                                    if !selected.contains(&scope_id) { selected.push(scope_id); }
                                                } else {
                                                    selected.retain(|id| *id != scope_id);
                                                }
                                                role_scope.set(selected);
                                            },
                                        }
                                        "{scope_name}"
                                    }
                                }
                            }
                        }
                    }
                }
                button {
                    r#type: "button",
                    class: "px-3 py-2 bg-accent hover:bg-accent/80 text-white text-sm rounded-lg",
                    onclick: move |_| {
                        let name = role_name.read().clone();
                        let manages = *role_manages.read();
                        let distributes = *role_distributes.read();
                        let edit = *role_edit.read();
                        let delete = *role_delete.read();
                        let close = *role_close.read();
                        let pin = *role_pin.read();
                        let move_posts = *role_move.read();
                        let scope = role_scope.read().clone();
                        match access::create_role(
                            name, manages, distributes, edit, delete, close, pin, move_posts,
                            scope,
                        ) {
                            Ok(()) => {
                                role_name.set(String::new());
                                role_manages.set(false);
                                role_distributes.set(false);
                                role_edit.set(false);
                                role_delete.set(false);
                                role_close.set(false);
                                role_pin.set(false);
                                role_move.set(false);
                                role_scope.set(Vec::new());
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
                        let can_edit_posts = role.role.can_edit_posts;
                        let can_delete_posts = role.role.can_delete_posts;
                        let can_close_posts = role.role.can_close_posts;
                        let can_pin_posts = role.role.can_pin_posts;
                        let can_move_posts = role.role.can_move_posts;
                        let role_scope_ids = role.role.scope.clone();
                        let scope_label = if role_scope_ids.is_empty() {
                            "whole board".to_string()
                        } else {
                            role_scope_ids
                                .iter()
                                .filter_map(|id| {
                                    scope_options
                                        .iter()
                                        .find(|(scope_id, _)| scope_id == id)
                                        .map(|(_, name)| name.clone())
                                })
                                .collect::<Vec<_>>()
                                .join(", ")
                        };
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
                                    for (enabled, label) in [
                                        (can_edit_posts, "edit"),
                                        (can_delete_posts, "delete"),
                                        (can_close_posts, "close"),
                                        (can_pin_posts, "pin"),
                                        (can_move_posts, "move"),
                                    ] {
                                        if enabled {
                                            span { class: "text-xs text-accent", "{label}" }
                                        }
                                    }
                                    span { class: "text-xs text-text-muted",
                                        "{assigned.len()} members"
                                    }
                                    if can_define_roles {
                                        div { class: "ml-auto flex items-center gap-2 text-xs text-text-muted",
                                            for (label, enabled, idx) in [
                                                ("edit", can_edit_posts, 0u8),
                                                ("delete", can_delete_posts, 1u8),
                                                ("close", can_close_posts, 2u8),
                                                ("pin", can_pin_posts, 3u8),
                                                ("move", can_move_posts, 4u8),
                                            ] {
                                                {
                                                    let scope = role_scope_ids.clone();
                                                    rsx! {
                                                        label { class: "flex items-center gap-1",
                                                            input {
                                                                r#type: "checkbox",
                                                                checked: enabled,
                                                                onchange: move |evt| {
                                                                    let edit = if idx == 0 { evt.checked() } else { can_edit_posts };
                                                                    let delete = if idx == 1 { evt.checked() } else { can_delete_posts };
                                                                    let close = if idx == 2 { evt.checked() } else { can_close_posts };
                                                                    let pin = if idx == 3 { evt.checked() } else { can_pin_posts };
                                                                    let move_posts = if idx == 4 { evt.checked() } else { can_move_posts };
                                                                    let _ = access::update_role_moderation(
                                                                        role_id, edit, delete, close, pin,
                                                                        move_posts, scope.clone(),
                                                                    );
                                                                },
                                                            }
                                                            "{label}"
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    if can_define_roles {
                                        div { class: "ml-auto flex items-center gap-1",
                                            label {
                                                class: "flex items-center gap-1 text-xs text-text-muted",
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
                                            InfoHint {
                                                text: "Allow this role's members to distribute the keys of restricted categories to new members. The owner can always do it.".to_string(),
                                            }
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
                                if can_define_roles {
                                    div { class: "mt-2 text-xs text-text-muted",
                                        details {
                                            summary { class: "cursor-pointer select-none", "Scope: {scope_label}" }
                                            div { class: "mt-2 max-h-40 overflow-y-auto border border-border rounded p-2 space-y-1",
                                                p { class: "text-xs text-text-muted", "No selection = whole board." }
                                                for (scope_id, scope_name) in scope_options.iter() {
                                                    {
                                                        let id = *scope_id;
                                                        let checked = role_scope_ids.contains(&id);
                                                        let current_scope = role_scope_ids.clone();
                                                        rsx! {
                                                            label { key: "{id:?}", class: "flex items-center gap-2 text-xs text-text-muted",
                                                                input {
                                                                    r#type: "checkbox",
                                                                    checked: checked,
                                                                    onchange: move |evt| {
                                                                        let mut selected = current_scope.clone();
                                                                        if evt.checked() {
                                                                            if !selected.contains(&id) { selected.push(id); }
                                                                        } else {
                                                                            selected.retain(|entry| *entry != id);
                                                                        }
                                                                        let _ = access::update_role_moderation(
                                                                            role_id,
                                                                            can_edit_posts,
                                                                            can_delete_posts,
                                                                            can_close_posts,
                                                                            can_pin_posts,
                                                                            can_move_posts,
                                                                            selected,
                                                                        );
                                                                    },
                                                                }
                                                                "{scope_name}"
                                                            }
                                                        }
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
    let mut link_label = use_signal(String::new);
    let mut link_includes_keys = use_signal(|| false);
    let mut created_link = use_signal(|| None::<(String, bool, usize)>);
    let mut copied = use_signal(|| false);
    let mut editing_label = use_signal(|| None::<plaza_core::board_state::invites::TokenId>);
    let mut label_edit = use_signal(String::new);
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
            input {
                class: "flex-1 min-w-40 px-3 py-2 bg-panel border border-border rounded-lg text-text text-sm",
                placeholder: "Label (e.g. Twitter, forum, October)",
                maxlength: "80",
                value: "{link_label}",
                oninput: move |evt| link_label.set(evt.value()),
            }
            div { class: "flex items-center gap-1 w-full",
                label {
                    class: "flex items-center gap-2 text-sm text-text-muted",
                    input {
                        r#type: "checkbox",
                        checked: *link_includes_keys.read(),
                        onchange: move |evt| link_includes_keys.set(evt.checked()),
                    }
                    "Include the category keys this role can read (works while key holders are offline)"
                }
                InfoHint {
                    text: "Put the keys of the restricted categories this role can read into the link itself. The new member can open them even if no key holder is online; anyone with the link can read them.".to_string(),
                }
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
                    let label = link_label.read().clone();
                    match access::create_invite_link(role_id, max, include_keys, label) {
                        Ok(link) => {
                            let key_count = access::JoinLink::decode(&link)
                                .map(|parsed| parsed.category_keys.len())
                                .unwrap_or(0);
                            created_link.set(Some((link, include_keys, key_count)));
                            copied.set(false);
                            link_label.set(String::new());
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
                div { class: "flex items-center gap-2",
                    input {
                        class: "flex-1 px-2 py-1 bg-surface border border-border rounded text-xs font-mono text-text",
                        readonly: true,
                        value: "{link}",
                    }
                    button {
                        r#type: "button",
                        class: "px-3 py-1 bg-surface hover:bg-surface-hover text-text text-xs rounded",
                        onclick: {
                            let link = link.clone();
                            move |_| {
                                crate::util::copy_to_clipboard(&link);
                                copied.set(true);
                            }
                        },
                        if *copied.read() { "Copied!" } else { "Copy" }
                    }
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
                        let label = if token.label.is_empty() {
                            "No label".to_string()
                        } else {
                            token.label.clone()
                        };
                        let label_for_edit = label.clone();
                        let created = format_created_at(token.created_at);
                        let includes_keys = token.includes_category_keys;
                        let editing_this = *editing_label.read() == Some(token_id);
                        rsx! {
                            div {
                                class: "bg-surface rounded-lg p-3",
                                title: "Link {token_code}: the board stores only this token, not the URL with its signing key.",
                                div { class: "flex items-start gap-3",
                                    div { class: "flex-1 min-w-0",
                                        div { class: "flex items-center gap-2 flex-wrap",
                                            p { class: "text-text text-sm font-medium", "{label}" }
                                            if includes_keys {
                                                span {
                                                    class: "text-[10px] px-2 py-0.5 rounded-full bg-yellow-500/10 text-yellow-400 border border-yellow-500/30",
                                                    title: "This link carried category keys when it was created.",
                                                    "with keys"
                                                }
                                            }
                                        }
                                        p { class: "text-text-muted text-xs",
                                            "Role: {role_name}"
                                            if let Some(date) = created {
                                                span { " · created {date}" }
                                            }
                                        }
                                        p { class: "text-text-muted text-xs",
                                            "Link #{short_id} · {uses} / {max_text} uses"
                                        }
                                        if editing_this {
                                            div { class: "flex items-center gap-2 mt-2",
                                                input {
                                                    class: "flex-1 px-2 py-1 bg-panel border border-border rounded text-xs text-text",
                                                    maxlength: "80",
                                                    value: "{label_edit}",
                                                    oninput: move |evt| label_edit.set(evt.value()),
                                                }
                                                button {
                                                    r#type: "button",
                                                    class: "px-2 py-1 bg-accent hover:bg-accent/80 text-white text-xs rounded",
                                                    onclick: move |_| {
                                                        let _ = access::rename_invite_link(
                                                            token_id,
                                                            label_edit.read().clone(),
                                                        );
                                                        editing_label.set(None);
                                                    },
                                                    "Save"
                                                }
                                                button {
                                                    r#type: "button",
                                                    class: "px-2 py-1 bg-panel text-text-muted text-xs rounded",
                                                    onclick: move |_| editing_label.set(None),
                                                    "Cancel"
                                                }
                                            }
                                        }
                                    }
                                    div { class: "flex items-center gap-1 flex-shrink-0",
                                        button {
                                            r#type: "button",
                                            class: "text-xs text-text-muted hover:bg-surface-hover rounded px-2 py-1",
                                            onclick: move |_| {
                                                label_edit.set(label_for_edit.clone());
                                                editing_label.set(Some(token_id));
                                            },
                                            "Rename"
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
}
