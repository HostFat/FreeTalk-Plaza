//! Moderator trash list. Content preview needs the trash key and is added with
//! the full hide flow; this view already exposes the metadata and the signed
//! restore/purge actions.

use crate::components::app::{BOARDS, CURRENT_BOARD};
use crate::util::message_actions::ActionContext;
use dioxus::prelude::*;
use plaza_core::board_state::member::MemberId;
use plaza_core::board_state::message::MessageId;
use plaza_core::board_state::moderation::category_chain;
use plaza_core::board_state::roles::ModerationPower;
use std::collections::{HashMap, HashSet};

#[component]
pub fn TrashView() -> Element {
    let board_data = use_memo(move || {
        CURRENT_BOARD
            .read()
            .owner_key
            .as_ref()
            .and_then(|key| BOARDS.read().map.get(key).cloned())
    });

    let Some(data) = board_data.read().clone() else {
        return rsx! { p { class: "text-text-muted", "Select a board." } };
    };

    // Make sure the owner key has a KEM key before a rotation removes the last
    // profile manager: the new trash key has to be sealed to someone.
    let mut pq_checked = use_signal(|| false);
    use_effect({
        let board_key = CURRENT_BOARD.read().owner_key;
        move || {
            if *pq_checked.peek() {
                return;
            }
            *pq_checked.write() = true;
            let Some(board_key) = board_key else {
                return;
            };
            let changed = BOARDS.with_mut(|boards| {
                boards
                    .map
                    .get_mut(&board_key)
                    .is_some_and(|board| board.ensure_pq_key())
            });
            if changed {
                crate::components::app::mark_needs_sync(board_key);
            }
            // A fresh board has KEM keys but no trash set yet. Create it now,
            // so access can be shared and rotated before the first hide.
            if let Some(ctx) = ActionContext::from_current_board() {
                match crate::util::trash_actions::ensure_trash_key(&ctx) {
                    Ok(true) => {
                        crate::components::app::toasts::show("Trash key created.")
                    }
                    Ok(false) => {}
                    Err(error) if error.contains("cannot create") => {}
                    Err(error) => crate::components::app::toasts::show_error(format!(
                        "Could not create the trash key: {error}"
                    )),
                }
            }
        }
    });

    // Apply the retention setting when the page opens, once per mount.
    let mut retention_ran = use_signal(|| false);
    use_effect({
        let days = data.trash_retention_days;
        move || {
            if *retention_ran.peek() {
                return;
            }
            *retention_ran.write() = true;
            if days == 0 {
                return;
            }
            let Some(ctx) = ActionContext::from_current_board() else {
                return;
            };
            wasm_bindgen_futures::spawn_local(async move {
                match crate::util::trash_actions::purge_expired(&ctx, days, 5).await {
                    Ok(0) => {}
                    Ok(count) => crate::components::app::toasts::show(format!(
                        "Purged {count} expired item(s)."
                    )),
                    Err(message) => crate::components::app::toasts::show_error(format!(
                        "Could not purge expired trash: {message}"
                    )),
                }
            });
        }
    });

    let mut error = use_signal(|| None::<String>);
    let mut preview = use_signal(|| {
        None::<(
            plaza_core::board_state::message::MessageId,
            Vec<(String, String)>,
        )>
    });
    let self_id = plaza_core::board_state::member::MemberId::from(&data.self_sk.verifying_key());
    let can_purge = data.is_current_owner()
        || data
            .board_state
            .admin
            .admins
            .iter()
            .any(|admin| admin.admin.id() == self_id);
    let mut restore_targets = use_signal(HashMap::<MessageId, MessageId>::new);
    let mut handled = use_signal(std::collections::HashSet::<MessageId>::new);
    let mut selected = use_signal(HashSet::<MessageId>::new);
    let mut grant_index = use_signal(|| 0usize);
    let mut grant_notice = use_signal(|| None::<String>);
    let routes = data.board_state.moderation.routes_map();
    let is_owner_or_admin = data.is_current_owner()
        || data
            .board_state
            .admin
            .admins
            .iter()
            .any(|admin| admin.admin.id() == self_id);
    let categories = data
        .board_state
        .recent_messages
        .messages
        .iter()
        .filter(|message| {
            message.message.content.is_category()
                && !data
                    .board_state
                    .recent_messages
                    .is_deleted(&message.id())
        })
        .map(|message| {
            let id = message.id();
            let chain = category_chain(&routes, &id);
            let can_move = is_owner_or_admin
                || crate::board_data::has_moderation_power(
                    &data.board_state,
                    self_id,
                    ModerationPower::Move,
                    &chain,
                );
            (
                id,
                message
                    .message
                    .content
                    .title()
                    .unwrap_or_else(|| "Section".to_string()),
                can_move,
            )
        })
        .collect::<Vec<_>>();
    let sealed_members: HashSet<_> = data
        .board_state
        .pq_secrets
        .sets
        .iter()
        .filter(|entry| {
            matches!(
                entry.set.scope,
                plaza_core::board_state::pq_secrets::PqScope::Trash
            )
        })
        .flat_map(|entry| entry.set.secrets.iter().map(|secret| secret.member_id))
        .collect();
    let mut grant_candidates: Vec<_> = data
        .board_state
        .admin
        .admins
        .iter()
        .map(|admin| admin.admin.id())
        .chain(
            data.board_state
                .roles
                .assignments
                .iter()
                .filter(|assignment| {
                    !assignment.assignment.revoked
                        && data.board_state.roles.roles.iter().any(|role| {
                            role.role.id == assignment.assignment.role_id
                                && role.role.can_manage_trash
                                && !role.role.deleted
                        })
                })
                .map(|assignment| assignment.assignment.member_id),
        )
        .filter(|member| *member != self_id && !sealed_members.contains(member))
        .collect();
    grant_candidates.sort();
    grant_candidates.dedup();
    // The owner, an admin or any member with the trash role may share the key;
    // the contract checks the same signer set for a Trash PQ set.
    let can_grant = is_owner_or_admin
        || crate::board_data::can_manage_trash(&data.board_state, self_id);
    let has_current_key = data.trash_secret.is_some();
    // A rotated-out manager keeps older keys, so old items stay readable.
    let has_trash_key = has_current_key || !data.trash_secrets.is_empty();
    let owner_id = MemberId::from(&data.owner_vk);
    let mut key_holders: Vec<MemberId> = sealed_members.iter().copied().collect();
    key_holders.sort();
    let selected_member = grant_candidates.get(*grant_index.read()).copied();
    let selected_has_pq_key = selected_member
        .map(|member| data.board_state.pq_secrets.key_for(member).is_some())
        .unwrap_or(false);
    let mut items = data
        .board_state
        .trash
        .items
        .iter()
        .filter(|item| data.board_state.trash.active_item(&item.item.id).is_some())
        .filter(|item| !handled.read().contains(&item.item.id))
        .cloned()
        .collect::<Vec<_>>();
    items.sort_by_key(|item| std::cmp::Reverse(item.item.hidden_at));
    let bulk_items = items.clone();

    rsx! {
        div { class: "space-y-3",
            div { class: "flex items-center justify-between",
                h2 { class: "text-lg font-semibold text-text", "Trash" }
                div { class: "flex items-center gap-3",
                    span { class: "text-sm text-text-muted", "{items.len()} items" }
                    button {
                        r#type: "button",
                        class: "px-3 py-1.5 text-xs rounded-md bg-surface hover:bg-surface-hover text-text",
                        title: "Reload the app and read the board state from the local node",
                        onclick: move |_| {
                            if let Some(window) = web_sys::window() {
                                let _ = window.location().reload();
                            }
                        },
                        "Reload page"
                    }
                }
            }
            p { class: "text-sm text-text-muted",
                "Hidden topics stay encrypted here until a moderator restores or purges them. Purge is reserved for the owner and admins."
            }
            p { class: "text-xs text-text-muted",
                "If another moderator just acted, use Reload page to read the latest state from your node."
            }
            if !has_current_key {
                p { class: "text-sm text-amber-400 border border-amber-600/40 rounded-md p-2",
                    "You do not have the current trash key. New items stay locked until a trash manager grants it to you."
                }
            }
            if can_grant {
                div { class: "border border-border rounded-lg p-3 bg-panel space-y-2",
                    div { class: "flex items-center justify-between",
                        h3 { class: "text-sm font-semibold text-text", "Trash access" }
                        span { class: "text-xs text-text-muted",
                            "{key_holders.len()} with the key"
                        }
                    }
                    if !key_holders.is_empty() {
                        div { class: "flex flex-wrap gap-1",
                            for member in key_holders {
                                span { class: "flex items-center gap-1 bg-surface rounded px-2 py-0.5 text-xs text-text-muted",
                                    "{member_name(&data, member)}"
                                    if member != owner_id && member != self_id && is_owner_or_admin {
                                        button {
                                            r#type: "button",
                                            class: "text-red-400",
                                            title: "Stop sharing the trash key with this member",
                                            onclick: move |_| {
                                                if let Some(window) = web_sys::window() {
                                                    let confirmed = window
                                                        .confirm_with_message(
                                                            "Rotate the trash key and remove this member? They keep the items they already opened.",
                                                        )
                                                        .unwrap_or(false);
                                                    if !confirmed {
                                                        return;
                                                    }
                                                }
                                                let Some(ctx) = ActionContext::from_current_board() else {
                                                    return;
                                                };
                                                grant_notice.set(None);
                                                error.set(None);
                                                wasm_bindgen_futures::spawn_local(async move {
                                                    match crate::util::trash_actions::revoke_trash_access(
                                                        &ctx, member,
                                                    )
                                                    .await
                                                    {
                                                        Ok(()) => {
                                                            grant_notice.set(Some(
                                                                "Removed from the trash key list.".to_string(),
                                                            ));
                                                            crate::components::app::toasts::show(
                                                                "Trash key rotated. Syncing with the network…",
                                                            );
                                                        }
                                                        Err(message) => {
                                                            crate::components::app::toasts::show_error(format!(
                                                                "Could not rotate the trash key: {message}"
                                                            ));
                                                            error.set(Some(message));
                                                        }
                                                    }
                                                });
                                            },
                                            "×"
                                        }
                                    }
                                }
                            }
                        }
                    }
                    p { class: "text-xs text-text-muted",
                        "Share the trash key with the other moderators so they can preview and restore items. A member has to have opened this board once. Removing a member rotates the key: they keep what they already opened, and new items stay sealed to the remaining managers."
                    }
                    if can_grant && !is_owner_or_admin {
                        p { class: "text-xs text-text-muted",
                            "Only the owner or an admin can rotate the key. You can still share the current key."
                        }
                    }
                    if !has_current_key {
                        p { class: "text-xs text-amber-400",
                            "You need the current trash key before you can share it."
                        }
                    } else if grant_candidates.is_empty() {
                        p { class: "text-xs text-text-muted",
                            "Every moderator with access already has the key."
                        }
                    } else {
                        div { class: "flex items-center gap-2",
                            select {
                                class: "min-w-0 flex-1 bg-panel border border-border rounded-md px-2 py-1 text-xs text-text",
                                onchange: move |event| {
                                    grant_index.set(event.value().parse::<usize>().unwrap_or(0));
                                    grant_notice.set(None);
                                },
                                for (index, member) in grant_candidates.iter().enumerate() {
                                    option { value: "{index}",
                                        if data.board_state.pq_secrets.key_for(*member).is_some() {
                                            "{member_name(&data, *member)}"
                                        } else {
                                            "{member_name(&data, *member)} (no PQ key yet)"
                                        }
                                    }
                                }
                            }
                            button {
                                r#type: "button",
                                class: if selected_has_pq_key {
                                    "px-3 py-1.5 text-xs rounded-md bg-accent hover:bg-accent/80 text-white"
                                } else {
                                    "px-3 py-1.5 text-xs rounded-md bg-surface text-text-muted cursor-not-allowed"
                                },
                                disabled: !selected_has_pq_key,
                                onclick: {
                                    let candidates = grant_candidates.clone();
                                    move |_| {
                                        let index = *grant_index.read();
                                        let Some(member) = candidates.get(index).copied() else {
                                            return;
                                        };
                                        let Some(ctx) = ActionContext::from_current_board() else {
                                            return;
                                        };
                                        grant_notice.set(None);
                                        error.set(None);
                                        wasm_bindgen_futures::spawn_local(async move {
                                            match crate::util::trash_actions::grant_trash_access(
                                                &ctx, member,
                                            )
                                            .await
                                            {
                                                Ok(()) => {
                                                    grant_notice.set(Some(
                                                        "Trash key granted.".to_string(),
                                                    ));
                                                    crate::components::app::toasts::show(
                                                        "Trash key shared. Syncing with the network…",
                                                    );
                                                }
                                                Err(message) => {
                                                    crate::components::app::toasts::show_error(format!(
                                                        "Could not share the trash key: {message}"
                                                    ));
                                                    error.set(Some(message));
                                                }
                                            }
                                        });
                                    }
                                },
                                "Grant access"
                            }
                        }
                        if !selected_has_pq_key {
                            p { class: "text-xs text-text-muted",
                                "This member has not published a PQ key yet. They get one after opening the board with the trash role."
                            }
                        }
                    }
                    if has_current_key {
                        button {
                            r#type: "button",
                            class: "text-xs text-accent hover:underline",
                            title: "Re-seal the current key to every moderator who has a PQ key",
                            onclick: move |_| {
                                let Some(ctx) = ActionContext::from_current_board() else {
                                    return;
                                };
                                grant_notice.set(None);
                                error.set(None);
                                match crate::util::trash_actions::grant_missing_trash_access(&ctx) {
                                    Ok(count) => {
                                        grant_notice.set(Some(format!(
                                            "Trash key shared with {count} moderators."
                                        )));
                                        crate::components::app::toasts::show(format!(
                                            "Trash key shared with {count} moderators. Syncing with the network…"
                                        ));
                                    }
                                    Err(message) => {
                                        crate::components::app::toasts::show_error(format!(
                                            "Could not share the trash key: {message}"
                                        ));
                                        error.set(Some(message));
                                    }
                                }
                            },
                            "Share the key with all moderators"
                        }
                    }
                    if let Some(message) = grant_notice.read().as_ref() {
                        p { class: "text-xs text-emerald-400", "{message}" }
                    }
                }
            }
            if let Some(message) = error.read().as_ref() {
                p { class: "text-sm text-red-400", "{message}" }
            }
            if let Some((_, messages)) = preview.read().as_ref() {
                div { class: "border border-accent/40 rounded-lg p-3 bg-panel space-y-2 max-h-80 overflow-y-auto",
                    div { class: "flex items-center justify-between",
                        h3 { class: "text-sm font-semibold text-text", "Preview" }
                        button {
                            r#type: "button",
                            class: "text-xs text-text-muted hover:text-text",
                            onclick: move |_| preview.set(None),
                            "Close"
                        }
                    }
                    for (title, body) in messages {
                        div { class: "border-t border-border pt-2",
                            p { class: "text-sm font-medium text-text", "{title}" }
                            p { class: "text-xs text-text-muted whitespace-pre-wrap", "{body}" }
                        }
                    }
                }
            }
            div { class: "flex flex-wrap items-center gap-3 border border-border rounded-lg p-3 bg-panel",
                label { class: "text-xs text-text-muted", "Auto-purge after" }
                select {
                    class: "px-2 py-1.5 bg-surface border border-border rounded-lg text-xs text-text",
                    value: "{data.trash_retention_days}",
                    onchange: {
                        let owner = data.owner_vk;
                        move |event| {
                            let days = event.value().parse::<u32>().unwrap_or(0);
                            BOARDS.with_mut(|boards| {
                                if let Some(board) = boards.map.get_mut(&owner) {
                                    board.trash_retention_days = days;
                                }
                            });
                            wasm_bindgen_futures::spawn_local(async {
                                let _ = crate::components::app::chat_delegate::save_boards_to_delegate()
                                    .await;
                            });
                            if days == 0 {
                                return;
                            }
                            let Some(ctx) = ActionContext::from_current_board() else {
                                return;
                            };
                            wasm_bindgen_futures::spawn_local(async move {
                                match crate::util::trash_actions::purge_expired(&ctx, days, 5).await {
                                    Ok(0) => {}
                                    Ok(count) => crate::components::app::toasts::show(format!(
                                        "Purged {count} expired item(s)."
                                    )),
                                    Err(message) => crate::components::app::toasts::show_error(
                                        format!("Could not purge expired trash: {message}"),
                                    ),
                                }
                            });
                        }
                    },
                    option { value: "0", "Off" }
                    option { value: "7", "7 days" }
                    option { value: "30", "30 days" }
                    option { value: "90", "90 days" }
                }
                span { class: "text-xs text-text-muted",
                    "Runs when this page opens; at most 5 items each time."
                }
                if !selected.read().is_empty() {
                    button {
                        r#type: "button",
                        class: "ml-auto px-3 py-1.5 text-xs rounded-md bg-red-600 hover:bg-red-500 text-white",
                        onclick: move |_| {
                            let Some((code, reason)) =
                                crate::util::trash_actions::ask_reason("spam")
                            else {
                                return;
                            };
                            let chosen: Vec<_> = bulk_items
                                .iter()
                                .filter(|item| selected.read().contains(&item.item.id))
                                .cloned()
                                .collect();
                            let Some(ctx) = ActionContext::from_current_board() else {
                                return;
                            };
                            wasm_bindgen_futures::spawn_local(async move {
                                let mut ok = 0usize;
                                let mut failed = 0usize;
                                for item in chosen {
                                    match crate::util::trash_actions::purge_item(
                                        &ctx, &item, &reason, code,
                                    )
                                    .await
                                    {
                                        Ok(()) => ok += 1,
                                        Err(message) => {
                                            failed += 1;
                                            crate::components::app::toasts::show_error(format!(
                                                "Could not purge an item: {message}"
                                            ));
                                        }
                                    }
                                }
                                if ok > 0 {
                                    crate::components::app::toasts::show(format!(
                                        "Purged {ok} item(s). Syncing with the network…"
                                    ));
                                }
                                if failed > 0 {
                                    crate::components::app::toasts::show_error(format!(
                                        "{failed} item(s) could not be purged."
                                    ));
                                }
                            });
                        },
                        "Purge selected ({selected.read().len()})"
                    }
                }
            }
            if items.is_empty() {
                p { class: "text-sm text-text-muted", "The trash is empty." }
            }
            for item in items {
                div {
                    key: "{item.item.id}",
                    class: "border border-border rounded-lg p-3 bg-panel space-y-2",
                    div { class: "flex items-center justify-between gap-3",
                        input {
                            r#type: "checkbox",
                            class: "mt-1",
                            checked: selected.read().contains(&item.item.id),
                            onchange: {
                                let item_id = item.item.id;
                                move |event: Event<FormData>| {
                                    selected.with_mut(|set| {
                                        if event.checked() {
                                            set.insert(item_id);
                                        } else {
                                            set.remove(&item_id);
                                        }
                                    });
                                }
                            },
                        }
                        div { class: "min-w-0 flex-1",
                            p { class: "text-sm text-text truncate", "Topic {item.item.root}" }
                            p { class: "text-xs text-text-muted",
                                "{item.item.messages.len()} messages · {item.item.reason}"
                            }
                            // A section is not a topic: the restore only brings
                            // it back under its stored parent, so there is no
                            // destination to choose.
                            if !crate::util::trash_actions::item_is_section(&item)
                                && item
                                    .item
                                    .section
                                    .map(|section| {
                                        data.board_state.moderation.routes_map().get(&section).is_none()
                                            || data
                                                .board_state
                                                .recent_messages
                                                .is_deleted(&section)
                                    })
                                    .unwrap_or(false)
                            {
                                select {
                                    class: "mt-2 w-full bg-panel border border-border rounded-md px-2 py-1 text-xs text-text",
                                    onchange: {
                                        let item_id = item.item.id;
                                        move |event| {
                                            if let Ok(section) = event.value().parse::<MessageId>() {
                                                restore_targets.write().insert(item_id, section);
                                            }
                                        }
                                    },
                                    option { value: "", "Original section deleted — choose one" }
                                    for (id, name, enabled) in &categories {
                                        option {
                                            value: "{id}",
                                            disabled: !*enabled,
                                            if *enabled { "{name}" } else { "{name} (no Move permission)" }
                                        }
                                    }
                                }
                            }
                        }
                        div { class: "flex items-center gap-2",
                            button {
                                r#type: "button",
                                class: if has_trash_key {
                                    "px-3 py-1.5 text-xs rounded-md bg-surface hover:bg-surface-hover text-text"
                                } else {
                                    "px-3 py-1.5 text-xs rounded-md bg-surface text-text-muted cursor-not-allowed"
                                },
                                disabled: !has_trash_key,
                                onclick: {
                                    let item = item.clone();
                                    move |_| {
                                        let Some(ctx) = ActionContext::from_current_board() else {
                                            return;
                                        };
                                        match crate::util::trash_actions::preview_item(&ctx, &item) {
                                            Ok(messages) => preview.set(Some((item.item.id, messages))),
                                            Err(message) => error.set(Some(message)),
                                        }
                                    }
                                },
                                "Preview"
                            }
                            button {
                                r#type: "button",
                                class: if has_trash_key {
                                    "px-3 py-1.5 text-xs rounded-md bg-surface hover:bg-surface-hover text-text"
                                } else {
                                    "px-3 py-1.5 text-xs rounded-md bg-surface text-text-muted cursor-not-allowed"
                                },
                                disabled: !has_trash_key,
                                onclick: {
                                    let item = item.clone();
                                    move |_| {
                                        if !has_trash_key {
                                            error.set(Some("You do not have the trash key".to_string()));
                                            return;
                                        }
                                        let Some(ctx) = ActionContext::from_current_board() else {
                                            return;
                                        };
                                        let item = item.clone();
                                        let is_section =
                                            crate::util::trash_actions::item_is_section(&item);
                                        let section_missing = item.item.section.map(|section| {
                                            ctx.board_state.moderation.routes_map().get(&section).is_none()
                                                || ctx.board_state.recent_messages.is_deleted(&section)
                                        }).unwrap_or(false);
                                        let destination = if section_missing && !is_section {
                                            restore_targets.read().get(&item.item.id).copied()
                                        } else {
                                            None
                                        };
                                        if section_missing && !is_section && destination.is_none() {
                                            error.set(Some("Choose a section for the restored topic".to_string()));
                                            return;
                                        }
                                        wasm_bindgen_futures::spawn_local(async move {
                                            match crate::util::trash_actions::restore_item(
                                                &ctx, &item, destination,
                                            )
                                            .await
                                            {
                                                Ok(()) => {
                                                    handled.write().insert(item.item.id);
                                                    crate::components::app::toasts::show(
                                                        "Topic restored. Syncing with the network…",
                                                    );
                                                }
                                                Err(message) => {
                                                    crate::components::app::toasts::show_error(format!(
                                                        "Could not restore: {message}"
                                                    ));
                                                    if is_stale(&message) {
                                                        handled.write().insert(item.item.id);
                                                        error.set(Some("This item was already handled. The list was refreshed.".to_string()));
                                                    } else {
                                                        error.set(Some(message));
                                                    }
                                                }
                                            }
                                        });
                                    }
                                },
                                "Restore"
                            }
                            if can_purge {
                                button {
                                    r#type: "button",
                                    class: "px-3 py-1.5 text-xs rounded-md bg-red-600 hover:bg-red-500 text-white",
                                    onclick: {
                                        let item = item.clone();
                                        move |_| {
                                            let Some((code, reason)) =
                                                crate::util::trash_actions::ask_reason("spam")
                                            else {
                                                return;
                                            };
                                            if item.item.messages.len() >= 10
                                                && !crate::util::trash_actions::ask_confirmation_word("PURGE")
                                            {
                                                return;
                                            }
                                            let Some(ctx) = ActionContext::from_current_board() else {
                                                return;
                                            };
                                            let item = item.clone();
                                            wasm_bindgen_futures::spawn_local(async move {
                                                match crate::util::trash_actions::purge_item(
                                                    &ctx, &item, &reason, code,
                                                )
                                                .await
                                                {
                                                    Ok(()) => {
                                                        crate::components::app::toasts::show(
                                                            "Item purged. Syncing with the network…",
                                                        );
                                                    }
                                                    Err(message) => {
                                                        crate::components::app::toasts::show_error(format!(
                                                            "Could not purge: {message}"
                                                        ));
                                                        error.set(Some(message));
                                                    }
                                                }
                                            });
                                        }
                                    },
                                    "Purge"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn is_stale(message: &str) -> bool {
    let message = message.to_lowercase();
    message.contains("missing item") || message.contains("older") || message.contains("already")
}

fn member_name(data: &crate::board_data::BoardData, id: MemberId) -> String {
    data.board_state
        .member_info
        .member_info
        .iter()
        .find(|info| info.member_info.member_id == id)
        .map(|info| info.member_info.preferred_nickname.to_string_lossy())
        .unwrap_or_else(|| format!("{id}"))
}
