use dioxus::prelude::*;
use plaza_core::board_state::admin::{
    Admin, AdminRevocation, AdminsDelta, AuthorizedAdmin, AuthorizedAdminRevocation,
};
use plaza_core::board_state::member::{AuthorizedMember, Member, MemberId, MembersDelta};
use plaza_core::board_state::ownership::{
    AuthorizedKeyDeactivation, AuthorizedOwnerTransfer, KeyDeactivationV1, OutgoingOwnerAction,
    OwnerTransferV1, OwnershipDelta,
};
use plaza_core::board_state::ChatBoardStateV1Delta;
use plaza_core::util::sign_struct;
use std::time::{Duration, SystemTime};

use crate::util::message_actions::{apply_state_delta, ActionContext};

#[component]
pub fn OwnershipView() -> Element {
    let mut error = use_signal(|| None::<String>);
    let mut selected = use_signal(|| None::<MemberId>);
    let mut outcome = use_signal(|| OutgoingOwnerAction::KeepAdmin);
    let mut confirmed = use_signal(|| false);
    let mut busy = use_signal(|| false);

    let board = ActionContext::from_current_board();
    let Some(ctx) = board else {
        return rsx! {
            div { class: "bg-surface rounded-lg p-4 text-text-muted", "No board selected." }
        };
    };

    let parameters = plaza_core::board_state::ChatBoardParametersV1 {
        owner: ctx.current_board,
    };
    let owner_id = ctx.board_state.ownership.current_owner(&parameters);
    let is_owner = ctx.self_sk.verifying_key() == ctx.board_state.ownership.current_owner_key(&parameters);

    // Members that can receive the board: a valid key, not the current owner,
    // not deactivated. An admin target skips the promotion step.
    let candidates: Vec<(MemberId, String, bool)> = ctx
        .board_state
        .members
        .members
        .iter()
        .filter(|member| {
            member.member.id() != owner_id
                && !ctx
                    .board_state
                    .ownership
                    .is_deactivated_now(&member.member.id())
        })
        .map(|member| {
            let id = member.member.id();
            let name = ctx
                .board_state
                .member_info
                .member_info
                .iter()
                .find(|info| info.member_info.member_id == id)
                .map(|info| info.member_info.preferred_nickname.to_string_lossy())
                .unwrap_or_else(|| format!("{}", id));
            let is_admin = ctx
                .board_state
                .admin
                .admins
                .iter()
                .any(|admin| admin.admin.id() == id);
            (id, name, is_admin)
        })
        .collect();

    let history = ctx.board_state.ownership.transfers.clone();
    let deactivations = ctx.board_state.ownership.deactivations.clone();
    // The select stores the candidate index: `MemberId`'s Display and FromStr
    // use different encodings, so parsing the printed id fails.
    let candidate_ids: Vec<MemberId> = candidates.iter().map(|(id, _, _)| *id).collect();
    let names: std::collections::HashMap<MemberId, String> = ctx
        .board_state
        .member_info
        .member_info
        .iter()
        .map(|info| {
            (
                info.member_info.member_id,
                info.member_info.preferred_nickname.to_string_lossy(),
            )
        })
        .collect();
    let founding_owner = parameters.owner_id();
    let name_of = |id: MemberId| -> String {
        if id == founding_owner {
            return "Owner (founding key)".to_string();
        }
        names
            .get(&id)
            .cloned()
            .unwrap_or_else(|| format!("{}", id))
    };

    let transfer = move |_: dioxus::prelude::Event<dioxus::prelude::MouseData>| {
        if *busy.read() {
            return;
        }
        let Some(target) = *selected.read() else {
            error.set(Some("Choose an admin to receive the board".to_string()));
            return;
        };
        if !*confirmed.read() {
            error.set(Some("Tick the confirmation to hand the board over".to_string()));
            return;
        }
        let Some(target_key) = ctx
            .board_state
            .members
            .members
            .iter()
            .find(|member| member.member.id() == target)
            .map(|member| member.member.member_vk)
        else {
            error.set(Some("The chosen admin has no member key".to_string()));
            return;
        };

        busy.set(true);
        let now = SystemTime::now();
        // Bundle records are signed just before the transfer so they resolve
        // the outgoing owner as their authority.
        let signed_at = now;
        let transferred_at = now + Duration::from_millis(2);

        // Only admins can receive the board: promote a plain member first.
        let target_is_admin = ctx
            .board_state
            .admin
            .admins
            .iter()
            .any(|admin| admin.admin.id() == target);
        if !target_is_admin {
            let generation = ctx.board_state.admin.next_generation(&target);
            let admin = Admin {
                member_id: target,
                generation,
                signed_at,
            };
            let delta = ChatBoardStateV1Delta {
                admin: Some(AdminsDelta::new(vec![AuthorizedAdmin::new(
                    admin,
                    &ctx.self_sk,
                )])),
                ..Default::default()
            };
            if let Err(e) = apply_state_delta(&ctx, delta) {
                error.set(Some(format!("Could not promote the target to admin: {e}")));
                busy.set(false);
                return;
            }
        }
        let Some(ctx) = ActionContext::from_current_board() else {
            error.set(Some("The board context is gone after the promotion".to_string()));
            busy.set(false);
            return;
        };

        let generation = ctx.board_state.ownership.transfers.len() as u64 + 1;
        let outgoing = *outcome.read();

        let mut delta = ChatBoardStateV1Delta::default();
        let mut deactivations = Vec::new();
        if outgoing == OutgoingOwnerAction::Deactivate {
            deactivations.push(AuthorizedKeyDeactivation::new(
                KeyDeactivationV1 {
                    member: owner_id,
                    key: ctx.self_sk.verifying_key(),
                    generation: 1,
                    deactivated_at: signed_at,
                },
                &ctx.self_sk,
            ));
        }
        delta.ownership = Some(OwnershipDelta {
            transfers: vec![AuthorizedOwnerTransfer::new(
                OwnerTransferV1 {
                    from: owner_id,
                    to: target,
                    to_key: target_key,
                    generation,
                    transferred_at,
                    outgoing,
                },
                &ctx.self_sk,
            )],
            deactivations,
        });

        // The outgoing owner rejoins as a member (and optionally an admin).
        delta.members = Some(MembersDelta::new(vec![AuthorizedMember::new(
            Member {
                owner_member_id: parameters.owner_id(),
                invited_by: owner_id,
                member_vk: ctx.self_sk.verifying_key(),
                join_proof: None,
            },
            &ctx.self_sk,
        )]));
        let next_admin_generation = ctx.board_state.admin.next_generation(&owner_id);
        if outgoing == OutgoingOwnerAction::KeepAdmin {
            delta.admin = Some(AdminsDelta::new(vec![AuthorizedAdmin::new(
                Admin {
                    member_id: owner_id,
                    generation: next_admin_generation,
                    signed_at,
                },
                &ctx.self_sk,
            )]));
        } else if ctx
            .board_state
            .admin
            .admins
            .iter()
            .any(|admin| admin.admin.id() == owner_id)
        {
            let revocation = AdminRevocation {
                member_id: owner_id,
                generation: next_admin_generation,
                signed_at,
            };
            let authorized = AuthorizedAdminRevocation::with_signature(
                revocation.clone(),
                sign_struct(&revocation, &ctx.self_sk),
            );
            delta.admin = Some(AdminsDelta::revocation(vec![authorized]));
        }

        let apply_ctx = ctx.clone();
        spawn(async move {
            match apply_state_delta(&apply_ctx, delta) {
                Ok(()) => {
                    error.set(None);
                    confirmed.set(false);
                }
                Err(e) => error.set(Some(format!("Transfer failed: {e}"))),
            }
            busy.set(false);
        });
    };
    rsx! {
        div { class: "space-y-4",
            div { class: "bg-surface rounded-lg p-4",
                h2 { class: "text-lg font-semibold text-text mb-1", "Ownership" }
                p { class: "text-text-muted text-sm",
                    "The owner can hand the board to an administrator. The board, its messages and its settings stay in place; the new owner gets every owner power and can transfer again."
                }
                p { class: "text-text-muted text-sm mt-2",
                    "Current owner: "
                    span { class: "text-text font-medium", "{name_of(owner_id)}" }
                }
            }

            if let Some(err) = error.read().as_ref() {
                div { class: "bg-red-500/10 border border-red-500/30 rounded-lg p-3 text-red-300 text-sm",
                    "{err}"
                }
            }

            if is_owner {
                div { class: "bg-surface rounded-lg p-4 space-y-3",
                    h3 { class: "text-text font-medium", "Transfer this board" }
                    if candidates.is_empty() {
                        p { class: "text-text-muted text-sm",
                            "No member can receive the board: the only member with a key is the current owner."
                        }
                    } else {
                        select {
                            class: "w-full bg-background border border-border rounded-lg px-3 py-2 text-text text-sm",
                            onchange: move |event| {
                                selected.set(
                                    event
                                        .value()
                                        .parse::<usize>()
                                        .ok()
                                        .and_then(|index| candidate_ids.get(index).copied()),
                                );
                            },
                            option { value: "", "Choose a member" }
                            for (index, (_, name, is_admin)) in candidates.iter().enumerate() {
                                option { value: "{index}",
                                    if *is_admin { "{name} (admin)" } else { "{name}" }
                                }
                            }
                        }
                        p { class: "text-text-muted text-xs",
                            "A plain member is promoted to admin in the same transfer."
                        }
                        div { class: "space-y-2 text-sm text-text-muted",
                            label { class: "flex items-center gap-2",
                                input {
                                    r#type: "radio",
                                    name: "outgoing",
                                    checked: *outcome.read() == OutgoingOwnerAction::KeepAdmin,
                                    onchange: move |_| outcome.set(OutgoingOwnerAction::KeepAdmin),
                                }
                                "I stay as an admin"
                            }
                            label { class: "flex items-center gap-2",
                                input {
                                    r#type: "radio",
                                    name: "outgoing",
                                    checked: *outcome.read() == OutgoingOwnerAction::Member,
                                    onchange: move |_| outcome.set(OutgoingOwnerAction::Member),
                                }
                                "I become a plain member"
                            }
                            label { class: "flex items-center gap-2",
                                input {
                                    r#type: "radio",
                                    name: "outgoing",
                                    checked: *outcome.read() == OutgoingOwnerAction::Deactivate,
                                    onchange: move |_| outcome.set(OutgoingOwnerAction::Deactivate),
                                }
                                "I deactivate my key on this board (shown as a deactivated user)"
                            }
                        }
                        label { class: "flex items-center gap-2 text-sm text-text",
                            input {
                                r#type: "checkbox",
                                checked: *confirmed.read(),
                                onchange: move |event| confirmed.set(event.checked()),
                            }
                            "I understand the new owner can transfer the board again and can remove me."
                        }
                        button {
                            r#type: "button",
                            class: "px-4 py-2 bg-red-500/80 hover:bg-red-500 text-white rounded-lg text-sm disabled:opacity-50",
                            disabled: *busy.read(),
                            onclick: transfer,
                            if *busy.read() { "Transferring..." } else { "Transfer ownership" }
                        }
                    }
                }
            }

            div { class: "bg-surface rounded-lg p-4",
                h3 { class: "text-text font-medium mb-2", "History" }
                if history.is_empty() {
                    p { class: "text-text-muted text-sm", "The founding owner still holds the board." }
                } else {
                    div { class: "space-y-2 text-sm",
                        for entry in history.iter() {
                            {
                                let change = &entry.transfer;
                                let when = chrono::DateTime::<chrono::Utc>::from(change.transferred_at)
                                    .format("%Y-%m-%d %H:%M UTC")
                                    .to_string();
                                let outgoing = match change.outgoing {
                                    OutgoingOwnerAction::KeepAdmin => "kept as admin",
                                    OutgoingOwnerAction::Member => "became a member",
                                    OutgoingOwnerAction::Deactivate => "deactivated",
                                };
                                rsx! {
                                    div { class: "bg-background rounded-lg p-3",
                                        p { class: "text-text",
                                            "{name_of(change.from)} -> {name_of(change.to)}"
                                        }
                                        p { class: "text-text-muted text-xs",
                                            "generation {change.generation} - {when} - outgoing owner {outgoing}"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if !deactivations.is_empty() {
                    div { class: "mt-3 text-sm text-text-muted",
                        "Deactivated identities: "
                        for entry in deactivations.iter() {
                            span { class: "text-text", "{name_of(entry.deactivation.member)} " }
                        }
                    }
                }
            }
        }
    }
}
