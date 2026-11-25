use dioxus::prelude::*;
use plaza_core::board_state::admin::{
    Admin, AdminRevocation, AdminsDelta, AuthorizedAdmin, AuthorizedAdminRevocation,
};
use plaza_core::board_state::member::{AuthorizedMember, Member, MemberId, MembersDelta};
use plaza_core::board_state::ownership::{
    required_succession_quorum, AuthorizedKeyDeactivation, AuthorizedOwnerTransfer,
    AuthorizedSuccessionVoteV1, KeyDeactivationV1, OutgoingOwnerAction, OwnerTransferV1,
    OwnershipDelta, SuccessionVoteV1,
};
use plaza_core::board_state::{ChatBoardParametersV1, ChatBoardStateV1Delta};
use plaza_core::util::sign_struct;
use crate::util::get_current_system_time;
use crate::util::message_actions::{apply_state_delta, ActionContext};
use std::time::Duration;

/// Hand the board to `target`: promote it when needed, then send the transfer,
/// the outgoing owner's new membership and its admin change.
///
/// The work runs in one spawned task. Applying a state delta subscribes the
/// open views, so it must not run inside the click handler itself.
#[allow(clippy::too_many_arguments)]
fn start_transfer(
    target: MemberId,
    _ctx: ActionContext,
    owner_id: MemberId,
    parameters: ChatBoardParametersV1,
    outgoing: OutgoingOwnerAction,
    confirmed: bool,
    mut error: Signal<Option<String>>,
    mut confirmed_signal: Signal<bool>,
    mut busy: Signal<bool>,
    mut revision: Signal<u32>,
) {
    if *busy.peek() {
        return;
    }
    if !confirmed {
        error.set(Some("Tick the confirmation to hand the board over".to_string()));
        return;
    }

    busy.set(true);
    error.set(None);
    // A plain future, like the other state-changing actions: applying a delta
    // inside a Dioxus task lets the runtime re-render while the board map is
    // borrowed.
    wasm_bindgen_futures::spawn_local(async move {
        // Read the board again: the view may hold a state from before the
        // target's membership arrived, and the contract verifies the transfer
        // against the state it is given.
        let Some(ctx) = ActionContext::from_current_board() else {
            error.set(Some("The board context is not available".to_string()));
            busy.set(false);
            return;
        };
        let shard_records = crate::components::app::member_contract::records_for_parent_board(
            ctx.current_board,
            &ctx.board_state,
            target,
        );
        let Some(target_key) = ctx
            .board_state
            .members
            .members
            .iter()
            .find(|member| member.member.id() == target)
            .map(|member| member.member.member_vk)
            .or_else(|| {
                shard_records
                    .iter()
                    .find(|member| member.member.id() == target)
                    .map(|member| member.member.member_vk)
            })
        else {
            error.set(Some("The chosen member is not on this board".to_string()));
            busy.set(false);
            return;
        };
        let now = get_current_system_time();
        // Records are signed just before the transfer so they resolve the
        // outgoing owner as their authority.
        let signed_at = now;
        let transferred_at = now + Duration::from_millis(2);

        // Only admins can receive the board: promote a plain member first.
        let target_is_admin = ctx
            .board_state
            .admin
            .admins
            .iter()
            .any(|admin| admin.admin.id() == target);
        if !target_is_admin || !shard_records.is_empty() {
            let admin_delta = if target_is_admin {
                None
            } else {
                let admin = Admin {
                    member_id: target,
                    generation: ctx.board_state.admin.next_generation(&target),
                    signed_at,
                };
                Some(AdminsDelta::new(vec![AuthorizedAdmin::new(
                    admin,
                    &ctx.owner_sk,
                )]))
            };
            let delta = ChatBoardStateV1Delta {
                admin: admin_delta,
                members: if shard_records.is_empty() {
                    None
                } else {
                    Some(MembersDelta::new(shard_records))
                },
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

        let owner_key = ctx.owner_sk.verifying_key();
        let profile_key = ctx.self_sk.verifying_key();
        let split_profile = profile_key != owner_key;
        let profile_id = MemberId::from(&profile_key);
        // The identity that stays visible on the board after the handover.
        let outgoing_id = if split_profile { profile_id } else { owner_id };
        // A handover to this client's own profile makes that profile the owner;
        // it must not be deactivated in the same bundle.
        let deactivate_profile = split_profile && target != profile_id;

        let mut delta = ChatBoardStateV1Delta::default();
        let mut deactivations = Vec::new();
        if outgoing == OutgoingOwnerAction::Deactivate {
            deactivations.push(AuthorizedKeyDeactivation::new(
                KeyDeactivationV1 {
                    member: owner_id,
                    key: owner_key,
                    generation: 1,
                    deactivated_at: signed_at,
                },
                &ctx.owner_sk,
            ));
            // The owner key never posts on a split board: retire the visible
            // profile too. The contract wants each key to sign its own record.
            if deactivate_profile {
                deactivations.push(AuthorizedKeyDeactivation::new(
                    KeyDeactivationV1 {
                        member: profile_id,
                        key: profile_key,
                        generation: 1,
                        deactivated_at: signed_at,
                    },
                    &ctx.self_sk,
                ));
            }
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
                &ctx.owner_sk,
            )],
            deactivations,
            ..Default::default()
        });

        // The outgoing identity rejoins as a member (and optionally an admin).
        // On a split board that identity is the profile, which is usually
        // already a member; the owner key never posts. A later handover finds
        // it already on the list: publishing a self-invitation again is
        // rejected as such.
        let membership_key = if split_profile { profile_key } else { owner_key };
        let membership_id = MemberId::from(&membership_key);
        let already_member = ctx
            .board_state
            .members
            .members
            .iter()
            .any(|member| member.member.id() == membership_id);
        let deactivating = outgoing == OutgoingOwnerAction::Deactivate;
        if !already_member && !(split_profile && deactivating) {
            delta.members = Some(MembersDelta::new(vec![AuthorizedMember::new(
                Member {
                    owner_member_id: parameters.owner_id(),
                    invited_by: owner_id,
                    member_vk: membership_key,
                    join_proof: None,
                },
                &ctx.owner_sk,
            )]));
        }
        let next_admin_generation =
            ctx.board_state.admin.next_generation(&outgoing_id);
        let outgoing_is_admin = ctx
            .board_state
            .admin
            .admins
            .iter()
            .any(|admin| admin.admin.id() == outgoing_id);
        if outgoing == OutgoingOwnerAction::KeepAdmin {
            // Adding a newer record would move its signed time past an earlier
            // transfer that names this owner as the target, which makes that
            // transfer invalid. Keep the record that is already there.
            if !outgoing_is_admin {
                delta.admin = Some(AdminsDelta::new(vec![AuthorizedAdmin::new(
                    Admin {
                        member_id: outgoing_id,
                        generation: next_admin_generation,
                        signed_at,
                    },
                    &ctx.owner_sk,
                )]));
            }
        } else if outgoing_is_admin && outgoing_id != target {
            // Revoking the target's admin record in the same bundle would make
            // the transfer invalid: the successor must still be an admin at
            // the transfer time. A handover to the outgoing identity itself
            // needs no revocation.
            let revocation = AdminRevocation {
                member_id: outgoing_id,
                generation: next_admin_generation,
                signed_at,
            };
            let authorized = AuthorizedAdminRevocation::with_signature(
                revocation.clone(),
                sign_struct(&revocation, &ctx.owner_sk),
            );
            delta.admin = Some(AdminsDelta::revocation(vec![authorized]));
        }

        match apply_state_delta(&ctx, delta) {
            Ok(()) => {
                error.set(None);
                confirmed_signal.set(false);
                revision.set(revision() + 1);
                crate::components::app::toasts::show(
                    "Ownership transferred. Syncing with the network…",
                );
                // A handover to the outgoing identity makes that identity the
                // owner; its admin record is now redundant. The contract drops
                // it during cleanup, but write the revocation too for states
                // that have not been normalized yet.
                if outgoing == OutgoingOwnerAction::KeepAdmin
                    && outgoing_id == target
                    && outgoing_is_admin
                {
                    if let Some(fresh) = ActionContext::from_current_board() {
                        if fresh
                            .board_state
                            .admin
                            .admins
                            .iter()
                            .any(|admin| admin.admin.id() == outgoing_id)
                        {
                            let revocation = AuthorizedAdminRevocation::new_at(
                                outgoing_id,
                                fresh.board_state.admin.next_generation(&outgoing_id),
                                get_current_system_time()
                                    + std::time::Duration::from_millis(2),
                                &fresh.owner_sk,
                            );
                            let _ = apply_state_delta(
                                &fresh,
                                ChatBoardStateV1Delta {
                                    admin: Some(AdminsDelta::revocation(vec![revocation])),
                                    ..Default::default()
                                },
                            );
                        }
                    }
                }
                // A transfer is not something to lose on a quick reload: write
                // it now instead of waiting for the periodic save.
                if let Err(error) =
                    crate::components::app::chat_delegate::save_boards_and_wait().await
                {
                    dioxus::logger::tracing::warn!(
                        "Could not save the ownership transfer: {error}"
                    );
                }
            }
            Err(e) => {
                crate::components::app::toasts::show_error(format!(
                    "Transfer failed: {e}"
                ));
                error.set(Some(format!("Transfer failed: {e}")));
            }
        }
        busy.set(false);
    });
}

/// Cast an admin vote for emergency succession. When this vote reaches the
/// required strict-majority quorum (`>= 2` active admins), emit the succession
/// transfer in the same delta so the successor becomes owner immediately.
#[allow(clippy::too_many_arguments)]
fn cast_succession_vote(
    target: MemberId,
    owner_id: MemberId,
    parameters: ChatBoardParametersV1,
    confirmed: bool,
    mut error: Signal<Option<String>>,
    mut confirmed_signal: Signal<bool>,
    mut busy: Signal<bool>,
    mut revision: Signal<u32>,
) {
    if *busy.peek() {
        return;
    }
    if !confirmed {
        error.set(Some(
            "Tick the confirmation before casting a succession vote".to_string(),
        ));
        return;
    }
    busy.set(true);
    error.set(None);
    wasm_bindgen_futures::spawn_local(async move {
        let Some(ctx) = ActionContext::from_current_board() else {
            error.set(Some("The board context is not available".to_string()));
            busy.set(false);
            return;
        };
        let active_admins = ctx
            .board_state
            .ownership
            .current_active_admins(&ctx.board_state, &parameters);
        let Some(quorum) = required_succession_quorum(active_admins.len()) else {
            error.set(Some(
                "Emergency succession requires at least 2 active admins".to_string(),
            ));
            busy.set(false);
            return;
        };
        let voter_sk = ctx.self_sk.clone();
        let voter_vk = voter_sk.verifying_key();
        let voter_id = MemberId::from(&voter_vk);
        if !active_admins.contains(&voter_id) {
            error.set(Some("Only active admins can vote for succession".to_string()));
            busy.set(false);
            return;
        }
        let Some(target_key) = ctx
            .board_state
            .members
            .members
            .iter()
            .find(|member| member.member.id() == target)
            .map(|member| member.member.member_vk)
            .or_else(|| {
                (target == parameters.owner_id()).then_some(parameters.owner)
            })
            .or_else(|| ctx.board_state.ownership.owner_key_of(&target))
        else {
            error.set(Some("The chosen admin key is not available on this board".to_string()));
            busy.set(false);
            return;
        };

        let generation = ctx.board_state.ownership.transfers.len() as u64 + 1;
        let now = get_current_system_time();
        let my_vote = AuthorizedSuccessionVoteV1::new(
            SuccessionVoteV1 {
                from: owner_id,
                to: target,
                to_key: target_key,
                generation,
                voter: voter_id,
                voter_key: voter_vk,
                signed_at: now,
            },
            &voter_sk,
        );

        let mut approvals: Vec<AuthorizedSuccessionVoteV1> = ctx
            .board_state
            .ownership
            .succession_votes
            .iter()
            .filter(|entry| {
                entry.vote.generation == generation
                    && entry.vote.from == owner_id
                    && entry.vote.to == target
                    && entry.vote.voter != voter_id
            })
            .cloned()
            .collect();
        approvals.push(my_vote.clone());

        let finalized = approvals.len() >= quorum;
        let transfers = if finalized {
            vec![AuthorizedOwnerTransfer::new_by_succession(
                OwnerTransferV1 {
                    from: owner_id,
                    to: target,
                    to_key: target_key,
                    generation,
                    transferred_at: now + Duration::from_millis(2),
                    outgoing: OutgoingOwnerAction::Member,
                },
                approvals,
                &voter_sk,
            )]
        } else {
            Vec::new()
        };

        let delta = ChatBoardStateV1Delta {
            ownership: Some(OwnershipDelta {
                transfers,
                deactivations: Vec::new(),
                succession_votes: vec![my_vote],
            }),
            ..Default::default()
        };
        match apply_state_delta(&ctx, delta) {
            Ok(()) => {
                error.set(None);
                confirmed_signal.set(false);
                revision.set(revision() + 1);
                if finalized {
                    crate::components::app::toasts::show(
                        "Quorum reached: ownership transferred to the successor. Syncing…",
                    );
                } else {
                    crate::components::app::toasts::show(
                        "Succession vote recorded. Waiting for remaining admin quorum…",
                    );
                }
                let _ = crate::components::app::chat_delegate::save_boards_and_wait().await;
            }
            Err(e) => {
                crate::components::app::toasts::show_error(format!(
                    "Succession vote failed: {e}"
                ));
                error.set(Some(format!("Succession vote failed: {e}")));
            }
        }
        busy.set(false);
    });
}

#[component]
pub fn OwnershipView() -> Element {
    use_effect(move || {
        if let Some(owner) = crate::components::app::CURRENT_BOARD.read().owner_key {
            crate::util::safe_spawn_local(async move {
                crate::components::app::member_contract::load_all_member_shards(owner).await;
                crate::components::app::profile_contract::load_all_profile_shards(owner).await;
            });
        }
    });

    let error = use_signal(|| None::<String>);
    let mut outcome = use_signal(|| OutgoingOwnerAction::KeepAdmin);
    let mut confirmed = use_signal(|| false);
    let mut succession_confirmed = use_signal(|| false);
    let busy = use_signal(|| false);

    // Re-read the board when a transfer lands: the component is not otherwise
    // subscribed to the board state it copies here.
    let revision = use_signal(|| 0u32);
    let _ = revision.read();
    let board = ActionContext::from_current_board();
    let Some(ctx) = board else {
        return rsx! {
            div { class: "bg-surface rounded-lg p-4 text-text-muted", "No board selected." }
        };
    };

    let parameters = ChatBoardParametersV1 {
        owner: ctx.current_board,
    };
    let owner_id = ctx.board_state.ownership.current_owner(&parameters);
    let is_owner =
        ctx.owner_sk.verifying_key() == ctx.board_state.ownership.current_owner_key(&parameters);
    let self_id = MemberId::from(&ctx.self_sk.verifying_key());
    let active_admins = ctx
        .board_state
        .ownership
        .current_active_admins(&ctx.board_state, &parameters);
    let is_active_admin = !is_owner && active_admins.contains(&self_id);
    let succession_quorum = required_succession_quorum(active_admins.len());
    let pending_votes = ctx.board_state.ownership.succession_votes.clone();

    let mut merged_members = ctx.board_state.members.clone();
    crate::components::app::member_contract::apply_to_members(
        ctx.current_board,
        &ctx.board_state,
        &mut merged_members,
    );

    // Members that can receive the board: a valid key, not the current owner,
    // not deactivated. An admin target skips the promotion step.
    let candidates: Vec<(MemberId, String, bool)> = merged_members
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
                        div { class: "flex flex-wrap gap-2",
                            for (id, name, is_admin) in candidates.iter() {
                                {
                                    let member = *id;
                                    let click_ctx = ctx.clone();
                                    let click_parameters = parameters.clone();
                                    rsx! {
                                        button {
                                            r#type: "button",
                                            class: "px-3 py-1.5 bg-background border border-border rounded-lg text-sm text-text hover:bg-surface-hover disabled:opacity-50",
                                            disabled: *busy.read(),
                                            onclick: move |_| start_transfer(
                                                member,
                                                click_ctx.clone(),
                                                owner_id,
                                                click_parameters.clone(),
                                                *outcome.peek(),
                                                *confirmed.peek(),
                                                error,
                                                confirmed,
                                                busy,
                                                revision,
                                            ),
                                            if *is_admin { "Transfer to {name} (admin)" } else { "Transfer to {name}" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if is_active_admin || !pending_votes.is_empty() {
                div { class: "bg-surface rounded-lg p-4 space-y-3",
                    h3 { class: "text-text font-medium", "Emergency succession (admin quorum)" }
                    p { class: "text-text-muted text-sm",
                        "If the current owner becomes permanently unreachable, a strict majority of active admins (at least 2) can elect one of the active admins as the new owner."
                    }
                    if let Some(quorum) = succession_quorum {
                        p { class: "text-text-muted text-xs",
                            "Active admins: {active_admins.len()} — Votes required for quorum: {quorum}"
                        }
                    } else {
                        p { class: "text-amber-300 text-xs",
                            "At least 2 active admins are required to enable emergency succession (currently {active_admins.len()})."
                        }
                    }
                    if !pending_votes.is_empty() {
                        div { class: "space-y-1 text-xs text-text-muted",
                            p { class: "text-text font-medium", "Pending succession votes:" }
                            for vote in pending_votes.iter() {
                                p {
                                    "{name_of(vote.vote.voter)} voted for {name_of(vote.vote.to)}"
                                }
                            }
                        }
                    }
                    if is_active_admin {
                        if let Some(quorum) = succession_quorum {
                            label { class: "flex items-center gap-2 text-sm text-text",
                                input {
                                    r#type: "checkbox",
                                    checked: *succession_confirmed.read(),
                                    onchange: move |event| succession_confirmed.set(event.checked()),
                                }
                                "I confirm the current owner is unreachable and I vote to transfer ownership by admin quorum."
                            }
                            div { class: "flex flex-wrap gap-2",
                                for admin_id in active_admins.iter() {
                                    {
                                        let target_admin = *admin_id;
                                        let target_name = name_of(target_admin);
                                        let existing_for_target = pending_votes
                                            .iter()
                                            .filter(|entry| {
                                                entry.vote.to == target_admin
                                                    && entry.vote.voter != self_id
                                            })
                                            .count();
                                        let will_finalize = existing_for_target + 1 >= quorum;
                                        let click_parameters = parameters.clone();
                                        rsx! {
                                            button {
                                                r#type: "button",
                                                class: "px-3 py-1.5 bg-background border border-border rounded-lg text-sm text-text hover:bg-surface-hover disabled:opacity-50",
                                                disabled: *busy.read(),
                                                onclick: move |_| cast_succession_vote(
                                                    target_admin,
                                                    owner_id,
                                                    click_parameters.clone(),
                                                    *succession_confirmed.peek(),
                                                    error,
                                                    succession_confirmed,
                                                    busy,
                                                    revision,
                                                ),
                                                if will_finalize {
                                                    "Vote & finalize for {target_name} ({existing_for_target + 1}/{quorum})"
                                                } else {
                                                    "Vote for {target_name} ({existing_for_target}/{quorum})"
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
                                let method = if entry.is_succession() {
                                    format!(
                                        " - via admin quorum ({} admins)",
                                        entry.succession_approvals.len()
                                    )
                                } else {
                                    String::new()
                                };
                                let digest = change.digest();
                                let signature: String = entry
                                    .signature
                                    .to_bytes()
                                    .iter()
                                    .take(8)
                                    .map(|byte| format!("{byte:02x}"))
                                    .collect();
                                rsx! {
                                    div { class: "bg-background rounded-lg p-3",
                                        p { class: "text-text",
                                            "{name_of(change.from)} -> {name_of(change.to)}"
                                        }
                                        p { class: "text-text-muted text-xs",
                                            "generation {change.generation} - {when} - outgoing owner {outgoing}{method}"
                                        }
                                        p { class: "text-text-muted text-xs font-mono",
                                            "digest {digest:016x} - signature {signature}..."
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
