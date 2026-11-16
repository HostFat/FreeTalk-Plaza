//! Warning and suspension records.

use crate::util::message_actions::{apply_state_delta, ActionContext};
use crate::util::get_current_system_time;
use plaza_core::board_state::member::MemberId;
use plaza_core::board_state::member_moderation::{
    AuthorizedSuspension, AuthorizedWarning, SuspensionV1, SuspensionsDelta, WarningV1,
    WarningsDelta,
};
use plaza_core::board_state::reports::ReportReason;
use plaza_core::board_state::roles::{
    admin_authority_proof, AuthorizedRoleAssignment, RoleAssignment, RolesDelta,
};
use plaza_core::board_state::ChatBoardStateV1Delta;

pub fn warn_member(
    ctx: &ActionContext,
    target: MemberId,
    reason: ReportReason,
) -> Result<(), String> {
    let warning = WarningV1 {
        target,
        reason,
        created_at: chrono::Utc::now().timestamp_millis(),
    };
    let delta =
        ChatBoardStateV1Delta {
            warnings: Some(WarningsDelta {
                warnings: vec![AuthorizedWarning::new(warning, &ctx.self_sk)
                    .with_optional_authority(admin_authority_proof(
                        &ctx.board_state,
                        &MemberId::from(&ctx.self_sk.verifying_key()),
                    ))],
            }),
            ..Default::default()
        };
    apply_state_delta(ctx, delta)
}

/// Suspend a member for `days` days. The contract stores the record; clients
/// stop the member from posting until it ends.
pub fn suspend_member(
    ctx: &ActionContext,
    target: MemberId,
    reason: ReportReason,
    days: i64,
) -> Result<(), String> {
    let now = chrono::Utc::now().timestamp_millis();
    let generation = ctx
        .board_state
        .suspensions
        .suspensions
        .iter()
        .filter(|entry| entry.suspension.target == target)
        .map(|entry| entry.suspension.generation)
        .max()
        .unwrap_or(0)
        + 1;
    let suspension = SuspensionV1 {
        target,
        reason,
        until: now + days.max(1) * 24 * 60 * 60 * 1000,
        created_at: now,
        generation,
    };
    // A suspended member must not keep moderation powers. The contract cannot
    // read a clock, so the role assignment is revoked explicitly; the owner
    // re-assigns it after the suspension if the member should keep the role.
    let signer_id = MemberId::from(&ctx.self_sk.verifying_key());
    let role_revocations: Vec<_> = ctx
        .board_state
        .roles
        .assignments
        .iter()
        .filter(|entry| entry.assignment.member_id == target && !entry.assignment.revoked)
        .map(|entry| {
            // Name the real signer: an admin's revocation signed through
            // `new` would claim the owner's key and fail verification.
            AuthorizedRoleAssignment::signed_by(
                RoleAssignment {
                    role_id: entry.assignment.role_id,
                    member_id: target,
                    generation: entry.assignment.generation + 1,
                    revoked: true,
                    signed_at: get_current_system_time(),
                },
                signer_id,
                &ctx.self_sk,
            )
            .with_optional_authority(admin_authority_proof(&ctx.board_state, &signer_id))
        })
        .collect();
    let delta = ChatBoardStateV1Delta {
        suspensions: Some(SuspensionsDelta {
            suspensions: vec![AuthorizedSuspension::new(suspension, &ctx.self_sk)
                .with_optional_authority(admin_authority_proof(
                    &ctx.board_state,
                    &MemberId::from(&ctx.self_sk.verifying_key()),
                ))],
        }),
        roles: Some(RolesDelta {
            roles: Vec::new(),
            assignments: role_revocations,
        }),
        ..Default::default()
    };
    apply_state_delta(ctx, delta)
}

/// End an active suspension by writing a record that expires immediately
/// before the current time.
pub fn lift_suspension(ctx: &ActionContext, target: MemberId) -> Result<(), String> {
    let now = chrono::Utc::now().timestamp_millis();
    let generation = ctx
        .board_state
        .suspensions
        .suspensions
        .iter()
        .filter(|entry| entry.suspension.target == target)
        .map(|entry| entry.suspension.generation)
        .max()
        .unwrap_or(0)
        + 1;
    let suspension = SuspensionV1 {
        target,
        reason: ReportReason::Other,
        until: now,
        created_at: now - 1,
        generation,
    };
    let delta = ChatBoardStateV1Delta {
        suspensions: Some(SuspensionsDelta {
            suspensions: vec![AuthorizedSuspension::new(suspension, &ctx.self_sk)
                .with_optional_authority(admin_authority_proof(
                    &ctx.board_state,
                    &MemberId::from(&ctx.self_sk.verifying_key()),
                ))],
        }),
        ..Default::default()
    };
    apply_state_delta(ctx, delta)
}
