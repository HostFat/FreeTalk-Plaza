//! Warning and suspension records.

use crate::util::message_actions::{apply_state_delta, ActionContext};
use plaza_core::board_state::member::MemberId;
use plaza_core::board_state::member_moderation::{
    AuthorizedSuspension, AuthorizedWarning, SuspensionV1, SuspensionsDelta, WarningV1,
    WarningsDelta,
};
use plaza_core::board_state::reports::ReportReason;
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
    let delta = ChatBoardStateV1Delta {
        warnings: Some(WarningsDelta {
            warnings: vec![AuthorizedWarning::new(warning, &ctx.self_sk)],
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
    let delta = ChatBoardStateV1Delta {
        suspensions: Some(SuspensionsDelta {
            suspensions: vec![AuthorizedSuspension::new(suspension, &ctx.self_sk)],
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
            suspensions: vec![AuthorizedSuspension::new(suspension, &ctx.self_sk)],
        }),
        ..Default::default()
    };
    apply_state_delta(ctx, delta)
}
