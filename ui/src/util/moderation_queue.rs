//! Signed records for reports, report resolutions and post approvals.

use crate::components::app::{mark_needs_sync, BOARDS};
use crate::util::message_actions::ActionContext;
use freenet_scaffold::ComposableState;
use plaza_core::board_state::approvals::{ApprovalV1, ApprovalsDelta, AuthorizedApproval};
use plaza_core::board_state::configuration::AuthorizedConfigurationV1;
use plaza_core::board_state::member::MemberId;
use plaza_core::board_state::message::MessageId;
use plaza_core::board_state::reports::{
    AuthorizedReport, AuthorizedReportResolution, ReportReason, ReportResolution, ReportStatus,
    ReportV1, ReportsDelta,
};
use plaza_core::board_state::{ChatBoardParametersV1, ChatBoardStateV1Delta};

fn apply(ctx: &ActionContext, delta: ChatBoardStateV1Delta) -> Result<(), String> {
    let parent = ctx.board_state.clone();
    let owner = ctx.current_board;
    let mut error: Option<String> = None;
    BOARDS.with_mut(|boards| {
        if let Some(board) = boards.map.get_mut(&owner) {
            if let Err(e) = board.board_state.apply_delta(
                &parent,
                &ChatBoardParametersV1 { owner },
                &Some(delta),
            ) {
                error = Some(e);
            }
        }
    });
    if let Some(error) = error {
        return Err(error);
    }
    mark_needs_sync(owner);
    Ok(())
}

/// Report a post. The reporter is the signing member.
pub fn report_post(
    ctx: &ActionContext,
    target: MessageId,
    reason: ReportReason,
) -> Result<(), String> {
    let reporter = MemberId::from(&ctx.self_sk.verifying_key());
    let report = ReportV1 {
        target,
        reporter,
        reason,
        created_at: chrono::Utc::now().timestamp_millis(),
    };
    let delta = ChatBoardStateV1Delta {
        reports: Some(ReportsDelta {
            reports: vec![AuthorizedReport::new(report, &ctx.self_sk)],
            resolutions: Vec::new(),
        }),
        ..Default::default()
    };
    apply(ctx, delta)
}

pub fn resolve_report(
    ctx: &ActionContext,
    report_id: MessageId,
    status: ReportStatus,
) -> Result<(), String> {
    let generation = ctx
        .board_state
        .reports
        .resolutions
        .iter()
        .filter(|entry| entry.resolution.report_id == report_id)
        .map(|entry| entry.resolution.generation)
        .max()
        .unwrap_or(0)
        + 1;
    let resolution = ReportResolution {
        report_id,
        status,
        generation,
    };
    let delta = ChatBoardStateV1Delta {
        reports: Some(ReportsDelta {
            reports: Vec::new(),
            resolutions: vec![AuthorizedReportResolution::new(resolution, &ctx.self_sk)],
        }),
        ..Default::default()
    };
    apply(ctx, delta)
}

pub fn approve_post(ctx: &ActionContext, target: MessageId, approved: bool) -> Result<(), String> {
    let generation = ctx
        .board_state
        .approvals
        .approvals
        .iter()
        .filter(|entry| entry.approval.target == target)
        .map(|entry| entry.approval.generation)
        .max()
        .unwrap_or(0)
        + 1;
    let approval = ApprovalV1 {
        target,
        approved,
        generation,
    };
    let delta = ChatBoardStateV1Delta {
        approvals: Some(ApprovalsDelta {
            approvals: vec![AuthorizedApproval::new(approval, &ctx.self_sk)],
        }),
        ..Default::default()
    };
    apply(ctx, delta)
}

/// Owner-only: require approval for posts by members without an approved post.
pub fn set_approval_required(ctx: &ActionContext, required: bool) -> Result<(), String> {
    if ctx.self_sk.verifying_key() != ctx.current_board {
        return Err("Only the board owner can change this setting".to_string());
    }
    if ctx
        .board_state
        .configuration
        .configuration
        .approval_required
        == required
    {
        return Ok(());
    }
    let mut config = ctx.board_state.configuration.configuration.clone();
    config.approval_required = required;
    config.configuration_version += 1;
    let authorized = AuthorizedConfigurationV1::new(config, &ctx.self_sk);
    let delta = ChatBoardStateV1Delta {
        configuration: Some(authorized),
        ..Default::default()
    };
    apply(ctx, delta)
}
