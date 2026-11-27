//! Board-level moderation configuration helpers.

use crate::util::message_actions::{apply_state_delta, ActionContext};
use plaza_core::board_state::configuration::AuthorizedConfigurationV1;
use plaza_core::board_state::ChatBoardStateV1Delta;

/// Owner-only: require approval for posts by members without an approved post.
pub fn set_approval_required(ctx: &ActionContext, required: bool) -> Result<(), String> {
    if !ctx.is_current_owner() {
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
    let authorized = AuthorizedConfigurationV1::new(config, &ctx.owner_sk);
    let delta = ChatBoardStateV1Delta {
        configuration: Some(authorized),
        ..Default::default()
    };
    apply_state_delta(ctx, delta)
}
