//! Put this client back on the board after a lift or a prune.

use crate::components::app::{BOARDS, CURRENT_BOARD};
use crate::util::message_actions::{apply_state_delta, ActionContext};
use dioxus::prelude::*;
use plaza_core::board_state::member::MemberId;
use plaza_core::board_state::ChatBoardStateV1Delta;

/// Re-publish the stored signed membership when this client is not a member
/// and no ban for it remains. Returns true when a delta was applied.
pub fn restore_self_membership() -> bool {
    let Some(board_key) = CURRENT_BOARD.read().owner_key else {
        return false;
    };
    let board = {
        let boards = BOARDS.read();
        let Some(board) = boards.map.get(&board_key).cloned() else {
            return false;
        };
        board
    };
    let self_id = MemberId::from(&board.self_sk.verifying_key());
    if self_id == MemberId::from(&board.owner_vk) {
        return false;
    }
    if board
        .board_state
        .members
        .members
        .iter()
        .any(|member| member.member.id() == self_id)
    {
        return false;
    }
    if board
        .board_state
        .bans
        .0
        .iter()
        .any(|ban| ban.ban.banned_user == self_id)
    {
        return false;
    }
    let Some((members, member_info)) = crate::util::messaging::self_membership_delta(&board) else {
        return false;
    };
    let delta = ChatBoardStateV1Delta {
        members: Some(members),
        member_info: Some(member_info),
        ..Default::default()
    };
    let Some(ctx) = ActionContext::from_current_board() else {
        return false;
    };
    apply_state_delta(&ctx, delta).is_ok()
}
