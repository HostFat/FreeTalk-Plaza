//! Put this client back on the board after a lift or a prune.

use crate::components::app::{BOARDS, CURRENT_BOARD};
use crate::util::message_actions::{
    apply_state_delta, apply_state_delta_unchecked, ActionContext,
};
use dioxus::logger::tracing::{info, warn};
use dioxus::prelude::*;
use plaza_core::board_state::member::{AuthorizedMember, Member, MemberId, MembersDelta};
use plaza_core::board_state::ChatBoardStateV1Delta;

/// Re-publish the stored signed membership when this client is not a member
/// and no ban for it remains. Returns true when a delta was applied.
///
/// A former owner has no stored record: after handing the board over it signs
/// its own membership, so it can rejoin if the record was pruned or removed.
pub fn restore_self_membership() -> bool {
    info!("membership restore: called");
    let Some(board_key) = CURRENT_BOARD.read().owner_key else {
        info!("membership restore skipped: no current board");
        return false;
    };
    // A legacy action in the stored state can make every full-state update
    // fail contract verification. Remove it before publishing the membership.
    let pruned = BOARDS.with_mut(|boards| {
        boards
            .map
            .get_mut(&board_key)
            .map(|board| {
                let params = plaza_core::board_state::ChatBoardParametersV1 {
                    owner: board_key,
                };
                let bad = crate::signing::remove_unverifiable_messages(
                    &mut board.board_state,
                    &params,
                );
                bad + board.prune_invalid_actions()
            })
            .unwrap_or(0)
    });
    if pruned > 0 {
        info!("membership restore: pruned {pruned} invalid action message(s)");
    }

    let board = {
        let boards = BOARDS.read();
        let Some(board) = boards.map.get(&board_key).cloned() else {
            info!("membership restore skipped: current board is not in the board map");
            return false;
        };
        board
    };
    let self_id = MemberId::from(&board.self_sk.verifying_key());
    // The current owner has no member record; a former owner is an ordinary
    // member and may need one. Check the visible key: a client can hold the
    // owner key while posting as a separate profile, and that profile still
    // needs its member record.
    if board.self_sk.verifying_key() == board.current_owner_key() {
        return false;
    }
    if board
        .board_state
        .members
        .members
        .iter()
        .any(|member| member.member.id() == self_id)
    {
        info!("membership restore skipped: already a member");
        return false;
    }
    if board
        .board_state
        .bans
        .0
        .iter()
        .any(|ban| ban.ban.banned_user == self_id)
    {
        warn!("membership restore skipped: this member is banned");
        return false;
    }

    let former_owner = board.board_state.ownership.was_owner(&self_id);
    let (delta, profile_info) = if let Some((members, member_info)) =
        crate::util::messaging::self_membership_delta(&board)
    {
        (
            ChatBoardStateV1Delta {
                members: Some(members),
                ..Default::default()
            },
            Some(member_info),
        )
    } else if former_owner {
        // The former owner signs its own record: the new owner cannot sign on
        // its behalf, and the contract accepts it because this key used to own
        // the board.
        info!("membership restore: publishing the former owner's own record");
        (
            ChatBoardStateV1Delta {
                members: Some(MembersDelta::new(vec![AuthorizedMember::new(
                    Member {
                        owner_member_id: MemberId::from(&board.owner_vk),
                        invited_by: self_id,
                        member_vk: board.self_sk.verifying_key(),
                        join_proof: None,
                    },
                    &board.self_sk,
                )])),
                ..Default::default()
            },
            None,
        )
    } else {
        warn!("membership restore skipped: no stored membership to publish");
        return false;
    };

    let Some(ctx) = ActionContext::from_current_board_for_repair() else {
        warn!("membership restore skipped: action context unavailable");
        return false;
    };
    let result = if former_owner {
        apply_state_delta_unchecked(&ctx, delta)
    } else {
        apply_state_delta(&ctx, delta)
    };
    if let Some(info) = profile_info {
        let signer_key = board.self_sk.verifying_key();
        crate::util::safe_spawn_local(async move {
            let _ = crate::components::app::profile_contract::record_member_info(
                board_key,
                info,
                signer_key,
            )
            .await;
        });
    }
    match result {
        Ok(()) => {
            info!("membership restore published the stored member record");
            true
        }
        Err(error) => {
            warn!("membership restore failed: {error}");
            false
        }
    }
}
