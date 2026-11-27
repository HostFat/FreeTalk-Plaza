//! Board membership, admin revocation, and category secret distribution helpers.

use crate::components::app::{mark_needs_sync, BOARDS};
use dioxus::logger::tracing::{error, info};
use dioxus::prelude::ReadableExt;
use ed25519_dalek::VerifyingKey;
use freenet_scaffold::ComposableState;
use plaza_core::board_state::admin::{AdminsDelta, AuthorizedAdminRevocation};
use plaza_core::board_state::member::MemberId;
use plaza_core::board_state::{ChatBoardParametersV1, ChatBoardStateV1Delta};

/// Membership and member-info records that put this client back on the board
/// after it was pruned or banned. `None` when it is already a member or has no
/// stored signed membership.
pub(crate) fn self_membership_delta(
    board_data: &crate::board_data::BoardData,
) -> Option<(
    plaza_core::board_state::member::MembersDelta,
    plaza_core::board_state::member_info::AuthorizedMemberInfo,
)> {
    let self_vk = board_data.self_sk.verifying_key();
    let is_in_members = self_vk == board_data.current_owner_key()
        || board_data
            .board_state
            .members
            .members
            .iter()
            .any(|member| member.member.member_vk == self_vk);
    if is_in_members {
        return None;
    }
    let authorized_member = board_data.self_authorized_member.as_ref()?;
    let current_member_ids: std::collections::HashSet<_> = board_data
        .board_state
        .members
        .members
        .iter()
        .map(|member| member.member.id())
        .collect();
    let mut members_to_add = vec![authorized_member.clone()];
    // A token join carries its own join_proof; replaying a stale invite chain
    // on top of it makes the membership delta fail verification.
    if authorized_member.member.join_proof.is_none() {
        for chain_member in &board_data.invite_chain {
            if !current_member_ids.contains(&chain_member.member.id()) {
                members_to_add.push(chain_member.clone());
            }
        }
    }

    use plaza_core::board_state::member_info::{AuthorizedMemberInfo, MemberInfo};
    let authorized_info: AuthorizedMemberInfo =
        if let Some(stored_info) = board_data.self_member_info.as_ref() {
            stored_info.clone()
        } else {
            use plaza_core::board_state::privacy::SealedBytes;
            let member_id = MemberId::from(&self_vk);
            let existing_version = board_data
                .board_state
                .member_info
                .member_info
                .iter()
                .find(|info| info.member_info.member_id == member_id)
                .map(|info| info.member_info.version)
                .unwrap_or(0);
            AuthorizedMemberInfo::new_with_member_key(
                MemberInfo {
                    member_id,
                    version: existing_version,
                    preferred_nickname: SealedBytes::public("Member".to_string().into_bytes()),
                },
                &board_data.self_sk,
            )
        };

    Some((
        plaza_core::board_state::member::MembersDelta::new(members_to_add),
        authorized_info,
    ))
}

/// Remove an admin's rights.
///
/// Only the board owner can do this: the revocation is signed with the owner's
/// key and is permanent for that member.
pub fn revoke_admin(member_id: MemberId) -> Result<(), String> {
    use crate::components::app::CURRENT_BOARD;

    let (current_board, owner_sk, board_state_clone, generation, appointed_at) = {
        let current_board_read = CURRENT_BOARD.read();
        let boards_read = BOARDS.read();

        let current_board = current_board_read.owner_key.ok_or("No board selected")?;
        let board_data = boards_read
            .map
            .get(&current_board)
            .ok_or("Board not found")?;

        if !board_data.is_current_owner() {
            return Err("Only the board owner can remove an admin".to_string());
        }

        let appointed_at = board_data
            .board_state
            .admin
            .admins
            .iter()
            .find(|a| a.admin.id() == member_id)
            .map(|a| a.admin.signed_at);

        (
            current_board,
            board_data.owner_key().clone(),
            board_data.board_state.clone(),
            board_data.board_state.admin.next_generation(&member_id),
            appointed_at,
        )
    };

    let revocation = AuthorizedAdminRevocation::new_at_with_appointment(
        member_id,
        generation,
        crate::util::get_current_system_time(),
        appointed_at,
        &owner_sk,
    );
    let delta = ChatBoardStateV1Delta {
        admin: Some(AdminsDelta::revocation(vec![revocation])),
        ..Default::default()
    };

    let mut apply_error: Option<String> = None;
    BOARDS.with_mut(|boards| {
        if let Some(board_data) = boards.map.get_mut(&current_board) {
            match board_data.board_state.apply_delta(
                &board_state_clone,
                &ChatBoardParametersV1 {
                    owner: current_board,
                },
                &Some(delta),
            ) {
                Ok(_) => mark_needs_sync(current_board),
                Err(e) => apply_error = Some(e),
            }
        }
    });

    match apply_error {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Hand per-category secrets to members who are now in an allowed role.
///
/// Only the owner signs these records, so this is a no-op on other clients.
/// Returns true when a delta was applied and should be pushed to the network.
pub fn distribute_category_secrets(owner: VerifyingKey) -> bool {
    let mut distributed = false;
    BOARDS.with_mut(|boards| {
        let Some(board_data) = boards.map.get_mut(&owner) else {
            return;
        };
        let Some(delta) = board_data.generate_missing_category_secrets() else {
            return;
        };
        let state_before = board_data.board_state.clone();
        let params = ChatBoardParametersV1 { owner };
        match board_data.board_state.apply_delta(
            &state_before,
            &params,
            &Some(ChatBoardStateV1Delta {
                category_secrets: Some(delta),
                ..Default::default()
            }),
        ) {
            Ok(_) => {
                info!("Distributed category secrets to new members");
                board_data.decrypt_category_secrets();
                mark_needs_sync(owner);
                distributed = true;
            }
            Err(e) => error!("Failed to distribute category secrets: {}", e),
        }
    });
    distributed
}
