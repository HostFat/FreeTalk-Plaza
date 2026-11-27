//! Shared board-level action context and state delta helpers.

use crate::components::app::{mark_needs_sync, BOARDS};
use crate::util::ecies::seal_bytes;
use dioxus::logger::tracing::warn;
use dioxus::prelude::*;
use ed25519_dalek::{SigningKey, VerifyingKey};
use freenet_scaffold::ComposableState;
use plaza_core::board_state::member::MemberId;
use plaza_core::board_state::privacy::SealedBytes;
use plaza_core::board_state::{ChatBoardParametersV1, ChatBoardStateV1, ChatBoardStateV1Delta};
use plaza_core::chat_delegate::BoardKey;

/// Parameters needed for board-level management and profile actions.
#[derive(Clone)]
pub struct ActionContext {
    pub current_board: VerifyingKey,
    pub board_key: BoardKey,
    pub self_sk: SigningKey,
    pub board_state: ChatBoardStateV1,
    /// Board owner key for ownership and configuration actions.
    pub owner_sk: SigningKey,
    pub is_private: bool,
    pub secret_opt: Option<([u8; 32], u32)>,
}

impl ActionContext {
    /// Create an ActionContext from the current board data, if available.
    pub fn from_current_board() -> Option<Self> {
        Self::build(true)
    }

    /// Like [`Self::from_current_board`] but without the write gate.
    ///
    /// One action needs it: a former owner that is not on the members list any
    /// more publishes its own signed membership to rejoin. The contract still
    /// verifies that record, so nothing else can pass through here.
    pub fn from_current_board_for_repair() -> Option<Self> {
        Self::build(false)
    }

    fn build(check_write: bool) -> Option<Self> {
        use crate::components::app::CURRENT_BOARD;

        let current_board = CURRENT_BOARD.read();
        if let Some(key) = current_board.owner_key {
            let boards = BOARDS.read();
            if let Some(board_data) = boards.map.get(&key) {
                // One gate for every action: banned, suspended and non-member
                // identities get no context, so no action can be sent.
                if check_write {
                    if let Err(error) = board_data.ensure_can_write() {
                        warn!("action context blocked: {error}");
                        return None;
                    }
                }
                return Some(Self {
                    current_board: key,
                    board_key: board_data.board_key(),
                    self_sk: board_data.self_sk.clone(),
                    owner_sk: board_data.owner_key().clone(),
                    board_state: board_data.board_state.clone(),
                    is_private: board_data.is_private(),
                    secret_opt: board_data.get_secret().map(|(s, v)| (*s, v)),
                });
            }
        }
        None
    }

    /// Whether the key in hand is the board's current owner.
    pub fn is_current_owner(&self) -> bool {
        self.owner_sk.verifying_key()
            == self.board_state.ownership.current_owner_key(
                &ChatBoardParametersV1 {
                    owner: self.current_board,
                },
            )
    }

    /// Key and signer id for management records. The owner signs as the owner;
    /// a manager signs as its profile and carries an authority proof.
    pub fn management_signer(&self) -> (SigningKey, Option<MemberId>) {
        if self.is_current_owner() {
            (self.owner_sk.clone(), None)
        } else {
            (
                self.self_sk.clone(),
                Some(MemberId::from(&self.self_sk.verifying_key())),
            )
        }
    }
}

/// Update the current member's nickname in `MemberInfoV1`.
pub async fn set_nickname(ctx: ActionContext, member_id: MemberId, nickname: String) {
    use plaza_core::board_state::member_info::{AuthorizedMemberInfo, MemberInfo};

    let trimmed = nickname.trim();
    if trimmed.is_empty() {
        return;
    }

    let self_id = MemberId::from(&ctx.self_sk.verifying_key());
    let owner_id = MemberId::from(&ctx.current_board);
    let signing_key = if member_id == self_id {
        &ctx.self_sk
    } else if member_id == owner_id && ctx.is_current_owner() {
        &ctx.owner_sk
    } else {
        crate::components::app::toasts::show_error(
            "Only a member can sign updates to their own nickname.",
        );
        return;
    };

    let next_version = ctx
        .board_state
        .member_info
        .member_info
        .iter()
        .find(|info| info.member_info.member_id == member_id)
        .map(|info| info.member_info.version.saturating_add(1))
        .unwrap_or(0);

    let preferred_nickname = if ctx.is_private {
        let Some((key, secret_version)) = ctx.secret_opt else {
            crate::components::app::toasts::show_error(
                "Could not update nickname: the board key is missing",
            );
            return;
        };
        seal_bytes(trimmed.as_bytes(), &key, secret_version)
    } else {
        SealedBytes::public(trimmed.as_bytes().to_vec())
    };

    let info = MemberInfo {
        member_id,
        version: next_version,
        preferred_nickname,
    };
    let authorized = AuthorizedMemberInfo::new_with_member_key(info, signing_key);
    let delta = ChatBoardStateV1Delta {
        member_info: Some(vec![authorized]),
        ..Default::default()
    };

    match apply_state_delta(&ctx, delta) {
        Ok(()) => crate::components::app::toasts::show("Nickname updated. Syncing with the network…"),
        Err(err) => crate::components::app::toasts::show_error(format!(
            "Could not update nickname: {err}"
        )),
    }
}

/// Publish or clear the current member's Freenet Mail address on this board.
/// The address lives in the dedicated `MailAddressesV1` state so a clear is a
/// tombstone, not another append-only action.
pub async fn set_mail_address(ctx: ActionContext, address: Option<String>) {
    use plaza_core::board_state::mail_addresses::{
        AuthorizedMailAddress, MailAddressRecord,
    };

    let member_id = MemberId::from(&ctx.self_sk.verifying_key());
    let version = ctx
        .board_state
        .mail_addresses
        .record_for(member_id)
        .map(|record| record.version.saturating_add(1))
        .unwrap_or(0);
    let sealed = match address {
        Some(address) => {
            let bytes = address.into_bytes();
            if ctx.is_private {
                let Some((key, secret_version)) = ctx.secret_opt else {
                    crate::components::app::toasts::show_error(
                        "Could not update the mail address: the board key is missing",
                    );
                    return;
                };
                Some(seal_bytes(&bytes, &key, secret_version))
            } else {
                Some(SealedBytes::public(bytes))
            }
        }
        None => None,
    };
    let record = MailAddressRecord {
        member_id,
        version,
        address: sealed,
        updated_at: chrono::Utc::now().timestamp_millis(),
    };
    let delta = ChatBoardStateV1Delta {
        mail_addresses: Some(vec![AuthorizedMailAddress::new(record, &ctx.self_sk)]),
        ..Default::default()
    };
    match apply_state_delta(&ctx, delta) {
        Ok(()) => {
            crate::components::app::toasts::show(
                "Mail address updated. Syncing with the network…",
            );
        }
        Err(_) => {
            crate::components::app::toasts::show_error(
                "Could not update the mail address on this board.",
            );
        }
    }
}

pub(crate) fn apply_state_delta(
    ctx: &ActionContext,
    delta: ChatBoardStateV1Delta,
) -> Result<(), String> {
    if let Some(board) = BOARDS.read().map.get(&ctx.current_board) {
        board.ensure_can_write()?;
    }
    apply_state_delta_unchecked(ctx, delta)
}

/// Apply a delta without the write gate. Only the former-owner rejoin uses
/// this: `apply_delta` still verifies every record against the contract rules.
pub(crate) fn apply_state_delta_unchecked(
    ctx: &ActionContext,
    delta: ChatBoardStateV1Delta,
) -> Result<(), String> {
    let parent = ctx.board_state.clone();
    let owner = ctx.current_board;
    let parameters = ChatBoardParametersV1 { owner };

    // Apply to a copy and keep it only when the result verifies, exactly as
    // the contract does. `apply_delta` writes field by field, so a late
    // rejection would otherwise leave the local state half updated.
    let mut next = parent.clone();
    next.apply_delta(&parent, &parameters, &Some(delta))
        .map_err(|e| {
            warn!("state delta rejected locally: {e}");
            e
        })?;
    next.verify(&next, &parameters).map_err(|e| {
        warn!("state delta left an invalid state: {e}");
        e
    })?;

    BOARDS.with_mut(|boards| {
        if let Some(board) = boards.map.get_mut(&owner) {
            board.board_state = next;
        }
    });
    mark_needs_sync(owner);
    Ok(())
}
