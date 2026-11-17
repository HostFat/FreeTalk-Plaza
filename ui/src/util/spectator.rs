//! Open a public board in read-only mode without joining it.
//!
//! The link carries only the board's public key. The client keeps a local
//! identity that is never published, fetches the state and subscribes, so the
//! contract grows by nothing for any number of visitors.

use crate::components::app::chat_delegate::save_boards_to_delegate;
use crate::components::app::sync_info::SYNC_INFO;
use crate::components::app::{BOARDS, CURRENT_BOARD, WEB_API};
use dioxus::logger::tracing::{info, warn};
use dioxus::prelude::*;
use ed25519_dalek::{SigningKey, VerifyingKey};
use freenet_stdlib::client_api::{ClientRequest, ContractRequest};
use plaza_core::board_state::ChatBoardStateV1;
use std::collections::HashMap;

/// Fetch attempts for read-only boards: owner key -> (last attempt ms, count).
static SPECTATOR_FETCHES: GlobalSignal<HashMap<VerifyingKey, (f64, u32)>> =
    Global::new(HashMap::new);

/// Register the board locally (if needed), select it and let the tick fetch it.
pub fn open_spectator_board(owner_vk: VerifyingKey) -> Result<(), String> {
    if BOARDS.read().map.contains_key(&owner_vk) {
        CURRENT_BOARD.with_mut(|current| current.owner_key = Some(owner_vk));
        return Ok(());
    }

    let contract_key = crate::util::owner_vk_to_contract_key(&owner_vk);
    let board_data = crate::board_data::BoardData {
        owner_vk,
        board_state: ChatBoardStateV1::default(),
        self_sk: SigningKey::generate(&mut rand::thread_rng()),
        contract_key,
        last_read_message_id: None,
        secrets: HashMap::new(),
        category_secrets: HashMap::new(),
        old_category_secrets: HashMap::new(),
        trash_secret: None,
        trash_secrets: HashMap::new(),
        collapsed_groups: Vec::new(),
        last_visit: 0,
        read_categories: HashMap::new(),
        draft: None,
        pending_uploads: Vec::new(),
        pending_send: None,
        subscribed_categories: Vec::new(),
        current_secret_version: None,
        last_secret_rotation: None,
        key_migrated_to_delegate: false,
        self_authorized_member: None,
        invite_chain: Vec::new(),
        self_member_info: None,
        spectator: true,
    };

    BOARDS.with_mut(|boards| {
        boards.removed.retain(|vk| *vk != owner_vk);
        boards.map.insert(owner_vk, board_data);
    });
    CURRENT_BOARD.with_mut(|current| current.owner_key = Some(owner_vk));
    crate::util::safe_spawn_local(async {
        if let Err(error) = save_boards_to_delegate().await {
            warn!("Could not store the read-only board: {error}");
        }
    });

    SYNC_INFO.with_mut(|sync_info| sync_info.register_new_board(owner_vk));
    info!(
        "Opening board {:?} as a spectator, contract {}",
        plaza_core::board_state::member::MemberId::from(&owner_vk),
        contract_key.id()
    );
    // The synchronizer fetches the state on its next pass: at this point the
    // WebSocket may still be connecting.
    Ok(())
}

/// Ask for the state of every read-only board that still has none.
///
/// The request cannot be sent once when the link opens: the delegate load and
/// the WebSocket race, and a response that arrives too early is dropped. The
/// housekeeping tick retries a few times and stops once the state arrives.
pub async fn fetch_pending_spectator_boards() {
    let now = crate::util::get_current_system_time()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as f64)
        .unwrap_or(0.0);
    let pending: Vec<VerifyingKey> = {
        let boards = BOARDS.read();
        let attempts = SPECTATOR_FETCHES.read();
        boards
            .map
            .iter()
            .filter(|(_, board)| board.spectator)
            .filter(|(_, board)| {
                board.board_state.members.members.is_empty()
                    && board.board_state.recent_messages.messages.is_empty()
            })
            .filter(|(key, _)| {
                let (last, count) = attempts.get(*key).copied().unwrap_or((0.0, 0));
                count < 20 && now - last > 15_000.0
            })
            .map(|(key, _)| *key)
            .collect()
    };
    for owner_vk in pending {
        let contract_key = crate::util::owner_vk_to_contract_key(&owner_vk);
        let request = ContractRequest::Get {
            key: *contract_key.id(),
            return_contract_code: true,
            subscribe: true,
            blocking_subscribe: true,
        };
        let mut api = WEB_API.write();
        let Some(api) = api.as_mut() else {
            return;
        };
        match api.send(ClientRequest::ContractOp(request)).await {
            Ok(_) => {
                info!(
                    "Requesting state for read-only board {:?}",
                    plaza_core::board_state::member::MemberId::from(&owner_vk)
                );
                SPECTATOR_FETCHES.with_mut(|fetches| {
                    let entry = fetches.entry(owner_vk).or_insert((0.0, 0));
                    entry.0 = now;
                    entry.1 += 1;
                });
            }
            Err(error) => warn!(
                "Could not request the state for read-only board {:?}: {error}",
                plaza_core::board_state::member::MemberId::from(&owner_vk)
            ),
        }
    }
}
