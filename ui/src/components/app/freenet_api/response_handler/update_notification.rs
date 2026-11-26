use crate::components::app::freenet_api::board_synchronizer::BoardSynchronizer;
use crate::components::app::freenet_api::error::SynchronizerError;
use crate::components::app::sync_info::SYNC_INFO;
use crate::util::try_from_cbor_slice;
use dioxus::logger::tracing::{debug, info, warn};
use dioxus::prelude::ReadableExt;
use freenet_stdlib::prelude::{ContractKey, UpdateData};
use plaza_core::board_state::{ChatBoardStateV1, ChatBoardStateV1Delta};

pub fn handle_update_notification(
    board_synchronizer: &mut BoardSynchronizer,
    key: ContractKey,
    update: UpdateData,
) -> Result<(), SynchronizerError> {
    info!("Received update notification for key: {key}");
    let board_owner_vk = match SYNC_INFO.read().get_owner_vk_for_instance_id(key.id()) {
        Some(vk) => vk,
        None => {
            warn!("Contract key not found in SYNC_INFO: {}", key.id());
            return Ok(());
        }
    };

    match update {
        UpdateData::State(state) => match try_from_cbor_slice::<ChatBoardStateV1>(&state) {
            Ok(new_state) => {
                debug!(
                    "Received new state in UpdateNotification ({} bytes)",
                    state.len()
                );
                board_synchronizer.update_board_state(&board_owner_vk, &new_state);
            }
            Err(e) => {
                warn!("Ignoring malformed board state in UpdateNotification: {e}");
            }
        },
        UpdateData::Delta(delta) => match try_from_cbor_slice::<ChatBoardStateV1Delta>(&delta) {
            Ok(new_delta) => {
                debug!(
                    "Received new delta in UpdateNotification ({} bytes)",
                    delta.len()
                );
                board_synchronizer.apply_delta(&board_owner_vk, new_delta);
            }
            Err(e) => {
                warn!("Ignoring malformed board delta in UpdateNotification: {e}");
            }
        },
        UpdateData::StateAndDelta { state, delta } => {
            debug!(
                "Received state ({} bytes) and delta ({} bytes) in UpdateNotification",
                state.len(),
                delta.len()
            );
            match try_from_cbor_slice::<ChatBoardStateV1>(&state) {
                Ok(new_state) => {
                    board_synchronizer.update_board_state(&board_owner_vk, &new_state);
                }
                Err(e) => {
                    warn!("Ignoring malformed board state in StateAndDelta: {e}");
                }
            }
            if !delta.is_empty() {
                match try_from_cbor_slice::<ChatBoardStateV1Delta>(&delta) {
                    Ok(new_delta) => {
                        board_synchronizer.apply_delta(&board_owner_vk, new_delta);
                    }
                    Err(e) => {
                        warn!("Ignoring malformed board delta in StateAndDelta: {e}");
                    }
                }
            }
        }
        UpdateData::RelatedState { .. } => {
            warn!("Received related state update, ignored");
        }
        UpdateData::RelatedDelta { .. } => {
            warn!("Received related delta update, ignored");
        }
        UpdateData::RelatedStateAndDelta { .. } => {
            warn!("Received related state and delta update, ignored");
        }
        _ => {
            warn!("Received unknown update data variant, ignored");
        }
    }

    Ok(())
}
