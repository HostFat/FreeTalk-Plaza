mod get_response;
mod put_response;
mod subscribe_response;
mod update_notification;
mod update_response;

use super::board_synchronizer::BoardSynchronizer;
use super::error::SynchronizerError;
use crate::board_data::Boards;
use crate::components::app::chat_delegate::{
    complete_pending_public_key_request, complete_pending_request, complete_pending_sign_request,
    complete_pending_signing_key_request, is_legacy_delegate_key, mark_legacy_migration_done,
    save_boards_to_delegate, BOARDS_STORAGE_KEY,
};
use crate::components::app::document_title::{mark_current_board_as_read, update_document_title};
use crate::components::app::notifications::mark_initial_sync_complete;
use crate::components::app::sync_info::{BoardSyncStatus, SYNC_INFO};
use crate::components::app::{BOARDS, BOARDS_LOADED, DELEGATE_HAD_BOARDS};
use crate::util::ecies::decrypt_secret_from_member_blob;
use crate::util::owner_vk_to_contract_key;
use ciborium::de::from_reader;
use dioxus::logger::tracing::{error, info, warn};
use dioxus::prelude::ReadableExt;

use freenet_stdlib::client_api::{ContractResponse, HostResponse};
use freenet_stdlib::prelude::OutboundDelegateMsg;
pub use get_response::handle_get_response;
use plaza_core::board_state::member::MemberId;
use plaza_core::board_state::privacy::PrivacyMode;
use plaza_core::board_state::ChatBoardParametersV1;
use plaza_core::chat_delegate::{ChatDelegateRequestMsg, ChatDelegateResponseMsg};
pub use put_response::handle_put_response;
pub use subscribe_response::handle_subscribe_response;
pub use update_notification::handle_update_notification;
pub use update_response::handle_update_response;
use x25519_dalek::PublicKey as X25519PublicKey;

/// Handles responses from the Freenet API
pub struct ResponseHandler {
    board_synchronizer: BoardSynchronizer,
}

/// Response flags returned from handle_api_response
#[derive(Default)]
pub struct ResponseFlags {
    /// True if a re-PUT should be scheduled (subscription failed but we have local state)
    pub needs_reput: bool,
    /// True if subscriptions were initiated and need timeout monitoring
    pub subscriptions_initiated: bool,
}

impl ResponseHandler {
    pub fn new(board_synchronizer: BoardSynchronizer) -> Self {
        Self { board_synchronizer }
    }

    // Create a new ResponseHandler that shares the same BoardSynchronizer
    pub fn new_with_shared_synchronizer(synchronizer: &BoardSynchronizer) -> Self {
        // Clone the BoardSynchronizer to share the same state
        Self {
            board_synchronizer: synchronizer.clone(),
        }
    }

    /// Handles individual API responses.
    /// Returns flags indicating what follow-up actions are needed.
    pub async fn handle_api_response(
        &mut self,
        response: HostResponse,
    ) -> Result<ResponseFlags, SynchronizerError> {
        let mut flags = ResponseFlags::default();

        match response {
            HostResponse::Ok => {
                info!("Received OK response from API");
            }
            HostResponse::ContractResponse(contract_response) => match contract_response {
                ContractResponse::GetResponse {
                    key,
                    contract: _,
                    state,
                } => {
                    handle_get_response(
                        &mut self.board_synchronizer,
                        key,
                        Vec::new(),
                        state.to_vec(),
                    )
                    .await?;
                }
                ContractResponse::PutResponse { key } => {
                    handle_put_response(&mut self.board_synchronizer, key).await?;
                }
                ContractResponse::UpdateNotification { key, update } => {
                    handle_update_notification(&mut self.board_synchronizer, key, update)?;
                }
                ContractResponse::UpdateResponse { key, summary } => {
                    handle_update_response(key, summary.to_vec());
                }
                ContractResponse::SubscribeResponse { key, subscribed } => {
                    flags.needs_reput = handle_subscribe_response(key, subscribed);
                    if subscribed {
                        // Fetch current contract state after successful subscribe.
                        // On reconnect, boards loaded from delegate storage may be stale.
                        // Subscribe doesn't return state, so we need an explicit GET.
                        if let Err(e) = self.board_synchronizer.get_contract_state(&key).await {
                            error!(
                                "Failed to GET state after subscribe for {}: {}",
                                key.id(),
                                e
                            );
                        }
                    }
                }
                _ => {
                    info!("Unhandled contract response: {:?}", contract_response);
                }
            },
            HostResponse::DelegateResponse { key, values } => {
                // Check if this is a response from any known legacy delegate
                let is_legacy_delegate = is_legacy_delegate_key(key.bytes());
                if is_legacy_delegate {
                    info!("Received response from LEGACY delegate - checking for migration data");
                }

                info!(
                    "Received delegate response from API with key: {:?} containing {} values",
                    key,
                    values.len()
                );
                for (i, v) in values.iter().enumerate() {
                    info!("Processing delegate response value #{}", i);
                    match v {
                        OutboundDelegateMsg::ApplicationMessage(app_msg) => {
                            info!(
                                "Delegate response is an ApplicationMessage, processed flag: {}",
                                app_msg.processed
                            );

                            // Log the raw payload for debugging
                            let payload_str = if app_msg.payload.len() < 100 {
                                format!("{:?}", app_msg.payload)
                            } else {
                                format!("{:?}... (truncated)", &app_msg.payload[..100])
                            };
                            info!("ApplicationMessage payload: {}", payload_str);

                            // Try to deserialize as a response
                            let deserialization_result = from_reader::<ChatDelegateResponseMsg, _>(
                                app_msg.payload.as_slice(),
                            );

                            // Also try to deserialize as a request to see if that's what's happening
                            let request_deser_result = from_reader::<ChatDelegateRequestMsg, _>(
                                app_msg.payload.as_slice(),
                            );
                            info!(
                                "Deserialization as request result: {:?}",
                                request_deser_result.is_ok()
                            );

                            if let Ok(response) = deserialization_result {
                                // Never log the whole value: the boards store can
                                // be tens of megabytes, and formatting it here
                                // freezes the page before it is applied.
                                let summary = match &response {
                                    ChatDelegateResponseMsg::GetResponse { key, value } => {
                                        format!(
                                            "GetResponse key={key:?} value_bytes={}",
                                            value.as_ref().map_or(0, Vec::len)
                                        )
                                    }
                                    ChatDelegateResponseMsg::ListResponse { keys } => {
                                        format!("ListResponse keys={}", keys.len())
                                    }
                                    ChatDelegateResponseMsg::StoreResponse {
                                        key,
                                        value_size,
                                        result,
                                    } => format!(
                                        "StoreResponse key={key:?} value_size={value_size} result={result:?}"
                                    ),
                                    ChatDelegateResponseMsg::DeleteResponse { key, result } => {
                                        format!("DeleteResponse key={key:?} result={result:?}")
                                    }
                                    ChatDelegateResponseMsg::StoreSigningKeyResponse {
                                        board_key,
                                        result,
                                    } => format!(
                                        "StoreSigningKeyResponse board={board_key:?} result={result:?}"
                                    ),
                                    ChatDelegateResponseMsg::GetPublicKeyResponse {
                                        board_key,
                                        public_key,
                                    } => format!(
                                        "GetPublicKeyResponse board={board_key:?} found={}",
                                        public_key.is_some()
                                    ),
                                    ChatDelegateResponseMsg::SignResponse {
                                        board_key,
                                        request_id,
                                        signature,
                                    } => format!(
                                        "SignResponse board={board_key:?} request={request_id} ok={}",
                                        signature.is_ok()
                                    ),
                                };
                                info!(
                                    "Successfully deserialized as ChatDelegateResponseMsg: {summary}"
                                );

                                // Try to complete any pending request waiting for this response
                                let completed = match &response {
                                    // Key-value storage responses
                                    ChatDelegateResponseMsg::GetResponse { key, .. } => {
                                        complete_pending_request(key, response.clone())
                                    }
                                    ChatDelegateResponseMsg::StoreResponse { key, .. } => {
                                        complete_pending_request(key, response.clone())
                                    }
                                    ChatDelegateResponseMsg::DeleteResponse { key, .. } => {
                                        complete_pending_request(key, response.clone())
                                    }
                                    ChatDelegateResponseMsg::ListResponse { .. } => {
                                        // Use the special list request key
                                        let list_key =
                                            plaza_core::chat_delegate::ChatDelegateKey::new(
                                                b"__list_request__".to_vec(),
                                            );
                                        complete_pending_request(&list_key, response.clone())
                                    }
                                    // Signing key management responses
                                    ChatDelegateResponseMsg::StoreSigningKeyResponse {
                                        board_key,
                                        ..
                                    } => complete_pending_signing_key_request(
                                        board_key,
                                        response.clone(),
                                    ),
                                    ChatDelegateResponseMsg::GetPublicKeyResponse {
                                        board_key,
                                        ..
                                    } => complete_pending_public_key_request(
                                        board_key,
                                        response.clone(),
                                    ),
                                    // Signing response - use both board_key and request_id for correlation
                                    ChatDelegateResponseMsg::SignResponse {
                                        board_key,
                                        request_id,
                                        ..
                                    } => complete_pending_sign_request(
                                        board_key,
                                        *request_id,
                                        response.clone(),
                                    ),
                                };

                                if completed {
                                    info!("Completed pending delegate request");
                                }

                                // Process the response based on its type
                                match response {
                                    ChatDelegateResponseMsg::GetResponse { key, value } => {
                                        info!(
                                            "Got value for key: {:?}, value present: {}",
                                            String::from_utf8_lossy(key.as_bytes()),
                                            value.is_some()
                                        );

                                        // Check if this is the boards data. A save reads it
                                        // first to merge boards added by another tab; that
                                        // read must not run the startup load path.
                                        if key.as_bytes() == BOARDS_STORAGE_KEY
                                            && !crate::components::app::chat_delegate::BOARDS_READ_FOR_MERGE
                                                .swap(false, std::sync::atomic::Ordering::SeqCst)
                                        {
                                            if let Some(boards_data) = value {
                                                // Deserialize the boards data
                                                match from_reader::<Boards, _>(&boards_data[..]) {
                                                    Ok(loaded_boards) => {
                                                        let stored_pending: usize = loaded_boards
                                                            .map
                                                            .values()
                                                            .map(|board| board.pending_uploads.len())
                                                            .sum();
                                                        info!(
                                                            "Loaded boards from delegate: {} boards, {} pending uploads",
                                                            loaded_boards.map.len(),
                                                            stored_pending
                                                        );
                                                        // TODO: Remove legacy migration code after 2026-03-01
                                                        if is_legacy_delegate {
                                                            info!("Successfully loaded boards from LEGACY delegate - migrating to new delegate");
                                                        } else {
                                                            info!("Successfully loaded boards from delegate");
                                                        }

                                                        if !loaded_boards.map.is_empty() {
                                                            *DELEGATE_HAD_BOARDS.write() = true;
                                                        }
                                                        // Older blobs kept the image index
                                                        // inside the board map. Note it so the
                                                        // separate key is written after loading.
                                                        crate::util::owned_images::note_legacy(
                                                            !loaded_boards.owned_images.is_empty(),
                                                        );

                                                        // Collect board keys and signing keys before merge
                                                        // (must extract before loaded_boards is moved into defer)
                                                        let board_keys: Vec<_> = loaded_boards
                                                            .map
                                                            .keys()
                                                            .copied()
                                                            .collect();
                                                        let signing_keys: Vec<_> = loaded_boards
                                                            .map
                                                            .iter()
                                                            .map(|(key, board_data)| {
                                                                (
                                                                    *key,
                                                                    board_data.board_key(),
                                                                    board_data.self_sk.clone(),
                                                                )
                                                            })
                                                            .collect();
                                                        // Keep the states so each one can be put back on
                                                        // the node after a contract re-key.
                                                        let states_for_put: Vec<(
                                                            ed25519_dalek::VerifyingKey,
                                                            plaza_core::ChatBoardStateV1,
                                                        )> = loaded_boards
                                                            .map
                                                            .iter()
                                                            .map(|(key, board_data)| {
                                                                (*key, board_data.board_state.clone())
                                                            })
                                                            .collect();

                                                        // Merge the loaded boards with the current boards
                                                        crate::util::defer(move || {
                                                            BOARDS.with_mut(|current_boards| {
                                                            if let Err(e) = current_boards.merge(loaded_boards) {
                                                                error!("Failed to merge boards: {}", e);
                                                            } else {
                                                                info!("Successfully merged boards from delegate");

                                                                // Re-decrypt ALL secret versions for each board (secrets are #[serde(skip)])
                                                                for board_data in current_boards.map.values_mut() {
                                                                    if board_data.board_state.configuration.configuration.privacy_mode == PrivacyMode::Private {
                                                                        let member_id = MemberId::from(&board_data.self_sk.verifying_key());
                                                                        let current_version = board_data.board_state.secrets.current_version;
                                                                        let self_sk = board_data.self_sk.clone();

                                                                        // Extract encrypted secret data to avoid borrow issues
                                                                        let member_secrets: Vec<_> = board_data
                                                                            .board_state
                                                                            .secrets
                                                                            .encrypted_secrets
                                                                            .iter()
                                                                            .filter(|s| s.secret.member_id == member_id)
                                                                            .map(|s| (
                                                                                s.secret.secret_version,
                                                                                s.secret.ciphertext.clone(),
                                                                                s.secret.nonce,
                                                                                s.secret.sender_ephemeral_public_key,
                                                                            ))
                                                                            .collect();

                                                                        if member_secrets.is_empty() {
                                                                            warn!("No encrypted secrets found for member {:?}", member_id);
                                                                        } else {
                                                                            info!("Found {} encrypted secrets for member {:?}", member_secrets.len(), member_id);
                                                                            for (version, ciphertext, nonce, ephemeral_key_bytes) in member_secrets {
                                                                                let ephemeral_key = X25519PublicKey::from(ephemeral_key_bytes);
                                                                                match decrypt_secret_from_member_blob(
                                                                                    &ciphertext,
                                                                                    &nonce,
                                                                                    &ephemeral_key,
                                                                                    &self_sk,
                                                                                ) {
                                                                                    Ok(decrypted_secret) => {
                                                                                        info!("Re-decrypted board secret version {} for member {:?}", version, member_id);
                                                                                        board_data.set_secret(decrypted_secret, version);
                                                                                    }
                                                                                    Err(e) => {
                                                                                        warn!("Failed to re-decrypt board secret version {}: {}", version, e);
                                                                                    }
                                                                                }
                                                                            }
                                                                        }

                                                                        // Ensure current_secret_version is set to the actual current version
                                                                        board_data.current_secret_version = Some(current_version);
                                                                        board_data.decrypt_pq_board_secrets();
                                                                    }
                                                                }

                                                                // Rebuild actions_state for each loaded board.
                                                                // actions_state is #[serde(skip)]; private and
                                                                // category-scoped actions need their key.
                                                                for board_data in current_boards.map.values_mut() {
                                                                    let owner = board_data.owner_vk;
                                                                    board_data.decrypt_category_secrets();
                                                                    board_data.rebuild_actions_with_local_secrets(
                                                                        &ChatBoardParametersV1 { owner },
                                                                    );
                                                                }
                                                            }
                                                        });
                                                            // Saves are refused until this is true, so set it only
                                                            // after the merge has placed the stored boards in BOARDS.
                                                            *BOARDS_LOADED.write() = true;
                                                        });

                                                        // The board list is already usable; fetch the
                                                        // larger image index separately so startup does not
                                                        // wait for it.
                                                        wasm_bindgen_futures::spawn_local(async {
                                                            crate::components::app::chat_delegate::fire_load_owned_images_request().await;
                                                        });

                                                        // Mark current board as read since user is viewing it
                                                        // (must be after merge so board data exists)
                                                        crate::util::defer(|| {
                                                            mark_current_board_as_read();
                                                            update_document_title();
                                                        });

                                                        // Migrate signing keys to delegate for each loaded board
                                                        // (uses pre-extracted signing_keys since BOARDS merge is deferred)
                                                        info!("Migrating signing keys to delegate for {} boards", signing_keys.len());
                                                        for (
                                                            board_key,
                                                            delegate_board_key,
                                                            signing_key,
                                                        ) in &signing_keys
                                                        {
                                                            {
                                                                // Spawn async migration task
                                                                let board_key_copy = *board_key;
                                                                let delegate_board_key =
                                                                    *delegate_board_key;
                                                                let signing_key =
                                                                    signing_key.clone();
                                                                wasm_bindgen_futures::spawn_local(
                                                                    async move {
                                                                        let migrated = crate::signing::migrate_signing_key(
                                                                        delegate_board_key,
                                                                        &signing_key,
                                                                    )
                                                                    .await;

                                                                        if migrated {
                                                                            // Must defer signal mutations from spawn_local to
                                                                            // avoid RefCell already borrowed panics in Dioxus runtime
                                                                            crate::util::defer(
                                                                                move || {
                                                                                    BOARDS.with_mut(|boards| {
                                                                                if let Some(board_data) = boards.map.get_mut(&board_key_copy) {
                                                                                    board_data.key_migrated_to_delegate = true;
                                                                                }
                                                                            });
                                                                                },
                                                                            );
                                                                        }
                                                                    },
                                                                );
                                                            }
                                                        }

                                                        // Mark all loaded boards as having completed initial sync
                                                        // and subscribe to receive updates
                                                        for board_key in &board_keys {
                                                            let board_key_copy = *board_key;
                                                            crate::util::defer(move || {
                                                                mark_initial_sync_complete(
                                                                    &board_key_copy,
                                                                );
                                                            });
                                                        }

                                                        // Subscribe to each loaded board's contract
                                                        info!(
                                                            "Subscribing to {} boards loaded from delegate",
                                                            board_keys.len()
                                                        );
                                                        for board_key in board_keys {
                                                            // Register the board in SYNC_INFO
                                                            crate::util::defer(move || {
                                                                SYNC_INFO
                                                                    .write()
                                                                    .register_new_board(board_key);
                                                                SYNC_INFO
                                                                    .write()
                                                                    .update_sync_status(
                                                                    &board_key,
                                                                    BoardSyncStatus::Subscribing,
                                                                );
                                                            });

                                                            // A board loaded from the delegate may have
                                                            // been created with an older contract build.
                                                            // Put the state back first: the node must
                                                            // cache the WASM and parameters before a
                                                            // subscribe can succeed.
                                                            if let Some((_, state)) = states_for_put
                                                                .iter()
                                                                .find(|(key, _)| key == &board_key)
                                                            {
                                                                match republish_board(board_key, state).await {
                                                                    Ok(()) => info!(
                                                                        "Re-published board state for {:?}",
                                                                        owner_vk_to_contract_key(&board_key).id()
                                                                    ),
                                                                    Err(e) => error!(
                                                                        "Failed to re-publish board {:?}: {}",
                                                                        owner_vk_to_contract_key(&board_key).id(),
                                                                        e
                                                                    ),
                                                                }
                                                            }

                                                            // Get contract key and subscribe
                                                            let contract_key =
                                                                owner_vk_to_contract_key(
                                                                    &board_key,
                                                                );
                                                            if let Err(e) = self
                                                                .board_synchronizer
                                                                .subscribe_to_contract(
                                                                    &contract_key,
                                                                )
                                                                .await
                                                            {
                                                                error!(
                                                                    "Failed to subscribe to loaded board {:?}: {}",
                                                                    contract_key.id(),
                                                                    e
                                                                );
                                                            } else {
                                                                info!(
                                                                    "Successfully sent subscribe request for loaded board {:?}",
                                                                    contract_key.id()
                                                                );
                                                                // Mark that subscriptions were initiated so timeout monitoring can be scheduled
                                                                flags.subscriptions_initiated =
                                                                    true;
                                                            }
                                                        }

                                                        // TODO: Remove legacy migration code after 2026-03-01
                                                        // If this was from the legacy delegate, save to the new delegate
                                                        if is_legacy_delegate {
                                                            info!("Migrating board data from legacy delegate to new delegate");
                                                            wasm_bindgen_futures::spawn_local(
                                                                async {
                                                                    match save_boards_to_delegate()
                                                                        .await
                                                                    {
                                                                        Ok(_) => {
                                                                            info!("Successfully migrated board data to new delegate");
                                                                            mark_legacy_migration_done();
                                                                        }
                                                                        Err(e) => {
                                                                            error!("Failed to migrate board data to new delegate: {}", e);
                                                                            // Don't mark as done - will retry on next startup
                                                                        }
                                                                    }
                                                                },
                                                            );
                                                        } else {
                                                            // Current delegate successfully returned data - no migration needed
                                                            mark_legacy_migration_done();
                                                        }
                                                    }
                                                    Err(e) => {
                                                        error!(
                                                            "Failed to deserialize boards data: {}",
                                                            e
                                                        );
                                                    }
                                                }
                                            } else {
                                                info!("No boards data found in delegate");
                                                // Nothing stored: the empty map in memory is the truth,
                                                // so saving is safe from now on.
                                                *BOARDS_LOADED.write() = true;
                                                // Mark migration as done regardless of which delegate responded.
                                                // - If current delegate: we successfully communicated with it,
                                                //   so legacy migration isn't needed
                                                // - If legacy delegate: it has no data, so nothing to migrate
                                                mark_legacy_migration_done();
                                            }
                                        } else if key.as_bytes()
                                            == crate::components::app::chat_delegate::OWNED_IMAGES_STORAGE_KEY
                                        {
                                            let loaded = value.and_then(|bytes| {
                                                match from_reader::<
                                                    Vec<crate::board_data::OwnedImage>,
                                                    _,
                                                >(&bytes[..])
                                                {
                                                    Ok(list) => Some(list),
                                                    Err(error) => {
                                                        error!(
                                                            "Failed to deserialize the owned images: {error}"
                                                        );
                                                        None
                                                    }
                                                }
                                            });
                                            let legacy =
                                                crate::util::owned_images::take_legacy();
                                            crate::util::defer(move || {
                                                crate::util::owned_images::apply_loaded(loaded);
                                                let has_any = !BOARDS.read().owned_images.is_empty();
                                                // The board blob still carried entries:
                                                // write them under the new key once. A
                                                // missing key with no legacy entries has
                                                // nothing to migrate.
                                                if legacy && has_any {
                                                    crate::util::owned_images::mark_dirty();
                                                    wasm_bindgen_futures::spawn_local(async {
                                                        if let Err(error) =
                                                            save_boards_to_delegate().await
                                                        {
                                                            warn!(
                                                                "Could not migrate the owned images: {error}"
                                                            );
                                                        }
                                                    });
                                                }
                                            });
                                        } else {
                                            warn!(
                                                "Unexpected key in GetResponse: {:?}",
                                                String::from_utf8_lossy(key.as_bytes())
                                            );
                                        }
                                    }
                                    ChatDelegateResponseMsg::ListResponse { keys } => {
                                        info!("Listed {} keys", keys.len());
                                    }
                                    ChatDelegateResponseMsg::StoreResponse {
                                        key,
                                        result,
                                        value_size: _,
                                    } => match result {
                                        Ok(_) => info!(
                                            "Successfully stored key: {:?}",
                                            String::from_utf8_lossy(key.as_bytes())
                                        ),
                                        Err(e) => warn!(
                                            "Failed to store key: {:?}, error: {}",
                                            String::from_utf8_lossy(key.as_bytes()),
                                            e
                                        ),
                                    },
                                    ChatDelegateResponseMsg::DeleteResponse { key, result } => {
                                        match result {
                                            Ok(_) => info!(
                                                "Successfully deleted key: {:?}",
                                                String::from_utf8_lossy(key.as_bytes())
                                            ),
                                            Err(e) => warn!(
                                                "Failed to delete key: {:?}, error: {}",
                                                String::from_utf8_lossy(key.as_bytes()),
                                                e
                                            ),
                                        }
                                    }
                                    // Signing key management responses
                                    ChatDelegateResponseMsg::StoreSigningKeyResponse {
                                        board_key,
                                        result,
                                    } => match result {
                                        Ok(_) => {
                                            info!("Stored signing key for board: {:?}", board_key)
                                        }
                                        Err(e) => warn!("Failed to store signing key: {}", e),
                                    },
                                    ChatDelegateResponseMsg::GetPublicKeyResponse {
                                        board_key,
                                        public_key,
                                    } => {
                                        info!(
                                            "Got public key for board {:?}: present={}",
                                            board_key,
                                            public_key.is_some()
                                        );
                                    }
                                    ChatDelegateResponseMsg::SignResponse {
                                        board_key,
                                        signature,
                                        ..
                                    } => match signature {
                                        Ok(_) => info!("Got signature for board: {:?}", board_key),
                                        Err(e) => {
                                            warn!("Failed to sign for board {:?}: {}", board_key, e)
                                        }
                                    },
                                }
                            } else {
                                warn!("Failed to deserialize chat delegate response");
                            }
                        }
                        _ => {
                            warn!("Unhandled delegate response: {:?}", v);
                        }
                    }
                }
            }
            _ => {
                warn!("Unhandled API response: {:?}", response);
            }
        }
        Ok(flags)
    }

    pub fn get_board_synchronizer_mut(&mut self) -> &mut BoardSynchronizer {
        &mut self.board_synchronizer
    }

    // Get a reference to the board synchronizer
    pub fn get_board_synchronizer(&self) -> &BoardSynchronizer {
        &self.board_synchronizer
    }
}

/// Put a board state to the node with the bundled contract. Used after a
/// contract re-key so a board loaded from the delegate has a contract the
/// node can update.
async fn republish_board(
    owner: ed25519_dalek::VerifyingKey,
    state: &plaza_core::ChatBoardStateV1,
) -> Result<(), String> {
    use freenet_stdlib::client_api::{ClientRequest, ContractRequest};
    use freenet_stdlib::prelude::{
        ContractCode, ContractContainer, ContractWasmAPIVersion, Parameters, WrappedContract,
        WrappedState,
    };
    let parameters = ChatBoardParametersV1 { owner };
    let contract = ContractContainer::from(ContractWasmAPIVersion::V1(WrappedContract::new(
        std::sync::Arc::new(ContractCode::from(crate::constants::BOARD_CONTRACT_WASM)),
        Parameters::from(crate::util::to_cbor_vec(&parameters)),
    )));
    let request = ContractRequest::Put {
        contract,
        state: WrappedState::new(crate::util::to_cbor_vec(state)),
        related_contracts: Default::default(),
        subscribe: false,
        blocking_subscribe: false,
    };
    let mut web_api = crate::components::app::WEB_API.write();
    let Some(web_api) = web_api.as_mut() else {
        return Err("WebAPI not available".to_string());
    };
    web_api
        .send(ClientRequest::ContractOp(request))
        .await
        .map_err(|error| error.to_string())
}
