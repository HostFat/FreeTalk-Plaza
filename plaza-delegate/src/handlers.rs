use super::*;
use ed25519_dalek::{Signer, SigningKey};
use freenet_stdlib::prelude::DelegateCtx;
use plaza_core::chat_delegate::{BoardKey, RequestId};

/// Handle an application message using the host function API for direct secret access.
pub(crate) fn handle_application_message(
    ctx: &mut DelegateCtx,
    app_msg: ApplicationMessage,
    origin: &Origin,
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    // Deserialize the request message
    let request: ChatDelegateRequestMsg = ciborium::from_reader(app_msg.payload.as_slice())
        .map_err(|e| DelegateError::Deser(format!("Failed to deserialize request: {e}")))?;

    match request {
        // Key-value storage operations
        ChatDelegateRequestMsg::StoreRequest { key, value } => {
            logging::info(
                format!(
                    "Delegate received StoreRequest key: {key:?}, value_len: {}",
                    value.len()
                )
                .as_str(),
            );
            handle_store_request(ctx, origin, key, value)
        }
        ChatDelegateRequestMsg::GetRequest { key } => {
            logging::info(format!("Delegate received GetRequest key: {key:?}").as_str());
            handle_get_request(ctx, origin, key)
        }
        ChatDelegateRequestMsg::DeleteRequest { key } => {
            logging::info(format!("Delegate received DeleteRequest key: {key:?}").as_str());
            handle_delete_request(ctx, origin, key)
        }
        ChatDelegateRequestMsg::ListRequest => {
            logging::info("Delegate received ListRequest");
            handle_list_request(ctx, origin)
        }

        // Signing key management
        ChatDelegateRequestMsg::StoreSigningKey {
            board_key,
            signing_key_bytes,
        } => {
            logging::info(
                format!("Delegate received StoreSigningKey for board: {board_key:?}").as_str(),
            );
            handle_store_signing_key(ctx, origin, board_key, signing_key_bytes)
        }
        ChatDelegateRequestMsg::GetPublicKey { board_key } => {
            logging::info(
                format!("Delegate received GetPublicKey for board: {board_key:?}").as_str(),
            );
            handle_get_public_key(ctx, origin, board_key)
        }

        // Signing operations - all include request_id for correlation
        ChatDelegateRequestMsg::SignMessage {
            board_key,
            request_id,
            message_bytes,
        } => {
            logging::info(
                format!("Delegate received SignMessage for board: {board_key:?}").as_str(),
            );
            handle_sign_request(ctx, origin, board_key, request_id, message_bytes)
        }
        ChatDelegateRequestMsg::SignMember {
            board_key,
            request_id,
            member_bytes,
        } => {
            logging::info(
                format!("Delegate received SignMember for board: {board_key:?}").as_str(),
            );
            handle_sign_request(ctx, origin, board_key, request_id, member_bytes)
        }
        ChatDelegateRequestMsg::SignBan {
            board_key,
            request_id,
            ban_bytes,
        } => {
            logging::info(format!("Delegate received SignBan for board: {board_key:?}").as_str());
            handle_sign_request(ctx, origin, board_key, request_id, ban_bytes)
        }
        ChatDelegateRequestMsg::SignConfig {
            board_key,
            request_id,
            config_bytes,
        } => {
            logging::info(
                format!("Delegate received SignConfig for board: {board_key:?}").as_str(),
            );
            handle_sign_request(ctx, origin, board_key, request_id, config_bytes)
        }
        ChatDelegateRequestMsg::SignMemberInfo {
            board_key,
            request_id,
            member_info_bytes,
        } => {
            logging::info(
                format!("Delegate received SignMemberInfo for board: {board_key:?}").as_str(),
            );
            handle_sign_request(ctx, origin, board_key, request_id, member_info_bytes)
        }
        ChatDelegateRequestMsg::SignSecretVersion {
            board_key,
            request_id,
            record_bytes,
        } => {
            logging::info(
                format!("Delegate received SignSecretVersion for board: {board_key:?}").as_str(),
            );
            handle_sign_request(ctx, origin, board_key, request_id, record_bytes)
        }
        ChatDelegateRequestMsg::SignEncryptedSecret {
            board_key,
            request_id,
            secret_bytes,
        } => {
            logging::info(
                format!("Delegate received SignEncryptedSecret for board: {board_key:?}").as_str(),
            );
            handle_sign_request(ctx, origin, board_key, request_id, secret_bytes)
        }
        ChatDelegateRequestMsg::SignUpgrade {
            board_key,
            request_id,
            upgrade_bytes,
        } => {
            logging::info(
                format!("Delegate received SignUpgrade for board: {board_key:?}").as_str(),
            );
            handle_sign_request(ctx, origin, board_key, request_id, upgrade_bytes)
        }
        ChatDelegateRequestMsg::SignAdmin {
            board_key,
            request_id,
            admin_bytes,
        } => {
            logging::info(format!("Delegate received SignAdmin for board: {board_key:?}").as_str());
            handle_sign_request(ctx, origin, board_key, request_id, admin_bytes)
        }
    }
}

// ============================================================================
// Key-Value Storage Handlers
// ============================================================================

const MAX_KEY_BYTES: usize = 1024;
const MAX_VALUE_BYTES: usize = 8 * 1024 * 1024;
const MAX_INDEX_KEYS: usize = 4_096;
const MAX_SIGN_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;

fn wipe_bytes(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        unsafe {
            core::ptr::write_volatile(byte, 0);
        }
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Handle a store request - stores value and updates the index
fn handle_store_request(
    ctx: &mut DelegateCtx,
    origin: &Origin,
    key: ChatDelegateKey,
    value: Vec<u8>,
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    if key.as_bytes().is_empty() || key.as_bytes().len() > MAX_KEY_BYTES {
        let response = ChatDelegateResponseMsg::StoreResponse {
            key,
            result: Err(format!(
                "Key length must be between 1 and {MAX_KEY_BYTES} bytes"
            )),
            value_size: 0,
        };
        return Ok(vec![create_app_response(&response)?]);
    }
    if value.len() > MAX_VALUE_BYTES {
        let response = ChatDelegateResponseMsg::StoreResponse {
            key,
            result: Err(format!(
                "Value exceeds maximum size of {MAX_VALUE_BYTES} bytes"
            )),
            value_size: 0,
        };
        return Ok(vec![create_app_response(&response)?]);
    }

    // Create a unique key for this origin's data
    let secret_key = create_origin_key(origin, &key);
    let index_key = create_index_key(origin);

    // Load index first so decode corruption or cap violation fails before writing.
    let mut key_index = get_key_index(ctx, &index_key)?;
    let is_new_key = !key_index.keys.contains(&key);
    if is_new_key && key_index.keys.len() >= MAX_INDEX_KEYS {
        let response = ChatDelegateResponseMsg::StoreResponse {
            key,
            result: Err(format!("Key index cap of {MAX_INDEX_KEYS} reached")),
            value_size: 0,
        };
        return Ok(vec![create_app_response(&response)?]);
    }

    // Store the value directly via host function
    // Note: In WASM, set_secret returns true on success. In non-WASM tests, it always returns false.
    #[cfg(target_family = "wasm")]
    if !ctx.set_secret(&secret_key, &value) {
        return Err(DelegateError::Other(
            "Failed to store secret via host function".into(),
        ));
    }
    #[cfg(not(target_family = "wasm"))]
    let _ = ctx.set_secret(&secret_key, &value);

    logging::info(&format!(
        "Stored secret with key length {}",
        secret_key.len()
    ));

    // Update the key index
    if is_new_key {
        key_index.keys.push(key.clone());
        set_key_index(ctx, &index_key, &key_index)?;
        logging::info(&format!(
            "Added key to index, now has {} keys",
            key_index.keys.len()
        ));
    }

    // Create response for the client
    let response = ChatDelegateResponseMsg::StoreResponse {
        key,
        result: Ok(()),
        value_size: value.len(),
    };

    Ok(vec![create_app_response(&response)?])
}

/// Handle a get request - retrieves value directly
fn handle_get_request(
    ctx: &mut DelegateCtx,
    origin: &Origin,
    key: ChatDelegateKey,
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    if key.as_bytes().is_empty() || key.as_bytes().len() > MAX_KEY_BYTES {
        let response = ChatDelegateResponseMsg::GetResponse { key, value: None };
        return Ok(vec![create_app_response(&response)?]);
    }

    // Create a unique key for this origin's data
    let secret_key = create_origin_key(origin, &key);

    // Get the value directly via host function
    let value = ctx.get_secret(&secret_key);
    logging::info(&format!(
        "Retrieved secret, value present: {}",
        value.is_some()
    ));

    // Create response for the client
    let response = ChatDelegateResponseMsg::GetResponse { key, value };

    Ok(vec![create_app_response(&response)?])
}

/// Handle a delete request - removes value and updates the index
fn handle_delete_request(
    ctx: &mut DelegateCtx,
    origin: &Origin,
    key: ChatDelegateKey,
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    if key.as_bytes().is_empty() || key.as_bytes().len() > MAX_KEY_BYTES {
        let response = ChatDelegateResponseMsg::DeleteResponse {
            key,
            result: Err(format!(
                "Key length must be between 1 and {MAX_KEY_BYTES} bytes"
            )),
        };
        return Ok(vec![create_app_response(&response)?]);
    }

    // Create keys
    let secret_key = create_origin_key(origin, &key);
    let index_key = create_index_key(origin);

    // Remove the secret via host function
    ctx.remove_secret(&secret_key);
    logging::info("Removed secret");

    // Update the key index
    let mut key_index = get_key_index(ctx, &index_key)?;
    key_index.keys.retain(|k| k != &key);
    set_key_index(ctx, &index_key, &key_index)?;
    logging::info(&format!(
        "Removed key from index, now has {} keys",
        key_index.keys.len()
    ));

    // Create response for the client
    let response = ChatDelegateResponseMsg::DeleteResponse {
        key,
        result: Ok(()),
    };

    Ok(vec![create_app_response(&response)?])
}

/// Handle a list request - returns all keys for this origin
fn handle_list_request(
    ctx: &mut DelegateCtx,
    origin: &Origin,
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    let index_key = create_index_key(origin);

    // Get the key index directly
    let key_index = get_key_index(ctx, &index_key)?;
    logging::info(&format!(
        "Returning list with {} keys",
        key_index.keys.len()
    ));

    // Create response for the client
    let response = ChatDelegateResponseMsg::ListResponse {
        keys: key_index.keys,
    };

    Ok(vec![create_app_response(&response)?])
}

// ============================================================================
// Signing Operations Handlers
// ============================================================================
//
// SECURITY MODEL:
//
// Signing keys are stored and retrieved using origin attestation to ensure that
// only the contract that stored a key can request signatures with it.
//
// The `attested` parameter passed to the delegate is cryptographically verified
// by Freenet - it contains the ContractInstanceId of the webapp that sent the
// message. This cannot be spoofed.
//
// Keys are stored under: "signing_key:{origin_base58}:{board_key_base58}"
//
// This means:
// - When Plaza (contract A) stores a signing key, it's stored under A's origin
// - When Plaza requests a signature, it looks up using A's origin -> found
// - If malicious contract B requests a signature, it looks up using B's origin -> not found
//
// The private key never leaves the delegate. The UI only receives:
// - Public keys (via GetPublicKey)
// - Signatures (via Sign* operations)
//
// ============================================================================

/// Create a secret key for storing a signing key for a board.
/// Format: "signing_key:{origin_base58}:{board_key_base58}"
fn create_signing_key_secret_key(origin: &Origin, board_key: &BoardKey) -> Vec<u8> {
    let origin_b58 = bs58::encode(&origin.0).into_string();
    let board_key_b58 = bs58::encode(board_key).into_string();
    format!("signing_key:{origin_b58}:{board_key_b58}").into_bytes()
}

/// Handle a store signing key request
fn handle_store_signing_key(
    ctx: &mut DelegateCtx,
    origin: &Origin,
    board_key: BoardKey,
    mut signing_key_bytes: [u8; 32],
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    if signing_key_bytes == [0u8; 32] {
        let response = ChatDelegateResponseMsg::StoreSigningKeyResponse {
            board_key,
            result: Err("Signing key cannot be all zeroes".to_string()),
        };
        return Ok(vec![create_app_response(&response)?]);
    }

    let secret_key = create_signing_key_secret_key(origin, &board_key);

    // Store the signing key directly via host function
    // Note: In WASM, set_secret returns true on success. In non-WASM tests, it always returns false.
    #[cfg(target_family = "wasm")]
    let stored = ctx.set_secret(&secret_key, &signing_key_bytes);
    #[cfg(not(target_family = "wasm"))]
    let _ = ctx.set_secret(&secret_key, &signing_key_bytes);
    wipe_bytes(&mut signing_key_bytes);

    #[cfg(target_family = "wasm")]
    if !stored {
        return Err(DelegateError::Other(
            "Failed to store signing key via host function".into(),
        ));
    }

    logging::info("Stored signing key for board");

    // Create response for the client
    let response = ChatDelegateResponseMsg::StoreSigningKeyResponse {
        board_key,
        result: Ok(()),
    };

    Ok(vec![create_app_response(&response)?])
}

/// Handle a get public key request
fn handle_get_public_key(
    ctx: &mut DelegateCtx,
    origin: &Origin,
    board_key: BoardKey,
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    let secret_key = create_signing_key_secret_key(origin, &board_key);

    // Get the signing key directly via host function
    let public_key = ctx.get_secret(&secret_key).and_then(|mut sk_bytes| {
        let pk = if sk_bytes.len() == 32 {
            <[u8; 32]>::try_from(sk_bytes.as_slice())
                .ok()
                .map(|mut sk_array| {
                    let signing_key = SigningKey::from_bytes(&sk_array);
                    let vk = signing_key.verifying_key().to_bytes();
                    wipe_bytes(&mut sk_array);
                    vk
                })
        } else {
            None
        };
        wipe_bytes(&mut sk_bytes);
        pk
    });

    logging::info(&format!(
        "Retrieved public key for board, key present: {}",
        public_key.is_some()
    ));

    // Create response for the client
    let response = ChatDelegateResponseMsg::GetPublicKeyResponse {
        board_key,
        public_key,
    };

    Ok(vec![create_app_response(&response)?])
}

/// Handle a sign request (for any signable type)
fn handle_sign_request(
    ctx: &mut DelegateCtx,
    origin: &Origin,
    board_key: BoardKey,
    request_id: RequestId,
    data_to_sign: Vec<u8>,
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    if data_to_sign.is_empty() || data_to_sign.len() > MAX_SIGN_PAYLOAD_BYTES {
        let response = ChatDelegateResponseMsg::SignResponse {
            board_key,
            request_id,
            signature: Err(format!(
                "Sign payload length must be between 1 and {MAX_SIGN_PAYLOAD_BYTES} bytes"
            )),
        };
        return Ok(vec![create_app_response(&response)?]);
    }

    let secret_key = create_signing_key_secret_key(origin, &board_key);

    // Get the signing key and sign directly
    let signature: Result<Vec<u8>, String> = match ctx.get_secret(&secret_key) {
        Some(mut sk_bytes) => {
            let res = match <[u8; 32]>::try_from(sk_bytes.as_slice()) {
                Ok(mut sk_array) => {
                    let signing_key = SigningKey::from_bytes(&sk_array);
                    let sig = signing_key.sign(&data_to_sign);
                    wipe_bytes(&mut sk_array);
                    Ok(sig.to_bytes().to_vec())
                }
                Err(_) => Err(format!(
                    "Invalid signing key length: expected 32, got {}",
                    sk_bytes.len()
                )),
            };
            wipe_bytes(&mut sk_bytes);
            res
        }
        None => Err("Signing key not found for this board".to_string()),
    };

    logging::info(&format!(
        "Sign request for board, signature created: {}",
        signature.is_ok()
    ));

    // Create response for the client
    let response = ChatDelegateResponseMsg::SignResponse {
        board_key,
        request_id,
        signature,
    };

    Ok(vec![create_app_response(&response)?])
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get the key index from secrets, returning an error on corrupt CBOR instead
/// of silently wiping the index.
fn get_key_index(ctx: &mut DelegateCtx, index_key: &[u8]) -> Result<KeyIndex, DelegateError> {
    match ctx.get_secret(index_key) {
        None => Ok(KeyIndex::default()),
        Some(data) => ciborium::from_reader::<KeyIndex, _>(data.as_slice())
            .map_err(|e| DelegateError::Deser(format!("Corrupt key index: {e}"))),
    }
}

/// Set the key index in secrets
fn set_key_index(
    ctx: &mut DelegateCtx,
    index_key: &[u8],
    key_index: &KeyIndex,
) -> Result<(), DelegateError> {
    let mut index_bytes = Vec::new();
    ciborium::ser::into_writer(key_index, &mut index_bytes)
        .map_err(|e| DelegateError::Deser(format!("Failed to serialize key index: {e}")))?;

    // Note: In WASM, set_secret returns true on success. In non-WASM tests, it always returns false.
    #[cfg(target_family = "wasm")]
    if !ctx.set_secret(index_key, &index_bytes) {
        return Err(DelegateError::Other(
            "Failed to store key index via host function".into(),
        ));
    }
    #[cfg(not(target_family = "wasm"))]
    let _ = ctx.set_secret(index_key, &index_bytes);

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use freenet_stdlib::prelude::{ContractInstanceId, DelegateCtx, MessageOrigin};

    /// Helper function to create empty parameters for testing
    fn create_test_parameters() -> Parameters<'static> {
        Parameters::from(vec![])
    }

    /// Helper function to create an application message
    fn create_app_message(request: ChatDelegateRequestMsg) -> ApplicationMessage {
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&request, &mut payload)
            .map_err(|e| panic!("Failed to serialize request: {e}"))
            .unwrap();
        ApplicationMessage::new(payload)
    }

    /// Helper function to extract response from outbound messages
    fn extract_response(messages: Vec<OutboundDelegateMsg>) -> Option<ChatDelegateResponseMsg> {
        for msg in messages {
            if let OutboundDelegateMsg::ApplicationMessage(app_msg) = msg {
                return ciborium::from_reader(app_msg.payload.as_slice())
                    .map_err(|e| panic!("Failed to deserialize response: {e}"))
                    .ok();
            }
        }
        None
    }

    // Test origin - using a fixed ContractInstanceId for testing
    fn get_test_origin() -> Option<MessageOrigin> {
        Some(MessageOrigin::WebApp(ContractInstanceId::new([42u8; 32])))
    }

    #[test]
    fn test_store_request() {
        let key = b"test_key".to_vec();
        let value = b"test_value".to_vec();

        let request = ChatDelegateRequestMsg::StoreRequest {
            key: plaza_core::chat_delegate::ChatDelegateKey(key.clone()),
            value: value.clone(),
        };
        let app_msg = create_app_message(request);
        let inbound_msg = InboundDelegateMsg::ApplicationMessage(app_msg);

        let result = crate::ChatDelegate::process(
            &mut DelegateCtx::default(),
            create_test_parameters(),
            get_test_origin(),
            inbound_msg,
        )
        .unwrap();

        // Should have 1 message: app response (secrets are stored via host function)
        assert_eq!(result.len(), 1);

        // Check app response
        let response = extract_response(result).unwrap();
        match response {
            ChatDelegateResponseMsg::StoreResponse {
                key: resp_key,
                result,
                value_size,
            } => {
                assert_eq!(
                    resp_key,
                    plaza_core::chat_delegate::ChatDelegateKey(key.clone())
                );
                assert!(result.is_ok());
                assert_eq!(value_size, value.len());
            }
            _ => panic!("Expected StoreResponse, got {:?}", response),
        }
    }

    #[test]
    fn test_get_request() {
        let key = b"test_key".to_vec();

        let request = ChatDelegateRequestMsg::GetRequest {
            key: plaza_core::chat_delegate::ChatDelegateKey(key.clone()),
        };
        let app_msg = create_app_message(request);
        let inbound_msg = InboundDelegateMsg::ApplicationMessage(app_msg);

        let result = crate::ChatDelegate::process(
            &mut DelegateCtx::default(),
            create_test_parameters(),
            get_test_origin(),
            inbound_msg,
        )
        .unwrap();

        // Should have 1 message: app response with the value (or None if not found)
        assert_eq!(result.len(), 1);

        // Check it's a GetResponse
        let response = extract_response(result).unwrap();
        match response {
            ChatDelegateResponseMsg::GetResponse {
                key: resp_key,
                value: _,
            } => {
                assert_eq!(
                    resp_key,
                    plaza_core::chat_delegate::ChatDelegateKey(key.clone())
                );
                // Value will be None in test since we didn't store it first
            }
            _ => panic!("Expected GetResponse, got {:?}", response),
        }
    }

    #[test]
    fn test_delete_request() {
        let key = b"test_key".to_vec();

        let request = ChatDelegateRequestMsg::DeleteRequest {
            key: plaza_core::chat_delegate::ChatDelegateKey(key.clone()),
        };
        let app_msg = create_app_message(request);
        let inbound_msg = InboundDelegateMsg::ApplicationMessage(app_msg);

        let result = crate::ChatDelegate::process(
            &mut DelegateCtx::default(),
            create_test_parameters(),
            get_test_origin(),
            inbound_msg,
        )
        .unwrap();

        // Should have 1 message: app response
        assert_eq!(result.len(), 1);

        // Check response
        let response = extract_response(result).unwrap();
        match response {
            ChatDelegateResponseMsg::DeleteResponse {
                key: resp_key,
                result,
            } => {
                assert_eq!(
                    resp_key,
                    plaza_core::chat_delegate::ChatDelegateKey(key.clone())
                );
                assert!(result.is_ok());
            }
            _ => panic!("Expected DeleteResponse, got {:?}", response),
        }
    }

    #[test]
    fn test_list_request() {
        let request = ChatDelegateRequestMsg::ListRequest;
        let app_msg = create_app_message(request);
        let inbound_msg = InboundDelegateMsg::ApplicationMessage(app_msg);

        let result = crate::ChatDelegate::process(
            &mut DelegateCtx::default(),
            create_test_parameters(),
            get_test_origin(),
            inbound_msg,
        )
        .unwrap();

        // Should have 1 message: app response with list
        assert_eq!(result.len(), 1);

        // Check response
        let response = extract_response(result).unwrap();
        match response {
            ChatDelegateResponseMsg::ListResponse { keys } => {
                // Empty list since we haven't stored anything
                assert!(keys.is_empty());
            }
            _ => panic!("Expected ListResponse, got {:?}", response),
        }
    }

    #[test]
    fn test_error_on_processed_message() {
        let request = ChatDelegateRequestMsg::ListRequest;
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&request, &mut payload).unwrap();

        let app_msg = ApplicationMessage::new(payload).processed(true);
        let inbound_msg = InboundDelegateMsg::ApplicationMessage(app_msg);

        let result = crate::ChatDelegate::process(
            &mut DelegateCtx::default(),
            create_test_parameters(),
            get_test_origin(),
            inbound_msg,
        );

        assert!(result.is_err());
        if let Err(DelegateError::Other(msg)) = result {
            assert!(msg.contains("already processed"));
        } else {
            panic!("Expected DelegateError::Other, got {:?}", result);
        }
    }

    #[test]
    fn test_error_on_missing_origin() {
        let request = ChatDelegateRequestMsg::ListRequest;
        let app_msg = create_app_message(request);
        let inbound_msg = InboundDelegateMsg::ApplicationMessage(app_msg);

        // Pass None for origin
        let result = crate::ChatDelegate::process(
            &mut DelegateCtx::default(),
            create_test_parameters(),
            None,
            inbound_msg,
        );
        assert!(result.is_err());

        if let Err(DelegateError::Other(msg)) = result {
            assert!(msg.contains("missing message origin"));
        } else {
            panic!("Expected DelegateError::Other, got {:?}", result);
        }
    }

    #[test]
    fn test_store_signing_key() {
        let board_key: plaza_core::chat_delegate::BoardKey = [7u8; 32];
        let signing_key_bytes: [u8; 32] = [8u8; 32];

        let request = ChatDelegateRequestMsg::StoreSigningKey {
            board_key,
            signing_key_bytes,
        };
        let app_msg = create_app_message(request);
        let inbound_msg = InboundDelegateMsg::ApplicationMessage(app_msg);

        let result = crate::ChatDelegate::process(
            &mut DelegateCtx::default(),
            create_test_parameters(),
            get_test_origin(),
            inbound_msg,
        )
        .unwrap();

        // Should have 1 message: app response
        assert_eq!(result.len(), 1);

        // Check response
        let response = extract_response(result).unwrap();
        match response {
            ChatDelegateResponseMsg::StoreSigningKeyResponse {
                board_key: resp_board_key,
                result,
            } => {
                assert_eq!(resp_board_key, board_key);
                assert!(result.is_ok());
            }
            _ => panic!("Expected StoreSigningKeyResponse, got {:?}", response),
        }
    }

    #[test]
    fn test_get_public_key_not_found() {
        let board_key: plaza_core::chat_delegate::BoardKey = [9u8; 32];

        let request = ChatDelegateRequestMsg::GetPublicKey { board_key };
        let app_msg = create_app_message(request);
        let inbound_msg = InboundDelegateMsg::ApplicationMessage(app_msg);

        let result = crate::ChatDelegate::process(
            &mut DelegateCtx::default(),
            create_test_parameters(),
            get_test_origin(),
            inbound_msg,
        )
        .unwrap();

        // Should have 1 message: app response
        assert_eq!(result.len(), 1);

        // Check response - public key should be None since no key is stored
        let response = extract_response(result).unwrap();
        match response {
            ChatDelegateResponseMsg::GetPublicKeyResponse {
                board_key: resp_board_key,
                public_key,
            } => {
                assert_eq!(resp_board_key, board_key);
                // In non-WASM test environment, get_secret returns None
                assert!(public_key.is_none());
            }
            _ => panic!("Expected GetPublicKeyResponse, got {:?}", response),
        }
    }

    #[test]
    fn test_sign_message_without_key_returns_error() {
        let board_key: plaza_core::chat_delegate::BoardKey = [10u8; 32];
        let request_id: plaza_core::chat_delegate::RequestId = 12345;
        let message_bytes = b"test message to sign".to_vec();

        let request = ChatDelegateRequestMsg::SignMessage {
            board_key,
            request_id,
            message_bytes,
        };
        let app_msg = create_app_message(request);
        let inbound_msg = InboundDelegateMsg::ApplicationMessage(app_msg);

        let result = crate::ChatDelegate::process(
            &mut DelegateCtx::default(),
            create_test_parameters(),
            get_test_origin(),
            inbound_msg,
        )
        .unwrap();

        // Should have 1 message: app response
        assert_eq!(result.len(), 1);

        // Check response - signature should be an error since no key is stored
        let response = extract_response(result).unwrap();
        match response {
            ChatDelegateResponseMsg::SignResponse {
                board_key: resp_board_key,
                request_id: resp_request_id,
                signature,
            } => {
                assert_eq!(resp_board_key, board_key);
                assert_eq!(resp_request_id, request_id);
                // Should be an error because no signing key is stored
                assert!(signature.is_err());
                let err_msg = signature.unwrap_err();
                assert!(
                    err_msg.contains("not found"),
                    "Expected 'not found' error, got: {}",
                    err_msg
                );
            }
            _ => panic!("Expected SignResponse, got {:?}", response),
        }
    }
}
