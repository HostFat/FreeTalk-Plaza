use super::*;

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Helper function to create a unique, collision-free secret key for an origin's data.
pub(crate) fn create_origin_key(origin: &Origin, key: &ChatDelegateKey) -> Vec<u8> {
    format!(
        "{}{}{}",
        origin.to_b58(),
        DATA_KEY_TAG,
        hex_encode(key.as_bytes())
    )
    .into_bytes()
}

/// Helper function to create an index key for an origin, disjoint from data keys.
pub(crate) fn create_index_key(origin: &Origin) -> Vec<u8> {
    format!("{}{}", origin.to_b58(), INDEX_KEY_TAG).into_bytes()
}

/// Helper function to create an app response
pub(crate) fn create_app_response<T: Serialize>(
    response: &T,
) -> Result<OutboundDelegateMsg, DelegateError> {
    // Serialize response
    let mut response_bytes = Vec::new();
    ciborium::ser::into_writer(response, &mut response_bytes)
        .map_err(|e| DelegateError::Deser(format!("Failed to serialize response: {e}")))?;

    logging::info(&format!(
        "Creating app response with {} bytes",
        response_bytes.len()
    ));

    // Create response message
    let app_msg = ApplicationMessage::new(response_bytes)
        .with_context(DelegateContext::default())
        .processed(true);

    Ok(OutboundDelegateMsg::ApplicationMessage(app_msg))
}
