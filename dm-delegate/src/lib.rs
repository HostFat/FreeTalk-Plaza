//! Freenet delegate for `plaza-dm`.
//!
//! The delegate owns the DM identity seed, device signing/key-encapsulation
//! seeds, conversation keys and the local index. The web app sends requests
//! through `DmDelegateRequestMsg` and receives `DmDelegateResponseMsg`.

#![allow(unexpected_cfgs)]

mod state;

use freenet_stdlib::prelude::{
    delegate, ApplicationMessage, DelegateContext, DelegateCtx, DelegateError, DelegateInterface,
    InboundDelegateMsg, MessageOrigin, OutboundDelegateMsg, Parameters,
};
use plaza_dm_core::delegate::{DmDelegateRequestMsg, DmDelegateResponseMsg};
use state::DmDelegateStateV1;

const STATE_KEY_SUFFIX: &[u8] = b"/plaza_dm_state_v1";

struct DmDelegate;

fn storage_key(origin: &[u8]) -> Vec<u8> {
    let mut key = origin.to_vec();
    key.extend_from_slice(STATE_KEY_SUFFIX);
    key
}

fn load_state(ctx: &mut DelegateCtx, key: &[u8]) -> Result<DmDelegateStateV1, DelegateError> {
    match ctx.get_secret(key) {
        Some(bytes) => DmDelegateStateV1::decode(&bytes)
            .map_err(|error| DelegateError::Deser(error.to_string())),
        None => Ok(DmDelegateStateV1::default()),
    }
}

fn save_state(
    ctx: &mut DelegateCtx,
    key: &[u8],
    state: &DmDelegateStateV1,
) -> Result<(), DelegateError> {
    let bytes = state
        .encode()
        .map_err(|error| DelegateError::Deser(error.to_string()))?;
    #[cfg(target_family = "wasm")]
    if !ctx.set_secret(key, &bytes) {
        return Err(DelegateError::Other(
            "failed to store the DM delegate state".to_string(),
        ));
    }
    #[cfg(not(target_family = "wasm"))]
    let _ = ctx.set_secret(key, &bytes);
    Ok(())
}

fn app_response(response: &DmDelegateResponseMsg) -> Result<OutboundDelegateMsg, DelegateError> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(response, &mut bytes)
        .map_err(|error| DelegateError::Deser(format!("serialize response: {error}")))?;
    let message = ApplicationMessage::new(bytes)
        .with_context(DelegateContext::default())
        .processed(true);
    Ok(OutboundDelegateMsg::ApplicationMessage(message))
}

#[delegate]
impl DelegateInterface for DmDelegate {
    fn process(
        ctx: &mut DelegateCtx,
        _parameters: Parameters<'static>,
        origin: Option<MessageOrigin>,
        message: InboundDelegateMsg,
    ) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
        let InboundDelegateMsg::ApplicationMessage(app_msg) = message else {
            return Err(DelegateError::Other(
                "plaza-dm-delegate only accepts application messages".to_string(),
            ));
        };
        if app_msg.processed {
            return Err(DelegateError::Other(
                "cannot process an already processed message".to_string(),
            ));
        }
        let origin = match origin {
            Some(MessageOrigin::WebApp(contract_id)) => contract_id.as_bytes().to_vec(),
            Some(MessageOrigin::Delegate(caller)) => {
                return Err(DelegateError::Other(format!(
                    "plaza-dm-delegate does not accept inter-delegate calls (caller: {caller})"
                )));
            }
            None => {
                return Err(DelegateError::Other("missing message origin".to_string()));
            }
            Some(_) => {
                return Err(DelegateError::Other(
                    "unsupported message origin".to_string(),
                ));
            }
        };
        let request: DmDelegateRequestMsg =
            ciborium::de::from_reader(app_msg.payload.as_slice())
                .map_err(|error| DelegateError::Deser(format!("decode request: {error}")))?;
        let key = storage_key(&origin);
        let mut state = load_state(ctx, &key)?;
        let response = state.apply(request);
        save_state(ctx, &key, &state)?;
        Ok(vec![app_response(&response)?])
    }
}

/// Revision marker: a bump changes the delegate wasm and therefore its key.
#[no_mangle]
pub extern "C" fn plaza_dm_delegate_revision() -> u32 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_storage_key_is_namespaced_per_origin() {
        assert_eq!(storage_key(b"origin-a"), b"origin-a/plaza_dm_state_v1");
        assert_eq!(storage_key(b"origin-b"), b"origin-b/plaza_dm_state_v1");
    }

    #[test]
    fn an_empty_store_decodes_as_default() {
        let state = DmDelegateStateV1::default();
        let bytes = state.encode().unwrap();
        let decoded = DmDelegateStateV1::decode(&bytes).unwrap();
        assert_eq!(decoded.version, 0);
        assert!(decoded.identity_seed.is_none());
    }

    #[test]
    fn a_response_round_trips() {
        let response = DmDelegateResponseMsg::Status {
            identity: None,
            devices: Vec::new(),
            conversations: 0,
            blocked: 0,
        };
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&response, &mut bytes).unwrap();
        let decoded: DmDelegateResponseMsg = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        assert!(matches!(decoded, DmDelegateResponseMsg::Status { .. }));
    }
}
