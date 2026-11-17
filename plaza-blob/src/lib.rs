//! Contract for one image payload.
//!
//! The state holds the bytes or the signed proof that they were retired. The
//! parameters fix the content hash and the keys allowed to retire it, so the
//! contract key identifies the content and its kill switch.

use ciborium::{de::from_reader, ser::into_writer};
use freenet_stdlib::prelude::*;
use plaza_blob_core::{merge_states, BlobParametersV1, BlobStateV1};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
struct BlobSummary {
    sha256: [u8; 32],
    retired: bool,
}

#[allow(dead_code)]
struct Contract;

#[contract]
impl ContractInterface for Contract {
    fn validate_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts<'static>,
    ) -> Result<ValidateResult, ContractError> {
        if state.as_ref().is_empty() {
            return Ok(ValidateResult::Valid);
        }
        let parameters = from_reader::<BlobParametersV1, &[u8]>(parameters.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        let state = from_reader::<BlobStateV1, &[u8]>(state.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        state
            .validate(&parameters)
            .map(|_| ValidateResult::Valid)
            .map_err(|e| ContractError::InvalidUpdateWithInfo { reason: e })
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let parameters = from_reader::<BlobParametersV1, &[u8]>(parameters.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;

        let mut current: Option<BlobStateV1> = if state.as_ref().is_empty() {
            None
        } else {
            Some(
                from_reader::<BlobStateV1, &[u8]>(state.as_ref())
                    .map_err(|e| ContractError::Deser(e.to_string()))?,
            )
        };

        for update in data {
            let incoming = match update {
                UpdateData::State(new_state) => {
                    from_reader::<BlobStateV1, &[u8]>(new_state.as_ref())
                        .map_err(|e| ContractError::Deser(e.to_string()))?
                }
                UpdateData::Delta(delta) => {
                    if delta.as_ref().is_empty() {
                        continue;
                    }
                    from_reader::<BlobStateV1, &[u8]>(delta.as_ref())
                        .map_err(|e| ContractError::Deser(e.to_string()))?
                }
                _ => continue,
            };
            current = Some(match current {
                None => incoming,
                Some(existing) => merge_states(&existing, &incoming, &parameters)
                    .map_err(|e| ContractError::InvalidUpdateWithInfo { reason: e })?,
            });
        }

        let Some(state) = current else {
            return Ok(UpdateModification::valid(Vec::new().into()));
        };
        state
            .validate(&parameters)
            .map_err(|e| ContractError::InvalidUpdateWithInfo { reason: e })?;
        let mut bytes = Vec::new();
        into_writer(&state, &mut bytes).map_err(|e| ContractError::Deser(e.to_string()))?;
        Ok(UpdateModification::valid(bytes.into()))
    }

    fn summarize_state(
        parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        if state.as_ref().is_empty() {
            return Ok(StateSummary::from(Vec::new()));
        }
        let parameters = from_reader::<BlobParametersV1, &[u8]>(parameters.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        let state = from_reader::<BlobStateV1, &[u8]>(state.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        let summary = BlobSummary {
            sha256: parameters.sha256,
            retired: state.retired,
        };
        let mut bytes = Vec::new();
        into_writer(&summary, &mut bytes).map_err(|e| ContractError::Deser(e.to_string()))?;
        Ok(StateSummary::from(bytes))
    }

    fn get_state_delta(
        parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        let parameters = from_reader::<BlobParametersV1, &[u8]>(parameters.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        let state = from_reader::<BlobStateV1, &[u8]>(state.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        let current = BlobSummary {
            sha256: parameters.sha256,
            retired: state.retired,
        };
        let known = if summary.as_ref().is_empty() {
            None
        } else {
            Some(
                from_reader::<BlobSummary, &[u8]>(summary.as_ref())
                    .map_err(|e| ContractError::Deser(e.to_string()))?,
            )
        };
        if known.as_ref() == Some(&current) {
            return Ok(StateDelta::from(Vec::new()));
        }
        let mut bytes = Vec::new();
        into_writer(&state, &mut bytes).map_err(|e| ContractError::Deser(e.to_string()))?;
        Ok(StateDelta::from(bytes))
    }
}
