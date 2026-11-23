//! Section child boards. A sectioned parent keeps only the section list and
//! authority; each section's topic index lives in its own contract.

use dioxus::prelude::*;
use ed25519_dalek::VerifyingKey;
use freenet_scaffold::ComposableState;
use freenet_stdlib::client_api::{ClientRequest, ContractRequest, ContractResponse};
use freenet_stdlib::prelude::{
    ContractCode, ContractContainer, ContractInstanceId, ContractKey, ContractWasmAPIVersion,
    Parameters, UpdateData, WrappedContract, WrappedState,
};
use plaza_core::board_state::sections::{
    AuthorizedSectionV1, SectionId, SectionParametersV1, SectionsV1,
};
use plaza_core::board_state::topics::TopicIndexV1;
use plaza_core::board_state::{BoardModeV1, ChatBoardParametersV1, ChatBoardStateV1};
use std::collections::HashMap;
use std::sync::Arc;

use crate::components::app::send_client_request;
use crate::constants::SECTION_CONTRACT_WASM;
use crate::util::to_cbor_vec;

pub struct SectionBoard {
    pub key: ContractKey,
    pub params: SectionParametersV1,
    pub state: ChatBoardStateV1,
    pub synced: bool,
}

pub static SECTION_BOARDS: GlobalSignal<HashMap<ContractInstanceId, SectionBoard>> =
    Global::new(HashMap::new);

pub fn section_key(owner: VerifyingKey, section: SectionId) -> ContractKey {
    let params = SectionParametersV1 { owner, section };
    let parameters = Parameters::from(to_cbor_vec(&params));
    let code = ContractCode::from(SECTION_CONTRACT_WASM);
    ContractKey::from_params_and_code(parameters, &code)
}

pub fn is_known_section_board(key: &ContractInstanceId) -> bool {
    SECTION_BOARDS.read().contains_key(key)
}

pub fn is_section_contract_response(response: &ContractResponse) -> bool {
    match response {
        ContractResponse::GetResponse { key, .. }
        | ContractResponse::PutResponse { key }
        | ContractResponse::UpdateResponse { key, .. }
        | ContractResponse::UpdateNotification { key, .. }
        | ContractResponse::SubscribeResponse { key, .. } => is_known_section_board(key.id()),
        _ => false,
    }
}

/// Build a child board from the parent and publish it. The section record must
/// already contain the child contract id, so the parent and the child sign the
/// same section.
pub async fn create_section_board(
    owner: VerifyingKey,
    section: &AuthorizedSectionV1,
    parent: &ChatBoardStateV1,
) -> Result<ContractKey, String> {
    let section_id = section.section.id;
    let key = section_key(owner, section_id);
    let child_id = *key.id();
    if section.section.contract != Some(child_id) {
        return Err("the section does not point to its child board".to_string());
    }

    let mut child = parent.clone();
    child.mode = BoardModeV1::SectionedTopicIndex;
    child.sections = SectionsV1 {
        sections: vec![section.clone()],
    };
    child.topics = TopicIndexV1::default();
    child.recent_messages = Default::default();
    child.trash = Default::default();
    child.message_keys = Default::default();
    child.moderation = Default::default();
    child.reports = Default::default();
    child.approvals = Default::default();
    child.invites = Default::default();

    let params = SectionParametersV1 { owner, section: section_id };
    let contract = ContractContainer::from(ContractWasmAPIVersion::V1(WrappedContract::new(
        Arc::new(ContractCode::from(SECTION_CONTRACT_WASM)),
        Parameters::from(to_cbor_vec(&params)),
    )));
    let state = WrappedState::new(to_cbor_vec(&child));
    SECTION_BOARDS.with_mut(|boards| {
        boards.insert(
            child_id,
            SectionBoard {
                key,
                params: params.clone(),
                state: child.clone(),
                synced: false,
            },
        );
    });
    send_client_request(ClientRequest::ContractOp(ContractRequest::Put {
        contract,
        state,
        related_contracts: Default::default(),
        subscribe: true,
        blocking_subscribe: false,
    }))
    .await
    .map_err(|error| format!("put section board: {error}"))?;
    Ok(key)
}

/// Fetch and subscribe to a section board. Safe to call on every render.
pub async fn load_section_board(
    owner: VerifyingKey,
    section: SectionId,
) -> Result<ContractInstanceId, String> {
    let key = section_key(owner, section);
    let contract_id = *key.id();
    let known = SECTION_BOARDS.read().contains_key(&contract_id);
    if !known {
        SECTION_BOARDS.with_mut(|boards| {
            boards.insert(
                contract_id,
                SectionBoard {
                    key,
                    params: SectionParametersV1 { owner, section },
                    state: ChatBoardStateV1::default(),
                    synced: false,
                },
            );
        });
    }
    send_client_request(ClientRequest::ContractOp(ContractRequest::Get {
        key: contract_id,
        return_contract_code: false,
        subscribe: true,
        blocking_subscribe: false,
    }))
    .await
    .map_err(|error| format!("get section board: {error}"))?;
    Ok(contract_id)
}

pub async fn handle_contract_response(response: ContractResponse) -> Result<(), String> {
    match response {
        ContractResponse::GetResponse { key, state, .. } => {
            let state = ciborium::de::from_reader::<ChatBoardStateV1, _>(state.as_ref())
                .map_err(|error| format!("decode section state: {error}"))?;
            let owner = SECTION_BOARDS
                .read()
                .get(key.id())
                .map(|board| board.params.owner)
                .ok_or("unknown section board")?;
            let params = ChatBoardParametersV1 { owner };
            state
                .verify_with_section(
                    &params,
                    Some(
                        SECTION_BOARDS
                            .read()
                            .get(key.id())
                            .map(|board| board.params.section)
                            .ok_or("unknown section board")?,
                    ),
                )
                .map_err(|error| format!("section state does not verify: {error}"))?;
            SECTION_BOARDS.with_mut(|boards| {
                if let Some(board) = boards.get_mut(key.id()) {
                    board.state = state;
                    board.synced = true;
                }
            });
        }
        ContractResponse::PutResponse { key }
        | ContractResponse::UpdateResponse { key, .. }
        | ContractResponse::SubscribeResponse { key, .. } => {
            SECTION_BOARDS.with_mut(|boards| {
                if let Some(board) = boards.get_mut(key.id()) {
                    board.synced = true;
                }
            });
        }
        ContractResponse::UpdateNotification { key, update } => {
            let entry = SECTION_BOARDS
                .read()
                .get(key.id())
                .map(|board| (board.params.owner, board.params.section))
                .ok_or("unknown section board")?;
            let params = ChatBoardParametersV1 { owner: entry.0 };
            let mut state = SECTION_BOARDS
                .read()
                .get(key.id())
                .map(|board| board.state.clone())
                .ok_or("unknown section board")?;
            match update {
                UpdateData::State(bytes) => {
                    state = ciborium::de::from_reader(bytes.as_ref())
                        .map_err(|error| format!("decode section update: {error}"))?;
                }
                UpdateData::Delta(bytes) => {
                    let delta = ciborium::de::from_reader(bytes.as_ref())
                        .map_err(|error| format!("decode section delta: {error}"))?;
                    let parent = state.clone();
                    state
                        .apply_delta(&parent, &params, &Some(delta))
                        .map_err(|error| format!("apply section delta: {error}"))?;
                }
                _ => {}
            }
            state
                .verify_with_section(&params, Some(entry.1))
                .map_err(|error| format!("section update does not verify: {error}"))?;
            SECTION_BOARDS.with_mut(|boards| {
                if let Some(board) = boards.get_mut(key.id()) {
                    board.state = state;
                    board.synced = true;
                }
            });
        }
        _ => {}
    }
    Ok(())
}
