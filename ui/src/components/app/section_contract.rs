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
    AuthorizedSectionV1, SectionId, SectionParametersV1,
};
use plaza_core::board_state::topics::TopicIndexV1;
use plaza_core::board_state::{
    BoardModeV1, ChatBoardParametersV1, ChatBoardStateV1,
};
use std::collections::HashMap;
use std::sync::Arc;

use crate::components::app::send_client_request;
use crate::constants::SECTION_CONTRACT_WASM;
use crate::util::to_cbor_vec;

pub struct SectionBoard {
    pub params: SectionParametersV1,
    pub state: ChatBoardStateV1,
    pub synced: bool,
    /// State has arrived and the parent authority has been copied in.
    pub ready: bool,
    /// An authority sync is in flight.
    pub syncing: bool,
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

pub fn section_state(owner: VerifyingKey, section: SectionId) -> Option<ChatBoardStateV1> {
    let key = section_key(owner, section);
    SECTION_BOARDS
        .read()
        .get(key.id())
        .map(|board| board.state.clone())
}

/// Merge the parent index (used by non-sharded boards) with every loaded
/// child index of this owner. The UI reads the union as one index.
pub fn merged_index(
    owner: VerifyingKey,
    parent: &TopicIndexV1,
) -> TopicIndexV1 {
    let mut merged = parent.clone();
    let boards = SECTION_BOARDS.read();
    for board in boards
        .values()
        .filter(|board| board.params.owner == owner)
    {
        merge_index(&mut merged, &board.state.topics);
    }
    merged
}

fn merge_index(dst: &mut TopicIndexV1, src: &TopicIndexV1) {
    for entry in &src.entries {
        match dst
            .entries
            .iter_mut()
            .find(|existing| existing.entry.topic_id == entry.entry.topic_id)
        {
            Some(existing) => {
                let take = entry.entry.generation > existing.entry.generation
                    || (entry.entry.generation == existing.entry.generation
                        && entry.digest() < existing.digest());
                if take {
                    *existing = entry.clone();
                }
            }
            None => dst.entries.push(entry.clone()),
        }
    }
    for entry in &src.activity {
        match dst
            .activity
            .iter_mut()
            .find(|existing| existing.activity.topic_id == entry.activity.topic_id)
        {
            Some(existing) => {
                if entry.activity.generation > existing.activity.generation {
                    *existing = entry.clone();
                }
            }
            None => dst.activity.push(entry.clone()),
        }
    }
    for entry in &src.flags {
        match dst.flags.iter_mut().find(|existing| {
            existing.flag.topic_id == entry.flag.topic_id
                && existing.flag.kind == entry.flag.kind
        }) {
            Some(existing) => {
                let take = entry.flag.generation > existing.flag.generation
                    || (entry.flag.generation == existing.flag.generation
                        && entry.flag.value == false
                        && existing.flag.value)
                    || (entry.flag.generation == existing.flag.generation
                        && entry.flag.value == existing.flag.value
                        && entry.digest() < existing.digest());
                if take {
                    *existing = entry.clone();
                }
            }
            None => dst.flags.push(entry.clone()),
        }
    }
    for entry in &src.reports {
        match dst.reports.iter_mut().find(|existing| {
            existing.report.topic_id == entry.report.topic_id
                && existing.report.post_id == entry.report.post_id
                && existing.report.reporter == entry.report.reporter
        }) {
            Some(existing) => {
                if entry.report.generation > existing.report.generation {
                    *existing = entry.clone();
                }
            }
            None => dst.reports.push(entry.clone()),
        }
    }
    for entry in &src.report_resolutions {
        match dst.report_resolutions.iter_mut().find(|existing| {
            existing.resolution.topic_id == entry.resolution.topic_id
                && existing.resolution.post_id == entry.resolution.post_id
                && existing.resolution.reporter == entry.resolution.reporter
        }) {
            Some(existing) => {
                if entry.resolution.generation > existing.resolution.generation {
                    *existing = entry.clone();
                }
            }
            None => dst.report_resolutions.push(entry.clone()),
        }
    }
}

/// Copy the parent's authority, members and global settings into a loaded
/// section child, keeping the section's own topic index and content.
pub async fn sync_section_authority(
    owner: VerifyingKey,
    section: SectionId,
    parent: &ChatBoardStateV1,
) -> Result<(), String> {
    let key = section_key(owner, section);
    let contract_id = *key.id();
    let Some((child, synced, syncing)) = SECTION_BOARDS
        .read()
        .get(&contract_id)
        .map(|board| (board.state.clone(), board.synced, board.syncing))
    else {
        return Err("the section board is not loaded".to_string());
    };
    if !synced {
        return Err("the section state has not arrived yet".to_string());
    }
    if syncing {
        return Ok(());
    }
    SECTION_BOARDS.with_mut(|boards| {
        if let Some(board) = boards.get_mut(&contract_id) {
            board.syncing = true;
            board.ready = false;
        }
    });
    let mut state = child;
    state.configuration = parent.configuration.clone();
    state.admin = parent.admin.clone();
    state.ownership = parent.ownership.clone();
    state.bans = parent.bans.clone();
    state.ban_revocations = parent.ban_revocations.clone();
    state.roles = parent.roles.clone();
    state.invites = parent.invites.clone();
    state.members = parent.members.clone();
    state.member_info = parent.member_info.clone();
    state.category_secrets = parent.category_secrets.clone();
    state.secrets = parent.secrets.clone();
    state.pq_secrets = parent.pq_secrets.clone();
    state.warnings = parent.warnings.clone();
    state.suspensions = parent.suspensions.clone();
    state.image_retirements = parent.image_retirements.clone();
    state.upgrade = parent.upgrade.clone();
    state.mail_addresses = parent.mail_addresses.clone();
    state.sections = parent.sections.clone();

    let board_params = ChatBoardParametersV1 { owner };
    state
        .verify_with_section(&board_params, Some(section))
        .map_err(|error| format!("section authority does not verify: {error}"))?;
    SECTION_BOARDS.with_mut(|boards| {
        if let Some(board) = boards.get_mut(&contract_id) {
            board.state = state.clone();
            board.synced = true;
            board.ready = false;
        }
    });
    let result = send_client_request(ClientRequest::ContractOp(ContractRequest::Update {
        key,
        data: UpdateData::State(to_cbor_vec(&state).into()),
    }))
    .await;
    SECTION_BOARDS.with_mut(|boards| {
        if let Some(board) = boards.get_mut(&contract_id) {
            board.syncing = false;
            board.ready = result.is_ok();
        }
    });
    result.map_err(|error| format!("send section authority: {error}"))
}

/// Apply a delta to a section child and publish it. The child contract
/// verifies its own records and section layout.
pub async fn apply_section_delta(
    owner: VerifyingKey,
    section: SectionId,
    delta: plaza_core::board_state::ChatBoardStateV1Delta,
) -> Result<(), String> {
    let key = section_key(owner, section);
    let contract_id = *key.id();
    if !SECTION_BOARDS
        .read()
        .get(&contract_id)
        .map(|board| board.synced)
        .unwrap_or(false)
    {
        ensure_section_loaded(owner, section).await?;
    }
    let parent = SECTION_BOARDS
        .read()
        .get(&contract_id)
        .map(|board| board.state.clone())
        .ok_or("the section board is not loaded")?;
    let mut state = parent.clone();
    state
        .apply_delta(
            &parent,
            &ChatBoardParametersV1 { owner },
            &Some(delta.clone()),
        )
        .map_err(|error| format!("apply section delta: {error}"))?;
    SECTION_BOARDS.with_mut(|boards| {
        if let Some(board) = boards.get_mut(&contract_id) {
            board.state = state;
            board.synced = false;
        }
    });
    let bytes = to_cbor_vec(&delta);
    send_client_request(ClientRequest::ContractOp(ContractRequest::Update {
        key,
        data: UpdateData::Delta(bytes.into()),
    }))
    .await
    .map_err(|error| format!("send section delta: {error}"))
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
    let mut sections = parent.sections.clone();
    if !sections
        .sections
        .iter()
        .any(|entry| entry.section.id == section_id)
    {
        sections.sections.push(section.clone());
    }
    sections
        .sections
        .sort_by_key(|entry| (*entry.section.id.as_bytes(), entry.section.generation));
    child.sections = sections;
    child.topics = TopicIndexV1::default();
    child.recent_messages = Default::default();
    child.trash = Default::default();
    child.message_keys = Default::default();
    child.moderation = Default::default();
    child.reports = Default::default();
    child.approvals = Default::default();
    child.invites = Default::default();

    let board_params = ChatBoardParametersV1 { owner };
    child
        .verify_with_section(&board_params, Some(section_id))
        .map_err(|error| format!("section state does not verify: {error}"))?;
    let mut normalized = child.clone();
    normalized
        .normalize(&board_params)
        .map_err(|error| format!("section state cleanup failed: {error}"))?;
    if normalized != child {
        return Err("section state is not normalized".to_string());
    }

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
                params: params.clone(),
                state: child.clone(),
                synced: false,
                ready: false,
                syncing: false,
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
    let known = SECTION_BOARDS
        .read()
        .get(&contract_id)
        .map(|board| board.synced)
        .unwrap_or(false);
    if known {
        return Ok(contract_id);
    }
    SECTION_BOARDS.with_mut(|boards| {
        if !boards.contains_key(&contract_id) {
            boards.insert(
                contract_id,
                SectionBoard {
                    params: SectionParametersV1 { owner, section },
                    state: ChatBoardStateV1::default(),
                    synced: false,
                    ready: false,
                    syncing: false,
                },
            );
        }
    });
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

/// Wait until a section child state has arrived. A GET is retried because the
/// child PUT may still be in flight right after the board or section is created.
pub async fn ensure_section_loaded(
    owner: VerifyingKey,
    section: SectionId,
) -> Result<(), String> {
    let key = section_key(owner, section);
    let contract_id = *key.id();
    for _ in 0..12 {
        if SECTION_BOARDS
            .read()
            .get(&contract_id)
            .map(|board| board.ready)
            .unwrap_or(false)
        {
            return Ok(());
        }
        let synced = SECTION_BOARDS
            .read()
            .get(&contract_id)
            .map(|board| board.synced)
            .unwrap_or(false);
        if !synced {
            load_section_board(owner, section).await?;
            for _ in 0..10 {
                crate::util::sleep(std::time::Duration::from_millis(200)).await;
                if SECTION_BOARDS
                    .read()
                    .get(&contract_id)
                    .map(|board| board.synced)
                    .unwrap_or(false)
                {
                    break;
                }
            }
            continue;
        }
        let parent = {
            let boards = crate::components::app::BOARDS.read();
            boards
                .map
                .get(&owner)
                .map(|board| board.board_state.clone())
        };
        let Some(parent) = parent else {
            return Err("the parent board is not loaded".to_string());
        };
        let _ = sync_section_authority(owner, section, &parent).await;
        for _ in 0..10 {
            crate::util::sleep(std::time::Duration::from_millis(200)).await;
            if SECTION_BOARDS
                .read()
                .get(&contract_id)
                .map(|board| board.ready)
                .unwrap_or(false)
            {
                return Ok(());
            }
        }
    }
    Err("the section board is not ready yet".to_string())
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
            let parent_state = {
                let boards = crate::components::app::BOARDS.read();
                boards
                    .map
                    .get(&owner)
                    .map(|board| board.board_state.clone())
            };
            SECTION_BOARDS.with_mut(|boards| {
                if let Some(board) = boards.get_mut(key.id()) {
                    board.state = state;
                    board.synced = true;
                }
            });
            if let Some(parent_state) = parent_state {
                if parent_state.mode == BoardModeV1::SectionedTopicIndex {
                    let section = SECTION_BOARDS
                        .read()
                        .get(key.id())
                        .map(|board| board.params.section);
                    if let Some(section) = section {
                        crate::util::safe_spawn_local(async move {
                            let _ = sync_section_authority(owner, section, &parent_state)
                                .await;
                        });
                    }
                }
            }
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
