//! Client for the `plaza-topic` contract.
//!
//! Creates a topic contract, loads it on demand, publishes replies as deltas
//! and keeps the board index in sync. The UI for index boards sits on top of
//! this module.

use crate::board_data::BoardData;
use crate::components::app::{mark_needs_sync, mark_needs_sync_later, BOARDS};
use crate::constants::TOPIC_CONTRACT_WASM;
use crate::util::ecies::{decrypt_with_symmetric_key, encrypt_with_symmetric_key};
use crate::util::{get_current_system_time, to_cbor_vec};
use dioxus::prelude::*;
use ed25519_dalek::VerifyingKey;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use freenet_scaffold::ComposableState;
use freenet_stdlib::client_api::{ClientRequest, ContractRequest, ContractResponse};
use freenet_stdlib::prelude::{
    ContractCode, ContractContainer, ContractInstanceId, ContractKey, ContractWasmAPIVersion,
    Parameters, UpdateData, WrappedContract, WrappedState,
};
use plaza_core::board_state::content::{
    PollContentV1, PollResultsVisibility, PollVoteV1,
};
use plaza_core::board_state::member::{AuthorizedMember, MemberId};
use plaza_core::board_state::message::MessageId;
use plaza_core::board_state::privacy::SealedBytes;
use plaza_core::board_state::rate_limit::{
    exceeds_window, system_time_ms, MAX_REPORTS_PER_WINDOW, MAX_TOPICS_PER_WINDOW,
    REPORT_RATE_WINDOW_MS, TOPIC_RATE_WINDOW_MS,
};
use plaza_core::board_state::reports::ReportReason;
use plaza_core::board_state::roles::{AuthorityProof, RoleGrantProof};
use plaza_core::board_state::sections::{
    AuthorizedSectionV1, SectionV1, SectionsDelta,
};
use plaza_core::board_state::topics::{
    AuthorizedTopicActivityV1, AuthorizedTopicEntryV1, AuthorizedTopicFlagV1,
    AuthorizedTopicReportV1, TopicActivityV1, TopicEntryV1, TopicFlagKind,
    AuthorizedTopicReportResolutionV1, TopicFlagV1, TopicIndexDelta,
    TopicReportResolutionV1, TopicReportV1,
};
use plaza_core::board_state::{BoardModeV1, ChatBoardParametersV1, ChatBoardStateV1Delta};
use plaza_topic_core::{
    decode_state, encode, AuthorizedParticipantV1, AuthorizedSectionSnapshotV1,
    AuthorizedTopicApprovalV1, AuthorizedTopicHeaderV1, AuthorizedTopicPolicyV1,
    AuthorizedTrustV1, ParticipantCertificateV1, ParticipantRecordV1,
    SectionSnapshotV1, TopicActionKind, TopicApprovalV1, TopicDeltaV1,
    TopicEditV1, TopicHeaderV1, TopicParamsV1, TopicPolicyV1, TopicPostContentV1,
    TopicStateV1, TrustV1, PostEditV1,
};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use rand::RngCore;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

#[derive(Clone)]
pub struct TopicConversation {
    pub key: ContractKey,
    pub params: TopicParamsV1,
    pub state: TopicStateV1,
    pub synced: bool,
    /// Last time this topic was opened, used to bound the client cache.
    pub last_used: i64,
}

pub static TOPIC_CACHE: GlobalSignal<HashMap<ContractInstanceId, TopicConversation>> =
    Global::new(HashMap::new);

/// Keep the state of recently opened topics. The node subscription is not
/// cancelled here; the client only drops the cached state.
const MAX_CACHED_TOPICS: usize = 24;

fn touch_topic(contract_id: ContractInstanceId) {
    let now = system_time_ms(get_current_system_time());
    TOPIC_CACHE.with_mut(|topics| {
        if let Some(conversation) = topics.get_mut(&contract_id) {
            conversation.last_used = now;
        }
    });
}

fn evict_topics(protect: ContractInstanceId) {
    TOPIC_CACHE.with_mut(|topics| {
        while topics.len() > MAX_CACHED_TOPICS {
            let victim = topics
                .iter()
                .filter(|(id, conversation)| **id != protect && conversation.synced)
                .min_by_key(|(_, conversation)| conversation.last_used)
                .map(|(id, _)| *id);
            match victim {
                Some(id) => {
                    topics.remove(&id);
                }
                None => break,
            }
        }
    });
}

pub fn topic_key_for(owner: VerifyingKey, topic_id: MessageId, part: u32) -> ContractKey {
    let params = TopicParamsV1::new(owner, *topic_id.as_bytes(), part);
    let parameters = Parameters::from(to_cbor_vec(&params));
    let code = ContractCode::from(TOPIC_CONTRACT_WASM);
    ContractKey::from_params_and_code(parameters, &code)
}

pub fn is_known_topic(key: &ContractInstanceId) -> bool {
    TOPIC_CACHE.read().contains_key(key)
}

pub fn is_topic_contract_response(response: &ContractResponse) -> bool {
    match response {
        ContractResponse::GetResponse { key, .. }
        | ContractResponse::PutResponse { key }
        | ContractResponse::UpdateResponse { key, .. }
        | ContractResponse::UpdateNotification { key, .. }
        | ContractResponse::SubscribeResponse { key, .. } => is_known_topic(key.id()),
        _ => false,
    }
}

pub fn topic_state(owner: VerifyingKey, topic_id: MessageId, part: u32) -> Option<TopicStateV1> {
    let key = topic_key_for(owner, topic_id, part);
    TOPIC_CACHE
        .read()
        .get(key.id())
        .map(|conversation| conversation.state.clone())
}

/// Ensure a topic is in the cache and fetch its state. Safe to call on every
/// render; a loaded state is not fetched again.
pub async fn load_topic(
    owner: VerifyingKey,
    topic_id: MessageId,
    part: u32,
) -> Result<ContractInstanceId, String> {
    let key = topic_key_for(owner, topic_id, part);
    let contract_id = *key.id();
    let already_loaded = TOPIC_CACHE
        .read()
        .get(&contract_id)
        .map(|conversation| conversation.state.header.is_some())
        .unwrap_or(false);
    if !already_loaded {
        TOPIC_CACHE.with_mut(|topics| {
            topics.entry(contract_id).or_insert_with(|| TopicConversation {
                key,
                params: TopicParamsV1::new(owner, *topic_id.as_bytes(), part),
                state: TopicStateV1::default(),
                synced: false,
                last_used: system_time_ms(get_current_system_time()),
            });
        });
        evict_topics(contract_id);
        send_contract_request(ContractRequest::Get {
            key: contract_id,
            return_contract_code: false,
            subscribe: true,
            blocking_subscribe: false,
        })
        .await
        .map_err(|error| format!("topic get {contract_id:?} part {part}: {error}"))?;
    }
    touch_topic(contract_id);
    Ok(contract_id)
}

pub async fn fetch_topic(contract_id: ContractInstanceId) -> Result<(), String> {
    send_contract_request(ContractRequest::Get {
        key: contract_id,
        return_contract_code: false,
        subscribe: true,
        blocking_subscribe: false,
    })
    .await
}




/// Start the next part of a long topic. The new contract reuses the header,
/// authority, participants, actions and trust, drops the old posts and records
/// the hash of the closed part. The board index moves to the new part.
pub async fn continue_topic(
    owner: VerifyingKey,
    topic_id: MessageId,
    part: u32,
) -> Result<u32, String> {
    let board = board_for(owner)?;
    let conversation = conversation_for(owner, topic_id, part)?;
    let header = conversation
        .state
        .header
        .clone()
        .ok_or("the topic is still loading")?;
    if conversation.state.generation.closed_at.is_some() {
        return Err("the topic part is already closed".to_string());
    }
    let next_part = part + 1;
    if next_part > plaza_topic_core::MAX_PARTS {
        return Err("the topic reached the maximum number of parts".to_string());
    }
    let mut next_state = conversation.state.clone();
    next_state.posts.clear();
    next_state.approvals.clear();
    let header_id = header.header.id();
    next_state.header = Some(header);
    next_state
        .actions
        .retain(|entry| entry.action.target == header_id);
    next_state.generation = plaza_topic_core::TopicGenerationV1 {
        part: next_part,
        closed_at: None,
        next_part: None,
        previous_hash: Some(
            Sha256::digest(encode(&conversation.state)?).into(),
        ),
    };
    let next_params = TopicParamsV1::new(owner, *topic_id.as_bytes(), next_part);
    next_state
        .verify(&next_params)
        .map_err(|error| format!("the new topic part does not verify: {error}"))?;
    let key = topic_key_for(owner, topic_id, next_part);
    let contract_id = *key.id();
    TOPIC_CACHE.with_mut(|topics| {
        topics.insert(
            contract_id,
            TopicConversation {
                key,
                params: next_params.clone(),
                state: next_state.clone(),
                synced: false,
                last_used: system_time_ms(get_current_system_time()),
            },
        );
    });
    evict_topics(contract_id);
    let contract = ContractContainer::from(ContractWasmAPIVersion::V1(WrappedContract::new(
        Arc::new(ContractCode::from(TOPIC_CONTRACT_WASM)),
        Parameters::from(to_cbor_vec(&next_params)),
    )));
    send_contract_request(ContractRequest::Put {
        contract,
        state: WrappedState::new(to_cbor_vec(&next_state)),
        related_contracts: Default::default(),
        subscribe: true,
        blocking_subscribe: false,
    })
    .await?;

    let now = system_time_ms(get_current_system_time());
    let closed = plaza_topic_core::TopicGenerationV1 {
        part,
        closed_at: Some(now),
        next_part: Some(next_part),
        previous_hash: conversation.state.generation.previous_hash,
    };
    publish_topic_delta(
        *conversation.key.id(),
        TopicDeltaV1 {
            generation: Some(closed),
            ..Default::default()
        },
    )
    .await?;

    let index = crate::components::app::section_contract::merged_index(
        owner,
        &board.board_state.topics,
    );
    let current_generation = index
        .flag(&topic_id, TopicFlagKind::Part)
        .map(|flag| flag.generation)
        .unwrap_or(0);
    let chain = conversation.state.effective_section().map(|section| section.chain).unwrap_or_default();
    let flag = TopicFlagV1 {
        topic_id,
        kind: TopicFlagKind::Part,
        value: true,
        destination: None,
        section: None,
        section_chain: Vec::new(),
        destination_sections: Vec::new(),
        part: Some(next_part),
        scope_chain: chain,
        generation: current_generation + 1,
        created_at: now,
    };
    let authorized_flag = AuthorizedTopicFlagV1 {
        signature: plaza_core::util::sign_struct(&flag, &board.self_sk),
        flag,
        signer: Some(MemberId::from(&board.self_sk.verifying_key())),
        signer_key: Some(board.self_sk.verifying_key()),
        authority: None,
    };
    let board_delta = ChatBoardStateV1Delta {
        topics: Some(TopicIndexDelta {
            flags: vec![authorized_flag],
            ..Default::default()
        }),
        ..Default::default()
    };
    apply_topic_board_delta(owner, topic_id, board_delta).await?;
    Ok(next_part)
}

fn section_snapshot_from_board(
    board: &BoardData,
    section_id: MessageId,
) -> Result<SectionSnapshotV1, String> {
    let section = board
        .board_state
        .sections
        .section(&section_id)
        .ok_or("the section does not exist")?;
    Ok(SectionSnapshotV1 {
        section: section_id,
        parent: section.parent,
        chain: board.board_state.sections.chain(&section_id),
        allowed_roles: section.allowed_roles.clone(),
        sealed_name: section.sealed_name.clone(),
        hidden: section.hidden,
        images_allowed: section.images_allowed,
        auto_moderated_topics: section.auto_moderated_topics,
        generation: section.generation,
        signed_at: system_time_ms(section.signed_at),
    })
}

/// Move a topic to another section. The owner signs a Move action carrying the
/// new section snapshot and a board `Section` flag for the index.
pub async fn move_topic(
    owner: VerifyingKey,
    topic_id: MessageId,
    part: u32,
    section_id: MessageId,
) -> Result<(), String> {
    let board = board_for(owner)?;
    if !board.is_current_owner() {
        return Err("only the board owner can move a topic for now".to_string());
    }
    let conversation = conversation_for(owner, topic_id, part)?;
    let header = conversation
        .state
        .header
        .as_ref()
        .ok_or("the topic is still loading")?;
    let snapshot = section_snapshot_from_board(&board, section_id)?;
    let payload = SealedBytes::public(encode(&snapshot)?);
    let now = system_time_ms(get_current_system_time());
    let owner_key = board.owner_key();
    let signer = MemberId::from(&owner_key.verifying_key());
    let generation = conversation
        .state
        .latest_action(header.header.id(), TopicActionKind::Move)
        .map(|entry| entry.action.generation + 1)
        .unwrap_or(1);
    let action = plaza_topic_core::TopicActionV1 {
        kind: TopicActionKind::Move,
        target: header.header.id(),
        payload,
        generation,
        created_at: now,
        signer,
    };
    let authorized = plaza_topic_core::AuthorizedTopicActionV1 {
        signature: plaza_core::util::sign_struct(&action, owner_key),
        action,
        signer_key: Some(owner_key.verifying_key()),
        authority: None,
    };
    publish_topic_delta(
        *conversation.key.id(),
        TopicDeltaV1 {
            actions: vec![authorized],
            ..Default::default()
        },
    )
    .await?;

    let index = crate::components::app::section_contract::merged_index(
        owner,
        &board.board_state.topics,
    );
    let base = index.entry(&topic_id).ok_or("the topic is not indexed")?;
    let current_generation = index
        .flag(&topic_id, TopicFlagKind::Section)
        .map(|flag| flag.generation)
        .unwrap_or(0);
    let flag = TopicFlagV1 {
        topic_id,
        kind: TopicFlagKind::Section,
        value: true,
        destination: None,
        section: Some(section_id),
        section_chain: snapshot.chain,
        destination_sections: board
            .board_state
            .sections
            .chain_only(&section_id)
            .sections,
        part: None,
        scope_chain: base.entry.section_chain.clone(),
        generation: current_generation + 1,
        created_at: now,
    };
    let authorized_flag = AuthorizedTopicFlagV1 {
        signature: plaza_core::util::sign_struct(&flag, owner_key),
        flag,
        signer: Some(signer),
        signer_key: Some(owner_key.verifying_key()),
        authority: None,
    };
    let board_delta = ChatBoardStateV1Delta {
        topics: Some(TopicIndexDelta {
            flags: vec![authorized_flag],
            ..Default::default()
        }),
        ..Default::default()
    };
    apply_topic_board_delta(owner, topic_id, board_delta).await
}

/// Merge a topic into another one as a link. Replies stay in the source
/// contract; the index marks the source as merged.
pub async fn merge_topic(
    owner: VerifyingKey,
    topic_id: MessageId,
    part: u32,
    destination: MessageId,
) -> Result<(), String> {
    let board = board_for(owner)?;
    if !board.is_current_owner() {
        return Err("only the board owner can merge topics for now".to_string());
    }
    if topic_id == destination {
        return Err("a topic cannot merge into itself".to_string());
    }
    let index = crate::components::app::section_contract::merged_index(
        owner,
        &board.board_state.topics,
    );
    if index.entry(&destination).is_none() {
        return Err("the destination topic is not indexed".to_string());
    }
    let source_section = index.section_of(&topic_id).0;
    let destination_section = index.section_of(&destination).0;
    let (flag_section, flag_section_chain) = if board.board_state.mode
        == BoardModeV1::SectionedTopicIndex
        && source_section != destination_section
    {
        let section = destination_section
            .ok_or("a cross-section merge needs a destination section")?;
        let chain = board.board_state.sections.chain(&section);
        (Some(section), chain)
    } else {
        (None, Vec::new())
    };
    let conversation = conversation_for(owner, topic_id, part)?;
    let header = conversation
        .state
        .header
        .as_ref()
        .ok_or("the topic is still loading")?;
    let now = system_time_ms(get_current_system_time());
    let owner_key = board.owner_key();
    let signer = MemberId::from(&owner_key.verifying_key());
    let generation = conversation
        .state
        .latest_action(header.header.id(), TopicActionKind::Merge)
        .map(|entry| entry.action.generation + 1)
        .unwrap_or(1);
    let action = plaza_topic_core::TopicActionV1 {
        kind: TopicActionKind::Merge,
        target: header.header.id(),
        payload: SealedBytes::public(destination.as_bytes().to_vec()),
        generation,
        created_at: now,
        signer,
    };
    let authorized = plaza_topic_core::AuthorizedTopicActionV1 {
        signature: plaza_core::util::sign_struct(&action, owner_key),
        action,
        signer_key: Some(owner_key.verifying_key()),
        authority: None,
    };
    publish_topic_delta(
        *conversation.key.id(),
        TopicDeltaV1 {
            actions: vec![authorized],
            ..Default::default()
        },
    )
    .await?;

    let base = index.entry(&topic_id).ok_or("the topic is not indexed")?;
    let current_generation = index
        .flag(&topic_id, TopicFlagKind::Merged)
        .map(|flag| flag.generation)
        .unwrap_or(0);
    let flag = TopicFlagV1 {
        topic_id,
        kind: TopicFlagKind::Merged,
        value: true,
        destination: Some(destination),
        section: flag_section,
        section_chain: flag_section_chain,
        destination_sections: flag_section
            .map(|section| {
                board
                    .board_state
                    .sections
                    .chain_only(&section)
                    .sections
            })
            .unwrap_or_default(),
        part: None,
        scope_chain: base.entry.section_chain.clone(),
        generation: current_generation + 1,
        created_at: now,
    };
    let authorized_flag = AuthorizedTopicFlagV1 {
        signature: plaza_core::util::sign_struct(&flag, owner_key),
        flag,
        signer: Some(signer),
        signer_key: Some(owner_key.verifying_key()),
        authority: None,
    };
    let board_delta = ChatBoardStateV1Delta {
        topics: Some(TopicIndexDelta {
            flags: vec![authorized_flag],
            ..Default::default()
        }),
        ..Default::default()
    };
    apply_topic_board_delta(owner, topic_id, board_delta).await
}

/// Split one text reply into a new topic and mark the original reply as moved.
pub async fn split_reply(
    owner: VerifyingKey,
    topic_id: MessageId,
    part: u32,
    reply_id: MessageId,
    title: String,
    section: Option<MessageId>,
) -> Result<MessageId, String> {
    let board = board_for(owner)?;
    if !board.is_current_owner() {
        return Err("only the board owner can split a reply for now".to_string());
    }
    let conversation = conversation_for(owner, topic_id, part)?;
    let post = conversation
        .state
        .posts
        .get(&reply_id)
        .ok_or("the reply is not in this topic")?;
    let body = match read_post_content(&board, &post.post.content) {
        Some(TopicPostContentV1::Text(text)) => text,
        Some(TopicPostContentV1::Poll(_)) => {
            return Err("splitting a poll is not supported yet".to_string());
        }
        None => return Err("the reply content could not be read".to_string()),
    };
    let new_topic = create_topic(owner, title, body, section).await?;
    let now = system_time_ms(get_current_system_time());
    let owner_key = board.owner_key();
    let signer = MemberId::from(&owner_key.verifying_key());
    let generation = conversation
        .state
        .latest_action(reply_id, TopicActionKind::Split)
        .map(|entry| entry.action.generation + 1)
        .unwrap_or(1);
    let action = plaza_topic_core::TopicActionV1 {
        kind: TopicActionKind::Split,
        target: reply_id,
        payload: SealedBytes::public(new_topic.as_bytes().to_vec()),
        generation,
        created_at: now,
        signer,
    };
    let authorized = plaza_topic_core::AuthorizedTopicActionV1 {
        signature: plaza_core::util::sign_struct(&action, owner_key),
        action,
        signer_key: Some(owner_key.verifying_key()),
        authority: None,
    };
    publish_topic_delta(
        *conversation.key.id(),
        TopicDeltaV1 {
            actions: vec![authorized],
            ..Default::default()
        },
    )
    .await?;
    Ok(new_topic)
}


/// Report a topic or one of its posts. Reports live in the per-board
/// moderation contract, so the moderation queue sees them without rewriting
/// the section page.
pub async fn report_post(
    owner: VerifyingKey,
    topic_id: MessageId,
    post_id: Option<MessageId>,
    reason: ReportReason,
    body: String,
) -> Result<(), String> {
    let board = board_for(owner)?;
    let index = board.clone().with_merged_topics().board_state.topics;
    if index.entry(&topic_id).is_none() {
        return Err("the topic is not indexed".to_string());
    }
    let body = body.trim().to_string();
    if body.len() > 2_000 {
        return Err("the report is too long".to_string());
    }
    let reporter = MemberId::from(&board.self_sk.verifying_key());
    let now = system_time_ms(get_current_system_time());
    let mut recent_reports: Vec<i64> = index
        .reports
        .iter()
        .filter(|entry| entry.report.reporter == reporter)
        .map(|entry| entry.report.created_at)
        .collect();
    recent_reports.push(now);
    if exceeds_window(
        &recent_reports,
        REPORT_RATE_WINDOW_MS,
        MAX_REPORTS_PER_WINDOW,
    ) {
        return Err("too many reports sent in the last hour; wait before sending another".to_string());
    }
    let generation = index
        .reports
        .iter()
        .filter(|entry| {
            entry.report.topic_id == topic_id
                && entry.report.post_id == post_id
                && entry.report.reporter == reporter
        })
        .map(|entry| entry.report.generation + 1)
        .max()
        .unwrap_or(1);
    let report = TopicReportV1 {
        topic_id,
        post_id,
        reporter,
        reason,
        body: seal_text(&board, &body)?,
        created_at: now,
        generation,
    };
    let authorized = AuthorizedTopicReportV1 {
        signature: plaza_core::util::sign_struct(&report, &board.self_sk),
        report,
    };
    crate::components::app::moderation_contract::record_report(owner, authorized).await
}


pub async fn resolve_report(
    owner: VerifyingKey,
    topic_id: MessageId,
    post_id: Option<MessageId>,
    reporter: MemberId,
) -> Result<(), String> {
    let board = board_for(owner)?;
    let index = board.clone().with_merged_topics().board_state.topics;
    let report = index
        .reports
        .iter()
        .find(|entry| {
            entry.report.topic_id == topic_id
                && entry.report.post_id == post_id
                && entry.report.reporter == reporter
        })
        .ok_or("the report does not exist")?;
    let _ = report;
    let self_id = MemberId::from(&board.self_sk.verifying_key());
    let owner_id = board.current_owner_id();
    let chain = index.section_of(&topic_id).1;
    let (signer_sk, signer, authority) = if self_id != owner_id
        && board.can_moderate(&chain)
    {
        (
            board.self_sk.clone(),
            self_id,
            delete_authority(&board, &self_id),
        )
    } else if board.is_current_owner() {
        (board.owner_key().clone(), owner_id, None)
    } else {
        return Err("only a moderator can resolve a report".to_string());
    };
    let generation = index
        .report_resolutions
        .iter()
        .filter(|entry| {
            entry.resolution.topic_id == topic_id
                && entry.resolution.post_id == post_id
                && entry.resolution.reporter == reporter
        })
        .map(|entry| entry.resolution.generation + 1)
        .max()
        .unwrap_or(1);
    let resolution = TopicReportResolutionV1 {
        topic_id,
        post_id,
        reporter,
        resolved_by: signer,
        created_at: system_time_ms(get_current_system_time()),
        generation,
    };
    let authorized = AuthorizedTopicReportResolutionV1 {
        signature: plaza_core::util::sign_struct(&resolution, &signer_sk),
        resolution,
        signer_key: Some(signer_sk.verifying_key()),
        authority: authority.clone().map(Box::new),
    };
    crate::components::app::moderation_contract::record_resolution(owner, authorized).await
}

pub fn topic_reports(
    board: &BoardData,
    topic_id: MessageId,
) -> Vec<TopicReportV1> {
    let mut reports: Vec<_> = board
        .board_state
        .topics
        .reports
        .iter()
        .filter(|entry| entry.report.topic_id == topic_id)
        .map(|entry| entry.report.clone())
        .collect();
    reports.sort_by_key(|report| (report.created_at, report.generation));
    reports
}

pub fn report_body(board: &BoardData, report: &TopicReportV1) -> String {
    read_text(board, &report.body).unwrap_or_default()
}

/// Create a new board section. Only the owner can sign the section record.
pub async fn create_section(
    owner: VerifyingKey,
    name: String,
) -> Result<MessageId, String> {
    let board = board_for(owner)?;
    if !board.is_current_owner() {
        return Err("only the board owner can create a section".to_string());
    }
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("the section needs a name".to_string());
    }
    if name.chars().count() > 200 {
        return Err("the section name is too long".to_string());
    }
    let mut id_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut id_bytes);
    let id = MessageId::from_bytes(id_bytes);
    let sectioned = board.board_state.mode
        == plaza_core::board_state::BoardModeV1::SectionedTopicIndex;
    let child_key: Option<ContractKey> = if sectioned {
        Some(crate::components::app::section_contract::section_key(owner, id))
    } else {
        None
    };
    let now = get_current_system_time();
    let (public_name, sealed_name) = if board.is_private() {
        let (secret, version) = board
            .get_secret()
            .ok_or("the board secret is not available")?;
        let (ciphertext, nonce) =
            encrypt_with_symmetric_key(secret, name.as_bytes(), version);
        (
            "Section".to_string(),
            Some(SealedBytes::private(
                ciphertext,
                nonce,
                version,
                name.len() as u32,
            )),
        )
    } else {
        (name, None)
    };
    let section = SectionV1 {
        id,
        parent: None,
        name: public_name,
        description: None,
        icon: None,
        color: "#6366f1".to_string(),
        allowed_roles: Vec::new(),
        sealed_name,
        hidden: false,
        is_group: false,
        images_allowed: true,
        auto_moderated_topics: None,
        generation: 1,
        deleted: false,
        contract: child_key.map(|key| *key.id()),
        signed_at: now,
    };
    let authorized = AuthorizedSectionV1::new(section, board.owner_key(), None);
    if child_key.is_some() {
        let owner_sk = board.owner_key();
        let page_size = crate::components::app::section_contract::current_topic_page_size();
        let topic_pages =
            plaza_core::board_state::pages::AuthorizedTopicPageListV1::new(
                id,
                Vec::new(),
                page_size,
                owner_sk,
                system_time_ms(now),
            );
        crate::components::app::section_contract::create_section_board(
            owner,
            &authorized,
            &board.board_state,
            Some(topic_pages),
        )
        .await?;
    }
    let delta = ChatBoardStateV1Delta {
        sections: Some(SectionsDelta {
            sections: vec![authorized],
        }),
        ..Default::default()
    };
    apply_board_delta(owner, delta)?;
    if sectioned {
        let refreshed = board_for(owner)?;
        let sections: Vec<_> = refreshed
            .board_state
            .sections
            .sections
            .iter()
            .filter_map(|entry| entry.section.contract.map(|_| entry.section.id))
            .collect();
        for section in sections {
            let _ = crate::components::app::section_contract::sync_section_authority(
                owner,
                section,
                &refreshed.board_state,
            )
            .await;
        }
    }
    Ok(id)
}


fn authority_from_board(
    board: &BoardData,
    is_owner: bool,
    member_ids: &HashSet<MemberId>,
) -> Result<plaza_topic_core::TopicAuthorityV1, String> {
    let now = system_time_ms(get_current_system_time());
    let policy = TopicPolicyV1 {
        read_only: board.board_state.configuration.configuration.read_only,
        approval_required: board
            .board_state
            .configuration
            .configuration
            .approval_required,
        rate_window_ms: board
            .board_state
            .configuration
            .configuration
            .rate_window_ms,
        max_posts_per_window: board
            .board_state
            .configuration
            .configuration
            .max_posts_per_window,
        images_allowed: true,
        auto_moderated_topics: board
            .board_state
            .configuration
            .configuration
            .auto_moderated_topics,
        reactions_enabled: board
            .board_state
            .configuration
            .configuration
            .reactions_enabled,
        max_post_size: board
            .board_state
            .configuration
            .configuration
            .max_message_size,
        generation: 1,
        updated_at: now,
    };
    let (policy, source_configuration) = if is_owner {
        (
            Some(AuthorizedTopicPolicyV1::new(policy, board.owner_key())),
            None,
        )
    } else {
        (None, Some(board.board_state.configuration.clone()))
    };
    let mut merged_board_state = board.board_state.clone();
    let mut merged_members = std::mem::take(&mut merged_board_state.members);
    crate::components::app::member_contract::apply_to_members(
        board.owner_vk,
        &merged_board_state,
        &mut merged_members,
    );
    merged_board_state.members = merged_members;
    let tree = plaza_topic_core::AuthorityTreeV1::from_board(&merged_board_state);
    let content_hash = tree.content_hash();
    let digest = tree.root(0).digest;
    let signed_root = board
        .board_state
        .authority_root
        .0
        .clone()
        .filter(|root| {
            root.root.digest == digest && root.root.content_hash == content_hash
        })
        .or_else(|| {
            board.owner_sk.as_ref().map(|owner_sk| {
                let mut root =
                    tree.root(system_time_ms(get_current_system_time()));
                root.content_hash = content_hash;
                plaza_topic_core::AuthorizedAuthorityRootV1::new(root, owner_sk)
            })
        });
    // A ban also needs the banner's key to verify its signature. When the
    // banner is not the owner or an admin, include that member's proof too.
    let owner_id = MemberId::from(&board.owner_vk);
    let admin_ids: HashSet<MemberId> = board
        .board_state
        .admin
        .admins
        .iter()
        .map(|admin| admin.admin.member_id)
        .collect();
    let mut ids: HashSet<MemberId> = member_ids.iter().copied().collect();
    loop {
        let mut added = false;
        for ban in &board.board_state.bans.0 {
            if ids.contains(&ban.ban.banned_user)
                && ban.banned_by != owner_id
                && !admin_ids.contains(&ban.banned_by)
                && ids.insert(ban.banned_by)
            {
                added = true;
            }
        }
        for suspension in &board.board_state.suspensions.suspensions {
            if ids.contains(&suspension.suspension.target) {
                if let Some(signer) = suspension.signer {
                    if signer != owner_id
                        && !admin_ids.contains(&signer)
                        && ids.insert(signer)
                    {
                        added = true;
                    }
                }
            }
        }
        if !added {
            break;
        }
    }
    let (root, member_proofs, roles, bans, ban_revocations, suspensions) =
        if let Some(root) = signed_root {
            (
                Some(root),
                tree.proofs_for(ids.iter()),
                plaza_core::board_state::roles::RolesV1 {
                    // Role definitions stay complete: a token join and a
                    // role-based moderator need the definition even when the
                    // member has no signed assignment.
                    roles: board.board_state.roles.roles.clone(),
                    assignments: Vec::new(),
                },
                Default::default(),
                Default::default(),
                Default::default(),
            )
        } else {
            // No owner-signed root is available yet (legacy board or a member
            // that has not received it). Keep the full lists; the contract
            // still verifies every record.
            (
                None,
                Vec::new(),
                board.board_state.roles.clone(),
                board.board_state.bans.clone(),
                board.board_state.ban_revocations.clone(),
                board.board_state.suspensions.clone(),
            )
        };
    Ok(plaza_topic_core::TopicAuthorityV1 {
        ownership: board.board_state.ownership.clone(),
        admins: board.board_state.admin.clone(),
        roles,
        bans,
        ban_revocations,
        suspensions,
        policy,
        source_configuration,
        root,
        member_proofs,
    })
}

/// Hash of the board authority fields that a topic mirrors. Used to trigger a
/// propagation pass only when bans, roles, admins, ownership or the policy
/// actually changed.
pub fn authority_hash(board: &BoardData) -> i64 {
    let state = &board.board_state;
    let bytes = match encode(&(
        &state.ownership,
        &state.admin,
        &state.roles,
        &state.bans,
        &state.ban_revocations,
        &state.suspensions,
        &state.configuration,
    )) {
        Ok(bytes) => bytes,
        Err(_) => return 0,
    };
    freenet_scaffold::util::fast_hash(&bytes).0
}

pub static PROPAGATED_AUTHORITY: GlobalSignal<HashMap<VerifyingKey, i64>> =
    Global::new(HashMap::new);

/// Returns true when this client has not propagated this authority snapshot
/// yet. The marker is local, so each client does its own pass.
pub fn mark_authority_seen(owner: VerifyingKey, hash: i64) -> bool {
    let mut seen = PROPAGATED_AUTHORITY.write();
    match seen.get(&owner) {
        Some(previous) if *previous == hash => false,
        _ => {
            seen.insert(owner, hash);
            true
        }
    }
}

/// Send the current board authority to one topic when it differs from the
/// topic's merged authority.
pub async fn sync_topic_authority(
    owner: VerifyingKey,
    topic_id: MessageId,
    part: u32,
) -> Result<bool, String> {
    let board = board_for(owner)?;
    let conversation = conversation_for(owner, topic_id, part)?;
    if conversation.state.header.is_none() {
        return Ok(false);
    }
    let mut member_ids = HashSet::new();
    if let Some(header) = &conversation.state.header {
        member_ids.insert(header.header.author);
    }
    for participant in &conversation.state.participants {
        member_ids.insert(participant.record.member_id);
    }
    for action in &conversation.state.actions {
        member_ids.insert(action.action.signer);
    }
    for approval in &conversation.state.approvals {
        member_ids.insert(approval.approval.signed_by);
    }
    for trust in &conversation.state.trust {
        member_ids.insert(trust.trust.signed_by);
    }
    let generated =
        authority_from_board(&board, board.is_current_owner(), &member_ids)?;
    let same_root = match (
        &conversation.state.authority.root,
        &generated.root,
    ) {
        (Some(current), Some(next)) => {
            current.root.content_hash == next.root.content_hash
                && current.root.digest == next.root.digest
        }
        (None, None) => true,
        _ => false,
    };
    let same_proofs =
        conversation.state.authority.member_proofs == generated.member_proofs;
    if same_root && same_proofs {
        return Ok(false);
    }
    publish_topic_delta(
        *conversation.key.id(),
        TopicDeltaV1 {
            authority: Some(generated),
            ..Default::default()
        },
    )
    .await?;
    Ok(true)
}

/// Push bans, suspensions, roles, admins, ownership and the policy to every
/// topic in the board index. Each topic gets the authority root and the proofs
/// for its own participants/moderators, so the payload does not grow with the
/// board. The pass is not capped at a fixed number of topics.
pub async fn propagate_authority(owner: VerifyingKey) -> Result<(), String> {
    let board = board_for(owner)?;
    if !board.board_state.mode.is_topic_index() {
        return Ok(());
    }
    if board.board_state.mode == BoardModeV1::SectionedTopicIndex {
        let sections: Vec<_> = board
            .board_state
            .sections
            .sections
            .iter()
            .filter_map(|entry| entry.section.contract.map(|_| entry.section.id))
            .collect();
        for section in sections {
            let _ = crate::components::app::section_contract::ensure_section_loaded(
                owner, section,
            )
            .await;
        }
    }
    let index = crate::components::app::section_contract::merged_index(
        owner,
        &board.board_state.topics,
    );
    let topics: Vec<(MessageId, u32)> = index
        .entries
        .iter()
        .map(|entry| (entry.entry.topic_id, index.part_of(&entry.entry.topic_id)))
        .collect();
    for (position, (topic_id, part)) in topics.into_iter().enumerate() {
        let key = topic_key_for(owner, topic_id, part);
        let loaded = TOPIC_CACHE
            .read()
            .get(key.id())
            .map(|conversation| conversation.state.header.is_some())
            .unwrap_or(false);
        if !loaded {
            let _ = load_topic(owner, topic_id, part).await;
            for _ in 0..30 {
                let ready = TOPIC_CACHE
                    .read()
                    .get(key.id())
                    .map(|conversation| conversation.state.header.is_some())
                    .unwrap_or(false);
                if ready {
                    break;
                }
                crate::util::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
        if let Err(error) = sync_topic_authority(owner, topic_id, part).await {
            dioxus::logger::tracing::warn!(
                "authority propagation failed for topic {}: {}",
                topic_id,
                error
            );
        }
        if position % 50 == 49 {
            crate::util::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
    Ok(())
}

/// Human-readable section name, decrypting the sealed name on private boards.
pub fn section_name(board: &BoardData, section: &MessageId) -> Option<String> {
    let value = board.board_state.sections.section(section)?;
    if let Some(sealed) = &value.sealed_name {
        read_text(board, sealed)
    } else {
        Some(value.name.clone())
    }
}

/// Create a topic contract owned by the current board owner and add its entry
/// to the board index.
pub async fn create_topic(
    owner: VerifyingKey,
    title: String,
    body: String,
    section: Option<MessageId>,
) -> Result<MessageId, String> {
    let board = board_for(owner)?;
    let sectioned = board.board_state.mode == BoardModeV1::SectionedTopicIndex;
    let target_section = if sectioned {
        Some(section.ok_or("choose a section for the topic")?)
    } else {
        section
    };
    if let Some(section_id) = target_section {
        if sectioned {
            crate::components::app::section_contract::ensure_section_loaded(
                owner, section_id,
            )
            .await?;
        }
    }
    let prepared = prepare_topic(owner, &title, &body, target_section).await?;
    let contract_id = *prepared.key.id();

    TOPIC_CACHE.with_mut(|topics| {
        topics.insert(
            contract_id,
            TopicConversation {
                key: prepared.key,
                params: prepared.params.clone(),
                state: prepared.state.clone(),
                synced: false,
                last_used: system_time_ms(get_current_system_time()),
            },
        );
    });
    evict_topics(contract_id);
    let contract = ContractContainer::from(ContractWasmAPIVersion::V1(WrappedContract::new(
        Arc::new(ContractCode::from(TOPIC_CONTRACT_WASM)),
        Parameters::from(to_cbor_vec(&prepared.params)),
    )));
    let request = ContractRequest::Put {
        contract,
        state: WrappedState::new(to_cbor_vec(&prepared.state)),
        related_contracts: Default::default(),
        subscribe: true,
        blocking_subscribe: false,
    };
    if let Err(error) = send_contract_request(request).await {
        TOPIC_CACHE.with_mut(|topics| {
            topics.remove(&contract_id);
        });
        return Err(error);
    }
    if let Err(error) = wait_topic_synced(contract_id).await {
        dioxus::logger::tracing::warn!(
            "topic PUT not confirmed id={} topic={}: {error}",
            contract_id,
            prepared.topic_id
        );
        TOPIC_CACHE.with_mut(|topics| {
            topics.remove(&contract_id);
        });
        return Err(format!(
            "topic {:?} was not accepted by the node: {error}",
            prepared.topic_id
        ));
    }
    if sectioned {
        if let Some(section_id) = target_section {
            if let Err(error) = crate::components::app::section_contract::apply_section_delta(
                owner,
                section_id,
                prepared.page,
                prepared.board_delta,
            )
            .await
            {
                dioxus::logger::tracing::warn!(
                    "topic {} was put but not indexed in its section: {}",
                    prepared.topic_id,
                    error
                );
            }
        }
    } else if let Err(error) = apply_board_delta(owner, prepared.board_delta) {
        // The topic exists; the index can be retried on the next board sync.
        dioxus::logger::tracing::warn!("topic {} was put but not indexed: {}", prepared.topic_id, error);
    } else if let Err(error) =
        crate::components::app::chat_delegate::save_boards_and_wait().await
    {
        // The index is in memory; the periodic save retries, but a reload
        // before it runs would hide the topic from search and the board list.
        dioxus::logger::tracing::warn!(
            "topic {} was indexed but the local board copy was not saved: {}",
            prepared.topic_id,
            error
        );
    }
    Ok(prepared.topic_id)
}

async fn ensure_part_for_new_post(
    owner: VerifyingKey,
    topic_id: MessageId,
    part: u32,
) -> Result<u32, String> {
    let conversation = conversation_for(owner, topic_id, part)?;
    let full = conversation.state.posts.len() >= plaza_topic_core::MAX_POSTS
        || encode(&conversation.state)
            .map(|bytes| bytes.len() >= plaza_topic_core::MAX_TOPIC_STATE_BYTES * 7 / 8)
            .unwrap_or(false);
    if full {
        continue_topic(owner, topic_id, part).await
    } else {
        Ok(part)
    }
}

/// Publish a reply in a topic and bump the board activity hint.
pub async fn send_reply(
    owner: VerifyingKey,
    topic_id: MessageId,
    part: u32,
    text: String,
) -> Result<(), String> {
    let part = ensure_part_for_new_post(owner, topic_id, part).await?;
    let prepared = prepare_reply(
        owner,
        topic_id,
        part,
        TopicPostContentV1::Text(text),
    )?;
    publish_prepared_reply(owner, prepared).await
}

/// Create a poll reply. Votes are separate signed actions.
pub async fn send_poll_reply(
    owner: VerifyingKey,
    topic_id: MessageId,
    part: u32,
    question: String,
    options: Vec<String>,
    multiselect: bool,
) -> Result<(), String> {
    let options: Vec<String> = options
        .into_iter()
        .map(|option| option.trim().to_string())
        .filter(|option| !option.is_empty())
        .collect();
    if question.trim().is_empty() {
        return Err("the poll needs a question".to_string());
    }
    if options.len() < 2 {
        return Err("a poll needs at least two options".to_string());
    }
    let poll = PollContentV1 {
        title: question.trim().to_string(),
        description: String::new(),
        options,
        closes_at: None,
        multiselect,
        results_visibility: PollResultsVisibility::Always,
        auto_moderated: false,
        category_id: None,
        topic_membership_key: None,
    };
    let part = ensure_part_for_new_post(owner, topic_id, part).await?;
    let prepared = prepare_reply(
        owner,
        topic_id,
        part,
        TopicPostContentV1::Poll(poll),
    )?;
    publish_prepared_reply(owner, prepared).await
}

async fn publish_prepared_reply(
    owner: VerifyingKey,
    prepared: PreparedReply,
) -> Result<(), String> {
    let contract_id = prepared.contract_id;
    publish_topic_delta(contract_id, prepared.topic_delta).await?;
    if let Some(activity) = prepared.activity {
        if let Err(error) = crate::components::app::activity_contract::record_activity(
            owner,
            prepared.topic_id,
            prepared.part,
            activity,
        )
        .await
        {
            dioxus::logger::tracing::warn!(
                "reply sent but activity not recorded: {}",
                error
            );
        }
    }
    Ok(())
}

/// Soft-delete a post (author or moderator authority checked by the contract).
pub async fn delete_post(
    owner: VerifyingKey,
    topic_id: MessageId,
    part: u32,
    target: MessageId,
) -> Result<(), String> {
    let board = board_for(owner)?;
    let conversation = conversation_for(owner, topic_id, part)?;
    let now = system_time_ms(get_current_system_time());
    let signer = MemberId::from(&board.self_sk.verifying_key());
    let action = plaza_topic_core::TopicActionV1 {
        kind: TopicActionKind::Delete,
        target,
        payload: SealedBytes::public(Vec::new()),
        generation: conversation
            .state
            .latest_action(target, TopicActionKind::Delete)
            .map(|entry| entry.action.generation + 1)
            .unwrap_or(1),
        created_at: now,
        signer,
    };
    let authorized = plaza_topic_core::AuthorizedTopicActionV1 {
        signature: plaza_core::util::sign_struct(&action, &board.self_sk),
        action,
        signer_key: Some(board.self_sk.verifying_key()),
        authority: None,
    };
    let delta = TopicDeltaV1 {
        actions: vec![authorized],
        ..Default::default()
    };
    publish_topic_delta(conversation.key.id().clone(), delta).await
}

/// Set one moderation flag on a topic. The owner signs both the topic action
/// and the board index flag; member moderators get their authority proof in a
/// later slice.
pub async fn set_flag(
    owner: VerifyingKey,
    topic_id: MessageId,
    part: u32,
    kind: TopicFlagKind,
    value: bool,
) -> Result<(), String> {
    let board = board_for(owner)?;
    if !board.is_current_owner() {
        return Err("only the board owner can change this flag for now".to_string());
    }
    let conversation = conversation_for(owner, topic_id, part)?;
    let header = conversation
        .state
        .header
        .as_ref()
        .ok_or("the topic is still loading")?;
    let target = header.header.id();
    let (kind_on, kind_off) = match kind {
        TopicFlagKind::Pinned => (TopicActionKind::Pin, TopicActionKind::Unpin),
        TopicFlagKind::Closed => (TopicActionKind::Close, TopicActionKind::Open),
        TopicFlagKind::Announced => {
            (TopicActionKind::Announce, TopicActionKind::Unannounce)
        }
        TopicFlagKind::Hidden => (TopicActionKind::Hide, TopicActionKind::Restore),
        TopicFlagKind::Approved => (TopicActionKind::Approve, TopicActionKind::Reject),
        TopicFlagKind::Merged => {
            return Err("use merge_topic for a merge".to_string());
        }
        TopicFlagKind::Section => {
            return Err("use move_topic for a section move".to_string());
        }
        TopicFlagKind::Part => {
            return Err("use continue_topic for a new part".to_string());
        }
    };
    let action_kind = if value { kind_on } else { kind_off };
    let now = system_time_ms(get_current_system_time());
    let owner_key = board.owner_key();
    let signer = MemberId::from(&owner_key.verifying_key());
    let generation = conversation
        .state
        .latest_action(target, action_kind)
        .map(|entry| entry.action.generation + 1)
        .unwrap_or(1);
    let action = plaza_topic_core::TopicActionV1 {
        kind: action_kind,
        target,
        payload: SealedBytes::public(Vec::new()),
        generation,
        created_at: now,
        signer,
    };
    let authorized = plaza_topic_core::AuthorizedTopicActionV1 {
        signature: plaza_core::util::sign_struct(&action, owner_key),
        action,
        signer_key: Some(owner_key.verifying_key()),
        authority: None,
    };
    let delta = TopicDeltaV1 {
        actions: vec![authorized],
        ..Default::default()
    };
    publish_topic_delta(*conversation.key.id(), delta).await?;

    let chain = conversation
        .state
        .section
        .as_ref()
        .map(|section| section.snapshot.chain.clone())
        .unwrap_or_default();
    let index = crate::components::app::section_contract::merged_index(
        owner,
        &board.board_state.topics,
    );
    let current_generation = index
        .flag(&topic_id, kind)
        .map(|flag| flag.generation)
        .unwrap_or(0);
    let flag = TopicFlagV1 {
        topic_id,
        kind,
        value,
        destination: None,
        section: None,
        section_chain: Vec::new(),
        destination_sections: Vec::new(),
        part: None,
        scope_chain: chain,
        generation: current_generation + 1,
        created_at: now,
    };
    let authorized_flag = AuthorizedTopicFlagV1 {
        signature: plaza_core::util::sign_struct(&flag, owner_key),
        flag,
        signer: Some(signer),
        signer_key: Some(owner_key.verifying_key()),
        authority: None,
    };
    let board_delta = ChatBoardStateV1Delta {
        topics: Some(TopicIndexDelta {
            flags: vec![authorized_flag],
            ..Default::default()
        }),
        ..Default::default()
    };
    apply_topic_board_delta(owner, topic_id, board_delta).await
}

struct PreparedTopic {
    params: TopicParamsV1,
    key: ContractKey,
    state: TopicStateV1,
    topic_id: MessageId,
    page: u32,
    board_delta: ChatBoardStateV1Delta,
}

async fn prepare_topic(
    owner: VerifyingKey,
    title: &str,
    body: &str,
    section: Option<MessageId>,
) -> Result<PreparedTopic, String> {
    let mut board = board_for(owner)?;
    if !board.board_state.mode.is_topic_index() {
        return Err("this board does not use topic contracts".to_string());
    }
    let mut page = 0;
    if board.board_state.mode == BoardModeV1::SectionedTopicIndex {
        let section_id = section.ok_or("choose a section for the topic")?;
        page = crate::components::app::section_contract::active_page(owner, section_id).await?;
        let child = crate::components::app::section_contract::section_page_state(
            owner,
            section_id,
            page,
        )
        .ok_or("the section page is still loading")?;
        board.board_state.topics = child.topics;
    }
    if title.trim().is_empty() {
        return Err("the topic needs a title".to_string());
    }

    let now = system_time_ms(get_current_system_time());
    let author = MemberId::from(&board.self_sk.verifying_key());
    let mut recent_topics: Vec<i64> = board
        .board_state
        .topics
        .entries
        .iter()
        .filter(|entry| entry.entry.author == author)
        .map(|entry| entry.entry.created_at)
        .collect();
    recent_topics.push(now);
    if exceeds_window(
        &recent_topics,
        TOPIC_RATE_WINDOW_MS,
        MAX_TOPICS_PER_WINDOW,
    ) {
        return Err(
            "too many topics created in the last hour; wait before creating another".to_string(),
        );
    }
    let is_owner = board.is_current_owner();
    let participant = participant_for(&board, author);
    if !is_owner && participant.is_none() {
        return Err("the active identity is not a member of this board".to_string());
    }
    let (section_snapshot, section_chain) = if let Some(section_id) = section {
        let section_data = board
            .board_state
            .sections
            .section(&section_id)
            .ok_or("the section does not exist")?;
        let chain = board.board_state.sections.chain(&section_id);
        if is_owner {
            let snapshot = SectionSnapshotV1 {
                section: section_id,
                parent: section_data.parent,
                chain: chain.clone(),
                allowed_roles: section_data.allowed_roles.clone(),
                sealed_name: section_data.sealed_name.clone(),
                hidden: section_data.hidden,
                images_allowed: section_data.images_allowed,
                auto_moderated_topics: section_data.auto_moderated_topics,
                generation: section_data.generation,
                signed_at: system_time_ms(section_data.signed_at),
            };
            (
                Some(AuthorizedSectionSnapshotV1::new(
                    snapshot,
                    board.owner_key(),
                    None,
                )),
                chain,
            )
        } else {
            // A member can start a topic in a section that is open to every
            // member. The index enforces the section roles; without an
            // owner-signed snapshot the topic contract cannot apply the
            // section-only policies, so those sections stay owner-only.
            if !section_data.allowed_roles.is_empty()
                || section_data.hidden
                || !section_data.images_allowed
                || section_data.auto_moderated_topics == Some(true)
            {
                return Err(
                    "only the board owner can create a topic in this section".to_string(),
                );
            }
            (None, chain)
        }
    } else {
        (None, Vec::new())
    };
    let topic_section = if section_snapshot.is_some() { section } else { None };
    let mut topic_id_bytes = [0u8; 32];
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut topic_id_bytes);
    OsRng.fill_bytes(&mut nonce);
    let topic_id = MessageId::from_bytes(topic_id_bytes);

    let sealed_title = seal_text(&board, title)?;
    let sealed_body = seal_text(&board, body)?;
    let header = TopicHeaderV1 {
        topic_id: topic_id_bytes,
        author,
        author_key: board.self_sk.verifying_key(),
        section: topic_section,
        section_chain: if topic_section.is_some() {
            section_chain.clone()
        } else {
            Vec::new()
        },
        title: sealed_title.clone(),
        body: sealed_body.clone(),
        auto_moderated: false,
        created_at: now,
        nonce,
    };
    let authorized_header = AuthorizedTopicHeaderV1::new(header.clone(), &board.self_sk);

    let mut authority_ids = HashSet::new();
    if !is_owner {
        authority_ids.insert(author);
    }
    let authority = authority_from_board(&board, is_owner, &authority_ids)?;

    let participants = participant
        .map(|participant| vec![participant])
        .unwrap_or_default();
    let state = TopicStateV1 {
        header: Some(authorized_header),
        section: section_snapshot,
        authority,
        participants,
        trust: Vec::new(),
        posts: Default::default(),
        actions: Vec::new(),
        approvals: Vec::new(),
        generation: plaza_topic_core::TopicGenerationV1::new(0),
        ..Default::default()
    };

    let params = TopicParamsV1::new(owner, topic_id_bytes, 0);
    state
        .verify(&params)
        .map_err(|error| format!("the new topic does not verify: {error}"))?;
    let key = topic_key_for(owner, topic_id, 0);

    let preview: String = body.chars().take(200).collect();
    let entry = TopicEntryV1 {
        topic_id,
        part: 0,
        protocol_version: plaza_core::board_state::topics::TOPIC_PROTOCOL_VERSION,
        author,
        section: section,
        section_chain: section_chain.clone(),
        title: sealed_title,
        preview: seal_text(&board, &preview)?,
        header_hash: header.hash(),
        created_at: now,
        generation: 1,
    };
    let authorized_entry = AuthorizedTopicEntryV1::new(entry, &board.self_sk);
    let board_delta = ChatBoardStateV1Delta {
        topics: Some(TopicIndexDelta {
            entries: vec![authorized_entry],
            ..Default::default()
        }),
        ..Default::default()
    };

    Ok(PreparedTopic {
        params,
        key,
        state,
        topic_id,
        page,
        board_delta,
    })
}

struct PreparedReply {
    contract_id: ContractInstanceId,
    topic_id: MessageId,
    part: u32,
    topic_delta: TopicDeltaV1,
    activity: Option<AuthorizedTopicActivityV1>,
}

fn prepare_reply(
    owner: VerifyingKey,
    topic_id: MessageId,
    part: u32,
    content: TopicPostContentV1,
) -> Result<PreparedReply, String> {
    let board = board_for(owner)?;
    let conversation = conversation_for(owner, topic_id, part)?;
    if conversation.state.header.is_none() {
        return Err("the topic is still loading".to_string());
    }
    match &content {
        TopicPostContentV1::Text(text) if text.trim().is_empty() => {
            return Err("the reply is empty".to_string());
        }
        TopicPostContentV1::Poll(poll)
            if poll.title.trim().is_empty() || poll.options.len() < 2 =>
        {
            return Err("the poll is incomplete".to_string());
        }
        _ => {}
    }
    let now = system_time_ms(get_current_system_time());
    let author = MemberId::from(&board.self_sk.verifying_key());
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    let post = plaza_topic_core::TopicPostV1 {
        author,
        parent: None,
        content: encode_content(&board, &content)?,
        images: Vec::new(),
        created_at: now,
        nonce,
    };
    let authorized = plaza_topic_core::AuthorizedTopicPostV1::new(post, &board.self_sk);
    let post_id = authorized.id();
    let mut participants = Vec::new();
    if !conversation
        .state
        .participants
        .iter()
        .any(|entry| entry.record.member_id == author)
    {
        if author == board.current_owner_id() {
            // The owner is implicit and never appears in the participant list.
        } else if let Some(participant) = participant_for(&board, author) {
            participants.push(participant);
        } else {
            return Err("the active identity is not a member of this board".to_string());
        }
    }
    let topic_delta = TopicDeltaV1 {
        posts: vec![authorized],
        participants,
        ..Default::default()
    };

    // Activity hint for the board list. If the board update fails the reply is
    // still valid; the next successful one refreshes the count.
    let contract_id = *conversation.key.id();
    let activity_index = board.clone().with_merged_topics().board_state.topics;
    let activity = activity_index.entry(&topic_id).map(|_| {
        let current = activity_index
            .activity_for(&topic_id)
            .map(|activity| activity.activity.clone());
        let value = TopicActivityV1 {
            topic_id,
            last_activity: now,
            last_post_id: Some(post_id),
            reply_count: current
                .as_ref()
                .map(|activity| activity.reply_count + 1)
                .unwrap_or(1),
            pending_approvals: {
                let current_pending = current
                    .as_ref()
                    .map(|activity| activity.pending_approvals)
                    .unwrap_or(0);
                let policy = conversation.state.authority.policy();
                if policy.approval_required
                    && !conversation.state.is_trusted(author)
                {
                    current_pending + 1
                } else {
                    current_pending
                }
            },
            generation: current
                .as_ref()
                .map(|activity| activity.generation + 1)
                .unwrap_or(1),
        };
        AuthorizedTopicActivityV1 {
            signature: plaza_core::util::sign_struct(&value, &board.self_sk),
            activity: value,
            signer: Some(author),
            signer_key: Some(board.self_sk.verifying_key()),
        }
    });

    Ok(PreparedReply {
        contract_id,
        topic_id,
        part,
        topic_delta,
        activity,
    })
}

fn participant_for(
    board: &BoardData,
    member_id: MemberId,
) -> Option<AuthorizedParticipantV1> {
    let shard_entry =
        crate::components::app::member_contract::find_member_entry(board.owner_vk, member_id);
    let self_entry = board
        .self_authorized_member
        .as_ref()
        .filter(|member| member.member.id() == member_id);
    let member = board
        .board_state
        .members
        .members
        .iter()
        .find(|member| member.member.id() == member_id)
        .cloned()
        .or_else(|| shard_entry.as_ref().map(|entry| entry.member.clone()))
        .or_else(|| self_entry.cloned())?;
    let owner_id = MemberId::from(&board.owner_vk);
    let current_owner = board.current_owner_id();
    let mut chain: Vec<AuthorizedMember> = if let Some(entry) = &shard_entry {
        entry.invite_chain.clone()
    } else if self_entry.is_some() && !board.invite_chain.is_empty() {
        board.invite_chain.clone()
    } else {
        Vec::new()
    };
    if chain.is_empty() {
        let mut current = member.clone();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let inviter = current.member.invited_by;
            if inviter == owner_id || inviter == current_owner {
                break;
            }
            // A token join is self-signed and carries its proof, not a member
            // ancestor chain.
            if current.member.join_proof.is_some() || inviter == current.member.id() {
                break;
            }
            if !seen.insert(inviter) {
                return None;
            }
            let parent = board
                .board_state
                .members
                .members
                .iter()
                .find(|candidate| candidate.member.id() == inviter)
                .cloned()
                .or_else(|| {
                    crate::components::app::member_contract::find_member_entry(
                        board.owner_vk,
                        inviter,
                    )
                    .map(|entry| entry.member)
                })?;
            chain.push(parent.clone());
            current = parent;
        }
    }
    let join_proof = member.member.join_proof.clone();
    let token = join_proof.as_ref().and_then(|proof| {
        board
            .board_state
            .invites
            .tokens
            .iter()
            .find(|token| token.token.id == proof.token_id)
            .cloned()
    });
    let record = ParticipantRecordV1 {
        member_id,
        member_vk: member.member.member_vk,
        certificate: ParticipantCertificateV1 {
            member,
            chain,
            token,
            join_proof,
        },
        joined_at: system_time_ms(get_current_system_time()),
    };
    Some(AuthorizedParticipantV1::new(record, &board.self_sk))
}

fn seal_text(board: &BoardData, text: &str) -> Result<SealedBytes, String> {
    if board.is_private() {
        let (secret, version) = board
            .get_secret()
            .ok_or("the board secret is not available")?;
        let (ciphertext, nonce) =
            encrypt_with_symmetric_key(secret, text.as_bytes(), version);
        Ok(SealedBytes::private(
            ciphertext,
            nonce,
            version,
            text.len() as u32,
        ))
    } else {
        Ok(SealedBytes::public(text.as_bytes().to_vec()))
    }
}

pub fn read_text(board: &BoardData, sealed: &SealedBytes) -> Option<String> {
    match sealed {
        SealedBytes::Public { value } => String::from_utf8(value.clone()).ok(),
        SealedBytes::Private {
            ciphertext,
            nonce,
            secret_version,
            ..
        } => {
            let secret = board.get_secret_for_version(*secret_version)?;
            decrypt_with_symmetric_key(secret, ciphertext, nonce, *secret_version)
                .ok()
                .and_then(|value| String::from_utf8(value).ok())
        }
    }
}

fn board_for(owner: VerifyingKey) -> Result<BoardData, String> {
    BOARDS
        .read()
        .map
        .get(&owner)
        .cloned()
        .ok_or_else(|| "the board is not loaded".to_string())
}

fn conversation_for(
    owner: VerifyingKey,
    topic_id: MessageId,
    part: u32,
) -> Result<TopicConversation, String> {
    let key = topic_key_for(owner, topic_id, part);
    TOPIC_CACHE
        .read()
        .get(key.id())
        .cloned()
        .ok_or_else(|| "the topic is not loaded".to_string())
}

fn section_for_topic(owner: VerifyingKey, topic_id: MessageId) -> Option<(MessageId, u32)> {
    let board = board_for(owner).ok()?;
    if let Some(entry) = board.board_state.topics.entry(&topic_id) {
        return entry.entry.section.map(|section| (section, 0));
    }
    if let Some(board) = crate::components::app::section_contract::SECTION_BOARDS
        .read()
        .values()
        .find(|board| {
            board.params.owner == owner
                && board.state.topics.entry(&topic_id).is_some()
        })
    {
        return Some((board.params.section, board.params.page));
    }
    TOPIC_CACHE
        .read()
        .values()
        .find(|conversation| {
            conversation
                .state
                .header
                .as_ref()
                .is_some_and(|header| header.header.id() == topic_id)
        })
        .and_then(|conversation| {
            conversation
                .state
                .section
                .as_ref()
                .map(|section| (section.snapshot.section, 0))
        })
}

/// Extra index pages load on demand, so the page that holds a topic may not
/// be in memory yet. The topic state knows its section; load that section's
/// pages and retry.
async fn locate_section_page(
    owner: VerifyingKey,
    topic_id: MessageId,
) -> Result<(MessageId, u32), String> {
    if let Some(found) = section_for_topic(owner, topic_id) {
        return Ok(found);
    }
    let section = TOPIC_CACHE
        .read()
        .values()
        .find(|conversation| {
            conversation
                .state
                .header
                .as_ref()
                .is_some_and(|header| header.header.id() == topic_id)
        })
        .and_then(|conversation| {
            conversation
                .state
                .section
                .as_ref()
                .map(|section| section.snapshot.section)
        });
    if let Some(section) = section {
        let _ = crate::components::app::section_contract::load_all_section_pages(owner, section)
            .await;
    }
    section_for_topic(owner, topic_id)
        .ok_or_else(|| "the topic section is not loaded".to_string())
}

async fn apply_topic_board_delta(
    owner: VerifyingKey,
    topic_id: MessageId,
    delta: ChatBoardStateV1Delta,
) -> Result<(), String> {
    let board = board_for(owner)?;
    if board.board_state.mode != BoardModeV1::SectionedTopicIndex {
        return apply_board_delta(owner, delta);
    }
    let (section, page) = locate_section_page(owner, topic_id).await?;
    crate::components::app::section_contract::apply_section_delta(owner, section, page, delta)
        .await
}

fn apply_board_delta(owner: VerifyingKey, delta: ChatBoardStateV1Delta) -> Result<(), String> {
    let activity_only = delta.is_activity_only();
    let mut apply_error = None;
    BOARDS.with_mut(|boards| {
        let Some(board) = boards.map.get_mut(&owner) else {
            apply_error = Some("the board is not loaded".to_string());
            return;
        };
        let parent = board.board_state.clone();
        if let Err(error) = board.board_state.apply_delta(
            &parent,
            &ChatBoardParametersV1 { owner },
            &Some(delta),
        ) {
            apply_error = Some(error);
        }
    });
    if let Some(error) = apply_error {
        return Err(error);
    }
    if activity_only {
        mark_needs_sync_later(owner, std::time::Duration::from_secs(10));
    } else {
        mark_needs_sync(owner);
    }
    Ok(())
}

async fn publish_topic_delta(
    contract_id: ContractInstanceId,
    delta: TopicDeltaV1,
) -> Result<(), String> {
    let (key, params, next_state, bytes) = {
        let topics = TOPIC_CACHE.read();
        let conversation = topics
            .get(&contract_id)
            .ok_or_else(|| "the topic is not loaded".to_string())?;
        let mut next_state = conversation.state.clone();
        next_state
            .apply_delta(&conversation.params, &delta)
            .map_err(|error| format!("apply topic delta: {error}"))?;
        let bytes = encode(&delta).map_err(|error| format!("encode topic delta: {error}"))?;
        (
            conversation.key,
            conversation.params.clone(),
            next_state,
            bytes,
        )
    };
    let _ = params;

    TOPIC_CACHE.with_mut(|topics| {
        if let Some(conversation) = topics.get_mut(&contract_id) {
            conversation.state = next_state;
            conversation.synced = false;
            conversation.last_used = system_time_ms(get_current_system_time());
        }
    });

    let retry_key = key;
    let retry_bytes = bytes.clone();
    match send_contract_request(ContractRequest::Update {
        key,
        data: UpdateData::Delta(bytes.into()),
    })
    .await
    {
        Ok(()) => Ok(()),
        Err(error) => {
            PENDING_TOPIC_DELTAS
                .lock()
                .unwrap()
                .push(PendingTopicDelta {
                    key: retry_key,
                    bytes: retry_bytes,
                    attempts: 0,
                });
            dioxus::logger::tracing::warn!(
                "topic delta could not be sent; queued for retry: {error}"
            );
            // The delta is already applied locally; the outbox will retry it.
            Ok(())
        }
    }
}

struct PendingTopicDelta {
    key: ContractKey,
    bytes: Vec<u8>,
    attempts: u8,
}

static PENDING_TOPIC_DELTAS: Mutex<Vec<PendingTopicDelta>> = Mutex::new(Vec::new());
static RETRY_RUNNING: AtomicBool = AtomicBool::new(false);

/// Retry topic deltas that could not be sent. Applying the same delta again is
/// idempotent: posts, actions and approvals are keyed by id or generation.
pub async fn retry_pending_topic_deltas() {
    if RETRY_RUNNING.swap(true, Ordering::SeqCst) {
        return;
    }
    let pending = {
        let mut queue = PENDING_TOPIC_DELTAS.lock().unwrap();
        std::mem::take(&mut *queue)
    };
    let mut keep = Vec::new();
    for mut item in pending {
        let result = send_contract_request(ContractRequest::Update {
            key: item.key,
            data: UpdateData::Delta(item.bytes.clone().into()),
        })
        .await;
        match result {
            Ok(()) => {
                dioxus::logger::tracing::info!("retried a queued topic delta");
            }
            Err(error) => {
                item.attempts += 1;
                if item.attempts < 5 {
                    keep.push(item);
                } else {
                    dioxus::logger::tracing::warn!(
                        "dropping a topic delta after 5 failed attempts: {error}"
                    );
                }
            }
        }
    }
    PENDING_TOPIC_DELTAS.lock().unwrap().extend(keep);
    RETRY_RUNNING.store(false, Ordering::SeqCst);
}

/// Start the periodic retry loop once per page.
pub fn start_topic_outbox() {
    static STARTED: AtomicBool = AtomicBool::new(false);
    if STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    crate::util::safe_spawn_local(async move {
        loop {
            crate::util::sleep(std::time::Duration::from_secs(20)).await;
            retry_pending_topic_deltas().await;
        }
    });
}

/// A new topic is confirmed either by a `PutResponse` or by the state a
/// `subscribe: true` PUT starts streaming back (`GetResponse`); the node does
/// not always send both.
async fn wait_topic_synced(contract_id: ContractInstanceId) -> Result<(), String> {
    for _ in 0..150 {
        if TOPIC_CACHE
            .read()
            .get(&contract_id)
            .map(|conversation| conversation.synced)
            .unwrap_or(false)
        {
            return Ok(());
        }
        crate::util::sleep(std::time::Duration::from_millis(200)).await;
    }
    Err("the node did not confirm the topic contract".to_string())
}

fn mark_synced(key: &ContractKey) {
    TOPIC_CACHE.with_mut(|topics| {
        if let Some(conversation) = topics.get_mut(key.id()) {
            conversation.synced = true;
        }
    });
}

/// Route a contract response that belongs to a topic contract.
pub async fn handle_contract_response(response: ContractResponse) -> Result<(), String> {
    match response {
        ContractResponse::GetResponse { key, state, .. } => {
            if !is_known_topic(key.id()) {
                return Ok(());
            }
            let state = decode_state(state.as_ref())
                .map_err(|error| format!("decode topic state: {error}"))?;
            TOPIC_CACHE.with_mut(|topics| {
                if let Some(conversation) = topics.get_mut(key.id()) {
                    conversation.state = state;
                    conversation.synced = true;
                    conversation.last_used = system_time_ms(get_current_system_time());
                }
            });
        }
        ContractResponse::PutResponse { key } => {
            mark_synced(&key);
        }
        ContractResponse::UpdateResponse { key, .. } => {
            mark_synced(&key);
        }
        ContractResponse::UpdateNotification { key, .. } => {
            if is_known_topic(key.id()) {
                fetch_topic(*key.id()).await?;
            }
        }
        ContractResponse::SubscribeResponse { key, subscribed } => {
            if subscribed && is_known_topic(key.id()) {
                fetch_topic(*key.id()).await?;
            }
        }
        _ => {}
    }
    Ok(())
}



fn encode_content(
    board: &BoardData,
    content: &TopicPostContentV1,
) -> Result<SealedBytes, String> {
    let bytes = encode(content)?;
    seal_action_payload(board, &bytes)
}

fn decode_content(board: &BoardData, sealed: &SealedBytes) -> Option<TopicPostContentV1> {
    let bytes = open_action_payload(board, sealed)?;
    ciborium::de::from_reader::<TopicPostContentV1, _>(bytes.as_slice()).ok()
}

/// Decode typed post content, falling back to a plain-text reply written before
/// the typed envelope existed.
pub fn read_post_content(
    board: &BoardData,
    sealed: &SealedBytes,
) -> Option<TopicPostContentV1> {
    if let Some(content) = decode_content(board, sealed) {
        return Some(content);
    }
    read_text(board, sealed).map(TopicPostContentV1::Text)
}

/// Latest reaction per member and emoji for one post or the topic header.
pub fn reactions_for(
    board: &BoardData,
    state: &TopicStateV1,
    target: MessageId,
) -> BTreeMap<String, Vec<MemberId>> {
    let mut latest: BTreeMap<(MemberId, String), (u64, bool)> = BTreeMap::new();
    for entry in state.actions.iter().filter(|entry| {
        entry.action.target == target
            && matches!(
                entry.action.kind,
                TopicActionKind::React | TopicActionKind::Unreact
            )
    }) {
        let Some(bytes) = open_action_payload(board, &entry.action.payload) else {
            continue;
        };
        let Ok(emoji) = String::from_utf8(bytes) else {
            continue;
        };
        let key = (entry.action.signer, emoji);
        let value = (entry.action.generation, entry.action.kind == TopicActionKind::React);
        match latest.get(&key) {
            Some((generation, _)) if *generation >= value.0 => {}
            _ => {
                latest.insert(key, value);
            }
        }
    }
    let mut out: BTreeMap<String, Vec<MemberId>> = BTreeMap::new();
    for ((member, emoji), (_, active)) in latest {
        if active {
            out.entry(emoji).or_default().push(member);
        }
    }
    for members in out.values_mut() {
        members.sort();
    }
    out
}

pub async fn toggle_reaction(
    owner: VerifyingKey,
    topic_id: MessageId,
    part: u32,
    target: MessageId,
    emoji: String,
    add: bool,
) -> Result<(), String> {
    let board = board_for(owner)?;
    let conversation = conversation_for(owner, topic_id, part)?;
    if emoji.is_empty() || emoji.len() > 32 {
        return Err("the reaction is not valid".to_string());
    }
    let signer = MemberId::from(&board.self_sk.verifying_key());
    let now = system_time_ms(get_current_system_time());
    let generation = conversation
        .state
        .actions
        .iter()
        .filter(|entry| {
            entry.action.target == target
                && entry.action.signer == signer
                && matches!(
                    entry.action.kind,
                    TopicActionKind::React | TopicActionKind::Unreact
                )
        })
        .map(|entry| entry.action.generation + 1)
        .max()
        .unwrap_or(1);
    let action = plaza_topic_core::TopicActionV1 {
        kind: if add {
            TopicActionKind::React
        } else {
            TopicActionKind::Unreact
        },
        target,
        payload: seal_action_payload(&board, emoji.as_bytes())?,
        generation,
        created_at: now,
        signer,
    };
    let authorized = plaza_topic_core::AuthorizedTopicActionV1 {
        signature: plaza_core::util::sign_struct(&action, &board.self_sk),
        action,
        signer_key: Some(board.self_sk.verifying_key()),
        authority: None,
    };
    publish_topic_delta(
        *conversation.key.id(),
        TopicDeltaV1 {
            actions: vec![authorized],
            ..Default::default()
        },
    )
    .await
}

/// Counts per option, using the latest vote per member.
pub fn poll_votes(
    board: &BoardData,
    state: &TopicStateV1,
    poll_id: MessageId,
) -> Vec<Vec<MemberId>> {
    let Some(post) = state.posts.get(&poll_id) else {
        return Vec::new();
    };
    let Some(TopicPostContentV1::Poll(poll)) =
        read_post_content(board, &post.post.content)
    else {
        return Vec::new();
    };
    let mut latest: BTreeMap<MemberId, (u64, PollVoteV1)> = BTreeMap::new();
    for entry in state.actions.iter().filter(|entry| {
        entry.action.target == poll_id && entry.action.kind == TopicActionKind::Vote
    }) {
        let Some(bytes) = open_action_payload(board, &entry.action.payload) else {
            continue;
        };
        let Ok(vote) = ciborium::de::from_reader::<PollVoteV1, _>(bytes.as_slice()) else {
            continue;
        };
        if vote.poll != poll_id || vote.validate_for(&poll).is_err() {
            continue;
        }
        let signer = entry.action.signer;
        let generation = entry.action.generation;
        match latest.get(&signer) {
            Some((known, _)) if *known >= generation => {}
            _ => {
                latest.insert(signer, (generation, vote));
            }
        }
    }
    let mut counts = vec![Vec::new(); poll.options.len()];
    for (member, (_, vote)) in latest {
        for index in vote.options {
            if let Some(slot) = counts.get_mut(index as usize) {
                slot.push(member);
            }
        }
    }
    for slot in counts.iter_mut() {
        slot.sort();
    }
    counts
}

pub async fn vote(
    owner: VerifyingKey,
    topic_id: MessageId,
    part: u32,
    poll_id: MessageId,
    options: Vec<u16>,
) -> Result<(), String> {
    let board = board_for(owner)?;
    let conversation = conversation_for(owner, topic_id, part)?;
    let post = conversation
        .state
        .posts
        .get(&poll_id)
        .ok_or("the poll is not in this topic")?;
    let Some(TopicPostContentV1::Poll(poll)) =
        read_post_content(&board, &post.post.content)
    else {
        return Err("the target is not a poll".to_string());
    };
    let now = system_time_ms(get_current_system_time());
    if poll.closes_at.is_some_and(|closes| closes <= now) {
        return Err("the poll is closed".to_string());
    }
    let signer = MemberId::from(&board.self_sk.verifying_key());
    let generation = conversation
        .state
        .actions
        .iter()
        .filter(|entry| {
            entry.action.target == poll_id
                && entry.action.kind == TopicActionKind::Vote
                && entry.action.signer == signer
        })
        .map(|entry| entry.action.generation + 1)
        .max()
        .unwrap_or(1);
    let vote = PollVoteV1 {
        poll: poll_id,
        options,
        generation,
        created_at: now,
    };
    vote.validate_for(&poll)?;
    let payload = seal_action_payload(&board, &encode(&vote)?)?;
    let action = plaza_topic_core::TopicActionV1 {
        kind: TopicActionKind::Vote,
        target: poll_id,
        payload,
        generation,
        created_at: now,
        signer,
    };
    let authorized = plaza_topic_core::AuthorizedTopicActionV1 {
        signature: plaza_core::util::sign_struct(&action, &board.self_sk),
        action,
        signer_key: Some(board.self_sk.verifying_key()),
        authority: None,
    };
    publish_topic_delta(
        *conversation.key.id(),
        TopicDeltaV1 {
            actions: vec![authorized],
            ..Default::default()
        },
    )
    .await
}

fn open_action_payload(board: &BoardData, payload: &SealedBytes) -> Option<Vec<u8>> {
    match payload {
        SealedBytes::Public { value } => Some(value.clone()),
        SealedBytes::Private {
            ciphertext,
            nonce,
            secret_version,
            ..
        } => {
            let secret = board.get_secret_for_version(*secret_version)?;
            decrypt_with_symmetric_key(secret, ciphertext, nonce, *secret_version).ok()
        }
    }
}

fn seal_action_payload(board: &BoardData, bytes: &[u8]) -> Result<SealedBytes, String> {
    if board.is_private() {
        let (secret, version) = board
            .get_secret()
            .ok_or("the board secret is not available")?;
        let (ciphertext, nonce) = encrypt_with_symmetric_key(secret, bytes, version);
        Ok(SealedBytes::private(
            ciphertext,
            nonce,
            version,
            bytes.len() as u32,
        ))
    } else {
        Ok(SealedBytes::public(bytes.to_vec()))
    }
}

pub fn effective_topic_content(
    board: &BoardData,
    state: &TopicStateV1,
) -> Option<(SealedBytes, SealedBytes)> {
    let header = state.header.as_ref()?;
    let target = header.header.id();
    let fallback = (header.header.title.clone(), header.header.body.clone());
    let Some(action) = state.latest_action(target, TopicActionKind::Edit) else {
        return Some(fallback);
    };
    let Some(bytes) = open_action_payload(board, &action.action.payload) else {
        return Some(fallback);
    };
    let Ok(edit) = ciborium::de::from_reader::<TopicEditV1, _>(bytes.as_slice()) else {
        return Some(fallback);
    };
    Some((edit.title, edit.body))
}

pub fn effective_post_content(
    board: &BoardData,
    state: &TopicStateV1,
    post_id: MessageId,
) -> Option<SealedBytes> {
    let post = state.posts.get(&post_id)?;
    let Some(action) = state.latest_action(post_id, TopicActionKind::Edit) else {
        return Some(post.post.content.clone());
    };
    let Some(bytes) = open_action_payload(board, &action.action.payload) else {
        return Some(post.post.content.clone());
    };
    match ciborium::de::from_reader::<PostEditV1, _>(bytes.as_slice()) {
        Ok(edit) => Some(edit.content),
        Err(_) => Some(post.post.content.clone()),
    }
}

/// Edit the topic title and body. Only the topic author updates the board
/// index entry; a moderator edit changes the topic contract but leaves the
/// author-signed list metadata alone.
pub async fn edit_topic(
    owner: VerifyingKey,
    topic_id: MessageId,
    part: u32,
    title: String,
    body: String,
) -> Result<(), String> {
    let board = board_for(owner)?;
    let conversation = conversation_for(owner, topic_id, part)?;
    let header = conversation
        .state
        .header
        .as_ref()
        .ok_or("the topic is still loading")?;
    let self_id = MemberId::from(&board.self_sk.verifying_key());
    if header.header.author != self_id {
        return Err("only the topic author can edit its title here".to_string());
    }
    if title.trim().is_empty() {
        return Err("the topic needs a title".to_string());
    }
    let now = system_time_ms(get_current_system_time());
    let edit = TopicEditV1 {
        title: seal_text(&board, &title)?,
        body: seal_text(&board, &body)?,
    };
    let payload = seal_action_payload(&board, &encode(&edit)?)?;
    let generation = conversation
        .state
        .latest_action(header.header.id(), TopicActionKind::Edit)
        .map(|entry| entry.action.generation + 1)
        .unwrap_or(1);
    let action = plaza_topic_core::TopicActionV1 {
        kind: TopicActionKind::Edit,
        target: header.header.id(),
        payload,
        generation,
        created_at: now,
        signer: self_id,
    };
    let authorized = plaza_topic_core::AuthorizedTopicActionV1 {
        signature: plaza_core::util::sign_struct(&action, &board.self_sk),
        action,
        signer_key: Some(board.self_sk.verifying_key()),
        authority: None,
    };
    publish_topic_delta(
        *conversation.key.id(),
        TopicDeltaV1 {
            actions: vec![authorized],
            ..Default::default()
        },
    )
    .await?;

    let index = crate::components::app::section_contract::merged_index(
        owner,
        &board.board_state.topics,
    );
    if let Some(entry) = index.entry(&topic_id) {
        let mut next = entry.entry.clone();
        next.title = seal_text(&board, &title)?;
        let preview: String = body.chars().take(200).collect();
        next.preview = seal_text(&board, &preview)?;
        next.generation += 1;
        let authorized_entry = AuthorizedTopicEntryV1::new(next, &board.self_sk);
        let board_delta = ChatBoardStateV1Delta {
            topics: Some(TopicIndexDelta {
                entries: vec![authorized_entry],
                ..Default::default()
            }),
            ..Default::default()
        };
        apply_topic_board_delta(owner, topic_id, board_delta).await?;
    }
    Ok(())
}

/// Edit one reply. The author or the board owner may edit it.
pub async fn edit_post(
    owner: VerifyingKey,
    topic_id: MessageId,
    part: u32,
    post_id: MessageId,
    text: String,
) -> Result<(), String> {
    let board = board_for(owner)?;
    let conversation = conversation_for(owner, topic_id, part)?;
    let post = conversation
        .state
        .posts
        .get(&post_id)
        .ok_or("the reply is not in this topic")?;
    let self_id = MemberId::from(&board.self_sk.verifying_key());
    let signer_sk = if post.post.author == self_id {
        board.self_sk.clone()
    } else if board.is_current_owner() {
        board.owner_key().clone()
    } else {
        return Err("only the author or the owner can edit this reply".to_string());
    };
    let signer = MemberId::from(&signer_sk.verifying_key());
    let now = system_time_ms(get_current_system_time());
    let edit = PostEditV1 {
        content: seal_text(&board, &text)?,
    };
    let payload = seal_action_payload(&board, &encode(&edit)?)?;
    let generation = conversation
        .state
        .latest_action(post_id, TopicActionKind::Edit)
        .map(|entry| entry.action.generation + 1)
        .unwrap_or(1);
    let action = plaza_topic_core::TopicActionV1 {
        kind: TopicActionKind::Edit,
        target: post_id,
        payload,
        generation,
        created_at: now,
        signer,
    };
    let authorized = plaza_topic_core::AuthorizedTopicActionV1 {
        signature: plaza_core::util::sign_struct(&action, &signer_sk),
        action,
        signer_key: Some(signer_sk.verifying_key()),
        authority: None,
    };
    publish_topic_delta(
        *conversation.key.id(),
        TopicDeltaV1 {
            actions: vec![authorized],
            ..Default::default()
        },
    )
    .await
}



fn delete_authority(
    board: &BoardData,
    signer: &MemberId,
) -> Option<AuthorityProof> {
    let state = &board.board_state;
    let admin = state
        .admin
        .admins
        .iter()
        .find(|entry| entry.admin.id() == *signer)
        .cloned();
    let assignment = state.roles.assignments.iter().find(|entry| {
        entry.assignment.member_id == *signer && !entry.assignment.revoked
    });
    if let Some(assignment) = assignment {
        if let Some(role) = state.roles.roles.iter().find(|entry| {
            entry.role.id == assignment.assignment.role_id
                && !entry.role.deleted
                && entry.role.can_delete_posts
        }) {
            return Some(AuthorityProof {
                admin,
                grant: Some(Box::new(RoleGrantProof {
                    role: role.clone(),
                    assignment: assignment.clone(),
                })),
            });
        }
    }
    admin.map(|admin| AuthorityProof {
        admin: Some(admin),
        grant: None,
    })
}

/// Approve or reject one pending reply. The owner signs the approval and, when
/// approving, also trusts the author so later replies are visible immediately.
pub async fn approve_post(
    owner: VerifyingKey,
    topic_id: MessageId,
    part: u32,
    post_id: MessageId,
    approved: bool,
) -> Result<(), String> {
    let board = board_for(owner)?;
    let conversation = conversation_for(owner, topic_id, part)?;
    let header = conversation
        .state
        .header
        .as_ref()
        .ok_or("the topic is still loading")?;
    let chain = conversation
        .state
        .effective_section()
        .map(|section| section.chain)
        .unwrap_or_default();
    let self_id = MemberId::from(&board.self_sk.verifying_key());
    let owner_id = board.current_owner_id();
    let (signer_sk, signer, authority) = if self_id != owner_id
        && board.can_moderate(&chain)
    {
        (
            board.self_sk.clone(),
            self_id,
            delete_authority(&board, &self_id),
        )
    } else if board.is_current_owner() {
        (board.owner_key().clone(), owner_id, None)
    } else {
        return Err("only a moderator can approve replies".to_string());
    };
    let post = conversation
        .state
        .posts
        .get(&post_id)
        .ok_or("the reply is not in this topic")?;
    let now = system_time_ms(get_current_system_time());
    let generation = conversation
        .state
        .approvals
        .iter()
        .filter(|entry| entry.approval.target == post_id)
        .map(|entry| entry.approval.generation + 1)
        .max()
        .unwrap_or(1);
    let approval = TopicApprovalV1 {
        target: post_id,
        approved,
        generation,
        scope: header.header.section,
        signed_by: signer,
        created_at: now,
    };
    let authorized = AuthorizedTopicApprovalV1 {
        signature: plaza_core::util::sign_struct(&approval, &signer_sk),
        approval,
        signer_key: Some(signer_sk.verifying_key()),
        authority: authority.clone().map(Box::new),
    };
    let mut delta = TopicDeltaV1 {
        approvals: vec![authorized],
        ..Default::default()
    };
    if approved {
        let author = post.post.author;
        let trust_generation = conversation
            .state
            .trust
            .iter()
            .filter(|entry| entry.trust.member_id == author)
            .map(|entry| entry.trust.generation + 1)
            .max()
            .unwrap_or(1);
        let trust = TrustV1 {
            member_id: author,
            trusted: true,
            generation: trust_generation,
            signed_by: signer,
            created_at: now,
        };
        delta.trust.push(AuthorizedTrustV1 {
            signature: plaza_core::util::sign_struct(&trust, &signer_sk),
            trust,
            signer_key: Some(signer_sk.verifying_key()),
            authority: authority.clone().map(Box::new),
        });
    }
    publish_topic_delta(*conversation.key.id(), delta).await?;

    let index = board.clone().with_merged_topics().board_state.topics;
    if let Some(current) = index
        .activity_for(&topic_id)
        .map(|entry| entry.activity.clone())
    {
        let activity = TopicActivityV1 {
            topic_id,
            last_activity: current.last_activity,
            last_post_id: current.last_post_id,
            reply_count: current.reply_count,
            pending_approvals: current.pending_approvals.saturating_sub(1),
            generation: current.generation + 1,
        };
        let authorized_activity = AuthorizedTopicActivityV1 {
            signature: plaza_core::util::sign_struct(&activity, &signer_sk),
            activity,
            signer: Some(signer),
            signer_key: Some(signer_sk.verifying_key()),
        };
        if let Err(error) = crate::components::app::activity_contract::record_activity(
            owner,
            topic_id,
            part,
            authorized_activity,
        )
        .await
        {
            dioxus::logger::tracing::warn!(
                "approval sent but the pending count was not updated: {}",
                error
            );
        }
    }
    Ok(())
}


async fn send_contract_request(request: ContractRequest<'static>) -> Result<(), String> {
    let client_request = ClientRequest::ContractOp(request);
    crate::components::app::send_client_request(client_request)
        .await
        .map_err(|error| format!("send topic contract request: {error}"))
}
