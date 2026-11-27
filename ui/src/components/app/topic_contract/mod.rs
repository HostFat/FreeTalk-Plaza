//! Client for the `plaza-topic` contract.
//!
//! Creates a topic contract, loads it on demand, publishes replies as deltas
//! and keeps the board index in sync. The UI for index boards sits on top of
//! this module.


mod actions;
mod moderation;

use actions::{delete_authority, encode_content};
pub use actions::{
    approve_post, edit_poll, edit_post, edit_topic, effective_post_content, effective_topic_content, is_post_edited, is_topic_edited, poll_votes, reactions_for, read_post_content, toggle_reaction, vote,
};
use moderation::{authority_from_board};
pub use moderation::{
    authority_hash, create_section, mark_authority_seen, merge_topic, move_topic,
    propagate_authority, report_body, report_post, resolve_report, section_name, split_reply,
    sync_topic_authority, topic_reports, PROPAGATED_AUTHORITY,
};
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
    decode_page_state, decode_state, encode, AuthorizedParticipantV1, AuthorizedSectionSnapshotV1,
    AuthorizedTopicApprovalV1, AuthorizedTopicHeaderV1, AuthorizedTopicPageHeaderV1,
    AuthorizedTopicPageSealV1, AuthorizedTopicPolicyV1, AuthorizedTopicPostV1, AuthorizedTrustV1,
    ParticipantCertificateV1, ParticipantRecordV1, PostEditV1, SectionSnapshotV1,
    TopicActionKind, TopicApprovalV1, TopicAuthorityV1, TopicDeltaV1, TopicEditV1,
    TopicHeaderV1, TopicPageDeltaV1, TopicPageHeaderV1, TopicPageStateV1, TopicParamsV1,
    TopicPolicyV1, TopicPostContentV1, TopicStateV1, TrustV1, DEFAULT_TOPIC_PAGE_SIZE,
    MAX_TOPIC_PAGE_BYTES,
};
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

/// Cached state of one topic contract (`part == 0` head or `part > 0` compact
/// append-only post page).
#[derive(Clone, Debug)]
pub enum TopicPartState {
    Head(TopicStateV1),
    Page(TopicPageStateV1),
}

impl TopicPartState {
    pub fn empty_for_part(part: u32) -> Self {
        if part == 0 {
            Self::Head(TopicStateV1::default())
        } else {
            Self::Page(TopicPageStateV1::default())
        }
    }

    pub fn as_head(&self) -> Option<&TopicStateV1> {
        match self {
            Self::Head(state) => Some(state),
            Self::Page(_) => None,
        }
    }

    pub fn as_page(&self) -> Option<&TopicPageStateV1> {
        match self {
            Self::Page(page) => Some(page),
            Self::Head(_) => None,
        }
    }

    pub fn is_loaded(&self) -> bool {
        match self {
            Self::Head(state) => state.header.is_some(),
            Self::Page(page) => page.header.is_some(),
        }
    }

    pub fn is_sealed(&self) -> bool {
        match self {
            Self::Head(state) => state.is_posts_sealed(),
            Self::Page(page) => page.is_sealed(),
        }
    }

    pub fn is_closed_part(&self) -> bool {
        match self {
            Self::Head(state) => state.is_closed_part(),
            Self::Page(page) => page.is_closed_part(),
        }
    }

    pub fn posts(&self) -> &BTreeMap<MessageId, AuthorizedTopicPostV1> {
        match self {
            Self::Head(state) => &state.posts,
            Self::Page(page) => &page.posts,
        }
    }

    pub fn participants(&self) -> &[AuthorizedParticipantV1] {
        match self {
            Self::Head(state) => &state.participants,
            Self::Page(page) => &page.participants,
        }
    }

    pub fn approvals(&self) -> &[AuthorizedTopicApprovalV1] {
        match self {
            Self::Head(state) => &state.approvals,
            Self::Page(page) => &page.approvals,
        }
    }

    pub fn trust(&self) -> &[AuthorizedTrustV1] {
        match self {
            Self::Head(state) => &state.trust,
            Self::Page(page) => &page.trust,
        }
    }

    pub fn authority(&self) -> &TopicAuthorityV1 {
        match self {
            Self::Head(state) => &state.authority,
            Self::Page(page) => &page.authority,
        }
    }

    pub fn all_actions(&self) -> Vec<&plaza_topic_core::AuthorizedTopicActionV1> {
        match self {
            Self::Head(state) => state.actions.iter().collect(),
            Self::Page(page) => page.all_actions().collect(),
        }
    }

    pub fn latest_action(
        &self,
        target: MessageId,
        kind: TopicActionKind,
    ) -> Option<&plaza_topic_core::AuthorizedTopicActionV1> {
        match self {
            Self::Head(state) => state.latest_action(target, kind),
            Self::Page(page) => page.latest_action(target, kind),
        }
    }

    pub fn is_deleted(&self, target: MessageId) -> bool {
        match self {
            Self::Head(state) => state.is_deleted(target),
            Self::Page(page) => page.is_deleted(target),
        }
    }

    pub fn is_split(&self, post_id: MessageId) -> bool {
        match self {
            Self::Head(state) => state.is_split(post_id),
            Self::Page(page) => page.is_split(post_id),
        }
    }

    pub fn is_trusted(&self, member: MemberId) -> bool {
        match self {
            Self::Head(state) => state.is_trusted(member),
            Self::Page(page) => page.is_trusted(member),
        }
    }

    pub fn is_banned_member(&self, member: MemberId, at_ms: i64) -> bool {
        match self {
            Self::Head(state) => state.is_banned_member(member, at_ms),
            Self::Page(page) => page.is_banned_member(member, at_ms),
        }
    }

    pub fn is_suspended_member(&self, member: MemberId, at_ms: i64) -> bool {
        match self {
            Self::Head(state) => state.is_suspended_member(member, at_ms),
            Self::Page(page) => page.is_suspended_member(member, at_ms),
        }
    }

    pub fn post_is_visible(&self, post: &AuthorizedTopicPostV1, head_trusted: bool) -> bool {
        match self {
            Self::Head(state) => head_trusted && !state.is_deleted(post.id()) || state.post_is_visible(post),
            Self::Page(page) => page.post_is_visible(post, head_trusted),
        }
    }

    pub fn section_chain(&self) -> Vec<MessageId> {
        match self {
            Self::Head(state) => state
                .effective_section()
                .map(|section| section.chain)
                .unwrap_or_default(),
            Self::Page(page) => page
                .header
                .as_ref()
                .map(|h| h.header.section_chain.clone())
                .unwrap_or_default(),
        }
    }

    pub fn section_id(&self) -> Option<MessageId> {
        match self {
            Self::Head(state) => state
                .effective_section()
                .map(|section| section.section)
                .or_else(|| state.header.as_ref().and_then(|h| h.header.section)),
            Self::Page(page) => page
                .header
                .as_ref()
                .and_then(|h| h.header.section_chain.last().copied()),
        }
    }
}

#[derive(Clone)]
pub struct TopicConversation {
    pub key: ContractKey,
    pub params: TopicParamsV1,
    pub state: TopicPartState,
    pub synced: bool,
    /// Last time this topic was opened, used to bound the client cache.
    pub last_used: i64,
}

pub static TOPIC_CACHE: GlobalSignal<HashMap<ContractInstanceId, TopicConversation>> =
    Global::new(HashMap::new);

/// Keep the state of recently opened topics and their pages. The node
/// subscription is not cancelled here; the client only drops the cached state.
const MAX_CACHED_TOPICS: usize = 48;

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
                    crate::components::app::notify_contract_evicted("topic", id);
                }
                None => break,
            }
        }
    });
}

/// Multi-version topic contract code registry. Keeping this dispatch table
/// allows future topic protocol versions (v2+) to coexist alongside existing v1
/// topic contracts without re-keying historical discussions.
pub fn topic_code_for_version(protocol_version: u16) -> Option<&'static [u8]> {
    match protocol_version {
        1 => Some(TOPIC_CONTRACT_WASM),
        _ => None,
    }
}

pub fn topic_key_for_version(
    protocol_version: u16,
    owner: VerifyingKey,
    topic_id: MessageId,
    part: u32,
) -> Option<ContractKey> {
    let wasm = topic_code_for_version(protocol_version)?;
    let mut params = TopicParamsV1::new(owner, *topic_id.as_bytes(), part);
    params.protocol_version = protocol_version;
    let parameters = Parameters::from(to_cbor_vec(&params));
    let code = ContractCode::from(wasm);
    Some(ContractKey::from_params_and_code(parameters, &code))
}

pub fn topic_key_for(owner: VerifyingKey, topic_id: MessageId, part: u32) -> ContractKey {
    topic_key_for_version(1, owner, topic_id, part).expect("topic protocol v1 code is bundled")
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

pub fn topic_state(
    owner: VerifyingKey,
    topic_id: MessageId,
    part: u32,
) -> Option<TopicPartState> {
    let key = topic_key_for(owner, topic_id, part);
    TOPIC_CACHE
        .read()
        .get(key.id())
        .map(|conversation| conversation.state.clone())
}

/// Convenience accessor for the topic head (`part == 0`).
pub fn topic_head(owner: VerifyingKey, topic_id: MessageId) -> Option<TopicStateV1> {
    topic_state(owner, topic_id, 0).and_then(|state| match state {
        TopicPartState::Head(head) => Some(head),
        TopicPartState::Page(_) => None,
    })
}

/// Seed a pre-built topic head into `TOPIC_CACHE` for the static `example-data` build.
#[cfg(feature = "example-data")]
pub fn seed_topic_head(owner: VerifyingKey, topic_id: MessageId, state: TopicStateV1) {
    let key = topic_key_for(owner, topic_id, 0);
    let contract_id = *key.id();
    TOPIC_CACHE.with_mut(|topics| {
        topics.insert(
            contract_id,
            TopicConversation {
                key,
                params: TopicParamsV1::new(owner, *topic_id.as_bytes(), 0),
                state: TopicPartState::Head(state),
                synced: true,
                last_used: system_time_ms(get_current_system_time()),
            },
        );
    });
}

/// Ensure a topic part is in the cache and fetch its state. Safe to call on
/// every render; a loaded state is not fetched again.
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
        .map(|conversation| conversation.state.is_loaded())
        .unwrap_or(false);
    if !already_loaded {
        TOPIC_CACHE.with_mut(|topics| {
            topics.entry(contract_id).or_insert_with(|| TopicConversation {
                key,
                params: TopicParamsV1::new(owner, *topic_id.as_bytes(), part),
                state: TopicPartState::empty_for_part(part),
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

/// Start the next append-only post page (`part + 1`) of a long topic.
///
/// The new contract uses compact `TopicPageStateV1` (small signed
/// `TopicPageHeaderV1`, minimal authority/participants for the creator only,
/// no duplicated 64 KiB body or historical participants). The previous page is
/// closed to new posts and, when the current identity is the board owner,
/// sealed with `AuthorizedTopicPageSealV1` so future verifications run in O(1)
/// and old extra pages strip all duplicated authority records.
pub async fn continue_topic(
    owner: VerifyingKey,
    topic_id: MessageId,
    part: u32,
) -> Result<u32, String> {
    let board = board_for(owner)?;
    let conversation = conversation_for(owner, topic_id, part)?;
    if !conversation.state.is_loaded() {
        return Err("the topic is still loading".to_string());
    }
    if conversation.state.is_closed_part() {
        return Err("the topic part is already closed".to_string());
    }
    let next_part = part + 1;
    if next_part > plaza_topic_core::MAX_PARTS {
        return Err("the topic reached the maximum number of parts".to_string());
    }
    let now = system_time_ms(get_current_system_time());
    let is_owner = board.is_current_owner();
    let signer_sk = if is_owner {
        board.owner_key().clone()
    } else {
        board.self_sk.clone()
    };
    let creator = MemberId::from(&signer_sk.verifying_key());

    let (
        header_hash,
        previous_hash,
        topic_author,
        auto_moderated,
        section_chain,
        allowed_roles,
        images_allowed,
        prev_previous_hash,
    ) = match &conversation.state {
        TopicPartState::Head(head) => {
            let header = head
                .header
                .as_ref()
                .ok_or("the topic is still loading")?;
            let section = head.effective_section();
            let chain = section
                .as_ref()
                .map(|s| s.chain.clone())
                .unwrap_or_else(|| header.header.section_chain.clone());
            let allowed_roles = section
                .as_ref()
                .map(|s| s.allowed_roles.clone())
                .unwrap_or_default();
            let images_allowed = section
                .as_ref()
                .map(|s| s.images_allowed)
                .unwrap_or(true);
            (
                header.hash(),
                head.state_hash()?,
                header.header.author,
                header.header.auto_moderated,
                chain,
                allowed_roles,
                images_allowed,
                head.generation.previous_hash,
            )
        }
        TopicPartState::Page(page) => {
            let page_header = page
                .header
                .as_ref()
                .ok_or("the topic page is still loading")?;
            // If the head (`part == 0`) is loaded, refresh section rules in case
            // the topic was moved to another section since the previous page opened.
            let (chain, allowed_roles, images_allowed) = topic_head(owner, topic_id)
                .and_then(|head| head.effective_section())
                .map(|section| (section.chain, section.allowed_roles, section.images_allowed))
                .unwrap_or_else(|| {
                    (
                        page_header.header.section_chain.clone(),
                        page_header.header.allowed_roles.clone(),
                        page_header.header.images_allowed,
                    )
                });
            (
                page_header.header.header_hash,
                page.state_hash()?,
                page_header.header.topic_author,
                page_header.header.auto_moderated,
                chain,
                allowed_roles,
                images_allowed,
                page.generation.previous_hash,
            )
        }
    };

    let page_header = TopicPageHeaderV1 {
        topic_id: *topic_id.as_bytes(),
        part: next_part,
        header_hash,
        previous_hash,
        topic_author,
        auto_moderated,
        section_chain: section_chain.clone(),
        allowed_roles,
        images_allowed,
        max_posts: DEFAULT_TOPIC_PAGE_SIZE as u32,
        creator,
        created_at: now,
    };
    let mut participants = Vec::new();
    let mut member_ids = HashSet::new();
    if creator != board.current_owner_id() && creator != MemberId::from(&owner) {
        let cert = participant_for(&board, creator)
            .ok_or("the active identity is not a member of this board")?;
        participants.push(cert);
        member_ids.insert(creator);
    }
    let authority = authority_from_board(&board, is_owner, &member_ids)?;
    let next_page = TopicPageStateV1 {
        version: plaza_topic_core::PROTOCOL_VERSION,
        header: Some(AuthorizedTopicPageHeaderV1::new(page_header, &signer_sk)),
        authority,
        participants,
        trust: Vec::new(),
        posts: BTreeMap::new(),
        actions: Vec::new(),
        approvals: Vec::new(),
        generation: plaza_topic_core::TopicGenerationV1 {
            part: next_part,
            closed_at: None,
            next_part: None,
            previous_hash: Some(previous_hash),
        },
        seal: None,
        post_seal_actions: Vec::new(),
    };
    let next_params = TopicParamsV1::new(owner, *topic_id.as_bytes(), next_part);
    next_page
        .verify(&next_params)
        .map_err(|error| format!("the new topic page does not verify: {error}"))?;
    let key = topic_key_for(owner, topic_id, next_part);
    let contract_id = *key.id();
    TOPIC_CACHE.with_mut(|topics| {
        topics.insert(
            contract_id,
            TopicConversation {
                key,
                params: next_params.clone(),
                state: TopicPartState::Page(next_page.clone()),
                synced: false,
                last_used: now,
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
        state: WrappedState::new(to_cbor_vec(&next_page)),
        related_contracts: Default::default(),
        subscribe: true,
        blocking_subscribe: false,
    })
    .await?;

    let closed = plaza_topic_core::TopicGenerationV1 {
        part,
        closed_at: Some(now),
        next_part: Some(next_part),
        previous_hash: prev_previous_hash,
    };
    let admin_seal_proof = if is_owner {
        None
    } else {
        board
            .board_state
            .admin
            .admins
            .iter()
            .find(|entry| {
                entry.admin.id() == creator
                    && !board.board_state.admin.revoked.iter().any(|rev| {
                        rev.id() == creator && rev.revocation.generation >= entry.admin.generation
                    })
            })
            .cloned()
            .map(|admin| AuthorityProof {
                admin: Some(admin),
                grant: None,
            })
    };
    let can_seal = is_owner || admin_seal_proof.is_some();
    match &conversation.state {
        TopicPartState::Head(head) => {
            let posts_seal = if can_seal {
                head.build_posts_seal(&conversation.params, now)
                    .ok()
                    .map(|seal| {
                        AuthorizedTopicPageSealV1::new(seal, &signer_sk, admin_seal_proof.clone())
                    })
            } else {
                None
            };
            publish_topic_delta(
                *conversation.key.id(),
                TopicDeltaV1 {
                    generation: Some(closed),
                    posts_seal,
                    ..Default::default()
                },
            )
            .await?;
        }
        TopicPartState::Page(page) => {
            let seal = if can_seal {
                page.build_seal(&conversation.params, now)
                    .ok()
                    .map(|seal| AuthorizedTopicPageSealV1::new(seal, &signer_sk, admin_seal_proof))
            } else {
                None
            };
            publish_topic_page_delta(
                *conversation.key.id(),
                TopicPageDeltaV1 {
                    generation: Some(closed),
                    seal,
                    ..Default::default()
                },
            )
            .await?;
        }
    }

    let index = crate::components::app::section_contract::merged_index(
        owner,
        &board.board_state.topics,
    );
    let current_generation = index
        .flag(&topic_id, TopicFlagKind::Part)
        .map(|flag| flag.generation)
        .unwrap_or(0);
    let flag = TopicFlagV1 {
        topic_id,
        kind: TopicFlagKind::Part,
        value: true,
        destination: None,
        section: None,
        section_chain: Vec::new(),
        destination_sections: Vec::new(),
        part: Some(next_part),
        scope_chain: section_chain,
        generation: current_generation + 1,
        created_at: now,
    };
    let authorized_flag = AuthorizedTopicFlagV1 {
        signature: plaza_core::util::sign_struct(&flag, &signer_sk),
        flag,
        signer: Some(creator),
        signer_key: Some(signer_sk.verifying_key()),
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

/// Create a topic contract owned by the current board owner and add its entry
/// to the board index.
#[allow(dead_code)]
pub async fn create_topic(
    owner: VerifyingKey,
    title: String,
    body: String,
    section: Option<MessageId>,
) -> Result<MessageId, String> {
    create_topic_with_options(owner, title, body, section, false).await
}

/// Create a topic contract with explicit options (e.g. `auto_moderated`).
pub async fn create_topic_with_options(
    owner: VerifyingKey,
    title: String,
    body: String,
    section: Option<MessageId>,
    auto_moderated: bool,
) -> Result<MessageId, String> {
    let section_id = section.ok_or("choose a section for the topic")?;
    crate::components::app::section_contract::ensure_section_loaded(owner, section_id).await?;
    let prepared = prepare_topic(owner, &title, &body, Some(section_id), auto_moderated).await?;
    let contract_id = *prepared.key.id();

    TOPIC_CACHE.with_mut(|topics| {
        topics.insert(
            contract_id,
            TopicConversation {
                key: prepared.key,
                params: prepared.params.clone(),
                state: TopicPartState::Head(prepared.state.clone()),
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
    Ok(prepared.topic_id)
}

async fn ensure_part_for_new_post(
    owner: VerifyingKey,
    topic_id: MessageId,
    part: u32,
) -> Result<u32, String> {
    let conversation = conversation_for(owner, topic_id, part)?;
    let full = match &conversation.state {
        TopicPartState::Head(head) => {
            head.is_closed_part()
                || head.posts.len() >= DEFAULT_TOPIC_PAGE_SIZE
                || encode(head)
                    .map(|bytes| bytes.len() >= plaza_topic_core::MAX_TOPIC_STATE_BYTES * 7 / 8)
                    .unwrap_or(false)
        }
        TopicPartState::Page(page) => {
            page.is_closed_part()
                || page.is_full()
                || encode(page)
                    .map(|bytes| bytes.len() >= MAX_TOPIC_PAGE_BYTES * 7 / 8)
                    .unwrap_or(false)
        }
    };
    if full {
        continue_topic(owner, topic_id, part).await
    } else {
        Ok(part)
    }
}

/// Publish a reply in a topic and bump the board activity hint.
#[allow(dead_code)]
pub async fn send_reply(
    owner: VerifyingKey,
    topic_id: MessageId,
    part: u32,
    text: String,
) -> Result<(), String> {
    send_reply_with_images(owner, topic_id, part, text, Vec::new()).await
}

/// Publish a reply with optional attached images and bump the board activity hint.
pub async fn send_reply_with_images(
    owner: VerifyingKey,
    topic_id: MessageId,
    part: u32,
    text: String,
    images: Vec<plaza_core::board_state::images::ImageRef>,
) -> Result<(), String> {
    let published_images = images.clone();
    let part = ensure_part_for_new_post(owner, topic_id, part).await?;
    let prepared = prepare_reply(
        owner,
        topic_id,
        part,
        TopicPostContentV1::Text(text),
        images,
    )?;
    publish_prepared_reply(owner, prepared).await?;
    crate::util::owned_images::mark_published(&published_images);
    Ok(())
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
        Vec::new(),
    )?;
    publish_prepared_reply(owner, prepared).await
}

async fn publish_prepared_reply(
    owner: VerifyingKey,
    prepared: PreparedReply,
) -> Result<(), String> {
    let contract_id = prepared.contract_id;
    match prepared.delta {
        PreparedReplyDelta::Head(delta) => publish_topic_delta(contract_id, delta).await?,
        PreparedReplyDelta::Page(delta) => publish_topic_page_delta(contract_id, delta).await?,
    }
    if let Some(activity) = prepared.activity {
        let section = board_for(owner).ok().and_then(|board| {
            let index = board.with_merged_topics().board_state.topics;
            index
                .section_of(&prepared.topic_id)
                .0
                .or_else(|| section_for_topic(owner, prepared.topic_id).map(|(s, _)| s))
        });
        if let Err(error) = crate::components::app::activity_contract::record_activity(
            owner,
            section,
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
    let self_id = MemberId::from(&board.self_sk.verifying_key());
    let target_author = conversation
        .state
        .posts()
        .get(&target)
        .map(|post| post.post.author)
        .or_else(|| {
            conversation
                .state
                .as_head()
                .and_then(|head| head.header.as_ref())
                .filter(|header| header.header.id() == target)
                .map(|header| header.header.author)
        });
    let (signing_key, authority) = if target_author == Some(self_id) {
        (board.self_sk.clone(), None)
    } else if board.is_active_owner() {
        (board.owner_key().clone(), None)
    } else {
        (board.self_sk.clone(), delete_authority(&board, &self_id))
    };
    let signer = MemberId::from(&signing_key.verifying_key());
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
        signature: plaza_core::util::sign_struct(&action, &signing_key),
        action,
        signer_key: Some(signing_key.verifying_key()),
        authority,
    };
    publish_part_action(&conversation, authorized).await
}

/// Set one moderation flag on a topic. Topic-level flags always live on
/// `part == 0` (the topic head) and in the board/section manifest.
pub async fn set_flag(
    owner: VerifyingKey,
    topic_id: MessageId,
    _part: u32,
    kind: TopicFlagKind,
    value: bool,
) -> Result<(), String> {
    let board = board_for(owner)?;
    if !board.is_current_owner() {
        return Err("only the board owner can change this flag for now".to_string());
    }
    let conversation = conversation_for(owner, topic_id, 0)?;
    let head = conversation
        .state
        .as_head()
        .ok_or("topic head is not loaded")?;
    let header = head
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
    let generation = [kind_on, kind_off]
        .into_iter()
        .filter_map(|k| head.latest_action(target, k).map(|entry| entry.action.generation))
        .max()
        .unwrap_or(0)
        + 1;
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

    let chain = head
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
    auto_moderated: bool,
) -> Result<PreparedTopic, String> {
    let mut board = board_for(owner)?;
    if board.board_state.mode != BoardModeV1::SectionedTopicIndex {
        return Err("this board does not use section-sharded topic contracts".to_string());
    }
    let section_id = section.ok_or("choose a section for the topic")?;
    let page = crate::components::app::section_contract::active_page(owner, section_id).await?;
    let child_topics = crate::components::app::section_contract::section_page_index(
        owner,
        section_id,
        page,
    )
    .ok_or("the section page is still loading")?;
    board.board_state.topics = child_topics;
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

    let auto_moderated_allowed = section
        .and_then(|id| board.board_state.sections.section(&id))
        .and_then(|s| s.auto_moderated_topics)
        .unwrap_or(board.board_state.configuration.configuration.auto_moderated_topics);
    let effective_auto_moderated = auto_moderated && auto_moderated_allowed;

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
        auto_moderated: effective_auto_moderated,
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

enum PreparedReplyDelta {
    Head(TopicDeltaV1),
    Page(TopicPageDeltaV1),
}

struct PreparedReply {
    contract_id: ContractInstanceId,
    topic_id: MessageId,
    part: u32,
    delta: PreparedReplyDelta,
    activity: Option<AuthorizedTopicActivityV1>,
}

fn prepare_reply(
    owner: VerifyingKey,
    topic_id: MessageId,
    part: u32,
    content: TopicPostContentV1,
    images: Vec<plaza_core::board_state::images::ImageRef>,
) -> Result<PreparedReply, String> {
    let board = board_for(owner)?;
    let conversation = conversation_for(owner, topic_id, part)?;
    if !conversation.state.is_loaded() {
        return Err("the topic is still loading".to_string());
    }
    match &content {
        TopicPostContentV1::Text(text) if text.trim().is_empty() && images.is_empty() => {
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
        images,
        created_at: now,
        nonce,
    };
    let authorized = plaza_topic_core::AuthorizedTopicPostV1::new(post, &board.self_sk);
    let post_id = authorized.id();
    let mut participants = Vec::new();
    if !conversation
        .state
        .participants()
        .iter()
        .any(|entry| entry.record.member_id == author)
    {
        if author == board.current_owner_id() || author == MemberId::from(&owner) {
            // The owner is implicit and never appears in the participant list.
        } else if let Some(participant) = participant_for(&board, author) {
            participants.push(participant);
        } else {
            return Err("the active identity is not a member of this board".to_string());
        }
    }
    // When a participant joins a topic/page for the first time (e.g. a
    // token-joined member whose role was created after the topic), bundle any
    // newer board authority (role definitions, root/proofs) in the same delta
    // so the reply verifies atomically without racing on-demand authority sync.
    let bundled_authority = if !participants.is_empty() {
        let mut member_ids: HashSet<MemberId> = conversation
            .state
            .participants()
            .iter()
            .map(|p| p.record.member_id)
            .collect();
        member_ids.insert(author);
        authority_from_board(&board, board.is_current_owner(), &member_ids)
            .ok()
            .filter(|generated| {
                conversation.state.authority().merged_with(generated)
                    != *conversation.state.authority()
            })
    } else {
        None
    };
    let delta = match &conversation.state {
        TopicPartState::Head(_) => PreparedReplyDelta::Head(TopicDeltaV1 {
            posts: vec![authorized],
            participants,
            authority: bundled_authority,
            ..Default::default()
        }),
        TopicPartState::Page(_) => PreparedReplyDelta::Page(TopicPageDeltaV1 {
            posts: vec![authorized],
            participants,
            authority: bundled_authority,
            ..Default::default()
        }),
    };

    // Activity hint for the board list. If the board update fails the reply is
    // still valid; the next successful one refreshes the count.
    let contract_id = *conversation.key.id();
    let head_trusted = topic_head(owner, topic_id)
        .map(|head| head.is_trusted(author))
        .unwrap_or(false);
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
                let policy = conversation.state.authority().policy();
                if policy.approval_required
                    && !head_trusted
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
        delta,
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
        .find(|board| board.params.owner == owner && board.contains_topic(&topic_id))
    {
        return Some((board.params.section, board.params.page));
    }
    TOPIC_CACHE
        .read()
        .values()
        .find(|conversation| {
            conversation.params.topic_id == *topic_id.as_bytes()
                && conversation.state.is_loaded()
        })
        .and_then(|conversation| conversation.state.section_id().map(|section| (section, 0)))
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
            conversation.params.topic_id == *topic_id.as_bytes()
                && conversation.state.is_loaded()
        })
        .and_then(|conversation| conversation.state.section_id());
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
    let has_entries = delta
        .topics
        .as_ref()
        .is_some_and(|topics| !topics.entries.is_empty());
    let (section, page) = locate_section_page(owner, topic_id).await?;
    // Section flags live on page 0 (the manifest) so compact extra pages
    // (`page > 0`) stay immutable once sealed and never need authority syncs.
    let target_page = if has_entries { page } else { 0 };
    crate::components::app::section_contract::apply_section_delta(owner, section, target_page, delta)
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

async fn send_topic_delta_bytes(
    contract_id: ContractInstanceId,
    key: ContractKey,
    next_state: TopicPartState,
    bytes: Vec<u8>,
) -> Result<(), String> {
    TOPIC_CACHE.with_mut(|topics| {
        if let Some(conversation) = topics.get_mut(&contract_id) {
            conversation.state = next_state;
            #[cfg(feature = "no-sync")]
            {
                conversation.synced = true;
            }
            #[cfg(not(feature = "no-sync"))]
            {
                conversation.synced = false;
            }
            conversation.last_used = system_time_ms(get_current_system_time());
        }
    });

    #[cfg(feature = "no-sync")]
    {
        let _ = (key, bytes);
        return Ok(());
    }

    #[cfg(not(feature = "no-sync"))]
    {
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
}

async fn publish_topic_delta(
    contract_id: ContractInstanceId,
    delta: TopicDeltaV1,
) -> Result<(), String> {
    let (key, next_state, bytes) = {
        let topics = TOPIC_CACHE.read();
        let conversation = topics
            .get(&contract_id)
            .ok_or_else(|| "the topic is not loaded".to_string())?;
        let mut next_head = conversation
            .state
            .as_head()
            .ok_or_else(|| "expected topic head state for part 0 delta".to_string())?
            .clone();
        next_head
            .apply_delta(&conversation.params, &delta)
            .map_err(|error| format!("apply topic delta: {error}"))?;
        let bytes = encode(&delta).map_err(|error| format!("encode topic delta: {error}"))?;
        (conversation.key, TopicPartState::Head(next_head), bytes)
    };
    send_topic_delta_bytes(contract_id, key, next_state, bytes).await
}

async fn publish_topic_page_delta(
    contract_id: ContractInstanceId,
    delta: TopicPageDeltaV1,
) -> Result<(), String> {
    let (key, next_state, bytes) = {
        let topics = TOPIC_CACHE.read();
        let conversation = topics
            .get(&contract_id)
            .ok_or_else(|| "the topic page is not loaded".to_string())?;
        let mut next_page = conversation
            .state
            .as_page()
            .ok_or_else(|| "expected compact topic page state for part > 0 delta".to_string())?
            .clone();
        next_page
            .apply_delta(&conversation.params, &delta)
            .map_err(|error| format!("apply topic page delta: {error}"))?;
        let bytes = encode(&delta).map_err(|error| format!("encode topic page delta: {error}"))?;
        (conversation.key, TopicPartState::Page(next_page), bytes)
    };
    send_topic_delta_bytes(contract_id, key, next_state, bytes).await
}

async fn publish_part_action(
    conversation: &TopicConversation,
    action: plaza_topic_core::AuthorizedTopicActionV1,
) -> Result<(), String> {
    match &conversation.state {
        TopicPartState::Head(_) => {
            publish_topic_delta(
                *conversation.key.id(),
                TopicDeltaV1 {
                    actions: vec![action],
                    ..Default::default()
                },
            )
            .await
        }
        TopicPartState::Page(page) => {
            let delta = if page.is_sealed() {
                TopicPageDeltaV1 {
                    post_seal_actions: vec![action],
                    ..Default::default()
                }
            } else {
                TopicPageDeltaV1 {
                    actions: vec![action],
                    ..Default::default()
                }
            };
            publish_topic_page_delta(*conversation.key.id(), delta).await
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
    #[cfg(feature = "no-sync")]
    {
        TOPIC_CACHE.with_mut(|topics| {
            if let Some(conversation) = topics.get_mut(&contract_id) {
                conversation.synced = true;
            }
        });
        return Ok(());
    }
    #[cfg(not(feature = "no-sync"))]
    {
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
            let part = {
                let topics = TOPIC_CACHE.read();
                match topics.get(key.id()) {
                    Some(conversation) => conversation.params.part,
                    None => return Ok(()),
                }
            };
            let decoded = if part == 0 {
                let head = decode_state(state.as_ref())
                    .map_err(|error| format!("decode topic state: {error}"))?;
                TopicPartState::Head(head)
            } else {
                let page = decode_page_state(state.as_ref())
                    .map_err(|error| format!("decode topic page state: {error}"))?;
                TopicPartState::Page(page)
            };
            TOPIC_CACHE.with_mut(|topics| {
                if let Some(conversation) = topics.get_mut(key.id()) {
                    conversation.state = decoded;
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

async fn send_contract_request(request: ContractRequest<'static>) -> Result<(), String> {
    #[cfg(feature = "no-sync")]
    {
        let _ = request;
        return Ok(());
    }
    #[cfg(not(feature = "no-sync"))]
    {
        let client_request = ClientRequest::ContractOp(request);
        crate::components::app::send_client_request(client_request)
            .await
            .map_err(|error| format!("send topic contract request: {error}"))
    }
}
