//! Section child boards and compact extra topic pages.
//!
//! A sectioned parent board keeps only the section list and global authority.
//! Each section has:
//! - Page 0 (the manifest, `ChatBoardStateV1`): section authority (pruned),
//!   `topic_pages` manifest, page 0's topic entries, and all section flags.
//! - Pages `page > 0` (`SectionPageStateV1`): compact topic-entry pages with no
//!   board configuration, sections, bans, suspensions, activity, reports, or
//!   flags. When full, the owner seals a page, dropping all duplicated author,
//!   invite, and role records so new subscribers verify it with 1 signature.


mod authority;
mod pages;

use authority::{add_token_roles, build_compact_page_delta, collect_members_with_ancestors, relevant_invites_for_members, with_section_records};
pub use authority::sync_section_authority;
pub use pages::{
    active_page, clear_extra_pages, create_section_page, ensure_section_loaded,
    ensure_section_page_loaded, has_more_pages, load_all_section_pages,
    load_all_section_pages_for_board, load_next_pages, load_section_board, load_section_page,
    load_section_pages,
};
use dioxus::prelude::*;
use ed25519_dalek::{SigningKey, VerifyingKey};
use freenet_scaffold::ComposableState;
use freenet_stdlib::client_api::{ClientRequest, ContractRequest, ContractResponse};
use freenet_stdlib::prelude::{
    ContractCode, ContractContainer, ContractInstanceId, ContractKey, ContractWasmAPIVersion,
    Parameters, UpdateData, WrappedContract, WrappedState,
};
use plaza_core::board_state::admin::AdminsV1;
use plaza_core::board_state::ban::{AuthorizedBanRevocation, AuthorizedUserBan};
use plaza_core::board_state::invites::{AuthorizedInviteToken, InviteTokensDelta};
use plaza_core::board_state::member::{AuthorizedMember, MemberId, MembersDelta};
use plaza_core::board_state::member_moderation::{AuthorizedSuspension, SuspensionsDelta};
use plaza_core::board_state::message::MessageId;
use plaza_core::board_state::pages::{
    AuthorizedTopicPageListV1, DEFAULT_TOPIC_PAGE_SIZE, MAX_TOPIC_PAGE_SIZE,
};
use plaza_core::board_state::roles::{AuthorizedRole, AuthorizedRoleAssignment, RolesDelta};
use plaza_core::board_state::section_pages::{
    ownership_referenced_members, AuthorizedSectionPageHeaderV1, AuthorizedSectionPageSealV1,
    SectionPageDeltaV1, SectionPageHeaderV1, SectionPageStateV1,
};
use plaza_core::board_state::sections::{
    AuthorizedSectionV1, SectionId, SectionParametersV1, SectionsDelta,
};
use plaza_core::board_state::topics::{AuthorizedTopicActivityV1, TopicIndexDelta, TopicIndexV1};
use plaza_core::board_state::{
    BoardModeV1, ChatBoardParametersV1, ChatBoardStateV1, ChatBoardStateV1Delta,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::components::app::chat_delegate::{send_delegate_request, SECTION_BOARDS_STORAGE_KEY};
use crate::components::app::send_client_request;
use crate::constants::SECTION_CONTRACT_WASM;
use crate::util::to_cbor_vec;
use plaza_core::chat_delegate::{ChatDelegateKey, ChatDelegateRequestMsg, ChatDelegateResponseMsg};

/// State stored for a section contract: page 0 is the full manifest; extra
/// pages (`page > 0`) use the compact `SectionPageStateV1` format.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum SectionBoardState {
    Manifest(ChatBoardStateV1),
    CompactPage(SectionPageStateV1),
}

impl SectionBoardState {
    pub fn is_initialized(&self) -> bool {
        match self {
            Self::Manifest(state) => state.mode == BoardModeV1::SectionedTopicIndex,
            Self::CompactPage(page) => page.header.is_some(),
        }
    }

    pub fn is_sealed(&self) -> bool {
        match self {
            Self::Manifest(_) => false,
            Self::CompactPage(page) => page.is_sealed(),
        }
    }

    pub fn entry_count(&self) -> usize {
        match self {
            Self::Manifest(state) => state.topics.entries.len(),
            Self::CompactPage(page) => page.entries.len(),
        }
    }

    pub fn contains_topic(&self, topic_id: &MessageId) -> bool {
        match self {
            Self::Manifest(state) => state.topics.entry(topic_id).is_some(),
            Self::CompactPage(page) => page
                .entries
                .iter()
                .any(|entry| entry.entry.topic_id == *topic_id),
        }
    }

    pub fn topic_index(&self) -> TopicIndexV1 {
        match self {
            Self::Manifest(state) => state.topics.clone(),
            Self::CompactPage(page) => TopicIndexV1 {
                entries: page.effective_entries(),
                ..Default::default()
            },
        }
    }

    pub fn as_manifest(&self) -> Option<&ChatBoardStateV1> {
        match self {
            Self::Manifest(state) => Some(state),
            Self::CompactPage(_) => None,
        }
    }

    pub fn as_compact_page(&self) -> Option<&SectionPageStateV1> {
        match self {
            Self::Manifest(_) => None,
            Self::CompactPage(page) => Some(page),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct PersistedSectionBoard {
    owner: VerifyingKey,
    section: SectionId,
    #[serde(default)]
    page: u32,
    #[serde(default)]
    last_used: i64,
    state: SectionBoardState,
}

/// Number of topics in a page before the owner is asked to create the next.
/// This is the client default for new sections; an existing section uses the
/// page size signed in its manifest.
pub static TOPIC_PAGE_SIZE: GlobalSignal<usize> =
    Global::new(|| DEFAULT_TOPIC_PAGE_SIZE as usize);

/// The client default, clamped to the bound the contract accepts.
pub(crate) fn current_topic_page_size() -> u32 {
    let size = if dioxus::core::Runtime::try_current().is_some() {
        *TOPIC_PAGE_SIZE.read() as u32
    } else {
        DEFAULT_TOPIC_PAGE_SIZE
    };
    size.clamp(1, MAX_TOPIC_PAGE_SIZE)
}

fn now_ms() -> i64 {
    plaza_core::board_state::rate_limit::system_time_ms(crate::util::get_current_system_time())
}

static SECTION_SAVE_SCHEDULED: AtomicBool = AtomicBool::new(false);
static SECTION_LOAD_STARTED: AtomicBool = AtomicBool::new(false);

fn schedule_section_save() {
    if crate::components::app::chat_delegate::LOCAL_RESET.load(Ordering::SeqCst) {
        return;
    }
    if SECTION_SAVE_SCHEDULED.swap(true, Ordering::SeqCst) {
        return;
    }
    crate::util::safe_spawn_local(async {
        crate::util::sleep(std::time::Duration::from_secs(1)).await;
        if let Err(error) = save_section_boards_now().await {
            dioxus::logger::tracing::warn!("could not save section boards: {error}");
        }
        SECTION_SAVE_SCHEDULED.store(false, Ordering::SeqCst);
    });
}

/// Extra pages kept in the delegate blob and in RAM (`SECTION_BOARDS`), newest
/// first. Page 0 (the manifest) is always kept so the board list and page lists
/// survive a reload. Evicted extra pages are fetched again on demand.
const MAX_PERSISTED_SECTION_PAGES: usize = 24;
const MAX_CACHED_EXTRA_SECTION_PAGES: usize = 24;
const MAX_PERSISTED_SECTION_BYTES: usize = 4 * 1024 * 1024;

fn evict_extra_section_pages(protect: ContractInstanceId) {
    let mut evicted = Vec::new();
    SECTION_BOARDS.with_mut(|boards| {
        loop {
            let extra_count = boards.values().filter(|b| b.params.page > 0).count();
            if extra_count <= MAX_CACHED_EXTRA_SECTION_PAGES {
                break;
            }
            let victim = boards
                .iter()
                .filter(|(id, board)| **id != protect && board.params.page > 0 && !board.dirty)
                .min_by_key(|(_, board)| board.last_used)
                .map(|(id, _)| *id);
            match victim {
                Some(id) => {
                    boards.remove(&id);
                    evicted.push(id);
                }
                None => break,
            }
        }
    });
    for id in evicted {
        crate::components::app::notify_contract_evicted("section_page", id);
    }
}

fn cbor_len<T: serde::Serialize>(value: &T) -> usize {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes)
        .map(|_| bytes.len())
        .unwrap_or(0)
}

async fn save_section_boards_now() -> Result<(), String> {
    let (manifests, mut pages) = {
        let boards = SECTION_BOARDS.read();
        let mut manifests = Vec::new();
        let mut pages = Vec::new();
        for board in boards.values() {
            // A placeholder inserted by `load_section_page` has a default
            // state; saving it would restore an invalid child on the next load.
            if !board.state.is_initialized() {
                continue;
            }
            let entry = PersistedSectionBoard {
                owner: board.params.owner,
                section: board.params.section,
                page: board.params.page,
                last_used: board.last_used,
                state: board.state.clone(),
            };
            if board.params.page == 0 {
                manifests.push(entry);
            } else {
                pages.push(entry);
            }
        }
        (manifests, pages)
    };
    pages.sort_by(|left, right| right.last_used.cmp(&left.last_used));
    let mut entries = manifests;
    let mut bytes: usize = entries.iter().map(|entry| cbor_len(&entry.state)).sum();
    let mut kept_pages = 0;
    for entry in pages {
        if kept_pages >= MAX_PERSISTED_SECTION_PAGES || bytes >= MAX_PERSISTED_SECTION_BYTES {
            break;
        }
        let size = cbor_len(&entry.state);
        if bytes + size > MAX_PERSISTED_SECTION_BYTES {
            continue;
        }
        bytes += size;
        kept_pages += 1;
        entries.push(entry);
    }
    if entries.is_empty() {
        return Ok(());
    }
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&entries, &mut bytes)
        .map_err(|error| format!("serialize section boards: {error}"))?;
    match send_delegate_request(ChatDelegateRequestMsg::StoreRequest {
        key: ChatDelegateKey::new(SECTION_BOARDS_STORAGE_KEY.to_vec()),
        value: bytes,
    })
    .await
    {
        Ok(ChatDelegateResponseMsg::StoreResponse { result, .. }) => result,
        Ok(other) => Err(format!("unexpected section store response: {other:?}")),
        Err(error) => Err(error),
    }
}

/// Load cached section boards so the UI shows the last known index before the
/// network GET completes. Network state replaces them as soon as it arrives.
pub async fn load_persisted_section_boards() {
    if SECTION_LOAD_STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    let response = send_delegate_request(ChatDelegateRequestMsg::GetRequest {
        key: ChatDelegateKey::new(SECTION_BOARDS_STORAGE_KEY.to_vec()),
    })
    .await;
    let bytes = match response {
        Ok(ChatDelegateResponseMsg::GetResponse {
            value: Some(bytes), ..
        }) => bytes,
        _ => return,
    };
    let entries: Vec<PersistedSectionBoard> = match ciborium::de::from_reader(bytes.as_slice()) {
        Ok(entries) => entries,
        Err(error) => {
            dioxus::logger::tracing::warn!("could not decode section boards: {error}");
            return;
        }
    };
    let mut restored_activity = Vec::new();
    SECTION_BOARDS.with_mut(|boards| {
        for entry in entries {
            if !entry.state.is_initialized() {
                continue;
            }
            let key = section_page_key(entry.owner, entry.section, entry.page);
            let contract_id = *key.id();
            let activity = entry
                .state
                .as_manifest()
                .map(|s| s.topics.activity.clone())
                .unwrap_or_default();
            let has_local_activity = !activity.is_empty();
            if has_local_activity {
                restored_activity.push((contract_id, key, activity));
            }
            let last_used = if entry.last_used > 0 {
                entry.last_used
            } else {
                now_ms()
            };
            let mut board = SectionBoard::new(
                SectionParametersV1 {
                    owner: entry.owner,
                    section: entry.section,
                    page: entry.page,
                },
                entry.state,
                has_local_activity,
            );
            board.last_used = last_used;
            boards.insert(contract_id, board);
        }
    });
    for (contract_id, key, activity) in restored_activity {
        queue_section_activity(contract_id, key, activity);
    }
}

pub struct SectionBoard {
    pub params: SectionParametersV1,
    pub state: SectionBoardState,
    pub synced: bool,
    /// State has arrived and (for page 0) parent authority has been copied in.
    pub ready: bool,
    /// An authority sync is in flight (page 0 only).
    pub syncing: bool,
    /// Local changes have not been confirmed by the network yet.
    pub dirty: bool,
    /// Last time this page was read or written, for the persistence budget.
    pub last_used: i64,
    /// Last GET sent for this page; avoids duplicate fetches while it is in
    /// flight.
    pub last_fetch: i64,
}

impl SectionBoard {
    fn new(params: SectionParametersV1, state: SectionBoardState, dirty: bool) -> Self {
        Self {
            params,
            state,
            synced: false,
            ready: false,
            syncing: false,
            dirty,
            last_used: now_ms(),
            last_fetch: 0,
        }
    }

    pub fn contains_topic(&self, topic_id: &MessageId) -> bool {
        self.state.contains_topic(topic_id)
    }
}

pub static SECTION_BOARDS: GlobalSignal<HashMap<ContractInstanceId, SectionBoard>> =
    Global::new(HashMap::new);

/// Seed a pre-built section manifest (page 0) into `SECTION_BOARDS` for the
/// static `example-data` build.
#[cfg(feature = "example-data")]
pub fn seed_section_manifest(
    owner: VerifyingKey,
    section: SectionId,
    state: ChatBoardStateV1,
) {
    let key = section_key(owner, section);
    let contract_id = *key.id();
    let now = now_ms();
    SECTION_BOARDS.with_mut(|boards| {
        boards.insert(
            contract_id,
            SectionBoard {
                params: SectionParametersV1 {
                    owner,
                    section,
                    page: 0,
                },
                state: SectionBoardState::Manifest(state),
                synced: true,
                ready: true,
                syncing: false,
                dirty: false,
                last_used: now,
                last_fetch: now,
            },
        );
    });
}

const MAX_SECTION_ACTIVITY_RETRIES: u8 = 5;

struct PendingSectionActivity {
    key: ContractKey,
    activity: HashMap<MessageId, AuthorizedTopicActivityV1>,
    attempts: u8,
}

static SECTION_ACTIVITY: Mutex<Vec<(ContractInstanceId, PendingSectionActivity)>> =
    Mutex::new(Vec::new());
static SECTION_ACTIVITY_TIMERS: Mutex<Vec<ContractInstanceId>> = Mutex::new(Vec::new());

async fn flush_section_activity(contract_id: ContractInstanceId) {
    SECTION_ACTIVITY_TIMERS
        .lock()
        .unwrap()
        .retain(|id| *id != contract_id);
    let pending = {
        let mut queue = SECTION_ACTIVITY.lock().unwrap();
        queue
            .iter()
            .position(|(id, _)| *id == contract_id)
            .map(|index| queue.remove(index).1)
    };
    let Some(mut pending) = pending else {
        return;
    };
    let delta = ChatBoardStateV1Delta {
        topics: Some(TopicIndexDelta {
            activity: pending.activity.values().cloned().collect(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let bytes = to_cbor_vec(&delta);
    let result = send_client_request(ClientRequest::ContractOp(ContractRequest::Update {
        key: pending.key,
        data: UpdateData::Delta(bytes.into()),
    }))
    .await;
    match result {
        Ok(()) => {
            SECTION_BOARDS.with_mut(|boards| {
                if let Some(board) = boards.get_mut(&contract_id) {
                    board.dirty = true;
                }
            });
            schedule_section_save();
        }
        Err(error) => {
            pending.attempts = pending.attempts.saturating_add(1);
            dioxus::logger::tracing::warn!(
                "section activity was not sent (attempt {}/{}): {error}",
                pending.attempts,
                MAX_SECTION_ACTIVITY_RETRIES
            );
            SECTION_BOARDS.with_mut(|boards| {
                if let Some(board) = boards.get_mut(&contract_id) {
                    board.dirty = true;
                }
            });
            if pending.attempts >= MAX_SECTION_ACTIVITY_RETRIES {
                dioxus::logger::tracing::warn!(
                    "Dropping section activity for {contract_id} after {} failed attempts",
                    pending.attempts
                );
                return;
            }
            let retry_key = pending.key;
            let retry_records: Vec<_> = pending.activity.into_values().collect();
            {
                let mut queue = SECTION_ACTIVITY.lock().unwrap();
                if let Some(index) = queue.iter().position(|(id, _)| *id == contract_id) {
                    for record in retry_records {
                        queue[index]
                            .1
                            .activity
                            .entry(record.activity.topic_id)
                            .or_insert(record);
                    }
                    queue[index].1.attempts = queue[index].1.attempts.max(pending.attempts);
                } else {
                    let mut activity_map = HashMap::new();
                    for record in retry_records {
                        activity_map.insert(record.activity.topic_id, record);
                    }
                    queue.push((
                        contract_id,
                        PendingSectionActivity {
                            key: retry_key,
                            activity: activity_map,
                            attempts: pending.attempts,
                        },
                    ));
                }
            }
            queue_section_activity(contract_id, retry_key, Vec::new());
        }
    }
}

fn queue_section_activity(
    contract_id: ContractInstanceId,
    key: ContractKey,
    activity: Vec<AuthorizedTopicActivityV1>,
) {
    {
        let mut pending = SECTION_ACTIVITY.lock().unwrap();
        if let Some(index) = pending.iter().position(|(id, _)| *id == contract_id) {
            for record in activity {
                pending[index]
                    .1
                    .activity
                    .insert(record.activity.topic_id, record);
            }
        } else {
            let mut activity_map = HashMap::new();
            for record in activity {
                activity_map.insert(record.activity.topic_id, record);
            }
            pending.push((
                contract_id,
                PendingSectionActivity {
                    key,
                    activity: activity_map,
                    attempts: 0,
                },
            ));
        }
    }
    SECTION_BOARDS.with_mut(|boards| {
        if let Some(board) = boards.get_mut(&contract_id) {
            board.dirty = true;
        }
    });
    let mut timers = SECTION_ACTIVITY_TIMERS.lock().unwrap();
    if timers.contains(&contract_id) {
        return;
    }
    timers.push(contract_id);
    drop(timers);
    crate::util::safe_spawn_local(async move {
        crate::util::sleep(std::time::Duration::from_secs(10)).await;
        flush_section_activity(contract_id).await;
    });
}

pub fn section_key(owner: VerifyingKey, section: SectionId) -> ContractKey {
    section_page_key(owner, section, 0)
}

pub fn section_page_key(owner: VerifyingKey, section: SectionId, page: u32) -> ContractKey {
    let params = SectionParametersV1 {
        owner,
        section,
        page,
    };
    let parameters = Parameters::from(to_cbor_vec(&params));
    let code = ContractCode::from(SECTION_CONTRACT_WASM);
    ContractKey::from_params_and_code(parameters, &code)
}

pub fn is_known_section_board(key: &ContractInstanceId) -> bool {
    SECTION_BOARDS.read().contains_key(key)
}

pub fn section_state(owner: VerifyingKey, section: SectionId) -> Option<ChatBoardStateV1> {
    section_page_state(owner, section, 0)
}

pub fn section_page_state(
    owner: VerifyingKey,
    section: SectionId,
    page: u32,
) -> Option<ChatBoardStateV1> {
    let key = section_page_key(owner, section, page);
    SECTION_BOARDS
        .read()
        .get(key.id())
        .and_then(|board| board.state.as_manifest().cloned())
}

/// Topic index slice held by a loaded section page (works for both page 0
/// manifests and compact extra pages).
pub fn section_page_index(
    owner: VerifyingKey,
    section: SectionId,
    page: u32,
) -> Option<TopicIndexV1> {
    let key = section_page_key(owner, section, page);
    SECTION_BOARDS
        .read()
        .get(key.id())
        .map(|board| board.state.topic_index())
}

/// Page 0 plus the owner-signed extra pages of a section.
pub fn pages_for(owner: VerifyingKey, section: SectionId) -> Vec<u32> {
    section_state(owner, section)
        .map(|state| state.topic_pages.pages())
        .unwrap_or_else(|| vec![0])
}

/// Page size signed in the section manifest, when it has a page list.
pub fn page_size_for(owner: VerifyingKey, section: SectionId) -> Option<u32> {
    section_state(owner, section)
        .and_then(|state| state.topic_pages.page_size())
        .filter(|size| *size > 0 && *size <= MAX_TOPIC_PAGE_SIZE)
}

/// Merge the parent index (used by non-sharded boards) with every loaded
/// child manifest and compact page of this owner. The UI reads the union as
/// one index.
pub fn merged_index(owner: VerifyingKey, parent: &TopicIndexV1) -> TopicIndexV1 {
    let mut merged = parent.clone();
    let boards = SECTION_BOARDS.read();
    for board in boards.values().filter(|board| board.params.owner == owner) {
        match &board.state {
            SectionBoardState::Manifest(state) => merge_index(&mut merged, &state.topics),
            SectionBoardState::CompactPage(page) => {
                let effective = page.effective_entries();
                merge_entries(&mut merged.entries, &effective);
            }
        }
    }
    merged
}

fn merge_entries(
    dst: &mut Vec<plaza_core::board_state::topics::AuthorizedTopicEntryV1>,
    src: &[plaza_core::board_state::topics::AuthorizedTopicEntryV1],
) {
    for entry in src {
        match dst
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
            None => dst.push(entry.clone()),
        }
    }
}

fn merge_index(dst: &mut TopicIndexV1, src: &TopicIndexV1) {
    merge_entries(&mut dst.entries, &src.entries);
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
            existing.flag.topic_id == entry.flag.topic_id && existing.flag.kind == entry.flag.kind
        }) {
            Some(existing) => {
                let take = entry.flag.generation > existing.flag.generation
                    || (entry.flag.generation == existing.flag.generation
                        && !entry.flag.value
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


/// Apply a delta to a section page and publish it. Page 0 accepts full
/// manifest deltas (`ChatBoardStateV1Delta`); extra pages (`page > 0`) accept
/// compact topic entry deltas (`SectionPageDeltaV1`).
pub async fn apply_section_delta(
    owner: VerifyingKey,
    section: SectionId,
    page: u32,
    delta: ChatBoardStateV1Delta,
) -> Result<(), String> {
    let key = section_page_key(owner, section, page);
    let contract_id = *key.id();
    if !SECTION_BOARDS
        .read()
        .get(&contract_id)
        .map(|board| board.synced)
        .unwrap_or(false)
    {
        ensure_section_page_loaded(owner, section, page).await?;
    }

    if page > 0 {
        let page_state = SECTION_BOARDS
            .read()
            .get(&contract_id)
            .and_then(|board| board.state.as_compact_page().cloned())
            .ok_or("the section page is not loaded")?;
        let entries = delta
            .topics
            .as_ref()
            .map(|topics| topics.entries.clone())
            .unwrap_or_default();
        if entries.is_empty() {
            return Ok(());
        }
        let parent_state = {
            let boards = crate::components::app::BOARDS.read();
            boards.map.get(&owner).map(|board| board.board_state.clone())
        };
        let page_delta =
            build_compact_page_delta(owner, parent_state.as_ref(), &page_state, entries);
        let section_params = SectionParametersV1 {
            owner,
            section,
            page,
        };
        let mut next = page_state;
        next.apply_delta(&section_params, &page_delta)
            .map_err(|error| format!("apply compact section page delta: {error}"))?;
        SECTION_BOARDS.with_mut(|boards| {
            if let Some(board) = boards.get_mut(&contract_id) {
                board.state = SectionBoardState::CompactPage(next);
                board.synced = false;
                board.dirty = true;
                board.last_used = now_ms();
            }
        });
        schedule_section_save();
        let bytes = to_cbor_vec(&page_delta);
        let result = send_client_request(ClientRequest::ContractOp(ContractRequest::Update {
            key,
            data: UpdateData::Delta(bytes.into()),
        }))
        .await;
        SECTION_BOARDS.with_mut(|boards| {
            if let Some(board) = boards.get_mut(&contract_id) {
                board.dirty = true;
            }
        });
        return result.map_err(|error| format!("send section page delta: {error}"));
    }

    let parent = SECTION_BOARDS
        .read()
        .get(&contract_id)
        .and_then(|board| board.state.as_manifest().cloned())
        .ok_or("the section board is not loaded")?;
    let delta = {
        let boards = crate::components::app::BOARDS.read();
        match boards.map.get(&owner) {
            Some(board) => with_section_records(owner, &board.board_state, &parent, delta),
            None => delta,
        }
    };
    let mut state = parent.clone();
    let board_params = ChatBoardParametersV1 { owner };
    state
        .apply_delta(&parent, &board_params, &Some(delta.clone()))
        .map_err(|error| format!("apply section delta: {error}"))?;
    if delta.members.is_some()
        || delta.roles.is_some()
        || delta.bans.is_some()
        || delta.ban_revocations.is_some()
        || delta.suspensions.is_some()
    {
        state
            .verify_with_section(&board_params, Some(section))
            .map_err(|error| format!("section delta does not verify: {error}"))?;
    }
    SECTION_BOARDS.with_mut(|boards| {
        if let Some(board) = boards.get_mut(&contract_id) {
            board.state = SectionBoardState::Manifest(state);
            #[cfg(feature = "no-sync")]
            {
                board.synced = true;
                board.ready = true;
                board.dirty = false;
            }
            #[cfg(not(feature = "no-sync"))]
            {
                board.synced = false;
                board.dirty = true;
            }
            board.last_used = now_ms();
        }
    });
    #[cfg(feature = "no-sync")]
    {
        let _ = (key, delta);
        return Ok(());
    }
    #[cfg(not(feature = "no-sync"))]
    {
    schedule_section_save();
    if delta.is_activity_only() {
        if let Some(topics) = delta.topics.as_ref() {
            queue_section_activity(contract_id, key, topics.activity.clone());
        }
        return Ok(());
    }
    let bytes = to_cbor_vec(&delta);
    let result = send_client_request(ClientRequest::ContractOp(ContractRequest::Update {
        key,
        data: UpdateData::Delta(bytes.into()),
    }))
    .await;
    SECTION_BOARDS.with_mut(|boards| {
        if let Some(board) = boards.get_mut(&contract_id) {
            board.dirty = true;
        }
    });
    result.map_err(|error| format!("send section delta: {error}"))
    }
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

/// Build a section manifest (page 0) from the parent board and publish it.
pub async fn create_section_board(
    owner: VerifyingKey,
    section: &AuthorizedSectionV1,
    parent: &ChatBoardStateV1,
    topic_pages: Option<AuthorizedTopicPageListV1>,
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
        sections
            .sections
            .sort_by_key(|entry| (*entry.section.id.as_bytes(), entry.section.generation));
    }
    child.sections = sections.chain_only(&section_id);
    child.topics = TopicIndexV1::default();
    child.authority_root = Default::default();
    child.topic_pages = plaza_core::board_state::pages::TopicPageListV1(topic_pages);
    child.invites = Default::default();
    child.member_info = Default::default();
    // Only retain the tiny subset of members/invites/roles required to verify
    // an ownership transfer chain; never copy the full board member list.
    if parent.ownership.transfers.is_empty() {
        child.members = Default::default();
        child.roles = Default::default();
    } else {
        let transfer_ids = ownership_referenced_members(&parent.ownership);
        let members = collect_members_with_ancestors(owner, parent, &transfer_ids, &HashSet::new());
        let invites = relevant_invites_for_members(owner, parent, &HashSet::new(), &members);
        let mut roles = RolesDelta {
            roles: Vec::new(),
            assignments: Vec::new(),
        };
        add_token_roles(parent, &invites, &mut roles);
        child.members = plaza_core::board_state::member::MembersV1 { members };
        child.invites = plaza_core::board_state::invites::InviteTokensV1 { tokens: invites };
        child.roles = plaza_core::board_state::roles::RolesV1 {
            roles: roles.roles,
            assignments: roles.assignments,
        };
    }
    child.bans = Default::default();
    child.ban_revocations = Default::default();
    child.suspensions = Default::default();
    child.category_secrets = Default::default();
    child.secrets = Default::default();
    child.pq_secrets = Default::default();
    child.warnings = Default::default();
    child.image_retirements = Default::default();
    child.upgrade = Default::default();
    child.mail_addresses = Default::default();

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

    let params = SectionParametersV1 {
        owner,
        section: section_id,
        page: 0,
    };
    let contract = ContractContainer::from(ContractWasmAPIVersion::V1(WrappedContract::new(
        Arc::new(ContractCode::from(SECTION_CONTRACT_WASM)),
        Parameters::from(to_cbor_vec(&params)),
    )));
    let state = WrappedState::new(to_cbor_vec(&child));
    SECTION_BOARDS.with_mut(|boards| {
        #[allow(unused_mut)]
        let mut entry = SectionBoard::new(params.clone(), SectionBoardState::Manifest(child), true);
        #[cfg(feature = "no-sync")]
        {
            entry.synced = true;
            entry.ready = true;
            entry.dirty = false;
        }
        boards.insert(child_id, entry);
    });
    #[cfg(feature = "no-sync")]
    {
        let _ = (contract, state);
        return Ok(key);
    }
    #[cfg(not(feature = "no-sync"))]
    {
    schedule_section_save();
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
}


pub async fn handle_contract_response(response: ContractResponse) -> Result<(), String> {
    match response {
        ContractResponse::GetResponse { key, state, .. } => {
            let Some((section_params, cached, dirty)) =
                SECTION_BOARDS.read().get(key.id()).map(|board| {
                    (board.params.clone(), board.state.clone(), board.dirty)
                })
            else {
                return Err("unknown section board".to_string());
            };

            if section_params.page > 0 {
                let network = ciborium::de::from_reader::<SectionPageStateV1, _>(state.as_ref())
                    .map_err(|error| format!("decode compact section page: {error}"))?;
                network
                    .verify(&section_params)
                    .map_err(|error| format!("compact section page does not verify: {error}"))?;
                let next = if dirty {
                    if let SectionBoardState::CompactPage(cached_page) = cached {
                        let mut merged = cached_page;
                        match merged.merge(&section_params, &network) {
                            Ok(()) => merged,
                            Err(error) => {
                                dioxus::logger::tracing::warn!(
                                    "could not merge compact section page: {error}"
                                );
                                network
                            }
                        }
                    } else {
                        network
                    }
                } else {
                    network
                };
                SECTION_BOARDS.with_mut(|boards| {
                    if let Some(board) = boards.get_mut(key.id()) {
                        board.state = SectionBoardState::CompactPage(next);
                        board.synced = true;
                        board.ready = true;
                        board.last_used = now_ms();
                        board.last_fetch = 0;
                        board.dirty = dirty;
                    }
                });
                schedule_section_save();
                return Ok(());
            }

            let owner = section_params.owner;
            let section = section_params.section;
            let network = ciborium::de::from_reader::<ChatBoardStateV1, _>(state.as_ref())
                .map_err(|error| format!("decode section state: {error}"))?;
            let params = ChatBoardParametersV1 { owner };
            network
                .verify_with_section(&params, Some(section))
                .map_err(|error| format!("section state does not verify: {error}"))?;
            let state = if dirty {
                if let SectionBoardState::Manifest(cached_manifest) = cached {
                    let mut merged = cached_manifest.clone();
                    match merged.merge(&cached_manifest, &params, &network) {
                        Ok(()) => {
                            if let Err(error) = merged.verify_with_section(&params, Some(section)) {
                                dioxus::logger::tracing::warn!(
                                    "ignoring an unverifiable cached section state: {error}"
                                );
                                network
                            } else {
                                merged
                            }
                        }
                        Err(error) => {
                            dioxus::logger::tracing::warn!(
                                "could not merge cached section state: {error}"
                            );
                            network
                        }
                    }
                } else {
                    network
                }
            } else {
                network
            };
            state
                .verify_with_section(&params, Some(section))
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
                    board.state = SectionBoardState::Manifest(state);
                    board.synced = true;
                    board.last_used = now_ms();
                    board.last_fetch = 0;
                    board.dirty = dirty;
                }
            });
            schedule_section_save();
            if let Some(parent_state) = parent_state {
                if parent_state.mode == BoardModeV1::SectionedTopicIndex {
                    crate::util::safe_spawn_local(async move {
                        let _ = sync_section_authority(owner, section, &parent_state).await;
                    });
                }
            }
        }
        ContractResponse::PutResponse { key }
        | ContractResponse::UpdateResponse { key, .. }
        | ContractResponse::SubscribeResponse { key, .. } => {
            SECTION_BOARDS.with_mut(|boards| {
                if let Some(board) = boards.get_mut(key.id()) {
                    board.synced = true;
                    board.dirty = false;
                    if board.params.page > 0 {
                        board.ready = true;
                    }
                    board.last_used = now_ms();
                    board.last_fetch = 0;
                }
            });
        }
        ContractResponse::UpdateNotification { key, update } => {
            let Some((section_params, current_state, dirty)) =
                SECTION_BOARDS.read().get(key.id()).map(|board| {
                    (board.params.clone(), board.state.clone(), board.dirty)
                })
            else {
                return Err("unknown section board".to_string());
            };

            if section_params.page > 0 {
                let mut page_state = match current_state {
                    SectionBoardState::CompactPage(page) => page,
                    SectionBoardState::Manifest(_) => SectionPageStateV1::default(),
                };
                match update {
                    UpdateData::State(bytes) => {
                        if !bytes.as_ref().is_empty() {
                            let network: SectionPageStateV1 =
                                ciborium::de::from_reader(bytes.as_ref()).map_err(|error| {
                                    format!("decode compact section page update: {error}")
                                })?;
                            network.verify(&section_params).map_err(|error| {
                                format!("compact section page update does not verify: {error}")
                            })?;
                            if dirty {
                                page_state.merge(&section_params, &network).map_err(|error| {
                                    format!("merge compact section page update: {error}")
                                })?;
                            } else {
                                page_state = network;
                            }
                        }
                    }
                    UpdateData::Delta(bytes) => {
                        if !bytes.as_ref().is_empty() {
                            let delta: SectionPageDeltaV1 =
                                ciborium::de::from_reader(bytes.as_ref()).map_err(|error| {
                                    format!("decode compact section page delta: {error}")
                                })?;
                            page_state
                                .apply_delta(&section_params, &delta)
                                .map_err(|error| {
                                    format!("apply compact section page delta: {error}")
                                })?;
                        }
                    }
                    UpdateData::StateAndDelta { state, delta } => {
                        if !state.as_ref().is_empty() {
                            let network: SectionPageStateV1 =
                                ciborium::de::from_reader(state.as_ref()).map_err(|error| {
                                    format!("decode compact section page state: {error}")
                                })?;
                            network.verify(&section_params).map_err(|error| {
                                format!("compact section page state does not verify: {error}")
                            })?;
                            page_state.merge(&section_params, &network).map_err(|error| {
                                format!("merge compact section page state: {error}")
                            })?;
                        }
                        if !delta.as_ref().is_empty() {
                            let delta: SectionPageDeltaV1 =
                                ciborium::de::from_reader(delta.as_ref()).map_err(|error| {
                                    format!("decode compact section page delta: {error}")
                                })?;
                            page_state
                                .apply_delta(&section_params, &delta)
                                .map_err(|error| {
                                    format!("apply compact section page delta: {error}")
                                })?;
                        }
                    }
                    _ => {}
                }
                SECTION_BOARDS.with_mut(|boards| {
                    if let Some(board) = boards.get_mut(key.id()) {
                        board.state = SectionBoardState::CompactPage(page_state);
                        board.synced = true;
                        board.ready = true;
                        board.last_used = now_ms();
                        board.last_fetch = 0;
                    }
                });
                schedule_section_save();
                return Ok(());
            }

            let params = ChatBoardParametersV1 {
                owner: section_params.owner,
            };
            let mut state = match current_state {
                SectionBoardState::Manifest(manifest) => manifest,
                SectionBoardState::CompactPage(_) => ChatBoardStateV1::default(),
            };
            match update {
                UpdateData::State(bytes) => {
                    let network = ciborium::de::from_reader(bytes.as_ref())
                        .map_err(|error| format!("decode section update: {error}"))?;
                    let cached = state.clone();
                    if dirty {
                        let mut merged = cached.clone();
                        match merged.merge(&cached, &params, &network) {
                            Ok(()) => {
                                if let Err(error) =
                                    merged.verify_with_section(&params, Some(section_params.section))
                                {
                                    dioxus::logger::tracing::warn!(
                                        "ignoring an unverifiable merged section notification: {error}"
                                    );
                                    state = network;
                                } else {
                                    state = merged;
                                }
                            }
                            Err(error) => {
                                dioxus::logger::tracing::warn!(
                                    "could not merge section notification: {error}"
                                );
                                state = network;
                            }
                        }
                    } else {
                        state = network;
                    }
                }
                UpdateData::Delta(bytes) => {
                    if !bytes.as_ref().is_empty() {
                        let delta = ciborium::de::from_reader(bytes.as_ref())
                            .map_err(|error| format!("decode section delta: {error}"))?;
                        let parent = state.clone();
                        state
                            .apply_delta(&parent, &params, &Some(delta))
                            .map_err(|error| format!("apply section delta: {error}"))?;
                    }
                }
                UpdateData::StateAndDelta {
                    state: state_bytes,
                    delta: delta_bytes,
                } => {
                    if !state_bytes.as_ref().is_empty() {
                        let network = ciborium::de::from_reader(state_bytes.as_ref())
                            .map_err(|error| format!("decode section state: {error}"))?;
                        let cached = state.clone();
                        state
                            .merge(&cached, &params, &network)
                            .map_err(|error| format!("merge section state: {error}"))?;
                    }
                    if !delta_bytes.as_ref().is_empty() {
                        let delta = ciborium::de::from_reader(delta_bytes.as_ref())
                            .map_err(|error| format!("decode section delta: {error}"))?;
                        let parent = state.clone();
                        state
                            .apply_delta(&parent, &params, &Some(delta))
                            .map_err(|error| format!("apply section delta: {error}"))?;
                    }
                }
                _ => {}
            }
            state
                .verify_with_section(&params, Some(section_params.section))
                .map_err(|error| format!("section update does not verify: {error}"))?;
            SECTION_BOARDS.with_mut(|boards| {
                if let Some(board) = boards.get_mut(key.id()) {
                    board.state = SectionBoardState::Manifest(state);
                    board.synced = true;
                    board.last_used = now_ms();
                    board.last_fetch = 0;
                }
            });
            schedule_section_save();
        }
        _ => {}
    }
    Ok(())
}
