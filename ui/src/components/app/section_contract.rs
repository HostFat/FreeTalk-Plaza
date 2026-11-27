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

/// Members whose records a section manifest needs: topic authors, activity
/// signers, flag moderators, reporters, report resolvers, and any ownership
/// transfer targets/voters.
fn section_member_ids(state: &ChatBoardStateV1, parent: &ChatBoardStateV1) -> HashSet<MemberId> {
    let mut ids = HashSet::new();
    for entry in &state.topics.entries {
        ids.insert(entry.entry.author);
    }
    for entry in &state.topics.activity {
        if let Some(signer) = entry.signer {
            ids.insert(signer);
        }
    }
    for entry in &state.topics.flags {
        if let Some(signer) = entry.signer {
            ids.insert(signer);
        }
    }
    for entry in &state.topics.reports {
        ids.insert(entry.report.reporter);
    }
    for entry in &state.topics.report_resolutions {
        ids.insert(entry.resolution.resolved_by);
    }
    ids.extend(ownership_referenced_members(&parent.ownership));
    ids
}

fn delta_member_ids(delta: &ChatBoardStateV1Delta, owner_id: MemberId) -> HashSet<MemberId> {
    let mut ids = HashSet::new();
    if let Some(topics) = &delta.topics {
        for entry in &topics.entries {
            ids.insert(entry.entry.author);
        }
        for entry in &topics.activity {
            if let Some(signer) = entry.signer {
                ids.insert(signer);
            }
        }
        for entry in &topics.flags {
            if let Some(signer) = entry.signer {
                ids.insert(signer);
            }
        }
        for entry in &topics.reports {
            ids.insert(entry.report.reporter);
        }
        for entry in &topics.report_resolutions {
            ids.insert(entry.resolution.resolved_by);
        }
    }
    ids.remove(&owner_id);
    ids
}

/// Resolve the `AuthorizedMember` records for `ids` plus their invite-chain
/// ancestors from both `parent.members` and loaded `member_contract` shards,
/// skipping any member already in `known`.
fn collect_members_with_ancestors(
    owner: VerifyingKey,
    parent: &ChatBoardStateV1,
    ids: &HashSet<MemberId>,
    known: &HashSet<MemberId>,
) -> Vec<AuthorizedMember> {
    let owner_id = MemberId::from(&owner);
    let mut merged = parent.members.clone();
    crate::components::app::member_contract::apply_to_members(owner, parent, &mut merged);
    let by_id: HashMap<MemberId, AuthorizedMember> = merged
        .members
        .into_iter()
        .map(|m| (m.member.id(), m))
        .collect();

    let mut added = Vec::new();
    let mut added_ids: HashSet<MemberId> = HashSet::new();
    let mut stack: Vec<MemberId> = ids.iter().copied().collect();

    while let Some(id) = stack.pop() {
        if id == owner_id || known.contains(&id) || !added_ids.insert(id) {
            continue;
        }
        if let Some(member) = by_id.get(&id) {
            if member.member.join_proof.is_none()
                && member.member.invited_by != owner_id
                && member.member.invited_by != id
            {
                stack.push(member.member.invited_by);
            }
            added.push(member.clone());
        }
        if let Some(entry) = crate::components::app::member_contract::find_member_entry(owner, id) {
            if !by_id.contains_key(&id) {
                added.push(entry.member);
            }
            for ancestor in entry.invite_chain {
                let anc_id = ancestor.member.id();
                if anc_id != owner_id && !known.contains(&anc_id) && added_ids.insert(anc_id) {
                    added.push(ancestor);
                }
            }
        } else if !by_id.contains_key(&id) {
            let local = crate::components::app::BOARDS
                .read()
                .map
                .get(&owner)
                .and_then(|board| {
                    board
                        .self_authorized_member
                        .as_ref()
                        .filter(|member| member.member.id() == id)
                        .map(|member| (member.clone(), board.invite_chain.clone()))
                });
            if let Some((member, chain)) = local {
                added.push(member);
                for ancestor in chain {
                    let anc_id = ancestor.member.id();
                    if anc_id != owner_id && !known.contains(&anc_id) && added_ids.insert(anc_id) {
                        added.push(ancestor);
                    }
                }
            }
        }
    }
    added
}

fn relevant_roles(parent: &ChatBoardStateV1, ids: &HashSet<MemberId>) -> RolesDelta {
    let mut roles: Vec<AuthorizedRole> = Vec::new();
    let mut assignments: Vec<AuthorizedRoleAssignment> = Vec::new();
    let mut role_ids = HashSet::new();
    for id in ids {
        for role in parent.roles.active_roles_of(id) {
            role_ids.insert(role.id);
        }
        assignments.extend(
            parent
                .roles
                .assignments
                .iter()
                .filter(|assignment| assignment.assignment.member_id == *id)
                .cloned(),
        );
    }
    for entry in &parent.roles.roles {
        if role_ids.contains(&entry.role.id) {
            roles.push(entry.clone());
        }
    }
    RolesDelta { roles, assignments }
}

/// A token-joined member carries the join proof; the section child checks it
/// against the token record, so the token must travel with the member.
fn relevant_invites_for_members(
    owner: VerifyingKey,
    parent: &ChatBoardStateV1,
    known_tokens: &HashSet<[u8; 16]>,
    members: &[AuthorizedMember],
) -> Vec<AuthorizedInviteToken> {
    let mut tokens = Vec::new();
    for member in members {
        let Some(proof) = member.member.join_proof.as_ref() else {
            continue;
        };
        if known_tokens.contains(&proof.token_id) {
            continue;
        }
        let token = parent
            .invites
            .tokens
            .iter()
            .find(|t| t.token.id == proof.token_id)
            .cloned()
            .or_else(|| {
                crate::components::app::member_contract::find_member_entry(owner, member.member.id())
                    .and_then(|entry| entry.invite_token)
            });
        if let Some(token) = token {
            if !tokens
                .iter()
                .any(|existing: &AuthorizedInviteToken| existing.token.id == token.token.id)
            {
                tokens.push(token);
            }
        }
    }
    tokens
}

fn relevant_invites(
    owner: VerifyingKey,
    parent: &ChatBoardStateV1,
    child: &ChatBoardStateV1,
    ids: &HashSet<MemberId>,
    extra_members: &[AuthorizedMember],
) -> Vec<AuthorizedInviteToken> {
    let known: HashSet<[u8; 16]> = child
        .invites
        .tokens
        .iter()
        .map(|token| token.token.id)
        .collect();
    let mut candidates: Vec<AuthorizedMember> = parent
        .members
        .members
        .iter()
        .filter(|member| ids.contains(&member.member.id()))
        .cloned()
        .collect();
    candidates.extend(extra_members.iter().cloned());
    relevant_invites_for_members(owner, parent, &known, &candidates)
}

fn add_token_roles(
    parent: &ChatBoardStateV1,
    invites: &[AuthorizedInviteToken],
    roles: &mut RolesDelta,
) {
    for token in invites {
        if let Some(role) = parent
            .roles
            .roles
            .iter()
            .find(|role| role.role.id == token.token.role_id)
        {
            if !roles
                .roles
                .iter()
                .any(|existing| existing.role.id == role.role.id)
            {
                roles.roles.push(role.clone());
            }
        }
    }
}

fn relevant_bans(parent: &ChatBoardStateV1, ids: &HashSet<MemberId>) -> Vec<AuthorizedUserBan> {
    parent
        .bans
        .0
        .iter()
        .filter(|ban| ids.contains(&ban.ban.banned_user))
        .cloned()
        .collect()
}

fn relevant_revocations(
    parent: &ChatBoardStateV1,
    ids: &HashSet<MemberId>,
) -> Vec<AuthorizedBanRevocation> {
    parent
        .ban_revocations
        .revocations
        .iter()
        .filter(|revocation| ids.contains(&revocation.revocation.banned_user))
        .cloned()
        .collect()
}

fn relevant_suspensions(
    parent: &ChatBoardStateV1,
    ids: &HashSet<MemberId>,
) -> Vec<AuthorizedSuspension> {
    parent
        .suspensions
        .suspensions
        .iter()
        .filter(|suspension| ids.contains(&suspension.suspension.target))
        .cloned()
        .collect()
}

/// Add the member, role and moderation records that a manifest delta needs to
/// verify its new topic/flag records.
fn with_section_records(
    owner: VerifyingKey,
    parent: &ChatBoardStateV1,
    child: &ChatBoardStateV1,
    mut delta: ChatBoardStateV1Delta,
) -> ChatBoardStateV1Delta {
    let owner_id = MemberId::from(&owner);
    let ids = delta_member_ids(&delta, owner_id);
    if ids.is_empty() {
        return delta;
    }
    let known: HashSet<MemberId> = child
        .members
        .members
        .iter()
        .map(|member| member.member.id())
        .collect();
    let added = collect_members_with_ancestors(owner, parent, &ids, &known);
    let invites = relevant_invites(owner, parent, child, &ids, &added);
    if !added.is_empty() {
        delta.members = Some(MembersDelta::new(added));
    }
    let mut roles = relevant_roles(parent, &ids);
    add_token_roles(parent, &invites, &mut roles);
    if !invites.is_empty() {
        delta.invites = Some(InviteTokensDelta { tokens: invites });
    }
    let new_roles: Vec<_> = roles
        .roles
        .into_iter()
        .filter(|role| {
            !child.roles.roles.iter().any(|known| {
                known.role.id == role.role.id
                    && known.role.generation == role.role.generation
                    && known.role.deleted == role.role.deleted
            })
        })
        .collect();
    let new_assignments: Vec<_> = roles
        .assignments
        .into_iter()
        .filter(|assignment| {
            !child.roles.assignments.iter().any(|known| {
                known.assignment.role_id == assignment.assignment.role_id
                    && known.assignment.member_id == assignment.assignment.member_id
                    && known.assignment.generation == assignment.assignment.generation
                    && known.assignment.revoked == assignment.assignment.revoked
            })
        })
        .collect();
    if !new_roles.is_empty() || !new_assignments.is_empty() {
        delta.roles = Some(RolesDelta {
            roles: new_roles,
            assignments: new_assignments,
        });
    }
    let bans: Vec<_> = relevant_bans(parent, &ids)
        .into_iter()
        .filter(|ban| !child.bans.0.iter().any(|known| known.id() == ban.id()))
        .collect();
    if !bans.is_empty() {
        delta.bans = Some(bans);
    }
    let revocations: Vec<_> = relevant_revocations(parent, &ids)
        .into_iter()
        .filter(|revocation| {
            !child
                .ban_revocations
                .revocations
                .iter()
                .any(|known| known.revocation.ban_id == revocation.revocation.ban_id)
        })
        .collect();
    if !revocations.is_empty() {
        delta.ban_revocations = Some(revocations);
    }
    let suspensions: Vec<_> = relevant_suspensions(parent, &ids)
        .into_iter()
        .filter(|suspension| {
            !child.suspensions.suspensions.iter().any(|known| {
                known.suspension.target == suspension.suspension.target
                    && known.suspension.generation == suspension.suspension.generation
            })
        })
        .collect();
    if !suspensions.is_empty() {
        delta.suspensions = Some(SuspensionsDelta { suspensions });
    }
    delta
}

/// Sync parent authority to page 0 (the section manifest) only. Compact extra
/// pages (`page > 0`) do not duplicate board authority and never receive
/// authority syncs.
pub async fn sync_section_authority(
    owner: VerifyingKey,
    section: SectionId,
    parent: &ChatBoardStateV1,
) -> Result<(), String> {
    let loaded = SECTION_BOARDS
        .read()
        .get(section_page_key(owner, section, 0).id())
        .map(|board| board.synced)
        .unwrap_or(false);
    if loaded {
        sync_section_page_authority(owner, section, parent).await?;
    }
    Ok(())
}

async fn sync_section_page_authority(
    owner: VerifyingKey,
    section: SectionId,
    parent: &ChatBoardStateV1,
) -> Result<(), String> {
    let key = section_page_key(owner, section, 0);
    let contract_id = *key.id();
    let Some((child, synced, syncing)) = SECTION_BOARDS
        .read()
        .get(&contract_id)
        .and_then(|board| {
            board
                .state
                .as_manifest()
                .map(|manifest| (manifest.clone(), board.synced, board.syncing))
        })
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
    let board_params = ChatBoardParametersV1 { owner };
    let ids = section_member_ids(&child, parent);

    // Admin and ownership changes are rare and touch the whole chain; keep the
    // full-state path for them, but prune members/roles/bans/suspensions to
    // only the records this manifest and its ownership chain actually need.
    let full_state = parent.admin != child.admin || parent.ownership != child.ownership;
    let mut state = child.clone();
    let data = if full_state {
        state.configuration = parent.configuration.clone();
        state.admin = parent.admin.clone();
        state.ownership = parent.ownership.clone();
        state.sections = parent.sections.chain_only(&section);
        state.authority_root = Default::default();
        let members = collect_members_with_ancestors(owner, parent, &ids, &HashSet::new());
        let invites = relevant_invites_for_members(owner, parent, &HashSet::new(), &members);
        let mut roles = relevant_roles(parent, &ids);
        add_token_roles(parent, &invites, &mut roles);
        state.members = plaza_core::board_state::member::MembersV1 { members };
        state.invites = plaza_core::board_state::invites::InviteTokensV1 { tokens: invites };
        state.roles = plaza_core::board_state::roles::RolesV1 {
            roles: roles.roles,
            assignments: roles.assignments,
        };
        state.bans = plaza_core::board_state::ban::BansV1(relevant_bans(parent, &ids));
        state.ban_revocations = plaza_core::board_state::ban::BanRevocationsV1 {
            revocations: relevant_revocations(parent, &ids),
        };
        state.suspensions = plaza_core::board_state::member_moderation::SuspensionsV1 {
            suspensions: relevant_suspensions(parent, &ids),
        };
        state
            .verify_with_section(&board_params, Some(section))
            .map_err(|error| format!("section authority does not verify: {error}"))?;
        UpdateData::State(to_cbor_vec(&state).into())
    } else {
        let mut delta = ChatBoardStateV1Delta::default();
        if parent.configuration != child.configuration {
            delta.configuration = Some(parent.configuration.clone());
        }
        let wanted_sections = parent.sections.chain_only(&section);
        if wanted_sections != child.sections {
            delta.sections = Some(SectionsDelta {
                sections: wanted_sections.sections,
            });
        }
        let known: HashSet<MemberId> = child
            .members
            .members
            .iter()
            .map(|member| member.member.id())
            .collect();
        let added = collect_members_with_ancestors(owner, parent, &ids, &known);
        let invites = relevant_invites(owner, parent, &child, &ids, &added);
        if !added.is_empty() {
            delta.members = Some(MembersDelta::new(added));
        }
        let mut roles = relevant_roles(parent, &ids);
        add_token_roles(parent, &invites, &mut roles);
        if !invites.is_empty() {
            delta.invites = Some(InviteTokensDelta { tokens: invites });
        }
        let new_roles: Vec<_> = roles
            .roles
            .into_iter()
            .filter(|role| {
                !child.roles.roles.iter().any(|known| {
                    known.role.id == role.role.id
                        && known.role.generation == role.role.generation
                        && known.role.deleted == role.role.deleted
                })
            })
            .collect();
        let new_assignments: Vec<_> = roles
            .assignments
            .into_iter()
            .filter(|assignment| {
                !child.roles.assignments.iter().any(|known| {
                    known.assignment.role_id == assignment.assignment.role_id
                        && known.assignment.member_id == assignment.assignment.member_id
                        && known.assignment.generation == assignment.assignment.generation
                        && known.assignment.revoked == assignment.assignment.revoked
                })
            })
            .collect();
        if !new_roles.is_empty() || !new_assignments.is_empty() {
            delta.roles = Some(RolesDelta {
                roles: new_roles,
                assignments: new_assignments,
            });
        }
        let bans: Vec<_> = relevant_bans(parent, &ids)
            .into_iter()
            .filter(|ban| !child.bans.0.iter().any(|known| known.id() == ban.id()))
            .collect();
        if !bans.is_empty() {
            delta.bans = Some(bans);
        }
        let revocations: Vec<_> = relevant_revocations(parent, &ids)
            .into_iter()
            .filter(|revocation| {
                !child
                    .ban_revocations
                    .revocations
                    .iter()
                    .any(|known| known.revocation.ban_id == revocation.revocation.ban_id)
            })
            .collect();
        if !revocations.is_empty() {
            delta.ban_revocations = Some(revocations);
        }
        let suspensions: Vec<_> = relevant_suspensions(parent, &ids)
            .into_iter()
            .filter(|suspension| {
                !child.suspensions.suspensions.iter().any(|known| {
                    known.suspension.target == suspension.suspension.target
                        && known.suspension.generation == suspension.suspension.generation
                })
            })
            .collect();
        if !suspensions.is_empty() {
            delta.suspensions = Some(SuspensionsDelta { suspensions });
        }
        let has_changes = delta.configuration.is_some()
            || delta.sections.is_some()
            || delta.members.is_some()
            || delta.invites.is_some()
            || delta.roles.is_some()
            || delta.bans.is_some()
            || delta.ban_revocations.is_some()
            || delta.suspensions.is_some();
        if !has_changes {
            SECTION_BOARDS.with_mut(|boards| {
                if let Some(board) = boards.get_mut(&contract_id) {
                    board.syncing = false;
                    board.ready = true;
                    board.last_used = now_ms();
                }
            });
            return Ok(());
        }
        state
            .apply_delta(&child, &board_params, &Some(delta.clone()))
            .map_err(|error| format!("apply section authority: {error}"))?;
        state
            .verify_delta(&delta, &board_params)
            .map_err(|error| format!("section authority does not verify: {error}"))?;
        if state
            .topics
            .entries
            .iter()
            .any(|entry| entry.entry.section != Some(section))
        {
            return Err("section authority put a topic in another section".to_string());
        }
        UpdateData::Delta(to_cbor_vec(&delta).into())
    };

    SECTION_BOARDS.with_mut(|boards| {
        if let Some(board) = boards.get_mut(&contract_id) {
            board.state = SectionBoardState::Manifest(state.clone());
            board.synced = true;
            board.ready = false;
            board.dirty = true;
            board.last_used = now_ms();
        }
    });
    schedule_section_save();
    let result = send_client_request(ClientRequest::ContractOp(ContractRequest::Update {
        key,
        data,
    }))
    .await;
    SECTION_BOARDS.with_mut(|boards| {
        if let Some(board) = boards.get_mut(&contract_id) {
            board.syncing = false;
            board.ready = result.is_ok();
            // The UpdateResponse clears this; until then a Get that still has
            // the older authority must not replace the local copy.
            board.dirty = true;
        }
    });
    result.map_err(|error| format!("send section authority: {error}"))
}

/// Build a compact [`SectionPageDeltaV1`] for `page > 0` from topic entries,
/// attaching only the minimal author/invite/role records missing from `page_state`.
fn build_compact_page_delta(
    owner: VerifyingKey,
    parent: Option<&ChatBoardStateV1>,
    page_state: &SectionPageStateV1,
    entries: Vec<plaza_core::board_state::topics::AuthorizedTopicEntryV1>,
) -> SectionPageDeltaV1 {
    if page_state.is_sealed() {
        return SectionPageDeltaV1 {
            entry_edits: entries,
            ..Default::default()
        };
    }
    let owner_id = MemberId::from(&owner);
    let mut author_ids: HashSet<MemberId> = entries
        .iter()
        .map(|entry| entry.entry.author)
        .collect();
    author_ids.remove(&owner_id);

    let mut delta = SectionPageDeltaV1 {
        entries,
        ..Default::default()
    };
    let Some(parent) = parent else {
        return delta;
    };
    if author_ids.is_empty() {
        return delta;
    }

    let known_authors: HashSet<MemberId> = page_state
        .authors
        .iter()
        .map(|m| m.member.id())
        .collect();
    let authors = collect_members_with_ancestors(owner, parent, &author_ids, &known_authors);
    let known_tokens: HashSet<[u8; 16]> = page_state.invites.iter().map(|t| t.token.id).collect();
    let invites = relevant_invites_for_members(owner, parent, &known_tokens, &authors);

    let needs_roles = page_state
        .header
        .as_ref()
        .is_some_and(|h| !h.header.allowed_roles.is_empty());
    let mut roles = if needs_roles {
        relevant_roles(parent, &author_ids)
    } else {
        RolesDelta {
            roles: Vec::new(),
            assignments: Vec::new(),
        }
    };
    add_token_roles(parent, &invites, &mut roles);

    let new_roles: Vec<_> = roles
        .roles
        .into_iter()
        .filter(|role| {
            !page_state.roles.iter().any(|known| {
                known.role.id == role.role.id
                    && known.role.generation == role.role.generation
                    && known.role.deleted == role.role.deleted
            })
        })
        .collect();
    let new_assignments: Vec<_> = roles
        .assignments
        .into_iter()
        .filter(|assignment| {
            !page_state.role_assignments.iter().any(|known| {
                known.assignment.role_id == assignment.assignment.role_id
                    && known.assignment.member_id == assignment.assignment.member_id
                    && known.assignment.generation == assignment.assignment.generation
                    && known.assignment.revoked == assignment.assignment.revoked
            })
        })
        .collect();

    // Only include admin records when an invite token or role record was
    // signed by a non-owner admin not already present on the page.
    let mut needed_admin_ids: HashSet<MemberId> = HashSet::new();
    for token in &invites {
        if let Some(signer) = token.signer {
            if signer != owner_id {
                needed_admin_ids.insert(signer);
            }
        }
    }
    for role in &new_roles {
        if let Some(signer) = role.signer {
            if signer != owner_id {
                needed_admin_ids.insert(signer);
            }
        }
    }
    for assignment in &new_assignments {
        if let Some(signer) = assignment.signer {
            if signer != owner_id {
                needed_admin_ids.insert(signer);
            }
        }
    }
    if !needed_admin_ids.is_empty() {
        let missing_admins: Vec<_> = parent
            .admin
            .admins
            .iter()
            .filter(|a| {
                needed_admin_ids.contains(&a.admin.id())
                    && !page_state
                        .admin
                        .admins
                        .iter()
                        .any(|known| known.admin.id() == a.admin.id())
            })
            .cloned()
            .collect();
        if !missing_admins.is_empty() {
            delta.admin = Some(AdminsV1 {
                admins: missing_admins,
                revoked: Vec::new(),
            });
        }
    }

    delta.authors = authors;
    delta.invites = invites;
    delta.roles = new_roles;
    delta.role_assignments = new_assignments;
    delta
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

/// Resolve the signing key and optional admin proof for creating or sealing a
/// section page: either the current board owner or an active (non-revoked)
/// board admin.
fn resolve_section_page_signer(
    parent_state: &ChatBoardStateV1,
    owner_sk: Option<SigningKey>,
    current_owner: VerifyingKey,
    self_sk: SigningKey,
) -> Result<(SigningKey, Option<plaza_core::board_state::roles::AuthorityProof>), String> {
    if let Some(key) = owner_sk.filter(|key| key.verifying_key() == current_owner) {
        return Ok((key, None));
    }
    let self_id = MemberId::from(&self_sk.verifying_key());
    let active_admin = parent_state
        .admin
        .admins
        .iter()
        .find(|entry| {
            entry.admin.id() == self_id
                && !parent_state.admin.revoked.iter().any(|rev| {
                    rev.id() == self_id && rev.revocation.generation >= entry.admin.generation
                })
        })
        .cloned();
    if let Some(admin_record) = active_admin {
        return Ok((
            self_sk,
            Some(plaza_core::board_state::roles::AuthorityProof {
                admin: Some(admin_record),
                grant: None,
            }),
        ));
    }
    Err("only the board owner or an active admin can add or seal a section page".to_string())
}

/// Seal a full extra page (`page > 0`) as the board owner or an active admin,
/// compacting away all duplicated author/invite/role records.
async fn seal_section_page(
    owner: VerifyingKey,
    section: SectionId,
    page: u32,
    signer_sk: &SigningKey,
    authority: Option<plaza_core::board_state::roles::AuthorityProof>,
    parent_admins: &AdminsV1,
) -> Result<(), String> {
    if page == 0 {
        return Ok(());
    }
    let key = section_page_key(owner, section, page);
    let contract_id = *key.id();
    let Some(page_state) = SECTION_BOARDS
        .read()
        .get(&contract_id)
        .and_then(|board| board.state.as_compact_page().cloned())
    else {
        return Ok(());
    };
    if page_state.is_sealed() || page_state.entries.is_empty() {
        return Ok(());
    }
    let params = SectionParametersV1 {
        owner,
        section,
        page,
    };
    let seal = AuthorizedSectionPageSealV1::new_with_authority(
        &params,
        &page_state.entries,
        signer_sk,
        authority.clone(),
        now_ms(),
    )?;
    let delta = SectionPageDeltaV1 {
        admin: authority.is_some().then(|| parent_admins.clone()),
        seal: Some(seal),
        ..Default::default()
    };
    let mut next = page_state;
    next.apply_delta(&params, &delta)?;
    SECTION_BOARDS.with_mut(|boards| {
        if let Some(board) = boards.get_mut(&contract_id) {
            board.state = SectionBoardState::CompactPage(next);
            board.dirty = true;
            board.last_used = now_ms();
        }
    });
    schedule_section_save();
    send_client_request(ClientRequest::ContractOp(ContractRequest::Update {
        key,
        data: UpdateData::Delta(to_cbor_vec(&delta).into()),
    }))
    .await
    .map_err(|error| format!("seal section page {page}: {error}"))
}

/// Create the next compact topic-entry page (`page > 0`) of a section, seal
/// any full unsealed previous extra pages, and add the new page to the
/// manifest's signed page list. Both the current owner and active board admins
/// can add and seal pages.
pub async fn create_section_page(owner: VerifyingKey, section: SectionId) -> Result<u32, String> {
    let parent = {
        let boards = crate::components::app::BOARDS.read();
        boards
            .map
            .get(&owner)
            .map(|board| {
                (
                    board.board_state.clone(),
                    board.owner_sk.clone(),
                    board.current_owner_key(),
                    board.self_sk.clone(),
                )
            })
            .ok_or("the board is not loaded")?
    };
    let (parent_state, owner_sk, current_owner, self_sk) = parent;
    let (signer_sk, authority) =
        resolve_section_page_signer(&parent_state, owner_sk, current_owner, self_sk)?;
    let existing_pages = pages_for(owner, section);
    let page_size = page_size_for(owner, section).unwrap_or_else(current_topic_page_size);

    // Compact any full, unsealed extra pages before spilling to the next page.
    for existing in existing_pages.iter().copied().filter(|p| *p > 0) {
        let should_seal = SECTION_BOARDS
            .read()
            .get(section_page_key(owner, section, existing).id())
            .map(|board| {
                board.synced
                    && !board.state.is_sealed()
                    && board.state.entry_count() >= page_size as usize
            })
            .unwrap_or(false);
        if should_seal {
            if let Err(error) = seal_section_page(
                owner,
                section,
                existing,
                &signer_sk,
                authority.clone(),
                &parent_state.admin,
            )
            .await
            {
                dioxus::logger::tracing::warn!("could not seal section page {existing}: {error}");
            }
        }
    }

    let page = existing_pages.iter().copied().max().unwrap_or(0) + 1;
    let key = section_page_key(owner, section, page);
    let contract_id = *key.id();

    let section_data = parent_state
        .sections
        .section(&section)
        .ok_or("the section does not exist")?;
    let section_chain = parent_state.sections.chain(&section);
    let header = AuthorizedSectionPageHeaderV1::new_with_authority(
        SectionPageHeaderV1 {
            board: owner.to_bytes(),
            section,
            section_chain,
            page,
            page_size,
            allowed_roles: section_data.allowed_roles.clone(),
            created_at: now_ms(),
        },
        &signer_sk,
        authority.clone(),
    );

    let mut compact_page = SectionPageStateV1 {
        header: Some(header),
        ..Default::default()
    };
    if authority.is_some() {
        compact_page.admin = parent_state.admin.clone();
    }
    if !parent_state.ownership.transfers.is_empty() {
        compact_page.ownership = parent_state.ownership.clone();
        compact_page.admin = parent_state.admin.clone();
        let transfer_ids = ownership_referenced_members(&parent_state.ownership);
        let authors =
            collect_members_with_ancestors(owner, &parent_state, &transfer_ids, &HashSet::new());
        let invites =
            relevant_invites_for_members(owner, &parent_state, &HashSet::new(), &authors);
        let mut roles = RolesDelta {
            roles: Vec::new(),
            assignments: Vec::new(),
        };
        add_token_roles(&parent_state, &invites, &mut roles);
        compact_page.authors = authors;
        compact_page.invites = invites;
        compact_page.roles = roles.roles;
        compact_page.sort();
    }

    let params = SectionParametersV1 {
        owner,
        section,
        page,
    };
    compact_page
        .verify(&params)
        .map_err(|error| format!("section page does not verify: {error}"))?;

    let contract = ContractContainer::from(ContractWasmAPIVersion::V1(WrappedContract::new(
        Arc::new(ContractCode::from(SECTION_CONTRACT_WASM)),
        Parameters::from(to_cbor_vec(&params)),
    )));
    let encoded_state = WrappedState::new(to_cbor_vec(&compact_page));
    SECTION_BOARDS.with_mut(|boards| {
        let mut board = SectionBoard::new(
            params.clone(),
            SectionBoardState::CompactPage(compact_page),
            true,
        );
        board.ready = true;
        boards.insert(contract_id, board);
    });
    evict_extra_section_pages(contract_id);
    schedule_section_save();
    send_client_request(ClientRequest::ContractOp(ContractRequest::Put {
        contract,
        state: encoded_state,
        related_contracts: Default::default(),
        subscribe: true,
        blocking_subscribe: false,
    }))
    .await
    .map_err(|error| format!("put section page: {error}"))?;

    // The manifest owns the page list.
    let page0_key = section_page_key(owner, section, 0);
    let page0_id = *page0_key.id();
    if !SECTION_BOARDS
        .read()
        .get(&page0_id)
        .map(|board| board.synced)
        .unwrap_or(false)
    {
        let _ = load_section_page(owner, section, 0).await;
    }
    let mut pages = pages_for(owner, section);
    pages.retain(|existing| *existing > 0);
    pages.push(page);
    let list = AuthorizedTopicPageListV1::new_with_authority(
        section,
        pages,
        page_size,
        &signer_sk,
        authority,
        now_ms(),
    );
    SECTION_BOARDS.with_mut(|boards| {
        if let Some(board) = boards.get_mut(&page0_id) {
            if let SectionBoardState::Manifest(manifest) = &mut board.state {
                manifest.topic_pages.0 = Some(list.clone());
            }
            board.dirty = true;
        }
    });
    schedule_section_save();
    send_client_request(ClientRequest::ContractOp(ContractRequest::Update {
        key: page0_key,
        data: UpdateData::Delta(
            to_cbor_vec(&ChatBoardStateV1Delta {
                topic_pages: Some(list),
                ..Default::default()
            })
            .into(),
        ),
    }))
    .await
    .map_err(|error| format!("add the section page to its manifest: {error}"))?;
    Ok(page)
}

pub async fn ensure_section_page_loaded(
    owner: VerifyingKey,
    section: SectionId,
    page: u32,
) -> Result<(), String> {
    if page == 0 {
        return Ok(());
    }
    let key = section_page_key(owner, section, page);
    let contract_id = *key.id();
    for _ in 0..12 {
        if SECTION_BOARDS
            .read()
            .get(&contract_id)
            .map(|board| board.synced)
            .unwrap_or(false)
        {
            return Ok(());
        }
        let _ = load_section_page(owner, section, page).await;
        for _ in 0..10 {
            crate::util::sleep(std::time::Duration::from_millis(200)).await;
            if SECTION_BOARDS
                .read()
                .get(&contract_id)
                .map(|board| board.synced)
                .unwrap_or(false)
            {
                return Ok(());
            }
        }
    }
    Err("the section page is not loaded yet".to_string())
}

/// Choose the active page with room for another topic without fetching older
/// sealed pages. Checks the newest page first, creating a new page when the
/// current active page is full or sealed.
pub async fn active_page(owner: VerifyingKey, section: SectionId) -> Result<u32, String> {
    ensure_section_loaded(owner, section).await?;
    let limit = page_size_for(owner, section).unwrap_or_else(current_topic_page_size) as usize;
    let pages = pages_for(owner, section);

    // Check the newest page first so a section with many sealed archive pages
    // only touches its active tail page.
    if let Some(&last_page) = pages.last() {
        ensure_section_page_loaded(owner, section, last_page).await?;
        let has_room = SECTION_BOARDS
            .read()
            .get(section_page_key(owner, section, last_page).id())
            .map(|board| !board.state.is_sealed() && board.state.entry_count() < limit)
            .unwrap_or(false);
        if has_room {
            return Ok(last_page);
        }
    }
    create_section_page(owner, section).await
}

/// Fetch and subscribe to the section manifest (page 0). Safe to call on every
/// render.
pub async fn load_section_board(
    owner: VerifyingKey,
    section: SectionId,
) -> Result<ContractInstanceId, String> {
    load_section_page(owner, section, 0).await
}

/// Fetch and subscribe to one topic-entry page of a section.
pub async fn load_section_page(
    owner: VerifyingKey,
    section: SectionId,
    page: u32,
) -> Result<ContractInstanceId, String> {
    let key = section_page_key(owner, section, page);
    let contract_id = *key.id();
    let known = SECTION_BOARDS
        .read()
        .get(&contract_id)
        .map(|board| board.synced)
        .unwrap_or(false);
    if known {
        return Ok(contract_id);
    }
    let pending = SECTION_BOARDS
        .read()
        .get(&contract_id)
        .map(|board| !board.synced && now_ms().saturating_sub(board.last_fetch) < 10_000)
        .unwrap_or(false);
    if pending {
        return Ok(contract_id);
    }
    SECTION_BOARDS.with_mut(|boards| {
        if !boards.contains_key(&contract_id) {
            let empty_state = if page == 0 {
                SectionBoardState::Manifest(ChatBoardStateV1::default())
            } else {
                SectionBoardState::CompactPage(SectionPageStateV1::default())
            };
            boards.insert(
                contract_id,
                SectionBoard::new(
                    SectionParametersV1 {
                        owner,
                        section,
                        page,
                    },
                    empty_state,
                    false,
                ),
            );
        }
        if let Some(board) = boards.get_mut(&contract_id) {
            board.last_used = now_ms();
            board.last_fetch = now_ms();
        }
    });
    if page > 0 {
        evict_extra_section_pages(contract_id);
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

/// Load every page listed by the section manifest. Missing pages are fetched
/// with a GET; page 0 is the manifest itself.
pub async fn load_section_pages(owner: VerifyingKey, section: SectionId) -> Result<(), String> {
    load_section_board(owner, section).await?;
    let pages = pages_for(owner, section);
    for page in pages.into_iter().filter(|page| *page > 0) {
        let _ = load_section_page(owner, section, page).await;
    }
    Ok(())
}

/// Drop every extra page from memory and from the delegate blob. Test hook:
/// lets a reload exercise the on-demand page path instead of the persisted
/// cache. Page 0 and the boards themselves are kept.
pub async fn clear_extra_pages() {
    SECTION_BOARDS.with_mut(|boards| {
        boards.retain(|_, board| board.params.page == 0);
    });
    let _ = save_section_boards_now().await;
}

/// Load and wait for every page listed by a section manifest. Views that scan
/// the whole index (search, notifications, moderation) call this explicitly;
/// the board list loads pages on demand.
pub async fn load_all_section_pages(
    owner: VerifyingKey,
    section: SectionId,
) -> Result<(), String> {
    load_section_pages(owner, section).await?;
    for page in pages_for(owner, section)
        .into_iter()
        .filter(|page| *page > 0)
    {
        ensure_section_page_loaded(owner, section, page).await?;
    }
    Ok(())
}

/// Section ids of a loaded board that point to a child contract.
fn board_sections(owner: VerifyingKey) -> Vec<SectionId> {
    let boards = crate::components::app::BOARDS.read();
    boards
        .map
        .get(&owner)
        .map(|board| {
            board
                .board_state
                .sections
                .sections
                .iter()
                .filter(|entry| !entry.section.deleted && entry.section.contract.is_some())
                .map(|entry| entry.section.id)
                .collect()
        })
        .unwrap_or_default()
}

/// Load and wait for every page of every section of a board.
pub async fn load_all_section_pages_for_board(owner: VerifyingKey) -> Result<(), String> {
    for section in board_sections(owner) {
        let _ = load_all_section_pages(owner, section).await;
    }
    Ok(())
}

/// True when the manifest lists a page that is not loaded yet.
pub fn has_more_pages(owner: VerifyingKey) -> bool {
    for section in board_sections(owner) {
        for page in pages_for(owner, section)
            .into_iter()
            .filter(|page| *page > 0)
        {
            let loaded = SECTION_BOARDS
                .read()
                .get(section_page_key(owner, section, page).id())
                .map(|board| board.synced)
                .unwrap_or(false);
            if !loaded {
                return true;
            }
        }
    }
    false
}

/// Send a GET for up to `limit` pages that are not loaded yet. The states
/// arrive asynchronously and the list re-renders when they do.
pub async fn load_next_pages(owner: VerifyingKey, limit: usize) -> Result<usize, String> {
    let mut started = 0;
    for section in board_sections(owner) {
        for page in pages_for(owner, section)
            .into_iter()
            .filter(|page| *page > 0)
        {
            if started >= limit {
                return Ok(started);
            }
            let loaded = SECTION_BOARDS
                .read()
                .get(section_page_key(owner, section, page).id())
                .map(|board| board.synced)
                .unwrap_or(false);
            if loaded {
                continue;
            }
            load_section_page(owner, section, page).await?;
            started += 1;
        }
    }
    Ok(started)
}

pub async fn ensure_section_loaded(owner: VerifyingKey, section: SectionId) -> Result<(), String> {
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
