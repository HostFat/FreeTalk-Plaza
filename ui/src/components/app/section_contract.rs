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
use plaza_core::board_state::ban::{AuthorizedBanRevocation, AuthorizedUserBan};
use plaza_core::board_state::member::{AuthorizedMember, MemberId, MembersDelta};
use plaza_core::board_state::member_moderation::{AuthorizedSuspension, SuspensionsDelta};
use plaza_core::board_state::roles::{AuthorizedRole, AuthorizedRoleAssignment, RolesDelta};
use plaza_core::board_state::sections::{
    AuthorizedSectionV1, SectionId, SectionParametersV1, SectionsDelta,
};
use plaza_core::board_state::topics::{
    AuthorizedTopicActivityV1, TopicIndexDelta, TopicIndexV1,
};
use plaza_core::board_state::{
    BoardModeV1, ChatBoardParametersV1, ChatBoardStateV1, ChatBoardStateV1Delta,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::components::app::chat_delegate::{
    send_delegate_request, SECTION_BOARDS_STORAGE_KEY,
};
use plaza_core::chat_delegate::{
    ChatDelegateKey, ChatDelegateRequestMsg, ChatDelegateResponseMsg,
};
use crate::components::app::send_client_request;
use crate::constants::SECTION_CONTRACT_WASM;
use crate::util::to_cbor_vec;

#[derive(Serialize, Deserialize)]
struct PersistedSectionBoard {
    owner: VerifyingKey,
    section: SectionId,
    state: ChatBoardStateV1,
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

async fn save_section_boards_now() -> Result<(), String> {
    let entries: Vec<PersistedSectionBoard> = SECTION_BOARDS
        .read()
        .values()
        // A placeholder inserted by `load_section_board` has a default state;
        // saving it would restore an invalid child on the next load.
        .filter(|board| board.state.mode == BoardModeV1::SectionedTopicIndex)
        .map(|board| PersistedSectionBoard {
            owner: board.params.owner,
            section: board.params.section,
            state: board.state.clone(),
        })
        .collect();
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
        Ok(ChatDelegateResponseMsg::GetResponse { value: Some(bytes), .. }) => bytes,
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
            // Older blobs could contain a placeholder with the default state;
            // it has no signatures to verify.
            if entry.state.mode != BoardModeV1::SectionedTopicIndex {
                continue;
            }
            let key = section_key(entry.owner, entry.section);
            let contract_id = *key.id();
            let activity = entry.state.topics.activity.clone();
            let has_local_activity = !activity.is_empty();
            if has_local_activity {
                restored_activity.push((contract_id, key, activity));
            }
            // Replace a placeholder inserted by the route effect; otherwise
            // the persisted state would lose to an empty default.
            boards.insert(
                contract_id,
                SectionBoard {
                    params: SectionParametersV1 {
                        owner: entry.owner,
                        section: entry.section,
                    },
                    state: entry.state,
                    synced: false,
                    ready: false,
                    syncing: false,
                    dirty: has_local_activity,
                },
            );
        }
    });
    // Activity applied locally before the reload still has to reach the
    // network. Queue it again; otherwise the next GET overwrites the restored
    // reply count with the older network state.
    for (contract_id, key, activity) in restored_activity {
        queue_section_activity(contract_id, key, activity);
    }
}

pub struct SectionBoard {
    pub params: SectionParametersV1,
    pub state: ChatBoardStateV1,
    pub synced: bool,
    /// State has arrived and the parent authority has been copied in.
    pub ready: bool,
    /// An authority sync is in flight.
    pub syncing: bool,
    /// Local activity has not been confirmed by the network yet.
    pub dirty: bool,
}

pub static SECTION_BOARDS: GlobalSignal<HashMap<ContractInstanceId, SectionBoard>> =
    Global::new(HashMap::new);

struct PendingSectionActivity {
    key: ContractKey,
    activity: HashMap<plaza_core::board_state::message::MessageId, AuthorizedTopicActivityV1>,
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
    let Some(pending) = pending else {
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
            dioxus::logger::tracing::warn!("section activity was not sent: {error}");
            let retry_key = pending.key;
            {
                let mut queue = SECTION_ACTIVITY.lock().unwrap();
                queue.push((contract_id, pending));
            }
            SECTION_BOARDS.with_mut(|boards| {
                if let Some(board) = boards.get_mut(&contract_id) {
                    board.dirty = true;
                }
            });
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
/// Members whose records a section child needs: topic authors, activity
/// signers, flag moderators, reporters and report resolvers.
fn section_member_ids(state: &ChatBoardStateV1) -> HashSet<MemberId> {
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
    ids
}

fn delta_member_ids(
    delta: &ChatBoardStateV1Delta,
    owner_id: MemberId,
) -> HashSet<MemberId> {
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

/// Add the member, role and moderation records that a section delta needs to
/// verify its new topic records. A member that the child already knows costs
/// nothing.
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
    let added: Vec<AuthorizedMember> = parent
        .members
        .members
        .iter()
        .filter(|member| ids.contains(&member.member.id()) && !known.contains(&member.member.id()))
        .cloned()
        .collect();
    if !added.is_empty() {
        delta.members = Some(MembersDelta::new(added));
    }
    let roles = relevant_roles(parent, &ids);
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
    let board_params = ChatBoardParametersV1 { owner };
    let ids = section_member_ids(&child);

    // Admin and ownership changes are rare and touch the whole chain; keep the
    // existing full-state path for them. Everything else travels as a delta
    // with only the records this section actually needs.
    let full_state = parent.admin != child.admin || parent.ownership != child.ownership;
    let mut state = child.clone();
    let data = if full_state {
        state.configuration = parent.configuration.clone();
        state.admin = parent.admin.clone();
        state.ownership = parent.ownership.clone();
        state.sections = parent.sections.clone();
        state.members = parent.members.clone();
        state.roles = parent.roles.clone();
        state.bans = parent.bans.clone();
        state.ban_revocations = parent.ban_revocations.clone();
        state.suspensions = parent.suspensions.clone();
        state
            .verify_with_section(&board_params, Some(section))
            .map_err(|error| format!("section authority does not verify: {error}"))?;
        UpdateData::State(to_cbor_vec(&state).into())
    } else {
        let mut delta = ChatBoardStateV1Delta::default();
        if parent.configuration != child.configuration {
            delta.configuration = Some(parent.configuration.clone());
        }
        if parent.sections != child.sections {
            delta.sections = Some(SectionsDelta {
                sections: parent.sections.sections.clone(),
            });
        }
        let known: HashSet<MemberId> = child
            .members
            .members
            .iter()
            .map(|member| member.member.id())
            .collect();
        let added: Vec<AuthorizedMember> = parent
            .members
            .members
            .iter()
            .filter(|member| {
                ids.contains(&member.member.id()) && !known.contains(&member.member.id())
            })
            .cloned()
            .collect();
        if !added.is_empty() {
            delta.members = Some(MembersDelta::new(added));
        }
        let roles = relevant_roles(parent, &ids);
        if !roles.roles.is_empty() || !roles.assignments.is_empty() {
            delta.roles = Some(roles);
        }
        let bans = relevant_bans(parent, &ids);
        if !bans.is_empty() {
            delta.bans = Some(bans);
        }
        let revocations = relevant_revocations(parent, &ids);
        if !revocations.is_empty() {
            delta.ban_revocations = Some(revocations);
        }
        let suspensions = relevant_suspensions(parent, &ids);
        if !suspensions.is_empty() {
            delta.suspensions = Some(SuspensionsDelta { suspensions });
        }
        let has_changes = delta.configuration.is_some()
            || delta.sections.is_some()
            || delta.members.is_some()
            || delta.roles.is_some()
            || delta.bans.is_some()
            || delta.ban_revocations.is_some()
            || delta.suspensions.is_some();
        if !has_changes {
            SECTION_BOARDS.with_mut(|boards| {
                if let Some(board) = boards.get_mut(&contract_id) {
                    board.syncing = false;
                    board.ready = true;
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
            board.state = state.clone();
            board.synced = true;
            board.ready = false;
            board.dirty = true;
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
            board.state = state;
            board.synced = false;
            board.dirty = true;
        }
    });
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
            // Keep the cache marked until the node acknowledges this update;
            // a Get that still carries the older state must not drop it.
            board.dirty = true;
        }
    });
    result.map_err(|error| format!("send section delta: {error}"))
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
    // The child starts without a copy of the board authority. Members, roles
    // and moderation records are added as the section index needs them, so a
    // board with many members does not pay for all of them in every section.
    // A board with ownership transfers keeps the member/role lists: the
    // transfer target must be resolvable from the child.
    if parent.ownership.transfers.is_empty() {
        child.members = Default::default();
        child.member_info = Default::default();
        child.roles = Default::default();
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
                dirty: true,
            },
        );
    });
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
                    dirty: false,
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
            let network = ciborium::de::from_reader::<ChatBoardStateV1, _>(state.as_ref())
                .map_err(|error| format!("decode section state: {error}"))?;
            let Some((owner, section, cached, dirty)) = SECTION_BOARDS
                .read()
                .get(key.id())
                .map(|board| {
                    (
                        board.params.owner,
                        board.params.section,
                        board.state.clone(),
                        board.dirty,
                    )
                })
            else {
                return Err("unknown section board".to_string());
            };
            let params = ChatBoardParametersV1 { owner };
            network
                .verify_with_section(&params, Some(section))
                .map_err(|error| format!("section state does not verify: {error}"))?;
            // Any unconfirmed local change (a new entry, a flag or activity)
            // must survive a Get that still carries the older state.
            let state = if dirty {
                let mut merged = cached.clone();
                match merged.merge(&cached, &params, &network) {
                    Ok(()) => {
                        if let Err(error) = merged.verify_with_section(&params, Some(section))
                        {
                            // The cached copy can be a stale placeholder. The
                            // network state has already been verified; use it
                            // and let the queued activity reach the contract.
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
            };
            match (|| -> Result<(), String> {
                state.verify_with_section(&params, Some(section))?;
                Ok(())
            })() {
                Ok(()) => {}
                Err(error) => return Err(error),
            }
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
                    // Keep a local change marked until our UpdateResponse
                    // confirms it; a stale Get must not clear it.
                    board.dirty = dirty;
                }
            });
            schedule_section_save();
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
                    board.dirty = false;
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
                    let network = ciborium::de::from_reader(bytes.as_ref())
                        .map_err(|error| format!("decode section update: {error}"))?;
                    let cached = state.clone();
                    let dirty = SECTION_BOARDS
                        .read()
                        .get(key.id())
                        .map(|board| board.dirty)
                        .unwrap_or(false);
                    if dirty {
                        let mut merged = cached.clone();
                        match merged.merge(&cached, &params, &network) {
                            Ok(()) => {
                                if let Err(error) =
                                    merged.verify_with_section(&params, Some(entry.1))
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
                    // Keep dirty as it was: only the UpdateResponse for our
                    // own request confirms that the local change reached the
                    // node.
                }
            });
            schedule_section_save();
        }
        _ => {}
    }
    Ok(())
}
