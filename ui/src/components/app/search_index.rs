//! Persistent full-archive local search index stored in the encrypted chat
//! delegate.
//!
//! Extra section pages are loaded lazily and evicted from RAM/delegate storage
//! under an LRU budget. Keeping a compact summary of every topic title/preview
//! seen (up to `MAX_INDEXED_TOPICS_TOTAL` / `MAX_PERSISTED_SEARCH_INDEX_BYTES`)
//! lets `SearchView` query older pages instantaneously across reloads without
//! re-fetching the entire archive every time.

use crate::board_data::BoardData;
use crate::components::app::chat_delegate::{send_delegate_request, SEARCH_INDEX_STORAGE_KEY};
use crate::components::app::topic_contract;
use dioxus::prelude::*;
use ed25519_dalek::VerifyingKey;
use plaza_core::board_state::member::MemberId;
use plaza_core::board_state::message::MessageId;
use plaza_core::board_state::sections::SectionId;
use plaza_core::chat_delegate::{ChatDelegateKey, ChatDelegateRequestMsg, ChatDelegateResponseMsg};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};

/// Maximum topic summaries kept in the persisted local search archive.
const MAX_INDEXED_TOPICS_TOTAL: usize = 5_000;
/// Byte budget for the CBOR blob stored in the delegate.
const MAX_PERSISTED_SEARCH_INDEX_BYTES: usize = 2 * 1024 * 1024;

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct IndexedTopicSummary {
    pub topic_id: MessageId,
    pub section: Option<SectionId>,
    pub author: MemberId,
    pub title: String,
    pub preview: String,
    pub created_at: i64,
    pub last_activity: i64,
    #[serde(default)]
    pub hidden: bool,
    #[serde(default)]
    pub merged: bool,
}

#[derive(Serialize, Deserialize)]
struct PersistedBoardSearchIndex {
    owner: VerifyingKey,
    topics: Vec<IndexedTopicSummary>,
}

pub static SEARCH_INDEX: GlobalSignal<HashMap<VerifyingKey, HashMap<MessageId, IndexedTopicSummary>>> =
    Global::new(HashMap::new);

static SEARCH_SAVE_SCHEDULED: AtomicBool = AtomicBool::new(false);
static SEARCH_LOAD_STARTED: AtomicBool = AtomicBool::new(false);

fn schedule_search_index_save() {
    if crate::components::app::chat_delegate::LOCAL_RESET.load(Ordering::SeqCst) {
        return;
    }
    if SEARCH_SAVE_SCHEDULED.swap(true, Ordering::SeqCst) {
        return;
    }
    crate::util::safe_spawn_local(async {
        crate::util::sleep(std::time::Duration::from_millis(1_500)).await;
        if let Err(error) = save_search_index_now().await {
            dioxus::logger::tracing::warn!("could not save local search index: {error}");
        }
        SEARCH_SAVE_SCHEDULED.store(false, Ordering::SeqCst);
    });
}

async fn save_search_index_now() -> Result<(), String> {
    let mut flat: Vec<(VerifyingKey, IndexedTopicSummary)> = {
        let index = SEARCH_INDEX.read();
        let mut items = Vec::new();
        for (owner, map) in index.iter() {
            for summary in map.values() {
                items.push((*owner, summary.clone()));
            }
        }
        items
    };
    if flat.is_empty() {
        return Ok(());
    }
    // Keep the most recently active topics within both count and byte budgets.
    flat.sort_by_key(|(_, item)| std::cmp::Reverse(item.last_activity));
    flat.truncate(MAX_INDEXED_TOPICS_TOTAL);

    let mut grouped: HashMap<VerifyingKey, Vec<IndexedTopicSummary>> = HashMap::new();
    let mut est_bytes = 64usize;
    for (owner, item) in flat {
        let item_bytes = 128 + item.title.len() + item.preview.len();
        if est_bytes + item_bytes > MAX_PERSISTED_SEARCH_INDEX_BYTES {
            break;
        }
        est_bytes += item_bytes;
        grouped.entry(owner).or_default().push(item);
    }
    let payload: Vec<PersistedBoardSearchIndex> = grouped
        .into_iter()
        .map(|(owner, topics)| PersistedBoardSearchIndex { owner, topics })
        .collect();
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&payload, &mut bytes)
        .map_err(|error| format!("serialize search index: {error}"))?;
    match send_delegate_request(ChatDelegateRequestMsg::StoreRequest {
        key: ChatDelegateKey::new(SEARCH_INDEX_STORAGE_KEY.to_vec()),
        value: bytes,
    })
    .await
    {
        Ok(ChatDelegateResponseMsg::StoreResponse { result, .. }) => result,
        Ok(other) => Err(format!("unexpected search index store response: {other:?}")),
        Err(error) => Err(error),
    }
}

/// Restore the persisted full-archive search index from the delegate once on startup.
pub async fn load_persisted_search_index() {
    if SEARCH_LOAD_STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    let response = send_delegate_request(ChatDelegateRequestMsg::GetRequest {
        key: ChatDelegateKey::new(SEARCH_INDEX_STORAGE_KEY.to_vec()),
    })
    .await;
    let bytes = match response {
        Ok(ChatDelegateResponseMsg::GetResponse {
            value: Some(bytes), ..
        }) => bytes,
        _ => return,
    };
    let persisted: Vec<PersistedBoardSearchIndex> =
        match ciborium::de::from_reader(bytes.as_slice()) {
            Ok(entries) => entries,
            Err(error) => {
                dioxus::logger::tracing::warn!("could not decode persisted search index: {error}");
                return;
            }
        };
    SEARCH_INDEX.with_mut(|index| {
        for board in persisted {
            let map = index.entry(board.owner).or_default();
            for summary in board.topics {
                map.entry(summary.topic_id).or_insert(summary);
            }
        }
    });
}

/// Update the local full-archive search index from all currently loaded topic
/// entries of `board`. Only schedules a delegate write if at least one entry
/// was added or changed.
pub fn record_board_topics(board: &BoardData) {
    if !board.board_state.mode.is_topic_index() {
        return;
    }
    let owner = board.owner_vk;
    let mut updates: Vec<IndexedTopicSummary> = Vec::new();
    for entry in &board.board_state.topics.entries {
        let topic_id = entry.entry.topic_id;
        let (section, _) = board.board_state.topics.section_of(&topic_id);
        let title = topic_contract::read_text(board, &entry.entry.title)
            .unwrap_or_else(|| "Untitled".to_string());
        let preview = topic_contract::read_text(board, &entry.entry.preview).unwrap_or_default();
        let last_activity = board
            .board_state
            .topics
            .activity_for(&topic_id)
            .map(|a| a.activity.last_activity)
            .unwrap_or(entry.entry.created_at);
        let hidden = board.board_state.topics.is_hidden(&topic_id);
        let merged = board.board_state.topics.merged_into(&topic_id).is_some();
        updates.push(IndexedTopicSummary {
            topic_id,
            section,
            author: entry.entry.author,
            title,
            preview,
            created_at: entry.entry.created_at,
            last_activity,
            hidden,
            merged,
        });
    }
    if updates.is_empty() {
        return;
    }
    let mut changed = false;
    SEARCH_INDEX.with_mut(|index| {
        let map = index.entry(owner).or_default();
        for summary in updates {
            let needs_update = map
                .get(&summary.topic_id)
                .map(|existing| *existing != summary)
                .unwrap_or(true);
            if needs_update {
                map.insert(summary.topic_id, summary);
                changed = true;
            }
        }
    });
    if changed {
        schedule_search_index_save();
    }
}

pub fn entries_for(owner: VerifyingKey) -> Vec<IndexedTopicSummary> {
    SEARCH_INDEX
        .read()
        .get(&owner)
        .map(|map| map.values().cloned().collect())
        .unwrap_or_default()
}

pub fn count_for(owner: VerifyingKey) -> usize {
    SEARCH_INDEX
        .read()
        .get(&owner)
        .map(|map| map.len())
        .unwrap_or(0)
}

pub fn clear_memory() {
    SEARCH_INDEX.write().clear();
}
