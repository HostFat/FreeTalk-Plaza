use crate::components::app::freenet_api::constants::REPUT_DELAY_MS;
use crate::components::app::BOARDS;
use crate::util::owner_vk_to_contract_key;
use dioxus::logger::tracing::{debug, warn};
use dioxus::prelude::{Global, GlobalSignal, ReadableExt};
use ed25519_dalek::VerifyingKey;
use freenet_stdlib::prelude::tracing::info;
use freenet_stdlib::prelude::ContractInstanceId;
use plaza_core::board_state::member::MemberId;
use plaza_core::ChatBoardStateV1;
use std::collections::HashMap;

/// Get current time in milliseconds (works in WASM)
pub(crate) fn now_ms() -> f64 {
    #[cfg(target_arch = "wasm32")]
    {
        js_sys::Date::now()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as f64)
            .unwrap_or(0.0)
    }
}

pub static SYNC_INFO: GlobalSignal<SyncInfo> = Global::new(SyncInfo::new);

/// How long an unconfirmed change keeps the "Syncing" chip visible. A change
/// that no request carried (a network-driven mark, for example) must not spin
/// forever.
const SYNCING_VISIBLE_MS: f64 = 60_000.0;

pub struct SyncInfo {
    map: HashMap<VerifyingKey, BoardSyncInfo>,
    instances: HashMap<ContractInstanceId, VerifyingKey>,
}

pub struct BoardSyncInfo {
    pub sync_status: BoardSyncStatus,
    // TODO: Would be better if state implemented Hash trait and just store
    //       a hash of the state
    pub last_synced_state: Option<ChatBoardStateV1>,
    /// Timestamp (in ms) when subscription was initiated, used for timeout detection
    pub subscribing_since: Option<f64>,
    /// Bumped for every local change that has to reach the network.
    pub local_revision: u64,
    /// The revision carried by the last request we sent.
    pub sent_revision: Option<u64>,
    /// The highest revision the node confirmed.
    pub acked_revision: u64,
    /// When the last local change was marked.
    pub last_change_at: Option<f64>,
}

impl SyncInfo {
    pub fn new() -> Self {
        SyncInfo {
            map: HashMap::new(),
            instances: HashMap::new(),
        }
    }

    pub fn register_new_board(&mut self, owner_key: VerifyingKey) {
        let contract_key = owner_vk_to_contract_key(&owner_key);
        let contract_id = contract_key.id();

        if let std::collections::hash_map::Entry::Vacant(e) = self.map.entry(owner_key) {
            debug!(
                "Registering new board with owner key: {:?}, contract ID: {}",
                MemberId::from(owner_key),
                contract_id
            );

            e.insert(BoardSyncInfo {
                sync_status: BoardSyncStatus::Disconnected,
                last_synced_state: None,
                subscribing_since: None,
                local_revision: 0,
                sent_revision: None,
                acked_revision: 0,
                last_change_at: None,
            });

            self.instances.insert(*contract_id, owner_key);
            debug!(
                "Added mapping from contract ID {} to owner key {:?}",
                contract_id,
                MemberId::from(owner_key)
            );
        } else {
            debug!(
                "Board with owner key {:?} already registered",
                MemberId::from(owner_key)
            );
        }
    }

    pub fn update_sync_status(&mut self, owner_key: &VerifyingKey, status: BoardSyncStatus) {
        if let Some(sync_info) = self.map.get_mut(owner_key) {
            // Track when subscription starts for timeout detection
            if status == BoardSyncStatus::Subscribing {
                sync_info.subscribing_since = Some(now_ms());
            } else {
                sync_info.subscribing_since = None;
            }
            sync_info.sync_status = status;
        }
    }

    /// Current sync status of a board, if it is known.
    pub fn sync_status_of(&self, owner_key: &VerifyingKey) -> Option<BoardSyncStatus> {
        self.map.get(owner_key).map(|info| info.sync_status.clone())
    }

    /// Record a local change that has to be published.
    pub fn mark_local_change(&mut self, owner_key: &VerifyingKey) {
        if !self.map.contains_key(owner_key) {
            self.register_new_board(*owner_key);
        }
        if let Some(info) = self.map.get_mut(owner_key) {
            info.local_revision += 1;
            info.last_change_at = Some(now_ms());
        }
    }

    /// Record that the last request carried the current local revision.
    pub fn mark_sent(&mut self, owner_key: &VerifyingKey) {
        if let Some(info) = self.map.get_mut(owner_key) {
            info.sent_revision = Some(info.local_revision);
        }
    }

    /// The node confirmed the last request: it carried that revision.
    /// A confirmation also clears an earlier send error.
    pub fn mark_acked(&mut self, owner_key: &VerifyingKey) {
        if let Some(info) = self.map.get_mut(owner_key) {
            let revision = info.sent_revision.take().unwrap_or(info.local_revision);
            info.acked_revision = info.acked_revision.max(revision);
            if matches!(info.sync_status, BoardSyncStatus::Error(_)) {
                info.sync_status = BoardSyncStatus::Subscribed;
            }
        }
    }

    /// True when the node has not confirmed every local change, regardless of
    /// how old the change is.
    pub fn has_unacked(&self, owner_key: &VerifyingKey) -> bool {
        self.map
            .get(owner_key)
            .is_some_and(|info| info.local_revision > info.acked_revision)
    }

    /// True while a local change has not been confirmed by the node.
    pub fn is_syncing(&self, owner_key: &VerifyingKey) -> bool {
        self.map.get(owner_key).is_some_and(|info| {
            info.local_revision > info.acked_revision
                && info
                    .last_change_at
                    .is_some_and(|at| now_ms() - at < SYNCING_VISIBLE_MS)
        })
    }

    pub fn update_last_synced_state(&mut self, owner_key: &VerifyingKey, state: &ChatBoardStateV1) {        if let Some(sync_info) = self.map.get_mut(owner_key) {
            sync_info.last_synced_state = Some(state.clone());
        }
    }

    pub fn get_owner_vk_for_instance_id(
        &self,
        instance_id: &ContractInstanceId,
    ) -> Option<VerifyingKey> {
        let result = self.instances.get(instance_id).copied();
        if result.is_some() {
            debug!("Found owner key for contract ID {}", instance_id);
        } else {
            debug!("No owner key found for contract ID {}", instance_id);
            // Log all known mappings to help debug
            for (id, vk) in &self.instances {
                debug!(
                    "Known mapping: contract ID {} -> owner key {:?}",
                    id,
                    MemberId::from(*vk)
                );
            }
        }
        result
    }

    pub fn boards_awaiting_subscription(&mut self) -> HashMap<VerifyingKey, ChatBoardStateV1> {
        let mut boards_awaiting_subscription = HashMap::new();
        let boards = BOARDS.read();
        let current_time = now_ms();

        for (key, board_data) in boards.map.iter() {
            // A read-only visitor never puts its empty state: the board is
            // fetched with a GET and the local identity is not published.
            if board_data.spectator {
                if !self.map.contains_key(key) {
                    self.register_new_board(*key);
                }
                continue;
            }

            // Register new boards automatically
            if !self.map.contains_key(key) {
                self.register_new_board(*key);
                self.update_last_synced_state(key, &board_data.board_state);
            }

            let sync_info = self.map.get(key).unwrap();

            // Add board to awaiting list if it's disconnected
            if sync_info.sync_status == BoardSyncStatus::Disconnected {
                boards_awaiting_subscription.insert(*key, board_data.board_state.clone());
            }

            // Check for subscription timeout - if subscribing for longer than REPUT_DELAY_MS,
            // reset to Disconnected to trigger a re-PUT
            if sync_info.sync_status == BoardSyncStatus::Subscribing {
                if let Some(started_at) = sync_info.subscribing_since {
                    let elapsed_ms = current_time - started_at;
                    if elapsed_ms >= REPUT_DELAY_MS as f64 {
                        warn!(
                            "Subscription timeout for board {:?} after {:.1}s - will re-PUT contract",
                            MemberId::from(*key),
                            elapsed_ms / 1000.0
                        );
                        // Reset to disconnected to trigger re-PUT
                        // We can't modify the map while iterating, so collect for later
                        boards_awaiting_subscription.insert(*key, board_data.board_state.clone());
                    }
                }
            }
        }

        // Now update the status for timed-out boards
        for key in boards_awaiting_subscription.keys() {
            if let Some(sync_info) = self.map.get_mut(key) {
                if sync_info.sync_status == BoardSyncStatus::Subscribing {
                    sync_info.sync_status = BoardSyncStatus::Disconnected;
                    sync_info.subscribing_since = None;
                }
            }
        }

        boards_awaiting_subscription
    }

    /// Returns a list of boards for which an update should be sent to the network,
    /// automatically updates the last_synced_state for each board
    pub fn needs_to_send_update(&mut self) -> HashMap<VerifyingKey, ChatBoardStateV1> {
        let mut boards_needing_update = HashMap::new();

        // FIXME: Temporarily disabled to fix infinite loop bug
        // This secret rotation/generation code was modifying boards inside a "check if sync needed" function,
        // which triggered use_effect → ProcessBoards → needs_to_send_update → boards.with_mut → use_effect (infinite loop)
        //
        // TODO: Move this logic to a separate periodic task that runs independently of sync triggers
        // See: https://github.com/freenet/river/issues/XXX
        //
        // let keys_to_process: Vec<VerifyingKey> = boards.read().map.keys().copied().collect();
        //
        // for key in &keys_to_process {
        //     let should_generate = BOARDS.read().map.get(key).map(|board_data| {
        //         board_data.owner_vk == board_data.self_sk.verifying_key()
        //     }).unwrap_or(false);
        //
        //     if should_generate {
        //         BOARDS.with_mut(|boards| {
        //             if let Some(board_data) = boards.map.get_mut(key) {
        //                 if board_data.needs_secret_rotation() { ... }
        //                 if let Some(secrets_delta) = board_data.generate_missing_member_secrets() { ... }
        //             }
        //         });
        //     }
        // }

        // Second pass: check which boards need updates
        let boards = BOARDS.read();

        debug!(
            "Checking for boards that need updates, total boards: {}",
            boards.map.len()
        );

        for (key, board_data) in boards.map.iter() {
            // A read-only visitor has nothing to publish.
            if board_data.spectator {
                continue;
            }
            // Register new boards automatically
            if !self.map.contains_key(key) {
                info!("Registering new board: {:?}", key);
                self.register_new_board(*key);
            }

            let sync_info = self.map.get(key).unwrap();
            let sync_status = &sync_info.sync_status;
            let has_last_synced = sync_info.last_synced_state.is_some();
            // An unconfirmed revision may have been sent just before a
            // reconnect. Resending it is harmless and closes the gap. A board
            // that was never sent yet has no baseline to compare, so it keeps
            // using the state comparison only.
            let revision_pending = sync_info.last_synced_state.is_some()
                && sync_info.local_revision > sync_info.acked_revision;
            let states_match = sync_info.last_synced_state.as_ref()
                == Some(&board_data.board_state)
                && !revision_pending;

            debug!(
                "Board {:?} - sync status: {:?}, has last synced: {}, states match: {}",
                MemberId::from(key),
                sync_status,
                has_last_synced,
                states_match
            );

            if let Some(last_state) = &sync_info.last_synced_state {
                debug!(
                    "Board {:?} - last synced: {} members/{} member_info, current: {} members/{} member_info",
                    MemberId::from(key),
                    last_state.members.members.len(),
                    last_state.member_info.member_info.len(),
                    board_data.board_state.members.members.len(),
                    board_data.board_state.member_info.member_info.len(),
                );
            }

            // Add board to update list if it's subscribed and the state has changed
            if *sync_status == BoardSyncStatus::Subscribed {
                if !states_match {
                    info!(
                        "Board {:?} needs update - state has changed",
                        MemberId::from(key)
                    );
                    boards_needing_update.insert(*key, board_data.board_state.clone());
                    // Don't update the last synced state here - it will be updated after successful network send
                } else {
                    debug!(
                        "Board {:?} doesn't need update - state unchanged",
                        MemberId::from(key)
                    );
                }
            } else {
                debug!(
                    "Board {:?} doesn't need update - not subscribed (status: {:?})",
                    MemberId::from(key),
                    sync_status
                );
            }
        }

        info!(
            "Found {} boards needing updates",
            boards_needing_update.len()
        );
        boards_needing_update
    }

    /// Last state confirmed by the network for this board, if any.
    pub fn last_synced_state(&self, owner_key: &VerifyingKey) -> Option<ChatBoardStateV1> {
        self.map
            .get(owner_key)
            .and_then(|info| info.last_synced_state.clone())
    }

    /// Register that the state's current value has been sent to the network
    pub fn state_updated(&mut self, owner_key: &VerifyingKey, new_state: ChatBoardStateV1) {
        if let Some(sync_info) = self.map.get_mut(owner_key) {
            sync_info.last_synced_state = Some(new_state);
        }
    }
}

/// Ask the synchronizer to publish the board again after an error.
///
/// Resetting to `Disconnected` makes `ProcessBoards` send the whole state with
/// a PUT; that also recovers boards that never finished subscribing.
pub fn retry_board_sync(owner_key: VerifyingKey) {
    SYNC_INFO.with_mut(|info| {
        info.update_sync_status(&owner_key, BoardSyncStatus::Disconnected);
    });
    crate::components::app::mark_needs_sync(owner_key);
}

/// Test hook: put a board in the error state so the "Sync failed" chip and its
/// Retry can be exercised without a node failure. Reachable from the
/// Developer section of Board Settings.
pub fn simulate_board_error(owner_key: VerifyingKey) {
    SYNC_INFO.with_mut(|info| {
        info.register_new_board(owner_key);
        info.update_sync_status(
            &owner_key,
            BoardSyncStatus::Error("Simulated sync error".to_string()),
        );
    });
}

#[derive(Clone, PartialEq, Debug)]
pub enum BoardSyncStatus {
    Disconnected,

    Subscribing,

    Subscribed,

    Error(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn board() -> VerifyingKey {
        ed25519_dalek::SigningKey::generate(&mut rand::thread_rng()).verifying_key()
    }

    #[test]
    fn a_change_syncs_until_the_node_confirms_it() {
        let mut info = SyncInfo::new();
        let board = board();
        info.register_new_board(board);
        assert!(!info.is_syncing(&board));

        info.mark_local_change(&board);
        assert!(info.is_syncing(&board));

        info.mark_sent(&board);
        assert!(info.is_syncing(&board));

        info.mark_acked(&board);
        assert!(!info.is_syncing(&board));
        assert!(!info.has_unacked(&board));
    }

    #[test]
    fn a_change_after_the_send_stays_pending() {
        let mut info = SyncInfo::new();
        let board = board();
        info.register_new_board(board);

        info.mark_local_change(&board);
        info.mark_sent(&board);
        // A second change lands while the first request is in flight.
        info.mark_local_change(&board);
        info.mark_acked(&board);

        assert!(info.has_unacked(&board));
        assert!(info.is_syncing(&board));
    }

    #[test]
    fn a_confirmation_clears_a_send_error() {
        let mut info = SyncInfo::new();
        let board = board();
        info.register_new_board(board);
        info.mark_local_change(&board);
        info.update_sync_status(&board, BoardSyncStatus::Error("offline".to_string()));

        info.mark_sent(&board);
        info.mark_acked(&board);

        assert_eq!(info.sync_status_of(&board), Some(BoardSyncStatus::Subscribed));
    }
}
