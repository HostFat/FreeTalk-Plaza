//! Board ownership can move from one key to another without changing the
//! contract parameters (the board identity). The chain of signed transfers is
//! part of the state, so every peer agrees on who the owner is and on who it
//! was at any signed time.
//!
//! A transfer is unilateral: the current owner signs it. Records the owner
//! signed before the transfer keep verifying through the historical lookup;
//! the old key cannot sign anything new.
//!
//! Deactivations are per board and signed by the key itself. They cut the
//! future, not the past: records dated before the deactivation stay valid,
//! and a deactivated key can never sign again on this board.

use crate::board_state::member::MemberId;
use crate::board_state::rate_limit::system_time_ms;
use crate::board_state::{ChatBoardParametersV1, ChatBoardStateV1};
use crate::util::{sign_struct, verify_struct};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use freenet_scaffold::ComposableState;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

pub const MAX_OWNER_TRANSFERS: usize = 256;
pub const MAX_SUCCESSION_VOTES: usize = 256;

/// Minimum admin votes required for an emergency succession transfer.
/// Requires at least 2 active admins and a strict majority (`N / 2 + 1`), so a
/// single compromised admin can never seize a board.
pub fn required_succession_quorum(active_admin_count: usize) -> Option<usize> {
    if active_admin_count < 2 {
        None
    } else {
        Some((active_admin_count / 2) + 1)
    }
}

/// One step of the ownership chain.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct OwnerTransferV1 {
    /// Owner at the time of the signature.
    pub from: MemberId,
    /// Successor; must be a current admin.
    pub to: MemberId,
    /// The successor's verifying key, so the chain is self-contained.
    pub to_key: VerifyingKey,
    /// 1 for the first transfer out of the founding owner, then 2, 3, ...
    pub generation: u64,
    pub transferred_at: SystemTime,
    /// What the outgoing owner chose for itself.
    #[serde(default)]
    pub outgoing: OutgoingOwnerAction,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum OutgoingOwnerAction {
    /// Keep the admin record, signed while still owner.
    #[default]
    KeepAdmin,
    /// Drop the admin record and stay a plain member.
    Member,
    /// Stay visible as a deactivated identity.
    Deactivate,
}

impl OwnerTransferV1 {
    pub fn digest(&self) -> u64 {
        let mut bytes = Vec::new();
        let _ = ciborium::ser::into_writer(self, &mut bytes);
        freenet_scaffold::util::fast_hash(&bytes).0 as u64
    }
}

/// One admin's signed vote to promote an active admin as the next owner when
/// the current owner is unreachable.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct SuccessionVoteV1 {
    /// Current owner being replaced.
    pub from: MemberId,
    /// Admin proposed as the new owner.
    pub to: MemberId,
    /// Successor verifying key, so the vote is self-contained.
    pub to_key: VerifyingKey,
    /// Target transfer generation (`transfers.len() + 1`).
    pub generation: u64,
    /// Active admin casting this vote.
    pub voter: MemberId,
    /// Voter verifying key (verified against the board member record).
    pub voter_key: VerifyingKey,
    pub signed_at: SystemTime,
}

impl SuccessionVoteV1 {
    pub fn digest(&self) -> u64 {
        let mut bytes = Vec::new();
        let _ = ciborium::ser::into_writer(self, &mut bytes);
        freenet_scaffold::util::fast_hash(&bytes).0 as u64
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedSuccessionVoteV1 {
    pub vote: SuccessionVoteV1,
    pub signature: Signature,
}

impl AuthorizedSuccessionVoteV1 {
    pub fn new(vote: SuccessionVoteV1, voter_sk: &SigningKey) -> Self {
        Self {
            signature: sign_struct(&vote, voter_sk),
            vote,
        }
    }

    pub fn verify_signature(&self) -> Result<(), String> {
        if MemberId::from(&self.vote.voter_key) != self.vote.voter {
            return Err("Succession vote key does not match voter id".to_string());
        }
        verify_struct(&self.vote, &self.signature, &self.vote.voter_key)
            .map_err(|e| format!("Invalid succession vote signature: {e}"))
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedOwnerTransfer {
    pub transfer: OwnerTransferV1,
    pub signature: Signature,
    /// Present only for emergency admin-quorum successions; empty for normal
    /// owner-signed transfers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub succession_approvals: Vec<AuthorizedSuccessionVoteV1>,
}

impl AuthorizedOwnerTransfer {
    pub fn new(transfer: OwnerTransferV1, owner_sk: &SigningKey) -> Self {
        Self {
            signature: sign_struct(&transfer, owner_sk),
            transfer,
            succession_approvals: Vec::new(),
        }
    }

    /// Build a succession transfer backed by a quorum of admin votes. Signed
    /// by one of the voting admins (typically the admin whose vote completes
    /// the quorum).
    pub fn new_by_succession(
        transfer: OwnerTransferV1,
        mut approvals: Vec<AuthorizedSuccessionVoteV1>,
        finalizer_sk: &SigningKey,
    ) -> Self {
        approvals.sort_by_key(|entry| (entry.vote.voter.0 .0, entry.vote.digest()));
        Self {
            signature: sign_struct(&transfer, finalizer_sk),
            transfer,
            succession_approvals: approvals,
        }
    }

    pub fn is_succession(&self) -> bool {
        !self.succession_approvals.is_empty()
    }

    pub fn verify_signature(&self, owner_key: &VerifyingKey) -> Result<(), String> {
        verify_struct(&self.transfer, &self.signature, owner_key)
            .map_err(|e| format!("Invalid owner transfer signature: {e}"))
    }
}

/// A key says it stops signing on this board. Per board by design: the same
/// key may own or join other boards.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct KeyDeactivationV1 {
    pub member: MemberId,
    /// The key being retired; must match the member's key.
    pub key: VerifyingKey,
    pub generation: u64,
    pub deactivated_at: SystemTime,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedKeyDeactivation {
    pub deactivation: KeyDeactivationV1,
    pub signature: Signature,
}

impl AuthorizedKeyDeactivation {
    pub fn new(deactivation: KeyDeactivationV1, signing_key: &SigningKey) -> Self {
        Self {
            signature: sign_struct(&deactivation, signing_key),
            deactivation,
        }
    }

    pub fn verify_signature(&self) -> Result<(), String> {
        verify_struct(
            &self.deactivation,
            &self.signature,
            &self.deactivation.key,
        )
        .map_err(|e| format!("Invalid deactivation signature: {e}"))
    }
}

#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
pub struct OwnershipV1 {
    pub transfers: Vec<AuthorizedOwnerTransfer>,
    pub deactivations: Vec<AuthorizedKeyDeactivation>,
    /// Active admin votes for the next emergency succession generation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub succession_votes: Vec<AuthorizedSuccessionVoteV1>,
}

impl OwnershipV1 {
    pub fn is_empty(&self) -> bool {
        self.transfers.is_empty()
            && self.deactivations.is_empty()
            && self.succession_votes.is_empty()
    }

    /// Owner id at the end of the chain.
    pub fn current_owner(&self, parameters: &ChatBoardParametersV1) -> MemberId {
        self.transfers
            .last()
            .map(|entry| entry.transfer.to)
            .unwrap_or_else(|| parameters.owner_id())
    }

    /// Owner key at the end of the chain.
    pub fn current_owner_key(&self, parameters: &ChatBoardParametersV1) -> VerifyingKey {
        self.transfers
            .last()
            .map(|entry| entry.transfer.to_key)
            .unwrap_or(parameters.owner)
    }

    /// Owner at a signed instant. Records without a timestamp (epoch) are
    /// treated as written before any transfer.
    pub fn owner_at(&self, parameters: &ChatBoardParametersV1, at: SystemTime) -> MemberId {
        let at_ms = system_time_ms(at);
        self.transfers
            .iter()
            .filter(|entry| system_time_ms(entry.transfer.transferred_at) <= at_ms)
            .last()
            .map(|entry| entry.transfer.to)
            .unwrap_or_else(|| parameters.owner_id())
    }

    pub fn owner_key_at(
        &self,
        parameters: &ChatBoardParametersV1,
        at: SystemTime,
    ) -> VerifyingKey {
        let at_ms = system_time_ms(at);
        self.transfers
            .iter()
            .filter(|entry| system_time_ms(entry.transfer.transferred_at) <= at_ms)
            .last()
            .map(|entry| entry.transfer.to_key)
            .unwrap_or(parameters.owner)
    }

    /// Number of ownership transfers effective at `at` (`0` = founding owner).
    pub fn epoch_at(&self, at: SystemTime) -> usize {
        let at_ms = system_time_ms(at);
        self.transfers
            .iter()
            .filter(|entry| system_time_ms(entry.transfer.transferred_at) <= at_ms)
            .count()
    }

    /// Current ownership epoch (`0` = founding owner, `N` = after N transfers).
    pub fn current_epoch(&self) -> usize {
        self.transfers.len()
    }

    /// Whether the member has been an owner of this board.
    pub fn was_owner(&self, member: &MemberId) -> bool {
        self.transfers
            .iter()
            .any(|entry| entry.transfer.from == *member)
    }

    /// The key a member used as owner, if it ever was one.
    pub fn owner_key_of(&self, member: &MemberId) -> Option<VerifyingKey> {
        self.transfers
            .iter()
            .find(|entry| entry.transfer.to == *member)
            .map(|entry| entry.transfer.to_key)
    }

    /// Latest deactivation for a member.
    pub fn deactivation_of(&self, member: &MemberId) -> Option<&AuthorizedKeyDeactivation> {
        self.deactivations
            .iter()
            .filter(|entry| entry.deactivation.member == *member)
            .max_by_key(|entry| {
                (
                    entry.deactivation.generation,
                    system_time_ms(entry.deactivation.deactivated_at),
                )
            })
    }

    /// Whether the member retired its key at or before `at`.
    pub fn is_deactivated_at(&self, member: &MemberId, at: SystemTime) -> bool {
        let at_ms = system_time_ms(at);
        self.deactivations.iter().any(|entry| {
            entry.deactivation.member == *member
                && system_time_ms(entry.deactivation.deactivated_at) <= at_ms
        })
    }

    pub fn is_deactivated_now(&self, member: &MemberId) -> bool {
        self.deactivation_of(member).is_some()
    }

    /// Resolve the verifying key of `member` using the founding key, known
    /// historical owner keys, and the board's current member list.
    fn resolve_key(
        state: &ChatBoardStateV1,
        parameters: &ChatBoardParametersV1,
        known_owner_keys: &std::collections::HashMap<MemberId, VerifyingKey>,
        member_id: &MemberId,
    ) -> Option<VerifyingKey> {
        if *member_id == parameters.owner_id() {
            return Some(parameters.owner);
        }
        if let Some(key) = known_owner_keys.get(member_id) {
            return Some(*key);
        }
        state
            .members
            .members
            .iter()
            .find(|member| member.member.id() == *member_id)
            .map(|member| member.member.member_vk)
    }

    /// Active admins at `at` (excluding `current_owner` and deactivated keys).
    pub fn active_admins_at(
        &self,
        state: &ChatBoardStateV1,
        parameters: &ChatBoardParametersV1,
        current_owner: MemberId,
        at: SystemTime,
    ) -> std::collections::HashSet<MemberId> {
        let at_ms = system_time_ms(at);
        let mut active = std::collections::HashSet::new();

        for admin in &state.admin.admins {
            let id = admin.admin.id();
            if id == current_owner || self.is_deactivated_at(&id, at) {
                continue;
            }
            if system_time_ms(admin.admin.signed_at) > at_ms {
                continue;
            }
            let revoked_by_then = state.admin.revoked.iter().any(|rev| {
                rev.id() == id && system_time_ms(rev.revocation.signed_at) <= at_ms
            });
            if !revoked_by_then {
                active.insert(id);
            }
        }
        // An admin revoked strictly after `at` was still active at `at`,
        // unless its revocation records that it was also appointed after `at`.
        for rev in &state.admin.revoked {
            let id = rev.id();
            if id == current_owner || self.is_deactivated_at(&id, at) {
                continue;
            }
            if rev
                .revocation
                .appointed_at
                .is_some_and(|appointed| system_time_ms(appointed) > at_ms)
            {
                continue;
            }
            if system_time_ms(rev.revocation.signed_at) > at_ms {
                active.insert(id);
            }
        }
        let _ = parameters;
        active
    }

    /// Active admins right now (excluding the current owner and deactivated
    /// keys). Used by the UI and by pending succession vote verification.
    pub fn current_active_admins(
        &self,
        state: &ChatBoardStateV1,
        parameters: &ChatBoardParametersV1,
    ) -> Vec<MemberId> {
        let owner = self.current_owner(parameters);
        let mut admins: Vec<MemberId> = state
            .admin
            .admins
            .iter()
            .map(|admin| admin.admin.id())
            .filter(|id| *id != owner && !self.is_deactivated_now(id))
            .collect();
        admins.sort_by_key(|id| id.0 .0);
        admins.dedup();
        admins
    }

    /// Verify one pending succession vote against the current board state.
    pub fn verify_pending_vote(
        &self,
        vote: &AuthorizedSuccessionVoteV1,
        state: &ChatBoardStateV1,
        parameters: &ChatBoardParametersV1,
    ) -> Result<(), String> {
        vote.verify_signature()?;
        let current_owner = self.current_owner(parameters);
        let next_generation = self.transfers.len() as u64 + 1;
        if vote.vote.generation != next_generation {
            return Err("Succession vote is for a stale or future generation".to_string());
        }
        if vote.vote.from != current_owner {
            return Err("Succession vote does not target the current owner".to_string());
        }
        if vote.vote.to == current_owner || vote.vote.voter == current_owner {
            return Err("Current owner cannot vote or be targeted in succession".to_string());
        }
        let active_admins = self.current_active_admins(state, parameters);
        if !active_admins.contains(&vote.vote.voter) {
            return Err("Succession voter is not an active admin".to_string());
        }
        if !active_admins.contains(&vote.vote.to) {
            return Err("Succession target is not an active admin".to_string());
        }
        let mut known_owner_keys = std::collections::HashMap::new();
        for entry in &self.transfers {
            known_owner_keys.insert(entry.transfer.to, entry.transfer.to_key);
        }
        let expected_voter_key =
            Self::resolve_key(state, parameters, &known_owner_keys, &vote.vote.voter)
                .ok_or_else(|| "Succession voter key not found".to_string())?;
        if expected_voter_key != vote.vote.voter_key {
            return Err("Succession voter key does not match the member".to_string());
        }
        let expected_to_key =
            Self::resolve_key(state, parameters, &known_owner_keys, &vote.vote.to)
                .ok_or_else(|| "Succession target key not found".to_string())?;
        if expected_to_key != vote.vote.to_key {
            return Err("Succession target key does not match the member".to_string());
        }
        Ok(())
    }

    /// Verify the whole chain: generations start at one, each step is signed
    /// by the owner of the previous step (or backed by a quorum of active
    /// admins for emergency succession), the successor was an admin with a
    /// known key, and times never go backwards.
    pub fn verify(
        &self,
        state: &ChatBoardStateV1,
        parameters: &ChatBoardParametersV1,
    ) -> Result<(), String> {
        let mut from = parameters.owner_id();
        let mut from_key = parameters.owner;
        let mut generation = 1u64;
        let mut last_time = 0i64;
        let mut known_owner_keys = std::collections::HashMap::new();
        known_owner_keys.insert(from, from_key);

        for entry in &self.transfers {
            let transfer = &entry.transfer;
            if transfer.from != from {
                return Err("Owner transfer chain is broken".to_string());
            }
            if transfer.generation != generation {
                return Err("Owner transfer generation is not sequential".to_string());
            }
            let at = system_time_ms(transfer.transferred_at);
            if at < last_time {
                return Err("Owner transfer time goes backwards".to_string());
            }
            if transfer.to == transfer.from {
                return Err("An owner cannot transfer the board to itself".to_string());
            }

            if entry.succession_approvals.is_empty() {
                entry.verify_signature(&from_key)?;
            } else {
                if entry.succession_approvals.len() > MAX_SUCCESSION_VOTES {
                    return Err("Too many succession approvals on transfer".to_string());
                }
                let active_admins =
                    self.active_admins_at(state, parameters, from, transfer.transferred_at);
                let quorum = required_succession_quorum(active_admins.len()).ok_or_else(|| {
                    "Emergency succession requires at least two active admins".to_string()
                })?;
                let max_timelock_secs = (i64::MAX / 1_000) as u64;
                let timelock_ms = (state
                    .configuration
                    .configuration
                    .succession_timelock_secs
                    .min(max_timelock_secs) as i64)
                    .saturating_mul(1_000);
                let mut voters = std::collections::HashSet::new();
                let mut matured_voters = 0usize;
                let mut valid_keys = Vec::new();
                for approval in &entry.succession_approvals {
                    approval.verify_signature()?;
                    let vote = &approval.vote;
                    if vote.from != transfer.from
                        || vote.to != transfer.to
                        || vote.to_key != transfer.to_key
                        || vote.generation != transfer.generation
                    {
                        return Err(
                            "Succession approval does not match the transfer target".to_string()
                        );
                    }
                    let vote_ms = system_time_ms(vote.signed_at);
                    if vote_ms > at {
                        return Err(
                            "Succession approval is dated after the transfer".to_string()
                        );
                    }
                    if vote_ms < last_time {
                        return Err(
                            "Succession approval predates the previous ownership transfer"
                                .to_string(),
                        );
                    }
                    if !voters.insert(vote.voter) {
                        return Err("Duplicate voter in succession approvals".to_string());
                    }
                    if !active_admins.contains(&vote.voter) {
                        return Err(
                            "Succession voter was not an active admin at the transfer".to_string()
                        );
                    }
                    if let Some(admin_record) = state
                        .admin
                        .admins
                        .iter()
                        .find(|a| a.admin.id() == vote.voter)
                    {
                        if vote_ms < system_time_ms(admin_record.admin.signed_at) {
                            return Err(
                                "Succession approval predates the voter's admin appointment"
                                    .to_string(),
                            );
                        }
                    }
                    let expected_key =
                        Self::resolve_key(state, parameters, &known_owner_keys, &vote.voter)
                            .ok_or_else(|| "Succession voter key is unknown".to_string())?;
                    if expected_key != vote.voter_key {
                        return Err(
                            "Succession voter key does not match the member".to_string()
                        );
                    }
                    if at >= vote_ms.saturating_add(timelock_ms) {
                        matured_voters += 1;
                    }
                    valid_keys.push(vote.voter_key);
                }
                if voters.len() < quorum {
                    return Err(format!(
                        "Succession transfer lacks admin quorum: {} < {}",
                        voters.len(),
                        quorum
                    ));
                }
                if timelock_ms > 0 && matured_voters < quorum {
                    return Err(format!(
                        "Succession timelock has not elapsed for enough admin votes: {} < {}",
                        matured_voters, quorum
                    ));
                }
                if !valid_keys
                    .iter()
                    .any(|key| entry.verify_signature(key).is_ok())
                {
                    return Err(
                        "Succession transfer must be signed by one of the approving admins"
                            .to_string(),
                    );
                }
            }

            // The successor must be a member whose key is the one named, and
            // an admin at the time of the transfer. The founding owner counts
            // as a member even after cleanup drops its record: once it owns the
            // board again the owner is implicit, and a return transfer names
            // exactly it.
            let member_key = Self::resolve_key(state, parameters, &known_owner_keys, &transfer.to)
                .ok_or_else(|| "Owner transfer target is not a member".to_string())?;
            if member_key != transfer.to_key {
                return Err("Owner transfer target key does not match the member".to_string());
            }
            let admin_signed_at = match state
                .admin
                .admins
                .iter()
                .find(|admin| admin.admin.id() == transfer.to)
            {
                Some(admin) => Some(system_time_ms(admin.admin.signed_at)),
                // A revocation recorded after the transfer removed the record,
                // but the appointment still existed at the transfer time (unless
                // the revocation itself records a later appointment).
                None if state.admin.revoked.iter().any(|revocation| {
                    revocation.id() == transfer.to
                        && system_time_ms(revocation.revocation.signed_at) > at
                        && revocation
                            .revocation
                            .appointed_at
                            .map_or(true, |appointed| system_time_ms(appointed) <= at)
                }) => None,
                // The founding owner is the board's root authority and needs
                // no appointment of its own.
                None if transfer.to == parameters.owner_id() => None,
                None => {
                    return Err("Owner transfer target is not an admin".to_string());
                }
            };
            if let Some(admin_signed_at) = admin_signed_at {
                if admin_signed_at > at {
                    return Err(
                        "Owner transfer target became admin after the transfer".to_string()
                    );
                }
                let revoked_before = state.admin.revoked.iter().any(|revocation| {
                    revocation.id() == transfer.to
                        && system_time_ms(revocation.revocation.signed_at) <= at
                });
                if revoked_before {
                    return Err("Owner transfer target was not an admin at the transfer".to_string());
                }
            }

            from = transfer.to;
            from_key = transfer.to_key;
            known_owner_keys.insert(from, from_key);
            generation += 1;
            last_time = at;
        }

        // Deactivations name their key, sign with it, and cannot retire the
        // current owner (the board would lose its only authority).
        for entry in &self.deactivations {
            entry.verify_signature()?;
            if entry.deactivation.member == from {
                return Err("The current owner cannot deactivate its key".to_string());
            }
            let expected =
                Self::resolve_key(state, parameters, &known_owner_keys, &entry.deactivation.member);
            match expected {
                Some(key) if key == entry.deactivation.key => {}
                Some(_) => return Err("Deactivation key does not match the member".to_string()),
                None => return Err("Deactivation targets an unknown key".to_string()),
            }
        }

        // Pending succession votes target the next generation and must be
        // signed by distinct active admins.
        if self.succession_votes.len() > MAX_SUCCESSION_VOTES {
            return Err("Too many pending succession votes".to_string());
        }
        let mut seen_voters = std::collections::HashSet::new();
        for vote in &self.succession_votes {
            if !seen_voters.insert(vote.vote.voter) {
                return Err("Duplicate pending succession vote for the same admin".to_string());
            }
            self.verify_pending_vote(vote, state, parameters)?;
        }

        Ok(())
    }

    /// Keep one transfer per generation (lowest digest wins, so concurrent
    /// transfers converge), drop the tail that no longer verifies, keep the
    /// latest deactivation per member, and keep only valid current-generation
    /// succession votes (latest per voter).
    pub fn cleanup(&mut self, state: &ChatBoardStateV1, parameters: &ChatBoardParametersV1) {
        let pending_votes = std::mem::take(&mut self.succession_votes);

        self.transfers
            .sort_by_key(|entry| (entry.transfer.generation, entry.transfer.digest()));
        self.transfers
            .dedup_by_key(|entry| entry.transfer.generation);
        self.transfers.truncate(MAX_OWNER_TRANSFERS);
        while !self.transfers.is_empty() && self.verify(state, parameters).is_err() {
            self.transfers.pop();
        }

        self.deactivations.sort_by(|a, b| {
            a.deactivation
                .member
                .0
                 .0
                .cmp(&b.deactivation.member.0 .0)
                .then(b.deactivation.generation.cmp(&a.deactivation.generation))
        });
        self.deactivations
            .dedup_by_key(|entry| entry.deactivation.member);

        let all = std::mem::take(&mut self.deactivations);
        let mut kept = Vec::new();
        for entry in all {
            self.deactivations = kept.clone();
            self.deactivations.push(entry.clone());
            if self.verify(state, parameters).is_ok() {
                kept.push(entry);
            }
        }
        self.deactivations = kept;

        let next_generation = self.transfers.len() as u64 + 1;
        let mut votes: Vec<AuthorizedSuccessionVoteV1> = pending_votes
            .into_iter()
            .filter(|vote| {
                vote.vote.generation == next_generation
                    && self.verify_pending_vote(vote, state, parameters).is_ok()
            })
            .collect();
        votes.sort_by(|a, b| {
            a.vote
                .voter
                .0
                 .0
                .cmp(&b.vote.voter.0 .0)
                .then(system_time_ms(b.vote.signed_at).cmp(&system_time_ms(a.vote.signed_at)))
                .then(a.vote.digest().cmp(&b.vote.digest()))
        });
        votes.dedup_by_key(|entry| entry.vote.voter);
        votes.truncate(MAX_SUCCESSION_VOTES);
        self.succession_votes = votes;
    }
}

#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
pub struct OwnershipSummary {
    pub transfers: Vec<u64>,
    pub deactivations: Vec<(MemberId, u64)>,
    #[serde(default)]
    pub succession_votes: Vec<u64>,
}

#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
pub struct OwnershipDelta {
    pub transfers: Vec<AuthorizedOwnerTransfer>,
    pub deactivations: Vec<AuthorizedKeyDeactivation>,
    #[serde(default)]
    pub succession_votes: Vec<AuthorizedSuccessionVoteV1>,
}

impl OwnershipV1 {
    fn transfer_digests(&self) -> Vec<u64> {
        self.transfers
            .iter()
            .map(|entry| entry.transfer.digest())
            .collect()
    }

    fn deactivation_digests(&self) -> Vec<(MemberId, u64)> {
        self.deactivations
            .iter()
            .map(|entry| {
                let mut bytes = Vec::new();
                let _ = ciborium::ser::into_writer(entry, &mut bytes);
                (
                    entry.deactivation.member,
                    freenet_scaffold::util::fast_hash(&bytes).0 as u64,
                )
            })
            .collect()
    }

    fn succession_vote_digests(&self) -> Vec<u64> {
        self.succession_votes
            .iter()
            .map(|entry| entry.vote.digest())
            .collect()
    }
}

impl ComposableState for OwnershipV1 {
    type ParentState = ChatBoardStateV1;
    type Summary = OwnershipSummary;
    type Delta = OwnershipDelta;
    type Parameters = ChatBoardParametersV1;

    fn verify(
        &self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
    ) -> Result<(), String> {
        OwnershipV1::verify(self, parent_state, parameters)
    }

    fn summarize(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
    ) -> Self::Summary {
        OwnershipSummary {
            transfers: self.transfer_digests(),
            deactivations: self.deactivation_digests(),
            succession_votes: self.succession_vote_digests(),
        }
    }

    fn delta(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
        old_state_summary: &Self::Summary,
    ) -> Option<Self::Delta> {
        let transfers: Vec<_> = self
            .transfers
            .iter()
            .filter(|entry| !old_state_summary.transfers.contains(&entry.transfer.digest()))
            .cloned()
            .collect();
        let current_deactivations = self.deactivation_digests();
        let deactivations: Vec<_> = self
            .deactivations
            .iter()
            .filter(|entry| {
                let digest = current_deactivations
                    .iter()
                    .find(|(member, _)| *member == entry.deactivation.member)
                    .map(|(_, digest)| *digest)
                    .unwrap_or_default();
                !old_state_summary
                    .deactivations
                    .iter()
                    .any(|(member, old)| *member == entry.deactivation.member && *old == digest)
            })
            .cloned()
            .collect();
        let succession_votes: Vec<_> = self
            .succession_votes
            .iter()
            .filter(|entry| {
                !old_state_summary
                    .succession_votes
                    .contains(&entry.vote.digest())
            })
            .cloned()
            .collect();
        if transfers.is_empty() && deactivations.is_empty() && succession_votes.is_empty() {
            None
        } else {
            Some(OwnershipDelta {
                transfers,
                deactivations,
                succession_votes,
            })
        }
    }

    fn apply_delta(
        &mut self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
        delta: &Option<Self::Delta>,
    ) -> Result<(), String> {
        let Some(delta) = delta else {
            return Ok(());
        };
        let mut trial = self.clone();
        trial.transfers.extend(delta.transfers.iter().cloned());
        trial
            .deactivations
            .extend(delta.deactivations.iter().cloned());
        trial
            .succession_votes
            .extend(delta.succession_votes.iter().cloned());
        trial.cleanup(parent_state, parameters);
        // A delta may extend the chain, never shorten an accepted one. When a
        // record elsewhere in the update invalidates an earlier transfer (a
        // newer admin appointment for the member that transfer handed the board
        // to), cleanup would drop it and hand the board back. Keep the chain.
        let keeps_accepted_chain = trial.transfers.len() >= self.transfers.len()
            && trial.transfers[..self.transfers.len()] == self.transfers[..];
        if keeps_accepted_chain && trial.verify(parent_state, parameters).is_ok() {
            *self = trial;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board_state::admin::{
        Admin, AdminRevocation, AdminsDelta, AuthorizedAdmin, AuthorizedAdminRevocation,
    };
    use crate::board_state::configuration::{AuthorizedConfigurationV1, Configuration};
    use crate::board_state::member::{AuthorizedMember, Member, MembersDelta};
    use crate::board_state::roles::verify_admin_authority;
    use crate::board_state::ChatBoardStateV1Delta;
    use crate::ChatBoardStateV1;
    use ed25519_dalek::SigningKey;

    struct Fixture {
        state: ChatBoardStateV1,
        parameters: ChatBoardParametersV1,
        owner_sk: SigningKey,
        owner_id: MemberId,
        admin_sk: SigningKey,
        admin_id: MemberId,
        now: SystemTime,
    }

    fn fixture() -> Fixture {
        let owner_sk = SigningKey::from_bytes(&[1u8; 32]);
        let admin_sk = SigningKey::from_bytes(&[2u8; 32]);
        let owner_id = MemberId::from(&owner_sk.verifying_key());
        let admin_id = MemberId::from(&admin_sk.verifying_key());
        let parameters = ChatBoardParametersV1 {
            owner: owner_sk.verifying_key(),
        };
        let mut state = ChatBoardStateV1 {
            configuration: AuthorizedConfigurationV1::new(Configuration::default(), &owner_sk),
            ..Default::default()
        };
        state.members.members.push(AuthorizedMember::new(
            Member {
                owner_member_id: owner_id,
                invited_by: owner_id,
                member_vk: admin_sk.verifying_key(),
                join_proof: None,
            },
            &owner_sk,
        ));
        state.admin.admins.push(AuthorizedAdmin::new(
            Admin {
                member_id: admin_id,
                generation: 1,
                signed_at: SystemTime::UNIX_EPOCH,
            },
            &owner_sk,
        ));
        Fixture {
            state,
            parameters,
            owner_sk,
            owner_id,
            admin_sk,
            admin_id,
            now: SystemTime::now(),
        }
    }

    fn transfer(
        from: MemberId,
        to: MemberId,
        to_key: VerifyingKey,
        generation: u64,
        at: SystemTime,
        signer: &SigningKey,
    ) -> AuthorizedOwnerTransfer {
        transfer_with_outgoing(
            from,
            to,
            to_key,
            generation,
            at,
            signer,
            OutgoingOwnerAction::KeepAdmin,
        )
    }

    fn transfer_with_outgoing(
        from: MemberId,
        to: MemberId,
        to_key: VerifyingKey,
        generation: u64,
        at: SystemTime,
        signer: &SigningKey,
        outgoing: OutgoingOwnerAction,
    ) -> AuthorizedOwnerTransfer {
        AuthorizedOwnerTransfer::new(
            OwnerTransferV1 {
                from,
                to,
                to_key,
                generation,
                transferred_at: at,
                outgoing,
            },
            signer,
        )
    }

    fn apply(state: &mut ChatBoardStateV1, parameters: &ChatBoardParametersV1, delta: OwnershipDelta) {
        let parent = state.clone();
        state
            .apply_delta(
                &parent,
                parameters,
                &Some(ChatBoardStateV1Delta {
                    ownership: Some(delta),
                    ..Default::default()
                }),
            )
            .expect("ownership delta applies");
    }

    #[test]
    fn a_transfer_moves_the_owner_and_keeps_the_board() {
        let mut fixture = fixture();
        let state_before = fixture.state.clone();
        apply(
            &mut fixture.state,
            &fixture.parameters,
            OwnershipDelta {
                transfers: vec![transfer(
                    fixture.owner_id,
                    fixture.admin_id,
                    fixture.admin_sk.verifying_key(),
                    1,
                    fixture.now,
                    &fixture.owner_sk,
                )],
                deactivations: Vec::new(),
                succession_votes: Vec::new(),
            },
        );

        assert_eq!(
            fixture.state.ownership.current_owner(&fixture.parameters),
            fixture.admin_id
        );
        // Configuration, members and admins written before the transfer stay.
        assert_eq!(
            fixture.state.members.members.len(),
            state_before.members.members.len()
        );
        assert_eq!(fixture.state.admin.admins.len(), 1);
        fixture
            .state
            .verify(&fixture.state.clone(), &fixture.parameters)
            .expect("the state verifies after the transfer");

        let later = fixture.now + std::time::Duration::from_secs(60);
        verify_admin_authority(
            &fixture.state,
            &fixture.parameters,
            &fixture.admin_id,
            None,
            8,
            later,
        )
        .expect("the new owner holds the owner powers");
        assert!(verify_admin_authority(
            &fixture.state,
            &fixture.parameters,
            &fixture.owner_id,
            None,
            8,
            later,
        )
        .is_err());
    }

    /// The transfer screen sends the outgoing owner's admin record in the same
    /// update as the transfer: it is signed while the founder still owns the
    /// board, so the delta cannot wait for the transfer to be recorded.
    #[test]
    fn an_invalid_state_cannot_wipe_the_accepted_chain() {
        let fixture = fixture();
        let mut ownership = OwnershipV1::default();
        ownership
            .apply_delta(
                &fixture.state,
                &fixture.parameters,
                &Some(OwnershipDelta {
                    transfers: vec![transfer(
                        fixture.owner_id,
                        fixture.admin_id,
                        fixture.admin_sk.verifying_key(),
                        1,
                        fixture.now,
                        &fixture.owner_sk,
                    )],
                    deactivations: Vec::new(),
                succession_votes: Vec::new(),
                }),
            )
            .unwrap();
        assert_eq!(ownership.transfers.len(), 1);

        // A later "keep admin" bundle re-issued the new owner's record with a
        // newer timestamp: the accepted transfer no longer verifies.
        let mut later = fixture.state.clone();
        later.admin.admins = vec![AuthorizedAdmin::new(
            Admin {
                member_id: fixture.admin_id,
                generation: 2,
                signed_at: fixture.now + std::time::Duration::from_secs(3600),
            },
            &fixture.owner_sk,
        )];

        ownership
            .apply_delta(
                &later,
                &fixture.parameters,
                &Some(OwnershipDelta {
                    transfers: Vec::new(),
                    deactivations: Vec::new(),
                succession_votes: Vec::new(),
                }),
            )
            .unwrap();

        assert_eq!(
            ownership.transfers.len(),
            1,
            "the accepted transfer is kept even when it stops verifying"
        );
        assert_eq!(
            ownership.current_owner(&fixture.parameters),
            fixture.admin_id
        );
    }

    #[test]
    fn the_founding_owner_keeps_admin_rights_across_the_transfer() {
        let mut fixture = fixture();
        let parent = fixture.state.clone();
        // The UI signs the outgoing record first and dates the transfer two
        // milliseconds later, so the record resolves the founder as authority.
        let transferred_at = fixture.now + std::time::Duration::from_millis(2);
        let outgoing_admin = AuthorizedAdmin::new(
            Admin {
                member_id: fixture.owner_id,
                generation: 1,
                signed_at: fixture.now,
            },
            &fixture.owner_sk,
        );

        fixture
            .state
            .apply_delta(
                &parent,
                &fixture.parameters,
                &Some(ChatBoardStateV1Delta {
                    ownership: Some(OwnershipDelta {
                        transfers: vec![transfer(
                            fixture.owner_id,
                            fixture.admin_id,
                            fixture.admin_sk.verifying_key(),
                            1,
                            transferred_at,
                            &fixture.owner_sk,
                        )],
                        deactivations: Vec::new(),
                succession_votes: Vec::new(),
                    }),
                    admin: Some(AdminsDelta::new(vec![outgoing_admin])),
                    members: Some(MembersDelta::new(vec![AuthorizedMember::new(
                        Member {
                            owner_member_id: fixture.owner_id,
                            invited_by: fixture.owner_id,
                            member_vk: fixture.owner_sk.verifying_key(),
                            join_proof: None,
                        },
                        &fixture.owner_sk,
                    )])),
                    ..Default::default()
                }),
            )
            .expect("the transfer and the outgoing admin record apply together");

        assert!(
            fixture
                .state
                .members
                .members
                .iter()
                .any(|member| member.member.id() == fixture.owner_id),
            "the former owner stays a member"
        );

        assert!(fixture
            .state
            .admin
            .admins
            .iter()
            .any(|admin| admin.admin.id() == fixture.owner_id));
        fixture
            .state
            .verify(&fixture.state.clone(), &fixture.parameters)
            .expect("the state verifies after the transfer");

        let later = fixture.now + std::time::Duration::from_secs(60);
        verify_admin_authority(
            &fixture.state,
            &fixture.parameters,
            &fixture.owner_id,
            None,
            8,
            later,
        )
        .expect("the former owner keeps its admin powers");
    }

    /// The UI bundle for "I become a plain member": the outgoing owner keeps
    /// its member record and loses its admin appointment.
    #[test]
    fn the_old_owner_can_step_down_to_a_plain_member() {
        let mut fixture = fixture();
        let first_sign = fixture.now;
        let first_at = first_sign + std::time::Duration::from_millis(2);
        // The founder hands the board over and stays admin: the bundle carries
        // its member record and its appointment.
        let parent = fixture.state.clone();
        fixture
            .state
            .apply_delta(
                &parent,
                &fixture.parameters,
                &Some(ChatBoardStateV1Delta {
                    ownership: Some(OwnershipDelta {
                        transfers: vec![transfer(
                            fixture.owner_id,
                            fixture.admin_id,
                            fixture.admin_sk.verifying_key(),
                            1,
                            first_at,
                            &fixture.owner_sk,
                        )],
                        deactivations: Vec::new(),
                succession_votes: Vec::new(),
                    }),
                    members: Some(MembersDelta::new(vec![AuthorizedMember::new(
                        Member {
                            owner_member_id: fixture.owner_id,
                            invited_by: fixture.owner_id,
                            member_vk: fixture.owner_sk.verifying_key(),
                            join_proof: None,
                        },
                        &fixture.owner_sk,
                    )])),
                    admin: Some(AdminsDelta::new(vec![AuthorizedAdmin::new(
                        Admin {
                            member_id: fixture.owner_id,
                            generation: fixture.state.admin.next_generation(&fixture.owner_id),
                            signed_at: first_sign,
                        },
                        &fixture.owner_sk,
                    )])),
                    ..Default::default()
                }),
            )
            .expect("the first transfer applies");

        // The admin hands the board back and steps down to a plain member.
        let back_sign = first_at + std::time::Duration::from_secs(60);
        let back_at = back_sign + std::time::Duration::from_millis(2);
        let revocation = AdminRevocation {
            member_id: fixture.admin_id,
            generation: fixture.state.admin.next_generation(&fixture.admin_id),
            signed_at: back_sign,
            appointed_at: None,
        };
        let parent = fixture.state.clone();
        fixture
            .state
            .apply_delta(
                &parent,
                &fixture.parameters,
                &Some(ChatBoardStateV1Delta {
                    ownership: Some(OwnershipDelta {
                        transfers: vec![transfer_with_outgoing(
                            fixture.admin_id,
                            fixture.owner_id,
                            fixture.owner_sk.verifying_key(),
                            2,
                            back_at,
                            &fixture.admin_sk,
                            OutgoingOwnerAction::Member,
                        )],
                        deactivations: Vec::new(),
                succession_votes: Vec::new(),
                    }),
                    admin: Some(AdminsDelta::revocation(vec![
                        AuthorizedAdminRevocation::with_signature(
                            revocation.clone(),
                            sign_struct(&revocation, &fixture.admin_sk),
                        ),
                    ])),
                    ..Default::default()
                }),
            )
            .expect("the handover back with a plain-member outcome applies");

        assert_eq!(
            fixture.state.ownership.current_owner(&fixture.parameters),
            fixture.owner_id
        );
        assert!(
            fixture
                .state
                .admin
                .admins
                .iter()
                .all(|admin| admin.admin.id() != fixture.admin_id),
            "the outgoing owner lost its appointment"
        );
        assert!(
            fixture
                .state
                .members
                .members
                .iter()
                .any(|member| member.member.id() == fixture.admin_id),
            "the outgoing owner stays a member"
        );
        fixture
            .state
            .normalize(&fixture.parameters)
            .expect("cleanup accepts the stepped-down owner");
        fixture
            .state
            .verify(&fixture.state.clone(), &fixture.parameters)
            .expect("the state verifies after the handover");
        assert_eq!(
            fixture.state.ownership.transfers.len(),
            2,
            "cleanup kept the chain"
        );

        // The former owner can no longer transfer: the delta changes nothing.
        let late = back_sign + std::time::Duration::from_secs(60);
        let parent = fixture.state.clone();
        fixture
            .state
            .apply_delta(
                &parent,
                &fixture.parameters,
                &Some(ChatBoardStateV1Delta {
                    ownership: Some(OwnershipDelta {
                        transfers: vec![transfer(
                            fixture.admin_id,
                            fixture.admin_id,
                            fixture.admin_sk.verifying_key(),
                            3,
                            late,
                            &fixture.admin_sk,
                        )],
                        deactivations: Vec::new(),
                succession_votes: Vec::new(),
                    }),
                    ..Default::default()
                }),
            )
            .expect("a refused ownership delta is not an apply error");
        assert_eq!(
            fixture.state.ownership.transfers.len(),
            2,
            "the stepped-down admin cannot transfer"
        );
        assert_eq!(
            fixture.state.ownership.current_owner(&fixture.parameters),
            fixture.owner_id
        );
    }

    /// The UI bundle for "I deactivate my key on this board": the outgoing
    /// owner retires its key and its appointment.
    #[test]
    fn the_old_owner_can_deactivate_its_key() {
        let mut fixture = fixture();
        let first_sign = fixture.now;
        let first_at = first_sign + std::time::Duration::from_millis(2);
        apply(
            &mut fixture.state,
            &fixture.parameters,
            OwnershipDelta {
                transfers: vec![transfer(
                    fixture.owner_id,
                    fixture.admin_id,
                    fixture.admin_sk.verifying_key(),
                    1,
                    first_at,
                    &fixture.owner_sk,
                )],
                deactivations: Vec::new(),
                succession_votes: Vec::new(),
            },
        );

        let back_sign = first_at + std::time::Duration::from_secs(60);
        let back_at = back_sign + std::time::Duration::from_millis(2);
        let revocation = AdminRevocation {
            member_id: fixture.admin_id,
            generation: fixture.state.admin.next_generation(&fixture.admin_id),
            signed_at: back_sign,
            appointed_at: None,
        };
        let parent = fixture.state.clone();
        fixture
            .state
            .apply_delta(
                &parent,
                &fixture.parameters,
                &Some(ChatBoardStateV1Delta {
                    ownership: Some(OwnershipDelta {
                        transfers: vec![transfer_with_outgoing(
                            fixture.admin_id,
                            fixture.owner_id,
                            fixture.owner_sk.verifying_key(),
                            2,
                            back_at,
                            &fixture.admin_sk,
                            OutgoingOwnerAction::Deactivate,
                        )],
                        deactivations: vec![AuthorizedKeyDeactivation::new(
                            KeyDeactivationV1 {
                                member: fixture.admin_id,
                                key: fixture.admin_sk.verifying_key(),
                                generation: 1,
                                deactivated_at: back_sign,
                            },
                            &fixture.admin_sk,
                        )],
                        succession_votes: Vec::new(),
                    }),
                    admin: Some(AdminsDelta::revocation(vec![
                        AuthorizedAdminRevocation::with_signature(
                            revocation.clone(),
                            sign_struct(&revocation, &fixture.admin_sk),
                        ),
                    ])),
                    ..Default::default()
                }),
            )
            .expect("the handover back with a deactivation applies");

        assert_eq!(
            fixture.state.ownership.current_owner(&fixture.parameters),
            fixture.owner_id
        );
        assert!(fixture
            .state
            .ownership
            .is_deactivated_now(&fixture.admin_id));
        assert_eq!(fixture.state.ownership.deactivations.len(), 1);
        assert!(fixture
            .state
            .admin
            .admins
            .iter()
            .all(|admin| admin.admin.id() != fixture.admin_id));
        fixture
            .state
            .normalize(&fixture.parameters)
            .expect("cleanup accepts the deactivated owner");
        fixture
            .state
            .verify(&fixture.state.clone(), &fixture.parameters)
            .expect("the state verifies with a deactivated outgoing owner");
    }

    #[test]
    fn the_board_can_return_to_the_founding_owner() {
        let mut fixture = fixture();
        let first_at = fixture.now;
        apply(
            &mut fixture.state,
            &fixture.parameters,
            OwnershipDelta {
                transfers: vec![transfer(
                    fixture.owner_id,
                    fixture.admin_id,
                    fixture.admin_sk.verifying_key(),
                    1,
                    first_at,
                    &fixture.owner_sk,
                )],
                deactivations: Vec::new(),
                succession_votes: Vec::new(),
            },
        );

        // The new owner hands the board back to the founder, who is no longer
        // on the members list by then: the owner is implicit.
        let back_at = first_at + std::time::Duration::from_secs(60);
        apply(
            &mut fixture.state,
            &fixture.parameters,
            OwnershipDelta {
                transfers: vec![transfer(
                    fixture.admin_id,
                    fixture.owner_id,
                    fixture.owner_sk.verifying_key(),
                    2,
                    back_at,
                    &fixture.admin_sk,
                )],
                deactivations: Vec::new(),
                succession_votes: Vec::new(),
            },
        );

        assert_eq!(
            fixture.state.ownership.current_owner(&fixture.parameters),
            fixture.owner_id
        );
        fixture
            .state
            .normalize(&fixture.parameters)
            .expect("cleanup accepts the returned board");
        fixture
            .state
            .verify(&fixture.state.clone(), &fixture.parameters)
            .expect("the state verifies after the return transfer");
    }

    #[test]
    fn the_new_owner_can_transfer_again() {        let mut fixture = fixture();
        let second_sk = SigningKey::from_bytes(&[3u8; 32]);
        let second_id = MemberId::from(&second_sk.verifying_key());
        fixture.state.members.members.push(AuthorizedMember::new(
            Member {
                owner_member_id: fixture.owner_id,
                invited_by: fixture.admin_id,
                member_vk: second_sk.verifying_key(),
                join_proof: None,
            },
            &fixture.admin_sk,
        ));
        fixture.state.admin.admins.push(AuthorizedAdmin::new(
            Admin {
                member_id: second_id,
                generation: 1,
                signed_at: fixture.now,
            },
            &fixture.admin_sk,
        ));

        apply(
            &mut fixture.state,
            &fixture.parameters,
            OwnershipDelta {
                transfers: vec![
                    transfer(
                        fixture.owner_id,
                        fixture.admin_id,
                        fixture.admin_sk.verifying_key(),
                        1,
                        fixture.now,
                        &fixture.owner_sk,
                    ),
                    transfer(
                        fixture.admin_id,
                        second_id,
                        second_sk.verifying_key(),
                        2,
                        fixture.now + std::time::Duration::from_secs(1),
                        &fixture.admin_sk,
                    ),
                ],
                deactivations: Vec::new(),
                succession_votes: Vec::new(),
            },
        );

        assert_eq!(
            fixture.state.ownership.current_owner(&fixture.parameters),
            second_id
        );
        fixture
            .state
            .verify(&fixture.state.clone(), &fixture.parameters)
            .expect("the chain verifies");
    }

    #[test]
    fn a_promotion_then_transfer_in_two_updates_succeeds() {
        let mut fixture = fixture();
        fixture.state.admin.admins.clear();
        let now = std::time::SystemTime::now();
        let parent = fixture.state.clone();
        fixture
            .state
            .apply_delta(
                &parent,
                &fixture.parameters,
                &Some(ChatBoardStateV1Delta {
                    admin: Some(crate::board_state::admin::AdminsDelta::new(vec![
                        AuthorizedAdmin::new(
                            Admin {
                                member_id: fixture.admin_id,
                                generation: 1,
                                signed_at: now,
                            },
                            &fixture.owner_sk,
                        ),
                    ])),
                    ..Default::default()
                }),
            )
            .expect("promotion applies");

        apply(
            &mut fixture.state,
            &fixture.parameters,
            OwnershipDelta {
                transfers: vec![transfer(
                    fixture.owner_id,
                    fixture.admin_id,
                    fixture.admin_sk.verifying_key(),
                    1,
                    now + std::time::Duration::from_millis(2),
                    &fixture.owner_sk,
                )],
                deactivations: Vec::new(),
                succession_votes: Vec::new(),
            },
        );

        assert_eq!(
            fixture.state.ownership.current_owner(&fixture.parameters),
            fixture.admin_id,
            "the transfer must survive cleanup"
        );
    }

    #[test]
    fn a_transfer_target_must_be_an_admin() {
        let mut fixture = fixture();
        fixture.state.admin.admins.clear();
        let parent = fixture.state.clone();
        let error = fixture
            .state
            .apply_delta(
                &parent,
                &fixture.parameters,
                &Some(ChatBoardStateV1Delta {
                    ownership: Some(OwnershipDelta {
                        transfers: vec![transfer(
                            fixture.owner_id,
                            fixture.admin_id,
                            fixture.admin_sk.verifying_key(),
                            1,
                            fixture.now,
                            &fixture.owner_sk,
                        )],
                        deactivations: Vec::new(),
                succession_votes: Vec::new(),
                    }),
                    ..Default::default()
                }),
            );
        // cleanup drops the record, so the state keeps the founding owner.
        assert_eq!(
            fixture.state.ownership.current_owner(&fixture.parameters),
            fixture.owner_id
        );
        let _ = error;
    }

    #[test]
    fn a_deactivated_key_cannot_sign_later() {
        let mut fixture = fixture();
        apply(
            &mut fixture.state,
            &fixture.parameters,
            OwnershipDelta {
                transfers: vec![transfer(
                    fixture.owner_id,
                    fixture.admin_id,
                    fixture.admin_sk.verifying_key(),
                    1,
                    fixture.now,
                    &fixture.owner_sk,
                )],
                deactivations: vec![AuthorizedKeyDeactivation::new(
                    KeyDeactivationV1 {
                        member: fixture.owner_id,
                        key: fixture.owner_sk.verifying_key(),
                        generation: 1,
                        deactivated_at: fixture.now,
                    },
                    &fixture.owner_sk,
                )],
                succession_votes: Vec::new(),
            },
        );

        let later = fixture.now + std::time::Duration::from_secs(60);
        assert!(fixture
            .state
            .ownership
            .is_deactivated_at(&fixture.owner_id, later));
        assert!(verify_admin_authority(
            &fixture.state,
            &fixture.parameters,
            &fixture.owner_id,
            None,
            8,
            later,
        )
        .is_err());
        // The retired key cannot vouch for later records, but the board with
        // the new owner stays valid.
        assert!(fixture
            .state
            .verify(&fixture.state.clone(), &fixture.parameters)
            .is_ok());
    }

    fn add_admin(fixture: &mut Fixture, seed: u8) -> (SigningKey, MemberId) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let id = MemberId::from(&sk.verifying_key());
        fixture.state.members.members.push(AuthorizedMember::new(
            Member {
                owner_member_id: fixture.owner_id,
                invited_by: fixture.owner_id,
                member_vk: sk.verifying_key(),
                join_proof: None,
            },
            &fixture.owner_sk,
        ));
        fixture.state.admin.admins.push(AuthorizedAdmin::new(
            Admin {
                member_id: id,
                generation: 1,
                signed_at: SystemTime::UNIX_EPOCH,
            },
            &fixture.owner_sk,
        ));
        (sk, id)
    }

    fn succession_vote(
        from: MemberId,
        to: MemberId,
        to_key: VerifyingKey,
        generation: u64,
        voter_sk: &SigningKey,
        signed_at: SystemTime,
    ) -> AuthorizedSuccessionVoteV1 {
        AuthorizedSuccessionVoteV1::new(
            SuccessionVoteV1 {
                from,
                to,
                to_key,
                generation,
                voter: MemberId::from(&voter_sk.verifying_key()),
                voter_key: voter_sk.verifying_key(),
                signed_at,
            },
            voter_sk,
        )
    }

    #[test]
    fn admin_quorum_succession_promotes_new_owner_and_clears_votes() {
        let mut fixture = fixture();
        let (admin2_sk, admin2_id) = add_admin(&mut fixture, 3);
        let (_admin3_sk, _admin3_id) = add_admin(&mut fixture, 4);
        assert_eq!(required_succession_quorum(3), Some(2));

        let vote1 = succession_vote(
            fixture.owner_id,
            admin2_id,
            admin2_sk.verifying_key(),
            1,
            &fixture.admin_sk,
            fixture.now,
        );
        // First admin records a pending vote on the board.
        apply(
            &mut fixture.state,
            &fixture.parameters,
            OwnershipDelta {
                transfers: Vec::new(),
                deactivations: Vec::new(),
                succession_votes: vec![vote1.clone()],
            },
        );
        assert_eq!(fixture.state.ownership.succession_votes.len(), 1);
        assert_eq!(
            fixture.state.ownership.current_owner(&fixture.parameters),
            fixture.owner_id
        );

        // Second admin casts the quorum vote and finalizes the succession
        // transfer without any signature from the unreachable owner.
        let vote2 = succession_vote(
            fixture.owner_id,
            admin2_id,
            admin2_sk.verifying_key(),
            1,
            &admin2_sk,
            fixture.now + std::time::Duration::from_millis(1),
        );
        let transferred_at = fixture.now + std::time::Duration::from_millis(2);
        let succession = AuthorizedOwnerTransfer::new_by_succession(
            OwnerTransferV1 {
                from: fixture.owner_id,
                to: admin2_id,
                to_key: admin2_sk.verifying_key(),
                generation: 1,
                transferred_at,
                outgoing: OutgoingOwnerAction::Member,
            },
            vec![vote1, vote2.clone()],
            &admin2_sk,
        );
        apply(
            &mut fixture.state,
            &fixture.parameters,
            OwnershipDelta {
                transfers: vec![succession],
                deactivations: Vec::new(),
                succession_votes: vec![vote2],
            },
        );

        assert_eq!(
            fixture.state.ownership.current_owner(&fixture.parameters),
            admin2_id
        );
        assert!(
            fixture.state.ownership.succession_votes.is_empty(),
            "pending votes are cleared once the generation completes"
        );
        fixture
            .state
            .verify(&fixture.state.clone(), &fixture.parameters)
            .expect("state verifies after quorum succession");

        // The new owner can update owner-only configuration immediately.
        let mut next_config = fixture.state.configuration.configuration.clone();
        next_config.configuration_version += 1;
        next_config.updated_at = transferred_at + std::time::Duration::from_secs(10);
        let parent = fixture.state.clone();
        fixture
            .state
            .apply_delta(
                &parent,
                &fixture.parameters,
                &Some(ChatBoardStateV1Delta {
                    configuration: Some(AuthorizedConfigurationV1::new(next_config, &admin2_sk)),
                    ..Default::default()
                }),
            )
            .expect("the successor can update board configuration");
    }

    #[test]
    fn single_admin_cannot_seize_ownership_via_succession() {
        let mut fixture = fixture();
        // Only 1 active admin: quorum is None.
        assert_eq!(required_succession_quorum(1), None);
        let vote1 = succession_vote(
            fixture.owner_id,
            fixture.admin_id,
            fixture.admin_sk.verifying_key(),
            1,
            &fixture.admin_sk,
            fixture.now,
        );
        let bogus = AuthorizedOwnerTransfer::new_by_succession(
            OwnerTransferV1 {
                from: fixture.owner_id,
                to: fixture.admin_id,
                to_key: fixture.admin_sk.verifying_key(),
                generation: 1,
                transferred_at: fixture.now + std::time::Duration::from_millis(2),
                outgoing: OutgoingOwnerAction::Member,
            },
            vec![vote1],
            &fixture.admin_sk,
        );
        apply(
            &mut fixture.state,
            &fixture.parameters,
            OwnershipDelta {
                transfers: vec![bogus],
                deactivations: Vec::new(),
                succession_votes: Vec::new(),
            },
        );
        assert_eq!(
            fixture.state.ownership.current_owner(&fixture.parameters),
            fixture.owner_id,
            "a single admin must not succeed without quorum"
        );
    }

    #[test]
    fn insufficient_quorum_and_duplicate_votes_are_rejected() {
        let mut fixture = fixture();
        let (admin2_sk, admin2_id) = add_admin(&mut fixture, 3);
        let (_admin3_sk, _admin3_id) = add_admin(&mut fixture, 4);
        let (_admin4_sk, _admin4_id) = add_admin(&mut fixture, 5);
        // 4 admins require 3 votes.
        assert_eq!(required_succession_quorum(4), Some(3));

        let vote1 = succession_vote(
            fixture.owner_id,
            admin2_id,
            admin2_sk.verifying_key(),
            1,
            &fixture.admin_sk,
            fixture.now,
        );
        let vote2 = succession_vote(
            fixture.owner_id,
            admin2_id,
            admin2_sk.verifying_key(),
            1,
            &admin2_sk,
            fixture.now,
        );
        // 2 votes out of 4 admins (even with a duplicate) must be rejected.
        let dup_transfer = AuthorizedOwnerTransfer::new_by_succession(
            OwnerTransferV1 {
                from: fixture.owner_id,
                to: admin2_id,
                to_key: admin2_sk.verifying_key(),
                generation: 1,
                transferred_at: fixture.now + std::time::Duration::from_millis(2),
                outgoing: OutgoingOwnerAction::Member,
            },
            vec![vote1.clone(), vote2, vote1],
            &admin2_sk,
        );
        let mut trial = fixture.state.ownership.clone();
        trial.transfers.push(dup_transfer);
        assert!(trial.verify(&fixture.state, &fixture.parameters).is_err());
    }

    #[test]
    fn revoked_admin_vote_is_dropped_by_cleanup() {
        let mut fixture = fixture();
        let (admin2_sk, admin2_id) = add_admin(&mut fixture, 3);
        let vote1 = succession_vote(
            fixture.owner_id,
            admin2_id,
            admin2_sk.verifying_key(),
            1,
            &fixture.admin_sk,
            fixture.now,
        );
        apply(
            &mut fixture.state,
            &fixture.parameters,
            OwnershipDelta {
                transfers: Vec::new(),
                deactivations: Vec::new(),
                succession_votes: vec![vote1],
            },
        );
        assert_eq!(fixture.state.ownership.succession_votes.len(), 1);

        // Owner returns and revokes admin1: their pending vote disappears.
        let rev = AdminRevocation {
            member_id: fixture.admin_id,
            generation: fixture.state.admin.next_generation(&fixture.admin_id),
            signed_at: fixture.now + std::time::Duration::from_secs(5),
            appointed_at: None,
        };
        let parent = fixture.state.clone();
        fixture
            .state
            .apply_delta(
                &parent,
                &fixture.parameters,
                &Some(ChatBoardStateV1Delta {
                    admin: Some(AdminsDelta::revocation(vec![
                        AuthorizedAdminRevocation::with_signature(
                            rev.clone(),
                            sign_struct(&rev, &fixture.owner_sk),
                        ),
                    ])),
                    ..Default::default()
                }),
            )
            .expect("revocation applies");
        assert!(
            fixture.state.ownership.succession_votes.is_empty(),
            "revoked admin vote must be dropped"
        );
    }

    #[test]
    fn future_admin_appointed_and_revoked_after_succession_does_not_break_historical_quorum() {
        let mut fixture = fixture();
        let (admin2_sk, admin2_id) = add_admin(&mut fixture, 3);
        // 2 admins => quorum is 2.
        let transferred_at = fixture.now + std::time::Duration::from_secs(10);
        let vote1 = succession_vote(
            fixture.owner_id,
            admin2_id,
            admin2_sk.verifying_key(),
            1,
            &fixture.admin_sk,
            fixture.now,
        );
        let vote2 = succession_vote(
            fixture.owner_id,
            admin2_id,
            admin2_sk.verifying_key(),
            1,
            &admin2_sk,
            fixture.now,
        );
        let transfer = AuthorizedOwnerTransfer::new_by_succession(
            OwnerTransferV1 {
                from: fixture.owner_id,
                to: admin2_id,
                to_key: admin2_sk.verifying_key(),
                generation: 1,
                transferred_at,
                outgoing: OutgoingOwnerAction::Member,
            },
            vec![vote1, vote2],
            &admin2_sk,
        );
        apply(
            &mut fixture.state,
            &fixture.parameters,
            OwnershipDelta {
                transfers: vec![transfer],
                deactivations: Vec::new(),
                succession_votes: Vec::new(),
            },
        );
        assert_eq!(
            fixture.state.ownership.current_owner(&fixture.parameters),
            admin2_id
        );

        // Later, the new owner (admin2) appoints two new admins (admin3 & admin4)
        // and subsequently revokes them with `appointed_at` populated.
        // Without `appointed_at`, `active_admins_at(transferred_at)` would count
        // 4 historical admins (quorum 3) and invalidate the earlier 2-of-2 transfer!
        let appointed_later = transferred_at + std::time::Duration::from_secs(60);
        let revoked_later = transferred_at + std::time::Duration::from_secs(120);
        for seed in [11u8, 12u8] {
            let sk = SigningKey::from_bytes(&[seed; 32]);
            let id = MemberId::from(&sk.verifying_key());
            let member = AuthorizedMember::new(
                Member {
                    owner_member_id: fixture.owner_id,
                    invited_by: admin2_id,
                    member_vk: sk.verifying_key(),
                    join_proof: None,
                },
                &admin2_sk,
            );
            let admin = AuthorizedAdmin::new(
                Admin {
                    member_id: id,
                    generation: 1,
                    signed_at: appointed_later,
                },
                &admin2_sk,
            );
            let parent = fixture.state.clone();
            fixture
                .state
                .apply_delta(
                    &parent,
                    &fixture.parameters,
                    &Some(ChatBoardStateV1Delta {
                        members: Some(MembersDelta::new(vec![member])),
                        admin: Some(AdminsDelta::new(vec![admin])),
                        ..Default::default()
                    }),
                )
                .expect("new owner appoints later admin");

            let revocation = AuthorizedAdminRevocation::new_at_with_appointment(
                id,
                fixture.state.admin.next_generation(&id),
                revoked_later,
                Some(appointed_later),
                &admin2_sk,
            );
            let parent = fixture.state.clone();
            fixture
                .state
                .apply_delta(
                    &parent,
                    &fixture.parameters,
                    &Some(ChatBoardStateV1Delta {
                        admin: Some(AdminsDelta::revocation(vec![revocation])),
                        ..Default::default()
                    }),
                )
                .expect("new owner revokes later admin");
        }

        fixture
            .state
            .verify(&fixture.state.clone(), &fixture.parameters)
            .expect("historical 2-of-2 succession must still verify after later admins are revoked");
    }

    #[test]
    fn succession_timelock_blocks_early_transfer_and_allows_after_grace_period() {
        let mut fixture = fixture();
        let (admin2_sk, admin2_id) = add_admin(&mut fixture, 3);

        // Configure a 1-hour succession timelock.
        let mut cfg = fixture.state.configuration.configuration.clone();
        cfg.configuration_version += 1;
        cfg.succession_timelock_secs = 3_600;
        cfg.updated_at = fixture.now;
        let parent = fixture.state.clone();
        fixture
            .state
            .apply_delta(
                &parent,
                &fixture.parameters,
                &Some(ChatBoardStateV1Delta {
                    configuration: Some(AuthorizedConfigurationV1::new(cfg, &fixture.owner_sk)),
                    ..Default::default()
                }),
            )
            .expect("owner sets succession timelock");

        let vote_time = fixture.now + std::time::Duration::from_secs(10);
        let vote1 = succession_vote(
            fixture.owner_id,
            admin2_id,
            admin2_sk.verifying_key(),
            1,
            &fixture.admin_sk,
            vote_time,
        );
        let vote2 = succession_vote(
            fixture.owner_id,
            admin2_id,
            admin2_sk.verifying_key(),
            1,
            &admin2_sk,
            vote_time,
        );

        // Attempt to finalize after only 60 seconds: rejected.
        let early_transfer = AuthorizedOwnerTransfer::new_by_succession(
            OwnerTransferV1 {
                from: fixture.owner_id,
                to: admin2_id,
                to_key: admin2_sk.verifying_key(),
                generation: 1,
                transferred_at: vote_time + std::time::Duration::from_secs(60),
                outgoing: OutgoingOwnerAction::Member,
            },
            vec![vote1.clone(), vote2.clone()],
            &admin2_sk,
        );
        let mut trial = fixture.state.ownership.clone();
        trial.transfers.push(early_transfer);
        let err = trial
            .verify(&fixture.state, &fixture.parameters)
            .expect_err("early succession must fail timelock");
        assert!(err.contains("timelock"), "unexpected error: {err}");

        // Finalize after the 1-hour grace period elapses: accepted.
        let mature_transfer = AuthorizedOwnerTransfer::new_by_succession(
            OwnerTransferV1 {
                from: fixture.owner_id,
                to: admin2_id,
                to_key: admin2_sk.verifying_key(),
                generation: 1,
                transferred_at: vote_time + std::time::Duration::from_secs(3_600),
                outgoing: OutgoingOwnerAction::Member,
            },
            vec![vote1, vote2],
            &admin2_sk,
        );
        apply(
            &mut fixture.state,
            &fixture.parameters,
            OwnershipDelta {
                transfers: vec![mature_transfer],
                deactivations: Vec::new(),
                succession_votes: Vec::new(),
            },
        );
        assert_eq!(
            fixture.state.ownership.current_owner(&fixture.parameters),
            admin2_id
        );
        fixture
            .state
            .verify(&fixture.state.clone(), &fixture.parameters)
            .expect("matured succession verifies");
    }
}

