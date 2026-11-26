//! Sharded per-board member directory, kept outside the parent board state.
//!
//! A board with 10,000 members carried ~3.35 MiB of `AuthorizedMember` records
//! inline, and every join rewrote and re-broadcast the parent board. Members
//! now live in deterministic buckets (`MEMBER_SHARD_COUNT` fixed shards
//! addressed by `{ owner, bucket }`):
//! - no owner is needed online to open new pages,
//! - each join is a ~0.4 KiB delta to one shard with zero writes to the parent
//!   board,
//! - each shard entry is self-verifying (carrying its invite chain or invite
//!   token) so the contract validates deltas without fetching the other shards.

use crate::board_state::admin::AuthorizedAdmin;
use crate::board_state::invites::{join_message, AuthorizedInviteToken};
use crate::board_state::member::{AuthorizedMember, MemberId, MembersV1};
use crate::board_state::ownership::{
    AuthorizedOwnerTransfer, MAX_OWNER_TRANSFERS, MAX_SUCCESSION_VOTES,
};
use crate::board_state::rate_limit::system_time_ms;
use crate::board_state::roles::AuthorityProof;
use crate::board_state::ChatBoardParametersV1;
use crate::util::verify_struct;
use crate::ChatBoardStateV1;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};

/// Fixed number of deterministic member buckets per board.
/// With 32 buckets, 10,000 members average ~312 entries (~105 KiB) per shard.
pub const MEMBER_SHARD_COUNT: u16 = 32;
/// Hard cap on entries in one shard, enforced by the contract.
pub const MAX_MEMBERS_PER_SHARD: usize = 2_000;
/// Maximum invite-chain depth accepted inside one shard entry.
pub const MAX_MEMBER_INVITE_CHAIN: usize = 64;
/// Maximum nested authority proof depth when verifying delegated invite tokens
/// inside a standalone shard contract.
const MAX_SHARD_AUTHORITY_DEPTH: u8 = 8;

/// Deterministic bucket index for a member id.
pub fn member_shard_bucket(member_id: &MemberId) -> u16 {
    let digest = blake3::hash(member_id.as_bytes());
    let prefix = u16::from_le_bytes([digest.as_bytes()[0], digest.as_bytes()[1]]);
    prefix % MEMBER_SHARD_COUNT
}

/// Contract parameters for one member shard of a board.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct MemberShardParametersV1 {
    pub owner: VerifyingKey,
    pub bucket: u16,
}

impl MemberShardParametersV1 {
    pub fn owner_id(&self) -> MemberId {
        MemberId::from(&self.owner)
    }

    pub fn verify(&self) -> Result<(), String> {
        if self.bucket >= MEMBER_SHARD_COUNT {
            return Err(format!(
                "member shard bucket {} out of range (max {})",
                self.bucket,
                MEMBER_SHARD_COUNT - 1
            ));
        }
        Ok(())
    }
}

/// One member record plus the proof material needed to verify it independently
/// of the other shards.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct MemberShardEntryV1 {
    pub member: AuthorizedMember,
    /// Ancestor member records from `member.invited_by` up to a board owner
    /// (or to a token-joined ancestor). Empty when invited directly by an
    /// owner or joined via token.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub invite_chain: Vec<AuthorizedMember>,
    /// Invite token used when `member` (or the root of `invite_chain`) joined
    /// through an invite link.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_token: Option<AuthorizedInviteToken>,
    /// Founding-to-current ownership transfer chain when the inviter or token
    /// signer is a post-transfer owner (or an admin appointed by one). Empty
    /// on boards that never transferred ownership.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ownership_transfers: Vec<AuthorizedOwnerTransfer>,
    /// Admin appointment records needed to verify admin-quorum succession
    /// transfers inside `ownership_transfers`. Empty for normal transfers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transfer_admins: Vec<AuthorizedAdmin>,
}

/// Self-contained cryptographic proof that a member belongs to `board_owner`,
/// reusable across standalone per-board contracts (`profile`, `activity`,
/// `moderation`) without fetching the parent board or member shards.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct MemberProofV1 {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ownership_transfers: Vec<AuthorizedOwnerTransfer>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transfer_admins: Vec<AuthorizedAdmin>,
    /// Membership entry proving the member's invite chain or invite token.
    /// `None` only when the subject is itself a verified owner in
    /// `ownership_transfers`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership: Option<Box<MemberShardEntryV1>>,
}

/// Verify an ownership transfer chain starting at `founding_owner` and return
/// every valid owner key along the chain (including `founding_owner`).
pub fn verify_ownership_chain(
    founding_owner: &VerifyingKey,
    transfers: &[AuthorizedOwnerTransfer],
    transfer_admins: &[AuthorizedAdmin],
) -> Result<Vec<VerifyingKey>, String> {
    if transfers.len() > MAX_OWNER_TRANSFERS {
        return Err("ownership transfer chain exceeds maximum length".to_string());
    }
    if transfer_admins.len() > MAX_SUCCESSION_VOTES {
        return Err("too many transfer admin records in standalone proof".to_string());
    }
    let mut owner_history: Vec<(i64, VerifyingKey)> = vec![(i64::MIN, *founding_owner)];
    let mut keys = vec![*founding_owner];
    let mut from_key = *founding_owner;
    let mut from_id = MemberId::from(&from_key);
    let mut generation = 1u64;
    let mut last_time = 0i64;

    for entry in transfers {
        let transfer = &entry.transfer;
        if transfer.from != from_id {
            return Err("standalone ownership transfer chain is broken".to_string());
        }
        if transfer.generation != generation {
            return Err("standalone ownership transfer generation is not sequential".to_string());
        }
        let at = system_time_ms(transfer.transferred_at);
        if at < last_time {
            return Err("standalone ownership transfer time goes backwards".to_string());
        }
        if transfer.to == transfer.from {
            return Err("owner cannot transfer board to itself".to_string());
        }
        if MemberId::from(&transfer.to_key) != transfer.to {
            return Err("ownership transfer target key does not match id".to_string());
        }

        if entry.succession_approvals.is_empty() {
            entry.verify_signature(&from_key)?;
        } else {
            if entry.succession_approvals.len() > MAX_SUCCESSION_VOTES {
                return Err("too many succession approvals on transfer".to_string());
            }
            let owner_key_at_ms = |ms: i64| -> VerifyingKey {
                owner_history
                    .iter()
                    .rev()
                    .find(|(since, _)| *since <= ms)
                    .map(|(_, k)| *k)
                    .unwrap_or(*founding_owner)
            };
            let mut active_admins: std::collections::HashMap<MemberId, i64> =
                std::collections::HashMap::new();
            for admin in transfer_admins {
                let admin_ms = system_time_ms(admin.admin.signed_at);
                if admin_ms > at || admin.admin.id() == transfer.from {
                    continue;
                }
                let expected_owner = owner_key_at_ms(admin_ms);
                if admin.verify_signature(&expected_owner).is_ok() {
                    active_admins
                        .entry(admin.admin.id())
                        .and_modify(|prev| *prev = (*prev).min(admin_ms))
                        .or_insert(admin_ms);
                }
            }
            if transfer.to != MemberId::from(founding_owner)
                && !active_admins.contains_key(&transfer.to)
            {
                return Err(
                    "succession transfer target lacks an owner-signed admin record".to_string(),
                );
            }
            let quorum = crate::board_state::ownership::required_succession_quorum(
                active_admins.len(),
            )
            .ok_or_else(|| {
                "succession transfer requires at least 2 active admin records".to_string()
            })?;
            let mut voters = HashSet::new();
            let mut valid_keys = Vec::new();
            for approval in &entry.succession_approvals {
                approval.verify_signature()?;
                let vote = &approval.vote;
                if vote.from != transfer.from
                    || vote.to != transfer.to
                    || vote.to_key != transfer.to_key
                    || vote.generation != transfer.generation
                {
                    return Err("succession approval does not match transfer".to_string());
                }
                let vote_ms = system_time_ms(vote.signed_at);
                if vote_ms > at {
                    return Err("succession approval is dated after the transfer".to_string());
                }
                if vote_ms < last_time {
                    return Err(
                        "succession approval predates the previous ownership transfer".to_string(),
                    );
                }
                if !voters.insert(vote.voter) {
                    return Err("duplicate voter in succession approvals".to_string());
                }
                let Some(&admin_since) = active_admins.get(&vote.voter) else {
                    return Err(
                        "succession voter lacks an owner-signed admin record".to_string(),
                    );
                };
                if vote_ms < admin_since {
                    return Err(
                        "succession approval predates the voter's admin appointment".to_string(),
                    );
                }
                valid_keys.push(vote.voter_key);
            }
            if voters.len() < quorum {
                return Err(format!(
                    "succession transfer lacks admin quorum: {} < {}",
                    voters.len(),
                    quorum
                ));
            }
            if !valid_keys
                .iter()
                .any(|key| entry.verify_signature(key).is_ok())
            {
                return Err(
                    "succession transfer must be signed by one of the approving admins".to_string(),
                );
            }
        }

        from_key = transfer.to_key;
        from_id = transfer.to;
        owner_history.push((at, from_key));
        if !keys.contains(&from_key) {
            keys.push(from_key);
        }
        generation += 1;
        last_time = at;
    }

    Ok(keys)
}

/// Verify that `member_id` / `member_vk` is a valid member (or owner) of the
/// board anchored at `board_owner`.
pub fn verify_member_proof(
    board_owner: &VerifyingKey,
    member_id: &MemberId,
    member_vk: &VerifyingKey,
    proof: Option<&MemberProofV1>,
) -> Result<(), String> {
    if MemberId::from(member_vk) != *member_id {
        return Err("member key does not match member id".to_string());
    }
    if member_vk == board_owner {
        return Ok(());
    }
    let proof = proof.ok_or_else(|| "non-owner record requires a membership proof".to_string())?;
    let owner_keys = verify_ownership_chain(
        board_owner,
        &proof.ownership_transfers,
        &proof.transfer_admins,
    )?;
    if owner_keys.contains(member_vk) {
        return Ok(());
    }
    let entry = proof
        .membership
        .as_deref()
        .ok_or_else(|| "membership proof is missing its member record".to_string())?;
    if entry.member.member.member_vk != *member_vk || entry.member.member.id() != *member_id {
        return Err("membership proof does not match the signer".to_string());
    }
    entry.verify_against_owners(board_owner, &owner_keys)
}

/// Verify that `signer` / `signer_key` holds moderation/resolution authority
/// (owner, admin, or role with `can_delete_posts` / `can_manage_trash`) on the
/// board anchored at `board_owner`, without needing the parent board state.
pub fn verify_moderation_proof_standalone(
    board_owner: &VerifyingKey,
    signer: &MemberId,
    signer_key: &VerifyingKey,
    proof: Option<&AuthorityProof>,
    ownership_transfers: &[AuthorizedOwnerTransfer],
    transfer_admins: &[AuthorizedAdmin],
) -> Result<(), String> {
    if MemberId::from(signer_key) != *signer {
        return Err("moderation signer key does not match signer id".to_string());
    }
    let owner_keys = verify_ownership_chain(board_owner, ownership_transfers, transfer_admins)?;
    if owner_keys.contains(signer_key) {
        return Ok(());
    }
    if MemberShardEntryV1::verify_standalone_admin_authority(
        &owner_keys,
        signer,
        proof,
        MAX_SHARD_AUTHORITY_DEPTH,
    )
    .is_ok()
    {
        return Ok(());
    }
    let proof = proof
        .ok_or_else(|| "non-owner resolution requires a moderation authority proof".to_string())?;
    let grant = proof
        .grant
        .as_ref()
        .ok_or_else(|| "resolution authority proof has neither admin nor role grant".to_string())?;
    if grant.role.role.deleted
        || !(grant.role.role.can_delete_posts || grant.role.role.can_manage_trash)
    {
        return Err("resolution proof role does not grant report resolution".to_string());
    }
    if grant.assignment.assignment.role_id != grant.role.role.id
        || grant.assignment.assignment.member_id != *signer
        || grant.assignment.assignment.revoked
    {
        return Err("resolution proof assignment does not match signer or role".to_string());
    }
    let owner_id_set: HashMap<MemberId, VerifyingKey> = owner_keys
        .iter()
        .map(|k| (MemberId::from(k), *k))
        .collect();
    let role_signer = grant
        .role
        .signer
        .unwrap_or_else(|| MemberId::from(board_owner));
    let role_key = if let Some(key) = owner_id_set.get(&role_signer) {
        *key
    } else {
        let key = grant
            .role
            .signer_key
            .ok_or_else(|| "resolution role proof is missing signer key".to_string())?;
        if MemberId::from(&key) != role_signer {
            return Err("resolution role proof signer key mismatch".to_string());
        }
        key
    };
    verify_struct(&grant.role.role, &grant.role.signature, &role_key)
        .map_err(|error| format!("invalid role signature in resolution proof: {error}"))?;
    MemberShardEntryV1::verify_standalone_admin_authority(
        &owner_keys,
        &role_signer,
        grant.role.authority.as_deref(),
        MAX_SHARD_AUTHORITY_DEPTH - 1,
    )?;

    let assign_signer = grant
        .assignment
        .signer
        .unwrap_or_else(|| MemberId::from(board_owner));
    if assign_signer == *signer {
        return Err("resolution role assignment proof cannot be self-granted".to_string());
    }
    let assign_key = if let Some(key) = owner_id_set.get(&assign_signer) {
        *key
    } else {
        let key = grant
            .assignment
            .signer_key
            .ok_or_else(|| "resolution assignment proof is missing signer key".to_string())?;
        if MemberId::from(&key) != assign_signer {
            return Err("resolution assignment proof signer key mismatch".to_string());
        }
        key
    };
    verify_struct(
        &grant.assignment.assignment,
        &grant.assignment.signature,
        &assign_key,
    )
    .map_err(|error| format!("invalid assignment signature in resolution proof: {error}"))?;
    MemberShardEntryV1::verify_standalone_manager_authority(
        &owner_keys,
        &assign_signer,
        grant.assignment.authority.as_deref(),
        MAX_SHARD_AUTHORITY_DEPTH - 1,
    )
}

impl MemberShardEntryV1 {
    pub fn member_id(&self) -> MemberId {
        self.member.member.id()
    }

    pub fn verify(&self, params: &MemberShardParametersV1) -> Result<(), String> {
        params.verify()?;
        let member_id = self.member.member.id();

        if member_shard_bucket(&member_id) != params.bucket {
            return Err(format!(
                "member {:?} belongs to bucket {}, not {}",
                member_id,
                member_shard_bucket(&member_id),
                params.bucket
            ));
        }
        let owner_keys = verify_ownership_chain(
            &params.owner,
            &self.ownership_transfers,
            &self.transfer_admins,
        )?;
        self.verify_against_owners(&params.owner, &owner_keys)
    }

    pub(crate) fn verify_against_owners(
        &self,
        founding_owner: &VerifyingKey,
        owner_keys: &[VerifyingKey],
    ) -> Result<(), String> {
        let founding_owner_id = MemberId::from(founding_owner);
        let member_id = self.member.member.id();
        let owner_by_id: HashMap<MemberId, VerifyingKey> = owner_keys
            .iter()
            .map(|key| (MemberId::from(key), *key))
            .collect();

        if self.member.member.owner_member_id != founding_owner_id {
            return Err("member shard entry belongs to another board".to_string());
        }
        if self.invite_chain.len() > MAX_MEMBER_INVITE_CHAIN {
            return Err("member shard invite chain is too long".to_string());
        }
        for ancestor in &self.invite_chain {
            if ancestor.member.owner_member_id != founding_owner_id {
                return Err("invite chain member belongs to another board".to_string());
            }
        }

        if let Some(proof) = &self.member.member.join_proof {
            return Self::verify_token_member(
                &self.member,
                proof,
                self.invite_token.as_ref(),
                founding_owner,
                owner_keys,
            );
        }

        // Self-signed non-token entries cannot be verified without the parent
        // board's ownership history (former owners remain on the parent board),
        // so accepting them in a standalone shard would allow unauthenticated
        // shard filling.
        if self.member.member.invited_by == member_id {
            return Err("self-signed non-token members are not accepted in member shards".to_string());
        }

        if let Some(inviter_owner_key) = owner_by_id.get(&self.member.member.invited_by) {
            return self
                .member
                .verify_signature(inviter_owner_key)
                .map_err(|error| format!("invalid owner-invited member signature: {error}"));
        }

        // Multi-hop invite chain verified cryptographically up to any verified
        // owner in the chain or a verified invite token.
        let chain_by_id: HashMap<MemberId, &AuthorizedMember> = self
            .invite_chain
            .iter()
            .map(|entry| (entry.member.id(), entry))
            .collect();
        let mut current = &self.member;
        let mut visited = HashSet::new();

        for _ in 0..=MAX_MEMBER_INVITE_CHAIN {
            let current_id = current.member.id();
            if !visited.insert(current_id) {
                return Err("circular invite chain in member shard entry".to_string());
            }
            if let Some(proof) = &current.member.join_proof {
                return Self::verify_token_member(
                    current,
                    proof,
                    self.invite_token.as_ref(),
                    founding_owner,
                    owner_keys,
                );
            }
            if let Some(inviter_owner_key) = owner_by_id.get(&current.member.invited_by) {
                return current
                    .verify_signature(inviter_owner_key)
                    .map_err(|error| format!("invalid invite chain owner signature: {error}"));
            }
            if current.member.invited_by == current_id {
                return Err(
                    "self-signed non-token ancestor is not accepted in member shards".to_string(),
                );
            }
            let inviter = chain_by_id
                .get(&current.member.invited_by)
                .ok_or_else(|| {
                    format!(
                        "missing inviter {:?} in member shard invite chain",
                        current.member.invited_by
                    )
                })?;
            current
                .verify_signature(&inviter.member.member_vk)
                .map_err(|error| format!("invalid invite chain signature: {error}"))?;
            current = inviter;
        }

        Err("member shard invite chain exceeds maximum depth".to_string())
    }

    pub(crate) fn verify_standalone_admin_authority(
        owner_keys: &[VerifyingKey],
        signer: &MemberId,
        proof: Option<&AuthorityProof>,
        depth: u8,
    ) -> Result<(), String> {
        if owner_keys.iter().any(|k| MemberId::from(k) == *signer) {
            return Ok(());
        }
        if depth == 0 {
            return Err("member shard authority proof is nested too deeply".to_string());
        }
        let proof = proof
            .ok_or_else(|| "non-owner invite token in member shard requires an authority proof".to_string())?;
        if let Some(admin) = &proof.admin {
            if admin.admin.id() == *signer
                && owner_keys.iter().any(|k| admin.verify_signature(k).is_ok())
            {
                return Ok(());
            }
        }
        Err("member shard signer lacks a valid owner-signed admin proof".to_string())
    }

    pub(crate) fn verify_standalone_manager_authority(
        owner_keys: &[VerifyingKey],
        signer: &MemberId,
        proof: Option<&AuthorityProof>,
        depth: u8,
    ) -> Result<(), String> {
        if owner_keys.iter().any(|k| MemberId::from(k) == *signer) {
            return Ok(());
        }
        if Self::verify_standalone_admin_authority(owner_keys, signer, proof, depth).is_ok() {
            return Ok(());
        }
        if depth == 0 {
            return Err("member shard authority proof is nested too deeply".to_string());
        }
        let proof = proof
            .ok_or_else(|| "non-owner invite token in member shard requires an authority proof".to_string())?;
        let grant = proof
            .grant
            .as_ref()
            .ok_or_else(|| "member shard authority proof has neither valid admin nor role grant".to_string())?;
        if grant.role.role.deleted || !grant.role.role.can_manage_access {
            return Err("member shard proof role does not grant access management".to_string());
        }
        if grant.assignment.assignment.role_id != grant.role.role.id
            || grant.assignment.assignment.member_id != *signer
            || grant.assignment.assignment.revoked
        {
            return Err("member shard proof assignment does not match signer or role".to_string());
        }

        let owner_by_id: HashMap<MemberId, VerifyingKey> = owner_keys
            .iter()
            .map(|key| (MemberId::from(key), *key))
            .collect();
        let founding_owner = owner_keys[0];
        let founding_owner_id = MemberId::from(&founding_owner);

        let role_signer = grant.role.signer.unwrap_or(founding_owner_id);
        let role_key = if let Some(key) = owner_by_id.get(&role_signer) {
            *key
        } else {
            let key = grant
                .role
                .signer_key
                .ok_or_else(|| "member shard role proof is missing signer key".to_string())?;
            if MemberId::from(&key) != role_signer {
                return Err("member shard role proof signer key mismatch".to_string());
            }
            key
        };
        verify_struct(&grant.role.role, &grant.role.signature, &role_key)
            .map_err(|error| format!("invalid role signature in member shard proof: {error}"))?;
        Self::verify_standalone_admin_authority(
            owner_keys,
            &role_signer,
            grant.role.authority.as_deref(),
            depth - 1,
        )?;

        let assign_signer = grant.assignment.signer.unwrap_or(founding_owner_id);
        if assign_signer == *signer {
            return Err("member shard role assignment proof cannot be self-granted".to_string());
        }
        let assign_key = if let Some(key) = owner_by_id.get(&assign_signer) {
            *key
        } else {
            let key = grant
                .assignment
                .signer_key
                .ok_or_else(|| "member shard assignment proof is missing signer key".to_string())?;
            if MemberId::from(&key) != assign_signer {
                return Err("member shard assignment proof signer key mismatch".to_string());
            }
            key
        };
        verify_struct(
            &grant.assignment.assignment,
            &grant.assignment.signature,
            &assign_key,
        )
        .map_err(|error| format!("invalid role assignment signature in member shard proof: {error}"))?;
        Self::verify_standalone_manager_authority(
            owner_keys,
            &assign_signer,
            grant.assignment.authority.as_deref(),
            depth - 1,
        )
    }

    fn verify_token_member(
        member: &AuthorizedMember,
        proof: &crate::board_state::invites::JoinProof,
        invite_token: Option<&AuthorizedInviteToken>,
        founding_owner: &VerifyingKey,
        owner_keys: &[VerifyingKey],
    ) -> Result<(), String> {
        if member.member.invited_by != member.member.id() {
            return Err("a token-joined member must be self-signed".to_string());
        }
        member
            .verify_signature(&member.member.member_vk)
            .map_err(|error| format!("invalid token-joined member signature: {error}"))?;

        let token = invite_token
            .ok_or_else(|| "token-joined member shard entry requires its invite token".to_string())?;
        if token.token.id != proof.token_id {
            return Err("invite token id does not match join proof".to_string());
        }
        if token.token.deleted {
            return Err("invite token is deleted".to_string());
        }
        let owner_by_id: HashMap<MemberId, VerifyingKey> = owner_keys
            .iter()
            .map(|key| (MemberId::from(key), *key))
            .collect();
        let founding_owner_id = MemberId::from(founding_owner);
        let (signer_id, signer_key) = match (token.signer, token.signer_key) {
            (None, _) => (founding_owner_id, *founding_owner),
            (Some(signer), _) if owner_by_id.contains_key(&signer) => {
                (signer, owner_by_id[&signer])
            }
            (Some(signer), Some(key)) if MemberId::from(&key) == signer => (signer, key),
            _ => {
                return Err("invite token signer key is missing or mismatched".to_string());
            }
        };
        verify_struct(&token.token, &token.signature, &signer_key)
            .map_err(|error| format!("invalid invite token signature: {error}"))?;
        if !owner_by_id.contains_key(&signer_id) {
            Self::verify_standalone_manager_authority(
                owner_keys,
                &signer_id,
                token.authority.as_deref(),
                MAX_SHARD_AUTHORITY_DEPTH,
            )?;
        }

        proof.verify(
            &token.token.verifying_key,
            &join_message(founding_owner, &member.member.member_vk),
        )
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct MemberShardStateV1 {
    #[serde(default)]
    pub entries: Vec<MemberShardEntryV1>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct MemberShardDeltaV1 {
    #[serde(default)]
    pub entries: Vec<MemberShardEntryV1>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct MemberShardSummaryV1 {
    #[serde(default)]
    pub member_ids: BTreeSet<MemberId>,
}

impl MemberShardStateV1 {
    pub fn verify(&self, params: &MemberShardParametersV1) -> Result<(), String> {
        params.verify()?;
        if self.entries.len() > MAX_MEMBERS_PER_SHARD {
            return Err(format!(
                "member shard exceeds cap: {} > {}",
                self.entries.len(),
                MAX_MEMBERS_PER_SHARD
            ));
        }
        let mut seen = HashSet::with_capacity(self.entries.len());
        for entry in &self.entries {
            if !seen.insert(entry.member_id()) {
                return Err("duplicate member in member shard".to_string());
            }
            entry.verify(params)?;
        }
        Ok(())
    }

    /// Apply a delta verifying only the incoming entries. Existing entries are
    /// already verified; duplicate member ids are ignored idempotently.
    pub fn apply_delta(
        &mut self,
        params: &MemberShardParametersV1,
        delta: &MemberShardDeltaV1,
    ) -> Result<(), String> {
        params.verify()?;
        let mut existing: HashSet<MemberId> =
            self.entries.iter().map(MemberShardEntryV1::member_id).collect();
        let mut accepted = Vec::new();

        for entry in &delta.entries {
            let id = entry.member_id();
            if existing.contains(&id) {
                continue;
            }
            entry.verify(params)?;
            existing.insert(id);
            accepted.push(entry.clone());
        }

        if self.entries.len() + accepted.len() > MAX_MEMBERS_PER_SHARD {
            return Err(format!(
                "member shard exceeds cap after delta: {} > {}",
                self.entries.len() + accepted.len(),
                MAX_MEMBERS_PER_SHARD
            ));
        }

        self.entries.extend(accepted);
        self.entries
            .sort_by_key(|entry| *entry.member_id().as_bytes());
        Ok(())
    }

    pub fn summarize(&self) -> MemberShardSummaryV1 {
        MemberShardSummaryV1 {
            member_ids: self.entries.iter().map(MemberShardEntryV1::member_id).collect(),
        }
    }

    pub fn delta(&self, summary: &MemberShardSummaryV1) -> Option<MemberShardDeltaV1> {
        let missing: Vec<MemberShardEntryV1> = self
            .entries
            .iter()
            .filter(|entry| !summary.member_ids.contains(&entry.member_id()))
            .cloned()
            .collect();
        if missing.is_empty() {
            None
        } else {
            Some(MemberShardDeltaV1 { entries: missing })
        }
    }
}

/// Overlay verified member shard entries onto a board's `MembersV1` for display
/// and client-side operations. Filters out banned members (and descendants of
/// banned members), validates token-joined entries against active board invite
/// tokens, and verifies former-owner self-registrations against `ownership`.
pub fn merge_into_members<'a>(
    entries: impl IntoIterator<Item = &'a MemberShardEntryV1>,
    board: &ChatBoardStateV1,
    params: &ChatBoardParametersV1,
    target: &mut MembersV1,
) {
    let owner_id = params.owner_id();
    let current_owner = board.ownership.current_owner(params);
    let banned_ids: HashSet<MemberId> = board
        .bans
        .0
        .iter()
        .map(|ban| ban.ban.banned_user)
        .collect();
    let mut known: HashSet<MemberId> = target
        .members
        .iter()
        .map(|member| member.member.id())
        .collect();

    for entry in entries {
        let id = entry.member_id();
        if id == current_owner || known.contains(&id) || banned_ids.contains(&id) {
            continue;
        }
        if entry.member.member.owner_member_id != owner_id {
            continue;
        }
        if entry
            .invite_chain
            .iter()
            .any(|ancestor| banned_ids.contains(&ancestor.member.id()))
        {
            continue;
        }

        // Token-joined entries must match an active token and existing role on
        // the parent board, so revoked tokens cannot admit members in overlay.
        if let Some(proof) = &entry.member.member.join_proof {
            let Some(token) = board.invites.token(&proof.token_id) else {
                continue;
            };
            if board.roles.role(&token.role_id).is_none() {
                continue;
            }
            if proof
                .verify(
                    &token.verifying_key,
                    &join_message(&params.owner, &entry.member.member.member_vk),
                )
                .is_err()
            {
                continue;
            }
        } else if entry.member.member.invited_by == id {
            // Self-registered former owner: only valid if this key actually
            // owned the board before a transfer.
            if !board.ownership.was_owner(&id) {
                continue;
            }
        }

        known.insert(id);
        target.members.push(entry.member.clone());
    }

    target.members.sort_by_key(|member| member.member.id());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board_state::ban::{AuthorizedUserBan, UserBan};
    use crate::board_state::invites::{
        AuthorizedInviteToken, InviteToken, JoinProof,
    };
    use crate::board_state::member::Member;
    use crate::board_state::roles::{AuthorizedRole, Role};
    use ed25519_dalek::SigningKey;
    use std::time::SystemTime;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn owner_invited(owner: &SigningKey, member_sk: &SigningKey) -> AuthorizedMember {
        let owner_id = MemberId::from(&owner.verifying_key());
        AuthorizedMember::new(
            Member {
                owner_member_id: owner_id,
                invited_by: owner_id,
                member_vk: member_sk.verifying_key(),
                join_proof: None,
            },
            owner,
        )
    }

    #[test]
    fn owner_invited_member_verifies_in_its_bucket() {
        let owner = key(1);
        let alice = key(2);
        let member = owner_invited(&owner, &alice);
        let bucket = member_shard_bucket(&member.member.id());
        let params = MemberShardParametersV1 {
            owner: owner.verifying_key(),
            bucket,
        };
        let entry = MemberShardEntryV1 {
            member,
            invite_chain: Vec::new(),
            invite_token: None,
            ownership_transfers: Vec::new(),
            transfer_admins: Vec::new(),
        };

        let mut state = MemberShardStateV1::default();
        state
            .apply_delta(
                &params,
                &MemberShardDeltaV1 {
                    entries: vec![entry.clone()],
                },
            )
            .unwrap();
        assert_eq!(state.entries.len(), 1);
        state.verify(&params).unwrap();

        // Idempotent duplicate delta does not grow the shard.
        state
            .apply_delta(&params, &MemberShardDeltaV1 { entries: vec![entry] })
            .unwrap();
        assert_eq!(state.entries.len(), 1);
    }

    #[test]
    fn wrong_bucket_is_rejected() {
        let owner = key(1);
        let alice = key(2);
        let member = owner_invited(&owner, &alice);
        let wrong_bucket = (member_shard_bucket(&member.member.id()) + 1) % MEMBER_SHARD_COUNT;
        let params = MemberShardParametersV1 {
            owner: owner.verifying_key(),
            bucket: wrong_bucket,
        };
        let entry = MemberShardEntryV1 {
            member,
            invite_chain: Vec::new(),
            invite_token: None,
            ownership_transfers: Vec::new(),
            transfer_admins: Vec::new(),
        };
        let mut state = MemberShardStateV1::default();
        assert!(state
            .apply_delta(&params, &MemberShardDeltaV1 { entries: vec![entry] })
            .is_err());
    }

    #[test]
    fn multi_hop_invite_chain_verifies_without_other_shards() {
        let owner = key(1);
        let alice = key(2);
        let bob = key(3);
        let owner_id = MemberId::from(&owner.verifying_key());
        let alice_member = owner_invited(&owner, &alice);
        let bob_member = AuthorizedMember::new(
            Member {
                owner_member_id: owner_id,
                invited_by: alice_member.member.id(),
                member_vk: bob.verifying_key(),
                join_proof: None,
            },
            &alice,
        );
        let params = MemberShardParametersV1 {
            owner: owner.verifying_key(),
            bucket: member_shard_bucket(&bob_member.member.id()),
        };
        let entry = MemberShardEntryV1 {
            member: bob_member,
            invite_chain: vec![alice_member],
            invite_token: None,
            ownership_transfers: Vec::new(),
            transfer_admins: Vec::new(),
        };
        let mut state = MemberShardStateV1::default();
        state
            .apply_delta(&params, &MemberShardDeltaV1 { entries: vec![entry] })
            .unwrap();
        state.verify(&params).unwrap();
    }

    #[test]
    fn token_joined_member_verifies_and_respects_board_overlay_revocation() {
        let owner = key(1);
        let link_sk = key(7);
        let bob = key(8);
        let owner_id = MemberId::from(&owner.verifying_key());
        let bob_id = MemberId::from(&bob.verifying_key());
        let role_id = [5u8; 16];

        let token = AuthorizedInviteToken::new(
            InviteToken {
                id: [9u8; 16],
                verifying_key: link_sk.verifying_key(),
                role_id,
                label: "Test".to_string(),
                max_uses: None,
                not_after: None,
                includes_category_keys: false,
                created_at: Some(SystemTime::UNIX_EPOCH),
                generation: 1,
                deleted: false,
            },
            &owner,
        );
        let proof = JoinProof::new(
            token.token.id,
            &link_sk,
            &join_message(&owner.verifying_key(), &bob.verifying_key()),
        );
        let bob_member = AuthorizedMember::new(
            Member {
                owner_member_id: owner_id,
                invited_by: bob_id,
                member_vk: bob.verifying_key(),
                join_proof: Some(proof),
            },
            &bob,
        );

        let params = MemberShardParametersV1 {
            owner: owner.verifying_key(),
            bucket: member_shard_bucket(&bob_id),
        };
        let entry = MemberShardEntryV1 {
            member: bob_member,
            invite_chain: Vec::new(),
            invite_token: Some(token.clone()),
            ownership_transfers: Vec::new(),
            transfer_admins: Vec::new(),
        };
        let mut state = MemberShardStateV1::default();
        state
            .apply_delta(&params, &MemberShardDeltaV1 { entries: vec![entry] })
            .unwrap();
        state.verify(&params).unwrap();

        let board_params = ChatBoardParametersV1 {
            owner: owner.verifying_key(),
        };
        let mut board = ChatBoardStateV1::default();
        board.roles.roles.push(AuthorizedRole::new(
            Role {
                id: role_id,
                name: "Member".to_string(),
                generation: 1,
                can_manage_access: false,
                can_distribute_keys: false,
                can_edit_posts: false,
                can_delete_posts: false,
                can_close_posts: false,
                can_pin_posts: false,
                can_move_posts: false,
                can_manage_trash: false,
                can_attach_images: false,
                can_retire_images: false,
                scope: Vec::new(),
                deleted: false,
                signed_at: SystemTime::UNIX_EPOCH,
            },
            &owner,
        ));
        board.invites.tokens.push(token);

        let mut merged = MembersV1::default();
        merge_into_members(&state.entries, &board, &board_params, &mut merged);
        assert_eq!(merged.members.len(), 1);

        // Once banned on the parent board, the overlay hides the member.
        board.bans.0.push(AuthorizedUserBan::new(
            UserBan {
                owner_member_id: owner_id,
                banned_at: SystemTime::UNIX_EPOCH,
                banned_user: bob_id,
                expires_at: None,
                target_member: None,
                invite_chain: Vec::new(),
            },
            owner_id,
            &owner,
        ));
        let mut merged_after_ban = MembersV1::default();
        merge_into_members(&state.entries, &board, &board_params, &mut merged_after_ban);
        assert!(merged_after_ban.members.is_empty());
    }

    #[test]
    fn summarize_and_delta_send_only_missing_members() {
        let owner = key(1);
        let mut bucket_entries = Vec::new();
        for seed in 2u8..=255 {
            let member = owner_invited(&owner, &key(seed));
            if member_shard_bucket(&member.member.id()) == 0 {
                bucket_entries.push(MemberShardEntryV1 {
                    member,
                    invite_chain: Vec::new(),
                    invite_token: None,
                    ownership_transfers: Vec::new(),
                    transfer_admins: Vec::new(),
                });
                if bucket_entries.len() == 2 {
                    break;
                }
            }
        }
        assert_eq!(bucket_entries.len(), 2);
        let params = MemberShardParametersV1 {
            owner: owner.verifying_key(),
            bucket: 0,
        };

        let mut peer_a = MemberShardStateV1::default();
        peer_a
            .apply_delta(
                &params,
                &MemberShardDeltaV1 {
                    entries: vec![bucket_entries[0].clone()],
                },
            )
            .unwrap();
        let mut peer_b = MemberShardStateV1::default();
        peer_b
            .apply_delta(
                &params,
                &MemberShardDeltaV1 {
                    entries: bucket_entries.clone(),
                },
            )
            .unwrap();

        let summary_a = peer_a.summarize();
        let delta = peer_b.delta(&summary_a).expect("delta carries one member");
        assert_eq!(delta.entries.len(), 1);
        assert_eq!(delta.entries[0].member_id(), bucket_entries[1].member_id());
        peer_a.apply_delta(&params, &delta).unwrap();
        assert_eq!(peer_a, peer_b);
        assert!(peer_b.delta(&peer_a.summarize()).is_none());
    }

    #[test]
    fn self_signed_non_token_member_is_rejected() {
        let owner = key(1);
        let attacker = key(99);
        let owner_id = MemberId::from(&owner.verifying_key());
        let attacker_id = MemberId::from(&attacker.verifying_key());
        let bogus = AuthorizedMember::new(
            Member {
                owner_member_id: owner_id,
                invited_by: attacker_id,
                member_vk: attacker.verifying_key(),
                join_proof: None,
            },
            &attacker,
        );
        let params = MemberShardParametersV1 {
            owner: owner.verifying_key(),
            bucket: member_shard_bucket(&attacker_id),
        };
        let entry = MemberShardEntryV1 {
            member: bogus,
            invite_chain: Vec::new(),
            invite_token: None,
            ownership_transfers: Vec::new(),
            transfer_admins: Vec::new(),
        };
        let mut state = MemberShardStateV1::default();
        assert!(state
            .apply_delta(&params, &MemberShardDeltaV1 { entries: vec![entry] })
            .is_err());
    }

    #[test]
    fn forged_non_owner_invite_token_without_authority_is_rejected() {
        let owner = key(1);
        let attacker = key(50);
        let link_sk = key(51);
        let bob = key(52);
        let owner_id = MemberId::from(&owner.verifying_key());
        let attacker_id = MemberId::from(&attacker.verifying_key());
        let bob_id = MemberId::from(&bob.verifying_key());

        // Attacker mints their own token without any owner-signed authority.
        let forged_token = AuthorizedInviteToken::signed_by(
            InviteToken {
                id: [42u8; 16],
                verifying_key: link_sk.verifying_key(),
                role_id: [1u8; 16],
                label: "Forged".to_string(),
                max_uses: None,
                not_after: None,
                includes_category_keys: false,
                created_at: Some(SystemTime::UNIX_EPOCH),
                generation: 1,
                deleted: false,
            },
            attacker_id,
            &attacker,
        );
        let proof = JoinProof::new(
            forged_token.token.id,
            &link_sk,
            &join_message(&owner.verifying_key(), &bob.verifying_key()),
        );
        let bob_member = AuthorizedMember::new(
            Member {
                owner_member_id: owner_id,
                invited_by: bob_id,
                member_vk: bob.verifying_key(),
                join_proof: Some(proof),
            },
            &bob,
        );
        let params = MemberShardParametersV1 {
            owner: owner.verifying_key(),
            bucket: member_shard_bucket(&bob_id),
        };
        let entry = MemberShardEntryV1 {
            member: bob_member,
            invite_chain: Vec::new(),
            invite_token: Some(forged_token),
            ownership_transfers: Vec::new(),
            transfer_admins: Vec::new(),
        };
        let mut state = MemberShardStateV1::default();
        assert!(state
            .apply_delta(&params, &MemberShardDeltaV1 { entries: vec![entry] })
            .is_err());
    }

    #[test]
    fn delegated_admin_and_role_manager_tokens_verify_with_authority_proof() {
        use crate::board_state::admin::{Admin, AuthorizedAdmin};
        use crate::board_state::roles::{
            AuthorizedRoleAssignment, RoleAssignment, RoleGrantProof,
        };

        let owner = key(1);
        let admin_sk = key(20);
        let manager_sk = key(21);
        let link_admin_sk = key(22);
        let link_mgr_sk = key(23);
        let bob = key(24);
        let carol = key(25);
        let owner_id = MemberId::from(&owner.verifying_key());
        let admin_id = MemberId::from(&admin_sk.verifying_key());
        let manager_id = MemberId::from(&manager_sk.verifying_key());
        let bob_id = MemberId::from(&bob.verifying_key());
        let carol_id = MemberId::from(&carol.verifying_key());

        let admin_record = AuthorizedAdmin::new(
            Admin {
                member_id: admin_id,
                generation: 1,
                signed_at: SystemTime::UNIX_EPOCH,
            },
            &owner,
        );
        let admin_proof = AuthorityProof {
            admin: Some(admin_record),
            grant: None,
        };

        // 1) Admin-delegated invite token verifies.
        let admin_token = AuthorizedInviteToken::signed_by(
            InviteToken {
                id: [61u8; 16],
                verifying_key: link_admin_sk.verifying_key(),
                role_id: [2u8; 16],
                label: "Admin link".to_string(),
                max_uses: None,
                not_after: None,
                includes_category_keys: false,
                created_at: Some(SystemTime::UNIX_EPOCH),
                generation: 1,
                deleted: false,
            },
            admin_id,
            &admin_sk,
        )
        .with_authority(admin_proof.clone());
        let bob_proof = JoinProof::new(
            admin_token.token.id,
            &link_admin_sk,
            &join_message(&owner.verifying_key(), &bob.verifying_key()),
        );
        let bob_member = AuthorizedMember::new(
            Member {
                owner_member_id: owner_id,
                invited_by: bob_id,
                member_vk: bob.verifying_key(),
                join_proof: Some(bob_proof),
            },
            &bob,
        );
        let bob_entry = MemberShardEntryV1 {
            member: bob_member,
            invite_chain: Vec::new(),
            invite_token: Some(admin_token),
            ownership_transfers: Vec::new(),
            transfer_admins: Vec::new(),
        };
        let bob_params = MemberShardParametersV1 {
            owner: owner.verifying_key(),
            bucket: member_shard_bucket(&bob_id),
        };
        bob_entry.verify(&bob_params).expect("admin token verifies");

        // 2) Role-manager-delegated invite token verifies (role + assignment by admin).
        let role_id = [7u8; 16];
        let auth_role = AuthorizedRole::signed_by(
            Role {
                id: role_id,
                name: "AccessMgr".to_string(),
                generation: 1,
                can_manage_access: true,
                can_distribute_keys: false,
                can_edit_posts: false,
                can_delete_posts: false,
                can_close_posts: false,
                can_pin_posts: false,
                can_move_posts: false,
                can_manage_trash: false,
                can_attach_images: false,
                can_retire_images: false,
                scope: Vec::new(),
                deleted: false,
                signed_at: SystemTime::UNIX_EPOCH,
            },
            admin_id,
            &admin_sk,
        )
        .with_authority(admin_proof.clone());
        let auth_assignment = AuthorizedRoleAssignment::signed_by(
            RoleAssignment {
                member_id: manager_id,
                role_id,
                generation: 1,
                revoked: false,
                signed_at: SystemTime::UNIX_EPOCH,
            },
            admin_id,
            &admin_sk,
        )
        .with_authority(admin_proof);
        let mgr_proof = AuthorityProof {
            admin: None,
            grant: Some(Box::new(RoleGrantProof {
                role: auth_role,
                assignment: auth_assignment,
            })),
        };
        let mgr_token = AuthorizedInviteToken::signed_by(
            InviteToken {
                id: [62u8; 16],
                verifying_key: link_mgr_sk.verifying_key(),
                role_id,
                label: "Mgr link".to_string(),
                max_uses: None,
                not_after: None,
                includes_category_keys: false,
                created_at: Some(SystemTime::UNIX_EPOCH),
                generation: 1,
                deleted: false,
            },
            manager_id,
            &manager_sk,
        )
        .with_authority(mgr_proof);
        let carol_proof = JoinProof::new(
            mgr_token.token.id,
            &link_mgr_sk,
            &join_message(&owner.verifying_key(), &carol.verifying_key()),
        );
        let carol_member = AuthorizedMember::new(
            Member {
                owner_member_id: owner_id,
                invited_by: carol_id,
                member_vk: carol.verifying_key(),
                join_proof: Some(carol_proof),
            },
            &carol,
        );
        let carol_entry = MemberShardEntryV1 {
            member: carol_member,
            invite_chain: Vec::new(),
            invite_token: Some(mgr_token),
            ownership_transfers: Vec::new(),
            transfer_admins: Vec::new(),
        };
        let carol_params = MemberShardParametersV1 {
            owner: owner.verifying_key(),
            bucket: member_shard_bucket(&carol_id),
        };
        carol_entry
            .verify(&carol_params)
            .expect("role-manager token verifies");
    }

    #[test]
    fn post_transfer_and_post_succession_owners_can_admit_shard_members() {
        use crate::board_state::admin::{Admin, AuthorizedAdmin};
        use crate::board_state::ownership::{
            AuthorizedOwnerTransfer, AuthorizedSuccessionVoteV1, OutgoingOwnerAction,
            OwnerTransferV1, SuccessionVoteV1,
        };

        let founding = key(1);
        let admin1 = key(2);
        let admin2 = key(3);
        let successor = key(4);
        let new_member = key(5);
        let founding_id = MemberId::from(&founding.verifying_key());
        let admin1_id = MemberId::from(&admin1.verifying_key());
        let admin2_id = MemberId::from(&admin2.verifying_key());
        let successor_id = MemberId::from(&successor.verifying_key());
        let new_member_id = MemberId::from(&new_member.verifying_key());

        let t0 = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(100);
        let t1 = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(200);
        let t2 = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(300);

        // 1) Direct owner transfer founding -> admin1; admin1 invites new_member.
        let direct_transfer = AuthorizedOwnerTransfer::new(
            OwnerTransferV1 {
                from: founding_id,
                to: admin1_id,
                to_key: admin1.verifying_key(),
                generation: 1,
                transferred_at: t1,
                outgoing: OutgoingOwnerAction::KeepAdmin,
            },
            &founding,
        );
        let invited_by_new_owner = AuthorizedMember::new(
            Member {
                owner_member_id: founding_id,
                invited_by: admin1_id,
                member_vk: new_member.verifying_key(),
                join_proof: None,
            },
            &admin1,
        );
        let params = MemberShardParametersV1 {
            owner: founding.verifying_key(),
            bucket: member_shard_bucket(&new_member_id),
        };
        let entry = MemberShardEntryV1 {
            member: invited_by_new_owner,
            invite_chain: Vec::new(),
            invite_token: None,
            ownership_transfers: vec![direct_transfer.clone()],
            transfer_admins: Vec::new(),
        };
        entry
            .verify(&params)
            .expect("member invited by post-transfer owner verifies");

        // 2) Emergency succession admin1 -> successor backed by admin2 + successor
        // appointed by admin1; successor then admits new_member.
        let admin2_rec = AuthorizedAdmin::new(
            Admin {
                member_id: admin2_id,
                generation: 1,
                signed_at: t1,
            },
            &admin1,
        );
        let succ_rec = AuthorizedAdmin::new(
            Admin {
                member_id: successor_id,
                generation: 1,
                signed_at: t1,
            },
            &admin1,
        );
        let vote1 = AuthorizedSuccessionVoteV1::new(
            SuccessionVoteV1 {
                from: admin1_id,
                to: successor_id,
                to_key: successor.verifying_key(),
                generation: 2,
                voter: admin2_id,
                voter_key: admin2.verifying_key(),
                signed_at: t1 + std::time::Duration::from_secs(10),
            },
            &admin2,
        );
        let vote2 = AuthorizedSuccessionVoteV1::new(
            SuccessionVoteV1 {
                from: admin1_id,
                to: successor_id,
                to_key: successor.verifying_key(),
                generation: 2,
                voter: successor_id,
                voter_key: successor.verifying_key(),
                signed_at: t1 + std::time::Duration::from_secs(10),
            },
            &successor,
        );
        let succession_transfer = AuthorizedOwnerTransfer::new_by_succession(
            OwnerTransferV1 {
                from: admin1_id,
                to: successor_id,
                to_key: successor.verifying_key(),
                generation: 2,
                transferred_at: t2,
                outgoing: OutgoingOwnerAction::Member,
            },
            vec![vote1, vote2],
            &successor,
        );
        let invited_by_successor = AuthorizedMember::new(
            Member {
                owner_member_id: founding_id,
                invited_by: successor_id,
                member_vk: new_member.verifying_key(),
                join_proof: None,
            },
            &successor,
        );
        let entry_succ = MemberShardEntryV1 {
            member: invited_by_successor.clone(),
            invite_chain: Vec::new(),
            invite_token: None,
            ownership_transfers: vec![direct_transfer.clone(), succession_transfer.clone()],
            transfer_admins: vec![admin2_rec, succ_rec],
        };
        entry_succ
            .verify(&params)
            .expect("member invited by post-succession owner verifies");

        // Missing admin records on succession transfer must fail.
        let bad_entry = MemberShardEntryV1 {
            member: invited_by_successor,
            invite_chain: Vec::new(),
            invite_token: None,
            ownership_transfers: vec![direct_transfer, succession_transfer],
            transfer_admins: Vec::new(),
        };
        assert!(bad_entry.verify(&params).is_err());
        let _ = t0;
    }
}
