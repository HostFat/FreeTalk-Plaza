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

use crate::board_state::invites::{join_message, AuthorizedInviteToken};
use crate::board_state::member::{AuthorizedMember, MemberId, MembersV1};
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
    /// Ancestor member records from `member.invited_by` up to the board owner
    /// (or to a token-joined ancestor). Empty when invited directly by the
    /// owner, joined via token, or self-registered as a former owner.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub invite_chain: Vec<AuthorizedMember>,
    /// Invite token used when `member` (or the root of `invite_chain`) joined
    /// through an invite link.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_token: Option<AuthorizedInviteToken>,
}

impl MemberShardEntryV1 {
    pub fn member_id(&self) -> MemberId {
        self.member.member.id()
    }

    pub fn verify(&self, params: &MemberShardParametersV1) -> Result<(), String> {
        params.verify()?;
        let owner_id = params.owner_id();
        let member_id = self.member.member.id();

        if member_shard_bucket(&member_id) != params.bucket {
            return Err(format!(
                "member {:?} belongs to bucket {}, not {}",
                member_id,
                member_shard_bucket(&member_id),
                params.bucket
            ));
        }
        if self.member.member.owner_member_id != owner_id {
            return Err("member shard entry belongs to another board".to_string());
        }
        if self.invite_chain.len() > MAX_MEMBER_INVITE_CHAIN {
            return Err("member shard invite chain is too long".to_string());
        }
        for ancestor in &self.invite_chain {
            if ancestor.member.owner_member_id != owner_id {
                return Err("invite chain member belongs to another board".to_string());
            }
        }

        if let Some(proof) = &self.member.member.join_proof {
            return Self::verify_token_member(
                &self.member,
                proof,
                self.invite_token.as_ref(),
                params,
            );
        }

        // Former owner re-registering after a transfer: self-signed. The
        // client checks `board.ownership.was_owner(&member_id)` before overlay.
        if self.member.member.invited_by == member_id {
            return self
                .member
                .verify_signature(&self.member.member.member_vk)
                .map_err(|error| format!("invalid self-signed member record: {error}"));
        }

        if self.member.member.invited_by == owner_id {
            return self
                .member
                .verify_signature(&params.owner)
                .map_err(|error| format!("invalid owner-invited member signature: {error}"));
        }

        // Multi-hop invite chain verified cryptographically up to owner or token.
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
                    params,
                );
            }
            if current.member.invited_by == owner_id {
                return current
                    .verify_signature(&params.owner)
                    .map_err(|error| format!("invalid invite chain owner signature: {error}"));
            }
            if current.member.invited_by == current_id {
                return current
                    .verify_signature(&current.member.member_vk)
                    .map_err(|error| format!("invalid former-owner chain signature: {error}"));
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

    fn verify_token_member(
        member: &AuthorizedMember,
        proof: &crate::board_state::invites::JoinProof,
        invite_token: Option<&AuthorizedInviteToken>,
        params: &MemberShardParametersV1,
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
        let owner_id = params.owner_id();
        let signer_key = match (token.signer, token.signer_key) {
            (None, _) => params.owner,
            (Some(signer), _) if signer == owner_id => params.owner,
            (Some(signer), Some(key)) if MemberId::from(&key) == signer => key,
            _ => {
                return Err("invite token signer key is missing or mismatched".to_string());
            }
        };
        verify_struct(&token.token, &token.signature, &signer_key)
            .map_err(|error| format!("invalid invite token signature: {error}"))?;

        proof.verify(
            &token.token.verifying_key,
            &join_message(&params.owner, &member.member.member_vk),
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
}
