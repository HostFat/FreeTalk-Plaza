//! Sharded per-board member profiles (nicknames), kept outside the board state.
//!
//! A board with thousands of nicknames carried several MiB of profile records
//! and verified every signature on each sync. Profiles now live in deterministic
//! bucket contracts (`PROFILE_SHARD_COUNT` fixed shards addressed by
//! `{ owner, bucket }`, matching `member_shards`):
//! - no owner is needed online to open new pages,
//! - each rename or join writes a ~0.3 KiB delta to one shard with zero writes
//!   to the parent board,
//! - `summarize`/`delta` sync only new or bumped versions instead of full state.

use crate::board_state::member::MemberId;
use crate::board_state::member_info::{AuthorizedMemberInfo, MemberInfo};
use crate::board_state::member_shards::{verify_member_proof, MemberProofV1};
use crate::util::{sign_struct, verify_struct};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

/// Fixed number of deterministic profile buckets per board.
/// Matches `MEMBER_SHARD_COUNT` so a member's profile and membership share the
/// same bucket index; at 10,000 members each shard holds ~312 profiles (~100 KiB).
pub const PROFILE_SHARD_COUNT: u16 = 32;
/// Hard cap on entries in one profile shard, enforced by the contract.
pub const MAX_PROFILES_PER_SHARD: usize = 2_000;
/// Generous bound for a sealed nickname; the board configuration can be
/// stricter and the client enforces it.
pub const MAX_PROFILE_NICKNAME_BYTES: usize = 4_096;

/// Deterministic bucket index for a member id.
pub fn profile_shard_bucket(member_id: &MemberId) -> u16 {
    let digest = blake3::hash(member_id.as_bytes());
    let prefix = u16::from_le_bytes([digest.as_bytes()[0], digest.as_bytes()[1]]);
    prefix % PROFILE_SHARD_COUNT
}

/// Contract parameters for one profile shard of a board.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct ProfileShardParametersV1 {
    pub owner: VerifyingKey,
    pub bucket: u16,
}

impl ProfileShardParametersV1 {
    pub fn owner_id(&self) -> MemberId {
        MemberId::from(&self.owner)
    }

    pub fn verify(&self) -> Result<(), String> {
        if self.bucket >= PROFILE_SHARD_COUNT {
            return Err(format!(
                "profile shard bucket {} out of range (max {})",
                self.bucket,
                PROFILE_SHARD_COUNT - 1
            ));
        }
        Ok(())
    }
}

/// One nickname with the member key that signed it plus a cryptographic proof
/// of board membership (omitted only for the founding board owner), so the
/// contract rejects unauthenticated spam without fetching the parent board.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct ProfileEntryV1 {
    pub info: MemberInfo,
    pub signer_key: VerifyingKey,
    pub signature: Signature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Box<MemberProofV1>>,
}

impl ProfileEntryV1 {
    pub fn new(info: MemberInfo, member_key: &SigningKey) -> Self {
        Self {
            signature: sign_struct(&info, member_key),
            info,
            signer_key: member_key.verifying_key(),
            proof: None,
        }
    }

    /// Reuse the signature the board member-info record already carries.
    pub fn from_authorized(info: AuthorizedMemberInfo, signer_key: VerifyingKey) -> Self {
        Self {
            info: info.member_info,
            signer_key,
            signature: info.signature,
            proof: None,
        }
    }

    pub fn with_proof(mut self, proof: MemberProofV1) -> Self {
        self.proof = Some(Box::new(proof));
        self
    }

    pub fn with_optional_proof(mut self, proof: Option<MemberProofV1>) -> Self {
        self.proof = proof.map(Box::new);
        self
    }

    pub fn authorized(&self) -> AuthorizedMemberInfo {
        AuthorizedMemberInfo {
            member_info: self.info.clone(),
            signature: self.signature,
        }
    }

    pub fn member_id(&self) -> MemberId {
        self.info.member_id
    }

    pub fn verify(&self, params: &ProfileShardParametersV1) -> Result<(), String> {
        params.verify()?;
        if profile_shard_bucket(&self.info.member_id) != params.bucket {
            return Err(format!(
                "profile {:?} belongs to bucket {}, not {}",
                self.info.member_id,
                profile_shard_bucket(&self.info.member_id),
                params.bucket
            ));
        }
        if MemberId::from(&self.signer_key) != self.info.member_id {
            return Err("the profile key does not match its member id".to_string());
        }
        if self.info.preferred_nickname.declared_len() > MAX_PROFILE_NICKNAME_BYTES {
            return Err("the nickname is too long".to_string());
        }
        verify_struct(&self.info, &self.signature, &self.signer_key)
            .map_err(|error| format!("invalid profile signature: {error}"))?;
        verify_member_proof(
            &params.owner,
            &self.info.member_id,
            &self.signer_key,
            self.proof.as_deref(),
        )
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct ProfileStateV1 {
    #[serde(default)]
    pub entries: Vec<ProfileEntryV1>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct ProfileDeltaV1 {
    #[serde(default)]
    pub entries: Vec<ProfileEntryV1>,
}

/// Compact summary for incremental Freenet state synchronization: maps each
/// member id in this shard to its latest nickname version.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct ProfileSummaryV1 {
    #[serde(default)]
    pub versions: BTreeMap<MemberId, u32>,
}

fn should_replace(existing: &ProfileEntryV1, incoming: &ProfileEntryV1) -> bool {
    incoming.info.version > existing.info.version
        || (incoming.info.version == existing.info.version
            && incoming.signature.to_bytes() < existing.signature.to_bytes())
}

impl ProfileStateV1 {
    pub fn verify(&self, params: &ProfileShardParametersV1) -> Result<(), String> {
        params.verify()?;
        if self.entries.len() > MAX_PROFILES_PER_SHARD {
            return Err("too many member profiles in shard".to_string());
        }
        let mut seen = HashSet::new();
        for entry in &self.entries {
            entry.verify(params)?;
            if !seen.insert(entry.info.member_id) {
                return Err("duplicate member profile".to_string());
            }
        }
        Ok(())
    }

    /// Verify only the entries the delta carries; the rest of the state was
    /// validated when it was written. Applies atomically so a rejected delta
    /// leaves `self` unchanged.
    pub fn apply_delta(
        &mut self,
        params: &ProfileShardParametersV1,
        delta: &ProfileDeltaV1,
    ) -> Result<(), String> {
        params.verify()?;
        let mut by_member: HashMap<MemberId, ProfileEntryV1> = self
            .entries
            .iter()
            .cloned()
            .map(|entry| (entry.info.member_id, entry))
            .collect();
        for entry in &delta.entries {
            entry.verify(params)?;
            let member_id = entry.info.member_id;
            match by_member.get_mut(&member_id) {
                Some(existing) => {
                    if should_replace(existing, entry) {
                        *existing = entry.clone();
                    }
                }
                None => {
                    by_member.insert(member_id, entry.clone());
                }
            }
        }
        if by_member.len() > MAX_PROFILES_PER_SHARD {
            return Err(format!(
                "profile shard exceeds cap after delta: {} > {}",
                by_member.len(),
                MAX_PROFILES_PER_SHARD
            ));
        }
        self.entries = by_member.into_values().collect();
        self.normalize();
        Ok(())
    }

    pub fn summarize(&self) -> ProfileSummaryV1 {
        ProfileSummaryV1 {
            versions: self
                .entries
                .iter()
                .map(|entry| (entry.info.member_id, entry.info.version))
                .collect(),
        }
    }

    pub fn delta(&self, summary: &ProfileSummaryV1) -> Option<ProfileDeltaV1> {
        let missing: Vec<ProfileEntryV1> = self
            .entries
            .iter()
            .filter(|entry| {
                summary
                    .versions
                    .get(&entry.info.member_id)
                    .copied()
                    .is_none_or(|version| entry.info.version > version)
            })
            .cloned()
            .collect();
        if missing.is_empty() {
            None
        } else {
            Some(ProfileDeltaV1 { entries: missing })
        }
    }

    /// Deterministic order so independent merges produce the same bytes.
    fn normalize(&mut self) {
        self.entries.sort_by_key(|entry| {
            (
                *entry.info.member_id.as_bytes(),
                entry.info.version,
            )
        });
    }
}

/// Merge profile records onto a board's legacy member-info list for display.
pub fn merge_into(
    legacy: &mut Vec<AuthorizedMemberInfo>,
    entries: impl IntoIterator<Item = AuthorizedMemberInfo>,
) {
    for entry in entries {
        let member_id = entry.member_info.member_id;
        if let Some(existing) = legacy
            .iter_mut()
            .find(|existing| existing.member_info.member_id == member_id)
        {
            if entry.member_info.version > existing.member_info.version {
                *existing = entry;
            }
            continue;
        }
        legacy.push(entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board_state::privacy::SealedBytes;

    fn owner_sk() -> SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[99u8; 32])
    }

    fn owner_vk() -> VerifyingKey {
        owner_sk().verifying_key()
    }

    fn key_for_bucket(target_bucket: u16, start_seed: u64) -> (SigningKey, u64) {
        let mut seed = start_seed;
        loop {
            let mut key_bytes = [0u8; 32];
            key_bytes[..8].copy_from_slice(&seed.to_le_bytes());
            let key = SigningKey::from_bytes(&key_bytes);
            let id = MemberId::from(&key.verifying_key());
            if profile_shard_bucket(&id) == target_bucket {
                return (key, seed + 1);
            }
            seed += 1;
        }
    }

    fn entry_for_key(key: &SigningKey, version: u32, name: &str) -> ProfileEntryV1 {
        let owner = owner_sk();
        let owner_id = MemberId::from(&owner.verifying_key());
        let info = MemberInfo {
            member_id: MemberId::from(&key.verifying_key()),
            version,
            preferred_nickname: SealedBytes::public(name.as_bytes().to_vec()),
        };
        let member = crate::board_state::member::AuthorizedMember::new(
            crate::board_state::member::Member {
                owner_member_id: owner_id,
                invited_by: owner_id,
                member_vk: key.verifying_key(),
                join_proof: None,
            },
            &owner,
        );
        let proof = MemberProofV1 {
            ownership_transfers: Vec::new(),
            transfer_admins: Vec::new(),
            membership: Some(Box::new(
                crate::board_state::member_shards::MemberShardEntryV1 {
                    member,
                    invite_chain: Vec::new(),
                    invite_token: None,
                    ownership_transfers: Vec::new(),
                    transfer_admins: Vec::new(),
                },
            )),
        };
        ProfileEntryV1::new(info, key).with_proof(proof)
    }

    #[test]
    fn unauthenticated_non_member_profile_is_rejected() {
        let params = ProfileShardParametersV1 {
            owner: owner_vk(),
            bucket: 0,
        };
        let (stranger, _) = key_for_bucket(0, 1);
        let info = MemberInfo {
            member_id: MemberId::from(&stranger.verifying_key()),
            version: 1,
            preferred_nickname: SealedBytes::public(b"Spammer".to_vec()),
        };
        let unauthenticated = ProfileEntryV1::new(info, &stranger);
        let mut state = ProfileStateV1::default();
        assert!(state
            .apply_delta(
                &params,
                &ProfileDeltaV1 {
                    entries: vec![unauthenticated],
                },
            )
            .is_err());
    }

    #[test]
    fn bucket_is_deterministic_and_matches_member_shards() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let id = MemberId::from(&key.verifying_key());
        let bucket = profile_shard_bucket(&id);
        assert!(bucket < PROFILE_SHARD_COUNT);
        assert_eq!(bucket, profile_shard_bucket(&id));
        assert_eq!(
            bucket,
            crate::board_state::member_shards::member_shard_bucket(&id)
        );
    }

    #[test]
    fn a_newer_version_wins_and_duplicates_are_rejected() {
        let params = ProfileShardParametersV1 {
            owner: owner_vk(),
            bucket: 0,
        };
        let (key1, next) = key_for_bucket(0, 1);
        let (key2, _) = key_for_bucket(0, next);
        let id1 = MemberId::from(&key1.verifying_key());

        let mut state = ProfileStateV1::default();
        state
            .apply_delta(
                &params,
                &ProfileDeltaV1 {
                    entries: vec![entry_for_key(&key1, 1, "Alice")],
                },
            )
            .unwrap();
        state
            .apply_delta(
                &params,
                &ProfileDeltaV1 {
                    entries: vec![
                        entry_for_key(&key1, 2, "Alice 2"),
                        entry_for_key(&key2, 1, "Bob"),
                    ],
                },
            )
            .unwrap();
        assert_eq!(state.entries.len(), 2);
        let first = state
            .entries
            .iter()
            .find(|entry| entry.info.member_id == id1)
            .unwrap();
        assert_eq!(first.info.version, 2);
        state.verify(&params).unwrap();

        state.entries.push(entry_for_key(&key1, 3, "Duplicate"));
        assert!(state.verify(&params).is_err());
    }

    #[test]
    fn wrong_bucket_and_out_of_range_bucket_are_rejected() {
        let (key0, _) = key_for_bucket(0, 1);
        let wrong_params = ProfileShardParametersV1 {
            owner: owner_vk(),
            bucket: 1,
        };
        let mut state = ProfileStateV1::default();
        assert!(state
            .apply_delta(
                &wrong_params,
                &ProfileDeltaV1 {
                    entries: vec![entry_for_key(&key0, 1, "Alice")],
                },
            )
            .is_err());

        let oob_params = ProfileShardParametersV1 {
            owner: owner_vk(),
            bucket: PROFILE_SHARD_COUNT,
        };
        assert!(oob_params.verify().is_err());
        assert!(state.verify(&oob_params).is_err());
    }

    #[test]
    fn a_signature_by_another_member_is_rejected() {
        let params = ProfileShardParametersV1 {
            owner: owner_vk(),
            bucket: 0,
        };
        let (key1, _) = key_for_bucket(0, 1);
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let mut bad = entry_for_key(&key1, 1, "Alice");
        bad.signature = sign_struct(&bad.info, &other);
        let mut state = ProfileStateV1::default();
        assert!(state
            .apply_delta(&params, &ProfileDeltaV1 { entries: vec![bad] })
            .is_err());
    }

    #[test]
    fn summarize_and_delta_sync_incrementally() {
        let params = ProfileShardParametersV1 {
            owner: owner_vk(),
            bucket: 0,
        };
        let (key1, next) = key_for_bucket(0, 1);
        let (key2, _) = key_for_bucket(0, next);

        let mut peer_a = ProfileStateV1::default();
        peer_a
            .apply_delta(
                &params,
                &ProfileDeltaV1 {
                    entries: vec![entry_for_key(&key1, 1, "Alice")],
                },
            )
            .unwrap();
        let mut peer_b = peer_a.clone();
        peer_b
            .apply_delta(
                &params,
                &ProfileDeltaV1 {
                    entries: vec![
                        entry_for_key(&key1, 2, "Alice renamed"),
                        entry_for_key(&key2, 1, "Bob"),
                    ],
                },
            )
            .unwrap();

        let summary_a = peer_a.summarize();
        let delta = peer_b.delta(&summary_a).expect("delta has updates");
        assert_eq!(delta.entries.len(), 2);

        peer_a.apply_delta(&params, &delta).unwrap();
        assert_eq!(peer_a, peer_b);
        assert!(peer_b.delta(&peer_a.summarize()).is_none());
    }

    #[test]
    fn the_caps_are_enforced() {
        let params = ProfileShardParametersV1 {
            owner: owner_vk(),
            bucket: 0,
        };
        let mut state = ProfileStateV1::default();
        let mut seed = 1u64;
        for _ in 0..MAX_PROFILES_PER_SHARD {
            let (key, next) = key_for_bucket(0, seed);
            seed = next;
            state.entries.push(entry_for_key(&key, 1, "Member"));
        }
        let (overflow_key, _) = key_for_bucket(0, seed);
        assert!(state
            .apply_delta(
                &params,
                &ProfileDeltaV1 {
                    entries: vec![entry_for_key(&overflow_key, 1, "Overflow")],
                },
            )
            .is_err());
        assert_eq!(state.entries.len(), MAX_PROFILES_PER_SHARD);

        state.entries.push(entry_for_key(&overflow_key, 1, "Overflow"));
        assert!(state.verify(&params).is_err());
    }
}
