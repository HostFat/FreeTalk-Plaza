//! Per-board member profiles (nicknames), kept outside the board state.
//!
//! A board with thousands of nicknames carried several MiB of profile records
//! and verified every signature on each sync. The profile contract keeps the
//! records instead; the client overlays the nickname on the board for display.
//! The contract verifies the member signature, so the client does not repeat
//! one signature check per render.

use crate::board_state::member::MemberId;
use crate::board_state::member_info::{AuthorizedMemberInfo, MemberInfo};
use crate::util::{sign_struct, verify_struct};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// A board with more members than this needs paged profiles; the feed stays
/// bounded so the contract state cannot grow without limit.
pub const MAX_PROFILE_ENTRIES: usize = 10_000;
/// Generous bound for a sealed nickname; the board configuration can be
/// stricter and the client enforces it.
pub const MAX_PROFILE_NICKNAME_BYTES: usize = 4_096;

/// One nickname with the member key that signed it, so the contract can
/// verify it without the board member list.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct ProfileEntryV1 {
    pub info: MemberInfo,
    pub signer_key: VerifyingKey,
    pub signature: Signature,
}

impl ProfileEntryV1 {
    pub fn new(info: MemberInfo, member_key: &SigningKey) -> Self {
        Self {
            signature: sign_struct(&info, member_key),
            info,
            signer_key: member_key.verifying_key(),
        }
    }

    /// Reuse the signature the board member-info record already carries.
    pub fn from_authorized(info: AuthorizedMemberInfo, signer_key: VerifyingKey) -> Self {
        Self {
            info: info.member_info,
            signer_key,
            signature: info.signature,
        }
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

    fn verify(&self) -> Result<(), String> {
        if MemberId::from(&self.signer_key) != self.info.member_id {
            return Err("the profile key does not match its member id".to_string());
        }
        if self.info.preferred_nickname.declared_len() > MAX_PROFILE_NICKNAME_BYTES {
            return Err("the nickname is too long".to_string());
        }
        verify_struct(&self.info, &self.signature, &self.signer_key)
            .map_err(|error| format!("invalid profile signature: {error}"))
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

fn upsert(entries: &mut Vec<ProfileEntryV1>, entry: &ProfileEntryV1) {
    let member_id = entry.info.member_id;
    if let Some(existing) = entries
        .iter_mut()
        .find(|existing| existing.info.member_id == member_id)
    {
        if entry.info.version > existing.info.version {
            *existing = entry.clone();
        }
        return;
    }
    entries.push(entry.clone());
}

impl ProfileStateV1 {
    pub fn verify(&self) -> Result<(), String> {
        if self.entries.len() > MAX_PROFILE_ENTRIES {
            return Err("too many member profiles".to_string());
        }
        let mut seen = HashSet::new();
        for entry in &self.entries {
            entry.verify()?;
            if !seen.insert(entry.info.member_id) {
                return Err("duplicate member profile".to_string());
            }
        }
        Ok(())
    }

    /// Verify only the entries the delta carries; the rest of the state was
    /// validated when it was written.
    pub fn apply_delta(&mut self, delta: &ProfileDeltaV1) -> Result<(), String> {
        for entry in &delta.entries {
            entry.verify()?;
            upsert(&mut self.entries, entry);
        }
        self.normalize();
        Ok(())
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

    fn info(member: u8, version: u32) -> MemberInfo {
        MemberInfo {
            member_id: MemberId::from(
                &ed25519_dalek::SigningKey::from_bytes(&[member; 32]).verifying_key(),
            ),
            version,
            preferred_nickname: SealedBytes::public(format!("Member {member}").into_bytes()),
        }
    }

    fn entry(member: u8, version: u32) -> ProfileEntryV1 {
        let key = ed25519_dalek::SigningKey::from_bytes(&[member; 32]);
        ProfileEntryV1::new(info(member, version), &key)
    }

    #[test]
    fn a_newer_version_wins_and_duplicates_are_rejected() {
        let mut state = ProfileStateV1::default();
        state
            .apply_delta(&ProfileDeltaV1 {
                entries: vec![entry(1, 1)],
            })
            .unwrap();
        state
            .apply_delta(&ProfileDeltaV1 {
                entries: vec![entry(1, 2), entry(2, 1)],
            })
            .unwrap();
        assert_eq!(state.entries.len(), 2);
        let first = state
            .entries
            .iter()
            .find(|entry| entry.info.member_id == info(1, 0).member_id)
            .unwrap();
        assert_eq!(first.info.version, 2);
        state.verify().unwrap();

        state.entries.push(entry(1, 3));
        assert!(state.verify().is_err());
    }

    #[test]
    fn a_signature_by_another_member_is_rejected() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let mut bad = entry(1, 1);
        bad.signature = sign_struct(&bad.info, &key);
        let mut state = ProfileStateV1::default();
        assert!(state
            .apply_delta(&ProfileDeltaV1 { entries: vec![bad] })
            .is_err());
    }

    #[test]
    fn the_caps_are_enforced() {
        let mut state = ProfileStateV1::default();
        for index in 0..=MAX_PROFILE_ENTRIES {
            let mut key_bytes = [0u8; 32];
            key_bytes[..8].copy_from_slice(&(index as u64).to_le_bytes());
            let key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
            let member_info = MemberInfo {
                member_id: MemberId::from(&key.verifying_key()),
                version: 1,
                preferred_nickname: SealedBytes::public(b"Member".to_vec()),
            };
            state
                .entries
                .push(ProfileEntryV1::new(member_info, &key));
        }
        assert!(state.verify().is_err());
    }
}
