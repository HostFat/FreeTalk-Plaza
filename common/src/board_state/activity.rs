//! Recent topic activity, kept outside the board index.
//!
//! The board index no longer changes on every reply. A small per-board
//! activity contract keeps the most recent `MAX_ACTIVITY_ENTRIES` topics so
//! the list can still show reply counts, pending approvals and a recent
//! ordering. A topic that falls out of this window falls back to its index
//! `created_at`.

use crate::board_state::message::MessageId;
use crate::board_state::topics::{AuthorizedTopicActivityV1, TopicActivityV1};
use crate::board_state::member::MemberId;
use crate::util::verify_struct;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

pub const MAX_ACTIVITY_ENTRIES: usize = 200;
pub const MAX_ACTIVITY_COUNT: u32 = 1_000_000;
pub const MAX_PENDING_APPROVALS: u32 = 10_000;

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct ActivityEntryV1 {
    pub topic_id: MessageId,
    pub part: u32,
    pub activity: AuthorizedTopicActivityV1,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct ActivityStateV1 {
    #[serde(default)]
    pub entries: Vec<ActivityEntryV1>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct ActivityDeltaV1 {
    #[serde(default)]
    pub entries: Vec<ActivityEntryV1>,
}

/// Compact summary for incremental Freenet state synchronization: maps
/// `(topic_id, part)` to `(generation, last_activity)`.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct ActivitySummaryV1 {
    #[serde(default)]
    pub entries: BTreeMap<(MessageId, u32), (u64, i64)>,
}

impl ActivityEntryV1 {
    fn key(&self) -> (MessageId, u32) {
        (self.topic_id, self.part)
    }

    fn version_tuple(&self) -> (u64, i64) {
        (
            self.activity.activity.generation,
            self.activity.activity.last_activity,
        )
    }

    fn verify(&self) -> Result<(), String> {
        if self.activity.activity.topic_id != self.topic_id {
            return Err("activity entry names another topic".to_string());
        }
        if self.activity.activity.generation == 0 {
            return Err("activity generation must be positive".to_string());
        }
        if self.activity.activity.reply_count > MAX_ACTIVITY_COUNT {
            return Err("activity reply count is out of range".to_string());
        }
        if self.activity.activity.pending_approvals > MAX_PENDING_APPROVALS {
            return Err("activity pending approval count is out of range".to_string());
        }
        let signer = self
            .activity
            .signer
            .ok_or("activity has no signer")?;
        let key = self
            .activity
            .signer_key
            .ok_or("activity has no signer key")?;
        if MemberId::from(&key) != signer {
            return Err("activity signer key does not match its id".to_string());
        }
        verify_struct(
            &self.activity.activity,
            &self.activity.signature,
            &key,
        )
        .map_err(|error| format!("invalid activity signature: {error}"))
    }
}

impl ActivityStateV1 {
    pub fn verify(&self) -> Result<(), String> {
        if self.entries.len() > MAX_ACTIVITY_ENTRIES {
            return Err("too many activity entries".to_string());
        }
        let mut seen = HashSet::new();
        for entry in &self.entries {
            entry.verify()?;
            if !seen.insert(entry.key()) {
                return Err("duplicate activity entry".to_string());
            }
        }
        Ok(())
    }

    pub fn apply_delta(&mut self, delta: &ActivityDeltaV1) -> Result<(), String> {
        for entry in &delta.entries {
            entry.verify()?;
        }
        for entry in &delta.entries {
            match self
                .entries
                .iter_mut()
                .find(|existing| existing.key() == entry.key())
            {
                Some(existing) => {
                    let take = entry.version_tuple() > existing.version_tuple()
                        || (entry.version_tuple() == existing.version_tuple()
                            && entry.activity.signature.to_bytes()
                                < existing.activity.signature.to_bytes());
                    if take {
                        *existing = entry.clone();
                    }
                }
                None => self.entries.push(entry.clone()),
            }
        }
        self.normalize();
        Ok(())
    }

    pub fn summarize(&self) -> ActivitySummaryV1 {
        ActivitySummaryV1 {
            entries: self
                .entries
                .iter()
                .map(|entry| (entry.key(), entry.version_tuple()))
                .collect(),
        }
    }

    pub fn delta(&self, summary: &ActivitySummaryV1) -> Option<ActivityDeltaV1> {
        let missing: Vec<ActivityEntryV1> = self
            .entries
            .iter()
            .filter(|entry| {
                summary
                    .entries
                    .get(&entry.key())
                    .copied()
                    .is_none_or(|known| entry.version_tuple() > known)
            })
            .cloned()
            .collect();
        if missing.is_empty() {
            None
        } else {
            Some(ActivityDeltaV1 { entries: missing })
        }
    }

    fn normalize(&mut self) {
        self.entries.sort_by(|left, right| {
            right
                .activity
                .activity
                .last_activity
                .cmp(&left.activity.activity.last_activity)
                .then_with(|| left.topic_id.cmp(&right.topic_id))
                .then_with(|| left.part.cmp(&right.part))
        });
        self.entries.truncate(MAX_ACTIVITY_ENTRIES);
    }

    pub fn merged_with(&self, other: &ActivityStateV1) -> ActivityStateV1 {
        let mut merged = self.clone();
        let delta = ActivityDeltaV1 {
            entries: other.entries.clone(),
        };
        let _ = merged.apply_delta(&delta);
        merged
    }

    pub fn activity_for(&self, topic_id: &MessageId) -> Option<&TopicActivityV1> {
        self.entries
            .iter()
            .filter(|entry| entry.topic_id == *topic_id)
            .max_by_key(|entry| entry.activity.activity.last_activity)
            .map(|entry| &entry.activity.activity)
    }

    pub fn part_for(&self, topic_id: &MessageId) -> Option<u32> {
        self.entries
            .iter()
            .filter(|entry| entry.topic_id == *topic_id)
            .max_by_key(|entry| entry.activity.activity.last_activity)
            .map(|entry| entry.part)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::sign_struct;
    use ed25519_dalek::SigningKey;

    fn activity(
        key: &SigningKey,
        topic: u8,
        generation: u64,
        last: i64,
        replies: u32,
    ) -> ActivityEntryV1 {
        let topic_id = MessageId::from_bytes([topic; 32]);
        let value = TopicActivityV1 {
            topic_id,
            last_activity: last,
            last_post_id: None,
            reply_count: replies,
            pending_approvals: 0,
            generation,
        };
        ActivityEntryV1 {
            topic_id,
            part: 0,
            activity: AuthorizedTopicActivityV1 {
                signature: sign_struct(&value, key),
                activity: value,
                signer: Some(MemberId::from(&key.verifying_key())),
                signer_key: Some(key.verifying_key()),
            },
        }
    }

    #[test]
    fn an_activity_delta_upserts_and_sorts() {
        let key = SigningKey::from_bytes(&[1u8; 32]);
        let mut state = ActivityStateV1::default();
        state
            .apply_delta(&ActivityDeltaV1 {
                entries: vec![activity(&key, 1, 1, 10, 1)],
            })
            .unwrap();
        state
            .apply_delta(&ActivityDeltaV1 {
                entries: vec![
                    activity(&key, 2, 1, 20, 1),
                    activity(&key, 1, 2, 30, 2),
                ],
            })
            .unwrap();
        assert_eq!(state.entries[0].topic_id, MessageId::from_bytes([1u8; 32]));
        assert_eq!(state.entries[0].activity.activity.reply_count, 2);
        assert_eq!(state.entries.len(), 2);
        state.verify().unwrap();
    }

    #[test]
    fn the_activity_window_is_bounded() {
        let key = SigningKey::from_bytes(&[1u8; 32]);
        let mut state = ActivityStateV1::default();
        let entries = (0..(MAX_ACTIVITY_ENTRIES + 20))
            .map(|index| {
                let mut seed = [0u8; 32];
                seed[..8].copy_from_slice(&(index as u64).to_le_bytes());
                let topic_id = MessageId::from_bytes(seed);
                let value = TopicActivityV1 {
                    topic_id,
                    last_activity: index as i64,
                    last_post_id: None,
                    reply_count: 1,
                    pending_approvals: 0,
                    generation: 1,
                };
                ActivityEntryV1 {
                    topic_id,
                    part: 0,
                    activity: AuthorizedTopicActivityV1 {
                        signature: sign_struct(&value, &key),
                        activity: value,
                        signer: Some(MemberId::from(&key.verifying_key())),
                        signer_key: Some(key.verifying_key()),
                    },
                }
            })
            .collect();
        state
            .apply_delta(&ActivityDeltaV1 { entries })
            .unwrap();
        assert_eq!(state.entries.len(), MAX_ACTIVITY_ENTRIES);
        assert_eq!(state.entries[0].activity.activity.last_activity, (MAX_ACTIVITY_ENTRIES + 19) as i64);
        state.verify().unwrap();
    }

    #[test]
    fn a_tampered_activity_is_rejected() {
        let key = SigningKey::from_bytes(&[1u8; 32]);
        let mut entry = activity(&key, 1, 1, 10, 1);
        entry.activity.activity.reply_count = 99;
        let mut state = ActivityStateV1::default();
        assert!(state
            .apply_delta(&ActivityDeltaV1 {
                entries: vec![entry],
            })
            .is_err());
    }

    #[test]
    fn summarize_and_delta_sync_incrementally() {
        let key = SigningKey::from_bytes(&[1u8; 32]);
        let mut peer_a = ActivityStateV1::default();
        peer_a
            .apply_delta(&ActivityDeltaV1 {
                entries: vec![activity(&key, 1, 1, 10, 1), activity(&key, 2, 1, 20, 1)],
            })
            .unwrap();

        let mut peer_b = peer_a.clone();
        peer_b
            .apply_delta(&ActivityDeltaV1 {
                entries: vec![activity(&key, 2, 2, 30, 2), activity(&key, 3, 1, 40, 1)],
            })
            .unwrap();

        let delta = peer_b
            .delta(&peer_a.summarize())
            .expect("delta carries only newer/missing entries");
        assert_eq!(delta.entries.len(), 2);

        peer_a.apply_delta(&delta).unwrap();
        assert_eq!(peer_a, peer_b);
        assert!(peer_b.delta(&peer_a.summarize()).is_none());
    }
}
