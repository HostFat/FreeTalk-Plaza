//! Topic reports and resolutions, kept outside the section index.
//!
//! Reporting a topic used to rewrite the page of the section index and
//! broadcast it to every reader. This small per-board contract keeps the
//! moderation queue instead. The contract checks structure, caps and (for
//! resolutions) the resolver signature; the client verifies the reporter
//! signature and the moderator authority against the board state before it
//! shows an entry.

use crate::board_state::member::MemberId;
use crate::board_state::topics::{
    AuthorizedTopicReportResolutionV1, AuthorizedTopicReportV1, TopicReportKey,
    MAX_TOPIC_REPORT_BYTES,
};
use crate::util::verify_struct;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

/// A busy board still needs a bounded queue. Older reports are dropped when
/// the cap is reached; the resolutions that point at them go with them.
pub const MAX_REPORT_FEED: usize = 500;
pub const MAX_REPORT_FEED_RESOLUTIONS: usize = 500;

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct ReportFeedStateV1 {
    #[serde(default)]
    pub reports: Vec<AuthorizedTopicReportV1>,
    #[serde(default)]
    pub resolutions: Vec<AuthorizedTopicReportResolutionV1>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct ReportFeedDeltaV1 {
    #[serde(default)]
    pub reports: Vec<AuthorizedTopicReportV1>,
    #[serde(default)]
    pub resolutions: Vec<AuthorizedTopicReportResolutionV1>,
}

/// Compact summary for incremental Freenet state synchronization: maps each
/// report and resolution key to its current generation.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct ReportFeedSummaryV1 {
    #[serde(default)]
    pub reports: BTreeMap<TopicReportKey, u64>,
    #[serde(default)]
    pub resolutions: BTreeMap<TopicReportKey, u64>,
}

fn report_key(entry: &AuthorizedTopicReportV1) -> TopicReportKey {
    (
        entry.report.topic_id,
        entry.report.post_id,
        entry.report.reporter,
    )
}

fn resolution_key(entry: &AuthorizedTopicReportResolutionV1) -> TopicReportKey {
    (
        entry.resolution.topic_id,
        entry.resolution.post_id,
        entry.resolution.reporter,
    )
}

fn verify_report(entry: &AuthorizedTopicReportV1) -> Result<(), String> {
    if entry.report.generation == 0 {
        return Err("report generation must be positive".to_string());
    }
    if entry.report.created_at <= 0 {
        return Err("report timestamp is missing".to_string());
    }
    if entry.report.body.declared_len() > MAX_TOPIC_REPORT_BYTES {
        return Err("report body is too large".to_string());
    }
    Ok(())
}

fn verify_resolution(entry: &AuthorizedTopicReportResolutionV1) -> Result<(), String> {
    let value = &entry.resolution;
    if value.generation == 0 {
        return Err("resolution generation must be positive".to_string());
    }
    if value.created_at <= 0 {
        return Err("resolution timestamp is missing".to_string());
    }
    let key = entry
        .signer_key
        .ok_or("resolution has no signer key")?;
    if MemberId::from(&key) != value.resolved_by {
        return Err("resolution signer key does not match its id".to_string());
    }
    verify_struct(value, &entry.signature, &key)
        .map_err(|error| format!("invalid resolution signature: {error}"))
}

fn upsert_report(list: &mut Vec<AuthorizedTopicReportV1>, entry: &AuthorizedTopicReportV1) {
    let key = report_key(entry);
    if let Some(existing) = list.iter_mut().find(|existing| report_key(existing) == key) {
        if entry.report.generation > existing.report.generation
            || (entry.report.generation == existing.report.generation
                && entry.signature.to_bytes() < existing.signature.to_bytes())
        {
            *existing = entry.clone();
        }
        return;
    }
    list.push(entry.clone());
}

fn upsert_resolution(
    list: &mut Vec<AuthorizedTopicReportResolutionV1>,
    entry: &AuthorizedTopicReportResolutionV1,
) {
    let key = resolution_key(entry);
    if let Some(existing) = list
        .iter_mut()
        .find(|existing| resolution_key(existing) == key)
    {
        if entry.resolution.generation > existing.resolution.generation
            || (entry.resolution.generation == existing.resolution.generation
                && entry.signature.to_bytes() < existing.signature.to_bytes())
        {
            *existing = entry.clone();
        }
        return;
    }
    list.push(entry.clone());
}

impl ReportFeedStateV1 {
    pub fn verify(&self) -> Result<(), String> {
        if self.reports.len() > MAX_REPORT_FEED {
            return Err("too many reports".to_string());
        }
        if self.resolutions.len() > MAX_REPORT_FEED_RESOLUTIONS {
            return Err("too many report resolutions".to_string());
        }
        let mut reports = HashSet::new();
        for entry in &self.reports {
            verify_report(entry)?;
            if !reports.insert(report_key(entry)) {
                return Err("duplicate report".to_string());
            }
        }
        let mut resolutions = HashSet::new();
        for entry in &self.resolutions {
            verify_resolution(entry)?;
            if !resolutions.insert(resolution_key(entry)) {
                return Err("duplicate report resolution".to_string());
            }
            if !reports.contains(&resolution_key(entry)) {
                return Err("resolution targets a missing report".to_string());
            }
        }
        Ok(())
    }

    /// Upsert reports first, so a delta can carry a report and its resolution
    /// together. Enforces caps atomically so a rejected delta leaves `self`
    /// unchanged and callers do not need to re-verify existing entries.
    pub fn apply_delta(&mut self, delta: &ReportFeedDeltaV1) -> Result<(), String> {
        let mut next = self.clone();
        for entry in &delta.reports {
            verify_report(entry)?;
            upsert_report(&mut next.reports, entry);
        }
        for entry in &delta.resolutions {
            verify_resolution(entry)?;
            if !next
                .reports
                .iter()
                .any(|report| report_key(report) == resolution_key(entry))
            {
                return Err("resolution targets a missing report".to_string());
            }
            upsert_resolution(&mut next.resolutions, entry);
        }
        if next.reports.len() > MAX_REPORT_FEED {
            return Err("too many reports".to_string());
        }
        if next.resolutions.len() > MAX_REPORT_FEED_RESOLUTIONS {
            return Err("too many report resolutions".to_string());
        }
        next.normalize();
        *self = next;
        Ok(())
    }

    pub fn summarize(&self) -> ReportFeedSummaryV1 {
        ReportFeedSummaryV1 {
            reports: self
                .reports
                .iter()
                .map(|entry| (report_key(entry), entry.report.generation))
                .collect(),
            resolutions: self
                .resolutions
                .iter()
                .map(|entry| (resolution_key(entry), entry.resolution.generation))
                .collect(),
        }
    }

    pub fn delta(&self, summary: &ReportFeedSummaryV1) -> Option<ReportFeedDeltaV1> {
        let reports: Vec<AuthorizedTopicReportV1> = self
            .reports
            .iter()
            .filter(|entry| {
                summary
                    .reports
                    .get(&report_key(entry))
                    .copied()
                    .is_none_or(|generation| entry.report.generation > generation)
            })
            .cloned()
            .collect();
        let resolutions: Vec<AuthorizedTopicReportResolutionV1> = self
            .resolutions
            .iter()
            .filter(|entry| {
                summary
                    .resolutions
                    .get(&resolution_key(entry))
                    .copied()
                    .is_none_or(|generation| entry.resolution.generation > generation)
            })
            .cloned()
            .collect();
        if reports.is_empty() && resolutions.is_empty() {
            None
        } else {
            Some(ReportFeedDeltaV1 {
                reports,
                resolutions,
            })
        }
    }

    /// Deterministic order so independent merges produce the same bytes.
    fn normalize(&mut self) {
        self.reports.sort_by_key(|entry| {
            (
                *entry.report.topic_id.as_bytes(),
                entry.report.post_id.map(|id| *id.as_bytes()),
                *entry.report.reporter.as_bytes(),
            )
        });
        self.resolutions.sort_by_key(|entry| {
            (
                *entry.resolution.topic_id.as_bytes(),
                entry.resolution.post_id.map(|id| *id.as_bytes()),
                *entry.resolution.reporter.as_bytes(),
            )
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board_state::reports::ReportReason;
    use crate::board_state::topics::{TopicReportResolutionV1, TopicReportV1};
    use crate::board_state::privacy::SealedBytes;
    use crate::util::sign_struct;
    use ed25519_dalek::SigningKey;

    fn report(
        topic: [u8; 32],
        reporter: &SigningKey,
        generation: u64,
    ) -> AuthorizedTopicReportV1 {
        let value = TopicReportV1 {
            topic_id: crate::board_state::message::MessageId::from_bytes(topic),
            post_id: None,
            reporter: MemberId::from(&reporter.verifying_key()),
            reason: ReportReason::Spam,
            body: SealedBytes::public(b"Spam".to_vec()),
            created_at: 1_000 + generation as i64,
            generation,
        };
        AuthorizedTopicReportV1 {
            signature: sign_struct(&value, reporter),
            report: value,
        }
    }

    fn resolution(
        topic: [u8; 32],
        reporter: &SigningKey,
        resolver: &SigningKey,
        generation: u64,
    ) -> AuthorizedTopicReportResolutionV1 {
        let value = TopicReportResolutionV1 {
            topic_id: crate::board_state::message::MessageId::from_bytes(topic),
            post_id: None,
            reporter: MemberId::from(&reporter.verifying_key()),
            resolved_by: MemberId::from(&resolver.verifying_key()),
            created_at: 2_000 + generation as i64,
            generation,
        };
        AuthorizedTopicReportResolutionV1 {
            signature: sign_struct(&value, resolver),
            resolution: value,
            signer_key: Some(resolver.verifying_key()),
            authority: None,
        }
    }

    #[test]
    fn a_report_and_its_resolution_upsert_by_generation() {
        let reporter = SigningKey::from_bytes(&[1u8; 32]);
        let resolver = SigningKey::from_bytes(&[2u8; 32]);
        let mut state = ReportFeedStateV1::default();
        state
            .apply_delta(&ReportFeedDeltaV1 {
                reports: vec![report([7u8; 32], &reporter, 1)],
                resolutions: Vec::new(),
            })
            .unwrap();
        state
            .apply_delta(&ReportFeedDeltaV1 {
                reports: vec![report([7u8; 32], &reporter, 2)],
                resolutions: vec![resolution([7u8; 32], &reporter, &resolver, 1)],
            })
            .unwrap();
        assert_eq!(state.reports.len(), 1);
        assert_eq!(state.reports[0].report.generation, 2);
        assert_eq!(state.resolutions.len(), 1);
        assert_eq!(state.resolutions[0].resolution.generation, 1);
        state.verify().unwrap();

        // A stale resolution does not replace a newer one.
        state
            .apply_delta(&ReportFeedDeltaV1 {
                reports: Vec::new(),
                resolutions: vec![resolution([7u8; 32], &reporter, &resolver, 1)],
            })
            .unwrap();
        assert_eq!(state.resolutions[0].resolution.generation, 1);
    }

    #[test]
    fn a_resolution_needs_its_report() {
        let reporter = SigningKey::from_bytes(&[1u8; 32]);
        let resolver = SigningKey::from_bytes(&[2u8; 32]);
        let mut state = ReportFeedStateV1::default();
        assert!(state
            .apply_delta(&ReportFeedDeltaV1 {
                reports: Vec::new(),
                resolutions: vec![resolution([7u8; 32], &reporter, &resolver, 1)],
            })
            .is_err());
    }

    #[test]
    fn the_caps_are_enforced() {
        let reporter = SigningKey::from_bytes(&[1u8; 32]);
        let mut state = ReportFeedStateV1::default();
        for index in 0..MAX_REPORT_FEED {
            let mut topic = [0u8; 32];
            topic[..8].copy_from_slice(&(index as u64).to_le_bytes());
            state
                .apply_delta(&ReportFeedDeltaV1 {
                    reports: vec![report(topic, &reporter, 1)],
                    resolutions: Vec::new(),
                })
                .unwrap();
        }
        let mut overflow = [0u8; 32];
        overflow[..8].copy_from_slice(&(MAX_REPORT_FEED as u64).to_le_bytes());
        assert!(state
            .apply_delta(&ReportFeedDeltaV1 {
                reports: vec![report(overflow, &reporter, 1)],
                resolutions: Vec::new(),
            })
            .is_err());
        assert_eq!(state.reports.len(), MAX_REPORT_FEED);

        state.reports.push(report(overflow, &reporter, 1));
        assert!(state.verify().is_err());
    }

    #[test]
    fn summarize_and_delta_sync_incrementally() {
        let reporter = SigningKey::from_bytes(&[1u8; 32]);
        let resolver = SigningKey::from_bytes(&[2u8; 32]);
        let mut peer_a = ReportFeedStateV1::default();
        peer_a
            .apply_delta(&ReportFeedDeltaV1 {
                reports: vec![report([1u8; 32], &reporter, 1)],
                resolutions: Vec::new(),
            })
            .unwrap();

        let mut peer_b = peer_a.clone();
        peer_b
            .apply_delta(&ReportFeedDeltaV1 {
                reports: vec![report([2u8; 32], &reporter, 1)],
                resolutions: vec![resolution([1u8; 32], &reporter, &resolver, 1)],
            })
            .unwrap();

        let delta = peer_b
            .delta(&peer_a.summarize())
            .expect("delta carries missing report and resolution");
        assert_eq!(delta.reports.len(), 1);
        assert_eq!(delta.resolutions.len(), 1);

        peer_a.apply_delta(&delta).unwrap();
        assert_eq!(peer_a, peer_b);
        assert!(peer_b.delta(&peer_a.summarize()).is_none());
    }
}
