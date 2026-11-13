//! Post reports and their moderator resolutions.
//!
//! A report is a small signed record: target, reporter and a reason code. The
//! contract verifies the reporter, the target and the resolver's permission.
//! Reasons are codes rather than free text so board state carries no private
//! commentary about members.

use crate::board_state::member::MemberId;
use crate::board_state::message::MessageId;
use crate::board_state::moderation::{category_chain, is_owner_or_admin};
use crate::board_state::roles::{signer_key, ModerationPower};
use crate::board_state::ChatBoardParametersV1;
use crate::util::{sign_struct, verify_struct};
use crate::ChatBoardStateV1;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use freenet_scaffold::util::fast_hash;
use freenet_scaffold::ComposableState;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

/// Keep the queue bounded. Older reports are dropped by cleanup.
pub const MAX_REPORTS: usize = 200;

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum ReportReason {
    #[default]
    Spam,
    Abuse,
    OffTopic,
    Illegal,
    Other,
}

impl ReportReason {
    pub fn label(&self) -> &'static str {
        match self {
            ReportReason::Spam => "Spam",
            ReportReason::Abuse => "Abuse",
            ReportReason::OffTopic => "Off topic",
            ReportReason::Illegal => "Illegal content",
            ReportReason::Other => "Other",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum ReportStatus {
    #[default]
    Open,
    Resolved,
    Dismissed,
}

impl ReportStatus {
    pub fn label(&self) -> &'static str {
        match self {
            ReportStatus::Open => "Open",
            ReportStatus::Resolved => "Resolved",
            ReportStatus::Dismissed => "Dismissed",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct ReportV1 {
    pub target: MessageId,
    pub reporter: MemberId,
    pub reason: ReportReason,
    pub created_at: i64,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedReport {
    pub report: ReportV1,
    pub signature: Signature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<MemberId>,
}

impl AuthorizedReport {
    pub fn new(report: ReportV1, signing_key: &SigningKey) -> Self {
        Self {
            signature: sign_struct(&report, signing_key),
            report,
            signer: Some(MemberId::from(&signing_key.verifying_key())),
        }
    }

    pub fn signer_id(&self, parameters: &ChatBoardParametersV1) -> MemberId {
        self.signer.unwrap_or_else(|| parameters.owner_id())
    }

    /// Stable id derived from the signature.
    pub fn id(&self) -> MessageId {
        MessageId(fast_hash(&self.signature.to_bytes()))
    }

    pub fn verify_signature_with(&self, key: &VerifyingKey) -> Result<(), String> {
        verify_struct(&self.report, &self.signature, key)
            .map_err(|e| format!("Invalid report signature: {}", e))
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct ReportResolution {
    pub report_id: MessageId,
    pub status: ReportStatus,
    pub generation: u64,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedReportResolution {
    pub resolution: ReportResolution,
    pub signature: Signature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<MemberId>,
}

impl AuthorizedReportResolution {
    pub fn new(resolution: ReportResolution, signing_key: &SigningKey) -> Self {
        Self {
            signature: sign_struct(&resolution, signing_key),
            resolution,
            signer: Some(MemberId::from(&signing_key.verifying_key())),
        }
    }

    pub fn signer_id(&self, parameters: &ChatBoardParametersV1) -> MemberId {
        self.signer.unwrap_or_else(|| parameters.owner_id())
    }

    pub fn verify_signature_with(&self, key: &VerifyingKey) -> Result<(), String> {
        verify_struct(&self.resolution, &self.signature, key)
            .map_err(|e| format!("Invalid report resolution signature: {}", e))
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct ReportsV1 {
    pub reports: Vec<AuthorizedReport>,
    #[serde(default)]
    pub resolutions: Vec<AuthorizedReportResolution>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct ReportState {
    pub status: ReportStatus,
    pub generation: u64,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct ReportsSummary {
    pub reports: BTreeMap<MessageId, MessageId>,
    pub resolutions: BTreeMap<MessageId, ReportState>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct ReportsDelta {
    #[serde(default)]
    pub reports: Vec<AuthorizedReport>,
    #[serde(default)]
    pub resolutions: Vec<AuthorizedReportResolution>,
}

fn message_author(state: &ChatBoardStateV1, target: &MessageId) -> Option<MemberId> {
    state
        .recent_messages
        .messages
        .iter()
        .find(|message| message.id() == *target)
        .map(|message| message.message.author)
}

fn resolution_map(resolutions: &[AuthorizedReportResolution]) -> BTreeMap<MessageId, ReportState> {
    resolutions
        .iter()
        .map(|entry| {
            (
                entry.resolution.report_id,
                ReportState {
                    status: entry.resolution.status,
                    generation: entry.resolution.generation,
                },
            )
        })
        .collect()
}

fn verify_report(
    state: &ChatBoardStateV1,
    parameters: &ChatBoardParametersV1,
    entry: &AuthorizedReport,
) -> Result<(), String> {
    let signer = entry.signer_id(parameters);
    let key = signer_key(state, parameters, &signer)?;
    entry.verify_signature_with(&key)?;
    if entry.report.reporter != signer {
        return Err("Report reporter must be its signer".to_string());
    }
    if message_author(state, &entry.report.target).is_none() {
        return Err("Report targets a missing message".to_string());
    }
    Ok(())
}

fn can_resolve(
    state: &ChatBoardStateV1,
    parameters: &ChatBoardParametersV1,
    signer: &MemberId,
    target: &MessageId,
) -> bool {
    if is_owner_or_admin(state, parameters, signer) {
        return true;
    }
    let routes = state.moderation.routes_map();
    let chain = category_chain(&routes, target);
    state
        .roles
        .has_moderation_power(signer, ModerationPower::Delete, &chain)
}

fn verify_resolution(
    state: &ChatBoardStateV1,
    parameters: &ChatBoardParametersV1,
    reports: &[AuthorizedReport],
    entry: &AuthorizedReportResolution,
) -> Result<(), String> {
    let signer = entry.signer_id(parameters);
    let key = signer_key(state, parameters, &signer)?;
    entry.verify_signature_with(&key)?;
    let report = reports
        .iter()
        .find(|report| report.id() == entry.resolution.report_id)
        .ok_or("Report resolution targets a missing report")?;
    if !can_resolve(state, parameters, &signer, &report.report.target) {
        return Err("Signer cannot resolve this report".to_string());
    }
    Ok(())
}

impl ReportsV1 {
    pub fn status_of(&self, report_id: &MessageId) -> ReportStatus {
        self.resolutions
            .iter()
            .filter(|entry| entry.resolution.report_id == *report_id)
            .max_by_key(|entry| entry.resolution.generation)
            .map(|entry| entry.resolution.status)
            .unwrap_or(ReportStatus::Open)
    }

    /// Reports whose resolution status is `Open`, newest first.
    pub fn open_reports(&self) -> Vec<&AuthorizedReport> {
        let mut open: Vec<&AuthorizedReport> = self
            .reports
            .iter()
            .filter(|report| self.status_of(&report.id()) == ReportStatus::Open)
            .collect();
        open.sort_by_key(|report| std::cmp::Reverse(report.report.created_at));
        open
    }

    pub fn cleanup(&mut self, state: &ChatBoardStateV1, parameters: &ChatBoardParametersV1) {
        let live: HashSet<MessageId> = state
            .recent_messages
            .messages
            .iter()
            .map(|message| message.id())
            .collect();
        self.reports.retain(|entry| {
            live.contains(&entry.report.target)
                && signer_key(state, parameters, &entry.signer_id(parameters)).is_ok()
        });

        // One report per reporter and target; keep the lowest id.
        let mut by_pair: BTreeMap<(i64, i64), MessageId> = BTreeMap::new();
        for entry in &self.reports {
            let key = (entry.report.reporter.0 .0, entry.report.target.0 .0);
            let id = entry.id();
            by_pair
                .entry(key)
                .and_modify(|kept| {
                    if id.0 .0 < kept.0 .0 {
                        *kept = id;
                    }
                })
                .or_insert(id);
        }
        let keep: HashSet<MessageId> = by_pair.into_values().collect();
        self.reports.retain(|entry| keep.contains(&entry.id()));

        // Keep the newest MAX_REPORTS, with the id as the tie breaker.
        if self.reports.len() > MAX_REPORTS {
            self.reports
                .sort_by_key(|entry| (std::cmp::Reverse(entry.report.created_at), entry.id().0 .0));
            self.reports.truncate(MAX_REPORTS);
        }
        self.reports.sort_by_key(|entry| entry.id().0 .0);

        let report_ids: HashSet<MessageId> =
            self.reports.iter().map(|report| report.id()).collect();
        self.resolutions.retain(|entry| {
            let signer = entry.signer_id(parameters);
            report_ids.contains(&entry.resolution.report_id)
                && signer_key(state, parameters, &signer).is_ok()
                && self
                    .reports
                    .iter()
                    .find(|report| report.id() == entry.resolution.report_id)
                    .map(|report| can_resolve(state, parameters, &signer, &report.report.target))
                    .unwrap_or(false)
        });

        // One resolution per report, the highest generation wins.
        self.resolutions.sort_by_key(|entry| {
            (
                entry.resolution.report_id.0 .0,
                entry.resolution.generation,
                entry.signer_id(parameters).0 .0,
            )
        });
        self.resolutions
            .dedup_by_key(|entry| entry.resolution.report_id);
        self.resolutions
            .sort_by_key(|entry| entry.resolution.report_id.0 .0);
    }
}

impl ComposableState for ReportsV1 {
    type ParentState = ChatBoardStateV1;
    type Summary = ReportsSummary;
    type Delta = ReportsDelta;
    type Parameters = ChatBoardParametersV1;

    fn verify(
        &self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
    ) -> Result<(), String> {
        let mut ids = HashSet::new();
        let mut pairs = HashSet::new();
        for entry in &self.reports {
            if !ids.insert(entry.id()) {
                return Err("Duplicate report id".to_string());
            }
            if !pairs.insert((entry.report.reporter, entry.report.target)) {
                return Err("Duplicate report for one member and post".to_string());
            }
            verify_report(parent_state, parameters, entry)?;
        }
        let mut resolution_ids = HashSet::new();
        for entry in &self.resolutions {
            if !resolution_ids.insert(entry.resolution.report_id) {
                return Err("Duplicate resolution for one report".to_string());
            }
            verify_resolution(parent_state, parameters, &self.reports, entry)?;
        }
        Ok(())
    }

    fn summarize(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
    ) -> Self::Summary {
        ReportsSummary {
            reports: self
                .reports
                .iter()
                .map(|entry| (entry.id(), entry.report.target))
                .collect(),
            resolutions: resolution_map(&self.resolutions),
        }
    }

    fn delta(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
        old_state: &Self::Summary,
    ) -> Option<Self::Delta> {
        let reports: Vec<AuthorizedReport> = self
            .reports
            .iter()
            .filter(|entry| !old_state.reports.contains_key(&entry.id()))
            .cloned()
            .collect();
        let resolutions: Vec<AuthorizedReportResolution> = self
            .resolutions
            .iter()
            .filter(|entry| {
                old_state
                    .resolutions
                    .get(&entry.resolution.report_id)
                    .map(|old| old.generation < entry.resolution.generation)
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        if reports.is_empty() && resolutions.is_empty() {
            None
        } else {
            Some(ReportsDelta {
                reports,
                resolutions,
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
        for entry in &delta.reports {
            verify_report(parent_state, parameters, entry)?;
            let duplicate = self.reports.iter().any(|existing| {
                existing.report.reporter == entry.report.reporter
                    && existing.report.target == entry.report.target
            });
            if !duplicate
                && !self
                    .reports
                    .iter()
                    .any(|existing| existing.id() == entry.id())
            {
                self.reports.push(entry.clone());
            }
        }
        for entry in &delta.resolutions {
            verify_resolution(parent_state, parameters, &self.reports, entry)?;
            match self
                .resolutions
                .iter()
                .find(|existing| existing.resolution.report_id == entry.resolution.report_id)
            {
                Some(existing) if existing.resolution.generation >= entry.resolution.generation => {
                }
                _ => {
                    self.resolutions.retain(|existing| {
                        existing.resolution.report_id != entry.resolution.report_id
                    });
                    self.resolutions.push(entry.clone());
                }
            }
        }
        self.reports.sort_by_key(|entry| entry.id().0 .0);
        self.resolutions
            .sort_by_key(|entry| entry.resolution.report_id.0 .0);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board_state::configuration::{AuthorizedConfigurationV1, Configuration};
    use crate::board_state::member::{AuthorizedMember, Member};
    use crate::board_state::member_info::MemberInfoV1;
    use crate::board_state::message::{AuthorizedMessageV1, BoardMessageBody, MessageV1};
    use crate::board_state::secret::BoardSecretsV1;
    use crate::board_state::ChatBoardStateV1;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use std::time::SystemTime;

    struct Board {
        state: ChatBoardStateV1,
        parameters: ChatBoardParametersV1,
        owner_sk: SigningKey,
        member_sk: SigningKey,
        member_id: MemberId,
        post: MessageId,
    }

    fn board() -> Board {
        let owner_sk = SigningKey::generate(&mut OsRng);
        let owner_vk = owner_sk.verifying_key();
        let owner_id = MemberId::from(&owner_vk);
        let parameters = ChatBoardParametersV1 { owner: owner_vk };
        let member_sk = SigningKey::generate(&mut OsRng);
        let member_vk = member_sk.verifying_key();
        let member_id = MemberId::from(&member_vk);

        let member = AuthorizedMember::new(
            Member {
                owner_member_id: owner_id,
                invited_by: owner_id,
                member_vk,
                join_proof: None,
            },
            &owner_sk,
        );
        let post = AuthorizedMessageV1::new(
            MessageV1 {
                board_owner: owner_id,
                author: member_id,
                time: SystemTime::now(),
                content: BoardMessageBody::public("Post".into(), "Body".into()),
            },
            &member_sk,
        );
        let post_id = post.id();

        let state = ChatBoardStateV1 {
            configuration: AuthorizedConfigurationV1::new(Configuration::default(), &owner_sk),
            members: crate::board_state::member::MembersV1 {
                members: vec![member],
            },
            member_info: MemberInfoV1::default(),
            secrets: BoardSecretsV1::default(),
            recent_messages: crate::board_state::message::MessagesV1 {
                messages: vec![post],
                ..Default::default()
            },
            ..Default::default()
        };

        Board {
            state,
            parameters,
            owner_sk,
            member_sk,
            member_id,
            post: post_id,
        }
    }

    #[test]
    fn a_member_report_verifies_and_resolves_only_with_moderation_power() {
        let mut board = board();
        let owner_id = MemberId::from(&board.owner_sk.verifying_key());
        let report = AuthorizedReport::new(
            ReportV1 {
                target: board.post,
                reporter: owner_id,
                reason: ReportReason::Spam,
                created_at: 1,
            },
            &board.owner_sk,
        );
        let report_id = report.id();
        board.state.reports.reports.push(report);

        board
            .state
            .reports
            .verify(&board.state, &board.parameters)
            .expect("a member can report another member's post");

        // The reporter cannot resolve their own report without a role.
        let resolution = AuthorizedReportResolution::new(
            ReportResolution {
                report_id,
                status: ReportStatus::Resolved,
                generation: 1,
            },
            &board.member_sk,
        );
        board.state.reports.resolutions.push(resolution);
        assert!(board
            .state
            .reports
            .verify(&board.state, &board.parameters)
            .is_err());
        board.state.reports.resolutions.clear();

        // The owner can.
        let resolution = AuthorizedReportResolution::new(
            ReportResolution {
                report_id,
                status: ReportStatus::Dismissed,
                generation: 1,
            },
            &board.owner_sk,
        );
        board.state.reports.resolutions.push(resolution);
        board
            .state
            .reports
            .verify(&board.state, &board.parameters)
            .expect("the owner can resolve a report");
        assert_eq!(
            board.state.reports.status_of(&report_id),
            ReportStatus::Dismissed
        );
        assert!(board.state.reports.open_reports().is_empty());
    }

    #[test]
    fn own_posts_can_be_reported_but_duplicates_are_rejected() {
        let mut board = board();
        let self_report = AuthorizedReport::new(
            ReportV1 {
                target: board.post,
                reporter: board.member_id,
                reason: ReportReason::Other,
                created_at: 1,
            },
            &board.member_sk,
        );
        board.state.reports.reports.push(self_report);
        board
            .state
            .reports
            .verify(&board.state, &board.parameters)
            .expect("a member can ask moderators to look at their own post");

        // Two reports for the same reporter and post are rejected.
        let owner_id = MemberId::from(&board.owner_sk.verifying_key());
        let report = AuthorizedReport::new(
            ReportV1 {
                target: board.post,
                reporter: owner_id,
                reason: ReportReason::Spam,
                created_at: 1,
            },
            &board.owner_sk,
        );
        board.state.reports.reports.clear();
        board.state.reports.reports.push(report.clone());
        board.state.reports.reports.push(report);
        assert!(board
            .state
            .reports
            .verify(&board.state, &board.parameters)
            .is_err());
    }

    #[test]
    fn cleanup_keeps_reports_on_your_own_post() {
        let mut board = board();
        let report = AuthorizedReport::new(
            ReportV1 {
                target: board.post,
                reporter: board.member_id,
                reason: ReportReason::Other,
                created_at: 1,
            },
            &board.member_sk,
        );
        board.state.reports.reports.push(report);
        let mut reports = std::mem::take(&mut board.state.reports);
        reports.cleanup(&board.state, &board.parameters);
        assert_eq!(reports.reports.len(), 1);
    }

    #[test]
    fn cleanup_drops_reports_for_missing_messages() {
        let mut board = board();
        let report = AuthorizedReport::new(
            ReportV1 {
                target: board.post,
                reporter: MemberId::from(&board.owner_sk.verifying_key()),
                reason: ReportReason::Abuse,
                created_at: 1,
            },
            &board.owner_sk,
        );
        board.state.reports.reports.push(report);
        board.state.recent_messages.messages.clear();
        let mut reports = std::mem::take(&mut board.state.reports);
        reports.cleanup(&board.state, &board.parameters);
        assert!(reports.reports.is_empty());
    }
}
