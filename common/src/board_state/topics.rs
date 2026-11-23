//! Topic index stored in the board: titles, activity hints and moderation
//! flags. The discussion itself lives in the topic contract.

use crate::board_state::member::MemberId;
use crate::board_state::message::MessageId;
use crate::board_state::privacy::SealedBytes;
use crate::board_state::rate_limit::{
    exceeding_member, MAX_REPORTS_PER_WINDOW, MAX_TOPICS_PER_WINDOW, REPORT_RATE_WINDOW_MS,
    TOPIC_RATE_WINDOW_MS,
};
use crate::board_state::reports::ReportReason;
use crate::board_state::roles::{
    resolve_signer_key, verify_moderation_authority, AuthorityProof,
    ModerationPower,
};
use crate::board_state::sections::{SectionId, SectionsV1};
use crate::board_state::ChatBoardParametersV1;
use crate::board_state::ChatBoardStateV1;
use crate::util::{sign_struct, verify_struct};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use freenet_scaffold::ComposableState;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

/// The index travels in full with every board update, so it is kept small
/// enough to verify and broadcast. Larger boards use more sections or a new
/// board.
pub const MAX_TOPICS: usize = 2_000;
pub const MAX_TOPIC_ACTIVITY: usize = 2_000;
/// Eight flag kinds per topic.
pub const MAX_TOPIC_FLAGS: usize = 8 * MAX_TOPICS;
pub const MAX_TOPIC_REPORTS: usize = 2_000;
pub const MAX_TOPIC_REPORT_BYTES: usize = 2_000;
pub const MAX_TOPIC_TITLE_BYTES: usize = 512;
pub const MAX_TOPIC_PREVIEW_BYTES: usize = 512;
pub const MAX_TOPIC_PARTS: u32 = 64;
pub const TOPIC_PROTOCOL_VERSION: u16 = 1;

pub type TopicId = MessageId;

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct TopicEntryV1 {
    pub topic_id: TopicId,
    pub part: u32,
    pub protocol_version: u16,
    pub author: MemberId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section: Option<SectionId>,
    #[serde(default)]
    pub section_chain: Vec<SectionId>,
    pub title: SealedBytes,
    pub preview: SealedBytes,
    pub header_hash: [u8; 32],
    pub created_at: i64,
    pub generation: u64,
}

impl TopicEntryV1 {
    pub fn verify_basics(&self) -> Result<(), String> {
        if self.generation == 0 {
            return Err("topic entry generation must be positive".to_string());
        }
        if self.protocol_version != TOPIC_PROTOCOL_VERSION {
            return Err("unsupported topic protocol version".to_string());
        }
        if self.part > MAX_TOPIC_PARTS {
            return Err("topic part is out of range".to_string());
        }
        if self.title.declared_len() > MAX_TOPIC_TITLE_BYTES {
            return Err("topic title is too large".to_string());
        }
        if self.preview.declared_len() > MAX_TOPIC_PREVIEW_BYTES {
            return Err("topic preview is too large".to_string());
        }
        if self.header_hash == [0u8; 32] {
            return Err("topic header hash is empty".to_string());
        }
        if self.section.is_none() && !self.section_chain.is_empty() {
            return Err("a root topic cannot carry a section chain".to_string());
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct AuthorizedTopicEntryV1 {
    pub entry: TopicEntryV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<MemberId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_key: Option<VerifyingKey>,
    pub signature: Signature,
}

impl AuthorizedTopicEntryV1 {
    pub fn new(entry: TopicEntryV1, author_key: &SigningKey) -> Self {
        Self {
            signature: sign_struct(&entry, author_key),
            entry,
            signer: Some(MemberId::from(&author_key.verifying_key())),
            signer_key: Some(author_key.verifying_key()),
        }
    }

    pub fn digest(&self) -> i64 {
        let mut bytes = Vec::new();
        let _ = ciborium::ser::into_writer(&self.entry, &mut bytes);
        freenet_scaffold::util::fast_hash(&bytes).0
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct TopicActivityV1 {
    pub topic_id: TopicId,
    pub last_activity: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_post_id: Option<MessageId>,
    pub reply_count: u32,
    #[serde(default)]
    pub pending_approvals: u32,
    pub generation: u64,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedTopicActivityV1 {
    pub activity: TopicActivityV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<MemberId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_key: Option<VerifyingKey>,
    pub signature: Signature,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum TopicFlagKind {
    Pinned,
    Closed,
    Announced,
    Merged,
    Hidden,
    Approved,
    Section,
    Part,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct TopicFlagV1 {
    pub topic_id: TopicId,
    pub kind: TopicFlagKind,
    pub value: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<TopicId>,
    /// New section for a `Section` flag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section: Option<SectionId>,
    #[serde(default)]
    pub section_chain: Vec<SectionId>,
    /// New part for a `Part` flag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub part: Option<u32>,
    #[serde(default)]
    pub scope_chain: Vec<SectionId>,
    pub generation: u64,
    pub created_at: i64,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedTopicFlagV1 {
    pub flag: TopicFlagV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<MemberId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_key: Option<VerifyingKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<Box<AuthorityProof>>,
    pub signature: Signature,
}

/// A member report about a topic or one of its posts. The report lives in the
/// board index so the moderation queue sees reports from every topic.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct TopicReportV1 {
    pub topic_id: TopicId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_id: Option<MessageId>,
    pub reporter: MemberId,
    pub reason: ReportReason,
    pub body: SealedBytes,
    pub created_at: i64,
    pub generation: u64,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct AuthorizedTopicReportV1 {
    pub report: TopicReportV1,
    pub signature: Signature,
}


#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct TopicReportResolutionV1 {
    pub topic_id: TopicId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_id: Option<MessageId>,
    pub reporter: MemberId,
    pub resolved_by: MemberId,
    pub created_at: i64,
    pub generation: u64,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct AuthorizedTopicReportResolutionV1 {
    pub resolution: TopicReportResolutionV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_key: Option<VerifyingKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<Box<AuthorityProof>>,
    pub signature: Signature,
}

pub type TopicReportKey = (TopicId, Option<MessageId>, MemberId);

impl AuthorizedTopicFlagV1 {
    pub fn digest(&self) -> i64 {
        let mut bytes = Vec::new();
        let _ = ciborium::ser::into_writer(&self.flag, &mut bytes);
        freenet_scaffold::util::fast_hash(&bytes).0
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct TopicIndexV1 {
    pub entries: Vec<AuthorizedTopicEntryV1>,
    #[serde(default)]
    pub activity: Vec<AuthorizedTopicActivityV1>,
    #[serde(default)]
    pub flags: Vec<AuthorizedTopicFlagV1>,
    #[serde(default)]
    pub reports: Vec<AuthorizedTopicReportV1>,
    #[serde(default)]
    pub report_resolutions: Vec<AuthorizedTopicReportResolutionV1>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct TopicEntryState {
    pub generation: u64,
    pub digest: i64,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct TopicActivityState {
    pub generation: u64,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct TopicFlagState {
    pub generation: u64,
    pub value: bool,
    pub destination: Option<TopicId>,
    pub section: Option<SectionId>,
    pub section_chain: Vec<SectionId>,
    pub part: Option<u32>,
    pub digest: i64,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct TopicIndexSummary {
    pub entries: BTreeMap<TopicId, TopicEntryState>,
    pub activity: BTreeMap<TopicId, TopicActivityState>,
    pub flags: BTreeMap<(TopicId, TopicFlagKind), TopicFlagState>,
    pub reports: BTreeMap<TopicReportKey, u64>,
    pub report_resolutions: BTreeMap<TopicReportKey, u64>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct TopicIndexDelta {
    pub entries: Vec<AuthorizedTopicEntryV1>,
    pub activity: Vec<AuthorizedTopicActivityV1>,
    pub flags: Vec<AuthorizedTopicFlagV1>,
    pub reports: Vec<AuthorizedTopicReportV1>,
    pub report_resolutions: Vec<AuthorizedTopicReportResolutionV1>,
}

impl TopicIndexV1 {
    pub fn entry(&self, topic_id: &TopicId) -> Option<&AuthorizedTopicEntryV1> {
        self.entries
            .iter()
            .find(|entry| entry.entry.topic_id == *topic_id)
    }

    pub fn activity_for(&self, topic_id: &TopicId) -> Option<&AuthorizedTopicActivityV1> {
        self.activity
            .iter()
            .find(|entry| entry.activity.topic_id == *topic_id)
    }

    pub fn flag(&self, topic_id: &TopicId, kind: TopicFlagKind) -> Option<&TopicFlagV1> {
        self.flags
            .iter()
            .filter(|entry| entry.flag.topic_id == *topic_id && entry.flag.kind == kind)
            .max_by_key(|entry| entry.flag.generation)
            .map(|entry| &entry.flag)
    }

    pub fn is_pinned(&self, topic_id: &TopicId) -> bool {
        self.flag(topic_id, TopicFlagKind::Pinned)
            .map(|flag| flag.value)
            .unwrap_or(false)
    }

    pub fn is_closed(&self, topic_id: &TopicId) -> bool {
        self.flag(topic_id, TopicFlagKind::Closed)
            .map(|flag| flag.value)
            .unwrap_or(false)
    }

    pub fn is_announced(&self, topic_id: &TopicId) -> bool {
        self.flag(topic_id, TopicFlagKind::Announced)
            .map(|flag| flag.value)
            .unwrap_or(false)
    }

    pub fn is_hidden(&self, topic_id: &TopicId) -> bool {
        self.flag(topic_id, TopicFlagKind::Hidden)
            .map(|flag| flag.value)
            .unwrap_or(false)
    }

    pub fn is_approved(&self, topic_id: &TopicId) -> bool {
        self.flag(topic_id, TopicFlagKind::Approved)
            .map(|flag| flag.value)
            .unwrap_or(true)
    }

    pub fn merged_into(&self, topic_id: &TopicId) -> Option<TopicId> {
        self.flag(topic_id, TopicFlagKind::Merged)
            .filter(|flag| flag.value)
            .and_then(|flag| flag.destination)
    }

    /// Effective section of a topic, after an owner/moderator move. The base
    /// entry keeps the author-signed creation section.
    pub fn section_of(&self, topic_id: &TopicId) -> (Option<SectionId>, Vec<SectionId>) {
        let base = self
            .entry(topic_id)
            .map(|entry| (entry.entry.section, entry.entry.section_chain.clone()))
            .unwrap_or((None, Vec::new()));
        match self.flag(topic_id, TopicFlagKind::Section) {
            Some(flag) if flag.value && flag.section.is_some() => {
                (flag.section, flag.section_chain.clone())
            }
            _ => base,
        }
    }

    /// Current topic part, after a continuation. The entry keeps the part the
    /// author created; any board member may publish a newer `Part` flag.
    pub fn part_of(&self, topic_id: &TopicId) -> u32 {
        match self.flag(topic_id, TopicFlagKind::Part) {
            Some(flag) if flag.value => flag
                .part
                .or_else(|| self.entry(topic_id).map(|entry| entry.entry.part))
                .unwrap_or(0),
            _ => self
                .entry(topic_id)
                .map(|entry| entry.entry.part)
                .unwrap_or(0),
        }
    }

    pub fn next_entry_generation(&self, topic_id: &TopicId) -> u64 {
        self.entry(topic_id)
            .map(|entry| entry.entry.generation + 1)
            .unwrap_or(1)
    }

    fn member_key(
        state: &ChatBoardStateV1,
        parameters: &ChatBoardParametersV1,
        signer: MemberId,
        embedded: Option<VerifyingKey>,
    ) -> Result<VerifyingKey, String> {
        resolve_signer_key(state, parameters, &signer, embedded.as_ref())
    }

    fn verify_entry(
        &self,
        state: &ChatBoardStateV1,
        parameters: &ChatBoardParametersV1,
        entry: &AuthorizedTopicEntryV1,
    ) -> Result<(), String> {
        let value = &entry.entry;
        value.verify_basics()?;
        if value.author != parameters.owner_id()
            && !state
                .members
                .members
                .iter()
                .any(|member| member.member.id() == value.author)
        {
            return Err("topic author is not a board member".to_string());
        }
        let author_key = if value.author == parameters.owner_id() {
            parameters.owner
        } else {
            state
                .members
                .members
                .iter()
                .find(|member| member.member.id() == value.author)
                .map(|member| member.member.member_vk)
                .ok_or("topic author is missing")?
        };
        if let Some(signer_key) = entry.signer_key {
            if MemberId::from(&signer_key) != value.author {
                return Err("topic entry signer is not the author".to_string());
            }
        }
        if let Some(signer) = entry.signer {
            if signer != value.author {
                return Err("topic entry signer is not the author".to_string());
            }
        }
        verify_struct(value, &entry.signature, &author_key)
            .map_err(|error| format!("invalid topic entry signature: {error}"))?;
        if let Some(section) = value.section {
            if !state.sections.exists(&section) {
                return Err("topic section does not exist".to_string());
            }
            if state.sections.chain(&section) != value.section_chain {
                return Err("topic section chain does not match the board".to_string());
            }
        }
        Ok(())
    }

    fn verify_activity(
        &self,
        state: &ChatBoardStateV1,
        parameters: &ChatBoardParametersV1,
        entry: &AuthorizedTopicActivityV1,
    ) -> Result<(), String> {
        let value = &entry.activity;
        if self.entry(&value.topic_id).is_none() {
            return Err("activity targets a missing topic".to_string());
        }
        if value.generation == 0 {
            return Err("activity generation must be positive".to_string());
        }
        if value.reply_count > 1_000_000 {
            return Err("topic reply count is out of range".to_string());
        }
        if value.pending_approvals > 10_000 {
            return Err("topic pending approvals are out of range".to_string());
        }
        let signer = entry.signer.unwrap_or(parameters.owner_id());
        let key = Self::member_key(state, parameters, signer, entry.signer_key)?;
        verify_struct(value, &entry.signature, &key)
            .map_err(|error| format!("invalid topic activity signature: {error}"))
    }

    fn verify_flag(
        &self,
        state: &ChatBoardStateV1,
        parameters: &ChatBoardParametersV1,
        entry: &AuthorizedTopicFlagV1,
    ) -> Result<(), String> {
        let value = &entry.flag;
        let topic = self
            .entry(&value.topic_id)
            .ok_or("topic flag targets a missing topic")?;
        if value.generation == 0 {
            return Err("topic flag generation must be positive".to_string());
        }
        if value.kind == TopicFlagKind::Merged {
            if value.value && value.destination.is_none() {
                return Err("a merged topic needs a destination".to_string());
            }
            if value.destination == Some(value.topic_id) {
                return Err("a topic cannot merge into itself".to_string());
            }
            if let Some(destination) = value.destination {
                if self.entry(&destination).is_none() {
                    return Err("the merge destination is not indexed".to_string());
                }
            }
            if value.section.is_some() || !value.section_chain.is_empty() {
                return Err("a merge flag cannot move the section".to_string());
            }
        } else if value.kind == TopicFlagKind::Section {
            if !value.value {
                return Err("a section move flag must be active".to_string());
            }
            let section = value
                .section
                .ok_or("a section move needs a destination section")?;
            if !state.sections.exists(&section) {
                return Err("the new section does not exist".to_string());
            }
            if state.sections.chain(&section) != value.section_chain {
                return Err("the new section chain does not match the board".to_string());
            }
            if value.destination.is_some() {
                return Err("a section move cannot carry a topic destination".to_string());
            }
            if value.scope_chain != topic.entry.section_chain {
                return Err("a section move must name the current section chain".to_string());
            }
        } else if value.kind == TopicFlagKind::Part {
            if !value.value {
                return Err("a continuation flag must be active".to_string());
            }
            let part = value
                .part
                .ok_or("a continuation flag needs a part")?;
            if part == 0 {
                return Err("a continuation part must be positive".to_string());
            }
            if value.destination.is_some()
                || value.section.is_some()
                || !value.section_chain.is_empty()
            {
                return Err("a continuation flag only carries a part".to_string());
            }
            let signer = entry.signer.unwrap_or(parameters.owner_id());
            let is_member = signer == parameters.owner_id()
                || state
                    .members
                    .members
                    .iter()
                    .any(|member| member.member.id() == signer);
            if !is_member {
                return Err("only a board member can continue a topic".to_string());
            }
            return Ok(());
        } else if value.destination.is_some()
            || value.section.is_some()
            || !value.section_chain.is_empty()
            || value.part.is_some()
        {
            return Err("only a merge, section or part flag carries a destination".to_string());
        }
        let chain = topic.entry.section_chain.clone();
        if !value.scope_chain.is_empty() && value.scope_chain != chain {
            return Err("the flag scope chain does not match the topic".to_string());
        }
        let signer = entry.signer.unwrap_or(parameters.owner_id());
        let key = Self::member_key(state, parameters, signer, entry.signer_key)?;
        verify_struct(value, &entry.signature, &key)
            .map_err(|error| format!("invalid topic flag signature: {error}"))?;
        let power = match value.kind {
            TopicFlagKind::Pinned | TopicFlagKind::Announced => ModerationPower::Pin,
            TopicFlagKind::Closed => ModerationPower::Close,
            TopicFlagKind::Merged | TopicFlagKind::Section => ModerationPower::Move,
            TopicFlagKind::Hidden | TopicFlagKind::Approved => ModerationPower::Delete,
            TopicFlagKind::Part => unreachable!("part flags are handled above"),
        };
        verify_moderation_authority(
            state,
            parameters,
            &signer,
            power,
            &chain,
            entry.authority.as_deref(),
            crate::board_state::rate_limit::system_time_from_ms(value.created_at),
        )
    }


    fn verify_report(
        &self,
        state: &ChatBoardStateV1,
        parameters: &ChatBoardParametersV1,
        entry: &AuthorizedTopicReportV1,
    ) -> Result<(), String> {
        let value = &entry.report;
        if self.entry(&value.topic_id).is_none() {
            return Err("report targets a missing topic".to_string());
        }
        if value.generation == 0 {
            return Err("report generation must be positive".to_string());
        }
        if value.body.declared_len() > MAX_TOPIC_REPORT_BYTES {
            return Err("report body is too large".to_string());
        }
        let signer = value.reporter;
        let key = Self::member_key(state, parameters, signer, None)?;
        verify_struct(value, &entry.signature, &key)
            .map_err(|error| format!("invalid report signature: {error}"))?;
        if signer != parameters.owner_id()
            && !state
                .members
                .members
                .iter()
                .any(|member| member.member.id() == signer)
        {
            return Err("only a board member can report".to_string());
        }
        Ok(())
    }


    fn verify_report_resolution(
        &self,
        state: &ChatBoardStateV1,
        parameters: &ChatBoardParametersV1,
        entry: &AuthorizedTopicReportResolutionV1,
    ) -> Result<(), String> {
        let value = &entry.resolution;
        if !self.reports.iter().any(|report| {
            report.report.topic_id == value.topic_id
                && report.report.post_id == value.post_id
                && report.report.reporter == value.reporter
        }) {
            return Err("resolution targets a missing report".to_string());
        }
        if value.generation == 0 {
            return Err("resolution generation must be positive".to_string());
        }
        let signer = value.resolved_by;
        let key = Self::member_key(state, parameters, signer, entry.signer_key)?;
        verify_struct(value, &entry.signature, &key)
            .map_err(|error| format!("invalid resolution signature: {error}"))?;
        let chain = self.section_of(&value.topic_id).1;
        verify_moderation_authority(
            state,
            parameters,
            &signer,
            ModerationPower::Delete,
            &chain,
            entry.authority.as_deref(),
            crate::board_state::rate_limit::system_time_from_ms(value.created_at),
        )
    }

    pub fn report_count(&self, topic_id: &TopicId) -> usize {
        self.reports
            .iter()
            .filter(|entry| entry.report.topic_id == *topic_id)
            .count()
    }

    fn sort(&mut self) {
        self.entries
            .sort_by_key(|entry| (entry.entry.topic_id.0 .0, entry.entry.generation));
        self.activity
            .sort_by_key(|entry| (entry.activity.topic_id.0 .0, entry.activity.generation));
        self.flags.sort_by_key(|entry| {
            (
                entry.flag.topic_id.0 .0,
                entry.flag.kind,
                entry.flag.generation,
            )
        });
        self.reports.sort_by_key(|entry| {
            (
                entry.report.topic_id.0 .0,
                entry.report.post_id.map(|id| id.0 .0),
                entry.report.reporter.0 .0,
                entry.report.generation,
            )
        });
        self.report_resolutions.sort_by_key(|entry| {
            (
                entry.resolution.topic_id.0 .0,
                entry.resolution.post_id.map(|id| id.0 .0),
                entry.resolution.reporter.0 .0,
                entry.resolution.generation,
            )
        });
    }
}

impl ComposableState for TopicIndexV1 {
    type ParentState = ChatBoardStateV1;
    type Summary = TopicIndexSummary;
    type Delta = TopicIndexDelta;
    type Parameters = ChatBoardParametersV1;

    fn verify(
        &self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
    ) -> Result<(), String> {
        self.verify_limits()?;
        let mut topics = HashSet::new();
        for entry in &self.entries {
            if !topics.insert(entry.entry.topic_id) {
                return Err("duplicate topic".to_string());
            }
            self.verify_entry(parent_state, parameters, entry)?;
        }
        let mut activity = HashSet::new();
        for entry in &self.activity {
            if !activity.insert(entry.activity.topic_id) {
                return Err("duplicate topic activity".to_string());
            }
            self.verify_activity(parent_state, parameters, entry)?;
        }
        let mut flags = HashSet::new();
        for entry in &self.flags {
            if !flags.insert((entry.flag.topic_id, entry.flag.kind)) {
                return Err("duplicate topic flag".to_string());
            }
            self.verify_flag(parent_state, parameters, entry)?;
        }
        let mut reports = HashSet::new();
        for entry in &self.reports {
            if !reports.insert((
                entry.report.topic_id,
                entry.report.post_id,
                entry.report.reporter,
            )) {
                return Err("duplicate topic report".to_string());
            }
            self.verify_report(parent_state, parameters, entry)?;
        }
        let mut resolutions = HashSet::new();
        for entry in &self.report_resolutions {
            if !resolutions.insert((
                entry.resolution.topic_id,
                entry.resolution.post_id,
                entry.resolution.reporter,
            )) {
                return Err("duplicate report resolution".to_string());
            }
            self.verify_report_resolution(parent_state, parameters, entry)?;
        }
        Ok(())
    }

    fn summarize(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
    ) -> Self::Summary {
        TopicIndexSummary {
            entries: self
                .entries
                .iter()
                .map(|entry| {
                    (
                        entry.entry.topic_id,
                        TopicEntryState {
                            generation: entry.entry.generation,
                            digest: entry.digest(),
                        },
                    )
                })
                .collect(),
            activity: self
                .activity
                .iter()
                .map(|entry| {
                    (
                        entry.activity.topic_id,
                        TopicActivityState {
                            generation: entry.activity.generation,
                        },
                    )
                })
                .collect(),
            flags: self
                .flags
                .iter()
                .map(|entry| {
                    (
                        (entry.flag.topic_id, entry.flag.kind),
                        TopicFlagState {
                            generation: entry.flag.generation,
                            value: entry.flag.value,
                            destination: entry.flag.destination,
                            section: entry.flag.section,
                            section_chain: entry.flag.section_chain.clone(),
                            part: entry.flag.part,
                            digest: entry.digest(),
                        },
                    )
                })
                .collect(),
            reports: self
                .reports
                .iter()
                .map(|entry| {
                    (
                        (
                            entry.report.topic_id,
                            entry.report.post_id,
                            entry.report.reporter,
                        ),
                        entry.report.generation,
                    )
                })
                .collect(),
            report_resolutions: self
                .report_resolutions
                .iter()
                .map(|entry| {
                    (
                        (
                            entry.resolution.topic_id,
                            entry.resolution.post_id,
                            entry.resolution.reporter,
                        ),
                        entry.resolution.generation,
                    )
                })
                .collect(),
        }
    }

    fn delta(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
        old_state_summary: &Self::Summary,
    ) -> Option<Self::Delta> {
        let entries: Vec<_> = self
            .entries
            .iter()
            .filter(|entry| {
                old_state_summary
                    .entries
                    .get(&entry.entry.topic_id)
                    .map(|known| {
                        known.generation != entry.entry.generation
                            || known.digest != entry.digest()
                    })
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        let activity: Vec<_> = self
            .activity
            .iter()
            .filter(|entry| {
                old_state_summary
                    .activity
                    .get(&entry.activity.topic_id)
                    .map(|known| known.generation != entry.activity.generation)
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        let flags: Vec<_> = self
            .flags
            .iter()
            .filter(|entry| {
                old_state_summary
                    .flags
                    .get(&(entry.flag.topic_id, entry.flag.kind))
                    .map(|known| {
                        known.generation != entry.flag.generation
                            || known.value != entry.flag.value
                            || known.destination != entry.flag.destination
                            || known.section != entry.flag.section
                            || known.section_chain != entry.flag.section_chain
                            || known.part != entry.flag.part
                            || known.digest != entry.digest()
                    })
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        let reports: Vec<_> = self
            .reports
            .iter()
            .filter(|entry| {
                old_state_summary
                    .reports
                    .get(&(
                        entry.report.topic_id,
                        entry.report.post_id,
                        entry.report.reporter,
                    ))
                    .map(|known| *known < entry.report.generation)
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        let report_resolutions: Vec<_> = self
            .report_resolutions
            .iter()
            .filter(|entry| {
                old_state_summary
                    .report_resolutions
                    .get(&(
                        entry.resolution.topic_id,
                        entry.resolution.post_id,
                        entry.resolution.reporter,
                    ))
                    .map(|known| *known < entry.resolution.generation)
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        if entries.is_empty()
            && activity.is_empty()
            && flags.is_empty()
            && reports.is_empty()
            && report_resolutions.is_empty()
        {
            None
        } else {
            Some(TopicIndexDelta {
                entries,
                activity,
                flags,
                reports,
                report_resolutions,
            })
        }
    }

    fn apply_delta(
        &mut self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
        delta: &Option<Self::Delta>,
    ) -> Result<(), String> {
        if let Some(delta) = delta {
            for entry in &delta.entries {
                self.verify_entry(parent_state, parameters, entry)?;
                match self
                    .entries
                    .iter_mut()
                    .find(|existing| existing.entry.topic_id == entry.entry.topic_id)
                {
                    Some(existing) => {
                        let take = entry.entry.generation > existing.entry.generation
                            || (entry.entry.generation == existing.entry.generation
                                && entry.digest() < existing.digest());
                        if take {
                            *existing = entry.clone();
                        }
                    }
                    None => self.entries.push(entry.clone()),
                }
            }
            for entry in &delta.activity {
                self.verify_activity(parent_state, parameters, entry)?;
                match self
                    .activity
                    .iter_mut()
                    .find(|existing| existing.activity.topic_id == entry.activity.topic_id)
                {
                    Some(existing) => {
                        if entry.activity.generation > existing.activity.generation {
                            *existing = entry.clone();
                        }
                    }
                    None => self.activity.push(entry.clone()),
                }
            }
            for entry in &delta.flags {
                self.verify_flag(parent_state, parameters, entry)?;
                match self.flags.iter_mut().find(|existing| {
                    existing.flag.topic_id == entry.flag.topic_id
                        && existing.flag.kind == entry.flag.kind
                }) {
                    Some(existing) => {
                        let take = entry.flag.generation > existing.flag.generation
                            || (entry.flag.generation == existing.flag.generation
                                && entry.flag.value == false
                                && existing.flag.value)
                            || (entry.flag.generation == existing.flag.generation
                                && entry.flag.value == existing.flag.value
                                && entry.digest() < existing.digest());
                        if take {
                            *existing = entry.clone();
                        }
                    }
                    None => self.flags.push(entry.clone()),
                }
            }
            for entry in &delta.reports {
                self.verify_report(parent_state, parameters, entry)?;
                match self.reports.iter_mut().find(|existing| {
                    existing.report.topic_id == entry.report.topic_id
                        && existing.report.post_id == entry.report.post_id
                        && existing.report.reporter == entry.report.reporter
                }) {
                    Some(existing) => {
                        if entry.report.generation > existing.report.generation {
                            *existing = entry.clone();
                        }
                    }
                    None => self.reports.push(entry.clone()),
                }
            }
            for entry in &delta.report_resolutions {
                self.verify_report_resolution(parent_state, parameters, entry)?;
                match self.report_resolutions.iter_mut().find(|existing| {
                    existing.resolution.topic_id == entry.resolution.topic_id
                        && existing.resolution.post_id == entry.resolution.post_id
                        && existing.resolution.reporter == entry.resolution.reporter
                }) {
                    Some(existing) => {
                        if entry.resolution.generation > existing.resolution.generation {
                            *existing = entry.clone();
                        }
                    }
                    None => self.report_resolutions.push(entry.clone()),
                }
            }
        }
        self.sort();
        self.entries.dedup_by_key(|entry| entry.entry.topic_id);
        self.activity.dedup_by_key(|entry| entry.activity.topic_id);
        self.flags
            .dedup_by_key(|entry| (entry.flag.topic_id, entry.flag.kind));
        self.reports.dedup_by_key(|entry| {
            (
                entry.report.topic_id,
                entry.report.post_id,
                entry.report.reporter,
            )
        });
        self.report_resolutions.dedup_by_key(|entry| {
            (
                entry.resolution.topic_id,
                entry.resolution.post_id,
                entry.resolution.reporter,
            )
        });
        self.verify_limits()
    }
}

impl TopicIndexV1 {
    /// Caps and per-author frequency limits. These do not verify record
    /// signatures, so the delta fast path can run them after applying a
    /// topics-only update.
    pub fn verify_limits(&self) -> Result<(), String> {
        if self.entries.len() > MAX_TOPICS {
            return Err("too many topics".to_string());
        }
        if self.activity.len() > MAX_TOPIC_ACTIVITY {
            return Err("too many topic activity records".to_string());
        }
        if self.flags.len() > MAX_TOPIC_FLAGS {
            return Err("too many topic flags".to_string());
        }
        if self.reports.len() > MAX_TOPIC_REPORTS {
            return Err("too many topic reports".to_string());
        }
        if self.report_resolutions.len() > MAX_TOPIC_REPORTS {
            return Err("too many report resolutions".to_string());
        }
        if let Some(author) = exceeding_member(
            self.entries
                .iter()
                .map(|entry| (entry.entry.author, entry.entry.created_at)),
            TOPIC_RATE_WINDOW_MS,
            MAX_TOPICS_PER_WINDOW,
        ) {
            return Err(format!("too many topics from {author} in the window"));
        }
        if let Some(reporter) = exceeding_member(
            self.reports
                .iter()
                .map(|entry| (entry.report.reporter, entry.report.created_at)),
            REPORT_RATE_WINDOW_MS,
            MAX_REPORTS_PER_WINDOW,
        ) {
            return Err(format!("too many reports from {reporter} in the window"));
        }
        Ok(())
    }

    pub fn cleanup(
        &mut self,
        state: &ChatBoardStateV1,
        parameters: &ChatBoardParametersV1,
    ) {
        let mut entries = std::mem::take(&mut self.entries);
        entries.retain(|entry| self.verify_entry(state, parameters, entry).is_ok());
        self.entries = entries;
        let live: HashSet<TopicId> = self
            .entries
            .iter()
            .map(|entry| entry.entry.topic_id)
            .collect();
        self.activity
            .retain(|entry| live.contains(&entry.activity.topic_id));
        self.flags
            .retain(|entry| live.contains(&entry.flag.topic_id));
        let mut reports = std::mem::take(&mut self.reports);
        reports.retain(|entry| {
            live.contains(&entry.report.topic_id)
                && self.verify_report(state, parameters, entry).is_ok()
        });
        self.reports = reports;
        let mut resolutions = std::mem::take(&mut self.report_resolutions);
        resolutions.retain(|entry| {
            live.contains(&entry.resolution.topic_id)
                && self.reports.iter().any(|report| {
                    report.report.topic_id == entry.resolution.topic_id
                        && report.report.post_id == entry.resolution.post_id
                        && report.report.reporter == entry.resolution.reporter
                })
                && self.verify_report_resolution(state, parameters, entry).is_ok()
        });
        self.report_resolutions = resolutions;
        self.sort();
        self.entries.dedup_by_key(|entry| entry.entry.topic_id);
        self.activity.dedup_by_key(|entry| entry.activity.topic_id);
        self.flags
            .dedup_by_key(|entry| (entry.flag.topic_id, entry.flag.kind));
        self.reports.dedup_by_key(|entry| {
            (
                entry.report.topic_id,
                entry.report.post_id,
                entry.report.reporter,
            )
        });
        self.report_resolutions.dedup_by_key(|entry| {
            (
                entry.resolution.topic_id,
                entry.resolution.post_id,
                entry.resolution.reporter,
            )
        });
    }

    pub fn section_chain_for(&self, sections: &SectionsV1, section: Option<SectionId>) -> Vec<SectionId> {
        section
            .map(|section| sections.chain(&section))
            .unwrap_or_default()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::board_state::configuration::{
        AuthorizedConfigurationV1, Configuration,
    };
    use crate::board_state::member::{AuthorizedMember, Member};
    use crate::board_state::roles::{
        AuthorizedRole, AuthorizedRoleAssignment, Role, RoleAssignment,
    };
    use crate::board_state::sections::{AuthorizedSectionV1, SectionV1};
    use crate::util::sign_struct;
    use std::time::SystemTime;

    pub(crate) fn owner() -> SigningKey {
        SigningKey::from_bytes(&[1u8; 32])
    }

    pub(crate) fn member() -> SigningKey {
        SigningKey::from_bytes(&[2u8; 32])
    }

    pub(crate) fn params() -> ChatBoardParametersV1 {
        ChatBoardParametersV1 {
            owner: owner().verifying_key(),
        }
    }

    pub(crate) fn board() -> ChatBoardStateV1 {
        let owner = owner();
        let member = member();
        let owner_id = MemberId::from(&owner.verifying_key());
        let mut state = ChatBoardStateV1 {
            configuration: AuthorizedConfigurationV1::new(
                Configuration::default(),
                &owner,
            ),
            ..Default::default()
        };
        state.members.members.push(AuthorizedMember::new(
            Member {
                owner_member_id: owner_id,
                invited_by: owner_id,
                member_vk: member.verifying_key(),
                join_proof: None,
            },
            &owner,
        ));
        state
    }

    pub(crate) fn topic(author: &SigningKey, section: Option<SectionId>, chain: Vec<SectionId>) -> AuthorizedTopicEntryV1 {
        AuthorizedTopicEntryV1::new(
            TopicEntryV1 {
                topic_id: TopicId::from_bytes([7u8; 32]),
                part: 0,
                protocol_version: TOPIC_PROTOCOL_VERSION,
                author: MemberId::from(&author.verifying_key()),
                section,
                section_chain: chain,
                title: SealedBytes::public(b"Title".to_vec()),
                preview: SealedBytes::public(b"Preview".to_vec()),
                header_hash: [9u8; 32],
                created_at: 1,
                generation: 1,
            },
            author,
        )
    }

    pub(crate) fn activity(topic_id: TopicId, generation: u64) -> AuthorizedTopicActivityV1 {
        let value = TopicActivityV1 {
            topic_id,
            last_activity: 10,
            last_post_id: None,
            reply_count: 1,
            pending_approvals: 0,
            generation,
        };
        AuthorizedTopicActivityV1 {
            signature: sign_struct(&value, &member()),
            activity: value,
            signer: Some(MemberId::from(&member().verifying_key())),
            signer_key: Some(member().verifying_key()),
        }
    }

    pub(crate) fn flag(kind: TopicFlagKind, value: bool) -> AuthorizedTopicFlagV1 {
        let flag = TopicFlagV1 {
            topic_id: TopicId::from_bytes([7u8; 32]),
            kind,
            value,
            destination: None,
            section: None,
            section_chain: Vec::new(),
            part: None,
            scope_chain: Vec::new(),
            generation: 1,
            created_at: 1,
        };
        AuthorizedTopicFlagV1 {
            signature: sign_struct(&flag, &owner()),
            flag,
            signer: Some(MemberId::from(&owner().verifying_key())),
            signer_key: Some(owner().verifying_key()),
            authority: None,
        }
    }

    #[test]
    fn a_member_creates_a_topic_entry() {
        let state = board();
        let mut index = TopicIndexV1::default();
        index.entries.push(topic(&member(), None, Vec::new()));
        index.verify(&state, &params()).unwrap();
    }

    #[test]
    fn an_outsider_cannot_create_a_topic_entry() {
        let state = board();
        let outsider = SigningKey::from_bytes(&[3u8; 32]);
        let mut index = TopicIndexV1::default();
        index.entries.push(topic(&outsider, None, Vec::new()));
        assert!(index.verify(&state, &params()).is_err());
    }

    #[test]
    fn activity_is_signed_by_a_member() {
        let state = board();
        let mut index = TopicIndexV1::default();
        index.entries.push(topic(&member(), None, Vec::new()));
        index
            .activity
            .push(activity(TopicId::from_bytes([7u8; 32]), 1));
        index.verify(&state, &params()).unwrap();
    }

    #[test]
    fn the_owner_pins_a_topic() {
        let state = board();
        let mut index = TopicIndexV1::default();
        index.entries.push(topic(&member(), None, Vec::new()));
        index.flags.push(flag(TopicFlagKind::Pinned, true));
        index.verify(&state, &params()).unwrap();
        assert!(index.is_pinned(&TopicId::from_bytes([7u8; 32])));
    }

    #[test]
    fn a_member_cannot_pin_a_topic() {
        let state = board();
        let mut index = TopicIndexV1::default();
        index.entries.push(topic(&member(), None, Vec::new()));
        let mut pinned = flag(TopicFlagKind::Pinned, true);
        pinned.signature = sign_struct(&pinned.flag, &member());
        pinned.signer = Some(MemberId::from(&member().verifying_key()));
        pinned.signer_key = Some(member().verifying_key());
        index.flags.push(pinned);
        assert!(index.verify(&state, &params()).is_err());
    }

    #[test]
    fn a_topic_can_be_hidden_and_approved() {
        let state = board();
        let mut index = TopicIndexV1::default();
        index.entries.push(topic(&member(), None, Vec::new()));
        index.flags.push(flag(TopicFlagKind::Hidden, true));
        index.flags.push(flag(TopicFlagKind::Approved, false));
        index.verify(&state, &params()).unwrap();
        assert!(index.is_hidden(&TopicId::from_bytes([7u8; 32])));
        assert!(!index.is_approved(&TopicId::from_bytes([7u8; 32])));
    }

    #[test]
    fn a_section_chain_must_match_the_board() {
        let mut state = board();
        let section = SectionId::from_bytes([9u8; 32]);
        state.sections.sections.push(AuthorizedSectionV1::new(
            SectionV1 {
                id: section,
                parent: None,
                name: "Test".to_string(),
                description: None,
                icon: None,
                color: "#fff".to_string(),
                allowed_roles: Vec::new(),
                sealed_name: None,
                hidden: false,
                is_group: false,
                images_allowed: true,
                auto_moderated_topics: None,
                generation: 1,
                deleted: false,
                signed_at: SystemTime::UNIX_EPOCH,
            },
            &owner(),
            None,
        ));
        let mut index = TopicIndexV1::default();
        index
            .entries
            .push(topic(&member(), Some(section), vec![section]));
        index.verify(&state, &params()).unwrap();

        let mut wrong = TopicIndexV1::default();
        wrong
            .entries
            .push(topic(&member(), Some(section), Vec::new()));
        assert!(wrong.verify(&state, &params()).is_err());
    }

    #[test]
    fn a_title_over_the_limit_is_rejected() {
        let state = board();
        let mut index = TopicIndexV1::default();
        let mut entry = topic(&member(), None, Vec::new());
        entry.entry.title = SealedBytes::public(vec![b'x'; MAX_TOPIC_TITLE_BYTES + 1]);
        index.entries.push(entry);
        assert!(index.verify(&state, &params()).is_err());
    }
}

#[cfg(test)]
mod section_move_tests {
    use super::tests::*;
    use super::*;
    use crate::board_state::sections::{AuthorizedSectionV1, SectionV1};
    use std::time::SystemTime;

    #[test]
    fn a_section_flag_moves_a_topic() {
        let mut state = board();
        let section_a = SectionId::from_bytes([1u8; 32]);
        let section_b = SectionId::from_bytes([2u8; 32]);
        for (id, name) in [(section_a, "A"), (section_b, "B")] {
            state.sections.sections.push(AuthorizedSectionV1::new(
                SectionV1 {
                    id,
                    parent: None,
                    name: name.to_string(),
                    description: None,
                    icon: None,
                    color: "#fff".to_string(),
                    allowed_roles: Vec::new(),
                    sealed_name: None,
                    hidden: false,
                    is_group: false,
                    images_allowed: true,
                    auto_moderated_topics: None,
                    generation: 1,
                    deleted: false,
                    signed_at: SystemTime::UNIX_EPOCH,
                },
                &owner(),
                None,
            ));
        }
        let mut index = TopicIndexV1::default();
        index
            .entries
            .push(topic(&member(), Some(section_a), vec![section_a]));
        let flag = TopicFlagV1 {
            topic_id: TopicId::from_bytes([7u8; 32]),
            kind: TopicFlagKind::Section,
            value: true,
            destination: None,
            section: Some(section_b),
            section_chain: vec![section_b],
            part: None,
            scope_chain: vec![section_a],
            generation: 1,
            created_at: 1,
        };
        index.flags.push(AuthorizedTopicFlagV1 {
            signature: sign_struct(&flag, &owner()),
            flag,
            signer: Some(MemberId::from(&owner().verifying_key())),
            signer_key: Some(owner().verifying_key()),
            authority: None,
        });
        index.verify(&state, &params()).unwrap();
        assert_eq!(
            index.section_of(&TopicId::from_bytes([7u8; 32])).0,
            Some(section_b)
        );
    }
}

#[cfg(test)]
mod continuation_flag_tests {
    use super::tests::*;
    use super::*;

    #[test]
    fn a_part_flag_moves_the_index_to_the_next_part() {
        let state = board();
        let mut index = TopicIndexV1::default();
        index.entries.push(topic(&member(), None, Vec::new()));
        let flag = TopicFlagV1 {
            topic_id: TopicId::from_bytes([7u8; 32]),
            kind: TopicFlagKind::Part,
            value: true,
            destination: None,
            section: None,
            section_chain: Vec::new(),
            part: Some(2),
            scope_chain: Vec::new(),
            generation: 1,
            created_at: 1,
        };
        index.flags.push(AuthorizedTopicFlagV1 {
            signature: sign_struct(&flag, &owner()),
            flag,
            signer: Some(MemberId::from(&owner().verifying_key())),
            signer_key: Some(owner().verifying_key()),
            authority: None,
        });
        index.verify(&state, &params()).unwrap();
        assert_eq!(index.part_of(&TopicId::from_bytes([7u8; 32])), 2);
    }
}

#[cfg(test)]
mod report_tests {
    use super::tests::*;
    use super::*;
    use crate::board_state::reports::ReportReason;

    #[test]
    fn a_member_report_is_indexed() {
        let state = board();
        let mut index = TopicIndexV1::default();
        index.entries.push(topic(&member(), None, Vec::new()));
        let report = TopicReportV1 {
            topic_id: TopicId::from_bytes([7u8; 32]),
            post_id: None,
            reporter: MemberId::from(&member().verifying_key()),
            reason: ReportReason::Other,
            body: SealedBytes::public(b"spam".to_vec()),
            created_at: 1,
            generation: 1,
        };
        index.reports.push(AuthorizedTopicReportV1 {
            signature: sign_struct(&report, &member()),
            report,
        });
        index.verify(&state, &params()).unwrap();
        assert_eq!(index.report_count(&TopicId::from_bytes([7u8; 32])), 1);
    }
}
