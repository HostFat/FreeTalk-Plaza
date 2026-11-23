//! Core state for `plaza-topic`: one contract per discussion.
//!
//! Phase 1: header, section snapshot, mirrored authority, participants, trusted
//! participants, posts, moderation actions, approvals and the state envelope.
//! The client and the UI are Phase 3+.

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use freenet_scaffold::ComposableState;
use plaza_core::board_state::admin::{AdminsV1, AuthorizedAdmin};
use plaza_core::board_state::ban::{
    BanRevocationsV1, BansV1,
};
use plaza_core::board_state::configuration::{
    AuthorizedConfigurationV1, Configuration,
};
use plaza_core::board_state::content::PollContentV1;
use plaza_core::board_state::images::ImageRef;
use plaza_core::board_state::invites::{
    join_message, AuthorizedInviteToken, JoinProof,
};
use plaza_core::board_state::member::{
    AuthorizedMember, MemberId, MembersV1,
};
use plaza_core::board_state::member_moderation::{
    AuthorizedSuspension, SuspensionsV1,
};
use plaza_core::board_state::message::MessageId;
use plaza_core::board_state::ownership::OwnershipV1;
use plaza_core::board_state::privacy::SealedBytes;
use plaza_core::board_state::rate_limit::{system_time_from_ms, system_time_ms};
use plaza_core::board_state::roles::{
    resolve_signer_key, verify_moderation_authority, AuthorityProof,
    AuthorizedRole, AuthorizedRoleAssignment, ModerationPower, RoleId, RolesV1,
};use plaza_core::board_state::ChatBoardParametersV1;
use plaza_core::ChatBoardStateV1;
use plaza_core::util::{sign_struct, verify_struct};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::time::SystemTime;

pub const PROTOCOL_VERSION: u16 = 1;
/// The contract returns the full state on every update and subscribers receive
/// it, so a part must stay small enough to broadcast. Clients continue a topic
/// at 7/8 of this budget.
pub const MAX_TOPIC_STATE_BYTES: usize = 1024 * 1024;
pub const MAX_POSTS: usize = 500;
pub const MAX_PARTICIPANTS: usize = 512;
pub const MAX_POST_BYTES: usize = 16 * 1024;
pub const MAX_PARTS: u32 = 64;
pub const MAX_TITLE_BYTES: usize = 512;
pub const MAX_BODY_BYTES: usize = 64 * 1024;
pub const MAX_IMAGES_PER_POST: usize = 4;
pub const MAX_ACTIONS: usize = 2_000;
pub const MAX_APPROVALS: usize = 2_000;
pub const MAX_JOIN_DEPTH: usize = 64;

pub type TopicId = MessageId;
pub type SectionId = MessageId;

/// Contract parameters. They never change, so the key is derivable by anyone.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct TopicParamsV1 {
    pub protocol_version: u16,
    /// Founding owner of the board. Ownership transfers travel in the state.
    pub board_owner: VerifyingKey,
    pub topic_id: [u8; 32],
    /// Part of a long topic; 0 for the first contract.
    pub part: u32,
}

impl TopicParamsV1 {
    pub fn new(board_owner: VerifyingKey, topic_id: [u8; 32], part: u32) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            board_owner,
            topic_id,
            part,
        }
    }

    pub fn verify(&self) -> Result<(), String> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(format!(
                "unsupported topic protocol version {}",
                self.protocol_version
            ));
        }
        if self.part > MAX_PARTS {
            return Err("topic part is out of range".to_string());
        }
        Ok(())
    }

    pub fn owner_id(&self) -> MemberId {
        MemberId::from(&self.board_owner)
    }

    pub fn board_parameters(&self) -> ChatBoardParametersV1 {
        ChatBoardParametersV1 {
            owner: self.board_owner,
        }
    }
}

/// The topic itself: title, body and the section it belongs to.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct TopicHeaderV1 {
    pub topic_id: [u8; 32],
    pub author: MemberId,
    pub author_key: VerifyingKey,
    pub section: Option<SectionId>,
    #[serde(default)]
    pub section_chain: Vec<SectionId>,
    pub title: SealedBytes,
    pub body: SealedBytes,
    #[serde(default)]
    pub auto_moderated: bool,
    pub created_at: i64,
    pub nonce: [u8; 16],
}

impl TopicHeaderV1 {
    pub fn verify(&self, params: &TopicParamsV1) -> Result<(), String> {
        if self.topic_id != params.topic_id {
            return Err("header topic id does not match the parameters".to_string());
        }
        if MemberId::from(&self.author_key) != self.author {
            return Err("header author key does not match the author".to_string());
        }
        if self.title.declared_len() > MAX_TITLE_BYTES {
            return Err("topic title is too large".to_string());
        }
        if self.body.declared_len() > MAX_BODY_BYTES {
            return Err("topic body is too large".to_string());
        }
        if self.section.is_some() && !self.section_chain.contains(&self.section.unwrap()) {
            return Err("topic section is not in its chain".to_string());
        }
        Ok(())
    }

    pub fn hash(&self) -> [u8; 32] {
        value_hash(self)
    }

    pub fn id(&self) -> MessageId {
        MessageId::from_bytes(self.topic_id)
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct AuthorizedTopicHeaderV1 {
    pub header: TopicHeaderV1,
    pub signature: Signature,
}

impl AuthorizedTopicHeaderV1 {
    pub fn new(header: TopicHeaderV1, signing_key: &SigningKey) -> Self {
        Self {
            signature: sign_struct(&header, signing_key),
            header,
        }
    }

    pub fn verify(&self, params: &TopicParamsV1) -> Result<(), String> {
        self.header.verify(params)?;
        verify_struct(&self.header, &self.signature, &self.header.author_key)
            .map_err(|error| format!("invalid topic header signature: {error}"))
    }

    pub fn hash(&self) -> [u8; 32] {
        self.header.hash()
    }
}

/// The section metadata a topic needs to enforce its access rules without
/// reading the board contract.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct SectionSnapshotV1 {
    pub section: SectionId,
    pub parent: Option<SectionId>,
    pub chain: Vec<SectionId>,
    /// Empty means every board member may read and post here.
    #[serde(default)]
    pub allowed_roles: Vec<RoleId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed_name: Option<SealedBytes>,
    #[serde(default)]
    pub hidden: bool,
    #[serde(default = "default_true")]
    pub images_allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_moderated_topics: Option<bool>,
    pub generation: u64,
    pub signed_at: i64,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct AuthorizedSectionSnapshotV1 {
    pub snapshot: SectionSnapshotV1,
    pub signer: Option<MemberId>,
    pub signer_key: Option<VerifyingKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<Box<AuthorityProof>>,
    pub signature: Signature,
}

impl AuthorizedSectionSnapshotV1 {
    pub fn new(
        snapshot: SectionSnapshotV1,
        signing_key: &SigningKey,
        authority: Option<AuthorityProof>,
    ) -> Self {
        let signer = MemberId::from(&signing_key.verifying_key());
        Self {
            signature: sign_struct(&snapshot, signing_key),
            snapshot,
            signer: Some(signer),
            signer_key: Some(signing_key.verifying_key()),
            authority: authority.map(Box::new),
        }
    }

    pub fn hash(&self) -> [u8; 32] {
        value_hash(&self.snapshot)
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct TopicPolicyV1 {
    pub read_only: bool,
    pub approval_required: bool,
    pub rate_window_ms: u64,
    pub max_posts_per_window: u32,
    pub images_allowed: bool,
    pub auto_moderated_topics: bool,
    pub reactions_enabled: bool,
    pub max_post_size: usize,
    pub generation: u64,
    pub updated_at: i64,
}

impl Default for TopicPolicyV1 {
    fn default() -> Self {
        Self {
            read_only: false,
            approval_required: false,
            rate_window_ms: 60_000,
            max_posts_per_window: 120,
            images_allowed: true,
            auto_moderated_topics: true,
            reactions_enabled: true,
            max_post_size: MAX_POST_BYTES,
            generation: 1,
            updated_at: 0,
        }
    }
}

impl TopicPolicyV1 {
    pub fn verify(&self) -> Result<(), String> {
        if self.generation == 0 {
            return Err("policy generation must be positive".to_string());
        }
        if self.max_post_size == 0 || self.max_post_size > MAX_POST_BYTES {
            return Err("policy post size is out of range".to_string());
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedTopicPolicyV1 {
    pub policy: TopicPolicyV1,
    pub signer: Option<MemberId>,
    pub signer_key: Option<VerifyingKey>,
    pub signature: Signature,
}

impl Default for AuthorizedTopicPolicyV1 {
    fn default() -> Self {
        Self {
            policy: TopicPolicyV1::default(),
            signer: None,
            signer_key: None,
            signature: Signature::from_bytes(&[0u8; 64]),
        }
    }
}

impl AuthorizedTopicPolicyV1 {
    pub fn new(policy: TopicPolicyV1, owner_sk: &SigningKey) -> Self {
        Self {
            signature: sign_struct(&policy, owner_sk),
            policy,
            signer: None,
            signer_key: None,
        }
    }

    pub fn verify(&self, owner_key: &VerifyingKey, owner_id: MemberId) -> Result<(), String> {
        self.policy.verify()?;
        if let Some(signer) = self.signer {
            if signer != owner_id {
                return Err("only the board owner can change the topic policy".to_string());
            }
        }
        verify_struct(&self.policy, &self.signature, owner_key)
            .map_err(|error| format!("invalid topic policy signature: {error}"))
    }
}

/// Authority records mirrored from the board. Only the entries a topic needs
/// are kept: all admins and role definitions, assignments and bans for the
/// participants and moderators.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct TopicAuthorityV1 {
    pub ownership: OwnershipV1,
    pub admins: AdminsV1,
    pub roles: RolesV1,
    pub bans: BansV1,
    pub ban_revocations: BanRevocationsV1,
    pub suspensions: SuspensionsV1,
    /// A policy signed by the owner for this topic. Owners use this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<AuthorizedTopicPolicyV1>,
    /// A board configuration signed by the owner, used by members who cannot
    /// sign a topic policy themselves. The topic derives its policy from it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_configuration: Option<AuthorizedConfigurationV1>,
}

impl TopicAuthorityV1 {
    pub fn effective_policy(&self) -> TopicPolicyV1 {
        if let Some(source) = &self.source_configuration {
            return policy_from_configuration(&source.configuration);
        }
        self.policy
            .as_ref()
            .map(|policy| policy.policy.clone())
            .unwrap_or_default()
    }

    pub fn policy(&self) -> TopicPolicyV1 {
        self.effective_policy()
    }

    /// Merge another authority snapshot without mutating either side. The
    /// client uses this to decide whether a propagated snapshot would change
    /// the topic before it sends an update.
    pub fn merged_with(&self, other: &TopicAuthorityV1) -> TopicAuthorityV1 {
        merge_authority(self, other)
    }
}

fn policy_from_configuration(configuration: &Configuration) -> TopicPolicyV1 {
    TopicPolicyV1 {
        read_only: configuration.read_only,
        approval_required: configuration.approval_required,
        rate_window_ms: configuration.rate_window_ms,
        max_posts_per_window: configuration.max_posts_per_window,
        images_allowed: true,
        auto_moderated_topics: configuration.auto_moderated_topics,
        reactions_enabled: configuration.reactions_enabled,
        max_post_size: configuration.max_message_size,
        generation: configuration.configuration_version as u64,
        updated_at: system_time_ms(configuration.updated_at),
    }
}

/// A participant proves board membership with an invite chain or a token join.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct ParticipantCertificateV1 {
    pub member: AuthorizedMember,
    /// Ancestors of `member`, excluding the owner.
    #[serde(default)]
    pub chain: Vec<AuthorizedMember>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<AuthorizedInviteToken>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub join_proof: Option<JoinProof>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct ParticipantRecordV1 {
    pub member_id: MemberId,
    pub member_vk: VerifyingKey,
    pub certificate: ParticipantCertificateV1,
    pub joined_at: i64,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct AuthorizedParticipantV1 {
    pub record: ParticipantRecordV1,
    pub signature: Signature,
}

impl AuthorizedParticipantV1 {
    pub fn new(record: ParticipantRecordV1, member_sk: &SigningKey) -> Self {
        Self {
            signature: sign_struct(&record, member_sk),
            record,
        }
    }

    pub fn hash(&self) -> [u8; 32] {
        value_hash(self)
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct TrustV1 {
    pub member_id: MemberId,
    pub trusted: bool,
    pub generation: u64,
    pub signed_by: MemberId,
    pub created_at: i64,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedTrustV1 {
    pub trust: TrustV1,
    pub signer_key: Option<VerifyingKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<Box<AuthorityProof>>,
    pub signature: Signature,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct TopicEditV1 {
    pub title: SealedBytes,
    pub body: SealedBytes,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct PostEditV1 {
    pub content: SealedBytes,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum TopicPostContentV1 {
    Text(String),
    Poll(PollContentV1),
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct TopicPostV1 {
    pub author: MemberId,
    /// `None` replies to the topic itself; otherwise the target post id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<MessageId>,
    pub content: SealedBytes,
    #[serde(default)]
    pub images: Vec<ImageRef>,
    pub created_at: i64,
    pub nonce: [u8; 16],
}

impl TopicPostV1 {
    pub fn id(&self) -> MessageId {
        MessageId::from_bytes(value_hash(self))
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct AuthorizedTopicPostV1 {
    pub post: TopicPostV1,
    pub signature: Signature,
}

impl AuthorizedTopicPostV1 {
    pub fn new(post: TopicPostV1, signing_key: &SigningKey) -> Self {
        Self {
            signature: sign_struct(&post, signing_key),
            post,
        }
    }

    pub fn id(&self) -> MessageId {
        self.post.id()
    }

    pub fn hash(&self) -> [u8; 32] {
        value_hash(self)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum TopicActionKind {
    Edit,
    Delete,
    Hide,
    Restore,
    Purge,
    Pin,
    Unpin,
    Close,
    Open,
    Announce,
    Unannounce,
    Move,
    Merge,
    Split,
    Approve,
    Reject,
    EditPoll,
    React,
    Unreact,
    Vote,
}

impl TopicActionKind {
    fn power(self) -> Option<ModerationPower> {
        match self {
            TopicActionKind::Edit => Some(ModerationPower::Edit),
            TopicActionKind::Delete
            | TopicActionKind::Hide
            | TopicActionKind::Restore
            | TopicActionKind::Approve
            | TopicActionKind::Reject => Some(ModerationPower::Delete),
            TopicActionKind::Pin
            | TopicActionKind::Unpin
            | TopicActionKind::Announce
            | TopicActionKind::Unannounce => Some(ModerationPower::Pin),
            TopicActionKind::Close | TopicActionKind::Open => {
                Some(ModerationPower::Close)
            }
            TopicActionKind::Move
            | TopicActionKind::Merge
            | TopicActionKind::Split => Some(ModerationPower::Move),
            TopicActionKind::Purge => None,
            TopicActionKind::EditPoll => Some(ModerationPower::Edit),
            TopicActionKind::React | TopicActionKind::Unreact | TopicActionKind::Vote => {
                None
            }
        }
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct TopicActionV1 {
    pub kind: TopicActionKind,
    pub target: MessageId,
    pub payload: SealedBytes,
    pub generation: u64,
    pub created_at: i64,
    pub signer: MemberId,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct AuthorizedTopicActionV1 {
    pub action: TopicActionV1,
    pub signer_key: Option<VerifyingKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<Box<AuthorityProof>>,
    pub signature: Signature,
}

impl AuthorizedTopicActionV1 {
    pub fn id(&self) -> [u8; 32] {
        value_hash(self)
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct TopicApprovalV1 {
    pub target: MessageId,
    pub approved: bool,
    pub generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<SectionId>,
    pub signed_by: MemberId,
    pub created_at: i64,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedTopicApprovalV1 {
    pub approval: TopicApprovalV1,
    pub signer_key: Option<VerifyingKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<Box<AuthorityProof>>,
    pub signature: Signature,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct TopicGenerationV1 {
    pub part: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_part: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_hash: Option<[u8; 32]>,
}

impl TopicGenerationV1 {
    pub fn new(part: u32) -> Self {
        Self {
            part,
            closed_at: None,
            next_part: None,
            previous_hash: None,
        }
    }
}

impl Default for TopicGenerationV1 {
    fn default() -> Self {
        Self::new(0)
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct TopicStateV1 {
    pub version: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<AuthorizedTopicHeaderV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section: Option<AuthorizedSectionSnapshotV1>,
    #[serde(default)]
    pub authority: TopicAuthorityV1,
    #[serde(default)]
    pub participants: Vec<AuthorizedParticipantV1>,
    #[serde(default)]
    pub trust: Vec<AuthorizedTrustV1>,
    #[serde(default)]
    pub posts: BTreeMap<MessageId, AuthorizedTopicPostV1>,
    #[serde(default)]
    pub actions: Vec<AuthorizedTopicActionV1>,
    #[serde(default)]
    pub approvals: Vec<AuthorizedTopicApprovalV1>,
    #[serde(default)]
    pub generation: TopicGenerationV1,
}

impl Default for TopicStateV1 {
    fn default() -> Self {
        Self {
            version: PROTOCOL_VERSION,
            header: None,
            section: None,
            authority: TopicAuthorityV1::default(),
            participants: Vec::new(),
            trust: Vec::new(),
            posts: BTreeMap::new(),
            actions: Vec::new(),
            approvals: Vec::new(),
            generation: TopicGenerationV1::default(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct TopicDeltaV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<AuthorizedTopicHeaderV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section: Option<AuthorizedSectionSnapshotV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<TopicAuthorityV1>,
    #[serde(default)]
    pub participants: Vec<AuthorizedParticipantV1>,
    #[serde(default)]
    pub trust: Vec<AuthorizedTrustV1>,
    #[serde(default)]
    pub posts: Vec<AuthorizedTopicPostV1>,
    #[serde(default)]
    pub actions: Vec<AuthorizedTopicActionV1>,
    #[serde(default)]
    pub approvals: Vec<AuthorizedTopicApprovalV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<TopicGenerationV1>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct TopicStateSummaryV1 {
    pub version: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_hash: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section_hash: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_hash: Option<[u8; 32]>,
    #[serde(default)]
    pub participants: BTreeMap<MemberId, [u8; 32]>,
    #[serde(default)]
    pub trust: BTreeMap<MemberId, u64>,
    #[serde(default)]
    pub posts: BTreeSet<MessageId>,
    #[serde(default)]
    pub actions: BTreeSet<[u8; 32]>,
    #[serde(default)]
    pub approvals: BTreeMap<MessageId, u64>,
    #[serde(default)]
    pub generation: TopicGenerationV1,
}

impl Default for TopicStateSummaryV1 {
    fn default() -> Self {
        Self {
            version: PROTOCOL_VERSION,
            header_hash: None,
            section_hash: None,
            authority_hash: None,
            participants: BTreeMap::new(),
            trust: BTreeMap::new(),
            posts: BTreeSet::new(),
            actions: BTreeSet::new(),
            approvals: BTreeMap::new(),
            generation: TopicGenerationV1::default(),
        }
    }
}

impl TopicStateV1 {
    pub fn verify(&self, params: &TopicParamsV1) -> Result<(), String> {
        params.verify()?;
        if self.version != PROTOCOL_VERSION {
            return Err(format!("unsupported topic state version {}", self.version));
        }
        if self.generation.part != params.part {
            return Err("topic generation does not match the parameters".to_string());
        }
        if self.generation.next_part.is_some() && self.generation.closed_at.is_none() {
            return Err("a continued topic must be closed".to_string());
        }
        if self.generation.next_part.is_some_and(|part| part != params.part + 1) {
            return Err("the next topic part is invalid".to_string());
        }
        if params.part == 0 && self.generation.previous_hash.is_some() {
            return Err("the first topic part cannot have a previous hash".to_string());
        }
        if params.part > 0 && self.generation.previous_hash.is_none() {
            return Err("a continued topic part needs the previous state hash".to_string());
        }

        let Some(header) = &self.header else {
            if self.section.is_some()
                || !self.participants.is_empty()
                || !self.trust.is_empty()
                || !self.posts.is_empty()
                || !self.actions.is_empty()
                || !self.approvals.is_empty()
            {
                return Err("a topic without a header cannot carry content".to_string());
            }
            return Ok(());
        };
        header.verify(params)?;
        if header.header.author != params.owner_id() {
            let author = self
                .participants
                .iter()
                .find(|p| p.record.member_id == header.header.author)
                .ok_or("the topic author is not a participant")?;
            if author.record.member_vk != header.header.author_key {
                return Err("the topic author key does not match the participant".to_string());
            }
        }

        if header.header.auto_moderated {
            let allowed = self
                .section
                .as_ref()
                .and_then(|section| section.snapshot.auto_moderated_topics)
                .unwrap_or(self.authority.policy().auto_moderated_topics);
            if !allowed {
                return Err("auto-moderated topics are disabled here".to_string());
            }
        }

        if self.participants.len() > MAX_PARTICIPANTS {
            return Err("too many participants".to_string());
        }
        if self.posts.len() > MAX_POSTS {
            return Err("too many posts".to_string());
        }
        if self.actions.len() > MAX_ACTIONS {
            return Err("too many actions".to_string());
        }
        if self.approvals.len() > MAX_APPROVALS {
            return Err("too many approvals".to_string());
        }
        if self.trust.len() > self.participants.len() {
            return Err("too many trust records".to_string());
        }

        let board_params = params.board_parameters();
        self.verify_participants(params, &board_params)?;
        let view = self.board_view(params);

        self.verify_authority(&view, &board_params)?;
        self.verify_section(&view, &board_params, params)?;
        self.verify_trust(&view, &board_params)?;
        self.verify_posts(&view, &board_params, params)?;
        self.verify_actions(&view, &board_params)?;
        self.verify_approvals(&view, &board_params)?;

        Ok(())
    }

    fn verify_participants(
        &self,
        params: &TopicParamsV1,
        board_params: &ChatBoardParametersV1,
    ) -> Result<(), String> {
        let mut ids = HashSet::new();
        let mut keys = HashSet::new();
        for participant in &self.participants {
            let record = &participant.record;
            if record.member_id != MemberId::from(&record.member_vk) {
                return Err("participant id does not match its key".to_string());
            }
            if record.certificate.member.member.id() != record.member_id {
                return Err("participant certificate is for another member".to_string());
            }
            if record.certificate.member.member.member_vk != record.member_vk {
                return Err("participant key does not match its certificate".to_string());
            }
            verify_struct(&record, &participant.signature, &record.member_vk)
                .map_err(|error| format!("invalid participant signature: {error}"))?;
            if !ids.insert(record.member_id) || !keys.insert(record.member_vk) {
                return Err("duplicate participant".to_string());
            }
            self.verify_certificate(&record.certificate, record.joined_at, params, board_params)?;
        }
        Ok(())
    }

    fn verify_certificate(
        &self,
        certificate: &ParticipantCertificateV1,
        joined_at: i64,
        params: &TopicParamsV1,
        board_params: &ChatBoardParametersV1,
    ) -> Result<(), String> {
        let owner_id = params.owner_id();
        let owner_key = self
            .authority
            .ownership
            .owner_key_at(board_params, system_time_from_ms(joined_at));
        let member = &certificate.member.member;
        if member.owner_member_id != owner_id {
            return Err("the member record belongs to another board".to_string());
        }

        if certificate.token.is_some() || certificate.join_proof.is_some() {
            let token = certificate
                .token
                .as_ref()
                .ok_or("a token join needs its token record")?;
            let proof = certificate
                .join_proof
                .as_ref()
                .ok_or("a token join needs its join proof")?;
            if member.invited_by != member.id() {
                return Err("a token-joined member must be self-signed".to_string());
            }
            certificate
                .member
                .verify_signature(&member.member_vk)
                .map_err(|error| format!("invalid token-joined member signature: {error}"))?;
            if token.token.deleted {
                return Err("the invite token is deleted".to_string());
            }
            if token.token.id != proof.token_id {
                return Err("the join proof names another token".to_string());
            }
            if let Some(not_after) = token.token.not_after {
                if system_time_ms(not_after) < joined_at {
                    return Err("the invite token had expired".to_string());
                }
            }
            self.authority
                .roles
                .role(&token.token.role_id)
                .ok_or("the invite token grants a role that no longer exists")?;
            proof
                .verify(
                    &token.token.verifying_key,
                    &join_message(&params.board_owner, &member.member_vk),
                )
                .map_err(|error| format!("invalid join proof: {error}"))?;

            let signer = token.signer.unwrap_or(owner_id);
            let manager_at = system_time_from_ms(token.token.created_at.map(system_time_ms).unwrap_or(joined_at));
            if signer == owner_id {
                let token_owner_key = self
                    .authority
                    .ownership
                    .owner_key_at(board_params, manager_at);
                token
                    .verify_signature(&token_owner_key)
                    .map_err(|error| format!("invalid invite token signature: {error}"))?;
            } else {
                let key = resolve_signer_key(
                    &self.board_view(params),
                    board_params,
                    &signer,
                    token.signer_key.as_ref(),
                )?;
                verify_struct(&token.token, &token.signature, &key)
                    .map_err(|error| format!("invalid invite token signature: {error}"))?;
            }
            self.verify_token_manager(&signer, token, board_params, params, manager_at)?;
            return Ok(());
        }

        // Invite chain up to the owner.
        let mut current = &certificate.member;
        let mut seen = HashSet::new();
        let current_owner = self
            .authority
            .ownership
            .owner_at(board_params, system_time_from_ms(joined_at));
        for _ in 0..MAX_JOIN_DEPTH {
            let current_member = &current.member;
            let inviter = current_member.invited_by;
            if inviter == owner_id {
                current
                    .verify_signature(&params.board_owner)
                    .map_err(|error| format!("invalid invite chain signature: {error}"))?;
                return Ok(());
            }
            if inviter == current_owner {
                current
                    .verify_signature(&owner_key)
                    .map_err(|error| format!("invalid invite chain signature: {error}"))?;
                return Ok(());
            }
            if !seen.insert(current_member.id()) {
                return Err("circular invite chain".to_string());
            }
            let parent = certificate
                .chain
                .iter()
                .find(|candidate| candidate.member.id() == inviter)
                .ok_or("the invite chain is incomplete")?;
            current
                .verify_signature(&parent.member.member_vk)
                .map_err(|error| format!("invalid invite chain signature: {error}"))?;
            current = parent;
        }
        Err("the invite chain is too deep".to_string())
    }

    fn verify_token_manager(
        &self,
        signer: &MemberId,
        token: &AuthorizedInviteToken,
        board_params: &ChatBoardParametersV1,
        params: &TopicParamsV1,
        at: SystemTime,
    ) -> Result<(), String> {
        let view = self.board_view(params);
        if *signer == self.authority.ownership.owner_at(board_params, at) {
            return Ok(());
        }
        if verify_owner_or_admin(&view, board_params, signer, token.authority.as_deref(), at)
            .is_ok()
        {
            return Ok(());
        }
        if view.roles.can_manage_access(signer) {
            return Ok(());
        }
        if let Some(proof) = token.authority.as_deref() {
            if let Some(grant) = proof.grant.as_ref() {
                if grant.role.role.can_manage_access
                    && !grant.role.role.deleted
                    && grant.assignment.assignment.member_id == *signer
                    && grant.assignment.assignment.role_id == grant.role.role.id
                    && !grant.assignment.assignment.revoked
                {
                    let role_signer = grant.role.signer_id(board_params);
                    let role_key = resolve_signer_key(
                        &view,
                        board_params,
                        &role_signer,
                        grant.role.signer_key.as_ref(),
                    )?;
                    grant.role.verify_signature_with(&role_key)?;
                    verify_owner_or_admin(
                        &view,
                        board_params,
                        &role_signer,
                        grant.role.authority.as_deref(),
                        grant.role.role.signed_at,
                    )?;
                    let assignment_signer = grant.assignment.signer_id(board_params);
                    let assignment_key = resolve_signer_key(
                        &view,
                        board_params,
                        &assignment_signer,
                        grant.assignment.signer_key.as_ref(),
                    )?;
                    verify_struct(
                        &grant.assignment.assignment,
                        &grant.assignment.signature,
                        &assignment_key,
                    )
                    .map_err(|error| format!("invalid role assignment signature: {error}"))?;
                    if verify_owner_or_admin(
                        &view,
                        board_params,
                        &assignment_signer,
                        grant.assignment.authority.as_deref(),
                        grant.assignment.assignment.signed_at,
                    )
                    .is_ok()
                        || view.roles.can_manage_access(&assignment_signer)
                    {
                        return Ok(());
                    }
                }
            }
        }
        Err("the invite token signer cannot manage access".to_string())
    }

    fn verify_authority(
        &self,
        view: &ChatBoardStateV1,
        board_params: &ChatBoardParametersV1,
    ) -> Result<(), String> {
        self.authority.ownership.verify(view, board_params)?;
        self.authority.admins.verify(view, board_params)?;
        self.authority.roles.verify(view, board_params)?;
        self.authority.bans.verify(view, board_params)?;
        self.authority
            .ban_revocations
            .verify(view, board_params)?;
        self.authority.suspensions.verify(view, board_params)?;
        let owner_id = view.ownership.current_owner(board_params);
        if let Some(source) = &self.authority.source_configuration {
            let at_ms = system_time_ms(source.configuration.updated_at);
            let owner_key = self
                .authority
                .ownership
                .owner_key_at(board_params, system_time_from_ms(at_ms));
            source
                .verify_signature(&owner_key)
                .map_err(|error| format!("invalid source configuration signature: {error}"))?;
        } else if let Some(policy) = &self.authority.policy {
            let at_ms = policy.policy.updated_at;
            let owner_key = self
                .authority
                .ownership
                .owner_key_at(board_params, system_time_from_ms(at_ms));
            policy.verify(&owner_key, owner_id)?;
        } else {
            return Err("the topic has no policy".to_string());
        }
        Ok(())
    }

    fn verify_section(
        &self,
        view: &ChatBoardStateV1,
        board_params: &ChatBoardParametersV1,
        params: &TopicParamsV1,
    ) -> Result<(), String> {
        let header = self.header.as_ref().ok_or("missing header")?;
        if let Some(action) = self.latest_action(header.header.id(), TopicActionKind::Move) {
            let SealedBytes::Public { value } = &action.action.payload else {
                return Err("a section move payload must be public".to_string());
            };
            let snapshot: SectionSnapshotV1 = ciborium::de::from_reader(value.as_slice())
                .map_err(|error| format!("decode section move: {error}"))?;
            if !snapshot.chain.contains(&snapshot.section) {
                return Err("section move chain does not include the section".to_string());
            }
            if snapshot.section == header.header.id() {
                return Err("a topic cannot be its own section".to_string());
            }
            // The Move action itself carries the moderator's authority proof
            // and is checked by verify_actions. The snapshot fields are covered
            // by the action signature.
            return Ok(());
        }
        match (&header.header.section, &self.section) {
            (None, None) => {}
            (Some(section), Some(snapshot)) => {
                if snapshot.snapshot.section != *section {
                    return Err("section snapshot does not match the header".to_string());
                }
                if !snapshot.snapshot.chain.contains(section) {
                    return Err("section snapshot chain does not include the section".to_string());
                }
                if snapshot.snapshot.section == header.header.id() {
                    return Err("a topic cannot be its own section".to_string());
                }
                let signer = snapshot.signer.unwrap_or(params.owner_id());
                let key = resolve_signer_key(
                    view,
                    board_params,
                    &signer,
                    snapshot.signer_key.as_ref(),
                )?;
                verify_struct(&snapshot.snapshot, &snapshot.signature, &key)
                    .map_err(|error| format!("invalid section snapshot signature: {error}"))?;
                verify_owner_or_admin(
                    view,
                    board_params,
                    &signer,
                    snapshot.authority.as_deref(),
                    system_time_from_ms(snapshot.snapshot.signed_at),
                )?;
            }
            _ => return Err("header and section snapshot disagree".to_string()),
        }
        Ok(())
    }

    fn verify_trust(
        &self,
        view: &ChatBoardStateV1,
        board_params: &ChatBoardParametersV1,
    ) -> Result<(), String> {
        let mut latest: BTreeMap<MemberId, u64> = BTreeMap::new();
        for entry in &self.trust {
            if !self
                .participants
                .iter()
                .any(|p| p.record.member_id == entry.trust.member_id)
            {
                return Err("trust targets a non-participant".to_string());
            }
            if entry.trust.generation == 0 {
                return Err("trust generation must be positive".to_string());
            }
            let signer = entry.trust.signed_by;
            let key = resolve_signer_key(view, board_params, &signer, entry.signer_key.as_ref())?;
            verify_struct(&entry.trust, &entry.signature, &key)
                .map_err(|error| format!("invalid trust signature: {error}"))?;
            let chain = self.section_chain();
            verify_moderation_authority(
                view,
                board_params,
                &signer,
                ModerationPower::Delete,
                &chain,
                entry.authority.as_deref(),
                system_time_from_ms(entry.trust.created_at),
            )?;
            let slot = latest.entry(entry.trust.member_id).or_insert(0);
            if entry.trust.generation > *slot {
                *slot = entry.trust.generation;
            }
        }
        Ok(())
    }

    fn verify_posts(
        &self,
        view: &ChatBoardStateV1,
        board_params: &ChatBoardParametersV1,
        params: &TopicParamsV1,
    ) -> Result<(), String> {
        let policy = self.authority.policy();
        let owner_id = params.owner_id();
        for (id, entry) in &self.posts {
            let post = &entry.post;
            if post.id() != *id {
                return Err("post id does not match its content".to_string());
            }
            if post.content.declared_len() > policy.max_post_size
                || post.content.declared_len() > MAX_POST_BYTES
            {
                return Err("post content is too large".to_string());
            }
            if post.images.len() > MAX_IMAGES_PER_POST {
                return Err("too many images in a post".to_string());
            }
            if !post.images.is_empty()
                && !policy.images_allowed
            {
                return Err("images are disabled by the topic policy".to_string());
            }
            if !post.images.is_empty()
                && !self.section_images_allowed()
            {
                return Err("images are disabled in this section".to_string());
            }
            if let Some(parent) = post.parent {
                if !self.posts.contains_key(&parent) {
                    return Err("post parent does not exist".to_string());
                }
            }
            if post_cycle(&self.posts, *id) {
                return Err("circular reply chain".to_string());
            }

            let author_key = self.author_key(post.author, view, board_params, post.created_at, params)?;
            verify_struct(post, &entry.signature, &author_key)
                .map_err(|error| format!("invalid post signature: {error}"))?;

            if post.author == owner_id {
                continue;
            }
            if self.is_banned(post.author, post.created_at) {
                return Err("a banned member cannot post".to_string());
            }
            if self.is_suspended(post.author, post.created_at) {
                return Err("a suspended member cannot post".to_string());
            }
            if policy.read_only
                && !view.admin.admins.iter().any(|admin| admin.admin.id() == post.author)
            {
                return Err("the topic is read-only".to_string());
            }
            if !self.section_allows(post.author, view, board_params, params) {
                return Err("the author cannot write in this section".to_string());
            }
        }
        Ok(())
    }

    fn verify_actions(
        &self,
        view: &ChatBoardStateV1,
        board_params: &ChatBoardParametersV1,
    ) -> Result<(), String> {
        let header = self.header.as_ref().ok_or("missing header")?;
        for entry in &self.actions {
            let action = &entry.action;
            if action.payload.declared_len() > MAX_BODY_BYTES {
                return Err("action payload is too large".to_string());
            }
            let target_author = if action.target == header.header.id() {
                Some(header.header.author)
            } else {
                self.posts.get(&action.target).map(|post| post.post.author)
            };
            let target_author = target_author.ok_or("action target does not exist")?;

            let signer = action.signer;
            let key = resolve_signer_key(view, board_params, &signer, entry.signer_key.as_ref())?;
            verify_struct(action, &entry.signature, &key)
                .map_err(|error| format!("invalid action signature: {error}"))?;

            if matches!(
                action.kind,
                TopicActionKind::React | TopicActionKind::Unreact | TopicActionKind::Vote
            ) {
                let is_member = signer == board_params.owner_id()
                    || self
                        .participants
                        .iter()
                        .any(|participant| participant.record.member_id == signer);
                if !is_member {
                    return Err("only a board member can react or vote".to_string());
                }
                if self.is_banned(signer, action.created_at)
                    || self.is_suspended(signer, action.created_at)
                {
                    return Err(
                        "a banned or suspended member cannot react or vote".to_string()
                    );
                }
                continue;
            }

            if signer == target_author
                && matches!(
                    action.kind,
                    TopicActionKind::Edit | TopicActionKind::Delete | TopicActionKind::EditPoll
                )
            {
                continue;
            }

            let at = system_time_from_ms(action.created_at);
            if action.kind == TopicActionKind::Purge {
                verify_owner_or_admin(
                    view,
                    board_params,
                    &signer,
                    entry.authority.as_deref(),
                    at,
                )?;
                continue;
            }
            let power = action
                .kind
                .power()
                .ok_or("the action has no moderation power")?;
            let chain = self.section_chain();
            verify_moderation_authority(
                view,
                board_params,
                &signer,
                power,
                &chain,
                entry.authority.as_deref(),
                at,
            )?;
        }
        Ok(())
    }

    fn verify_approvals(
        &self,
        view: &ChatBoardStateV1,
        board_params: &ChatBoardParametersV1,
    ) -> Result<(), String> {
        let header = self.header.as_ref().ok_or("missing header")?;
        for entry in &self.approvals {
            let approval = &entry.approval;
            if approval.target != header.header.id()
                && !self.posts.contains_key(&approval.target)
            {
                return Err("approval targets a missing post".to_string());
            }
            if approval.generation == 0 {
                return Err("approval generation must be positive".to_string());
            }
            if let Some(scope) = approval.scope {
                if !self.section_chain().contains(&scope) {
                    return Err("approval scope is not the topic section".to_string());
                }
            }
            let signer = approval.signed_by;
            let key = resolve_signer_key(view, board_params, &signer, entry.signer_key.as_ref())?;
            verify_struct(approval, &entry.signature, &key)
                .map_err(|error| format!("invalid approval signature: {error}"))?;
            let chain = self.section_chain();
            verify_moderation_authority(
                view,
                board_params,
                &signer,
                ModerationPower::Delete,
                &chain,
                entry.authority.as_deref(),
                system_time_from_ms(approval.created_at),
            )?;
        }
        Ok(())
    }

    pub fn apply_delta(
        &mut self,
        params: &TopicParamsV1,
        delta: &TopicDeltaV1,
    ) -> Result<(), String> {
        if let Some(header) = &delta.header {
            header.verify(params)?;
            match &self.header {
                None => self.header = Some(header.clone()),
                Some(existing) if existing == header => {}
                Some(_) => return Err("topic header is immutable".to_string()),
            }
        }
        if self.generation.closed_at.is_some() && !delta.posts.is_empty() {
            return Err("the topic is closed to new posts".to_string());
        }
        if let Some(section) = &delta.section {
            match &self.section {
                None => self.section = Some(section.clone()),
                Some(existing) if existing == section => {}
                Some(_) => return Err("topic section is immutable".to_string()),
            }
        }
        if let Some(authority) = &delta.authority {
            self.authority = merge_authority(&self.authority, authority);
        }
        for participant in &delta.participants {
            merge_participant(&mut self.participants, participant);
        }
        for trust in &delta.trust {
            merge_trust(&mut self.trust, trust);
        }
        for post in &delta.posts {
            self.posts.entry(post.id()).or_insert_with(|| post.clone());
        }
        for action in &delta.actions {
            let id = action.id();
            if !self.actions.iter().any(|existing| existing.id() == id) {
                self.actions.push(action.clone());
            }
        }
        for approval in &delta.approvals {
            merge_approval(&mut self.approvals, approval);
        }
        if let Some(generation) = &delta.generation {
            self.generation = merge_generation(&self.generation, generation);
        }

        if !delta.posts.is_empty() {
            self.check_rate_limit(&delta.posts)?;
        }
        self.verify(params)
    }

    pub fn merge(&mut self, params: &TopicParamsV1, other: &TopicStateV1) -> Result<(), String> {
        if let Some(header) = &other.header {
            match &self.header {
                None => self.header = Some(header.clone()),
                Some(existing) if existing == header => {}
                Some(_) => return Err("cannot merge two different topic headers".to_string()),
            }
        }
        if let Some(section) = &other.section {
            match &self.section {
                None => self.section = Some(section.clone()),
                Some(existing) if existing == section => {}
                Some(_) => return Err("cannot merge two different topic sections".to_string()),
            }
        }
        self.authority = merge_authority(&self.authority, &other.authority);
        for participant in &other.participants {
            merge_participant(&mut self.participants, participant);
        }
        for trust in &other.trust {
            merge_trust(&mut self.trust, trust);
        }
        for (id, post) in &other.posts {
            self.posts.entry(*id).or_insert_with(|| post.clone());
        }
        for action in &other.actions {
            let id = action.id();
            if !self.actions.iter().any(|existing| existing.id() == id) {
                self.actions.push(action.clone());
            }
        }
        for approval in &other.approvals {
            merge_approval(&mut self.approvals, approval);
        }
        self.generation = merge_generation(&self.generation, &other.generation);
        self.normalize();
        self.verify(params)
    }

    fn normalize(&mut self) {
        self.participants
            .sort_by_key(|p| (p.record.member_id.0 .0, *p.record.member_vk.as_bytes()));
        self.participants.dedup_by_key(|p| p.record.member_id);
        self.trust.sort_by_key(|t| {
            (
                t.trust.member_id.0 .0,
                t.trust.generation,
                t.trust.signed_by.0 .0,
            )
        });
        self.actions.sort_by_key(|a| {
            (
                a.action.target.0 .0,
                a.action.kind,
                a.action.generation,
                a.action.signer.0 .0,
            )
        });
        self.approvals.sort_by_key(|a| {
            (
                a.approval.target.0 .0,
                a.approval.generation,
                a.approval.signed_by.0 .0,
            )
        });
    }

    fn check_rate_limit(&self, incoming: &[AuthorizedTopicPostV1]) -> Result<(), String> {
        let policy = self.authority.policy();
        if policy.max_posts_per_window == 0 || policy.rate_window_ms == 0 {
            return Ok(());
        }
        let window = policy.rate_window_ms as i64;
        let limit = policy.max_posts_per_window as usize;
        for post in incoming {
            let author = post.post.author;
            let at = post.post.created_at;
            let mut count = 0usize;
            for existing in self.posts.values() {
                if existing.post.author == author
                    && existing.post.created_at <= at
                    && existing.post.created_at >= at - window
                {
                    count += 1;
                }
            }
            if count > limit {
                return Err("the author exceeded the topic rate limit".to_string());
            }
        }
        Ok(())
    }

    pub fn summarize(&self) -> TopicStateSummaryV1 {
        let mut participants = BTreeMap::new();
        for participant in &self.participants {
            participants.insert(participant.record.member_id, participant.hash());
        }
        let mut trust = BTreeMap::new();
        for entry in &self.trust {
            let slot = trust.entry(entry.trust.member_id).or_insert(0);
            if entry.trust.generation > *slot {
                *slot = entry.trust.generation;
            }
        }
        let mut approvals = BTreeMap::new();
        for entry in &self.approvals {
            let slot = approvals.entry(entry.approval.target).or_insert(0);
            if entry.approval.generation > *slot {
                *slot = entry.approval.generation;
            }
        }
        TopicStateSummaryV1 {
            version: self.version,
            header_hash: self.header.as_ref().map(AuthorizedTopicHeaderV1::hash),
            section_hash: self.section.as_ref().map(AuthorizedSectionSnapshotV1::hash),
            authority_hash: self.header.as_ref().map(|_| value_hash(&self.authority)),
            participants,
            trust,
            posts: self.posts.keys().copied().collect(),
            actions: self.actions.iter().map(AuthorizedTopicActionV1::id).collect(),
            approvals,
            generation: self.generation.clone(),
        }
    }

    pub fn delta(&self, summary: &TopicStateSummaryV1) -> Option<TopicDeltaV1> {
        let mut delta = TopicDeltaV1::default();
        let header_hash = self.header.as_ref().map(AuthorizedTopicHeaderV1::hash);
        if summary.header_hash != header_hash {
            delta.header = self.header.clone();
        }
        let section_hash = self.section.as_ref().map(AuthorizedSectionSnapshotV1::hash);
        if summary.section_hash != section_hash {
            delta.section = self.section.clone();
        }
        if self.header.is_some() && summary.authority_hash != Some(value_hash(&self.authority)) {
            delta.authority = Some(self.authority.clone());
        }
        for participant in &self.participants {
            if summary
                .participants
                .get(&participant.record.member_id)
                != Some(&participant.hash())
            {
                delta.participants.push(participant.clone());
            }
        }
        for entry in &self.trust {
            let known = summary.trust.get(&entry.trust.member_id).copied().unwrap_or(0);
            if entry.trust.generation > known {
                delta.trust.push(entry.clone());
            }
        }
        for (id, post) in &self.posts {
            if !summary.posts.contains(id) {
                delta.posts.push(post.clone());
            }
        }
        for action in &self.actions {
            if !summary.actions.contains(&action.id()) {
                delta.actions.push(action.clone());
            }
        }
        for entry in &self.approvals {
            let known = summary
                .approvals
                .get(&entry.approval.target)
                .copied()
                .unwrap_or(0);
            if entry.approval.generation > known {
                delta.approvals.push(entry.clone());
            }
        }
        if summary.generation != self.generation {
            delta.generation = Some(self.generation.clone());
        }
        if delta.header.is_none()
            && delta.section.is_none()
            && delta.authority.is_none()
            && delta.participants.is_empty()
            && delta.trust.is_empty()
            && delta.posts.is_empty()
            && delta.actions.is_empty()
            && delta.approvals.is_empty()
            && delta.generation.is_none()
        {
            None
        } else {
            Some(delta)
        }
    }

    pub fn board_view(&self, params: &TopicParamsV1) -> ChatBoardStateV1 {
        let mut configuration = Configuration::default();
        configuration.max_admins = 1_000_000;
        configuration.max_user_bans = 1_000_000;
        configuration.max_message_size = MAX_POST_BYTES;
        configuration.owner_member_id = params.owner_id();
        let dummy = SigningKey::from_bytes(&[0u8; 32]);
        let mut view = ChatBoardStateV1 {
            configuration: AuthorizedConfigurationV1::new(configuration, &dummy),
            ownership: self.authority.ownership.clone(),
            admin: self.authority.admins.clone(),
            roles: self.authority.roles.clone(),
            bans: self.authority.bans.clone(),
            ban_revocations: self.authority.ban_revocations.clone(),
            suspensions: self.authority.suspensions.clone(),
            ..Default::default()
        };
        view.members = MembersV1 {
            members: self
                .participants
                .iter()
                .map(|p| p.record.certificate.member.clone())
                .collect(),
        };
        let _ = params;
        view
    }

    fn author_key(
        &self,
        author: MemberId,
        view: &ChatBoardStateV1,
        board_params: &ChatBoardParametersV1,
        at: i64,
        params: &TopicParamsV1,
    ) -> Result<VerifyingKey, String> {
        if author == params.owner_id() {
            return Ok(self
                .authority
                .ownership
                .owner_key_at(board_params, system_time_from_ms(at)));
        }
        if let Some(participant) = self
            .participants
            .iter()
            .find(|p| p.record.member_id == author)
        {
            return Ok(participant.record.member_vk);
        }
        // An admin or a role holder may act without being a participant, but
        // posts are attributed to members; resolve the key from the view.
        resolve_signer_key(view, board_params, &author, None)
    }

    fn section_chain(&self) -> Vec<MessageId> {
        self.effective_section()
            .map(|section| section.chain)
            .unwrap_or_default()
    }

    fn section_images_allowed(&self) -> bool {
        self.effective_section()
            .map(|section| section.images_allowed)
            .unwrap_or(true)
    }

    fn section_allows(
        &self,
        author: MemberId,
        view: &ChatBoardStateV1,
        board_params: &ChatBoardParametersV1,
        params: &TopicParamsV1,
    ) -> bool {
        let Some(section) = self.effective_section() else {
            return true;
        };
        if section.allowed_roles.is_empty() {
            return true;
        }
        let owner = self.authority.ownership.current_owner(board_params);
        if author == owner
            || author == params.owner_id()
            || view.admin.admins.iter().any(|a| a.admin.id() == author)
        {
            return true;
        }
        view.roles
            .active_roles_of(&author)
            .iter()
            .any(|role| section.allowed_roles.contains(&role.id))
    }

    fn is_banned(&self, member: MemberId, at_ms: i64) -> bool {
        self.authority.bans.0.iter().any(|ban| {
            if ban.ban.banned_user != member {
                return false;
            }
            let banned_at = system_time_ms(ban.ban.banned_at);
            let expired = ban
                .ban
                .expires_at
                .map(|expires| system_time_ms(expires) <= at_ms)
                .unwrap_or(false);
            banned_at <= at_ms
                && !expired
                && !self.authority.ban_revocations.revoked(&ban.id())
        })
    }

    fn is_suspended(&self, member: MemberId, at_ms: i64) -> bool {
        self.authority
            .suspensions
            .suspensions
            .iter()
            .filter(|entry| {
                entry.suspension.target == member && entry.suspension.created_at <= at_ms
            })
            .max_by_key(|entry| entry.suspension.generation)
            .map(|entry| entry.suspension.until > at_ms)
            .unwrap_or(false)
    }

    pub fn is_banned_member(&self, member: MemberId, at_ms: i64) -> bool {
        self.is_banned(member, at_ms)
    }

    pub fn is_suspended_member(&self, member: MemberId, at_ms: i64) -> bool {
        self.is_suspended(member, at_ms)
    }

    pub fn is_trusted(&self, member: MemberId) -> bool {
        self.trust
            .iter()
            .filter(|entry| entry.trust.member_id == member)
            .max_by_key(|entry| entry.trust.generation)
            .map(|entry| entry.trust.trusted)
            .unwrap_or(false)
    }

    /// Section after an owner/moderator move, or the creation snapshot.
    pub fn effective_section(&self) -> Option<SectionSnapshotV1> {
        if let Some(header) = &self.header {
            if let Some(action) = self.latest_action(header.header.id(), TopicActionKind::Move) {
                if let SealedBytes::Public { value } = &action.action.payload {
                    if let Ok(snapshot) =
                        ciborium::de::from_reader::<SectionSnapshotV1, _>(value.as_slice())
                    {
                        return Some(snapshot);
                    }
                }
            }
        }
        self.section
            .as_ref()
            .map(|section| section.snapshot.clone())
    }

    pub fn merged_into(&self) -> Option<MessageId> {
        let header = self.header.as_ref()?;
        let action = self.latest_action(header.header.id(), TopicActionKind::Merge)?;
        let SealedBytes::Public { value } = &action.action.payload else {
            return None;
        };
        let bytes: [u8; 32] = value.as_slice().try_into().ok()?;
        Some(MessageId::from_bytes(bytes))
    }

    pub fn is_split(&self, post_id: MessageId) -> bool {
        self.latest_action(post_id, TopicActionKind::Split).is_some()
    }

    pub fn split_target(&self, post_id: MessageId) -> Option<MessageId> {
        let action = self.latest_action(post_id, TopicActionKind::Split)?;
        let SealedBytes::Public { value } = &action.action.payload else {
            return None;
        };
        let bytes: [u8; 32] = value.as_slice().try_into().ok()?;
        Some(MessageId::from_bytes(bytes))
    }

    pub fn latest_action(
        &self,
        target: MessageId,
        kind: TopicActionKind,
    ) -> Option<&AuthorizedTopicActionV1> {
        self.actions
            .iter()
            .filter(|entry| entry.action.target == target && entry.action.kind == kind)
            .max_by(|a, b| {
                a.action
                    .generation
                    .cmp(&b.action.generation)
                    .then_with(|| b.id().cmp(&a.id()))
            })
    }

    fn flag_state(
        &self,
        kind_on: TopicActionKind,
        kind_off: TopicActionKind,
    ) -> bool {
        let target = self.header.as_ref().map(|h| h.header.id());
        let Some(target) = target else {
            return false;
        };
        let on = self
            .latest_action(target, kind_on)
            .map(|entry| (entry.action.generation, entry.id()));
        let off = self
            .latest_action(target, kind_off)
            .map(|entry| (entry.action.generation, entry.id()));
        match (on, off) {
            (Some(on), Some(off)) => on > off,
            (Some(_), None) => true,
            _ => false,
        }
    }

    pub fn is_pinned(&self) -> bool {
        self.flag_state(TopicActionKind::Pin, TopicActionKind::Unpin)
    }

    pub fn is_closed(&self) -> bool {
        self.flag_state(TopicActionKind::Close, TopicActionKind::Open)
    }

    pub fn is_announced(&self) -> bool {
        self.flag_state(TopicActionKind::Announce, TopicActionKind::Unannounce)
    }

    pub fn is_hidden(&self) -> bool {
        let Some(header) = &self.header else {
            return false;
        };
        let target = header.header.id();
        let hide = self.latest_action(target, TopicActionKind::Hide);
        let restore = self.latest_action(target, TopicActionKind::Restore);
        match (hide, restore) {
            (Some(hide), Some(restore)) => {
                (hide.action.generation, hide.id()) > (restore.action.generation, restore.id())
            }
            (Some(_), None) => true,
            _ => false,
        }
    }

    pub fn is_deleted(&self, target: MessageId) -> bool {
        let delete = self
            .actions
            .iter()
            .filter(|entry| {
                entry.action.target == target
                    && matches!(
                        entry.action.kind,
                        TopicActionKind::Delete | TopicActionKind::Purge
                    )
            })
            .max_by(|a, b| {
                a.action
                    .generation
                    .cmp(&b.action.generation)
                    .then_with(|| b.id().cmp(&a.id()))
            });
        let restore = self.latest_action(target, TopicActionKind::Restore);
        match (delete, restore) {
            (Some(delete), Some(restore)) => {
                (delete.action.generation, delete.id())
                    > (restore.action.generation, restore.id())
            }
            (Some(_), None) => true,
            _ => false,
        }
    }

    pub fn approval_for(&self, target: MessageId) -> Option<&AuthorizedTopicApprovalV1> {
        self.approvals
            .iter()
            .filter(|entry| entry.approval.target == target)
            .max_by(|a, b| {
                a.approval
                    .generation
                    .cmp(&b.approval.generation)
                    .then_with(|| value_hash(a).cmp(&value_hash(b)))
            })
    }

    pub fn post_is_visible(&self, post: &AuthorizedTopicPostV1) -> bool {
        let author = post.post.author;
        !self.is_deleted(post.id())
            && (self.is_trusted(author)
                || !self.authority.policy().approval_required
                || self
                    .approval_for(post.id())
                    .map(|entry| entry.approval.approved)
                    .unwrap_or(false)
                || author == self.header.as_ref().map(|h| h.header.author).unwrap_or(author))
    }
}

fn post_cycle(posts: &BTreeMap<MessageId, AuthorizedTopicPostV1>, start: MessageId) -> bool {
    let mut seen = HashSet::new();
    let mut current = Some(start);
    for _ in 0..MAX_POSTS {
        let Some(id) = current else {
            return false;
        };
        if !seen.insert(id) {
            return true;
        }
        current = posts.get(&id).and_then(|post| post.post.parent);
    }
    true
}

fn verify_owner_or_admin(
    view: &ChatBoardStateV1,
    board_params: &ChatBoardParametersV1,
    signer: &MemberId,
    proof: Option<&AuthorityProof>,
    at: SystemTime,
) -> Result<(), String> {
    if *signer == view.ownership.owner_at(board_params, at) {
        return Ok(());
    }
    let at_ms = system_time_ms(at);
    if view
        .admin
        .admins
        .iter()
        .any(|admin| {
            admin.admin.id() == *signer && system_time_ms(admin.admin.signed_at) <= at_ms
        })
        && !view.admin.revoked.iter().any(|revocation| {
            revocation.id() == *signer && system_time_ms(revocation.revocation.signed_at) <= at_ms
        })
    {
        return Ok(());
    }
    if let Some(proof) = proof {
        if let Some(admin) = &proof.admin {
            let owner_key = view
                .ownership
                .owner_key_at(board_params, admin.admin.signed_at);
            admin.verify_signature(&owner_key)?;
            if admin.admin.id() == *signer
                && !view
                    .admin
                    .revoked
                    .iter()
                    .any(|revocation| revocation.id() == *signer)
            {
                return Ok(());
            }
        }
    }
    Err("signer is not the owner or an admin".to_string())
}

fn merge_authority(left: &TopicAuthorityV1, right: &TopicAuthorityV1) -> TopicAuthorityV1 {
    let ownership = merge_ownership(&left.ownership, &right.ownership);
    let policy = merge_policy(&left.policy, &right.policy);
    let source_configuration =
        merge_source_configuration(&left.source_configuration, &right.source_configuration);
    TopicAuthorityV1 {
        ownership,
        admins: merge_admins(&left.admins, &right.admins),
        roles: merge_roles(&left.roles, &right.roles),
        bans: merge_bans(&left.bans, &right.bans),
        ban_revocations: merge_revocations(
            &left.ban_revocations,
            &right.ban_revocations,
        ),
        suspensions: merge_suspensions(&left.suspensions, &right.suspensions),
        policy,
        source_configuration,
    }
}

fn merge_policy(
    left: &Option<AuthorizedTopicPolicyV1>,
    right: &Option<AuthorizedTopicPolicyV1>,
) -> Option<AuthorizedTopicPolicyV1> {
    match (left, right) {
        (None, other) | (other, None) => other.clone(),
        (Some(left), Some(right)) => {
            if right.policy.generation > left.policy.generation
                || (right.policy.generation == left.policy.generation
                    && value_hash(&right.signature) < value_hash(&left.signature))
            {
                Some(right.clone())
            } else {
                Some(left.clone())
            }
        }
    }
}

fn merge_source_configuration(
    left: &Option<AuthorizedConfigurationV1>,
    right: &Option<AuthorizedConfigurationV1>,
) -> Option<AuthorizedConfigurationV1> {
    match (left, right) {
        (None, other) | (other, None) => other.clone(),
        (Some(left), Some(right)) => {
            if right.configuration.configuration_version
                > left.configuration.configuration_version
                || (right.configuration.configuration_version
                    == left.configuration.configuration_version
                    && value_hash(&right.signature) < value_hash(&left.signature))
            {
                Some(right.clone())
            } else {
                Some(left.clone())
            }
        }
    }
}

fn merge_ownership(left: &OwnershipV1, right: &OwnershipV1) -> OwnershipV1 {
    let mut transfers: BTreeMap<u64, _> = BTreeMap::new();
    for entry in left.transfers.iter().chain(right.transfers.iter()) {
        let generation = entry.transfer.generation;
        match transfers.get(&generation) {
            Some(existing) if value_hash(existing) <= value_hash(entry) => {}
            _ => {
                transfers.insert(generation, entry.clone());
            }
        }
    }
    let mut deactivations: BTreeMap<(MemberId, u64), _> = BTreeMap::new();
    for entry in left.deactivations.iter().chain(right.deactivations.iter()) {
        let key = (entry.deactivation.member, entry.deactivation.generation);
        deactivations.entry(key).or_insert_with(|| entry.clone());
    }
    OwnershipV1 {
        transfers: transfers.into_values().collect(),
        deactivations: deactivations.into_values().collect(),
    }
}

fn merge_admins(left: &AdminsV1, right: &AdminsV1) -> AdminsV1 {
    let mut grants: BTreeMap<MemberId, AuthorizedAdmin> = left
        .admins
        .iter()
        .map(|admin| (admin.admin.id(), admin.clone()))
        .collect();
    for admin in &right.admins {
        let id = admin.admin.id();
        match grants.get(&id) {
            Some(existing) if existing.admin.generation > admin.admin.generation => {}
            Some(existing)
                if existing.admin.generation == admin.admin.generation
                    && value_hash(&existing.signature) <= value_hash(&admin.signature) => {}
            _ => {
                grants.insert(id, admin.clone());
            }
        }
    }
    let mut revocations: BTreeMap<MemberId, _> = left
        .revoked
        .iter()
        .map(|entry| (entry.id(), entry.clone()))
        .collect();
    for revocation in &right.revoked {
        let id = revocation.id();
        match revocations.get(&id) {
            Some(existing)
                if existing.revocation.generation > revocation.revocation.generation => {}
            Some(existing)
                if existing.revocation.generation == revocation.revocation.generation
                    && value_hash(&existing.signature)
                        <= value_hash(&revocation.signature) => {}
            _ => {
                revocations.insert(id, revocation.clone());
            }
        }
    }
    let mut admins = AdminsV1::default();
    for (id, grant) in grants {
        match revocations.get(&id) {
            Some(revocation)
                if revocation.revocation.generation >= grant.admin.generation =>
            {
                admins.revoked.push(revocation.clone());
            }
            _ => admins.admins.push(grant),
        }
    }
    for (id, revocation) in revocations {
        if !admins.revoked.iter().any(|entry| entry.id() == id)
            && !admins.admins.iter().any(|entry| entry.admin.id() == id)
        {
            admins.revoked.push(revocation);
        }
    }
    admins.admins.sort_by_key(|entry| entry.admin.id());
    admins.revoked.sort_by_key(|entry| entry.id());
    admins
}

fn merge_roles(left: &RolesV1, right: &RolesV1) -> RolesV1 {
    let mut roles: BTreeMap<RoleId, AuthorizedRole> = BTreeMap::new();
    for role in left.roles.iter().chain(right.roles.iter()) {
        let id = role.role.id;
        match roles.get(&id) {
            Some(existing) if existing.role.generation > role.role.generation => {}
            Some(existing)
                if existing.role.generation == role.role.generation
                    && existing.role.deleted == role.role.deleted
                    && value_hash(&existing.signature) <= value_hash(&role.signature) => {}
            Some(existing)
                if existing.role.generation == role.role.generation
                    && existing.role.deleted
                    && !role.role.deleted => {}
            _ => {
                roles.insert(id, role.clone());
            }
        }
    }
    let mut assignments: BTreeMap<(RoleId, MemberId), AuthorizedRoleAssignment> =
        BTreeMap::new();
    for assignment in left.assignments.iter().chain(right.assignments.iter()) {
        let key = (
            assignment.assignment.role_id,
            assignment.assignment.member_id,
        );
        match assignments.get(&key) {
            Some(existing)
                if existing.assignment.generation > assignment.assignment.generation => {}
            Some(existing)
                if existing.assignment.generation == assignment.assignment.generation
                    && existing.assignment.revoked
                    && !assignment.assignment.revoked => {}
            Some(existing)
                if existing.assignment.generation == assignment.assignment.generation
                    && existing.assignment.revoked == assignment.assignment.revoked
                    && value_hash(&existing.signature) <= value_hash(&assignment.signature) => {}
            _ => {
                assignments.insert(key, assignment.clone());
            }
        }
    }
    RolesV1 {
        roles: roles.into_values().collect(),
        assignments: assignments.into_values().collect(),
    }
}

fn merge_bans(left: &BansV1, right: &BansV1) -> BansV1 {
    let mut bans: BTreeMap<_, _> = left
        .0
        .iter()
        .map(|ban| (ban.id(), ban.clone()))
        .collect();
    for ban in &right.0 {
        bans.entry(ban.id()).or_insert_with(|| ban.clone());
    }
    BansV1(bans.into_values().collect())
}

fn merge_revocations(
    left: &BanRevocationsV1,
    right: &BanRevocationsV1,
) -> BanRevocationsV1 {
    let mut revocations: BTreeMap<_, _> = left
        .revocations
        .iter()
        .map(|entry| (entry.revocation.ban_id.clone(), entry.clone()))
        .collect();
    for entry in &right.revocations {
        revocations
            .entry(entry.revocation.ban_id.clone())
            .or_insert_with(|| entry.clone());
    }
    BanRevocationsV1 {
        revocations: revocations.into_values().collect(),
    }
}

fn merge_suspensions(
    left: &SuspensionsV1,
    right: &SuspensionsV1,
) -> SuspensionsV1 {
    let mut suspensions: BTreeMap<MemberId, AuthorizedSuspension> = BTreeMap::new();
    for entry in left.suspensions.iter().chain(right.suspensions.iter()) {
        let target = entry.suspension.target;
        match suspensions.get(&target) {
            Some(existing)
                if existing.suspension.generation > entry.suspension.generation => {}
            Some(existing)
                if existing.suspension.generation == entry.suspension.generation
                    && value_hash(&existing.signature) <= value_hash(&entry.signature) => {}
            _ => {
                suspensions.insert(target, entry.clone());
            }
        }
    }
    SuspensionsV1 {
        suspensions: suspensions.into_values().collect(),
    }
}

fn merge_participant(
    participants: &mut Vec<AuthorizedParticipantV1>,
    incoming: &AuthorizedParticipantV1,
) {
    if let Some(existing) = participants
        .iter_mut()
        .find(|entry| entry.record.member_id == incoming.record.member_id)
    {
        if incoming.record.joined_at < existing.record.joined_at {
            *existing = incoming.clone();
        } else if incoming.record.joined_at == existing.record.joined_at
            && value_hash(incoming) < value_hash(existing)
        {
            *existing = incoming.clone();
        }
    } else {
        participants.push(incoming.clone());
    }
}

fn merge_trust(trust: &mut Vec<AuthorizedTrustV1>, incoming: &AuthorizedTrustV1) {
    if let Some(existing) = trust
        .iter_mut()
        .find(|entry| entry.trust.member_id == incoming.trust.member_id)
    {
        let replace = incoming.trust.generation > existing.trust.generation
            || (incoming.trust.generation == existing.trust.generation
                && !incoming.trust.trusted
                && existing.trust.trusted)
            || (incoming.trust.generation == existing.trust.generation
                && incoming.trust.trusted == existing.trust.trusted
                && value_hash(incoming) < value_hash(existing));
        if replace {
            *existing = incoming.clone();
        }
    } else {
        trust.push(incoming.clone());
    }
}

fn merge_approval(
    approvals: &mut Vec<AuthorizedTopicApprovalV1>,
    incoming: &AuthorizedTopicApprovalV1,
) {
    if let Some(existing) = approvals
        .iter_mut()
        .find(|entry| entry.approval.target == incoming.approval.target)
    {
        let replace = incoming.approval.generation > existing.approval.generation
            || (incoming.approval.generation == existing.approval.generation
                && !incoming.approval.approved
                && existing.approval.approved)
            || (incoming.approval.generation == existing.approval.generation
                && incoming.approval.approved == existing.approval.approved
                && value_hash(incoming) < value_hash(existing));
        if replace {
            *existing = incoming.clone();
        }
    } else {
        approvals.push(incoming.clone());
    }
}

fn merge_generation(
    left: &TopicGenerationV1,
    right: &TopicGenerationV1,
) -> TopicGenerationV1 {
    if right.part > left.part || right.next_part.unwrap_or(0) > left.next_part.unwrap_or(0) {
        right.clone()
    } else {
        left.clone()
    }
}

fn value_hash<T: Serialize>(value: &T) -> [u8; 32] {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes)
        .expect("topic value serialization should not fail");
    *blake3::hash(&bytes).as_bytes()
}

fn default_true() -> bool {
    true
}

pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes).map_err(|error| error.to_string())?;
    Ok(bytes)
}

pub fn decode_params(bytes: &[u8]) -> Result<TopicParamsV1, String> {
    ciborium::de::from_reader(bytes).map_err(|error| error.to_string())
}

pub fn decode_state(bytes: &[u8]) -> Result<TopicStateV1, String> {
    ciborium::de::from_reader(bytes).map_err(|error| error.to_string())
}

pub fn decode_delta(bytes: &[u8]) -> Result<TopicDeltaV1, String> {
    ciborium::de::from_reader(bytes).map_err(|error| error.to_string())
}

pub fn decode_summary(bytes: &[u8]) -> Result<TopicStateSummaryV1, String> {
    ciborium::de::from_reader(bytes).map_err(|error| error.to_string())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use plaza_core::board_state::ban::{AuthorizedUserBan, UserBan};
    use plaza_core::board_state::member::{AuthorizedMember, Member};
    use plaza_core::board_state::member_moderation::{
        AuthorizedSuspension, SuspensionV1,
    };
    use plaza_core::board_state::reports::ReportReason;
    use plaza_core::board_state::roles::{Role, RoleAssignment};
    use std::time::Duration;

    pub(crate) fn owner() -> SigningKey {
        SigningKey::from_bytes(&[1u8; 32])
    }

    pub(crate) fn member() -> SigningKey {
        SigningKey::from_bytes(&[2u8; 32])
    }

    pub(crate) fn other() -> SigningKey {
        SigningKey::from_bytes(&[3u8; 32])
    }

    pub(crate) fn owner_id() -> MemberId {
        MemberId::from(&owner().verifying_key())
    }

    pub(crate) fn member_id() -> MemberId {
        MemberId::from(&member().verifying_key())
    }

    pub(crate) fn params() -> TopicParamsV1 {
        TopicParamsV1::new(owner().verifying_key(), [7u8; 32], 0)
    }

    pub(crate) fn at(ms: i64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_millis(ms as u64)
    }

    pub(crate) fn policy(generation: u64) -> AuthorizedTopicPolicyV1 {
        AuthorizedTopicPolicyV1::new(
            TopicPolicyV1 {
                generation,
                updated_at: 1,
                ..Default::default()
            },
            &owner(),
        )
    }

    pub(crate) fn authority() -> TopicAuthorityV1 {
        TopicAuthorityV1 {
            policy: Some(policy(1)),
            ..Default::default()
        }
    }

    pub(crate) fn header(author: &SigningKey, section: Option<SectionId>) -> AuthorizedTopicHeaderV1 {
        AuthorizedTopicHeaderV1::new(
            TopicHeaderV1 {
                topic_id: [7u8; 32],
                author: MemberId::from(&author.verifying_key()),
                author_key: author.verifying_key(),
                section,
                section_chain: section.map(|id| vec![id]).unwrap_or_default(),
                title: SealedBytes::public(b"Title".to_vec()),
                body: SealedBytes::public(b"Body".to_vec()),
                auto_moderated: false,
                created_at: 1,
                nonce: [3u8; 16],
            },
            author,
        )
    }

    pub(crate) fn participant(sk: &SigningKey, joined_at: i64) -> AuthorizedParticipantV1 {
        let member_record = AuthorizedMember::new(
            Member {
                owner_member_id: owner_id(),
                invited_by: owner_id(),
                member_vk: sk.verifying_key(),
                join_proof: None,
            },
            &owner(),
        );
        let record = ParticipantRecordV1 {
            member_id: MemberId::from(&sk.verifying_key()),
            member_vk: sk.verifying_key(),
            certificate: ParticipantCertificateV1 {
                member: member_record,
                chain: Vec::new(),
                token: None,
                join_proof: None,
            },
            joined_at,
        };
        AuthorizedParticipantV1::new(record, sk)
    }

    pub(crate) fn post(sk: &SigningKey, content: &str, created_at: i64, nonce: u8) -> AuthorizedTopicPostV1 {
        AuthorizedTopicPostV1::new(
            TopicPostV1 {
                author: MemberId::from(&sk.verifying_key()),
                parent: None,
                content: SealedBytes::public(content.as_bytes().to_vec()),
                images: Vec::new(),
                created_at,
                nonce: [nonce; 16],
            },
            sk,
        )
    }

    pub(crate) fn base_state() -> TopicStateV1 {
        TopicStateV1 {
            header: Some(header(&owner(), None)),
            authority: authority(),
            participants: vec![participant(&member(), 1)],
            posts: BTreeMap::new(),
            generation: TopicGenerationV1::new(0),
            ..Default::default()
        }
    }

    pub(crate) fn action(
        signer: &SigningKey,
        kind: TopicActionKind,
        target: MessageId,
        generation: u64,
    ) -> AuthorizedTopicActionV1 {
        let value = TopicActionV1 {
            kind,
            target,
            payload: SealedBytes::public(Vec::new()),
            generation,
            created_at: 10,
            signer: MemberId::from(&signer.verifying_key()),
        };
        AuthorizedTopicActionV1 {
            signature: sign_struct(&value, signer),
            action: value,
            signer_key: Some(signer.verifying_key()),
            authority: None,
        }
    }

    #[test]
    fn a_minimal_topic_verifies() {
        let mut state = base_state();
        state.posts.insert(
            post(&member(), "hello", 10, 1).id(),
            post(&member(), "hello", 10, 1),
        );
        state.verify(&params()).unwrap();
    }

    #[test]
    fn a_tampered_post_is_rejected() {
        let mut state = base_state();
        let mut entry = post(&member(), "hello", 10, 1);
        entry.post.content = SealedBytes::public(b"other".to_vec());
        state.posts.insert(entry.id(), entry);
        assert!(state.verify(&params()).is_err());
    }

    #[test]
    fn a_post_from_an_outsider_is_rejected() {
        let mut state = base_state();
        let entry = post(&other(), "hello", 10, 1);
        state.posts.insert(entry.id(), entry);
        assert!(state.verify(&params()).is_err());
    }

    #[test]
    fn merge_collects_posts_from_both_sides() {
        let mut left = base_state();
        let a = post(&member(), "left", 10, 1);
        left.posts.insert(a.id(), a);
        let mut right = base_state();
        let b = post(&member(), "right", 20, 2);
        right.posts.insert(b.id(), b);
        left.merge(&params(), &right).unwrap();
        assert_eq!(left.posts.len(), 2);
        left.verify(&params()).unwrap();
    }

    #[test]
    fn delta_serves_the_missing_posts() {
        let left = base_state();
        let mut right = base_state();
        let b = post(&member(), "right", 20, 2);
        right.posts.insert(b.id(), b);
        let delta = right.delta(&left.summarize()).unwrap();
        let mut merged = left.clone();
        merged.apply_delta(&params(), &delta).unwrap();
        assert_eq!(merged.posts.len(), 1);
        merged.verify(&params()).unwrap();
    }

    #[test]
    fn an_author_can_delete_their_post() {
        let mut state = base_state();
        let entry = post(&member(), "hello", 10, 1);
        let id = entry.id();
        state.posts.insert(id, entry);
        state
            .actions
            .push(action(&member(), TopicActionKind::Delete, id, 1));
        state.verify(&params()).unwrap();
        assert!(state.is_deleted(id));
    }

    #[test]
    fn the_owner_can_delete_another_post() {
        let mut state = base_state();
        let entry = post(&member(), "hello", 10, 1);
        let id = entry.id();
        state.posts.insert(id, entry);
        state
            .actions
            .push(action(&owner(), TopicActionKind::Delete, id, 1));
        state.verify(&params()).unwrap();
        assert!(state.is_deleted(id));
    }

    #[test]
    fn an_outsider_cannot_delete_a_post() {
        let mut state = base_state();
        let entry = post(&member(), "hello", 10, 1);
        let id = entry.id();
        state.posts.insert(id, entry);
        state
            .actions
            .push(action(&other(), TopicActionKind::Delete, id, 1));
        assert!(state.verify(&params()).is_err());
    }

    #[test]
    fn a_ban_blocks_new_posts_but_not_old_ones() {
        let mut state = base_state();
        let entry = post(&member(), "before", 10, 1);
        state.posts.insert(entry.id(), entry);
        let ban = UserBan {
            owner_member_id: owner_id(),
            banned_at: at(20),
            banned_user: member_id(),
            expires_at: None,
            target_member: None,
            invite_chain: Vec::new(),
        };
        state
            .authority
            .bans
            .0
            .push(AuthorizedUserBan::new(ban, owner_id(), &owner()));
        state.verify(&params()).unwrap();

        let after = post(&member(), "after", 30, 2);
        state.posts.insert(after.id(), after);
        assert!(state.verify(&params()).is_err());
    }

    #[test]
    fn a_suspension_blocks_new_posts() {
        let mut state = base_state();
        state.authority.suspensions.suspensions.push(
            AuthorizedSuspension::new(
                SuspensionV1 {
                    target: member_id(),
                    reason: ReportReason::Spam,
                    until: 100,
                    created_at: 10,
                    generation: 1,
                },
                &owner(),
            ),
        );
        state.verify(&params()).unwrap();
        let entry = post(&member(), "suspended", 50, 1);
        state.posts.insert(entry.id(), entry);
        assert!(state.verify(&params()).is_err());
    }

    #[test]
    fn the_header_is_immutable() {
        let params = params();
        let mut state = base_state();
        let mut other_header = header(&owner(), None).header;
        other_header.nonce = [4u8; 16];
        let delta = TopicDeltaV1 {
            header: Some(AuthorizedTopicHeaderV1::new(other_header, &owner())),
            ..Default::default()
        };
        assert!(state.apply_delta(&params, &delta).is_err());
    }

    #[test]
    fn the_part_is_bound_to_the_parameters() {
        let mut state = base_state();
        state.generation.part = 1;
        assert!(state.verify(&params()).is_err());
    }

    #[test]
    fn state_and_delta_round_trip() {
        let state = base_state();
        let bytes = encode(&state).unwrap();
        assert_eq!(decode_state(&bytes).unwrap(), state);
        let delta = TopicDeltaV1 {
            header: state.header.clone(),
            ..Default::default()
        };
        let bytes = encode(&delta).unwrap();
        assert_eq!(decode_delta(&bytes).unwrap(), delta);
        let summary = state.summarize();
        let bytes = encode(&summary).unwrap();
        assert_eq!(decode_summary(&bytes).unwrap(), summary);
    }

    #[test]
    fn approvals_gate_untrusted_posts() {
        let mut state = base_state();
        let mut policy = state.authority.policy().clone();
        policy.approval_required = true;
        state.authority.policy = Some(AuthorizedTopicPolicyV1::new(policy, &owner()));

        let entry = post(&member(), "pending", 10, 1);
        let id = entry.id();
        state.posts.insert(id, entry.clone());
        state.verify(&params()).unwrap();
        assert!(!state.post_is_visible(&entry));

        let approval = TopicApprovalV1 {
            target: id,
            approved: true,
            generation: 1,
            scope: None,
            signed_by: owner_id(),
            created_at: 11,
        };
        state.approvals.push(AuthorizedTopicApprovalV1 {
            signature: sign_struct(&approval, &owner()),
            approval,
            signer_key: Some(owner().verifying_key()),
            authority: None,
        });
        state.verify(&params()).unwrap();
        assert!(state.post_is_visible(&entry));
    }

    #[test]
    fn section_acl_blocks_a_member_without_the_role() {
        let section = MessageId::from_bytes([9u8; 32]);
        let role_id = [5u8; 16];
        let snapshot = SectionSnapshotV1 {
            section,
            parent: None,
            chain: vec![section],
            allowed_roles: vec![role_id],
            sealed_name: None,
            hidden: false,
            images_allowed: true,
            auto_moderated_topics: None,
            generation: 1,
            signed_at: 1,
        };
        let mut state = base_state();
        state.header = Some(header(&owner(), Some(section)));
        state.section = Some(AuthorizedSectionSnapshotV1::new(
            snapshot,
            &owner(),
            None,
        ));
        state.verify(&params()).unwrap();

        let entry = post(&member(), "blocked", 10, 1);
        state.posts.insert(entry.id(), entry);
        assert!(state.verify(&params()).is_err());
    }

    #[test]
    fn the_section_acl_admits_the_role_member() {
        let section = MessageId::from_bytes([9u8; 32]);
        let role_id = [5u8; 16];
        let snapshot = SectionSnapshotV1 {
            section,
            parent: None,
            chain: vec![section],
            allowed_roles: vec![role_id],
            sealed_name: None,
            hidden: false,
            images_allowed: true,
            auto_moderated_topics: None,
            generation: 1,
            signed_at: 1,
        };
        let mut state = base_state();
        state.header = Some(header(&owner(), Some(section)));
        state.section = Some(AuthorizedSectionSnapshotV1::new(
            snapshot,
            &owner(),
            None,
        ));
        state.authority.roles.roles.push(AuthorizedRole::new(
            Role {
                id: role_id,
                name: "members".to_string(),
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
            &owner(),
        ));
        state.authority.roles.assignments.push(
            AuthorizedRoleAssignment::new(
                RoleAssignment {
                    role_id,
                    member_id: member_id(),
                    generation: 1,
                    revoked: false,
                    signed_at: SystemTime::UNIX_EPOCH,
                },
                &owner(),
            ),
        );
        let entry = post(&member(), "allowed", 10, 1);
        state.posts.insert(entry.id(), entry);
        state.verify(&params()).unwrap();
    }

    #[test]
    fn the_rate_limit_rejects_a_burst() {
        let mut state = base_state();
        let mut policy = state.authority.policy().clone();
        policy.max_posts_per_window = 2;
        state.authority.policy = Some(AuthorizedTopicPolicyV1::new(policy, &owner()));
        let delta = TopicDeltaV1 {
            posts: vec![
                post(&member(), "one", 10, 1),
                post(&member(), "two", 20, 2),
                post(&member(), "three", 30, 3),
            ],
            ..Default::default()
        };
        assert!(state.apply_delta(&params(), &delta).is_err());
    }
}

#[cfg(test)]
mod phase1_extra_tests {
    use super::tests::*;
    use super::*;
    use plaza_core::board_state::admin::{Admin, AuthorizedAdmin};
    use plaza_core::board_state::invites::{
        join_message, AuthorizedInviteToken, InviteToken, JoinProof,
    };
    use plaza_core::board_state::member::{AuthorizedMember, Member};
    use plaza_core::board_state::roles::{
        AuthorizedRole, AuthorizedRoleAssignment, Role, RoleAssignment,
    };
    use std::time::SystemTime;

    #[test]
    fn a_tampered_header_is_rejected() {
        let mut state = base_state();
        state.header.as_mut().unwrap().header.title =
            SealedBytes::public(b"Other".to_vec());
        assert!(state.verify(&params()).is_err());
    }

    #[test]
    fn a_token_join_is_accepted() {
        let token_sk = SigningKey::from_bytes(&[4u8; 32]);
        let role_id = [5u8; 16];
        let mut state = base_state();
        state.authority.roles.roles.push(AuthorizedRole::new(
            role(role_id),
            &owner(),
        ));

        let token = InviteToken {
            id: [6u8; 16],
            verifying_key: token_sk.verifying_key(),
            role_id,
            max_uses: None,
            not_after: None,
            generation: 1,
            deleted: false,
            label: String::new(),
            created_at: Some(SystemTime::UNIX_EPOCH),
            includes_category_keys: false,
        };
        let authorized = AuthorizedInviteToken::new(token, &owner());
        let member_sk = other();
        let member_id = MemberId::from(&member_sk.verifying_key());
        let proof = JoinProof::new(
            [6u8; 16],
            &token_sk,
            &join_message(&owner().verifying_key(), &member_sk.verifying_key()),
        );
        let member_record = AuthorizedMember::new(
            Member {
                owner_member_id: owner_id(),
                invited_by: member_id,
                member_vk: member_sk.verifying_key(),
                join_proof: Some(proof.clone()),
            },
            &member_sk,
        );
        let record = ParticipantRecordV1 {
            member_id,
            member_vk: member_sk.verifying_key(),
            certificate: ParticipantCertificateV1 {
                member: member_record,
                chain: Vec::new(),
                token: Some(authorized),
                join_proof: Some(proof),
            },
            joined_at: 2,
        };
        state
            .participants
            .push(AuthorizedParticipantV1::new(record, &member_sk));
        state.verify(&params()).unwrap();
    }

    #[test]
    fn a_role_holder_can_moderate() {
        let role_id = [5u8; 16];
        let mut state = base_state();
        state.authority.roles.roles.push(AuthorizedRole::new(
            Role {
                can_delete_posts: true,
                ..role(role_id)
            },
            &owner(),
        ));
        state.authority.roles.assignments.push(
            AuthorizedRoleAssignment::new(
                RoleAssignment {
                    role_id,
                    member_id: member_id(),
                    generation: 1,
                    revoked: false,
                    signed_at: SystemTime::UNIX_EPOCH,
                },
                &owner(),
            ),
        );
        let target = state.header.as_ref().unwrap().header.id();
        state.actions.push(action(
            &member(),
            TopicActionKind::Delete,
            target,
            1,
        ));
        state.verify(&params()).unwrap();
        assert!(state.is_deleted(target));
    }

    #[test]
    fn an_admin_can_moderate() {
        let mut state = base_state();
        state.authority.admins.admins.push(AuthorizedAdmin::new(
            Admin {
                member_id: member_id(),
                generation: 1,
                signed_at: SystemTime::UNIX_EPOCH,
            },
            &owner(),
        ));
        let target = state.header.as_ref().unwrap().header.id();
        state.actions.push(action(
            &member(),
            TopicActionKind::Delete,
            target,
            1,
        ));
        state.verify(&params()).unwrap();
        assert!(state.is_deleted(target));
    }

    fn role(id: [u8; 16]) -> Role {
        Role {
            id,
            name: "moderator".to_string(),
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
        }
    }
}

#[cfg(test)]
mod phase1_policy_tests {
    use super::tests::*;
    use super::*;

    #[test]
    fn a_purged_topic_is_deleted() {
        let mut state = base_state();
        let target = state.header.as_ref().unwrap().header.id();
        state.actions.push(action(
            &owner(),
            TopicActionKind::Purge,
            target,
            1,
        ));
        state.verify(&params()).unwrap();
        assert!(state.is_deleted(target));
    }

    #[test]
    fn auto_moderated_topics_need_the_policy() {
        let mut state = base_state();
        let mut policy = state.authority.policy().clone();
        policy.auto_moderated_topics = false;
        state.authority.policy = Some(AuthorizedTopicPolicyV1::new(policy, &owner()));
        let header = state.header.as_mut().unwrap();
        header.header.auto_moderated = true;
        header.signature = sign_struct(&header.header, &owner());
        assert!(state.verify(&params()).is_err());
    }

    #[test]
    fn the_summary_tracks_approvals() {
        let mut state = base_state();
        let entry = post(&member(), "hello", 10, 1);
        let id = entry.id();
        state.posts.insert(id, entry);
        let approval = TopicApprovalV1 {
            target: id,
            approved: true,
            generation: 1,
            scope: None,
            signed_by: owner_id(),
            created_at: 11,
        };
        state.approvals.push(AuthorizedTopicApprovalV1 {
            signature: sign_struct(&approval, &owner()),
            approval,
            signer_key: Some(owner().verifying_key()),
            authority: None,
        });
        let summary = state.summarize();
        assert_eq!(summary.approvals.get(&id), Some(&1));
    }
}

#[cfg(test)]
mod member_topic_tests {
    use super::tests::*;
    use super::*;
    use plaza_core::board_state::configuration::{
        AuthorizedConfigurationV1, Configuration,
    };
    use std::time::SystemTime;

    #[test]
    fn a_member_topic_can_use_the_owner_signed_board_config() {
        let mut state = base_state();
        let configuration = Configuration {
            owner_member_id: owner_id(),
            updated_at: SystemTime::UNIX_EPOCH,
            ..Default::default()
        };
        state.authority.policy = None;
        state.authority.source_configuration = Some(AuthorizedConfigurationV1::new(
            configuration,
            &owner(),
        ));
        state.header = Some(header(&member(), None));
        state.participants = vec![participant(&member(), 1)];
        state.verify(&params()).unwrap();
        assert_eq!(state.authority.policy().max_post_size, 10_000);
    }
}

#[cfg(test)]
mod edit_tests {
    use super::tests::*;
    use super::*;

    #[test]
    fn an_author_can_edit_a_post() {
        let mut state = base_state();
        let entry = post(&member(), "before", 10, 1);
        let id = entry.id();
        state.posts.insert(id, entry);
        state
            .actions
            .push(action(&member(), TopicActionKind::Edit, id, 1));
        state.verify(&params()).unwrap();
        assert!(state.latest_action(id, TopicActionKind::Edit).is_some());
    }

    #[test]
    fn an_outsider_cannot_edit_a_post() {
        let mut state = base_state();
        let entry = post(&member(), "before", 10, 1);
        let id = entry.id();
        state.posts.insert(id, entry);
        state
            .actions
            .push(action(&other(), TopicActionKind::Edit, id, 1));
        assert!(state.verify(&params()).is_err());
    }
}

#[cfg(test)]
mod approval_tests {
    use super::tests::*;
    use super::*;

    fn approval_state() -> (TopicStateV1, MessageId) {
        let mut state = base_state();
        let mut policy = state.authority.policy().clone();
        policy.approval_required = true;
        state.authority.policy = Some(AuthorizedTopicPolicyV1::new(policy, &owner()));
        let entry = post(&member(), "pending", 10, 1);
        let id = entry.id();
        state.posts.insert(id, entry);
        (state, id)
    }

    #[test]
    fn an_outsider_cannot_approve_a_post() {
        let (mut state, id) = approval_state();
        let approval = TopicApprovalV1 {
            target: id,
            approved: true,
            generation: 1,
            scope: None,
            signed_by: MemberId::from(&other().verifying_key()),
            created_at: 11,
        };
        state.approvals.push(AuthorizedTopicApprovalV1 {
            signature: sign_struct(&approval, &other()),
            approval,
            signer_key: Some(other().verifying_key()),
            authority: None,
        });
        assert!(state.verify(&params()).is_err());
    }

    #[test]
    fn a_rejected_post_stays_hidden() {
        let (mut state, id) = approval_state();
        let approval = TopicApprovalV1 {
            target: id,
            approved: false,
            generation: 1,
            scope: None,
            signed_by: owner_id(),
            created_at: 11,
        };
        state.approvals.push(AuthorizedTopicApprovalV1 {
            signature: sign_struct(&approval, &owner()),
            approval,
            signer_key: Some(owner().verifying_key()),
            authority: None,
        });
        state.verify(&params()).unwrap();
        assert!(!state.post_is_visible(state.posts.get(&id).unwrap()));
    }

    #[test]
    fn trust_makes_a_post_visible_without_an_approval() {
        let (mut state, id) = approval_state();
        let trust = TrustV1 {
            member_id: member_id(),
            trusted: true,
            generation: 1,
            signed_by: owner_id(),
            created_at: 11,
        };
        state.trust.push(AuthorizedTrustV1 {
            signature: sign_struct(&trust, &owner()),
            trust,
            signer_key: Some(owner().verifying_key()),
            authority: None,
        });
        state.verify(&params()).unwrap();
        assert!(state.post_is_visible(state.posts.get(&id).unwrap()));
    }
}

#[cfg(test)]
mod propagation_tests {
    use super::tests::*;
    use super::*;
    use plaza_core::board_state::ban::{AuthorizedUserBan, UserBan};

    #[test]
    fn a_propagated_ban_blocks_later_posts() {
        let mut state = base_state();
        let before = post(&member(), "before", 10, 1);
        state.posts.insert(before.id(), before);
        state.verify(&params()).unwrap();

        let mut updated = state.authority.clone();
        updated.bans.0.push(AuthorizedUserBan::new(
            UserBan {
                owner_member_id: owner_id(),
                banned_at: at(20),
                banned_user: member_id(),
                expires_at: None,
                target_member: None,
                invite_chain: Vec::new(),
            },
            owner_id(),
            &owner(),
        ));
        state.authority = state.authority.merged_with(&updated);
        state.verify(&params()).unwrap();
        assert!(state.is_banned_member(member_id(), 30));

        let after = post(&member(), "after", 30, 2);
        state.posts.insert(after.id(), after);
        assert!(state.verify(&params()).is_err());
    }
}

#[cfg(test)]
mod role_propagation_tests {
    use super::tests::*;
    use super::*;
    use plaza_core::board_state::roles::{
        AuthorizedRole, AuthorizedRoleAssignment, Role, RoleAssignment,
    };
    use std::time::SystemTime;

    #[test]
    fn a_propagated_role_can_moderate() {
        let mut state = base_state();
        let role_id = [5u8; 16];
        let mut updated = state.authority.clone();
        updated.roles.roles.push(AuthorizedRole::new(
            Role {
                id: role_id,
                name: "Moderators".to_string(),
                generation: 1,
                can_manage_access: false,
                can_distribute_keys: false,
                can_edit_posts: false,
                can_delete_posts: true,
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
            &owner(),
        ));
        updated.roles.assignments.push(AuthorizedRoleAssignment::new(
            RoleAssignment {
                role_id,
                member_id: member_id(),
                generation: 1,
                revoked: false,
                signed_at: SystemTime::UNIX_EPOCH,
            },
            &owner(),
        ));
        state.authority = state.authority.merged_with(&updated);
        let target = state.header.as_ref().unwrap().header.id();
        state
            .actions
            .push(action(&member(), TopicActionKind::Delete, target, 1));
        state.verify(&params()).unwrap();
        assert!(state.is_deleted(target));
    }
}

#[cfg(test)]
mod reaction_tests {
    use super::tests::*;
    use super::*;
    use plaza_core::board_state::ban::{AuthorizedUserBan, UserBan};

    fn state_with_post() -> (TopicStateV1, MessageId) {
        let mut state = base_state();
        let entry = post(&member(), "hello", 1, 1);
        let id = entry.id();
        state.posts.insert(id, entry);
        (state, id)
    }

    #[test]
    fn a_participant_can_react_and_vote() {
        let (mut state, id) = state_with_post();
        state.actions.push(action(&member(), TopicActionKind::React, id, 1));
        state.actions.push(action(&member(), TopicActionKind::Vote, id, 1));
        state.verify(&params()).unwrap();
    }

    #[test]
    fn an_outsider_cannot_react() {
        let (mut state, id) = state_with_post();
        state.actions.push(action(&other(), TopicActionKind::React, id, 1));
        assert!(state.verify(&params()).is_err());
    }

    #[test]
    fn a_banned_member_cannot_react() {
        let (mut state, id) = state_with_post();
        state.authority.bans.0.push(AuthorizedUserBan::new(
            UserBan {
                owner_member_id: owner_id(),
                banned_at: at(1),
                banned_user: member_id(),
                expires_at: None,
                target_member: None,
                invite_chain: Vec::new(),
            },
            owner_id(),
            &owner(),
        ));
        state.actions.push(action(&member(), TopicActionKind::React, id, 1));
        assert!(state.verify(&params()).is_err());
    }
}

#[cfg(test)]
mod move_merge_split_tests {
    use super::tests::*;
    use super::*;

    fn signed_action(
        signer: &SigningKey,
        kind: TopicActionKind,
        target: MessageId,
        payload: SealedBytes,
    ) -> AuthorizedTopicActionV1 {
        let value = TopicActionV1 {
            kind,
            target,
            payload,
            generation: 1,
            created_at: 1,
            signer: MemberId::from(&signer.verifying_key()),
        };
        AuthorizedTopicActionV1 {
            signature: sign_struct(&value, signer),
            action: value,
            signer_key: Some(signer.verifying_key()),
            authority: None,
        }
    }

    #[test]
    fn a_move_action_changes_the_effective_section() {
        let mut state = base_state();
        let section = MessageId::from_bytes([9u8; 32]);
        let snapshot = SectionSnapshotV1 {
            section,
            parent: None,
            chain: vec![section],
            allowed_roles: Vec::new(),
            sealed_name: None,
            hidden: false,
            images_allowed: true,
            auto_moderated_topics: None,
            generation: 1,
            signed_at: 1,
        };
        let payload = SealedBytes::public(encode(&snapshot).unwrap());
        let target = state.header.as_ref().unwrap().header.id();
        state.actions.push(signed_action(
            &owner(),
            TopicActionKind::Move,
            target,
            payload,
        ));
        state.verify(&params()).unwrap();
        assert_eq!(state.effective_section().unwrap().section, section);
    }

    #[test]
    fn a_merge_action_records_the_destination() {
        let mut state = base_state();
        let destination = MessageId::from_bytes([4u8; 32]);
        let target = state.header.as_ref().unwrap().header.id();
        state.actions.push(signed_action(
            &owner(),
            TopicActionKind::Merge,
            target,
            SealedBytes::public(destination.as_bytes().to_vec()),
        ));
        state.verify(&params()).unwrap();
        assert_eq!(state.merged_into(), Some(destination));
    }

    #[test]
    fn a_split_action_marks_the_reply() {
        let mut state = base_state();
        let entry = post(&member(), "reply", 1, 1);
        let id = entry.id();
        state.posts.insert(id, entry);
        let destination = MessageId::from_bytes([5u8; 32]);
        state.actions.push(signed_action(
            &owner(),
            TopicActionKind::Split,
            id,
            SealedBytes::public(destination.as_bytes().to_vec()),
        ));
        state.verify(&params()).unwrap();
        assert!(state.is_split(id));
        assert_eq!(state.split_target(id), Some(destination));
    }
}

#[cfg(test)]
mod continuation_tests {
    use super::tests::*;
    use super::*;

    #[test]
    fn a_continuation_part_needs_the_previous_hash() {
        let mut state = base_state();
        state.generation = TopicGenerationV1 {
            part: 1,
            closed_at: None,
            next_part: None,
            previous_hash: Some([1u8; 32]),
        };
        let params = TopicParamsV1::new(owner().verifying_key(), [7u8; 32], 1);
        state.verify(&params).unwrap();

        state.generation.previous_hash = None;
        assert!(state.verify(&params).is_err());
    }

    #[test]
    fn the_first_part_cannot_carry_a_previous_hash() {
        let mut state = base_state();
        state.generation.previous_hash = Some([1u8; 32]);
        assert!(state.verify(&params()).is_err());
    }
}
