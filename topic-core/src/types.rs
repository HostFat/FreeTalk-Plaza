//! Data model types for `plaza-topic` contract state, deltas, and summaries.

use crate::pages::AuthorizedTopicPageSealV1;
use crate::{
    default_true, value_hash, AuthorizedAuthorityRootV1, MemberStatusProofV1, SectionId,
    MAX_BODY_BYTES, MAX_PARTS, MAX_POST_BYTES, MAX_TITLE_BYTES, PROTOCOL_VERSION,
};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use freenet_scaffold::ComposableState;
use plaza_core::board_state::admin::{AdminsV1, AuthorizedAdmin};
use plaza_core::board_state::ban::{BanRevocationsV1, BansV1};
use plaza_core::board_state::configuration::{AuthorizedConfigurationV1, Configuration};
use plaza_core::board_state::content::PollContentV1;
use plaza_core::board_state::images::ImageRef;
use plaza_core::board_state::invites::{join_message, AuthorizedInviteToken, JoinProof};
use plaza_core::board_state::member::{AuthorizedMember, MemberId, MembersV1};
use plaza_core::board_state::member_moderation::{AuthorizedSuspension, SuspensionsV1};
use plaza_core::board_state::message::MessageId;
use plaza_core::board_state::ownership::OwnershipV1;
use plaza_core::board_state::privacy::SealedBytes;
use plaza_core::board_state::rate_limit::{system_time_from_ms, system_time_ms};
use plaza_core::board_state::roles::{
    resolve_signer_key, verify_moderation_authority, AuthorityProof, AuthorizedRole,
    AuthorizedRoleAssignment, ModerationPower, RoleId, RolesV1,
};
use plaza_core::board_state::ChatBoardParametersV1;
use plaza_core::util::{sign_struct, verify_struct};
use plaza_core::ChatBoardStateV1;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::time::SystemTime;

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
    /// Compact commitment to the board authority, signed by the owner. When
    /// present, the topic keeps only the proofs of the members it references.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<AuthorizedAuthorityRootV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub member_proofs: Vec<MemberStatusProofV1>,
}

impl TopicAuthorityV1 {
    pub fn effective_policy(&self) -> TopicPolicyV1 {
        match (&self.source_configuration, &self.policy) {
            (Some(source), Some(policy)) => {
                let from_config = policy_from_configuration(&source.configuration);
                let config_rank = (from_config.updated_at, from_config.generation);
                let policy_rank = (policy.policy.updated_at, policy.policy.generation);
                if policy_rank >= config_rank {
                    policy.policy.clone()
                } else {
                    from_config
                }
            }
            (Some(source), None) => policy_from_configuration(&source.configuration),
            (None, Some(policy)) => policy.policy.clone(),
            (None, None) => TopicPolicyV1::default(),
        }
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

pub(crate) fn policy_from_configuration(configuration: &Configuration) -> TopicPolicyV1 {
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
    /// Optional owner/admin seal freezing `posts` on `part == 0` once closed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posts_seal: Option<AuthorizedTopicPageSealV1>,
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
            posts_seal: None,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posts_seal: Option<AuthorizedTopicPageSealV1>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posts_seal_hash: Option<[u8; 32]>,
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
            posts_seal_hash: None,
        }
    }
}
