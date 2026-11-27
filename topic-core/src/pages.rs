//! Compact append-only post pages (`part > 0`) for `plaza-topic`.
//!
//! Part 0 (`TopicStateV1`) holds the topic head (title, body, section snapshot,
//! topic-level moderation flags/edits/moves/merges, canonical authority) plus
//! the first slice of replies. Once a discussion grows past a page (default 50
//! posts, or manual continuation), new replies are written to compact
//! append-only pages (`part = 1, 2, ...`) backed by `TopicPageStateV1`:
//!
//! - A reply writes only the active page (never touches `part 0` or older pages).
//! - Extra pages carry a small signed `TopicPageHeaderV1` instead of duplicating
//!   the full 64 KiB topic body, section snapshot, topic-level flags, or
//!   historical participants from earlier pages.
//! - When a page fills up and the next page opens, the owner (or an active
//!   admin) can seal it with `AuthorizedTopicPageSealV1`. Sealing freezes
//!   `posts`, `actions`, and `approvals` under a BLAKE3 `content_digest` and
//!   strips `participants`, `trust`, and heavy `authority` fields, reducing
//!   bootstrap verification from O(posts + participants) Ed25519 checks to 1
//!   seal signature + 1 BLAKE3 digest.
//! - Post-seal author edits/deletes and owner/admin moderation continue to work
//!   through `post_seal_actions` without mutating the sealed digest.

use crate::{
    build_board_view, check_posts_rate_limit, default_true, encode, is_member_banned,
    is_member_suspended, merge_admins, merge_approval, merge_authority, merge_generation,
    merge_ownership, merge_participant, merge_trust, post_cycle, value_hash,
    verify_authority_records, verify_owner_or_admin, verify_participants_list,
    AuthorizedParticipantV1, AuthorizedTopicActionV1, AuthorizedTopicApprovalV1,
    AuthorizedTopicPostV1, AuthorizedTrustV1, SectionId, TopicActionKind, TopicAuthorityV1,
    TopicGenerationV1, TopicParamsV1, MAX_BODY_BYTES, MAX_IMAGES_PER_POST, MAX_PARTS,
    MAX_POSTS, MAX_POST_BYTES, MAX_REACTION_PAYLOAD_BYTES, PROTOCOL_VERSION,
};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use freenet_scaffold::ComposableState;
use plaza_core::board_state::member::MemberId;
use plaza_core::board_state::message::MessageId;
use plaza_core::board_state::rate_limit::system_time_from_ms;
use plaza_core::board_state::roles::{
    resolve_signer_key, verify_moderation_authority, AuthorityProof, ModerationPower, RoleId,
};
use plaza_core::board_state::ChatBoardParametersV1;
use plaza_core::util::{sign_struct, verify_struct};
use plaza_core::ChatBoardStateV1;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Default number of posts per topic page before auto-continuing to the next
/// append-only page. Keeps per-reply broadcasts small (~20-30 KiB).
pub const DEFAULT_TOPIC_PAGE_SIZE: usize = 50;
/// Hard contract cap on posts in one append-only page.
pub const MAX_TOPIC_PAGE_POSTS: usize = MAX_POSTS;
/// Maximum serialized CBOR size of a compact append-only topic page (`part > 0`).
pub const MAX_TOPIC_PAGE_BYTES: usize = 256 * 1024;
pub const MAX_TOPIC_PAGE_PARTICIPANTS: usize = 256;
pub const MAX_TOPIC_PAGE_ACTIONS: usize = 1_000;
pub const MAX_TOPIC_PAGE_APPROVALS: usize = 500;
pub const MAX_POST_SEAL_ACTIONS: usize = 500;

/// Small signed header that anchors an append-only topic page (`part > 0`) to
/// the topic head (`part == 0`) and previous page without duplicating the full
/// topic title, body, section snapshot, or historical participants.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct TopicPageHeaderV1 {
    pub topic_id: [u8; 32],
    pub part: u32,
    /// BLAKE3 hash of `TopicHeaderV1` on `part == 0`.
    pub header_hash: [u8; 32],
    /// BLAKE3 hash of the encoded previous part (`part - 1`), forming an
    /// append-only hash chain across pages.
    pub previous_hash: [u8; 32],
    pub topic_author: MemberId,
    #[serde(default)]
    pub auto_moderated: bool,
    #[serde(default)]
    pub section_chain: Vec<SectionId>,
    #[serde(default)]
    pub allowed_roles: Vec<RoleId>,
    #[serde(default = "default_true")]
    pub images_allowed: bool,
    pub max_posts: u32,
    pub creator: MemberId,
    pub created_at: i64,
}

impl TopicPageHeaderV1 {
    pub fn verify(&self, params: &TopicParamsV1) -> Result<(), String> {
        params.verify()?;
        if params.part == 0 {
            return Err("compact topic pages require part > 0".to_string());
        }
        if self.topic_id != params.topic_id {
            return Err("page header topic id does not match the parameters".to_string());
        }
        if self.part != params.part {
            return Err("page header part does not match the parameters".to_string());
        }
        if self.header_hash == [0u8; 32] {
            return Err("page header_hash cannot be empty".to_string());
        }
        if self.previous_hash == [0u8; 32] {
            return Err("page previous_hash cannot be empty".to_string());
        }
        if self.max_posts == 0 || self.max_posts as usize > MAX_TOPIC_PAGE_POSTS {
            return Err("page max_posts is out of range".to_string());
        }
        if self.section_chain.len() > 64 {
            return Err("page section chain is too deep".to_string());
        }
        Ok(())
    }

    pub fn hash(&self) -> [u8; 32] {
        value_hash(self)
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct AuthorizedTopicPageHeaderV1 {
    pub header: TopicPageHeaderV1,
    pub creator_key: VerifyingKey,
    pub signature: Signature,
}

impl AuthorizedTopicPageHeaderV1 {
    pub fn new(header: TopicPageHeaderV1, signing_key: &SigningKey) -> Self {
        Self {
            signature: sign_struct(&header, signing_key),
            creator_key: signing_key.verifying_key(),
            header,
        }
    }

    pub fn verify(&self, params: &TopicParamsV1) -> Result<(), String> {
        self.header.verify(params)?;
        if MemberId::from(&self.creator_key) != self.header.creator {
            return Err("page header creator key does not match creator".to_string());
        }
        verify_struct(&self.header, &self.signature, &self.creator_key)
            .map_err(|error| format!("invalid page header signature: {error}"))
    }

    pub fn hash(&self) -> [u8; 32] {
        self.header.hash()
    }
}

/// Owner/admin-signed cryptographic seal over a closed topic page (or over the
/// posts of `part == 0`). Once sealed, posts are immutable and bootstrap
/// verification reduces to checking this seal signature and `content_digest`.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct TopicPageSealV1 {
    pub topic_id: [u8; 32],
    pub part: u32,
    pub post_count: u32,
    pub action_count: u32,
    pub approval_count: u32,
    /// BLAKE3 digest over canonical CBOR of `(header, posts, actions, approvals)`
    /// for `part > 0`, or canonical CBOR of `posts` for `part == 0`.
    pub content_digest: [u8; 32],
    /// Next page number (always `part + 1`).
    pub next_part: u32,
    pub sealed_at: i64,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct AuthorizedTopicPageSealV1 {
    pub seal: TopicPageSealV1,
    pub signer: MemberId,
    pub signer_key: VerifyingKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<Box<AuthorityProof>>,
    pub signature: Signature,
}

impl AuthorizedTopicPageSealV1 {
    pub fn new(
        seal: TopicPageSealV1,
        signing_key: &SigningKey,
        authority: Option<AuthorityProof>,
    ) -> Self {
        let signer_key = signing_key.verifying_key();
        Self {
            signature: sign_struct(&seal, signing_key),
            signer: MemberId::from(&signer_key),
            signer_key,
            authority: authority.map(Box::new),
            seal,
        }
    }

    pub fn verify_signature(&self) -> Result<(), String> {
        if MemberId::from(&self.signer_key) != self.signer {
            return Err("page seal signer key does not match signer".to_string());
        }
        verify_struct(&self.seal, &self.signature, &self.signer_key)
            .map_err(|error| format!("invalid topic page seal signature: {error}"))
    }

    pub fn hash(&self) -> [u8; 32] {
        value_hash(&self.seal)
    }
}

pub(crate) fn verify_page_seal_authority(
    seal: &AuthorizedTopicPageSealV1,
    view: &ChatBoardStateV1,
    board_params: &ChatBoardParametersV1,
) -> Result<(), String> {
    seal.verify_signature()?;
    verify_owner_or_admin(
        view,
        board_params,
        &seal.signer,
        seal.authority.as_deref(),
        system_time_from_ms(seal.seal.sealed_at),
    )
    .map_err(|error| format!("unauthorized topic page seal: {error}"))
}

pub(crate) fn compare_seals(
    left: &AuthorizedTopicPageSealV1,
    right: &AuthorizedTopicPageSealV1,
) -> std::cmp::Ordering {
    left.seal
        .post_count
        .cmp(&right.seal.post_count)
        .then_with(|| right.seal.sealed_at.cmp(&left.seal.sealed_at))
        .then_with(|| right.seal.content_digest.cmp(&left.seal.content_digest))
        .then_with(|| right.signature.to_bytes().cmp(&left.signature.to_bytes()))
}

pub(crate) fn canonical_posts_digest(
    posts: &BTreeMap<MessageId, AuthorizedTopicPostV1>,
) -> Result<[u8; 32], String> {
    let bytes = encode(posts)?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

fn canonical_page_content_digest(
    header: &AuthorizedTopicPageHeaderV1,
    posts: &BTreeMap<MessageId, AuthorizedTopicPostV1>,
    actions: &[AuthorizedTopicActionV1],
    approvals: &[AuthorizedTopicApprovalV1],
) -> Result<[u8; 32], String> {
    let mut sorted_actions: Vec<&AuthorizedTopicActionV1> = actions.iter().collect();
    sorted_actions.sort_by_key(|a| {
        (
            a.action.target.0 .0,
            a.action.kind,
            a.action.generation,
            a.action.signer.0 .0,
            a.id(),
        )
    });
    let mut sorted_approvals: Vec<&AuthorizedTopicApprovalV1> = approvals.iter().collect();
    sorted_approvals.sort_by_key(|a| {
        (
            a.approval.target.0 .0,
            a.approval.generation,
            a.approval.signed_by.0 .0,
            value_hash(a),
        )
    });
    let bytes = encode(&(header, posts, sorted_actions, sorted_approvals))?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

fn is_page_post_action_kind(kind: TopicActionKind) -> bool {
    matches!(
        kind,
        TopicActionKind::Edit
            | TopicActionKind::Delete
            | TopicActionKind::Hide
            | TopicActionKind::Restore
            | TopicActionKind::Purge
            | TopicActionKind::Split
            | TopicActionKind::Approve
            | TopicActionKind::Reject
            | TopicActionKind::EditPoll
            | TopicActionKind::React
            | TopicActionKind::Unreact
            | TopicActionKind::Vote
    )
}

fn is_post_seal_admin_action_kind(kind: TopicActionKind) -> bool {
    matches!(
        kind,
        TopicActionKind::Edit
            | TopicActionKind::Delete
            | TopicActionKind::Hide
            | TopicActionKind::Restore
            | TopicActionKind::Purge
            | TopicActionKind::Split
    )
}

/// Compact append-only state for topic pages `part > 0`.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct TopicPageStateV1 {
    pub version: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<AuthorizedTopicPageHeaderV1>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal: Option<AuthorizedTopicPageSealV1>,
    #[serde(default)]
    pub post_seal_actions: Vec<AuthorizedTopicActionV1>,
}

impl Default for TopicPageStateV1 {
    fn default() -> Self {
        Self {
            version: PROTOCOL_VERSION,
            header: None,
            authority: TopicAuthorityV1::default(),
            participants: Vec::new(),
            trust: Vec::new(),
            posts: BTreeMap::new(),
            actions: Vec::new(),
            approvals: Vec::new(),
            generation: TopicGenerationV1::default(),
            seal: None,
            post_seal_actions: Vec::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct TopicPageDeltaV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<AuthorizedTopicPageHeaderV1>,
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
    pub seal: Option<AuthorizedTopicPageSealV1>,
    #[serde(default)]
    pub post_seal_actions: Vec<AuthorizedTopicActionV1>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct TopicPageSummaryV1 {
    pub version: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_hash: Option<[u8; 32]>,
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
    pub seal_hash: Option<[u8; 32]>,
    #[serde(default)]
    pub post_seal_actions: BTreeSet<[u8; 32]>,
}

impl Default for TopicPageSummaryV1 {
    fn default() -> Self {
        Self {
            version: PROTOCOL_VERSION,
            header_hash: None,
            authority_hash: None,
            participants: BTreeMap::new(),
            trust: BTreeMap::new(),
            posts: BTreeSet::new(),
            actions: BTreeSet::new(),
            approvals: BTreeMap::new(),
            generation: TopicGenerationV1::default(),
            seal_hash: None,
            post_seal_actions: BTreeSet::new(),
        }
    }
}

impl TopicPageStateV1 {
    pub fn is_sealed(&self) -> bool {
        self.seal.is_some()
    }

    pub fn is_closed_part(&self) -> bool {
        self.seal.is_some() || self.generation.closed_at.is_some()
    }

    pub fn max_posts(&self) -> usize {
        self.header
            .as_ref()
            .map(|h| h.header.max_posts as usize)
            .unwrap_or(DEFAULT_TOPIC_PAGE_SIZE)
    }

    pub fn is_full(&self) -> bool {
        self.posts.len() >= self.max_posts()
    }

    pub fn state_hash(&self) -> Result<[u8; 32], String> {
        let bytes = encode(self)?;
        Ok(*blake3::hash(&bytes).as_bytes())
    }

    pub fn content_digest(&self) -> Result<[u8; 32], String> {
        let header = self
            .header
            .as_ref()
            .ok_or("cannot compute content digest without a page header")?;
        canonical_page_content_digest(header, &self.posts, &self.actions, &self.approvals)
    }

    /// Build a `TopicPageSealV1` covering the current header, posts, actions,
    /// and approvals of this page.
    pub fn build_seal(&self, params: &TopicParamsV1, sealed_at: i64) -> Result<TopicPageSealV1, String> {
        if params.part == 0 {
            return Err("compact topic page seal requires part > 0".to_string());
        }
        let next_part = params.part + 1;
        if next_part > MAX_PARTS {
            return Err("cannot seal the final topic part".to_string());
        }
        Ok(TopicPageSealV1 {
            topic_id: params.topic_id,
            part: params.part,
            post_count: self.posts.len() as u32,
            action_count: self.actions.len() as u32,
            approval_count: self.approvals.len() as u32,
            content_digest: self.content_digest()?,
            next_part,
            sealed_at,
        })
    }

    /// Strip duplicated authority and participant records once sealed, keeping
    /// only `ownership` and `admins` so the seal and post-seal moderation
    /// actions remain verifiable.
    pub fn compact_for_seal(&mut self) {
        self.normalize();
        self.participants.clear();
        self.trust.clear();
        self.authority.roles = Default::default();
        self.authority.bans = Default::default();
        self.authority.ban_revocations = Default::default();
        self.authority.suspensions = Default::default();
        self.authority.policy = None;
        self.authority.source_configuration = None;
        self.authority.root = None;
        self.authority.member_proofs.clear();
        if let Some(seal) = &self.seal {
            if self.generation.closed_at.is_none() {
                self.generation.closed_at = Some(seal.seal.sealed_at);
            }
            self.generation.next_part = Some(seal.seal.next_part);
        }
    }

    pub fn board_view(&self, params: &TopicParamsV1) -> ChatBoardStateV1 {
        build_board_view(&self.authority, &self.participants, params)
    }

    pub fn verify(&self, params: &TopicParamsV1) -> Result<(), String> {
        if !self.verify_shape(params)? {
            return Ok(());
        }
        let board_params = params.board_parameters();
        if self.seal.is_some() {
            return self.verify_sealed(params, &board_params);
        }

        verify_participants_list(&self.authority, &self.participants, params, &board_params)?;
        let view = self.board_view(params);
        verify_authority_records(&self.authority, &view, &board_params)?;
        self.verify_header_creator(&view, &board_params, params)?;
        self.verify_trust(&view, &board_params)?;
        for (id, entry) in &self.posts {
            self.verify_post_record(id, entry, &view, &board_params, params)?;
        }
        for entry in &self.actions {
            self.verify_action_record(entry, &view, &board_params)?;
        }
        for entry in &self.approvals {
            self.verify_approval_record(entry, &view, &board_params)?;
        }
        Ok(())
    }

    fn verify_shape(&self, params: &TopicParamsV1) -> Result<bool, String> {
        params.verify()?;
        if params.part == 0 {
            return Err("compact topic pages require part > 0".to_string());
        }
        if self.version != PROTOCOL_VERSION {
            return Err(format!("unsupported topic page version {}", self.version));
        }

        let Some(header) = &self.header else {
            if !self.participants.is_empty()
                || !self.trust.is_empty()
                || !self.posts.is_empty()
                || !self.actions.is_empty()
                || !self.approvals.is_empty()
                || self.seal.is_some()
                || !self.post_seal_actions.is_empty()
            {
                return Err("a topic page without a header cannot carry content".to_string());
            }
            return Ok(false);
        };

        header.verify(params)?;
        if self.generation.part != params.part {
            return Err("page generation does not match the parameters".to_string());
        }
        if self.generation.next_part.is_some() && self.generation.closed_at.is_none() {
            return Err("a continued topic page must be closed".to_string());
        }
        if self
            .generation
            .next_part
            .is_some_and(|part| part != params.part + 1 || part > MAX_PARTS)
        {
            return Err("the next topic page part is invalid".to_string());
        }
        if self.generation.closed_at.is_some() && self.seal.is_none() {
            let at_capacity = self.posts.len() >= header.header.max_posts as usize
                || encode(self)
                    .map(|bytes| bytes.len() >= MAX_TOPIC_PAGE_BYTES * 3 / 4)
                    .unwrap_or(false);
            if !at_capacity {
                return Err(
                    "an unsealed topic page cannot be closed before reaching capacity".to_string(),
                );
            }
        }
        if self.generation.previous_hash != Some(header.header.previous_hash) {
            return Err("page generation previous_hash does not match page header".to_string());
        }
        if self.posts.len() > header.header.max_posts as usize
            || self.posts.len() > MAX_TOPIC_PAGE_POSTS
        {
            return Err("too many posts on topic page".to_string());
        }
        if self.participants.len() > MAX_TOPIC_PAGE_PARTICIPANTS {
            return Err("too many participants on topic page".to_string());
        }
        if self.actions.len() > MAX_TOPIC_PAGE_ACTIONS {
            return Err("too many actions on topic page".to_string());
        }
        if self.approvals.len() > MAX_TOPIC_PAGE_APPROVALS {
            return Err("too many approvals on topic page".to_string());
        }
        if self.post_seal_actions.len() > MAX_POST_SEAL_ACTIONS {
            return Err("too many post-seal actions on topic page".to_string());
        }
        if self.seal.is_none() {
            if !self.post_seal_actions.is_empty() {
                return Err("post_seal_actions are only allowed on sealed pages".to_string());
            }
            if self.trust.len() > self.participants.len() {
                return Err("too many trust records on topic page".to_string());
            }
        }
        Ok(true)
    }

    fn verify_sealed(
        &self,
        params: &TopicParamsV1,
        board_params: &ChatBoardParametersV1,
    ) -> Result<(), String> {
        let seal = self.seal.as_ref().ok_or("missing topic page seal")?;
        if !self.participants.is_empty()
            || !self.trust.is_empty()
            || !self.authority.roles.roles.is_empty()
            || !self.authority.roles.assignments.is_empty()
            || !self.authority.bans.0.is_empty()
            || !self.authority.ban_revocations.revocations.is_empty()
            || !self.authority.suspensions.suspensions.is_empty()
            || self.authority.policy.is_some()
            || self.authority.source_configuration.is_some()
            || self.authority.root.is_some()
            || !self.authority.member_proofs.is_empty()
        {
            return Err("sealed topic page must be compacted".to_string());
        }
        if seal.seal.topic_id != params.topic_id || seal.seal.part != params.part {
            return Err("topic page seal does not match parameters".to_string());
        }
        if seal.seal.next_part != params.part + 1 {
            return Err("topic page seal next_part is invalid".to_string());
        }
        if seal.seal.post_count as usize != self.posts.len()
            || seal.seal.action_count as usize != self.actions.len()
            || seal.seal.approval_count as usize != self.approvals.len()
        {
            return Err("topic page seal counts do not match content".to_string());
        }
        if seal.seal.content_digest != self.content_digest()? {
            return Err("topic page seal digest mismatch".to_string());
        }

        let view = self.board_view(params);
        self.authority.ownership.verify(&view, board_params)?;
        self.authority.admins.verify(&view, board_params)?;
        verify_page_seal_authority(seal, &view, board_params)?;

        for entry in &self.post_seal_actions {
            self.verify_post_seal_action_record(entry, &view, board_params)?;
        }
        Ok(())
    }

    fn verify_header_creator(
        &self,
        view: &ChatBoardStateV1,
        board_params: &ChatBoardParametersV1,
        params: &TopicParamsV1,
    ) -> Result<(), String> {
        let header = self.header.as_ref().ok_or("missing page header")?;
        let creator = header.header.creator;
        let at = system_time_from_ms(header.header.created_at);
        let owner_at = self.authority.ownership.owner_at(board_params, at);
        if creator == owner_at {
            let owner_key = self.authority.ownership.owner_key_at(board_params, at);
            if header.creator_key != owner_key {
                return Err("page creator key does not match board owner".to_string());
            }
            return Ok(());
        }
        let participant = self
            .participants
            .iter()
            .find(|p| p.record.member_id == creator)
            .ok_or("page creator is not a participant")?;
        if participant.record.member_vk != header.creator_key {
            return Err("page creator key does not match participant".to_string());
        }
        if is_member_banned(&self.authority, creator, header.header.created_at) {
            return Err("a banned member cannot open a topic page".to_string());
        }
        if is_member_suspended(&self.authority, creator, header.header.created_at) {
            return Err("a suspended member cannot open a topic page".to_string());
        }
        if !self.section_allows(creator, view, board_params, params) {
            return Err("page creator cannot write in this section".to_string());
        }
        Ok(())
    }

    fn section_chain(&self) -> &[SectionId] {
        self.header
            .as_ref()
            .map(|h| h.header.section_chain.as_slice())
            .unwrap_or(&[])
    }

    fn section_images_allowed(&self) -> bool {
        self.header
            .as_ref()
            .map(|h| h.header.images_allowed)
            .unwrap_or(true)
    }

    fn section_allows(
        &self,
        author: MemberId,
        view: &ChatBoardStateV1,
        board_params: &ChatBoardParametersV1,
        _params: &TopicParamsV1,
    ) -> bool {
        let Some(header) = &self.header else {
            return true;
        };
        if header.header.allowed_roles.is_empty() {
            return true;
        }
        let owner = self.authority.ownership.current_owner(board_params);
        if author == owner || view.admin.admins.iter().any(|a| a.admin.id() == author) {
            return true;
        }
        view.roles
            .active_roles_of(&author)
            .iter()
            .any(|role| header.header.allowed_roles.contains(&role.id))
    }

    fn author_key(
        &self,
        author: MemberId,
        view: &ChatBoardStateV1,
        board_params: &ChatBoardParametersV1,
        at: i64,
        params: &TopicParamsV1,
    ) -> Result<VerifyingKey, String> {
        let owner_at_key = self
            .authority
            .ownership
            .owner_key_at(board_params, system_time_from_ms(at));
        if author == MemberId::from(&owner_at_key) {
            return Ok(owner_at_key);
        }
        if author == params.owner_id() {
            return Ok(params.board_owner);
        }
        if let Some(participant) = self
            .participants
            .iter()
            .find(|p| p.record.member_id == author)
        {
            return Ok(participant.record.member_vk);
        }
        resolve_signer_key(view, board_params, &author, None)
    }

    fn verify_trust(
        &self,
        view: &ChatBoardStateV1,
        board_params: &ChatBoardParametersV1,
    ) -> Result<(), String> {
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
            verify_moderation_authority(
                view,
                board_params,
                &signer,
                ModerationPower::Delete,
                self.section_chain(),
                entry.authority.as_deref(),
                system_time_from_ms(entry.trust.created_at),
            )?;
        }
        Ok(())
    }

    fn verify_post_record(
        &self,
        id: &MessageId,
        entry: &AuthorizedTopicPostV1,
        view: &ChatBoardStateV1,
        board_params: &ChatBoardParametersV1,
        params: &TopicParamsV1,
    ) -> Result<(), String> {
        let policy = self.authority.policy();
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
        if !post.images.is_empty() && !policy.images_allowed {
            return Err("images are disabled by the topic policy".to_string());
        }
        if !post.images.is_empty() && !self.section_images_allowed() {
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

        let author_key =
            self.author_key(post.author, view, board_params, post.created_at, params)?;
        verify_struct(post, &entry.signature, &author_key)
            .map_err(|error| format!("invalid post signature: {error}"))?;

        let owner_at = self
            .authority
            .ownership
            .owner_at(board_params, system_time_from_ms(post.created_at));
        if post.author == owner_at {
            return Ok(());
        }
        if is_member_banned(&self.authority, post.author, post.created_at) {
            return Err("a banned member cannot post".to_string());
        }
        if is_member_suspended(&self.authority, post.author, post.created_at) {
            return Err("a suspended member cannot post".to_string());
        }
        if policy.read_only
            && !view
                .admin
                .admins
                .iter()
                .any(|admin| admin.admin.id() == post.author)
        {
            return Err("the topic is read-only".to_string());
        }
        if !self.section_allows(post.author, view, board_params, params) {
            return Err("the author cannot write in this section".to_string());
        }
        Ok(())
    }

    fn verify_action_record(
        &self,
        entry: &AuthorizedTopicActionV1,
        view: &ChatBoardStateV1,
        board_params: &ChatBoardParametersV1,
    ) -> Result<(), String> {
        let action = &entry.action;
        if !is_page_post_action_kind(action.kind) {
            return Err("topic-level actions belong on part 0".to_string());
        }
        if action.payload.declared_len() > MAX_BODY_BYTES {
            return Err("action payload is too large".to_string());
        }
        let target_post = self
            .posts
            .get(&action.target)
            .ok_or("action target does not exist on this page")?;
        let target_author = target_post.post.author;

        let signer = action.signer;
        let key = resolve_signer_key(view, board_params, &signer, entry.signer_key.as_ref())?;
        verify_struct(action, &entry.signature, &key)
            .map_err(|error| format!("invalid action signature: {error}"))?;

        if matches!(
            action.kind,
            TopicActionKind::React | TopicActionKind::Unreact | TopicActionKind::Vote
        ) {
            if action.payload.declared_len() > MAX_REACTION_PAYLOAD_BYTES {
                return Err("reaction or vote payload is too large".to_string());
            }
            if matches!(action.kind, TopicActionKind::React | TopicActionKind::Unreact)
                && !self.authority.policy().reactions_enabled
            {
                return Err("reactions are disabled by the topic policy".to_string());
            }
            let is_member = signer == board_params.owner_id()
                || self
                    .participants
                    .iter()
                    .any(|participant| participant.record.member_id == signer);
            if !is_member {
                return Err("only a board member can react or vote".to_string());
            }
            if is_member_banned(&self.authority, signer, action.created_at)
                || is_member_suspended(&self.authority, signer, action.created_at)
            {
                return Err("a banned or suspended member cannot react or vote".to_string());
            }
            return Ok(());
        }

        if signer == target_author
            && matches!(
                action.kind,
                TopicActionKind::Edit | TopicActionKind::Delete | TopicActionKind::EditPoll
            )
        {
            if signer != board_params.owner_id()
                && (is_member_banned(&self.authority, signer, action.created_at)
                    || is_member_suspended(&self.authority, signer, action.created_at))
            {
                return Err("a banned or suspended member cannot modify posts".to_string());
            }
            return Ok(());
        }

        let at = system_time_from_ms(action.created_at);
        if action.kind == TopicActionKind::Purge {
            verify_owner_or_admin(view, board_params, &signer, entry.authority.as_deref(), at)?;
            return Ok(());
        }
        let power = action
            .kind
            .power()
            .ok_or("the action has no moderation power")?;
        verify_moderation_authority(
            view,
            board_params,
            &signer,
            power,
            self.section_chain(),
            entry.authority.as_deref(),
            at,
        )?;
        Ok(())
    }

    fn verify_post_seal_action_record(
        &self,
        entry: &AuthorizedTopicActionV1,
        view: &ChatBoardStateV1,
        board_params: &ChatBoardParametersV1,
    ) -> Result<(), String> {
        let action = &entry.action;
        if action.payload.declared_len() > MAX_BODY_BYTES {
            return Err("post-seal action payload is too large".to_string());
        }
        let target_post = self
            .posts
            .get(&action.target)
            .ok_or("post-seal action target does not exist on this page")?;
        let signer = action.signer;

        // Post author can edit/delete their own post on a sealed page using
        // their verifying key directly (MemberId == hash(vk)), without needing
        // the stripped participants table.
        if signer == target_post.post.author
            && matches!(
                action.kind,
                TopicActionKind::Edit | TopicActionKind::Delete | TopicActionKind::EditPoll
            )
        {
            let key = entry
                .signer_key
                .ok_or("post-seal author action requires signer_key")?;
            if MemberId::from(&key) != signer {
                return Err("post-seal author signer_key does not match signer".to_string());
            }
            verify_struct(action, &entry.signature, &key)
                .map_err(|error| format!("invalid post-seal author action signature: {error}"))?;
            return Ok(());
        }

        if !is_post_seal_admin_action_kind(action.kind) {
            return Err("action kind is not allowed on a sealed topic page".to_string());
        }
        let key = resolve_signer_key(view, board_params, &signer, entry.signer_key.as_ref())?;
        verify_struct(action, &entry.signature, &key)
            .map_err(|error| format!("invalid post-seal action signature: {error}"))?;
        verify_owner_or_admin(
            view,
            board_params,
            &signer,
            entry.authority.as_deref(),
            system_time_from_ms(action.created_at),
        )?;
        Ok(())
    }

    fn verify_approval_record(
        &self,
        entry: &AuthorizedTopicApprovalV1,
        view: &ChatBoardStateV1,
        board_params: &ChatBoardParametersV1,
    ) -> Result<(), String> {
        let approval = &entry.approval;
        if !self.posts.contains_key(&approval.target) {
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
        verify_moderation_authority(
            view,
            board_params,
            &signer,
            ModerationPower::Delete,
            self.section_chain(),
            entry.authority.as_deref(),
            system_time_from_ms(approval.created_at),
        )?;
        Ok(())
    }

    fn apply_delta_merge(
        &mut self,
        params: &TopicParamsV1,
        delta: &TopicPageDeltaV1,
    ) -> Result<bool, String> {
        let was_sealed = self.seal.is_some();
        if let Some(header) = &delta.header {
            header.verify(params)?;
            match &self.header {
                None => {
                    self.header = Some(header.clone());
                    if self.generation.part == 0 {
                        self.generation = TopicGenerationV1 {
                            part: params.part,
                            closed_at: None,
                            next_part: None,
                            previous_hash: Some(header.header.previous_hash),
                        };
                    }
                }
                Some(existing) if existing == header => {}
                Some(_) => return Err("topic page header is immutable".to_string()),
            }
        }

        let already_closed = was_sealed || self.generation.closed_at.is_some();
        let closing_without_seal = delta.seal.is_none()
            && delta
                .generation
                .as_ref()
                .is_some_and(|generation| generation.closed_at.is_some());
        if (already_closed || closing_without_seal) && !delta.posts.is_empty() {
            return Err("the topic page is closed to new posts".to_string());
        }

        if was_sealed {
            if !delta.participants.is_empty()
                || !delta.trust.is_empty()
                || !delta.approvals.is_empty()
                || !delta.actions.is_empty()
            {
                return Err("cannot modify sealed content on a sealed topic page".to_string());
            }
            if let Some(incoming_seal) = &delta.seal {
                if self.seal.as_ref() != Some(incoming_seal) {
                    return Err("cannot replace an existing topic page seal".to_string());
                }
            }
            if let Some(authority) = &delta.authority {
                self.authority.ownership =
                    merge_ownership(&self.authority.ownership, &authority.ownership);
                self.authority.admins = merge_admins(&self.authority.admins, &authority.admins);
            }
            if let Some(generation) = &delta.generation {
                self.generation = merge_generation(&self.generation, generation);
            }
            for action in &delta.post_seal_actions {
                let id = action.id();
                if !self.post_seal_actions.iter().any(|existing| existing.id() == id) {
                    self.post_seal_actions.push(action.clone());
                }
            }
            return Ok(false);
        }

        // Open page path (possibly transitioning to sealed in this delta).
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
        if !delta.posts.is_empty() && delta.seal.is_none() {
            check_posts_rate_limit(&self.authority, &self.posts, &delta.posts)?;
        }

        let mut just_sealed = false;
        if let Some(seal) = &delta.seal {
            // Verify seal matches current content before compacting.
            let board_params = params.board_parameters();
            let view = self.board_view(params);
            self.authority.ownership.verify(&view, &board_params)?;
            self.authority.admins.verify(&view, &board_params)?;
            verify_page_seal_authority(seal, &view, &board_params)?;
            if seal.seal.topic_id != params.topic_id
                || seal.seal.part != params.part
                || seal.seal.next_part != params.part + 1
            {
                return Err("topic page seal does not match parameters".to_string());
            }
            if seal.seal.post_count as usize != self.posts.len()
                || seal.seal.action_count as usize != self.actions.len()
                || seal.seal.approval_count as usize != self.approvals.len()
                || seal.seal.content_digest != self.content_digest()?
            {
                return Err("topic page seal does not match current page content".to_string());
            }
            self.seal = Some(seal.clone());
            self.compact_for_seal();
            just_sealed = true;
        }

        for action in &delta.post_seal_actions {
            if self.seal.is_none() {
                return Err("post_seal_actions require a sealed page".to_string());
            }
            let id = action.id();
            if !self.post_seal_actions.iter().any(|existing| existing.id() == id) {
                self.post_seal_actions.push(action.clone());
            }
        }
        Ok(just_sealed)
    }

    fn verify_incremental(
        &self,
        params: &TopicParamsV1,
        delta: &TopicPageDeltaV1,
        just_sealed: bool,
    ) -> Result<(), String> {
        if !self.verify_shape(params)? {
            return Ok(());
        }
        let board_params = params.board_parameters();
        if self.seal.is_some() {
            if just_sealed || delta.authority.is_some() {
                return self.verify_sealed(params, &board_params);
            }
            let view = self.board_view(params);
            for entry in &delta.post_seal_actions {
                self.verify_post_seal_action_record(entry, &view, &board_params)?;
            }
            return Ok(());
        }

        let view = self.board_view(params);
        if delta.authority.is_some() {
            verify_authority_records(&self.authority, &view, &board_params)?;
        }
        if !delta.participants.is_empty() {
            verify_participants_list(&self.authority, &self.participants, params, &board_params)?;
        }
        if delta.header.is_some() {
            self.verify_header_creator(&view, &board_params, params)?;
        }
        if !delta.trust.is_empty() {
            self.verify_trust(&view, &board_params)?;
        }
        for entry in &delta.posts {
            self.verify_post_record(&entry.post.id(), entry, &view, &board_params, params)?;
        }
        for entry in &delta.actions {
            self.verify_action_record(entry, &view, &board_params)?;
        }
        for entry in &delta.approvals {
            self.verify_approval_record(entry, &view, &board_params)?;
        }
        Ok(())
    }

    pub fn apply_delta(
        &mut self,
        params: &TopicParamsV1,
        delta: &TopicPageDeltaV1,
    ) -> Result<(), String> {
        let mut next = self.clone();
        let _ = next.apply_delta_merge(params, delta)?;
        next.verify(params)?;
        *self = next;
        Ok(())
    }

    pub fn apply_delta_incremental(
        &mut self,
        params: &TopicParamsV1,
        delta: &TopicPageDeltaV1,
    ) -> Result<(), String> {
        let mut next = self.clone();
        let just_sealed = next.apply_delta_merge(params, delta)?;
        next.verify_incremental(params, delta, just_sealed)?;
        *self = next;
        Ok(())
    }

    pub fn merge(
        &mut self,
        params: &TopicParamsV1,
        other: &TopicPageStateV1,
    ) -> Result<(), String> {
        if other.header.is_none() {
            return self.verify(params);
        }
        if self.header.is_none() {
            *self = other.clone();
            self.normalize();
            return self.verify(params);
        }

        match (&self.header, &other.header) {
            (Some(left), Some(right)) if left == right => {}
            _ => return Err("cannot merge two different topic page headers".to_string()),
        }

        let take_other_sealed = match (&self.seal, &other.seal) {
            (None, Some(_)) => true,
            (Some(_), None) => false,
            (Some(left), Some(right)) => {
                compare_seals(right, left) == std::cmp::Ordering::Greater
            }
            (None, None) => false,
        };

        if self.seal.is_some() || other.seal.is_some() {
            let mut merged_post_seal = self.post_seal_actions.clone();
            for action in &other.post_seal_actions {
                let id = action.id();
                if !merged_post_seal.iter().any(|existing| existing.id() == id) {
                    merged_post_seal.push(action.clone());
                }
            }
            let merged_ownership =
                merge_ownership(&self.authority.ownership, &other.authority.ownership);
            let merged_admins = merge_admins(&self.authority.admins, &other.authority.admins);
            let merged_gen = merge_generation(&self.generation, &other.generation);

            if take_other_sealed {
                *self = other.clone();
            }
            self.authority.ownership = merged_ownership;
            self.authority.admins = merged_admins;
            self.generation = merged_gen;
            merged_post_seal.retain(|action| self.posts.contains_key(&action.action.target));
            self.post_seal_actions = merged_post_seal;
            self.compact_for_seal();
            self.normalize();
            return self.verify(params);
        }

        // Both unsealed: standard additive merge.
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
        let sort_actions = |actions: &mut Vec<AuthorizedTopicActionV1>| {
            actions.sort_by_key(|a| {
                (
                    a.action.target.0 .0,
                    a.action.kind,
                    a.action.generation,
                    a.action.signer.0 .0,
                    a.id(),
                )
            });
            actions.dedup_by_key(|a| a.id());
        };
        sort_actions(&mut self.actions);
        sort_actions(&mut self.post_seal_actions);
        self.approvals.sort_by_key(|a| {
            (
                a.approval.target.0 .0,
                a.approval.generation,
                a.approval.signed_by.0 .0,
            )
        });
    }

    pub fn summarize(&self) -> TopicPageSummaryV1 {
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
        TopicPageSummaryV1 {
            version: self.version,
            header_hash: self.header.as_ref().map(AuthorizedTopicPageHeaderV1::hash),
            authority_hash: self.header.as_ref().map(|_| value_hash(&self.authority)),
            participants,
            trust,
            posts: self.posts.keys().copied().collect(),
            actions: self.actions.iter().map(AuthorizedTopicActionV1::id).collect(),
            approvals,
            generation: self.generation.clone(),
            seal_hash: self.seal.as_ref().map(AuthorizedTopicPageSealV1::hash),
            post_seal_actions: self
                .post_seal_actions
                .iter()
                .map(AuthorizedTopicActionV1::id)
                .collect(),
        }
    }

    pub fn delta(&self, summary: &TopicPageSummaryV1) -> Option<TopicPageDeltaV1> {
        let mut delta = TopicPageDeltaV1::default();
        let header_hash = self.header.as_ref().map(AuthorizedTopicPageHeaderV1::hash);
        if summary.header_hash != header_hash {
            delta.header = self.header.clone();
        }
        let my_seal_hash = self.seal.as_ref().map(AuthorizedTopicPageSealV1::hash);
        let peer_has_same_seal = my_seal_hash.is_some() && summary.seal_hash == my_seal_hash;

        if self.header.is_some() && summary.authority_hash != Some(value_hash(&self.authority)) {
            delta.authority = Some(self.authority.clone());
        }

        if !peer_has_same_seal {
            for participant in &self.participants {
                if summary.participants.get(&participant.record.member_id)
                    != Some(&participant.hash())
                {
                    delta.participants.push(participant.clone());
                }
            }
            for entry in &self.trust {
                let known = summary
                    .trust
                    .get(&entry.trust.member_id)
                    .copied()
                    .unwrap_or(0);
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
            if summary.seal_hash != my_seal_hash {
                delta.seal = self.seal.clone();
            }
        }

        for action in &self.post_seal_actions {
            if !summary.post_seal_actions.contains(&action.id()) {
                delta.post_seal_actions.push(action.clone());
            }
        }
        if summary.generation != self.generation {
            delta.generation = Some(self.generation.clone());
        }

        if delta.header.is_none()
            && delta.authority.is_none()
            && delta.participants.is_empty()
            && delta.trust.is_empty()
            && delta.posts.is_empty()
            && delta.actions.is_empty()
            && delta.approvals.is_empty()
            && delta.generation.is_none()
            && delta.seal.is_none()
            && delta.post_seal_actions.is_empty()
        {
            None
        } else {
            Some(delta)
        }
    }

    pub fn is_banned_member(&self, member: MemberId, at_ms: i64) -> bool {
        is_member_banned(&self.authority, member, at_ms)
    }

    pub fn is_suspended_member(&self, member: MemberId, at_ms: i64) -> bool {
        is_member_suspended(&self.authority, member, at_ms)
    }

    pub fn is_trusted(&self, member: MemberId) -> bool {
        self.trust
            .iter()
            .filter(|entry| entry.trust.member_id == member)
            .max_by_key(|entry| entry.trust.generation)
            .map(|entry| entry.trust.trusted)
            .unwrap_or(false)
    }

    pub fn all_actions(&self) -> impl Iterator<Item = &AuthorizedTopicActionV1> {
        self.actions.iter().chain(self.post_seal_actions.iter())
    }

    pub fn latest_action(
        &self,
        target: MessageId,
        kind: TopicActionKind,
    ) -> Option<&AuthorizedTopicActionV1> {
        self.all_actions()
            .filter(|entry| entry.action.target == target && entry.action.kind == kind)
            .max_by(|a, b| {
                a.action
                    .generation
                    .cmp(&b.action.generation)
                    .then_with(|| b.id().cmp(&a.id()))
            })
    }

    pub fn is_deleted(&self, target: MessageId) -> bool {
        let delete = self
            .all_actions()
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
                (delete.action.generation, std::cmp::Reverse(delete.id()))
                    > (restore.action.generation, std::cmp::Reverse(restore.id()))
            }
            (Some(_), None) => true,
            _ => false,
        }
    }

    pub fn is_split(&self, post_id: MessageId) -> bool {
        self.latest_action(post_id, TopicActionKind::Split).is_some()
    }

    pub fn split_target(&self, post_id: MessageId) -> Option<MessageId> {
        let action = self.latest_action(post_id, TopicActionKind::Split)?;
        let plaza_core::board_state::privacy::SealedBytes::Public { value } = &action.action.payload
        else {
            return None;
        };
        let bytes: [u8; 32] = value.as_slice().try_into().ok()?;
        Some(MessageId::from_bytes(bytes))
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

    pub fn post_is_visible(&self, post: &AuthorizedTopicPostV1, head_trusted: bool) -> bool {
        let author = post.post.author;
        let topic_author = self
            .header
            .as_ref()
            .map(|h| h.header.topic_author)
            .unwrap_or(author);
        !self.is_deleted(post.id())
            && (head_trusted
                || self.is_trusted(author)
                || !self.authority.policy().approval_required
                || self
                    .approval_for(post.id())
                    .map(|entry| entry.approval.approved)
                    .unwrap_or(false)
                || author == topic_author)
    }
}

pub fn decode_page_state(bytes: &[u8]) -> Result<TopicPageStateV1, String> {
    ciborium::de::from_reader(bytes).map_err(|error| error.to_string())
}

pub fn decode_page_delta(bytes: &[u8]) -> Result<TopicPageDeltaV1, String> {
    ciborium::de::from_reader(bytes).map_err(|error| error.to_string())
}

pub fn decode_page_summary(bytes: &[u8]) -> Result<TopicPageSummaryV1, String> {
    ciborium::de::from_reader(bytes).map_err(|error| error.to_string())
}

#[cfg(test)]
mod page_tests {
    use super::*;
    use crate::{
        AuthorizedTopicHeaderV1, AuthorizedTopicPolicyV1, ParticipantCertificateV1,
        ParticipantRecordV1, PostEditV1, TopicActionV1, TopicApprovalV1, TopicDeltaV1,
        TopicHeaderV1, TopicPolicyV1, TopicPostV1, TopicStateV1,
    };
    use plaza_core::board_state::admin::{Admin, AuthorizedAdmin};
    use plaza_core::board_state::ban::{AuthorizedUserBan, UserBan};
    use plaza_core::board_state::member::{AuthorizedMember, Member};
    use plaza_core::board_state::privacy::SealedBytes;
    use plaza_core::board_state::rate_limit::system_time_from_ms;
    use plaza_core::board_state::roles::{
        AuthorizedRole, AuthorizedRoleAssignment, Role, RoleAssignment, RoleId,
    };
    use std::time::Instant;

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn owner() -> SigningKey {
        key(1)
    }

    fn member() -> SigningKey {
        key(2)
    }

    fn member_b() -> SigningKey {
        key(3)
    }

    fn outsider() -> SigningKey {
        key(4)
    }

    fn admin_key() -> SigningKey {
        key(5)
    }

    fn page_params(part: u32) -> TopicParamsV1 {
        TopicParamsV1::new(owner().verifying_key(), [9u8; 32], part)
    }

    fn participant(sk: &SigningKey) -> AuthorizedParticipantV1 {
        let member = AuthorizedMember::new(
            Member {
                owner_member_id: MemberId::from(&owner().verifying_key()),
                invited_by: MemberId::from(&owner().verifying_key()),
                member_vk: sk.verifying_key(),
                join_proof: None,
            },
            &owner(),
        );
        let record = ParticipantRecordV1 {
            member_id: MemberId::from(&sk.verifying_key()),
            member_vk: sk.verifying_key(),
            certificate: ParticipantCertificateV1 {
                member,
                chain: Vec::new(),
                token: None,
                join_proof: None,
            },
            joined_at: 500,
        };
        AuthorizedParticipantV1::new(record, sk)
    }

    fn authority_with_policy() -> TopicAuthorityV1 {
        let mut policy = TopicPolicyV1::default();
        policy.updated_at = 100;
        TopicAuthorityV1 {
            policy: Some(AuthorizedTopicPolicyV1::new(policy, &owner())),
            ..Default::default()
        }
    }

    fn make_post(sk: &SigningKey, text: &str, created_at: i64, nonce_byte: u8) -> AuthorizedTopicPostV1 {
        let post = TopicPostV1 {
            author: MemberId::from(&sk.verifying_key()),
            parent: None,
            content: SealedBytes::public(text.as_bytes().to_vec()),
            images: Vec::new(),
            created_at,
            nonce: [nonce_byte; 16],
        };
        AuthorizedTopicPostV1::new(post, sk)
    }

    fn base_page(part: u32) -> TopicPageStateV1 {
        let header = TopicPageHeaderV1 {
            topic_id: [9u8; 32],
            part,
            header_hash: [0x11u8; 32],
            previous_hash: [0x22u8; 32],
            topic_author: MemberId::from(&owner().verifying_key()),
            auto_moderated: false,
            section_chain: Vec::new(),
            allowed_roles: Vec::new(),
            images_allowed: true,
            max_posts: DEFAULT_TOPIC_PAGE_SIZE as u32,
            creator: MemberId::from(&owner().verifying_key()),
            created_at: 1_000,
        };
        TopicPageStateV1 {
            version: PROTOCOL_VERSION,
            header: Some(AuthorizedTopicPageHeaderV1::new(header, &owner())),
            authority: authority_with_policy(),
            participants: vec![participant(&member())],
            trust: Vec::new(),
            posts: BTreeMap::new(),
            actions: Vec::new(),
            approvals: Vec::new(),
            generation: TopicGenerationV1 {
                part,
                closed_at: None,
                next_part: None,
                previous_hash: Some([0x22u8; 32]),
            },
            seal: None,
            post_seal_actions: Vec::new(),
        }
    }

    #[test]
    fn compact_page_verifies_and_rejects_part_zero() {
        let page = base_page(1);
        page.verify(&page_params(1)).unwrap();
        assert!(page.verify(&page_params(0)).is_err());
    }

    #[test]
    fn member_can_open_a_compact_page_without_owner_online() {
        let header = TopicPageHeaderV1 {
            topic_id: [9u8; 32],
            part: 1,
            header_hash: [0x11u8; 32],
            previous_hash: [0x22u8; 32],
            topic_author: MemberId::from(&owner().verifying_key()),
            auto_moderated: false,
            section_chain: Vec::new(),
            allowed_roles: Vec::new(),
            images_allowed: true,
            max_posts: 50,
            creator: MemberId::from(&member().verifying_key()),
            created_at: 1_000,
        };
        let page = TopicPageStateV1 {
            version: PROTOCOL_VERSION,
            header: Some(AuthorizedTopicPageHeaderV1::new(header, &member())),
            authority: authority_with_policy(),
            participants: vec![participant(&member())],
            generation: TopicGenerationV1 {
                part: 1,
                closed_at: None,
                next_part: None,
                previous_hash: Some([0x22u8; 32]),
            },
            ..Default::default()
        };
        page.verify(&page_params(1)).unwrap();

        // Outsider without a valid participant certificate cannot open a page.
        let mut bad_header = page.header.as_ref().unwrap().header.clone();
        bad_header.creator = MemberId::from(&outsider().verifying_key());
        let mut bad_page = page.clone();
        bad_page.header = Some(AuthorizedTopicPageHeaderV1::new(bad_header, &outsider()));
        assert!(bad_page.verify(&page_params(1)).is_err());
    }

    #[test]
    fn incremental_reply_and_summary_delta_on_open_page() {
        let params = page_params(1);
        let mut page = base_page(1);
        let p1 = make_post(&member(), "first reply", 2_000, 1);
        let p2 = make_post(&member_b(), "second reply", 65_000, 2);

        page.apply_delta_incremental(
            &params,
            &TopicPageDeltaV1 {
                posts: vec![p1.clone()],
                ..Default::default()
            },
        )
        .unwrap();
        let summary_after_p1 = page.summarize();

        page.apply_delta_incremental(
            &params,
            &TopicPageDeltaV1 {
                participants: vec![participant(&member_b())],
                posts: vec![p2.clone()],
                ..Default::default()
            },
        )
        .unwrap();
        page.verify(&params).unwrap();

        let delta = page.delta(&summary_after_p1).expect("delta should contain p2");
        assert!(delta.header.is_none());
        assert_eq!(delta.posts.len(), 1);
        assert_eq!(delta.posts[0].id(), p2.id());
        assert_eq!(delta.participants.len(), 1);
        assert_eq!(delta.participants[0].record.member_id, MemberId::from(&member_b().verifying_key()));

        // Summary of current state produces no delta.
        assert!(page.delta(&page.summarize()).is_none());
    }

    #[test]
    fn topic_level_actions_are_rejected_on_compact_page() {
        let params = page_params(1);
        let mut page = base_page(1);
        let p1 = make_post(&member(), "reply", 2_000, 1);
        page.posts.insert(p1.id(), p1.clone());

        let action = TopicActionV1 {
            kind: TopicActionKind::Pin,
            target: p1.id(),
            payload: SealedBytes::public(Vec::new()),
            generation: 1,
            created_at: 3_000,
            signer: MemberId::from(&owner().verifying_key()),
        };
        let auth = AuthorizedTopicActionV1 {
            signature: sign_struct(&action, &owner()),
            action,
            signer_key: Some(owner().verifying_key()),
            authority: None,
        };
        assert!(page
            .apply_delta_incremental(
                &params,
                &TopicPageDeltaV1 {
                    actions: vec![auth],
                    ..Default::default()
                },
            )
            .is_err());
    }

    #[test]
    fn banned_and_unauthorized_role_members_cannot_post_on_page() {
        let params = page_params(1);
        let mut page = base_page(1);
        let ban = AuthorizedUserBan::new(
            UserBan {
                owner_member_id: MemberId::from(&owner().verifying_key()),
                banned_at: system_time_from_ms(1_500),
                banned_user: MemberId::from(&member().verifying_key()),
                expires_at: None,
                target_member: None,
                invite_chain: Vec::new(),
            },
            MemberId::from(&owner().verifying_key()),
            &owner(),
        );
        page.authority.bans.0.push(ban);

        let p = make_post(&member(), "after ban", 2_000, 1);
        assert!(page
            .apply_delta_incremental(
                &params,
                &TopicPageDeltaV1 {
                    posts: vec![p],
                    ..Default::default()
                },
            )
            .is_err());

        // Role-restricted page blocks member without the role, admits member with role.
        let mut restricted = base_page(1);
        let role_id: RoleId = [7u8; 16];
        let mut header = restricted.header.as_ref().unwrap().header.clone();
        header.allowed_roles = vec![role_id];
        restricted.header = Some(AuthorizedTopicPageHeaderV1::new(header, &owner()));
        let p_denied = make_post(&member(), "denied", 2_000, 2);
        assert!(restricted
            .clone()
            .apply_delta_incremental(
                &params,
                &TopicPageDeltaV1 {
                    posts: vec![p_denied.clone()],
                    ..Default::default()
                },
            )
            .is_err());

        let role = AuthorizedRole::new(
            Role {
                id: role_id,
                name: "VIP".to_string(),
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
                signed_at: system_time_from_ms(100),
            },
            &owner(),
        );
        let assignment = AuthorizedRoleAssignment::new(
            RoleAssignment {
                role_id,
                member_id: MemberId::from(&member().verifying_key()),
                generation: 1,
                revoked: false,
                signed_at: system_time_from_ms(200),
            },
            &owner(),
        );
        restricted.authority.roles.roles.push(role);
        restricted.authority.roles.assignments.push(assignment);
        restricted
            .apply_delta_incremental(
                &params,
                &TopicPageDeltaV1 {
                    posts: vec![p_denied],
                    ..Default::default()
                },
            )
            .unwrap();
    }

    #[test]
    fn seal_compacts_page_blocks_new_posts_and_allows_post_seal_author_and_admin_actions() {
        let params = page_params(1);
        let mut page = base_page(1);
        let p1 = make_post(&member(), "original text", 2_000, 1);
        let p2 = make_post(&member_b(), "second text", 65_000, 2);
        page.apply_delta_incremental(
            &params,
            &TopicPageDeltaV1 {
                participants: vec![participant(&member_b())],
                posts: vec![p1.clone(), p2.clone()],
                ..Default::default()
            },
        )
        .unwrap();

        // Non-owner / non-admin cannot seal.
        let fake_seal_val = page.build_seal(&params, 70_000).unwrap();
        let fake_seal = AuthorizedTopicPageSealV1::new(fake_seal_val, &member(), None);
        assert!(page
            .clone()
            .apply_delta_incremental(
                &params,
                &TopicPageDeltaV1 {
                    seal: Some(fake_seal),
                    ..Default::default()
                },
            )
            .is_err());

        // Owner seals the page.
        let seal_val = page.build_seal(&params, 70_000).unwrap();
        let seal = AuthorizedTopicPageSealV1::new(seal_val, &owner(), None);
        page.apply_delta_incremental(
            &params,
            &TopicPageDeltaV1 {
                seal: Some(seal),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(page.is_sealed());
        assert!(page.participants.is_empty());
        assert!(page.trust.is_empty());
        assert!(page.authority.policy.is_none());
        assert!(page.authority.roles.roles.is_empty());
        assert_eq!(page.generation.next_part, Some(2));
        page.verify(&params).unwrap();

        // New posts are rejected once sealed.
        let p3 = make_post(&owner(), "too late", 80_000, 3);
        assert!(page
            .clone()
            .apply_delta_incremental(
                &params,
                &TopicPageDeltaV1 {
                    posts: vec![p3],
                    ..Default::default()
                },
            )
            .is_err());

        // Tampering with a sealed post breaks digest verification.
        let mut tampered = page.clone();
        let fake = make_post(&member(), "tampered", 2_000, 99);
        tampered.posts.insert(p1.id(), fake);
        assert!(tampered.verify(&params).is_err());

        // Post author can still edit their own post on a sealed page without participants!
        let edit = PostEditV1 {
            content: SealedBytes::public(b"edited after seal".to_vec()),
        };
        let edit_action = TopicActionV1 {
            kind: TopicActionKind::Edit,
            target: p1.id(),
            payload: SealedBytes::public(encode(&edit).unwrap()),
            generation: 1,
            created_at: 90_000,
            signer: MemberId::from(&member().verifying_key()),
        };
        let auth_edit = AuthorizedTopicActionV1 {
            signature: sign_struct(&edit_action, &member()),
            action: edit_action,
            signer_key: Some(member().verifying_key()),
            authority: None,
        };
        page.apply_delta_incremental(
            &params,
            &TopicPageDeltaV1 {
                post_seal_actions: vec![auth_edit],
                ..Default::default()
            },
        )
        .unwrap();
        assert!(page.latest_action(p1.id(), TopicActionKind::Edit).is_some());
        page.verify(&params).unwrap();

        // Another member cannot edit or delete p1 on a sealed page.
        let bad_delete = TopicActionV1 {
            kind: TopicActionKind::Delete,
            target: p1.id(),
            payload: SealedBytes::public(Vec::new()),
            generation: 1,
            created_at: 95_000,
            signer: MemberId::from(&member_b().verifying_key()),
        };
        let bad_auth = AuthorizedTopicActionV1 {
            signature: sign_struct(&bad_delete, &member_b()),
            action: bad_delete,
            signer_key: Some(member_b().verifying_key()),
            authority: None,
        };
        assert!(page
            .clone()
            .apply_delta_incremental(
                &params,
                &TopicPageDeltaV1 {
                    post_seal_actions: vec![bad_auth],
                    ..Default::default()
                },
            )
            .is_err());

        // Owner can purge/delete p2 on a sealed page.
        let owner_del = TopicActionV1 {
            kind: TopicActionKind::Purge,
            target: p2.id(),
            payload: SealedBytes::public(Vec::new()),
            generation: 1,
            created_at: 96_000,
            signer: MemberId::from(&owner().verifying_key()),
        };
        let auth_del = AuthorizedTopicActionV1 {
            signature: sign_struct(&owner_del, &owner()),
            action: owner_del,
            signer_key: Some(owner().verifying_key()),
            authority: None,
        };
        page.apply_delta_incremental(
            &params,
            &TopicPageDeltaV1 {
                post_seal_actions: vec![auth_del],
                ..Default::default()
            },
        )
        .unwrap();
        assert!(page.is_deleted(p2.id()));
        page.verify(&params).unwrap();

        // Fresh peer bootstraps the sealed page via summary + delta in one shot!
        let fresh_delta = page
            .delta(&TopicPageSummaryV1::default())
            .expect("bootstrap delta");
        let mut fresh = TopicPageStateV1::default();
        fresh.apply_delta_incremental(&params, &fresh_delta).unwrap();
        fresh.verify(&params).unwrap();
        assert_eq!(fresh, page);
    }

    #[test]
    fn admin_can_seal_a_page() {
        let params = page_params(1);
        let mut page = base_page(1);
        let admin = AuthorizedAdmin::new(
            Admin {
                member_id: MemberId::from(&admin_key().verifying_key()),
                generation: 1,
                signed_at: system_time_from_ms(100),
            },
            &owner(),
        );
        page.authority.admins.admins.push(admin);
        page.participants.push(participant(&admin_key()));
        let p1 = make_post(&member(), "reply", 2_000, 1);
        page.posts.insert(p1.id(), p1);

        let seal_val = page.build_seal(&params, 5_000).unwrap();
        let seal = AuthorizedTopicPageSealV1::new(seal_val, &admin_key(), None);
        page.apply_delta_incremental(
            &params,
            &TopicPageDeltaV1 {
                seal: Some(seal),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(page.is_sealed());
        page.verify(&params).unwrap();
    }

    #[test]
    fn merge_is_commutative_associative_and_idempotent_across_sealed_and_open_states() {
        let params = page_params(1);
        let mut open_a = base_page(1);
        let p1 = make_post(&member(), "post 1", 2_000, 1);
        let p2 = make_post(&member_b(), "post 2", 65_000, 2);
        open_a
            .apply_delta_incremental(
                &params,
                &TopicPageDeltaV1 {
                    posts: vec![p1.clone()],
                    ..Default::default()
                },
            )
            .unwrap();

        let mut open_b = open_a.clone();
        open_b
            .apply_delta_incremental(
                &params,
                &TopicPageDeltaV1 {
                    participants: vec![participant(&member_b())],
                    posts: vec![p2.clone()],
                    ..Default::default()
                },
            )
            .unwrap();

        let mut sealed = open_b.clone();
        let seal_val = sealed.build_seal(&params, 70_000).unwrap();
        let seal = AuthorizedTopicPageSealV1::new(seal_val, &owner(), None);
        sealed
            .apply_delta_incremental(
                &params,
                &TopicPageDeltaV1 {
                    seal: Some(seal),
                    ..Default::default()
                },
            )
            .unwrap();

        // open_a ∪ sealed == sealed ∪ open_a
        let mut lr = open_a.clone();
        lr.merge(&params, &sealed).unwrap();
        let mut rl = sealed.clone();
        rl.merge(&params, &open_a).unwrap();
        assert_eq!(lr, rl);
        assert!(lr.is_sealed());
        assert_eq!(lr.posts.len(), 2);

        // idempotent: sealed ∪ sealed == sealed
        let mut idem = sealed.clone();
        idem.merge(&params, &sealed).unwrap();
        assert_eq!(idem, sealed);

        // Lagging peer at open_a catches up to sealed in a single delta!
        let catchup_delta = sealed.delta(&open_a.summarize()).expect("catchup delta");
        let mut caught_up = open_a.clone();
        caught_up.apply_delta_incremental(&params, &catchup_delta).unwrap();
        caught_up.verify(&params).unwrap();
        assert_eq!(caught_up, sealed);
    }

    #[test]
    fn part_zero_posts_seal_freezes_posts_and_keeps_topic_actions_working() {
        let params = page_params(0);
        let header = TopicHeaderV1 {
            topic_id: [9u8; 32],
            author: MemberId::from(&owner().verifying_key()),
            author_key: owner().verifying_key(),
            section: None,
            section_chain: Vec::new(),
            title: SealedBytes::public(b"Title".to_vec()),
            body: SealedBytes::public(b"Body".to_vec()),
            auto_moderated: false,
            created_at: 1_000,
            nonce: [1u8; 16],
        };
        let mut head = TopicStateV1 {
            version: PROTOCOL_VERSION,
            header: Some(AuthorizedTopicHeaderV1::new(header, &owner())),
            section: None,
            authority: authority_with_policy(),
            participants: vec![participant(&member())],
            trust: Vec::new(),
            posts: BTreeMap::new(),
            actions: Vec::new(),
            approvals: Vec::new(),
            generation: TopicGenerationV1::new(0),
            posts_seal: None,
        };
        let p1 = make_post(&member(), "p0 reply", 2_000, 1);
        head.posts.insert(p1.id(), p1.clone());
        head.verify(&params).unwrap();

        let seal_val = head.build_posts_seal(&params, 5_000).unwrap();
        let seal = AuthorizedTopicPageSealV1::new(seal_val, &owner(), None);
        head.apply_delta_incremental(
            &params,
            &TopicDeltaV1 {
                posts_seal: Some(seal),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(head.is_posts_sealed());
        assert_eq!(head.generation.next_part, Some(1));
        head.verify(&params).unwrap();

        // New posts on part 0 are rejected once sealed.
        let p2 = make_post(&member(), "late", 65_000, 2);
        assert!(head
            .clone()
            .apply_delta_incremental(
                &params,
                &TopicDeltaV1 {
                    posts: vec![p2],
                    ..Default::default()
                },
            )
            .is_err());

        // Topic-level actions (e.g. Pin) still work on part 0 after posts_seal!
        let pin = TopicActionV1 {
            kind: TopicActionKind::Pin,
            target: head.header.as_ref().unwrap().header.id(),
            payload: SealedBytes::public(Vec::new()),
            generation: 1,
            created_at: 6_000,
            signer: MemberId::from(&owner().verifying_key()),
        };
        let auth_pin = AuthorizedTopicActionV1 {
            signature: sign_struct(&pin, &owner()),
            action: pin,
            signer_key: Some(owner().verifying_key()),
            authority: None,
        };
        head.apply_delta_incremental(
            &params,
            &TopicDeltaV1 {
                actions: vec![auth_pin],
                ..Default::default()
            },
        )
        .unwrap();
        assert!(head.is_pinned());
        head.verify(&params).unwrap();

        // Approvals and actions on part 0 remain valid.
        let approval = TopicApprovalV1 {
            target: p1.id(),
            approved: true,
            generation: 1,
            scope: None,
            signed_by: MemberId::from(&owner().verifying_key()),
            created_at: 7_000,
        };
        let auth_approval = AuthorizedTopicApprovalV1 {
            signature: sign_struct(&approval, &owner()),
            approval,
            signer_key: Some(owner().verifying_key()),
            authority: None,
        };
        head.apply_delta_incremental(
            &params,
            &TopicDeltaV1 {
                approvals: vec![auth_approval],
                ..Default::default()
            },
        )
        .unwrap();
        head.verify(&params).unwrap();
    }

    /// `cargo test -p plaza-topic-core --release --lib scale_topic_pages_benchmark -- --ignored --nocapture`
    #[test]
    #[ignore = "scale benchmark; run in release"]
    fn scale_topic_pages_benchmark() {
        let params_p0 = page_params(0);
        let params_p1 = page_params(1);

        // Build a realistic 200-post monolithic TopicStateV1 (with 50 distinct
        // participants and a 4 KiB topic body).
        let member_keys: Vec<SigningKey> = (10u8..60u8).map(key).collect();
        let participants: Vec<AuthorizedParticipantV1> =
            member_keys.iter().map(participant).collect();
        let header = TopicHeaderV1 {
            topic_id: [9u8; 32],
            author: MemberId::from(&owner().verifying_key()),
            author_key: owner().verifying_key(),
            section: None,
            section_chain: Vec::new(),
            title: SealedBytes::public(b"Benchmark long discussion".to_vec()),
            body: SealedBytes::public(vec![b'a'; 4096]),
            auto_moderated: false,
            created_at: 1_000,
            nonce: [1u8; 16],
        };
        let mut mono = TopicStateV1 {
            version: PROTOCOL_VERSION,
            header: Some(AuthorizedTopicHeaderV1::new(header, &owner())),
            section: None,
            authority: authority_with_policy(),
            participants: participants.clone(),
            trust: Vec::new(),
            posts: BTreeMap::new(),
            actions: Vec::new(),
            approvals: Vec::new(),
            generation: TopicGenerationV1::new(0),
            posts_seal: None,
        };
        for i in 0..200usize {
            let sk = &member_keys[i % member_keys.len()];
            let p = make_post(
                sk,
                &format!("Reply #{i} with realistic discussion content for benchmark."),
                10_000 + i as i64 * 61_000,
                (i % 256) as u8,
            );
            mono.posts.insert(p.id(), p);
        }
        mono.verify(&params_p0).unwrap();
        let mono_bytes = encode(&mono).unwrap().len();
        let start = Instant::now();
        for _ in 0..5 {
            mono.verify(&params_p0).unwrap();
        }
        let mono_verify_ms = start.elapsed().as_secs_f64() * 1000.0 / 5.0;

        // Now build a 50-post compact append-only page (12 active participants on this page).
        let mut open_page = base_page(1);
        open_page.participants = participants[0..12].to_vec();
        for i in 0..49usize {
            let sk = &member_keys[i % 12];
            let p = make_post(
                sk,
                &format!("Reply #{i} with realistic discussion content for benchmark."),
                10_000 + i as i64 * 61_000,
                (i % 256) as u8,
            );
            open_page.posts.insert(p.id(), p);
        }
        open_page.verify(&params_p1).unwrap();
        let p50 = make_post(
            &member_keys[0],
            "Reply #49 final post on this append-only page.",
            10_000 + 49 * 61_000,
            49,
        );
        let reply_delta = TopicPageDeltaV1 {
            posts: vec![p50],
            ..Default::default()
        };
        let reply_delta_bytes = encode(&reply_delta).unwrap().len();
        let start = Instant::now();
        open_page
            .apply_delta_incremental(&params_p1, &reply_delta)
            .unwrap();
        let reply_inc_ms = start.elapsed().as_secs_f64() * 1000.0;

        let open_bytes = encode(&open_page).unwrap().len();
        let open_summary_bytes = encode(&open_page.summarize()).unwrap().len();
        let start = Instant::now();
        for _ in 0..5 {
            open_page.verify(&params_p1).unwrap();
        }
        let open_verify_ms = start.elapsed().as_secs_f64() * 1000.0 / 5.0;

        // Seal the 50-post page.
        let mut sealed_page = open_page.clone();
        let seal_val = sealed_page.build_seal(&params_p1, 5_000_000).unwrap();
        let seal = AuthorizedTopicPageSealV1::new(seal_val, &owner(), None);
        sealed_page
            .apply_delta_incremental(
                &params_p1,
                &TopicPageDeltaV1 {
                    seal: Some(seal),
                    ..Default::default()
                },
            )
            .unwrap();
        let sealed_bytes = encode(&sealed_page).unwrap().len();
        let start = Instant::now();
        for _ in 0..20 {
            sealed_page.verify(&params_p1).unwrap();
        }
        let sealed_verify_ms = start.elapsed().as_secs_f64() * 1000.0 / 20.0;

        println!(
            "\n=== Topic Append-Only Pages Benchmark (200 posts = 4 pages x 50) ===\n\
             monolithic 200p (50 authors): {:>6.1} KiB   verify {:>7.2} ms\n\
             compact open 50p (12 authors): {:>5.1} KiB   verify {:>7.2} ms   (summary {:.1} KiB; 1-reply delta {:.2} KiB in {:.2} ms)\n\
             compact sealed 50p:           {:>6.1} KiB   verify {:>7.2} ms   (0 duplicated participants/authority)\n\
             4-page total (3 sealed + 1 open): {:.1} KiB vs monolithic {:.1} KiB\n\
             per-reply broadcast state:    {:>6.1} KiB vs monolithic {:.1} KiB ({:.1}x smaller)",
            mono_bytes as f64 / 1024.0,
            mono_verify_ms,
            open_bytes as f64 / 1024.0,
            open_verify_ms,
            open_summary_bytes as f64 / 1024.0,
            reply_delta_bytes as f64 / 1024.0,
            reply_inc_ms,
            sealed_bytes as f64 / 1024.0,
            sealed_verify_ms,
            (sealed_bytes * 3 + open_bytes) as f64 / 1024.0,
            mono_bytes as f64 / 1024.0,
            open_bytes as f64 / 1024.0,
            mono_bytes as f64 / 1024.0,
            mono_bytes as f64 / open_bytes as f64,
        );
    }
}
