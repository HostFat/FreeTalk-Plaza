//! Core state for `plaza-topic`: one contract per discussion.
//!
//! Phase 1: header, section snapshot, mirrored authority, participants, trusted
//! participants, posts, moderation actions, approvals and the state envelope.
//! The client and the UI are Phase 3+.

mod merge;
pub mod pages;
mod types;
#[cfg(test)]
mod tests_suite;

pub(crate) use merge::*;
pub use pages::*;
pub use types::*;

pub use plaza_core::board_state::authority::{
    AuthorityRootV1, AuthorityTreeV1, AuthorizedAuthorityRootV1, MemberStatusProofV1,
    MemberStatusV1, AUTHORITY_ROOT_VERSION,
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

pub const PROTOCOL_VERSION: u16 = 1;
/// The contract returns the full state on every update and subscribers receive
/// it, so a part must stay small enough to broadcast. Clients continue a topic
/// at 7/8 of this budget.
pub const MAX_TOPIC_STATE_BYTES: usize = 512 * 1024;
pub const MAX_POSTS: usize = 200;
pub const MAX_PARTICIPANTS: usize = 512;
pub const MAX_POST_BYTES: usize = 16 * 1024;
pub const MAX_PARTS: u32 = 64;
pub const MAX_TITLE_BYTES: usize = 512;
pub const MAX_BODY_BYTES: usize = 64 * 1024;
pub const MAX_REACTION_PAYLOAD_BYTES: usize = 1024;
pub const MAX_IMAGES_PER_POST: usize = 4;
pub const MAX_ACTIONS: usize = 2_000;
pub const MAX_APPROVALS: usize = 2_000;
pub const MAX_JOIN_DEPTH: usize = 64;

pub type TopicId = MessageId;
pub type SectionId = MessageId;


impl TopicStateV1 {
    pub fn is_posts_sealed(&self) -> bool {
        self.posts_seal.is_some()
    }

    pub fn is_closed_part(&self) -> bool {
        self.posts_seal.is_some() || self.generation.closed_at.is_some()
    }

    pub fn state_hash(&self) -> Result<[u8; 32], String> {
        let bytes = encode(self)?;
        Ok(*blake3::hash(&bytes).as_bytes())
    }

    pub fn posts_digest(&self) -> Result<[u8; 32], String> {
        pages::canonical_posts_digest(&self.posts)
    }

    /// Build a `TopicPageSealV1` freezing the posts on `part == 0`.
    pub fn build_posts_seal(
        &self,
        params: &TopicParamsV1,
        sealed_at: i64,
    ) -> Result<TopicPageSealV1, String> {
        if params.part != 0 {
            return Err("posts_seal on TopicStateV1 is only for part 0".to_string());
        }
        Ok(TopicPageSealV1 {
            topic_id: params.topic_id,
            part: 0,
            post_count: self.posts.len() as u32,
            action_count: 0,
            approval_count: 0,
            content_digest: self.posts_digest()?,
            next_part: 1,
            sealed_at,
        })
    }

    fn verify_posts_seal(
        &self,
        seal: &AuthorizedTopicPageSealV1,
        view: &ChatBoardStateV1,
        board_params: &ChatBoardParametersV1,
        params: &TopicParamsV1,
    ) -> Result<(), String> {
        if params.part != 0 || seal.seal.part != 0 {
            return Err("posts_seal is only valid on part 0".to_string());
        }
        if seal.seal.topic_id != params.topic_id || seal.seal.next_part != 1 {
            return Err("posts_seal does not match topic parameters".to_string());
        }
        if seal.seal.post_count as usize != self.posts.len()
            || seal.seal.action_count != 0
            || seal.seal.approval_count != 0
        {
            return Err("posts_seal counts do not match posts".to_string());
        }
        if seal.seal.content_digest != self.posts_digest()? {
            return Err("posts_seal digest mismatch".to_string());
        }
        pages::verify_page_seal_authority(seal, view, board_params)
    }

    pub fn verify(&self, params: &TopicParamsV1) -> Result<(), String> {
        if !self.verify_shape(params)? {
            return Ok(());
        }
        let board_params = params.board_parameters();
        self.verify_participants(params, &board_params)?;
        let view = self.board_view(params);

        self.verify_authority(&view, &board_params)?;
        self.verify_section(&view, &board_params, params)?;
        self.verify_header_author(&view, &board_params, params)?;
        self.verify_trust(&view, &board_params)?;
        if let Some(seal) = &self.posts_seal {
            self.verify_posts_seal(seal, &view, &board_params, params)?;
        } else {
            self.verify_posts(&view, &board_params, params)?;
        }
        self.verify_actions(&view, &board_params)?;
        self.verify_approvals(&view, &board_params)?;

        Ok(())
    }

    fn verify_header_author(
        &self,
        view: &ChatBoardStateV1,
        board_params: &ChatBoardParametersV1,
        params: &TopicParamsV1,
    ) -> Result<(), String> {
        let Some(header) = &self.header else {
            return Ok(());
        };
        let author = header.header.author;
        let at_ms = header.header.created_at;
        let owner_at = self
            .authority
            .ownership
            .owner_at(board_params, system_time_from_ms(at_ms));
        if author == params.owner_id() || author == owner_at {
            return Ok(());
        }
        if self.is_banned(author, at_ms) {
            return Err("a banned member cannot create a topic".to_string());
        }
        if self.is_suspended(author, at_ms) {
            return Err("a suspended member cannot create a topic".to_string());
        }
        if !self.section_allows(author, view, board_params, params) {
            return Err("the topic author cannot write in this section".to_string());
        }
        Ok(())
    }

    /// Checks that do not depend on historical records. Returns `false` for an
    /// empty topic without a header.
    fn verify_shape(&self, params: &TopicParamsV1) -> Result<bool, String> {
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
        if self
            .generation
            .next_part
            .is_some_and(|part| part != params.part + 1 || part > MAX_PARTS)
        {
            return Err("the next topic part is invalid".to_string());
        }
        if self.generation.closed_at.is_some() && self.posts_seal.is_none() {
            let at_capacity = self.posts.len() >= DEFAULT_TOPIC_PAGE_SIZE
                || encode(self)
                    .map(|bytes| bytes.len() >= MAX_TOPIC_STATE_BYTES * 3 / 4)
                    .unwrap_or(false);
            if !at_capacity {
                return Err(
                    "an unsealed topic cannot be closed before reaching capacity".to_string(),
                );
            }
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
                || self.posts_seal.is_some()
            {
                return Err("a topic without a header cannot carry content".to_string());
            }
            return Ok(false);
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
        Ok(true)
    }

    fn verify_incremental(
        &self,
        params: &TopicParamsV1,
        delta: &TopicDeltaV1,
    ) -> Result<(), String> {
        if !self.verify_shape(params)? {
            return Ok(());
        }
        let board_params = params.board_parameters();
        let view = self.board_view(params);

        let has_move = delta
            .actions
            .iter()
            .any(|entry| entry.action.kind == TopicActionKind::Move);
        if delta.section.is_some() || has_move {
            self.verify_section(&view, &board_params, params)?;
        }
        if delta.authority.is_some() {
            self.verify_authority(&view, &board_params)?;
        }
        if !delta.participants.is_empty() {
            self.verify_participants(params, &board_params)?;
        }
        if delta.header.is_some() {
            self.verify_header_author(&view, &board_params, params)?;
        }
        if !delta.trust.is_empty() {
            self.verify_trust(&view, &board_params)?;
        }
        if let Some(seal) = &delta.posts_seal {
            self.verify_posts_seal(seal, &view, &board_params, params)?;
        } else {
            for entry in &delta.posts {
                self.verify_post_record(&entry.post.id(), entry, &view, &board_params, params)?;
            }
        }
        for entry in &delta.actions {
            self.verify_action_record(entry, &view, &board_params)?;
        }
        for entry in &delta.approvals {
            self.verify_approval_record(entry, &view, &board_params)?;
        }
        Ok(())
    }

    fn verify_participants(
        &self,
        params: &TopicParamsV1,
        board_params: &ChatBoardParametersV1,
    ) -> Result<(), String> {
        verify_participants_list(&self.authority, &self.participants, params, board_params)
    }

    fn verify_authority(
        &self,
        view: &ChatBoardStateV1,
        board_params: &ChatBoardParametersV1,
    ) -> Result<(), String> {
        verify_authority_records(&self.authority, view, board_params)
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
        }
        Ok(())
    }

    fn verify_posts(
        &self,
        view: &ChatBoardStateV1,
        board_params: &ChatBoardParametersV1,
        params: &TopicParamsV1,
    ) -> Result<(), String> {
        for (id, entry) in &self.posts {
            self.verify_post_record(id, entry, view, board_params, params)?;
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
        let owner_id = params.owner_id();
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

        let author_key = self.author_key(post.author, view, board_params, post.created_at, params)?;
        verify_struct(post, &entry.signature, &author_key)
            .map_err(|error| format!("invalid post signature: {error}"))?;

        if post.author == owner_id {
            return Ok(());
        }
        if self.is_banned(post.author, post.created_at) {
            return Err("a banned member cannot post".to_string());
        }
        if self.is_suspended(post.author, post.created_at) {
            return Err("a suspended member cannot post".to_string());
        }
        let is_admin = view
            .admin
            .admins
            .iter()
            .any(|admin| admin.admin.id() == post.author);
        if policy.read_only && !is_admin {
            return Err("the topic is read-only".to_string());
        }
        if self.is_closed() && !is_admin {
            if let Some(header) = &self.header {
                if let Some(close) = self.latest_action(header.header.id(), TopicActionKind::Close)
                {
                    if post.created_at >= close.action.created_at {
                        return Err("the topic is closed".to_string());
                    }
                }
            }
        }
        if !self.section_allows(post.author, view, board_params, params) {
            return Err("the author cannot write in this section".to_string());
        }
        Ok(())
    }

    fn verify_actions(
        &self,
        view: &ChatBoardStateV1,
        board_params: &ChatBoardParametersV1,
    ) -> Result<(), String> {
        for entry in &self.actions {
            self.verify_action_record(entry, view, board_params)?;
        }
        Ok(())
    }

    fn verify_action_record(
        &self,
        entry: &AuthorizedTopicActionV1,
        view: &ChatBoardStateV1,
        board_params: &ChatBoardParametersV1,
    ) -> Result<(), String> {
        let header = self.header.as_ref().ok_or("missing header")?;
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
            if self.is_banned(signer, action.created_at)
                || self.is_suspended(signer, action.created_at)
            {
                return Err(
                    "a banned or suspended member cannot react or vote".to_string()
                );
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
                && (self.is_banned(signer, action.created_at)
                    || self.is_suspended(signer, action.created_at))
            {
                return Err("a banned or suspended member cannot modify posts".to_string());
            }
            return Ok(());
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
            return Ok(());
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
        Ok(())
    }

    fn verify_approvals(
        &self,
        view: &ChatBoardStateV1,
        board_params: &ChatBoardParametersV1,
    ) -> Result<(), String> {
        for entry in &self.approvals {
            self.verify_approval_record(entry, view, board_params)?;
        }
        Ok(())
    }

    fn verify_approval_record(
        &self,
        entry: &AuthorizedTopicApprovalV1,
        view: &ChatBoardStateV1,
        board_params: &ChatBoardParametersV1,
    ) -> Result<(), String> {
        let header = self.header.as_ref().ok_or("missing header")?;
        let approval = &entry.approval;
        if approval.target != header.header.id() && !self.posts.contains_key(&approval.target) {
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
        Ok(())
    }

    fn apply_delta_merge(
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
        let already_closed = self.posts_seal.is_some() || self.generation.closed_at.is_some();
        let closing_without_seal = delta.posts_seal.is_none()
            && delta
                .generation
                .as_ref()
                .is_some_and(|generation| generation.closed_at.is_some());
        if (already_closed || closing_without_seal) && !delta.posts.is_empty() {
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
        if let Some(seal) = &delta.posts_seal {
            match &self.posts_seal {
                None => {
                    self.posts_seal = Some(seal.clone());
                    if self.generation.closed_at.is_none() {
                        self.generation.closed_at = Some(seal.seal.sealed_at);
                    }
                    self.generation.next_part = Some(seal.seal.next_part);
                }
                Some(existing) if existing == seal => {}
                Some(_) => return Err("cannot replace an existing posts seal".to_string()),
            }
        }

        if !delta.posts.is_empty() && delta.posts_seal.is_none() {
            self.check_rate_limit(&delta.posts)?;
        }
        Ok(())
    }

    /// Apply a delta and verify the whole state.
    ///
    /// Callers that already validated the previous state can use
    /// [`Self::apply_delta_incremental`], which verifies only the records in
    /// the delta.
    pub fn apply_delta(
        &mut self,
        params: &TopicParamsV1,
        delta: &TopicDeltaV1,
    ) -> Result<(), String> {
        let mut next = self.clone();
        next.apply_delta_merge(params, delta)?;
        next.verify(params)?;
        *self = next;
        Ok(())
    }

    /// Apply a delta and verify only its records plus the invariants they can
    /// change. The previous state is assumed to have been validated when it
    /// was stored.
    pub fn apply_delta_incremental(
        &mut self,
        params: &TopicParamsV1,
        delta: &TopicDeltaV1,
    ) -> Result<(), String> {
        let mut next = self.clone();
        next.apply_delta_merge(params, delta)?;
        next.verify_incremental(params, delta)?;
        *self = next;
        Ok(())
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
        match (&self.posts_seal, &other.posts_seal) {
            (None, None) => {
                for (id, post) in &other.posts {
                    self.posts.entry(*id).or_insert_with(|| post.clone());
                }
            }
            (Some(_), None) => {}
            (None, Some(other_seal)) => {
                self.posts = other.posts.clone();
                self.posts_seal = Some(other_seal.clone());
            }
            (Some(left), Some(right)) => {
                if pages::compare_seals(right, left) == std::cmp::Ordering::Greater {
                    self.posts = other.posts.clone();
                    self.posts_seal = Some(right.clone());
                }
            }
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
        if self.posts_seal.is_some() {
            let header_id = self.header.as_ref().map(|h| h.header.id());
            self.actions.retain(|entry| {
                Some(entry.action.target) == header_id
                    || self.posts.contains_key(&entry.action.target)
            });
            self.approvals.retain(|entry| {
                Some(entry.approval.target) == header_id
                    || self.posts.contains_key(&entry.approval.target)
            });
        }
        self.generation = merge_generation(&self.generation, &other.generation);
        if let Some(seal) = &self.posts_seal {
            if self.generation.closed_at.is_none() {
                self.generation.closed_at = Some(seal.seal.sealed_at);
            }
            self.generation.next_part = Some(seal.seal.next_part);
        }
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
        check_posts_rate_limit(&self.authority, &self.posts, incoming)
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
            posts_seal_hash: self.posts_seal.as_ref().map(AuthorizedTopicPageSealV1::hash),
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
        let seal_hash = self.posts_seal.as_ref().map(AuthorizedTopicPageSealV1::hash);
        if summary.posts_seal_hash != seal_hash {
            delta.posts_seal = self.posts_seal.clone();
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
            && delta.posts_seal.is_none()
        {
            None
        } else {
            Some(delta)
        }
    }

    pub fn board_view(&self, params: &TopicParamsV1) -> ChatBoardStateV1 {
        build_board_view(&self.authority, &self.participants, params)
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
        is_member_banned(&self.authority, member, at_ms)
    }

    fn is_suspended(&self, member: MemberId, at_ms: i64) -> bool {
        is_member_suspended(&self.authority, member, at_ms)
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
            .map(|entry| (entry.action.generation, std::cmp::Reverse(entry.id())));
        let off = self
            .latest_action(target, kind_off)
            .map(|entry| (entry.action.generation, std::cmp::Reverse(entry.id())));
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
                (hide.action.generation, std::cmp::Reverse(hide.id()))
                    > (restore.action.generation, std::cmp::Reverse(restore.id()))
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
                (delete.action.generation, std::cmp::Reverse(delete.id()))
                    > (restore.action.generation, std::cmp::Reverse(restore.id()))
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

pub(crate) fn value_hash<T: Serialize>(value: &T) -> [u8; 32] {
    let bytes = plaza_core::util::encode_cbor(value).unwrap_or_default();
    *blake3::hash(&bytes).as_bytes()
}

pub(crate) fn default_true() -> bool {
    true
}

pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    plaza_core::util::encode_cbor(value)
}

pub fn decode_params(bytes: &[u8]) -> Result<TopicParamsV1, String> {
    plaza_core::util::decode_cbor(bytes)
}

pub fn decode_state(bytes: &[u8]) -> Result<TopicStateV1, String> {
    plaza_core::util::decode_cbor(bytes)
}

pub fn decode_delta(bytes: &[u8]) -> Result<TopicDeltaV1, String> {
    plaza_core::util::decode_cbor(bytes)
}

pub fn decode_summary(bytes: &[u8]) -> Result<TopicStateSummaryV1, String> {
    plaza_core::util::decode_cbor(bytes)
}
