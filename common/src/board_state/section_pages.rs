//! Compact topic-entry pages (`page > 0`) for sectioned boards.
//!
//! Page 0 of a section is the section manifest (`ChatBoardStateV1`), holding
//! the section authority, the owner-signed page list (`topic_pages`), page 0's
//! entries, and all section-level flags.
//!
//! Every extra page (`page > 0`) uses [`SectionPageStateV1`] instead of copying
//! a full `ChatBoardStateV1`:
//! - No board configuration, sections, bans, suspensions, activity, reports,
//!   flags, or legacy message fields, and no authority sync fan-out.
//! - While open, the page stores only the owner-signed page header, its topic
//!   entries, and deduplicated author certificates (plus invites/roles/admins
//!   only when required by those authors).
//! - Once full, the owner seals the page with [`AuthorizedSectionPageSealV1`]:
//!   all duplicated author/invite/role records are dropped, entries become
//!   immutable, and new subscribers verify the entire page with a single
//!   Ed25519 signature and a BLAKE3 digest over `entries`.
//! - Authors can still edit titles/previews of topics on a sealed page via
//!   `entry_edits`, verified directly against the sealed entry's key.

use crate::board_state::admin::AdminsV1;
use crate::board_state::invites::AuthorizedInviteToken;
use crate::board_state::member::{AuthorizedMember, MemberId, MembersV1};
use crate::board_state::ownership::OwnershipV1;
use crate::board_state::pages::{MAX_TOPICS_PER_PAGE, MAX_TOPIC_PAGE_SIZE};
use crate::board_state::rate_limit::{
    exceeding_member, system_time_from_ms, MAX_TOPICS_PER_WINDOW, TOPIC_RATE_WINDOW_MS,
};
use crate::board_state::roles::{AuthorizedRole, AuthorizedRoleAssignment, RoleId, RolesV1};
use crate::board_state::sections::{SectionId, SectionParametersV1};
use crate::board_state::topics::{AuthorizedTopicEntryV1, TopicId};
use crate::board_state::ChatBoardParametersV1;
use crate::util::{sign_struct, verify_struct};
use crate::ChatBoardStateV1;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use freenet_scaffold::ComposableState;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

fn is_empty_ownership(ownership: &OwnershipV1) -> bool {
    ownership.transfers.is_empty()
}

fn is_empty_admins(admin: &AdminsV1) -> bool {
    admin.admins.is_empty() && admin.revoked.is_empty()
}

/// Owner-signed metadata binding an extra section page (`page > 0`) to its
/// board, section, section chain, page number, page size, and optional ACL.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct SectionPageHeaderV1 {
    /// Founding board owner verifying key bytes (prevents cross-board replay).
    pub board: [u8; 32],
    pub section: SectionId,
    pub section_chain: Vec<SectionId>,
    pub page: u32,
    pub page_size: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_roles: Vec<RoleId>,
    pub created_at: i64,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedSectionPageHeaderV1 {
    pub header: SectionPageHeaderV1,
    pub signer: MemberId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_key: Option<VerifyingKey>,
    pub signature: Signature,
}

impl AuthorizedSectionPageHeaderV1 {
    pub fn new(header: SectionPageHeaderV1, owner: &SigningKey) -> Self {
        Self {
            signature: sign_struct(&header, owner),
            header,
            signer: MemberId::from(&owner.verifying_key()),
            signer_key: Some(owner.verifying_key()),
        }
    }

    pub fn verify(
        &self,
        params: &SectionParametersV1,
        ownership: &OwnershipV1,
    ) -> Result<(), String> {
        if params.page == 0 {
            return Err("compact section pages require page > 0".to_string());
        }
        if self.header.page != params.page {
            return Err("section page header number does not match parameters".to_string());
        }
        if self.header.section != params.section {
            return Err("section page header section does not match parameters".to_string());
        }
        if self.header.board != params.owner.to_bytes() {
            return Err("section page header belongs to another board".to_string());
        }
        if self.header.page_size == 0 || self.header.page_size > MAX_TOPIC_PAGE_SIZE {
            return Err("section page size is out of range".to_string());
        }
        if self.header.section_chain.last() != Some(&params.section) {
            return Err("section page header chain does not end at its section".to_string());
        }
        let board_params = ChatBoardParametersV1 {
            owner: params.owner,
        };
        let owner_key =
            ownership.owner_key_at(&board_params, system_time_from_ms(self.header.created_at));
        if self.signer != MemberId::from(&owner_key) {
            return Err("section page header is signed by someone other than the owner".to_string());
        }
        if let Some(key) = self.signer_key {
            if key != owner_key {
                return Err("section page header signer key does not match the owner".to_string());
            }
        }
        verify_struct(&self.header, &self.signature, &owner_key)
            .map_err(|e| format!("invalid section page header signature: {e}"))
    }
}

/// Owner-signed cryptographic seal over a finalized section page's entries.
/// Once sealed, duplicated author/invite/role records are dropped and peers
/// verify the page with 1 Ed25519 signature + 1 BLAKE3 digest.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct SectionPageSealV1 {
    pub board: [u8; 32],
    pub section: SectionId,
    pub page: u32,
    pub entry_count: u32,
    pub entries_digest: [u8; 32],
    pub sealed_at: i64,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedSectionPageSealV1 {
    pub seal: SectionPageSealV1,
    pub signer: MemberId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_key: Option<VerifyingKey>,
    pub signature: Signature,
}

impl AuthorizedSectionPageSealV1 {
    pub fn new(
        params: &SectionParametersV1,
        entries: &[AuthorizedTopicEntryV1],
        owner: &SigningKey,
        sealed_at: i64,
    ) -> Result<Self, String> {
        if params.page == 0 {
            return Err("only extra section pages (page > 0) can be sealed".to_string());
        }
        let mut sorted = entries.to_vec();
        sort_entries(&mut sorted);
        let seal = SectionPageSealV1 {
            board: params.owner.to_bytes(),
            section: params.section,
            page: params.page,
            entry_count: sorted.len() as u32,
            entries_digest: entries_digest(&sorted)?,
            sealed_at,
        };
        Ok(Self {
            signature: sign_struct(&seal, owner),
            seal,
            signer: MemberId::from(&owner.verifying_key()),
            signer_key: Some(owner.verifying_key()),
        })
    }

    pub fn verify(
        &self,
        params: &SectionParametersV1,
        ownership: &OwnershipV1,
        entries: &[AuthorizedTopicEntryV1],
    ) -> Result<(), String> {
        if params.page == 0 {
            return Err("compact section pages require page > 0".to_string());
        }
        if self.seal.page != params.page {
            return Err("section page seal number does not match parameters".to_string());
        }
        if self.seal.section != params.section {
            return Err("section page seal section does not match parameters".to_string());
        }
        if self.seal.board != params.owner.to_bytes() {
            return Err("section page seal belongs to another board".to_string());
        }
        if entries.len() > MAX_TOPICS_PER_PAGE {
            return Err("sealed section page has too many topics".to_string());
        }
        if self.seal.entry_count as usize != entries.len() {
            return Err("section page seal entry count does not match".to_string());
        }
        let digest = entries_digest(entries)?;
        if self.seal.entries_digest != digest {
            return Err("section page seal digest does not match entries".to_string());
        }
        let board_params = ChatBoardParametersV1 {
            owner: params.owner,
        };
        let owner_key =
            ownership.owner_key_at(&board_params, system_time_from_ms(self.seal.sealed_at));
        if self.signer != MemberId::from(&owner_key) {
            return Err("section page seal is signed by someone other than the owner".to_string());
        }
        if let Some(key) = self.signer_key {
            if key != owner_key {
                return Err("section page seal signer key does not match the owner".to_string());
            }
        }
        verify_struct(&self.seal, &self.signature, &owner_key)
            .map_err(|e| format!("invalid section page seal signature: {e}"))
    }
}

pub fn entries_digest(entries: &[AuthorizedTopicEntryV1]) -> Result<[u8; 32], String> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(entries, &mut bytes)
        .map_err(|e| format!("serialize section page entries for digest: {e}"))?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

fn sort_entries(entries: &mut [AuthorizedTopicEntryV1]) {
    entries.sort_by_key(|entry| (entry.entry.topic_id.0 .0, entry.entry.generation));
}

fn seal_wins(incoming: &AuthorizedSectionPageSealV1, existing: &AuthorizedSectionPageSealV1) -> bool {
    incoming.seal.sealed_at > existing.seal.sealed_at
        || (incoming.seal.sealed_at == existing.seal.sealed_at
            && incoming.signature.to_bytes() < existing.signature.to_bytes())
}

fn entry_wins(incoming: &AuthorizedTopicEntryV1, existing: &AuthorizedTopicEntryV1) -> bool {
    incoming.entry.generation > existing.entry.generation
        || (incoming.entry.generation == existing.entry.generation
            && incoming.digest() < existing.digest())
}

/// Compact state for an extra section page (`page > 0`).
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct SectionPageStateV1 {
    pub header: Option<AuthorizedSectionPageHeaderV1>,
    #[serde(default, skip_serializing_if = "is_empty_ownership")]
    pub ownership: OwnershipV1,
    #[serde(default, skip_serializing_if = "is_empty_admins")]
    pub admin: AdminsV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal: Option<AuthorizedSectionPageSealV1>,
    #[serde(default)]
    pub entries: Vec<AuthorizedTopicEntryV1>,
    /// Title/preview updates for topics already sealed in `entries`. Verified
    /// directly against the original entry's author key without keeping the
    /// author certificate list on disk.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entry_edits: Vec<AuthorizedTopicEntryV1>,
    /// Deduplicated author records (plus invite-chain ancestors) while the page
    /// is unsealed. Cleared on seal (except any member needed to verify an
    /// ownership transfer chain).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authors: Vec<AuthorizedMember>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub invites: Vec<AuthorizedInviteToken>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<AuthorizedRole>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub role_assignments: Vec<AuthorizedRoleAssignment>,
}

/// Incremental delta for [`SectionPageStateV1`].
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct SectionPageDeltaV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<AuthorizedSectionPageHeaderV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ownership: Option<OwnershipV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin: Option<AdminsV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal: Option<AuthorizedSectionPageSealV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<AuthorizedTopicEntryV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entry_edits: Vec<AuthorizedTopicEntryV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authors: Vec<AuthorizedMember>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub invites: Vec<AuthorizedInviteToken>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<AuthorizedRole>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub role_assignments: Vec<AuthorizedRoleAssignment>,
}

impl SectionPageDeltaV1 {
    pub fn is_empty(&self) -> bool {
        self.header.is_none()
            && self.ownership.is_none()
            && self.admin.is_none()
            && self.seal.is_none()
            && self.entries.is_empty()
            && self.entry_edits.is_empty()
            && self.authors.is_empty()
            && self.invites.is_empty()
            && self.roles.is_empty()
            && self.role_assignments.is_empty()
    }
}

/// Compact summary for incremental peer sync of [`SectionPageStateV1`].
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct SectionPageSummaryV1 {
    pub has_header: bool,
    pub ownership_transfers: usize,
    pub sealed_at: Option<i64>,
    pub entries: BTreeMap<TopicId, (u64, i64)>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub entry_edits: BTreeMap<TopicId, (u64, i64)>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub authors: BTreeSet<MemberId>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub invites: BTreeSet<[u8; 16]>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub admins: BTreeSet<(MemberId, u64)>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub revoked_admins: BTreeSet<(MemberId, u64)>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub roles: BTreeSet<(RoleId, u64, bool)>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub role_assignments: BTreeSet<(RoleId, MemberId, u64, bool)>,
}

/// Member IDs referenced by an ownership transfer chain (successors and
/// succession voters). Used both when compacting sealed pages and when pruning
/// section manifest authority.
pub fn ownership_referenced_members(ownership: &OwnershipV1) -> HashSet<MemberId> {
    let mut ids = HashSet::new();
    for transfer in &ownership.transfers {
        ids.insert(transfer.transfer.to);
        for approval in &transfer.succession_approvals {
            ids.insert(approval.vote.voter);
        }
    }
    ids
}

impl SectionPageStateV1 {
    pub fn is_sealed(&self) -> bool {
        self.seal.is_some()
    }

    pub fn page_size(&self) -> Option<u32> {
        self.header.as_ref().map(|h| h.header.page_size)
    }

    /// Effective topic entries with any `entry_edits` overlaid on top of the
    /// base `entries`.
    pub fn effective_entries(&self) -> Vec<AuthorizedTopicEntryV1> {
        if self.entry_edits.is_empty() {
            return self.entries.clone();
        }
        let edits: HashMap<TopicId, &AuthorizedTopicEntryV1> = self
            .entry_edits
            .iter()
            .map(|entry| (entry.entry.topic_id, entry))
            .collect();
        self.entries
            .iter()
            .map(|entry| {
                edits
                    .get(&entry.entry.topic_id)
                    .copied()
                    .filter(|edit| entry_wins(edit, entry))
                    .cloned()
                    .unwrap_or_else(|| entry.clone())
            })
            .collect()
    }

    /// Ephemeral `ChatBoardStateV1` containing only the minimal authority
    /// fields stored on this page, so existing `MembersV1`, `InviteTokensV1`,
    /// `RolesV1`, `AdminsV1`, and `OwnershipV1` validators can be reused
    /// verbatim without duplicating cryptographic logic.
    fn verification_board(&self) -> ChatBoardStateV1 {
        let mut board = ChatBoardStateV1::default();
        board.ownership = self.ownership.clone();
        board.admin = self.admin.clone();
        board.members = MembersV1 {
            members: self.authors.clone(),
        };
        board.invites.tokens = self.invites.clone();
        board.roles = RolesV1 {
            roles: self.roles.clone(),
            assignments: self.role_assignments.clone(),
        };
        board
    }

    /// Drop duplicated author/invite/role records when sealing a page, keeping
    /// only the tiny subset required to verify `ownership` if transfers exist.
    pub fn compact_for_seal(&mut self, params: &SectionParametersV1) {
        self.roles.clear();
        self.role_assignments.clear();
        if self.ownership.transfers.is_empty() {
            self.admin = AdminsV1::default();
            self.authors.clear();
            self.invites.clear();
            return;
        }
        let needed_ids = self.ownership_closure_members(params);
        self.authors
            .retain(|member| needed_ids.contains(&member.member.id()));
        let needed_tokens: HashSet<[u8; 16]> = self
            .authors
            .iter()
            .filter_map(|member| member.member.join_proof.as_ref().map(|p| p.token_id))
            .collect();
        self.invites
            .retain(|token| needed_tokens.contains(&token.token.id));
        // Keep only admin/revocation records needed for transfer targets or
        // succession voters (and any admin who signed a retained invite token).
        let mut needed_admins = ownership_referenced_members(&self.ownership);
        for token in &self.invites {
            if let Some(signer) = token.signer {
                needed_admins.insert(signer);
            }
        }
        // Succession quorum checks count all active admins at transfer time, so
        // if any transfer used succession approvals keep the full admin list.
        let has_succession = self
            .ownership
            .transfers
            .iter()
            .any(|t| !t.succession_approvals.is_empty());
        if !has_succession {
            self.admin
                .admins
                .retain(|a| needed_admins.contains(&a.admin.id()));
            self.admin
                .revoked
                .retain(|r| needed_admins.contains(&r.id()));
        }
        self.sort();
    }

    fn ownership_closure_members(&self, params: &SectionParametersV1) -> HashSet<MemberId> {
        let owner_id = MemberId::from(&params.owner);
        let by_id: HashMap<MemberId, &AuthorizedMember> = self
            .authors
            .iter()
            .map(|m| (m.member.id(), m))
            .collect();
        let mut needed = HashSet::new();
        let mut stack: Vec<MemberId> = ownership_referenced_members(&self.ownership)
            .into_iter()
            .collect();
        while let Some(id) = stack.pop() {
            if id == owner_id || !needed.insert(id) {
                continue;
            }
            if let Some(member) = by_id.get(&id) {
                if member.member.join_proof.is_none()
                    && member.member.invited_by != owner_id
                    && member.member.invited_by != id
                {
                    stack.push(member.member.invited_by);
                }
            }
        }
        needed
    }

    pub fn sort(&mut self) {
        sort_entries(&mut self.entries);
        sort_entries(&mut self.entry_edits);
        self.authors.sort_by_key(|m| m.member.id().0 .0);
        self.invites.sort_by_key(|t| t.token.id);
        self.admin.admins.sort_by_key(|a| a.admin.id().0 .0);
        self.admin.revoked.sort_by_key(|r| r.id().0 .0);
        self.roles.sort_by_key(|r| (r.role.id, r.role.generation));
        self.role_assignments.sort_by_key(|a| {
            (
                a.assignment.role_id,
                a.assignment.member_id.0 .0,
                a.assignment.generation,
            )
        });
    }

    /// Full verification of the page state.
    ///
    /// When `self.seal` is `Some`, verification takes O(1) Ed25519 + O(N)
    /// BLAKE3 instead of verifying every author and topic signature.
    pub fn verify(&self, params: &SectionParametersV1) -> Result<(), String> {
        if params.page == 0 {
            return Err("compact section pages require page > 0".to_string());
        }
        let Some(header) = &self.header else {
            if !self.ownership.transfers.is_empty()
                || !is_empty_admins(&self.admin)
                || self.seal.is_some()
                || !self.entries.is_empty()
                || !self.entry_edits.is_empty()
                || !self.authors.is_empty()
                || !self.invites.is_empty()
                || !self.roles.is_empty()
                || !self.role_assignments.is_empty()
            {
                return Err("uninitialized section page cannot carry records".to_string());
            }
            return Ok(());
        };

        let board_params = ChatBoardParametersV1 {
            owner: params.owner,
        };

        // Check sorted uniqueness of topic entries.
        let mut seen_topics = HashSet::with_capacity(self.entries.len());
        for entry in &self.entries {
            if !seen_topics.insert(entry.entry.topic_id) {
                return Err("duplicate topic entry in section page".to_string());
            }
        }
        let max_entries = (header.header.page_size as usize).min(MAX_TOPICS_PER_PAGE);
        if self.entries.len() > max_entries {
            return Err("section page exceeds its signed page size".to_string());
        }

        if let Some(seal) = &self.seal {
            // Verify ownership chain if present.
            if !self.ownership.transfers.is_empty() {
                let board = self.verification_board();
                board.admin.verify(&board, &board_params)?;
                board.invites.verify(&board, &board_params)?;
                board.members.verify(&board, &board_params)?;
                board.ownership.verify(&board, &board_params)?;
                if !self.roles.is_empty() || !self.role_assignments.is_empty() {
                    return Err("sealed section page cannot retain roles".to_string());
                }
                let allowed_authors = self.ownership_closure_members(params);
                if self
                    .authors
                    .iter()
                    .any(|m| !allowed_authors.contains(&m.member.id()))
                {
                    return Err(
                        "sealed section page retains unreferenced author records".to_string()
                    );
                }
            } else if !is_empty_admins(&self.admin)
                || !self.authors.is_empty()
                || !self.invites.is_empty()
                || !self.roles.is_empty()
                || !self.role_assignments.is_empty()
            {
                return Err(
                    "sealed section page must not carry duplicated authority records".to_string(),
                );
            }

            header.verify(params, &self.ownership)?;
            seal.verify(params, &self.ownership, &self.entries)?;

            // Verify any edits against the sealed original entries.
            let mut seen_edits = HashSet::with_capacity(self.entry_edits.len());
            for edit in &self.entry_edits {
                if !seen_edits.insert(edit.entry.topic_id) {
                    return Err("duplicate topic edit in sealed section page".to_string());
                }
                self.verify_sealed_edit(params, edit)?;
            }
            return Ok(());
        }

        // Unsealed path: no entry_edits allowed (edits update `entries` directly).
        if !self.entry_edits.is_empty() {
            return Err("unsealed section page must apply edits directly to entries".to_string());
        }

        let board = self.verification_board();
        board.admin.verify(&board, &board_params)?;
        if !self.ownership.transfers.is_empty() {
            board.ownership.verify(&board, &board_params)?;
        }
        board.roles.verify(&board, &board_params)?;
        board.invites.verify(&board, &board_params)?;
        board.members.verify(&board, &board_params)?;

        header.verify(params, &self.ownership)?;

        for entry in &self.entries {
            self.verify_entry_against(params, &board, header, entry)?;
        }
        if exceeding_member(
            self.entries
                .iter()
                .map(|entry| (entry.entry.author, entry.entry.created_at)),
            TOPIC_RATE_WINDOW_MS,
            MAX_TOPICS_PER_WINDOW,
        )
        .is_some()
        {
            return Err("topic creation rate limit exceeded".to_string());
        }
        Ok(())
    }

    fn verify_entry_against(
        &self,
        params: &SectionParametersV1,
        board: &ChatBoardStateV1,
        header: &AuthorizedSectionPageHeaderV1,
        entry: &AuthorizedTopicEntryV1,
    ) -> Result<(), String> {
        let value = &entry.entry;
        value.verify_basics()?;
        if value.section != Some(params.section) {
            return Err("topic entry belongs to another section".to_string());
        }
        if value.section_chain != header.header.section_chain {
            return Err("topic entry section chain does not match page header".to_string());
        }
        let board_params = ChatBoardParametersV1 {
            owner: params.owner,
        };
        let founding_owner_id = board_params.owner_id();
        let current_owner_id = self.ownership.current_owner(&board_params);
        let author_key = if value.author == founding_owner_id {
            params.owner
        } else if value.author == current_owner_id {
            self.ownership.current_owner_key(&board_params)
        } else {
            board
                .members
                .members
                .iter()
                .find(|m| m.member.id() == value.author)
                .map(|m| m.member.member_vk)
                .ok_or("topic author is not a board member")?
        };
        if let Some(signer_key) = entry.signer_key {
            if MemberId::from(&signer_key) != value.author || signer_key != author_key {
                return Err("topic entry signer key does not match the author".to_string());
            }
        }
        if let Some(signer) = entry.signer {
            if signer != value.author {
                return Err("topic entry signer is not the author".to_string());
            }
        }
        verify_struct(value, &entry.signature, &author_key)
            .map_err(|e| format!("invalid topic entry signature: {e}"))?;

        if !header.header.allowed_roles.is_empty()
            && value.author != current_owner_id
            && value.author != founding_owner_id
        {
            let allowed = board
                .roles
                .active_roles_of(&value.author)
                .iter()
                .any(|role| header.header.allowed_roles.contains(&role.id));
            if !allowed {
                return Err("topic author cannot post in this section".to_string());
            }
        }
        Ok(())
    }

    fn verify_sealed_edit(
        &self,
        params: &SectionParametersV1,
        edit: &AuthorizedTopicEntryV1,
    ) -> Result<(), String> {
        edit.entry.verify_basics()?;
        let original = self
            .entries
            .iter()
            .find(|e| e.entry.topic_id == edit.entry.topic_id)
            .ok_or("topic edit targets a topic not on this sealed page")?;
        if edit.entry.author != original.entry.author {
            return Err("topic edit cannot change author".to_string());
        }
        if edit.entry.section != original.entry.section
            || edit.entry.section_chain != original.entry.section_chain
            || edit.entry.created_at != original.entry.created_at
        {
            return Err("topic edit cannot change immutable topic metadata".to_string());
        }
        if edit.entry.generation <= original.entry.generation {
            return Err("topic edit generation must exceed the sealed entry".to_string());
        }
        let board_params = ChatBoardParametersV1 {
            owner: params.owner,
        };
        let author_key = if let Some(vk) = original.signer_key {
            if MemberId::from(&vk) != original.entry.author {
                return Err("sealed entry signer key mismatch".to_string());
            }
            vk
        } else if original.entry.author == board_params.owner_id() {
            params.owner
        } else {
            let owner_at = self.ownership.owner_key_at(
                &board_params,
                system_time_from_ms(original.entry.created_at),
            );
            if MemberId::from(&owner_at) == original.entry.author {
                owner_at
            } else {
                return Err("sealed entry lacks author key for edits".to_string());
            }
        };
        if let Some(signer_key) = edit.signer_key {
            if signer_key != author_key {
                return Err("topic edit signer key does not match original author".to_string());
            }
        }
        if let Some(signer) = edit.signer {
            if signer != original.entry.author {
                return Err("topic edit signer does not match original author".to_string());
            }
        }
        verify_struct(&edit.entry, &edit.signature, &author_key)
            .map_err(|e| format!("invalid topic edit signature: {e}"))
    }

    /// Apply an incremental delta atomically, verifying only newly arriving
    /// records on the unsealed hot path and compacting automatically on seal.
    pub fn apply_delta(
        &mut self,
        params: &SectionParametersV1,
        delta: &SectionPageDeltaV1,
    ) -> Result<(), String> {
        if params.page == 0 {
            return Err("compact section pages require page > 0".to_string());
        }
        if delta.is_empty() {
            return Ok(());
        }

        let mut next = self.clone();
        let board_params = ChatBoardParametersV1 {
            owner: params.owner,
        };

        // 1. Merge ownership & admin if supplied.
        let mut ownership_or_admin_changed = false;
        if let Some(incoming_ownership) = &delta.ownership {
            if incoming_ownership.transfers.len() > next.ownership.transfers.len() {
                next.ownership = incoming_ownership.clone();
                ownership_or_admin_changed = true;
            }
        }
        if let Some(incoming_admin) = &delta.admin {
            for admin in &incoming_admin.admins {
                if !next
                    .admin
                    .admins
                    .iter()
                    .any(|a| a.admin.id() == admin.admin.id() && a.admin.generation >= admin.admin.generation)
                {
                    next.admin
                        .admins
                        .retain(|a| a.admin.id() != admin.admin.id());
                    next.admin.admins.push(admin.clone());
                    ownership_or_admin_changed = true;
                }
            }
            for rev in &incoming_admin.revoked {
                if !next
                    .admin
                    .revoked
                    .iter()
                    .any(|r| r.id() == rev.id() && r.revocation.generation >= rev.revocation.generation)
                {
                    next.admin.revoked.retain(|r| r.id() != rev.id());
                    next.admin.revoked.push(rev.clone());
                    ownership_or_admin_changed = true;
                }
            }
            // Keep admin and revoked lists disjoint by highest generation (tie -> revoked).
            next.admin.admins.retain(|a| {
                !next.admin.revoked.iter().any(|r| {
                    r.id() == a.admin.id() && r.revocation.generation >= a.admin.generation
                })
            });
            next.admin.revoked.retain(|r| {
                !next.admin.admins.iter().any(|a| {
                    a.admin.id() == r.id() && a.admin.generation > r.revocation.generation
                })
            });
        }

        // 2. Initialize header if missing (header is immutable once set).
        if let Some(incoming_header) = &delta.header {
            match &next.header {
                None => {
                    next.header = Some(incoming_header.clone());
                }
                Some(existing) => {
                    if existing != incoming_header {
                        return Err("section page header is immutable".to_string());
                    }
                }
            }
        }
        let header = next
            .header
            .clone()
            .ok_or("section page delta requires an initialized header")?;

        // 3. Handle seal transition or already-sealed page.
        if let Some(incoming_seal) = &delta.seal {
            let take_seal = match &next.seal {
                None => true,
                Some(existing) => seal_wins(incoming_seal, existing),
            };
            if take_seal {
                // Merge any entries carried with the seal delta (for peer sync
                // from an unsealed state to the sealed state).
                for entry in &delta.entries {
                    match next
                        .entries
                        .iter_mut()
                        .find(|e| e.entry.topic_id == entry.entry.topic_id)
                    {
                        Some(existing) => {
                            if entry_wins(entry, existing) {
                                *existing = entry.clone();
                            }
                        }
                        None => next.entries.push(entry.clone()),
                    }
                }
                sort_entries(&mut next.entries);
                // Merge any authors/invites needed for ownership verification if
                // ownership has transfers.
                for author in &delta.authors {
                    if !next
                        .authors
                        .iter()
                        .any(|m| m.member.id() == author.member.id())
                    {
                        next.authors.push(author.clone());
                    }
                }
                for token in &delta.invites {
                    if !next.invites.iter().any(|t| t.token.id == token.token.id) {
                        next.invites.push(token.clone());
                    }
                }
                next.compact_for_seal(params);
                if !next.ownership.transfers.is_empty() {
                    let board = next.verification_board();
                    board.admin.verify(&board, &board_params)?;
                    board.invites.verify(&board, &board_params)?;
                    board.members.verify(&board, &board_params)?;
                    board.ownership.verify(&board, &board_params)?;
                }
                header.verify(params, &next.ownership)?;
                incoming_seal.verify(params, &next.ownership, &next.entries)?;
                next.seal = Some(incoming_seal.clone());
            }
            // Apply any edits included alongside or on top of the seal.
            for edit in &delta.entry_edits {
                next.verify_sealed_edit(params, edit)?;
                next.upsert_sealed_edit(edit.clone());
            }
            next.sort();
            *self = next;
            return Ok(());
        }

        if next.seal.is_some() {
            // Already sealed: reject any entry mutations that are not already
            // present in the sealed entries.
            for entry in &delta.entries {
                let already_exact = next.entries.iter().any(|e| e == entry);
                if !already_exact {
                    return Err("cannot add or modify entries on a sealed section page".to_string());
                }
            }
            for edit in &delta.entry_edits {
                next.verify_sealed_edit(params, edit)?;
                next.upsert_sealed_edit(edit.clone());
            }
            next.sort();
            *self = next;
            return Ok(());
        }

        // 4. Unsealed hot path: merge and verify ONLY incoming records!
        if !delta.entry_edits.is_empty() {
            return Err("entry_edits are only valid on a sealed section page".to_string());
        }

        let mut new_invites = Vec::new();
        for token in &delta.invites {
            if !next.invites.iter().any(|t| t.token.id == token.token.id) {
                next.invites.push(token.clone());
                new_invites.push(token.clone());
            }
        }
        let mut roles_changed = false;
        for role in &delta.roles {
            match next
                .roles
                .iter_mut()
                .find(|r| r.role.id == role.role.id)
            {
                Some(existing) => {
                    if role.role.generation > existing.role.generation
                        || (role.role.generation == existing.role.generation
                            && role.role.deleted
                            && !existing.role.deleted)
                    {
                        *existing = role.clone();
                        roles_changed = true;
                    }
                }
                None => {
                    next.roles.push(role.clone());
                    roles_changed = true;
                }
            }
        }
        for assignment in &delta.role_assignments {
            match next.role_assignments.iter_mut().find(|a| {
                a.assignment.role_id == assignment.assignment.role_id
                    && a.assignment.member_id == assignment.assignment.member_id
            }) {
                Some(existing) => {
                    if assignment.assignment.generation > existing.assignment.generation
                        || (assignment.assignment.generation == existing.assignment.generation
                            && assignment.assignment.revoked
                            && !existing.assignment.revoked)
                    {
                        *existing = assignment.clone();
                        roles_changed = true;
                    }
                }
                None => {
                    next.role_assignments.push(assignment.clone());
                    roles_changed = true;
                }
            }
        }

        let mut new_authors = Vec::new();
        for author in &delta.authors {
            if !next
                .authors
                .iter()
                .any(|m| m.member.id() == author.member.id())
            {
                next.authors.push(author.clone());
                new_authors.push(author.clone());
            }
        }

        let board = next.verification_board();

        if ownership_or_admin_changed || delta.header.is_some() {
            board.admin.verify(&board, &board_params)?;
            if !next.ownership.transfers.is_empty() {
                board.ownership.verify(&board, &board_params)?;
            }
            header.verify(params, &next.ownership)?;
        }
        if roles_changed || ownership_or_admin_changed {
            board.roles.verify(&board, &board_params)?;
        }
        if !new_invites.is_empty() || ownership_or_admin_changed || roles_changed {
            board.invites.verify(&board, &board_params)?;
        }
        if !new_authors.is_empty() {
            let members_by_id = board.members.members_by_member_id();
            let owner_id = board_params.owner_id();
            let has_transferred = !board.ownership.transfers.is_empty();
            for member in &new_authors {
                if member.member.id() == owner_id && !has_transferred {
                    return Err("Owner should not be included in the members list".to_string());
                }
                if member.member.member_vk == board_params.owner && !has_transferred {
                    return Err(
                        "Member cannot have the same verifying key as the board owner".to_string(),
                    );
                }
                if let Some(proof) = &member.member.join_proof {
                    MembersV1::verify_token_join(member, proof, &board, &board_params)?;
                } else if member.member.invited_by == member.member.id() {
                    if !board.ownership.was_owner(&member.member.id()) {
                        return Err("Self-invitation detected".to_string());
                    }
                    member
                        .verify_signature(&member.member.member_vk)
                        .map_err(|e| format!("Invalid self-registration signature: {e}"))?;
                } else {
                    board.members.get_invite_chain_with_lookup(
                        member,
                        &board_params,
                        &members_by_id,
                    )?;
                }
            }
        }

        let max_entries = (header.header.page_size as usize).min(MAX_TOPICS_PER_PAGE);
        let mut touched_authors = HashSet::new();
        for entry in &delta.entries {
            next.verify_entry_against(params, &board, &header, entry)?;
            match next
                .entries
                .iter_mut()
                .find(|e| e.entry.topic_id == entry.entry.topic_id)
            {
                Some(existing) => {
                    if existing.entry.author != entry.entry.author {
                        return Err("topic entry update cannot change author".to_string());
                    }
                    if entry_wins(entry, existing) {
                        *existing = entry.clone();
                        touched_authors.insert(entry.entry.author);
                    }
                }
                None => {
                    if next.entries.len() >= max_entries {
                        return Err("section page is full".to_string());
                    }
                    next.entries.push(entry.clone());
                    touched_authors.insert(entry.entry.author);
                }
            }
        }

        // Enforce per-author topic creation rate limit for touched authors only.
        if !touched_authors.is_empty()
            && exceeding_member(
                next.entries
                    .iter()
                    .filter(|entry| touched_authors.contains(&entry.entry.author))
                    .map(|entry| (entry.entry.author, entry.entry.created_at)),
                TOPIC_RATE_WINDOW_MS,
                MAX_TOPICS_PER_WINDOW,
            )
            .is_some()
        {
            return Err("topic creation rate limit exceeded".to_string());
        }

        next.sort();
        *self = next;
        Ok(())
    }

    fn upsert_sealed_edit(&mut self, edit: AuthorizedTopicEntryV1) {
        match self
            .entry_edits
            .iter_mut()
            .find(|e| e.entry.topic_id == edit.entry.topic_id)
        {
            Some(existing) => {
                if entry_wins(&edit, existing) {
                    *existing = edit;
                }
            }
            None => self.entry_edits.push(edit),
        }
    }

    /// Commutative, associative, idempotent merge of two verified states.
    pub fn merge(&mut self, params: &SectionParametersV1, other: &Self) -> Result<(), String> {
        if other.header.is_none() {
            return Ok(());
        }
        if self.header.is_none() {
            other.verify(params)?;
            *self = other.clone();
            self.sort();
            return Ok(());
        }

        match (&self.seal, &other.seal) {
            (Some(our_seal), Some(their_seal)) => {
                other.verify(params)?;
                if seal_wins(their_seal, our_seal) {
                    let old_edits = std::mem::take(&mut self.entry_edits);
                    *self = other.clone();
                    for edit in old_edits {
                        if self.verify_sealed_edit(params, &edit).is_ok() {
                            self.upsert_sealed_edit(edit);
                        }
                    }
                } else {
                    for edit in &other.entry_edits {
                        if self.verify_sealed_edit(params, edit).is_ok() {
                            self.upsert_sealed_edit(edit.clone());
                        }
                    }
                }
                self.sort();
                Ok(())
            }
            (None, Some(_)) => {
                other.verify(params)?;
                let mut merged = other.clone();
                // Any higher-generation edit to a sealed entry survives sealing
                // as an entry_edit.
                for local_entry in &self.entries {
                    if merged.verify_sealed_edit(params, local_entry).is_ok() {
                        merged.upsert_sealed_edit(local_entry.clone());
                    }
                }
                merged.sort();
                *self = merged;
                Ok(())
            }
            (Some(_), None) => {
                // Keep our canonical sealed state; preserve any valid edit.
                for their_entry in &other.entries {
                    if self.verify_sealed_edit(params, their_entry).is_ok() {
                        self.upsert_sealed_edit(their_entry.clone());
                    }
                }
                self.sort();
                Ok(())
            }
            (None, None) => {
                let delta = SectionPageDeltaV1 {
                    header: other.header.clone(),
                    ownership: (!other.ownership.transfers.is_empty())
                        .then(|| other.ownership.clone()),
                    admin: (!is_empty_admins(&other.admin)).then(|| other.admin.clone()),
                    seal: None,
                    entries: other.entries.clone(),
                    entry_edits: Vec::new(),
                    authors: other.authors.clone(),
                    invites: other.invites.clone(),
                    roles: other.roles.clone(),
                    role_assignments: other.role_assignments.clone(),
                };
                self.apply_delta(params, &delta)
            }
        }
    }

    pub fn summarize(&self) -> SectionPageSummaryV1 {
        SectionPageSummaryV1 {
            has_header: self.header.is_some(),
            ownership_transfers: self.ownership.transfers.len(),
            sealed_at: self.seal.as_ref().map(|s| s.seal.sealed_at),
            entries: self
                .entries
                .iter()
                .map(|e| (e.entry.topic_id, (e.entry.generation, e.digest())))
                .collect(),
            entry_edits: self
                .entry_edits
                .iter()
                .map(|e| (e.entry.topic_id, (e.entry.generation, e.digest())))
                .collect(),
            authors: self.authors.iter().map(|m| m.member.id()).collect(),
            invites: self.invites.iter().map(|t| t.token.id).collect(),
            admins: self
                .admin
                .admins
                .iter()
                .map(|a| (a.admin.id(), a.admin.generation))
                .collect(),
            revoked_admins: self
                .admin
                .revoked
                .iter()
                .map(|r| (r.id(), r.revocation.generation))
                .collect(),
            roles: self
                .roles
                .iter()
                .map(|r| (r.role.id, r.role.generation, r.role.deleted))
                .collect(),
            role_assignments: self
                .role_assignments
                .iter()
                .map(|a| {
                    (
                        a.assignment.role_id,
                        a.assignment.member_id,
                        a.assignment.generation,
                        a.assignment.revoked,
                    )
                })
                .collect(),
        }
    }

    pub fn delta(&self, summary: &SectionPageSummaryV1) -> Option<SectionPageDeltaV1> {
        let mut delta = SectionPageDeltaV1::default();
        if !summary.has_header {
            delta.header = self.header.clone();
        }
        if self.ownership.transfers.len() > summary.ownership_transfers {
            delta.ownership = Some(self.ownership.clone());
        }
        let missing_admins: Vec<_> = self
            .admin
            .admins
            .iter()
            .filter(|a| !summary.admins.contains(&(a.admin.id(), a.admin.generation)))
            .cloned()
            .collect();
        let missing_revoked: Vec<_> = self
            .admin
            .revoked
            .iter()
            .filter(|r| {
                !summary
                    .revoked_admins
                    .contains(&(r.id(), r.revocation.generation))
            })
            .cloned()
            .collect();
        if !missing_admins.is_empty() || !missing_revoked.is_empty() {
            delta.admin = Some(AdminsV1 {
                admins: missing_admins,
                revoked: missing_revoked,
            });
        }
        if let Some(seal) = &self.seal {
            let peer_has_seal = summary
                .sealed_at
                .is_some_and(|ts| ts >= seal.seal.sealed_at);
            if !peer_has_seal {
                delta.seal = Some(seal.clone());
            }
        }
        delta.entries = self
            .entries
            .iter()
            .filter(|e| match summary.entries.get(&e.entry.topic_id) {
                None => true,
                Some(&(gen, digest)) => {
                    e.entry.generation > gen
                        || (e.entry.generation == gen && e.digest() < digest)
                }
            })
            .cloned()
            .collect();
        delta.entry_edits = self
            .entry_edits
            .iter()
            .filter(|e| match summary.entry_edits.get(&e.entry.topic_id) {
                None => true,
                Some(&(gen, digest)) => {
                    e.entry.generation > gen
                        || (e.entry.generation == gen && e.digest() < digest)
                }
            })
            .cloned()
            .collect();
        delta.authors = self
            .authors
            .iter()
            .filter(|m| !summary.authors.contains(&m.member.id()))
            .cloned()
            .collect();
        delta.invites = self
            .invites
            .iter()
            .filter(|t| !summary.invites.contains(&t.token.id))
            .cloned()
            .collect();
        delta.roles = self
            .roles
            .iter()
            .filter(|r| {
                !summary
                    .roles
                    .contains(&(r.role.id, r.role.generation, r.role.deleted))
            })
            .cloned()
            .collect();
        delta.role_assignments = self
            .role_assignments
            .iter()
            .filter(|a| {
                !summary.role_assignments.contains(&(
                    a.assignment.role_id,
                    a.assignment.member_id,
                    a.assignment.generation,
                    a.assignment.revoked,
                ))
            })
            .cloned()
            .collect();

        if delta.is_empty() {
            None
        } else {
            Some(delta)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board_state::member::Member;
    use crate::board_state::message::MessageId;
    use crate::board_state::privacy::SealedBytes;
    use crate::board_state::topics::TopicEntryV1;

    fn owner() -> SigningKey {
        SigningKey::from_bytes(&[1u8; 32])
    }

    fn member_sk(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn section_id() -> SectionId {
        MessageId::from_bytes([0x33u8; 32])
    }

    fn page_params(page: u32) -> SectionParametersV1 {
        SectionParametersV1 {
            owner: owner().verifying_key(),
            section: section_id(),
            page,
        }
    }

    fn make_member(sk: &SigningKey) -> AuthorizedMember {
        let owner_sk = owner();
        let owner_id = MemberId::from(&owner_sk.verifying_key());
        AuthorizedMember::new(
            Member {
                owner_member_id: owner_id,
                invited_by: owner_id,
                member_vk: sk.verifying_key(),
                join_proof: None,
            },
            &owner_sk,
        )
    }

    fn make_entry(
        author: &SigningKey,
        topic_byte: u8,
        created_at: i64,
        generation: u64,
        title: &str,
    ) -> AuthorizedTopicEntryV1 {
        let mut id = [0u8; 32];
        id[0] = topic_byte;
        AuthorizedTopicEntryV1::new(
            TopicEntryV1 {
                topic_id: MessageId::from_bytes(id),
                part: 0,
                protocol_version: 1,
                author: MemberId::from(&author.verifying_key()),
                section: Some(section_id()),
                section_chain: vec![section_id()],
                title: SealedBytes::public(title.as_bytes().to_vec()),
                preview: SealedBytes::public(b"Preview".to_vec()),
                header_hash: [topic_byte.max(1); 32],
                created_at,
                generation,
            },
            author,
        )
    }

    fn make_open_page(page: u32, page_size: u32) -> SectionPageStateV1 {
        let owner_sk = owner();
        let header = AuthorizedSectionPageHeaderV1::new(
            SectionPageHeaderV1 {
                board: owner_sk.verifying_key().to_bytes(),
                section: section_id(),
                section_chain: vec![section_id()],
                page,
                page_size,
                allowed_roles: Vec::new(),
                created_at: 1_000,
            },
            &owner_sk,
        );
        SectionPageStateV1 {
            header: Some(header),
            ..Default::default()
        }
    }

    #[test]
    fn open_page_accepts_member_entries_and_rejects_outsider() {
        let params = page_params(1);
        let mut state = make_open_page(1, 2);
        state.verify(&params).unwrap();

        let alice = member_sk(2);
        let alice_member = make_member(&alice);
        let topic1 = make_entry(&alice, 1, 2_000, 1, "First");
        state
            .apply_delta(
                &params,
                &SectionPageDeltaV1 {
                    authors: vec![alice_member],
                    entries: vec![topic1],
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(state.entries.len(), 1);
        assert_eq!(state.authors.len(), 1);
        state.verify(&params).unwrap();

        // Outsider without a valid member record is rejected atomically.
        let outsider = member_sk(9);
        let bad = make_entry(&outsider, 2, 3_000, 1, "Spam");
        assert!(state
            .apply_delta(
                &params,
                &SectionPageDeltaV1 {
                    entries: vec![bad],
                    ..Default::default()
                },
            )
            .is_err());
        assert_eq!(state.entries.len(), 1);
    }

    #[test]
    fn sealing_drops_authors_enforces_immutability_and_allows_author_edits() {
        let params = page_params(1);
        let mut state = make_open_page(1, 2);
        let alice = member_sk(2);
        let bob = member_sk(3);

        state
            .apply_delta(
                &params,
                &SectionPageDeltaV1 {
                    authors: vec![make_member(&alice), make_member(&bob)],
                    entries: vec![
                        make_entry(&alice, 1, 2_000, 1, "Alice topic"),
                        make_entry(&bob, 2, 3_000, 1, "Bob topic"),
                    ],
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(state.authors.len(), 2);

        // Seal page 1 as the owner.
        let seal =
            AuthorizedSectionPageSealV1::new(&params, &state.entries, &owner(), 5_000).unwrap();
        state
            .apply_delta(
                &params,
                &SectionPageDeltaV1 {
                    seal: Some(seal),
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(state.is_sealed());
        assert!(state.authors.is_empty());
        assert!(state.invites.is_empty());
        assert!(state.roles.is_empty());
        state.verify(&params).unwrap();

        // Adding a new entry to a sealed page is rejected.
        let charlie = member_sk(4);
        assert!(state
            .apply_delta(
                &params,
                &SectionPageDeltaV1 {
                    entries: vec![make_entry(&charlie, 3, 6_000, 1, "Too late")],
                    ..Default::default()
                },
            )
            .is_err());

        // Alice can still edit her sealed topic's title via `entry_edits`!
        let edited = make_entry(&alice, 1, 2_000, 2, "Alice edited");
        state
            .apply_delta(
                &params,
                &SectionPageDeltaV1 {
                    entry_edits: vec![edited.clone()],
                    ..Default::default()
                },
            )
            .unwrap();
        state.verify(&params).unwrap();
        let effective = state.effective_entries();
        let found = effective
            .iter()
            .find(|e| e.entry.topic_id == edited.entry.topic_id)
            .unwrap();
        assert_eq!(found.entry.generation, 2);

        // Bob cannot spoof an edit to Alice's topic.
        let spoof = make_entry(&bob, 1, 2_000, 3, "Spoofed");
        assert!(state
            .apply_delta(
                &params,
                &SectionPageDeltaV1 {
                    entry_edits: vec![spoof],
                    ..Default::default()
                },
            )
            .is_err());
    }

    #[test]
    fn incremental_summary_and_delta_sync_open_and_sealed_pages() {
        let params = page_params(1);
        let mut peer_a = make_open_page(1, 3);
        let mut peer_b = peer_a.clone();
        let alice = member_sk(2);
        let bob = member_sk(3);

        peer_a
            .apply_delta(
                &params,
                &SectionPageDeltaV1 {
                    authors: vec![make_member(&alice)],
                    entries: vec![make_entry(&alice, 1, 2_000, 1, "T1")],
                    ..Default::default()
                },
            )
            .unwrap();

        // Peer B syncs incrementally from Peer A.
        let delta1 = peer_a.delta(&peer_b.summarize()).expect("delta expected");
        assert_eq!(delta1.entries.len(), 1);
        assert_eq!(delta1.authors.len(), 1);
        assert!(delta1.header.is_none());
        peer_b.apply_delta(&params, &delta1).unwrap();
        assert_eq!(peer_a, peer_b);
        assert!(peer_a.delta(&peer_b.summarize()).is_none());

        // Peer A adds topic 2 and seals the page.
        peer_a
            .apply_delta(
                &params,
                &SectionPageDeltaV1 {
                    authors: vec![make_member(&bob)],
                    entries: vec![make_entry(&bob, 2, 3_000, 1, "T2")],
                    ..Default::default()
                },
            )
            .unwrap();
        let seal =
            AuthorizedSectionPageSealV1::new(&params, &peer_a.entries, &owner(), 9_000).unwrap();
        peer_a
            .apply_delta(
                &params,
                &SectionPageDeltaV1 {
                    seal: Some(seal),
                    ..Default::default()
                },
            )
            .unwrap();

        // Peer B receives only topic 2 + the seal, and compacts itself!
        let delta2 = peer_a.delta(&peer_b.summarize()).expect("seal delta");
        assert!(delta2.seal.is_some());
        assert_eq!(delta2.entries.len(), 1);
        assert!(delta2.authors.is_empty());
        peer_b.apply_delta(&params, &delta2).unwrap();
        assert_eq!(peer_a, peer_b);
        assert!(peer_b.is_sealed());
        assert!(peer_b.authors.is_empty());
        assert!(peer_a.delta(&peer_b.summarize()).is_none());
    }
}
