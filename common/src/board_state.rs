pub mod admin;
pub mod activity;
pub mod authority;
pub mod ban;
pub mod category_secrets;
pub mod configuration;
pub mod content;
pub mod id;
pub mod identity;
pub mod image_retirements;
pub mod images;
pub mod invites;
pub mod mail_addresses;
pub mod member;
pub mod member_info;
pub mod member_moderation;
pub mod member_shards;
pub mod message;
pub mod ownership;
pub mod pages;
pub mod pq_secrets;
pub mod privacy;
pub mod profiles;
pub mod rate_limit;
pub mod report_feed;
pub mod reports;
pub mod roles;
pub mod secret;
pub mod section_pages;
pub mod sections;
pub mod topics;
pub mod upgrade;
pub mod version;

use crate::board_state::admin::AdminsV1;
use crate::board_state::ban::BansV1;
use crate::board_state::category_secrets::CategorySecretsV1;
use crate::board_state::configuration::AuthorizedConfigurationV1;
use crate::board_state::invites::InviteTokensV1;
use crate::board_state::mail_addresses::MailAddressesV1;
use crate::board_state::member::{MemberId, MembersV1};
use crate::board_state::member_info::MemberInfoV1;
use crate::board_state::roles::RolesV1;
use crate::board_state::secret::BoardSecretsV1;
use crate::board_state::sections::SectionsV1;
use crate::board_state::topics::TopicIndexV1;
use crate::board_state::upgrade::OptionalUpgradeV1;
use crate::board_state::version::StateVersion;
use ed25519_dalek::VerifyingKey;
use freenet_scaffold_macro::composable;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// How this board stores discussions.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum BoardModeV1 {
    /// Section-sharded boards: the parent keeps sections and authority, each
    /// section is a child board with its own topic index and compact pages.
    #[default]
    SectionedTopicIndex,
}

impl BoardModeV1 {
    /// True when posts live in per-topic contracts indexed per section.
    pub fn is_topic_index(&self) -> bool {
        matches!(self, Self::SectionedTopicIndex)
    }
}

impl ComposableState for BoardModeV1 {
    type ParentState = ChatBoardStateV1;
    type Summary = BoardModeV1;
    type Delta = BoardModeV1;
    type Parameters = ChatBoardParametersV1;

    fn verify(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
    ) -> Result<(), String> {
        Ok(())
    }

    fn summarize(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
    ) -> Self::Summary {
        *self
    }

    fn delta(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
        _old_state_summary: &Self::Summary,
    ) -> Option<Self::Delta> {
        None
    }

    fn apply_delta(
        &mut self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
        delta: &Option<Self::Delta>,
    ) -> Result<(), String> {
        if let Some(mode) = delta {
            if *mode != *self {
                return Err("the board mode is immutable".to_string());
            }
        }
        Ok(())
    }
}

#[composable(post_apply_delta = "post_apply_cleanup")]
#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
pub struct ChatBoardStateV1 {
    // WARNING: The order of these fields is important for the purposes of the #[composable] macro.
    // `configuration` must be first, followed by `admin`, `ownership`, `bans`, `ban_revocations`,
    // `roles`, `invites`, `members`, `member_info`, `category_secrets`, `secrets`, etc.
    // This is due to interdependencies between the fields and the order in which they must be applied in
    // the `apply_delta` function. DO NOT reorder fields without fully understanding the implications.
    /// Configures things like maximum message length, can be updated by the owner.
    pub configuration: AuthorizedConfigurationV1,

    /// A list of all administrators
    /// Administrator can ban, remove content
    pub admin: AdminsV1,

    /// Signed ownership chain. After `admin`, so a transfer that promotes its
    /// target in the same update verifies the appointment, and before the
    /// fields that resolve the owner at signing time.
    #[serde(default)]
    pub ownership: crate::board_state::ownership::OwnershipV1,

    /// A list of recently banned members, a banned member can't be present in the
    /// members list and will be removed from it ifc necessary.
    pub bans: BansV1,

    /// Signed records that lift a ban. Kept as tombstones so a stale peer
    /// cannot put the ban back.
    #[serde(default)]
    pub ban_revocations: crate::board_state::ban::BanRevocationsV1,

    /// Named roles and their members, used for access control.
    #[serde(default)]
    pub roles: RolesV1,

    /// Reusable invite links. Applied before `members` so a token join can be
    /// validated in the same update that adds the member.
    #[serde(default)]
    pub invites: InviteTokensV1,

    /// The members in the chat board along with who invited them
    pub members: MembersV1,

    /// Metadata about members like their nickname, can be updated by members themselves.
    pub member_info: MemberInfoV1,

    /// Per-category secrets for restricted sections.
    #[serde(default)]
    pub category_secrets: CategorySecretsV1,

    /// Secret distribution for private boards.
    pub secrets: BoardSecretsV1,

    /// PQ KEM keys and sealed board/category secrets.
    #[serde(default)]
    pub pq_secrets: crate::board_state::pq_secrets::PqSecretsV1,

    /// Warnings addressed to members.
    #[serde(default)]
    pub warnings: crate::board_state::member_moderation::WarningsV1,

    /// Temporary suspensions addressed to members.
    #[serde(default)]
    pub suspensions: crate::board_state::member_moderation::SuspensionsV1,

    /// Signed retirements of images, including images uploaded by others, and
    /// the hash denylist derived from them.
    #[serde(default)]
    pub image_retirements: crate::board_state::image_retirements::ImageRetirementsV1,

    /// If this contract has been replaced by a new contract this will contain the new contract address.
    /// This can only be set by the owner.
    pub upgrade: OptionalUpgradeV1,

    /// State format version for migration compatibility.
    /// Defaults to 0 for backward compatibility with states created before versioning.
    #[serde(default)]
    pub version: StateVersion,

    /// Per-member Freenet Mail addresses. Added at the end of the struct so
    /// existing CBOR states keep decoding positionally. A record with a
    /// `None` address is a tombstone that clears the value.
    #[serde(default)]
    pub mail_addresses: MailAddressesV1,

    /// Layout mode for this board (`SectionedTopicIndex`).
    #[serde(default)]
    pub mode: BoardModeV1,

    /// Sections and groups for index boards.
    #[serde(default)]
    pub sections: SectionsV1,

    /// Topic index for section child boards.
    #[serde(default)]
    pub topics: TopicIndexV1,

    /// Owner-signed Merkle root of the member authority. It is the last
    /// composable field so its verification sees the authority records that
    /// were applied in the same delta.
    #[serde(default)]
    pub authority_root: crate::board_state::authority::AuthorityRootStateV1,

    /// Owner-signed list of extra topic-entry pages. Only a section manifest
    /// (page 0) uses it; other boards keep it empty.
    #[serde(default)]
    pub topic_pages: crate::board_state::pages::TopicPageListV1,
}

impl ChatBoardStateV1 {
    /// Apply a delta that only changes the topic index. Members, authority,
    /// sections and messages are unchanged, so the full cleanup (which
    /// re-verifies every entry and report) can be skipped. The topic part
    /// verifies every record in the delta and the index limits.
    pub fn apply_topics_delta(
        &mut self,
        parameters: &ChatBoardParametersV1,
        delta: &crate::board_state::topics::TopicIndexDelta,
    ) -> Result<(), String> {
        let mut topics = std::mem::take(&mut self.topics);
        let result = topics.apply_delta(self, parameters, &Some(delta.clone()));
        self.topics = topics;
        result
    }
}

impl ChatBoardStateV1 {
    /// Full verification plus the layout rules of a section-sharded board.
    /// `section` is `Some` for a child board and `None` for the parent.
    pub fn verify_with_section(
        &self,
        parameters: &ChatBoardParametersV1,
        section: Option<crate::board_state::sections::SectionId>,
    ) -> Result<(), String> {
        // A matching owner-signed root attests to the member, role, ban and
        // suspension records. Verifying every record signature again costs
        // seconds on a board with thousands of members; the root commits to
        // the same bytes with one signature.
        if self.authority_root_matches(parameters) {
            self.verify_without_authority_records(parameters)?;
        } else {
            <Self as ComposableState>::verify(self, self, parameters)?;
        }
        self.verify_sectioned_layout(parameters, section)
    }

    /// True when an owner-signed root commits to the current authority set.
    pub fn authority_root_matches(&self, parameters: &ChatBoardParametersV1) -> bool {
        self.authority_root.0.is_some()
            && self.authority_root.verify(self, parameters).is_ok()
    }

    /// Verify every field except the records the authority root covers.
    /// Callers must have checked `authority_root_matches` first. Any collection
    /// containing records outside the Merkle tree (unassigned roles, bans with
    /// `target_member: None`, non-member revocations/suspensions, or duplicate
    /// member_info) is verified in full so attackers cannot smuggle unsigned
    /// records past the root.
    fn verify_without_authority_records(
        &self,
        parameters: &ChatBoardParametersV1,
    ) -> Result<(), String> {
        self.configuration.verify(self, parameters)?;
        self.admin.verify(self, parameters)?;
        self.ownership.verify(self, parameters)?;
        self.invites.verify(self, parameters)?;
        self.verify_uncovered_authority_records(parameters)?;
        self.category_secrets.verify(self, parameters)?;
        self.secrets.verify(self, parameters)?;
        self.pq_secrets.verify(self, parameters)?;
        self.warnings.verify(self, parameters)?;
        self.image_retirements.verify(self, parameters)?;
        self.upgrade.verify(self, parameters)?;
        self.version.verify(self, parameters)?;
        self.mail_addresses.verify(self, parameters)?;
        self.mode.verify(self, parameters)?;
        self.sections.verify(self, parameters)?;
        self.topics.verify(self, parameters)?;
        self.topic_pages.verify(self, parameters)?;
        Ok(())
    }

    /// Verify any authority-related records not attested by the Merkle tree:
    /// - member_info for owner, non-covered members, or duplicate entries
    /// - unassigned roles or assignments targeting non-covered members
    /// - bans, ban revocations, or suspensions targeting non-covered members
    fn verify_uncovered_authority_records(
        &self,
        parameters: &ChatBoardParametersV1,
    ) -> Result<(), String> {
        let mut covered: std::collections::HashSet<MemberId> =
            self.members.members.iter().map(|m| m.member.id()).collect();
        for ban in &self.bans.0 {
            if let Some(target) = &ban.ban.target_member {
                covered.insert(target.member.id());
            }
        }

        // Roles: AuthorityTree only hashes roles referenced by an assignment of
        // a covered member. If any role is unassigned or any assignment targets
        // an uncovered member, verify the whole RolesV1 collection.
        let covered_role_ids: std::collections::HashSet<_> = self
            .roles
            .assignments
            .iter()
            .filter(|a| covered.contains(&a.assignment.member_id))
            .map(|a| a.assignment.role_id)
            .collect();
        let has_uncovered_roles = self
            .roles
            .roles
            .iter()
            .any(|r| !covered_role_ids.contains(&r.role.id))
            || self
                .roles
                .assignments
                .iter()
                .any(|a| !covered.contains(&a.assignment.member_id));
        if has_uncovered_roles {
            self.roles.verify(self, parameters)?;
        }

        // Bans, revocations, suspensions targeting uncovered IDs.
        if self.bans.0.iter().any(|b| !covered.contains(&b.ban.banned_user)) {
            self.bans.verify(self, parameters)?;
        }
        if self
            .ban_revocations
            .revocations
            .iter()
            .any(|r| !covered.contains(&r.revocation.banned_user))
        {
            self.ban_revocations.verify(self, parameters)?;
        }
        if self
            .suspensions
            .suspensions
            .iter()
            .any(|s| !covered.contains(&s.suspension.target))
        {
            self.suspensions.verify(self, parameters)?;
        }

        // MemberInfo: AuthorityTree only hashes the max-version entry per
        // covered member. Verify owner, uncovered members, and any duplicate
        // entries for covered members.
        let mut max_version_by_member: std::collections::HashMap<MemberId, u32> =
            std::collections::HashMap::new();
        for info in &self.member_info.member_info {
            let id = info.member_info.member_id;
            max_version_by_member
                .entry(id)
                .and_modify(|v| *v = (*v).max(info.member_info.version))
                .or_insert(info.member_info.version);
        }
        let mut seen_covered_max = std::collections::HashSet::new();
        let uncovered: Vec<_> = self
            .member_info
            .member_info
            .iter()
            .filter(|info| {
                let id = info.member_info.member_id;
                if id == parameters.owner_id() || !covered.contains(&id) {
                    return true;
                }
                let is_max = max_version_by_member.get(&id) == Some(&info.member_info.version);
                !(is_max && seen_covered_max.insert(id))
            })
            .cloned()
            .collect();
        self.member_info
            .verify_records(self, parameters, &uncovered)
    }

    fn verify_sectioned_layout(
        &self,
        _parameters: &ChatBoardParametersV1,
        section: Option<crate::board_state::sections::SectionId>,
    ) -> Result<(), String> {
        match section {
            Some(section_id) => {
                if !self
                    .sections
                    .sections
                    .iter()
                    .any(|entry| entry.section.id == section_id)
                {
                    return Err("a section board must contain its own section".to_string());
                }
                for entry in &self.topics.entries {
                    if entry.entry.section != Some(section_id) {
                        return Err("a section board cannot index topics of another section".to_string());
                    }
                }
            }
            None => {
                if !self.topics.entries.is_empty()
                    || !self.topics.activity.is_empty()
                    || !self.topics.flags.is_empty()
                    || !self.topics.reports.is_empty()
                    || !self.topics.report_resolutions.is_empty()
                {
                    return Err(
                        "a sectioned board keeps topics in its section boards".to_string()
                    );
                }
            }
        }
        Ok(())
    }

    /// Verify a non-topic delta after it was applied. The topic part already
    /// verified its new records; re-verifying every topic on a member or
    /// authority change would scan the whole board index. Parts that can
    /// interact with each other are verified together whenever one changes.
    pub fn verify_delta(
        &self,
        delta: &ChatBoardStateV1Delta,
        parameters: &ChatBoardParametersV1,
    ) -> Result<(), String> {
        self.configuration.verify(self, parameters)?;
        self.admin.verify(self, parameters)?;
        self.ownership.verify(self, parameters)?;
        self.mode.verify(self, parameters)?;

        let authority_changed = delta.bans.is_some()
            || delta.ban_revocations.is_some()
            || delta.roles.is_some()
            || delta.invites.is_some()
            || delta.members.is_some()
            || delta.suspensions.is_some()
            || delta.admin.is_some()
            || delta.ownership.is_some();
        // The owner re-signs the root before syncing, so an authority change
        // normally arrives with a matching root and skips the per-record
        // signature checks. A member-driven change without the new root keeps
        // the full path.
        let root_matches =
            authority_changed && self.authority_root_matches(parameters);
        if authority_changed {
            if !root_matches {
                self.bans.verify(self, parameters)?;
                self.ban_revocations.verify(self, parameters)?;
                self.roles.verify(self, parameters)?;
                self.members.verify(self, parameters)?;
            }
            self.invites.verify(self, parameters)?;
        }
        if let Some(records) = delta.member_info.as_ref() {
            // Verify the records the delta carries, not every nickname on
            // the board.
            self.member_info
                .verify_records(self, parameters, records)?;
        }

        if delta.sections.is_some() {
            self.sections.verify(self, parameters)?;
        }
        if delta.secrets.is_some() {
            self.secrets.verify(self, parameters)?;
        }
        if delta.category_secrets.is_some() {
            self.category_secrets.verify(self, parameters)?;
        }
        if delta.pq_secrets.is_some() {
            self.pq_secrets.verify(self, parameters)?;
        }
        if delta.warnings.is_some() {
            self.warnings.verify(self, parameters)?;
        }
        if delta.suspensions.is_some() && !root_matches {
            self.suspensions.verify(self, parameters)?;
        }
        if delta.image_retirements.is_some() {
            self.image_retirements.verify(self, parameters)?;
        }
        if delta.upgrade.is_some() {
            self.upgrade.verify(self, parameters)?;
        }
        if delta.mail_addresses.is_some() {
            self.mail_addresses.verify(self, parameters)?;
        }
        if (delta.authority_root.is_some()
            || delta.members.is_some()
            || delta.roles.is_some()
            || delta.bans.is_some()
            || delta.ban_revocations.is_some()
            || delta.suspensions.is_some())
            && !root_matches
        {
            self.authority_root.verify(self, parameters)?;
        }
        if delta.topic_pages.is_some() {
            self.topic_pages.verify(self, parameters)?;
        }
        self.topics.verify_limits()?;
        Ok(())
    }
}

impl ChatBoardStateV1Delta {
    /// A delta that only changes the topic index has no cross-part authority
    /// or member changes. The contract can verify it without re-verifying the
    /// whole board.
    pub fn is_topics_only(&self) -> bool {
        self.configuration.is_none()
            && self.admin.is_none()
            && self.ownership.is_none()
            && self.bans.is_none()
            && self.ban_revocations.is_none()
            && self.roles.is_none()
            && self.invites.is_none()
            && self.members.is_none()
            && self.member_info.is_none()
            && self.category_secrets.is_none()
            && self.secrets.is_none()
            && self.pq_secrets.is_none()
            && self.warnings.is_none()
            && self.suspensions.is_none()
            && self.image_retirements.is_none()
            && self.upgrade.is_none()
            && self.version.is_none()
            && self.mail_addresses.is_none()
            && self.mode.is_none()
            && self.sections.is_none()
            && self.authority_root.is_none()
            && self.topic_pages.is_none()
            && self.topics.is_some()
    }

    /// True for a delta that only refreshes topic activity.
    pub fn is_activity_only(&self) -> bool {
        self.is_topics_only()
            && self
                .topics
                .as_ref()
                .is_some_and(|topics| topics.is_activity_only())
    }
}

impl ChatBoardStateV1 {
    /// Post-apply cleanup: enforce invite caps, remove orphaned bans, clean up
    /// revoked admins/roles, category secrets, PQ secrets, warnings,
    /// suspensions, retirements, sections, and topic index, and keep records
    /// canonically sorted for deterministic CRDT convergence.
    fn post_apply_cleanup(&mut self, parameters: &ChatBoardParametersV1) -> Result<(), String> {
        let owner_id = MemberId::from(&parameters.owner);

        // Normalize the ownership chain first: the cleanups below resolve
        // authority against it.
        let mut ownership = std::mem::take(&mut self.ownership);
        ownership.cleanup(self, parameters);
        self.ownership = ownership;

        // 0. Enforce invite-link use caps first.
        self.enforce_invite_caps();

        // 5. Clean orphaned bans: keep only bans whose banner is still available
        // to sign/verify them.
        let current_member_ids: HashSet<MemberId> =
            self.members.members.iter().map(|m| m.member.id()).collect();

        self.bans.0.retain(|ban| {
            ban.ban.banned_user != owner_id
                && (ban.banned_by == owner_id || current_member_ids.contains(&ban.banned_by))
        });

        // 5a-bis. A revocation lifts its ban. Doing this before the cap keeps
        // revoked bans from evicting active ones.
        let mut revocations = std::mem::take(&mut self.ban_revocations);
        revocations.cleanup(self, parameters);
        self.ban_revocations = revocations;
        let revoked_ids: HashSet<_> = self
            .ban_revocations
            .revocations
            .iter()
            .map(|entry| entry.revocation.ban_id.clone())
            .collect();
        self.bans.0.retain(|ban| !revoked_ids.contains(&ban.id()));

        // 5b. Enforce the ban cap after the removals above. Doing it here (and
        // not only when a delta arrives) means lowering `max_user_bans` in the
        // configuration trims the collection deterministically instead of
        // leaving a state that `verify` rejects forever.
        let mut bans = std::mem::take(&mut self.bans);
        bans.enforce_cap(self, parameters);
        self.bans = bans;

        // 5c. Revocations win over admin records, so drop any admin the owner
        // has revoked. Running it here keeps merged states normalized.
        self.admin.resolve_conflicts();

        // The current owner has every admin power implicitly. A later signed
        // revocation (written after a self-handover) makes the old admin
        // record removable; ownership verification then reads the revocation
        // instead. Keep the record until that tombstone exists, or a transfer
        // would stop verifying.
        let current_owner = self.ownership.current_owner(parameters);
        if self
            .admin
            .admins
            .iter()
            .any(|admin| admin.admin.id() == current_owner)
        {
            let transfer_at = self
                .ownership
                .transfers
                .last()
                .map(|entry| entry.transfer.transferred_at);
            let revoked_after = self.admin.revoked.iter().any(|revocation| {
                revocation.id() == current_owner
                    && match transfer_at {
                        Some(at) => revocation.revocation.signed_at > at,
                        None => true,
                    }
            });
            if revoked_after {
                self.admin
                    .admins
                    .retain(|admin| admin.admin.id() != current_owner);
            }
        }

        // 5c-bis. An admin proof stops vouching for records once the owner
        // revokes that admin. Drop those records instead of leaving a state
        // that every later verification rejects.
        let mut bans = std::mem::take(&mut self.bans);
        bans.cleanup(self, parameters);
        self.bans = bans;

        let mut roles = std::mem::take(&mut self.roles);
        roles.cleanup(self, parameters);
        self.roles = roles;

        // 5d. Category key blobs only make sense for current members, signed
        // by the owner or by a current key-distribution role. Dropping the
        // others keeps the state valid after a member is pruned or a role
        // loses the permission.
        let authorized_signers: HashSet<MemberId> = std::iter::once(owner_id)
            .chain(
                self.members
                    .members
                    .iter()
                    .map(|member| member.member.id())
                    .filter(|member_id| self.roles.can_distribute_keys(member_id)),
            )
            .collect();
        for set in &mut self.category_secrets.categories {
            let current_version = set.current_version;
            set.encrypted_secrets.retain(|blob| {
                let signer = blob.signer.unwrap_or(owner_id);
                authorized_signers.contains(&signer)
                    && (blob.secret.member_id == owner_id
                        || current_member_ids.contains(&blob.secret.member_id))
                    && blob.secret.secret_version <= current_version
                    && !blob.secret.ciphertext.is_empty()
                    && blob.secret.ciphertext.len() <= 4096
            });
        }
        // Drop empty sets: they are unauthenticated and would otherwise be an
        // unbounded, replicated growth vector.
        self.category_secrets
            .categories
            .retain(|set| !set.versions.is_empty() || !set.encrypted_secrets.is_empty());

        // Index sections run before PQ secrets so PqScope::Category resolves
        // against the cleaned section set.
        let mut sections = std::mem::take(&mut self.sections);
        sections.cleanup(self, parameters);
        self.sections = sections;

        let mut pq = std::mem::take(&mut self.pq_secrets);
        pq.cleanup(self, parameters);
        self.pq_secrets = pq;

        let mut warnings = std::mem::take(&mut self.warnings);
        warnings.cleanup(self, parameters);
        self.warnings = warnings;

        let mut suspensions = std::mem::take(&mut self.suspensions);
        suspensions.cleanup(self, parameters);
        self.suspensions = suspensions;

        // Deterministic long-term pruning of expired suspensions and expired/
        // deleted unreferenced invite tokens, anchored to the state's own max
        // signed timestamp (never wall clock) so all peers converge identically.
        self.prune_expired_records(parameters);

        let mut retirements = std::mem::take(&mut self.image_retirements);
        retirements.cleanup(self, parameters);
        self.image_retirements = retirements;

        let mut topics = std::mem::take(&mut self.topics);
        topics.cleanup(self, parameters);
        self.topics = topics;

        // 6. Re-sort for deterministic ordering
        self.members.members.sort_by_key(|m| m.member.id());
        self.member_info
            .member_info
            .sort_by_key(|info| info.member_info.member_id);

        // The root is a commitment, not the authority itself. A member-driven
        // delta, member cleanup, or ownership transfer can invalidate it
        // without a new owner signature; drop the stale root and let the
        // current owner sign a new one on the next sync. Topics then use the
        // full authority lists.
        if let Some(root) = &self.authority_root.0 {
            let superseded_by_transfer = self.ownership.transfers.last().is_some_and(|t| {
                root.root.epoch
                    < crate::board_state::rate_limit::system_time_ms(t.transfer.transferred_at)
            });
            let tree = crate::board_state::authority::AuthorityTreeV1::from_board(self);
            if superseded_by_transfer
                || tree.root(root.root.epoch).digest != root.root.digest
                || tree.content_hash() != root.root.content_hash
            {
                self.authority_root.0 = None;
            }
        }

        Ok(())
    }

    /// Retention grace period (30 days) before expired suspensions and expired
    /// or deleted unreferenced invite tokens are pruned deterministically.
    pub const EXPIRED_RECORD_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1_000;

    /// Deterministic state-clock watermark derived strictly from owner-signed
    /// timestamps inside `self` (never wall clock, and never moderator-signed
    /// timestamps that could be inflated to prematurely purge records).
    pub fn deterministic_watermark_ms(&self) -> i64 {
        let mut max_ms = crate::board_state::rate_limit::system_time_ms(
            self.configuration.configuration.updated_at,
        );
        if let Some(root) = &self.authority_root.0 {
            max_ms = max_ms.max(root.root.epoch);
        }
        for transfer in &self.ownership.transfers {
            max_ms = max_ms.max(crate::board_state::rate_limit::system_time_ms(
                transfer.transfer.transferred_at,
            ));
        }
        max_ms
    }

    /// Deterministically prune long-expired suspensions and deleted/expired
    /// invite tokens not referenced by any member in `self.members`.
    pub fn prune_expired_records(&mut self, _parameters: &ChatBoardParametersV1) {
        let watermark = self.deterministic_watermark_ms();
        if watermark <= Self::EXPIRED_RECORD_RETENTION_MS {
            return;
        }
        let cutoff = watermark - Self::EXPIRED_RECORD_RETENTION_MS;
        self.suspensions
            .suspensions
            .retain(|entry| entry.suspension.until >= cutoff);

        let referenced_tokens: HashSet<[u8; 16]> = self
            .members
            .members
            .iter()
            .filter_map(|m| m.member.join_proof.as_ref().map(|p| p.token_id))
            .collect();
        self.invites.tokens.retain(|entry| {
            if referenced_tokens.contains(&entry.token.id) {
                return true;
            }
            if entry.token.deleted {
                let created = entry
                    .token
                    .created_at
                    .map(crate::board_state::rate_limit::system_time_ms)
                    .unwrap_or(0);
                return created >= cutoff;
            }
            if let Some(not_after) = entry.token.not_after {
                let exp_ms = crate::board_state::rate_limit::system_time_ms(not_after);
                return exp_ms >= cutoff;
            }
            true
        });
    }

    /// Keep at most `max_uses` members per invite link, choosing the lowest
    /// member ids. Deterministic, so peers that merge joins in a different order
    /// still keep the same members.
    pub(crate) fn enforce_invite_caps(&mut self) {
        let tokens: Vec<_> = self.invites.tokens.clone();
        for token in tokens {
            let Some(max) = token.token.max_uses else {
                continue;
            };
            let mut joined: Vec<MemberId> = self
                .members
                .members
                .iter()
                .filter(|m| {
                    m.member
                        .join_proof
                        .as_ref()
                        .map(|p| p.token_id == token.token.id)
                        .unwrap_or(false)
                })
                .map(|m| m.member.id())
                .collect();
            if joined.len() <= max as usize {
                continue;
            }
            joined.sort();
            let keep: HashSet<MemberId> = joined.into_iter().take(max as usize).collect();
            self.members.members.retain(|m| match &m.member.join_proof {
                Some(proof) if proof.token_id == token.token.id => keep.contains(&m.member.id()),
                _ => true,
            });
        }
    }

    /// Run the same cleanup `apply_delta` runs after every update.
    ///
    /// Exposed so the contract can check whether a state it is asked to accept
    /// is already normalized: a state that cleanup would change makes peers
    /// rewrite it on every round trip instead of converging.
    pub fn normalize(&mut self, parameters: &ChatBoardParametersV1) -> Result<(), String> {
        self.post_apply_cleanup(parameters)
    }
}

#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
pub struct ChatBoardParametersV1 {
    pub owner: VerifyingKey,
}

impl ChatBoardParametersV1 {
    pub fn owner_id(&self) -> MemberId {
        self.owner.into()
    }
}

#[cfg(test)]
mod tests;
