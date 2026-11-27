#![allow(dead_code)]

mod boards;
mod secrets;
#[cfg(test)]
mod tests;

pub use boards::{BoardIdentityMode, Boards, CurrentBoard, IdentityProfile, ProfileLinkability};

use crate::util::ecies::encrypt_secret_for_member;
use crate::util::get_current_system_time;
use crate::util::mail::MailVisibility;
use crate::{constants::BOARD_CONTRACT_WASM, util::to_cbor_vec};
use ed25519_dalek::{SigningKey, VerifyingKey};
use freenet_scaffold::ComposableState;
use freenet_stdlib::prelude::{ContractCode, ContractKey, Parameters};
use plaza_core::board_state::category_secrets::{CategorySecretSetDelta, CategorySecretsDelta};
use plaza_core::board_state::configuration::{AuthorizedConfigurationV1, Configuration};
use plaza_core::board_state::content::CategoryContentV1;
use plaza_core::board_state::admin::{Admin, AuthorizedAdmin};
use plaza_core::board_state::member::{AuthorizedMember, Member, MemberId};
use plaza_core::board_state::member_info::{AuthorizedMemberInfo, MemberInfo};
use plaza_core::board_state::message::MessageId;
use plaza_core::board_state::privacy::{
    BoardCipherSpec, BoardDisplayMetadata, PrivacyMode, SealedBytes,
};
use plaza_core::board_state::roles::{ModerationPower, RolesV1};
use plaza_core::board_state::secret::{
    AuthorizedEncryptedSecretForMember, AuthorizedSecretVersionRecord, EncryptedSecretForMemberV1,
    SecretVersionRecordV1,
};
use plaza_core::board_state::ChatBoardParametersV1;
use plaza_core::chat_delegate::BoardKey;
use plaza_core::ChatBoardStateV1;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, PartialEq)]
pub enum SendMessageError {
    UserNotMember,
    UserBanned,
    UserSuspended,
}

/// Client-side suspension check. The contract has no clock, so only the
/// client can tell whether a suspension is still running.
pub fn is_suspended_now(state: &ChatBoardStateV1, member: MemberId) -> bool {
    state
        .suspensions
        .active_until(member, chrono::Utc::now().timestamp_millis())
        .is_some()
}

/// Whether `member` holds `power` over `scope_chain` right now. A suspended
/// member keeps no power until the suspension ends. The contract still
/// verifies records signed before the suspension against the raw roles.
pub fn has_moderation_power(
    state: &ChatBoardStateV1,
    member: MemberId,
    power: ModerationPower,
    scope_chain: &[MessageId],
) -> bool {
    !is_suspended_now(state, member)
        && state
            .roles
            .has_moderation_power(&member, power, scope_chain)
}

pub fn can_manage_trash(state: &ChatBoardStateV1, member: MemberId) -> bool {
    !is_suspended_now(state, member) && state.roles.can_manage_trash(&member)
}

pub fn can_manage_access(state: &ChatBoardStateV1, member: MemberId) -> bool {
    !is_suspended_now(state, member) && state.roles.can_manage_access(&member)
}

/// A snapshot of the viewer's powers for closures that outlive the board data.
#[derive(Clone)]
pub struct ViewerPowers {
    roles: RolesV1,
    member: MemberId,
    suspended: bool,
}

impl Default for ViewerPowers {
    fn default() -> Self {
        Self {
            roles: RolesV1::default(),
            member: MemberId::from_bytes([0u8; 32]),
            suspended: true,
        }
    }
}

impl ViewerPowers {
    pub fn has_moderation_power(&self, power: ModerationPower, scope_chain: &[MessageId]) -> bool {
        !self.suspended
            && self
                .roles
                .has_moderation_power(&self.member, power, scope_chain)
    }
}

/// Unsent composer content. Local to this user and persisted in the delegate
/// store, so a reload or a navigation does not lose a half-written post.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug, Default)]
pub struct ComposerDraft {
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub reply_to: Option<MessageId>,
    #[serde(default)]
    pub reply_author: String,
    #[serde(default)]
    pub reply_preview: String,
    #[serde(default)]
    pub updated_at: i64,
}

/// An image prepared for upload that is not published yet. It rides with the
/// board in the delegate store, so a reload can resume it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PendingUpload {
    pub id: String,
    pub name: String,
    pub alt: String,
    pub nsfw: bool,
    pub mime: String,
    pub width: u32,
    pub height: u32,
    pub animated: bool,
    #[serde(default)]
    pub bytes: Vec<u8>,
    /// Board or section key that sealed the payload, kept so a reload resumes
    /// the same upload with the same bytes.
    #[serde(default)]
    pub secret: Option<([u8; 32], u32)>,
    /// Set once the blob is on the node, so a reload does not upload it again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<plaza_core::board_state::images::ImageRef>,
}

/// A post waiting for its images. The composer writes it when the user sends
/// during an upload; the background resume finishes uploads and publishes it.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct PendingSend {
    pub title: String,
    pub text: String,
    pub reply_to: Option<MessageId>,
    pub reply_author: Option<String>,
    pub reply_preview: Option<String>,
    pub category_id: Option<MessageId>,
    /// Attachments still uploading when the post was queued.
    #[serde(default)]
    pub attachment_ids: Vec<String>,
    /// Attachments already uploaded, kept so a crash mid-resume loses nothing.
    #[serde(default)]
    pub images: Vec<plaza_core::board_state::images::ImageRef>,
    /// The topic author moderates replies; queued with the rest of the intent.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub auto_moderated: bool,
    /// Topic membership key for the queued reply, kept so a resume can prove
    /// membership even before the board state is merged again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic_proof_key: Option<SigningKey>,
    #[serde(default)]
    pub queued_at: i64,
}

/// Raw copies of one uploaded blob, kept so it can be put back on the
/// network after nodes drop it.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct OwnedChunkCopy {
    pub parameters: Vec<u8>,
    pub state: Vec<u8>,
}

fn default_true() -> bool {
    true
}

/// One image this device uploaded, with what is needed to renew it and to
/// attach it again without uploading.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct OwnedImage {
    pub image: plaza_core::board_state::images::ImageRef,
    pub parameters: Vec<u8>,
    pub state: Vec<u8>,
    #[serde(default)]
    pub chunks: Vec<OwnedChunkCopy>,
    pub uploaded_at: i64,
    #[serde(default)]
    pub renewed_at: i64,
    /// Set once the image has been published in a topic post. Defaults to `true`
    /// when deserializing older records so pre-existing published uploads are
    /// never mistaken for unreferenced drafts.
    #[serde(default = "default_true")]
    pub published: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize, Default)]
pub enum NotificationMode {
    #[default]
    All,
    MentionsAndReplies,
    Muted,
}

impl NotificationMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::MentionsAndReplies => "mentions",
            Self::Muted => "muted",
        }
    }

    pub fn from_str(value: &str) -> Self {
        match value {
            "mentions" => Self::MentionsAndReplies,
            "muted" => Self::Muted,
            _ => Self::All,
        }
    }
}

fn default_topic_boards() -> bool {
    true
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ClientFeatures {
    /// Append the short member id in the member list.
    #[serde(default)]
    pub show_member_ids: bool,
    /// New boards use section-sharded topic contracts. Defaults to `true`.
    #[serde(default = "default_topic_boards")]
    pub topic_boards: bool,
}

impl Default for ClientFeatures {
    fn default() -> Self {
        Self {
            show_member_ids: false,
            topic_boards: true,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize, Default)]
pub enum NicknameRequestStatus {
    #[default]
    Pending,
    Approved,
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NicknameRequest {
    pub id: String,
    pub member_id: MemberId,
    pub current_name: String,
    pub requested_name: String,
    pub created_at: i64,
    #[serde(default)]
    pub status: NicknameRequestStatus,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct BoardData {
    pub owner_vk: VerifyingKey,
    pub board_state: ChatBoardStateV1,
    /// Key used for posts, admin and membership. It is the chosen profile and
    /// may be shared with other boards.
    pub self_sk: SigningKey,
    /// Key that owns this board. Older boards did not store it separately;
    /// `owner_key()` then falls back to `self_sk`.
    #[serde(default)]
    pub owner_sk: Option<SigningKey>,
    /// Local root profile this board's posting key belongs to. On a private
    /// board the key may be derived from the profile and differ from it.
    /// Boards stored before profiles had this link have no id here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    /// Root profile that owns this board. `profile_id` follows the visible
    /// profile; this one stays on the owner's profile, so owner controls do
    /// not appear while browsing as a member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_profile_id: Option<String>,
    pub contract_key: ContractKey,
    /// The last message ID that was read by the user (for unread tracking)
    /// Messages after this ID from other users are considered unread.
    /// This is persisted to delegate storage.
    #[serde(default)]
    pub last_read_message_id: Option<MessageId>,
    /// All decrypted board secrets by version (if board is private)
    /// Maps secret_version -> decrypted 32-byte secret
    #[serde(skip)]
    pub secrets: HashMap<u32, [u8; 32]>,
    /// Homepage groups this user collapsed. Local UI preference, persisted in
    /// the delegate; never part of the shared board state.
    #[serde(default)]
    pub collapsed_groups: Vec<MessageId>,

    /// Last time the user marked notifications as read (milliseconds).
    #[serde(default)]
    pub last_visit: i64,

    /// Last time each section was opened (milliseconds), for unread badges.
    #[serde(default)]
    pub read_categories: HashMap<MessageId, i64>,

    /// Last time each topic was opened (milliseconds) for index boards.
    #[serde(default)]
    pub topic_read: HashMap<MessageId, i64>,

    /// Unsent reply drafts per topic. Local UI state, never shared.
    #[serde(default)]
    pub topic_drafts: HashMap<MessageId, String>,

    /// What this device wants to be notified about on this board.
    #[serde(default)]
    pub notification_mode: NotificationMode,

    /// Whether this board shows the profile's Freenet Mail address. Local
    /// preference; the address itself travels as a signed action.
    #[serde(default)]
    pub mail_visibility: MailVisibility,

    /// Structured nickname change requests awaiting an owner/admin decision.
    #[serde(default)]
    pub nickname_requests: Vec<NicknameRequest>,

    /// The composer's unsent post. Local UI state, never shared with the board.
    #[serde(default)]
    pub draft: Option<ComposerDraft>,
    /// Drafts the user saved for later. Local UI state, kept newest first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub drafts: Vec<ComposerDraft>,
    /// Days after which items in the trash are purged when the Trash page
    /// opens. Zero disables it. Local preference.
    #[serde(default)]
    pub trash_retention_days: u32,
    /// Image uploads prepared but not yet published. Kept in memory only: the
    /// records carry the file bytes (up to 24 MiB) and are stored under their
    /// own delegate key. The field still deserializes so a blob written by an
    /// older version can be migrated; new saves omit it.
    #[serde(default, skip_serializing)]
    pub pending_uploads: Vec<PendingUpload>,

    /// A post the user asked to publish whose images were still uploading.
    /// Persisted so a reload finishes the upload and sends it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_send: Option<PendingSend>,

    /// Sections the user follows. New topics in these sections show up in the
    /// notifications list. Local preference, persisted in the delegate.
    #[serde(default)]
    pub subscribed_categories: Vec<MessageId>,

    /// Decrypted per-category secrets: category id -> (version, key).
    ///
    /// Persisted in the delegate store because an invite link can deliver a
    /// key that never becomes an owner-signed blob; without this, it would
    /// disappear on reload.
    #[serde(default)]
    pub category_secrets: HashMap<MessageId, (u32, [u8; 32])>,

    /// Keys from earlier versions of a rotated category, so messages sealed
    /// before the rotation stay readable. Local to this member.
    #[serde(default)]
    pub old_category_secrets: HashMap<MessageId, HashMap<u32, [u8; 32]>>,
    /// Decrypted board trash key: (secret version, key). Local to each manager.
    #[serde(default)]
    pub trash_secret: Option<(u32, [u8; 32])>,
    /// Every trash key this client has opened, by secret version. Rotation
    /// replaces the current key; older items stay readable with their version.
    #[serde(default)]
    pub trash_secrets: HashMap<u32, [u8; 32]>,
    /// The current (latest) secret version
    #[serde(skip)]
    pub current_secret_version: Option<u32>,
    /// When the secret was last rotated (for weekly rotation checks)
    #[serde(skip)]
    pub last_secret_rotation: Option<std::time::SystemTime>,
    /// Whether the signing key has been migrated to the delegate
    /// This is runtime state and not persisted - checked on each startup
    #[serde(skip)]
    pub key_migrated_to_delegate: bool,
    /// The user's own AuthorizedMember, stored so they can re-add themselves
    /// after being pruned for inactivity (no recent messages).
    #[serde(default)]
    pub self_authorized_member: Option<AuthorizedMember>,
    /// The invite chain members needed to validate self_authorized_member.
    /// Contains all members in the chain from self up to (but not including) the owner.
    #[serde(default)]
    pub invite_chain: Vec<AuthorizedMember>,
    /// The user's own AuthorizedMemberInfo, stored so their nickname survives
    /// being pruned for inactivity and re-added.
    #[serde(default)]
    pub self_member_info: Option<AuthorizedMemberInfo>,
    /// A public board opened in read-only mode: this client holds a local
    /// identity that is never published, so the contract grows by nothing.
    #[serde(default)]
    pub spectator: bool,
}

impl BoardData {
    /// For a sectioned board, present the union of the parent and child topic
    /// indexes as one index for the read-only UI.
    pub fn with_merged_topics(mut self) -> Self {
        if self.board_state.mode
            == plaza_core::board_state::BoardModeV1::SectionedTopicIndex
        {
            self.board_state.topics = crate::components::app::section_contract::merged_index(
                self.owner_vk,
                &self.board_state.topics,
            );
        }
        // Sharded members live in deterministic bucket contracts; overlay the
        // verified entries on the parent board before resolving activity,
        // moderation and profiles.
        let mut sharded_members = std::mem::take(&mut self.board_state.members);
        crate::components::app::member_contract::apply_to_members(
            self.owner_vk,
            &self.board_state,
            &mut sharded_members,
        );
        self.board_state.members = sharded_members;
        let members: std::collections::HashSet<_> = self
            .board_state
            .members
            .members
            .iter()
            .map(|member| member.member.id())
            .collect();
        crate::components::app::activity_contract::apply_to_index(
            self.owner_vk,
            &members,
            &mut self.board_state.topics,
        );
        // Reports and resolutions live in their own contract; the moderation
        // view overlays the verified entries on the merged index.
        let mut topics = std::mem::take(&mut self.board_state.topics);
        crate::components::app::moderation_contract::apply_to_index(
            self.owner_vk,
            &self.board_state,
            &mut topics,
        );
        self.board_state.topics = topics;
        // Nicknames live in their own contract; overlay the verified entries
        // on the legacy list for display.
        let mut member_info = std::mem::take(&mut self.board_state.member_info);
        crate::components::app::profile_contract::apply_to_member_info(
            self.owner_vk,
            &self.board_state,
            &mut member_info,
        );
        self.board_state.member_info = member_info;
        self
    }

    pub fn topic_last_read(&self, topic: &MessageId) -> i64 {
        self.topic_read.get(topic).copied().unwrap_or(0)
    }

    pub fn mark_topic_read(&mut self, topic: MessageId, at: i64) {
        if at > self.topic_last_read(&topic) {
            self.topic_read.insert(topic, at);
        }
    }

    pub fn topic_draft(&self, topic: &MessageId) -> String {
        self.topic_drafts.get(topic).cloned().unwrap_or_default()
    }

    pub fn set_topic_draft(&mut self, topic: MessageId, text: &str) {
        if text.trim().is_empty() {
            self.topic_drafts.remove(&topic);
        } else {
            self.topic_drafts.insert(topic, text.to_string());
        }
    }

    /// Whether the visible identity may delete/approve content in a section.
    pub fn can_moderate(&self, scope_chain: &[MessageId]) -> bool {
        let self_id = MemberId::from(&self.self_sk.verifying_key());
        if self_id == MemberId::from(&self.owner_vk)
            || self_id == self.current_owner_id()
        {
            return true;
        }
        let admin = self
            .board_state
            .admin
            .admins
            .iter()
            .any(|entry| entry.admin.id() == self_id);
        let revoked = self
            .board_state
            .admin
            .revoked
            .iter()
            .any(|entry| entry.id() == self_id);
        if admin && !revoked {
            return true;
        }
        self.board_state.roles.has_moderation_power(
            &self_id,
            plaza_core::board_state::roles::ModerationPower::Delete,
            scope_chain,
        )
    }

    /// Contract parameters for this board: the founding owner is the identity.
    pub fn board_parameters(&self) -> ChatBoardParametersV1 {
        ChatBoardParametersV1 {
            owner: self.owner_vk,
        }
    }

    /// Current owner from the signed transfer chain.
    pub fn current_owner_id(&self) -> MemberId {
        self.board_state
            .ownership
            .current_owner(&self.board_parameters())
    }

    pub fn current_owner_key(&self) -> VerifyingKey {
        self.board_state
            .ownership
            .current_owner_key(&self.board_parameters())
    }

    /// Whether this client holds the owner powers right now.
    /// Key that signs ownership and configuration. Older boards use the same
    /// key for ownership and posting. After a handover to this client's own
    /// profile, prefer the key that the signed ownership chain names.
    pub fn owner_key(&self) -> &SigningKey {
        let current = self.current_owner_key();
        if let Some(owner) = &self.owner_sk {
            if owner.verifying_key() == current {
                return owner;
            }
        }
        if self.self_sk.verifying_key() == current {
            return &self.self_sk;
        }
        self.owner_sk.as_ref().unwrap_or(&self.self_sk)
    }

    pub fn is_current_owner(&self) -> bool {
        self.owner_key().verifying_key() == self.current_owner_key()
    }

    /// Recompute and sign the board authority root when the member, role, ban
    /// or suspension records changed. Members cannot sign it; they receive the
    /// owner's root through the board state.
    pub fn refresh_authority_root(&mut self) {
        let Some(owner_sk) = self.owner_sk.as_ref() else {
            return;
        };
        if owner_sk.verifying_key() != self.current_owner_key() {
            return;
        }
        let tree = plaza_core::board_state::authority::AuthorityTreeV1::from_board(
            &self.board_state,
        );
        let content_hash = tree.content_hash();
        let digest = tree.root(0).digest;
        if self
            .board_state
            .authority_root
            .0
            .as_ref()
            .is_some_and(|root| {
                root.root.digest == digest && root.root.content_hash == content_hash
            })
        {
            return;
        }
        let now = plaza_core::board_state::rate_limit::system_time_ms(
            get_current_system_time(),
        );
        let mut root = tree.root(now);
        root.content_hash = content_hash;
        self.board_state.authority_root =
            plaza_core::board_state::authority::AuthorityRootStateV1(Some(
                plaza_core::board_state::authority::AuthorizedAuthorityRootV1::new(
                    root, owner_sk,
                ),
            ));
    }

    /// Whether the visible identity is the owner, not only whether this client
    /// holds the owner key. The owner key stays available after switching to a
    /// member profile; using it must not put the owner crown or Manage on that
    /// member's name.
    pub fn is_active_owner(&self) -> bool {
        if self.self_sk.verifying_key() == self.current_owner_key() {
            return true;
        }
        match (&self.owner_profile_id, &self.profile_id) {
            (Some(owner), Some(current)) => owner == current,
            _ => false,
        }
    }

    /// Legacy boards stored no owner profile. The creator profile is the first
    /// admin; when the visible profile is that admin, record it as the owner.
    /// A member profile never matches, so it cannot inherit the crown.
    pub fn backfill_owner_profile(&mut self) {
        if self.owner_profile_id.is_some() {
            return;
        }
        let Some(profile_id) = self.profile_id.clone() else {
            return;
        };
        let self_id = MemberId::from(&self.self_sk.verifying_key());
        let creator_is_visible = self
            .board_state
            .admin
            .admins
            .first()
            .is_some_and(|admin| admin.admin.id() == self_id);
        if creator_is_visible {
            self.owner_profile_id = Some(profile_id);
        }
    }

    /// Whether this board signs as the profile's root key. A derived board
    /// signs with another key and is not linked to the profile's other boards.
    pub fn uses_same_identity_as(&self, profile: &IdentityProfile) -> bool {
        self.self_sk == profile.signing_key
    }

    /// Key and signer id for management records. The owner signs as the owner;
    /// a profile signs as a member and must carry its authority proof.
    pub fn management_signer(&self) -> (SigningKey, Option<MemberId>) {
        if self.is_current_owner() {
            (self.owner_key().clone(), None)
        } else {
            (
                self.self_sk.clone(),
                Some(MemberId::from(&self.self_sk.verifying_key())),
            )
        }
    }

    /// Use another stored profile for this board without leaving it. The
    /// profile must already be a member and must not be deactivated here.
    pub fn switch_profile(&mut self, signing_key: &SigningKey) -> Result<(), String> {
        let vk = signing_key.verifying_key();
        let member = self
            .board_state
            .members
            .members
            .iter()
            .find(|member| member.member.member_vk == vk)
            .cloned()
            .ok_or("That profile is not a member of this board")?;
        if self
            .board_state
            .ownership
            .is_deactivated_now(&member.member.id())
        {
            return Err("That profile is deactivated on this board".to_string());
        }
        // Keep owner authority when switching away from the owner profile;
        // otherwise settings and trash actions sign with the new member key.
        // Store the real owner key, never the visible profile (which may be a
        // member with the same permissions but a different key).
        if self.is_current_owner() {
            let owner_key = self.owner_key().clone();
            self.owner_sk = Some(owner_key);
        }
        self.self_sk = signing_key.clone();
        // The old root profile no longer explains `self_sk`; callers that know
        // the selected profile write the new id.
        self.profile_id = None;
        self.self_authorized_member = Some(member.clone());
        self.self_member_info = self
            .board_state
            .member_info
            .member_info
            .iter()
            .filter(|info| info.member_info.member_id == member.member.id())
            .max_by_key(|info| info.member_info.version)
            .cloned();
        let parameters = self.board_parameters();
        self.capture_self_membership_data(&parameters);
        Ok(())
    }

    /// Whether this client is suspended right now.
    pub fn is_suspended_now(&self) -> bool {
        is_suspended_now(
            &self.board_state,
            MemberId::from(&self.self_sk.verifying_key()),
        )
    }

    /// The viewer's powers as the UI should show them.
    pub fn viewer_powers(&self) -> ViewerPowers {
        let member = MemberId::from(&self.self_sk.verifying_key());
        ViewerPowers {
            roles: self.board_state.roles.clone(),
            member,
            suspended: is_suspended_now(&self.board_state, member),
        }
    }


    /// Check if the user can send a message in the board.
    /// A user is considered a member if they are the owner, are in the active
    /// members list, or have a stored invitation (self_authorized_member).
    pub fn can_send_message(&self) -> Result<(), SendMessageError> {
        let verifying_key = self.self_sk.verifying_key();
        let member_id = MemberId::from(&verifying_key);

        // Check if banned first
        if self
            .board_state
            .bans
            .0
            .iter()
            .any(|b| b.ban.banned_user == member_id)
        {
            return Err(SendMessageError::UserBanned);
        }
        if self.is_suspended_now() {
            return Err(SendMessageError::UserSuspended);
        }

        // Owner can always send
        if verifying_key == self.current_owner_key() {
            return Ok(());
        }

        // Currently in members list
        if self
            .board_state
            .members
            .members
            .iter()
            .any(|m| m.member.member_vk == verifying_key)
        {
            return Ok(());
        }

        // Has stored invite (can re-add with first message)
        if self.self_authorized_member.is_some() {
            return Ok(());
        }

        Err(SendMessageError::UserNotMember)
    }

    /// One guard for every write path: content, votes, categories and access
    /// management all go through this instead of repeating the checks.
    pub fn ensure_can_write(&self) -> Result<(), String> {
        self.can_participate().map_err(|error| match error {
            SendMessageError::UserBanned => "You are banned from this board".to_string(),
            SendMessageError::UserSuspended => "You are suspended from this board".to_string(),
            SendMessageError::UserNotMember => "You are not a member of this board".to_string(),
        })
    }

    /// Whether the board refuses new content from ordinary members.
    pub fn is_read_only(&self) -> bool {
        self.board_state.configuration.configuration.read_only
    }

    /// Whether this identity may create content: the board is not read-only,
    /// or the identity is the current owner or an admin.
    pub fn may_write_content(&self) -> bool {
        if self.is_read_only() {
            let parameters = ChatBoardParametersV1 {
                owner: self.owner_vk,
            };
            let self_id = MemberId::from(&self.self_sk.verifying_key());
            let is_owner = self.board_state.ownership.current_owner(&parameters) == self_id;
            let is_admin = self
                .board_state
                .admin
                .admins
                .iter()
                .any(|admin| admin.admin.id() == self_id);
            if !is_owner && !is_admin {
                return false;
            }
        }
        self.can_participate().is_ok()
    }

    /// Whether a section allows images.
    pub fn section_images_allowed(&self, section: &MessageId) -> bool {
        self.board_state
            .sections
            .sections
            .iter()
            .find(|entry| !entry.section.deleted && entry.section.id == *section)
            .map(|entry| entry.section.images_allowed)
            .unwrap_or(true)
    }

    /// Whether the composer may offer the auto-moderated topic option here.
    /// The section override wins over the board configuration.
    pub fn auto_moderated_topics_enabled(&self, section: Option<&MessageId>) -> bool {
        section
            .and_then(|id| {
                self.board_state
                    .sections
                    .sections
                    .iter()
                    .find(|entry| !entry.section.deleted && entry.section.id == *id)
                    .and_then(|entry| entry.section.auto_moderated_topics)
            })
            .unwrap_or(
                self.board_state
                    .configuration
                    .configuration
                    .auto_moderated_topics,
            )
    }

    /// Whether the owner enabled reactions for this board.
    pub fn reactions_enabled(&self) -> bool {
        self.board_state.configuration.configuration.reactions_enabled
    }

    /// The nickname to show for a member from their published member info.
    pub fn display_nickname(&self, member_id: MemberId) -> Option<String> {
        self.board_state
            .member_info
            .member_info
            .iter()
            .find(|info| info.member_info.member_id == member_id)
            .map(|info| {
                match crate::util::ecies::unseal_bytes_with_secrets(
                    &info.member_info.preferred_nickname,
                    &self.secrets,
                ) {
                    Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
                    Err(_) => info.member_info.preferred_nickname.to_string_lossy(),
                }
            })
    }

    /// The member's published Freenet Mail address on this board, if any.
    /// Reads the dedicated state; old append-only actions are used only for
    /// the one-time migration path.
    pub fn mail_address_for(&self, member_id: MemberId) -> Option<String> {
        let address = self
            .board_state
            .mail_addresses
            .address_for(member_id)?;
        crate::util::ecies::unseal_bytes_with_secrets(address, &self.secrets)
            .ok()
            .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
            .filter(|value| !value.trim().is_empty())
    }

    /// The board's Freenet Mail contact, if the owner set one.
    pub fn board_contact_mail(&self) -> Option<String> {
        let contact = self
            .board_state
            .configuration
            .configuration
            .contact_mail
            .as_ref()?;
        crate::util::ecies::unseal_bytes_with_secrets(contact, &self.secrets)
            .ok()
            .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
            .filter(|value| !value.trim().is_empty())
    }

    /// The newest nickname request for a member, whatever its status.
    pub fn latest_nickname_request(&self, member_id: MemberId) -> Option<&NicknameRequest> {
        self.nickname_requests
            .iter()
            .filter(|request| request.member_id == member_id)
            .max_by_key(|request| request.created_at)
    }

    pub fn pending_nickname_request(&self, member_id: MemberId) -> Option<&NicknameRequest> {
        self.nickname_requests.iter().rev().find(|request| {
            request.member_id == member_id
                && request.status == NicknameRequestStatus::Pending
        })
    }

    pub fn add_nickname_request(
        &mut self,
        member_id: MemberId,
        current_name: String,
        requested_name: String,
    ) {
        let created_at = chrono::Utc::now().timestamp_millis();
        self.nickname_requests.push(NicknameRequest {
            id: format!("{created_at}-{member_id}"),
            member_id,
            current_name,
            requested_name,
            created_at,
            status: NicknameRequestStatus::Pending,
        });
    }

    pub fn decide_nickname_request(&mut self, id: &str, status: NicknameRequestStatus) {
        if let Some(request) = self.nickname_requests.iter_mut().find(|request| request.id == id) {
            request.status = status;
        }
    }

    /// Every secret that could have sealed an image this client may read: the
    /// board secret and each restricted section key.
    pub fn image_secret_candidates(&self) -> Vec<([u8; 32], u32)> {
        let mut out = Vec::new();
        if let (Some(version), Some(key)) =
            (self.current_secret_version, self.current_secret())
        {
            out.push((*key, version));
        }
        for (version, key) in self.category_secrets.values() {
            if !out.iter().any(|(existing, _)| existing == key) {
                out.push((*key, *version));
            }
        }
        out
    }

    /// Key to seal an image attached in `section`, or to a topic `target`.
    /// The section key comes first, then the board secret of a private board.
    pub fn image_upload_secret(
        &self,
        section: Option<&MessageId>,
        target: Option<&MessageId>,
    ) -> Option<([u8; 32], u32)> {
        if let Some(target) = target {
            if let (Some(section_id), _) = self.board_state.topics.section_of(target) {
                if let Some((version, key)) = self.category_secret(&section_id) {
                    return Some((key, version));
                }
            }
        }
        if let Some(section) = section {
            if let Some((version, key)) = self.category_secret(section) {
                return Some((key, version));
            }
        }
        self.current_secret()
            .copied()
            .map(|key| (key, self.current_secret_version.unwrap_or(0)))
    }

    /// Whether this identity may attach images in `section`. The section rule
    /// wins over the role, and a read-only board only lets owner and admins
    /// write at all.
    pub fn may_attach_images(&self, section: Option<&MessageId>) -> bool {
        if !self.may_write_content() {
            return false;
        }
        let parameters = self.board_parameters();
        let self_id = MemberId::from(&self.self_sk.verifying_key());
        let allowed_by_role = self_id == self.board_state.ownership.current_owner(&parameters)
            || plaza_core::board_state::roles::is_board_admin(&self.board_state, &self_id)
            || self.board_state.roles.can_attach_images(&self_id, section);
        if !allowed_by_role {
            return false;
        }
        match section {
            Some(section) => self.section_images_allowed(section),
            None => true,
        }
    }

    /// Whether this identity may retire an image for the whole board.
    pub fn may_retire_images(&self) -> bool {
        if !self.may_write_content() {
            return false;
        }
        let parameters = self.board_parameters();
        let self_id = MemberId::from(&self.self_sk.verifying_key());
        if self.board_state.ownership.current_owner(&parameters) == self_id
            || plaza_core::board_state::roles::is_board_admin(&self.board_state, &self_id)
        {
            return true;
        }
        self.board_state.roles.can_retire_images(&self_id)
    }

    /// Check if the user can participate in the board (send messages, edit profile).
    /// Returns Ok if user is not banned AND (is owner OR has self_authorized_member OR is in members list).
    pub fn can_participate(&self) -> Result<(), SendMessageError> {
        let verifying_key = self.self_sk.verifying_key();
        let member_id = MemberId::from(&verifying_key);

        // Check if banned first
        if self
            .board_state
            .bans
            .0
            .iter()
            .any(|b| b.ban.banned_user == member_id)
        {
            return Err(SendMessageError::UserBanned);
        }
        if self.is_suspended_now() {
            return Err(SendMessageError::UserSuspended);
        }

        // Owner can always participate
        if verifying_key == self.current_owner_key() {
            return Ok(());
        }

        // Currently in members list
        if self
            .board_state
            .members
            .members
            .iter()
            .any(|m| m.member.member_vk == verifying_key)
        {
            return Ok(());
        }

        // Has stored invite (was previously a member, can re-add)
        if self.self_authorized_member.is_some() {
            return Ok(());
        }

        Err(SendMessageError::UserNotMember)
    }

    /// Check if the current user can create categories (must be owner or admin)
    pub fn can_create_categories(&self) -> bool {
        let self_id = MemberId::from(&self.self_sk.verifying_key());

        // Owner can always create categories
        if self.is_current_owner() {
            return true;
        }

        // Check if user is an admin
        self.board_state
            .admin
            .admins
            .iter()
            .any(|a| a.admin.id() == self_id)
    }

    /// Capture the user's AuthorizedMember and MemberInfo from the current state.
    /// AuthorizedMember is only captured once (migration path for older boards).
    /// MemberInfo is always updated to the latest version so nickname edits are preserved.
    pub fn capture_self_membership_data(&mut self, parameters: &ChatBoardParametersV1) {
        let verifying_key = self.self_sk.verifying_key();
        if verifying_key == self.current_owner_key() {
            return; // Owner doesn't need this
        }

        // Always update self_member_info to latest version
        let member_id = MemberId::from(&verifying_key);
        if let Some(info) = self
            .board_state
            .member_info
            .member_info
            .iter()
            .filter(|i| i.member_info.member_id == member_id)
            .max_by_key(|i| i.member_info.version)
        {
            self.self_member_info = Some(info.clone());
        }

        // Only capture authorized member once
        if self.self_authorized_member.is_some() {
            return;
        }
        if let Some(member) = self
            .board_state
            .members
            .members
            .iter()
            .find(|m| m.member.member_vk == verifying_key)
        {
            self.self_authorized_member = Some(member.clone());
            // Capture invite chain
            if let Ok(chain) = self
                .board_state
                .members
                .get_invite_chain(member, parameters)
            {
                self.invite_chain = chain;
            }
        }
    }

    pub fn owner_id(&self) -> MemberId {
        self.owner_vk.into()
    }

    /// Replace an existing member entry with a new authorized member
    /// Returns true if the member was found and updated
    pub fn restore_member_access(
        &mut self,
        old_member_vk: VerifyingKey,
        new_authorized_member: AuthorizedMember,
    ) -> bool {
        // Find and replace the member entry
        if let Some(member) = self
            .board_state
            .members
            .members
            .iter_mut()
            .find(|m| m.member.member_vk == old_member_vk)
        {
            *member = new_authorized_member;
            true
        } else {
            false
        }
    }

    pub fn parameters(&self) -> ChatBoardParametersV1 {
        ChatBoardParametersV1 {
            owner: self.owner_vk,
        }
    }

    /// Rotate the board secret, generating a new secret and encrypting it for all current members
    /// This excludes banned members from receiving the new secret
    /// Returns a SecretsDelta with the new secret version and encrypted secrets
    pub fn rotate_secret(
        &mut self,
    ) -> Result<plaza_core::board_state::secret::SecretsDelta, String> {
        use plaza_core::board_state::secret::SecretsDelta;

        // Only allow rotation for private boards
        if !self.is_private() {
            return Err("Cannot rotate secret for public board".to_string());
        }

        // Only the board owner can rotate secrets
        if !self.is_current_owner() {
            return Err("Only board owner can rotate secrets".to_string());
        }

        // Get current version and increment
        let new_version = self.board_state.secrets.current_version + 1;

        // Generate new secret
        let new_secret = crate::util::ecies::generate_board_secret();

        // Create the secret version record
        let secret_version = SecretVersionRecordV1 {
            version: new_version,
            cipher_spec: BoardCipherSpec::Aes256Gcm,
            created_at: get_current_system_time(),
            category_id: None,
        };

        let authorized_version =
            AuthorizedSecretVersionRecord::new(secret_version, self.owner_key());

        // Get all current members, excluding banned members
        let banned_members: std::collections::HashSet<MemberId> = self
            .board_state
            .bans
            .0
            .iter()
            .map(|b| b.ban.banned_user)
            .collect();

        let mut current_members: Vec<MemberId> = self
            .board_state
            .members
            .members
            .iter()
            .map(|m| MemberId::from(&m.member.member_vk))
            .filter(|id| !banned_members.contains(id))
            .collect();
        // The owner is not a Member record, but needs the new board secret too.
        current_members.push(MemberId::from(&self.owner_vk));
        current_members.sort_by_key(|member| member.0 .0);
        current_members.dedup();

        if current_members.is_empty() {
            return Err("No members to encrypt secret for".to_string());
        }

        use dioxus::logger::tracing::info;
        info!(
            "Rotating secret to version {} for {} members",
            new_version,
            current_members.len()
        );

        // Encrypt the new secret for each member
        let mut new_encrypted_secrets = Vec::new();

        for member_id in current_members {
            // Find the member's verifying key
            if let Some(member) = self
                .board_state
                .members
                .members
                .iter()
                .find(|m| MemberId::from(&m.member.member_vk) == member_id)
            {
                let member_vk = member.member.member_vk;

                // Encrypt the board secret for this member
                let Ok((ciphertext, nonce, ephemeral_key)) =
                    crate::util::ecies::try_encrypt_secret_for_member(&new_secret, &member_vk)
                else {
                    dioxus::logger::tracing::warn!(
                        "Skipping rotated board secret for member with invalid public key"
                    );
                    continue;
                };

                // Create the encrypted secret record
                let encrypted_secret = EncryptedSecretForMemberV1 {
                    member_id,
                    secret_version: new_version,
                    ciphertext,
                    nonce,
                    sender_ephemeral_public_key: ephemeral_key.to_bytes(),
                    provider: self.owner_vk.into(),
                    category_id: None,
                };

                let authorized_encrypted_secret =
                    AuthorizedEncryptedSecretForMember::new(encrypted_secret, self.owner_key());

                new_encrypted_secrets.push(authorized_encrypted_secret);
            }
        }

        // Update our local secrets (add new version, keep old ones for decryption)
        self.secrets.insert(new_version, new_secret);
        self.current_secret_version = Some(new_version);
        self.last_secret_rotation = Some(get_current_system_time());
        // The PQ set is generated after the caller applies the SecretsDelta:
        // the contract rejects a set that references a not-yet-current version.

        Ok(SecretsDelta {
            current_version: Some(new_version),
            new_versions: vec![authorized_version],
            new_encrypted_secrets,
        })
    }

    /// Generate encrypted secrets for members who don't have them yet
    /// Returns a SecretsDelta if secrets were generated, None otherwise
    /// Owner-side: seal the board secret for every member that has no blob
    /// yet (new joiners, re-added members) and apply the delta locally.
    /// Returns true when the board state changed and should be published.
    pub fn distribute_missing_board_secrets(&mut self) -> bool {
        if !self.is_private() {
            return false;
        }
        self.ensure_pq_key();
        let mut changed = self.generate_missing_pq_secrets();
        if let Some(delta) = self.generate_missing_member_secrets() {
            let before = self.board_state.clone();
            let params = ChatBoardParametersV1 { owner: self.owner_vk };
            if self
                .board_state
                .apply_delta(
                    &before,
                    &params,
                    &Some(plaza_core::board_state::ChatBoardStateV1Delta {
                        secrets: Some(delta),
                        ..Default::default()
                    }),
                )
                .is_ok()
            {
                changed = true;
            }
        }
        changed
    }

    pub fn generate_missing_member_secrets(
        &self,
    ) -> Option<plaza_core::board_state::secret::SecretsDelta> {
        use plaza_core::board_state::secret::SecretsDelta;

        // Only generate secrets if this is a private board and we have the secret
        if !self.is_private() {
            return None;
        }

        let (board_secret, current_version) = self.get_secret()?;

        // Get all current members
        let member_ids: Vec<MemberId> = self
            .board_state
            .members
            .members
            .iter()
            .map(|m| MemberId::from(&m.member.member_vk))
            .collect();

        // Find members who don't have encrypted secrets for the current version
        let members_with_secrets: std::collections::HashSet<MemberId> = self
            .board_state
            .secrets
            .encrypted_secrets
            .iter()
            .filter(|s| s.secret.secret_version == current_version)
            .map(|s| s.secret.member_id)
            .collect();

        let members_without_secrets: Vec<_> = member_ids
            .into_iter()
            .filter(|id| !members_with_secrets.contains(id))
            .collect();

        if members_without_secrets.is_empty() {
            return None;
        }

        use dioxus::logger::tracing::info;
        info!(
            "Generating encrypted secrets for {} members",
            members_without_secrets.len()
        );

        // Generate encrypted secrets for each member
        let mut new_encrypted_secrets = Vec::new();

        for member_id in members_without_secrets {
            // Find the member's verifying key
            if let Some(member) = self
                .board_state
                .members
                .members
                .iter()
                .find(|m| MemberId::from(&m.member.member_vk) == member_id)
            {
                let member_vk = member.member.member_vk;

                // Encrypt the board secret for this member
                let Ok((ciphertext, nonce, ephemeral_key)) =
                    crate::util::ecies::try_encrypt_secret_for_member(board_secret, &member_vk)
                else {
                    dioxus::logger::tracing::warn!(
                        "Skipping board secret for member with invalid public key"
                    );
                    continue;
                };

                // Create the encrypted secret record
                let encrypted_secret = EncryptedSecretForMemberV1 {
                    member_id,
                    secret_version: current_version,
                    ciphertext,
                    nonce,
                    sender_ephemeral_public_key: ephemeral_key.to_bytes(),
                    provider: self.owner_vk.into(),
                    category_id: None,
                };

                let authorized_encrypted_secret =
                    AuthorizedEncryptedSecretForMember::new(encrypted_secret, self.owner_key());

                new_encrypted_secrets.push(authorized_encrypted_secret);
            }
        }

        // Also seal every older version. The board name and old posts may be
        // sealed with a version before the current one; a new member needs all
        // of them to read the board, not just the latest key.
        for member in &self.board_state.members.members {
            let member_id = MemberId::from(&member.member.member_vk);
            for (version, secret) in &self.secrets {
                if *version == current_version {
                    continue;
                }
                let already_has = self.board_state.secrets.encrypted_secrets.iter().any(|s| {
                    s.secret.member_id == member_id && s.secret.secret_version == *version
                });
                if already_has {
                    continue;
                }
                let Ok((ciphertext, nonce, ephemeral_key)) =
                    crate::util::ecies::try_encrypt_secret_for_member(
                        secret,
                        &member.member.member_vk,
                    )
                else {
                    dioxus::logger::tracing::warn!(
                        "Skipping historical board secret for member with invalid public key"
                    );
                    continue;
                };
                let encrypted_secret = EncryptedSecretForMemberV1 {
                    member_id,
                    secret_version: *version,
                    ciphertext,
                    nonce,
                    sender_ephemeral_public_key: ephemeral_key.to_bytes(),
                    provider: self.owner_vk.into(),
                    category_id: None,
                };
                new_encrypted_secrets.push(AuthorizedEncryptedSecretForMember::new(
                    encrypted_secret,
                    self.owner_key(),
                ));
            }
        }

        if new_encrypted_secrets.is_empty() {
            return None;
        }

        Some(SecretsDelta {
            current_version: None,
            new_versions: vec![],
            new_encrypted_secrets,
        })
    }
}
