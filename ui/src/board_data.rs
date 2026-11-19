#![allow(dead_code)]

use crate::util::ecies::encrypt_secret_for_member;
use crate::util::get_current_system_time;
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
use plaza_core::board_state::message::{BoardMessageBody, MessageId, SecretScope};
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

    /// Decrypt every category secret this member holds a blob for.
    ///
    /// Categories whose blob is missing stay out of the map: the UI treats them
    /// as unreadable, which is exactly what "restricted" means.
    pub fn decrypt_category_secrets(&mut self) {
        use crate::util::ecies::decrypt_secret_from_member_blob;
        use x25519_dalek::PublicKey as X25519PublicKey;

        let member_id = MemberId::from(&self.self_sk.verifying_key());
        let sets = self.board_state.category_secrets.categories.clone();
        for set in &sets {
            let mut latest: Option<(u32, [u8; 32])> = None;
            for blob in set
                .encrypted_secrets
                .iter()
                .filter(|s| s.secret.member_id == member_id)
            {
                let ephemeral = X25519PublicKey::from(blob.secret.sender_ephemeral_public_key);
                let Ok(secret) = decrypt_secret_from_member_blob(
                    &blob.secret.ciphertext,
                    &blob.secret.nonce,
                    &ephemeral,
                    &self.self_sk,
                ) else {
                    dioxus::logger::tracing::warn!(
                        "Failed to decrypt category secret v{}",
                        blob.secret.secret_version
                    );
                    continue;
                };
                let version = blob.secret.secret_version;
                match latest {
                    Some((best_version, _best_key)) if best_version >= version => {
                        self.old_category_secrets
                            .entry(set.category_id.clone())
                            .or_default()
                            .insert(version, secret);
                    }
                    Some((best_version, best_key)) => {
                        self.old_category_secrets
                            .entry(set.category_id.clone())
                            .or_default()
                            .insert(best_version, best_key);
                        latest = Some((version, secret));
                    }
                    None => latest = Some((version, secret)),
                }
            }
            if let Some((version, secret)) = latest {
                self.category_secrets
                    .insert(set.category_id.clone(), (version, secret));
            }
        }

        // Forget categories that no longer have a secret set.
        self.category_secrets
            .retain(|id, _| self.board_state.category_secrets.set(id).is_some());

        self.decrypt_pq_category_secrets();
    }

    pub fn category_secret(&self, category: &MessageId) -> Option<(u32, [u8; 32])> {
        self.category_secrets.get(category).copied()
    }

    /// Store keys that arrived outside the board state, such as the ones an
    /// invite link can carry.
    pub fn apply_category_keys(&mut self, keys: &[(MessageId, [u8; 32])]) {
        for (category_id, key) in keys {
            let version = self
                .board_state
                .category_secrets
                .current_version(category_id)
                .unwrap_or(0);
            self.category_secrets
                .insert(category_id.clone(), (version, *key));
        }
    }

    /// The newest secret that opens this body, whichever scope sealed it.
    pub fn body_secret(&self, content: &BoardMessageBody) -> Option<([u8; 32], u32)> {
        match content {
            BoardMessageBody::Private {
                secret_version,
                secret_scope,
                ..
            } => match secret_scope {
                SecretScope::Board => self
                    .get_secret_for_version(*secret_version)
                    .map(|secret| (*secret, *secret_version)),
                SecretScope::Category(id) => self
                    .category_secret(id)
                    .filter(|(version, _)| version == secret_version)
                    .map(|(version, secret)| (secret, version))
                    .or_else(|| {
                        self.old_category_secrets
                            .get(id)
                            .and_then(|versions| versions.get(secret_version))
                            .map(|secret| (*secret, *secret_version))
                    }),
            },
            BoardMessageBody::Public { .. } => None,
        }
    }

    /// Decode a category message. `None` when this client cannot open it.
    pub fn decode_category(&self, content: &BoardMessageBody) -> Option<CategoryContentV1> {
        use crate::util::ecies::decrypt_with_symmetric_key;
        use plaza_core::board_state::content::CONTENT_TYPE_CATEGORY;

        match content {
            BoardMessageBody::Public {
                content_type, data, ..
            } if *content_type == CONTENT_TYPE_CATEGORY => CategoryContentV1::decode(data).ok(),
            BoardMessageBody::Private {
                content_type,
                ciphertext,
                nonce,
                ..
            } if *content_type == CONTENT_TYPE_CATEGORY => {
                let (secret, version) = self.body_secret(content)?;
                let bytes = decrypt_with_symmetric_key(&secret, ciphertext, nonce, version).ok()?;
                CategoryContentV1::decode(&bytes).ok()
            }
            _ => None,
        }
    }

    /// Category content with its sealed name opened when we hold its key.
    pub fn readable_category(
        &self,
        category_id: &MessageId,
        content: &BoardMessageBody,
    ) -> Option<CategoryContentV1> {
        let mut category = self.decode_category(content)?;
        if let Some(sealed) = category.sealed_name.as_ref() {
            let mut keys = Vec::new();
            if let Some((_, key)) = self.category_secret(category_id) {
                keys.push(key);
            }
            if let Some(versions) = self.old_category_secrets.get(category_id) {
                keys.extend(versions.values().copied());
            }
            for key in keys {
                if let Ok(bytes) = crate::util::ecies::unseal_bytes(sealed, Some(&key)) {
                    if let Ok(name) = String::from_utf8(bytes) {
                        category.name = name;
                        break;
                    }
                }
            }
        }
        Some(category)
    }

    /// A restricted category is readable only with its own key. The owner
    /// always holds the key because creation distributes one to them.
    pub fn can_read_category(&self, category_id: &MessageId, content: &BoardMessageBody) -> bool {
        match self.decode_category(content) {
            Some(category) if category.is_restricted() => {
                self.category_secret(category_id).is_some()
            }
            Some(_) => true,
            None => false,
        }
    }

    /// The category a reply belongs to: the target itself when it is a
    /// restricted category, otherwise the category scope of the target.
    pub fn category_for_target(&self, target: &MessageId) -> Option<MessageId> {
        let message = self
            .board_state
            .recent_messages
            .messages
            .iter()
            .find(|m| m.id() == *target)?;
        if let Some(category) = self.decode_category(&message.message.content) {
            if category.is_restricted() {
                return Some(target.clone());
            }
        }
        match &message.message.content {
            BoardMessageBody::Private {
                secret_scope: SecretScope::Category(id),
                ..
            } => Some(id.clone()),
            _ => None,
        }
    }

    /// Secret to seal a post in the category that owns `target`.
    pub fn posting_secret_for(&self, target: &MessageId) -> Option<(MessageId, [u8; 32], u32)> {
        let category_id = self.category_for_target(target)?;
        let (version, secret) = self.category_secret(&category_id)?;
        Some((category_id, secret, version))
    }

    /// Root topic a message belongs to. A public `topic_id` counts only with a
    /// valid membership proof; otherwise the readable reply body is followed.
    /// A message with neither is its own root.
    pub fn topic_root_for(&self, target: &MessageId) -> Option<MessageId> {
        let mut current = target.clone();
        for _ in 0..64 {
            let message = self
                .board_state
                .recent_messages
                .messages
                .iter()
                .find(|message| message.id() == current)?;
            if let Some(root) = &message.message.topic_id {
                let valid = self
                    .topic_public_key(root)
                    .map(|key| message.message.has_valid_topic_proof(&key))
                    .unwrap_or(false);
                if valid {
                    return Some(root.clone());
                }
            }
            match self.readable_reply_target(&message.message.content) {
                Some(parent) => current = parent,
                None => return Some(current),
            }
        }
        None
    }

    /// Public membership key of a topic, when it published one.
    pub fn topic_public_key(&self, topic: &MessageId) -> Option<VerifyingKey> {
        self.board_state
            .recent_messages
            .messages
            .iter()
            .find(|message| message.id() == *topic)
            .and_then(|message| message.message.topic_public_key)
    }

    /// Topic membership private key, opened from the topic content when this
    /// client holds the key that sealed it.
    pub fn topic_membership_key(&self, topic: &MessageId) -> Option<SigningKey> {
        use plaza_core::board_state::content::{
            PollContentV1, TextContentV1, CONTENT_TYPE_POLL, CONTENT_TYPE_TEXT,
        };
        let message = self
            .board_state
            .recent_messages
            .messages
            .iter()
            .find(|message| message.id() == *topic)?;
        let plaintext = self.content_plaintext(&message.message.content)?;
        let key = match message.message.content.content_type() {
            CONTENT_TYPE_TEXT => TextContentV1::decode(&plaintext)
                .ok()?
                .topic_membership_key?,
            CONTENT_TYPE_POLL => PollContentV1::decode(&plaintext)
                .ok()?
                .topic_membership_key?,
            _ => return None,
        };
        let public = message.message.topic_public_key?;
        (public == key.verifying_key()).then_some(key)
    }

    /// Root topic of `target` and the key a reply must use to prove membership.
    pub fn topic_proof_key_for(&self, target: &MessageId) -> Option<(MessageId, SigningKey)> {
        let root = self.topic_root_for(target)?;
        let key = self.topic_membership_key(&root)?;
        Some((root, key))
    }

    /// Plaintext of a content body, public or sealed with a key we hold.
    fn content_plaintext(&self, content: &BoardMessageBody) -> Option<Vec<u8>> {
        match content {
            BoardMessageBody::Public { data, .. } => Some(data.clone()),
            BoardMessageBody::Private {
                ciphertext,
                nonce,
                ..
            } => {
                let (secret, version) = self.body_secret(content)?;
                crate::util::ecies::decrypt_with_symmetric_key(
                    &secret, ciphertext, nonce, version,
                )
                .ok()
            }
        }
    }

    /// Reply target the body names, public or sealed with a key we hold.
    fn readable_reply_target(&self, content: &BoardMessageBody) -> Option<MessageId> {
        use plaza_core::board_state::content::{ReplyContentV1, CONTENT_TYPE_REPLY};
        match content {
            BoardMessageBody::Public {
                content_type, data, ..
            } if *content_type == CONTENT_TYPE_REPLY => {
                ReplyContentV1::decode(data).ok().map(|reply| reply.target_message_id)
            }
            BoardMessageBody::Private {
                content_type,
                ciphertext,
                nonce,
                ..
            } if *content_type == CONTENT_TYPE_REPLY => {
                let (secret, version) = self.body_secret(content)?;
                let bytes = crate::util::ecies::decrypt_with_symmetric_key(
                    &secret,
                    ciphertext,
                    nonce,
                    version,
                )
                .ok()?;
                ReplyContentV1::decode(&bytes).ok().map(|reply| reply.target_message_id)
            }
            _ => None,
        }
    }

    /// Every restricted category this client can decode, with its content.
    pub fn restricted_categories(&self) -> Vec<(MessageId, CategoryContentV1)> {
        self.board_state
            .recent_messages
            .messages
            .iter()
            .filter_map(|message| {
                let category = self.decode_category(&message.message.content)?;
                category.is_restricted().then(|| (message.id(), category))
            })
            .collect()
    }

    /// Readers of a category: the owner plus every member of its roles.
    pub fn category_readers(&self, category: &CategoryContentV1) -> Vec<MemberId> {
        let mut readers: Vec<MemberId> = category
            .allowed_roles
            .iter()
            .flat_map(|role| self.board_state.roles.members_of_role(role))
            .collect();
        readers.push(self.owner_vk.into());
        readers.sort_by_key(|m| m.0 .0);
        readers.dedup();
        readers
    }

    fn category_secret_records(
        &self,
        category_id: &MessageId,
        secret: &[u8; 32],
        version: u32,
        readers: &[MemberId],
        include_version: bool,
    ) -> CategorySecretSetDelta {
        let owner_id = MemberId::from(&self.owner_vk);
        let (signing_key, signer) = self.management_signer();
        let provider_id = signer.unwrap_or(owner_id);
        let mut encrypted_secrets = Vec::new();
        for member_id in readers {
            let member_vk = if *member_id == owner_id {
                Some(self.owner_vk)
            } else {
                self.board_state
                    .members
                    .members
                    .iter()
                    .find(|m| MemberId::from(&m.member.member_vk) == *member_id)
                    .map(|m| m.member.member_vk)
            };
            let Some(member_vk) = member_vk else { continue };
            let (ciphertext, nonce, ephemeral_key) = encrypt_secret_for_member(secret, &member_vk);
            let record = EncryptedSecretForMemberV1 {
                member_id: *member_id,
                secret_version: version,
                ciphertext,
                nonce,
                sender_ephemeral_public_key: ephemeral_key.to_bytes(),
                provider: provider_id,
                category_id: Some(*category_id),
            };
            encrypted_secrets.push(match signer {
                None => AuthorizedEncryptedSecretForMember::new(record, &signing_key),
                Some(self_id) => AuthorizedEncryptedSecretForMember::signed_by(
                    record,
                    self_id,
                    &signing_key,
                )
                .with_optional_authority(
                    plaza_core::board_state::roles::distributor_authority_proof(
                        &self.board_state,
                        &self_id,
                    ),
                ),
            });
        }

        let versions = if include_version {
            vec![AuthorizedSecretVersionRecord::new(
                SecretVersionRecordV1 {
                    version,
                    cipher_spec: BoardCipherSpec::Aes256Gcm,
                    created_at: get_current_system_time(),
                    category_id: Some(*category_id),
                },
                &signing_key,
            )]
        } else {
            Vec::new()
        };

        CategorySecretSetDelta {
            category_id: category_id.clone(),
            current_version: version,
            versions,
            encrypted_secrets,
        }
    }

    /// Signed secret set for a freshly created restricted category.
    pub fn new_category_secret_set(
        &self,
        category_id: &MessageId,
        secret: &[u8; 32],
        version: u32,
        readers: &[MemberId],
    ) -> CategorySecretSetDelta {
        self.category_secret_records(category_id, secret, version, readers, true)
    }

    /// Owner-only: open a new secret version for a restricted category and
    /// hand it to the current readers. Posts sealed before the rotation stay
    /// readable with the old key kept locally; the past is not re-encrypted.
    pub fn rotate_category_secret(
        &mut self,
        category_id: &MessageId,
    ) -> Result<CategorySecretsDelta, String> {
        if !self.is_current_owner() {
            return Err("Only the board owner can rotate a category key".to_string());
        }
        let category = self
            .restricted_categories()
            .into_iter()
            .find(|(id, _)| id == category_id)
            .map(|(_, category)| category)
            .ok_or("Not a restricted category")?;
        let (old_version, old_key) = self
            .category_secret(category_id)
            .ok_or("No current key for this category")?;
        let version = self
            .board_state
            .category_secrets
            .current_version(category_id)
            .unwrap_or(old_version)
            + 1;
        let secret = crate::util::ecies::generate_board_secret();
        let readers = self.category_readers(&category);
        let set = self.new_category_secret_set(category_id, &secret, version, &readers);
        let delta = CategorySecretsDelta { sets: vec![set] };
        let params = ChatBoardParametersV1 {
            owner: self.owner_vk,
        };
        let before = self.board_state.clone();
        self.board_state
            .apply_delta(
                &before,
                &params,
                &Some(plaza_core::board_state::ChatBoardStateV1Delta {
                    category_secrets: Some(delta.clone()),
                    ..Default::default()
                }),
            )
            .map_err(|error| format!("Could not rotate the category key: {error}"))?;
        self.old_category_secrets
            .entry(category_id.clone())
            .or_default()
            .insert(old_version, old_key);
        self.category_secrets
            .insert(category_id.clone(), (version, secret));
        self.generate_missing_pq_category_secrets();
        Ok(delta)
    }

    /// Recompute edits, deletions and reactions, opening actions sealed with
    /// the board key or with a category key. The contract only understands
    /// public actions, so every private action is decrypted here.
    pub fn rebuild_actions_with_local_secrets(&mut self, parameters: &ChatBoardParametersV1) {
        use crate::util::ecies::decrypt_with_symmetric_key;
        use std::collections::HashSet;

        let decrypted_actions: HashMap<MessageId, Vec<u8>> = self
            .board_state
            .recent_messages
            .messages
            .iter()
            .filter(|message| message.message.content.is_action())
            .filter_map(|message| match &message.message.content {
                BoardMessageBody::Private {
                    ciphertext, nonce, ..
                } => {
                    let (key, version) = self.body_secret(&message.message.content)?;
                    decrypt_with_symmetric_key(&key, ciphertext, nonce, version)
                        .ok()
                        .map(|plaintext| (message.id(), plaintext))
                }
                BoardMessageBody::Public {
                    content_type, data, ..
                } if *content_type == plaza_core::board_state::content::CONTENT_TYPE_ACTION => {
                    Some((message.id(), data.clone()))
                }
                BoardMessageBody::Public {
                    content_type, data, ..
                } if *content_type
                    == plaza_core::board_state::content::CONTENT_TYPE_MODERATION_ACTION =>
                {
                    let envelope =
                        plaza_core::board_state::content::ModerationActionV1::decode(data).ok()?;
                    match envelope.payload {
                        plaza_core::board_state::privacy::SealedBytes::Public { value } => {
                            Some((message.id(), value))
                        }
                        plaza_core::board_state::privacy::SealedBytes::Private {
                            ciphertext,
                            nonce,
                            secret_version,
                            ..
                        } => {
                            let category_key = self
                                .category_secret(&envelope.target)
                                .filter(|(version, _)| *version == secret_version)
                                .map(|(_, key)| key);
                            let key = category_key
                                .or_else(|| self.get_secret_for_version(secret_version).copied())?;
                            decrypt_with_symmetric_key(&key, &ciphertext, &nonce, secret_version)
                                .ok()
                                .map(|plaintext| (message.id(), plaintext))
                        }
                    }
                }
                _ => None,
            })
            .collect();

        if decrypted_actions.is_empty() {
            self.board_state.recent_messages.rebuild_actions_state();
            return;
        }

        let owner_id = MemberId::from(&parameters.owner);
        let admin_ids: HashSet<MemberId> = self
            .board_state
            .admin
            .admins
            .iter()
            .map(|admin| admin.admin.id())
            .collect();

        let routes = self.board_state.moderation.routes_map();
        let mut closed = HashSet::new();
        let mut grants = Vec::new();
        for flag in &self.board_state.moderation.feature_flags {
            if flag.flag.kind == plaza_core::board_state::moderation::FeatureKind::Closed
                && flag.flag.value
            {
                closed.insert(flag.flag.target);
            }
        }
        for role in &self.board_state.roles.roles {
            if role.role.deleted || (!role.role.can_edit_posts && !role.role.can_delete_posts) {
                continue;
            }
            for member_id in self.board_state.roles.members_of_role(&role.role.id) {
                grants.push(plaza_core::board_state::message::ModerationGrant {
                    member_id,
                    can_edit: role.role.can_edit_posts,
                    can_delete: role.role.can_delete_posts,
                    scope: role.role.scope.clone(),
                });
            }
        }
        let scope_chains = self
            .board_state
            .recent_messages
            .messages
            .iter()
            .map(|message| {
                (
                    message.id(),
                    plaza_core::board_state::moderation::category_chain(&routes, &message.id()),
                )
            })
            .collect();
        let moderation = plaza_core::board_state::message::ModerationPermissions {
            closed,
            grants,
            scope_chains,
        };
        let member_ids: HashSet<MemberId> = self
            .board_state
            .members
            .members
            .iter()
            .map(|member| member.member.id())
            .collect();
        let reactions_enabled = self
            .board_state
            .configuration
            .configuration
            .reactions_enabled;
        self.board_state
            .recent_messages
            .rebuild_actions_state_with_permissions(
                &decrypted_actions,
                Some(owner_id),
                Some(&admin_ids),
                Some(&moderation),
                reactions_enabled,
                Some(&member_ids),
            );
    }

    /// Whether this client may sign category key distributions: the owner, or
    /// a member of a role the owner allowed to distribute keys.
    pub fn can_distribute_category_keys(&self) -> bool {
        if self.is_current_owner() {
            return true;
        }
        if self.is_suspended_now() {
            return false;
        }
        let self_id = MemberId::from(&self.self_sk.verifying_key());
        self.board_state.roles.can_distribute_keys(&self_id)
    }

    /// Blobs for members of a category's roles who still lack a key. The owner
    /// and members of roles with the distribution permission can sign these.
    pub fn generate_missing_category_secrets(&self) -> Option<CategorySecretsDelta> {
        if !self.can_distribute_category_keys() {
            return None;
        }
        let is_owner = self.is_current_owner();

        let mut sets = Vec::new();
        for (category_id, category) in self.restricted_categories() {
            let Some((version, secret)) = self.category_secret(&category_id) else {
                continue;
            };
            let readers = self.category_readers(&category);
            let missing = self
                .board_state
                .category_secrets
                .members_missing_secret(&category_id, &readers);
            let includes_version = self
                .board_state
                .category_secrets
                .set(&category_id)
                .map(|set| set.versions.iter().any(|v| v.record.version == version))
                .unwrap_or(false);
            if missing.is_empty() && includes_version {
                continue;
            }
            // Version records stay owner-only. A delegated distributor can add
            // blobs to an existing set but cannot open a new version.
            if !includes_version && !is_owner {
                continue;
            }
            sets.push(self.category_secret_records(
                &category_id,
                &secret,
                version,
                &missing,
                !includes_version,
            ));
        }

        if sets.is_empty() {
            None
        } else {
            Some(CategorySecretsDelta { sets })
        }
    }

    /// Regenerate the contract_key from the owner_vk using the current WASM.
    /// This ensures the contract_key always matches the bundled WASM, which may
    /// have been updated since the board was first created/stored.
    pub fn regenerate_contract_key(&mut self) {
        let params = ChatBoardParametersV1 {
            owner: self.owner_vk,
        };
        let params_bytes = to_cbor_vec(&params);
        let contract_code = ContractCode::from(BOARD_CONTRACT_WASM);
        self.contract_key =
            ContractKey::from_params_and_code(Parameters::from(params_bytes), &contract_code);
    }

    /// Get the board key for delegate operations (owner's verifying key bytes)
    pub fn board_key(&self) -> BoardKey {
        self.owner_vk.to_bytes()
    }

    /// Check if the board state has been populated from the network.
    /// A board that was just imported (or created but not yet synced) will have
    /// an empty members list AND empty messages. This is used to show a
    /// "Syncing..." indicator and disable message input until the real board
    /// state arrives from the network.
    ///
    /// Uses both empty members AND empty messages to distinguish "just imported"
    /// from "synced but all members pruned for inactivity" — in the latter case,
    /// messages would still be present and the user should see the normal
    /// can_participate() flow which handles re-adding via self_authorized_member.
    pub fn is_awaiting_initial_sync(&self) -> bool {
        let is_owner = self.is_current_owner();
        if is_owner {
            return false;
        }
        self.board_state.members.members.is_empty()
            && self.board_state.recent_messages.messages.is_empty()
    }

    /// Check if the board is in private mode
    pub fn is_private(&self) -> bool {
        matches!(
            self.board_state.configuration.configuration.privacy_mode,
            plaza_core::board_state::privacy::PrivacyMode::Private
        )
    }

    /// Get the current (latest) secret for encryption/decryption
    pub fn get_secret(&self) -> Option<(&[u8; 32], u32)> {
        self.current_secret_version
            .and_then(|v| self.secrets.get(&v).map(|s| (s, v)))
    }

    /// Get a secret for a specific version (for decrypting old content)
    pub fn get_secret_for_version(&self, version: u32) -> Option<&[u8; 32]> {
        self.secrets.get(&version)
    }

    /// Get a reference to the current secret (convenience method)
    pub fn current_secret(&self) -> Option<&[u8; 32]> {
        self.current_secret_version
            .and_then(|v| self.secrets.get(&v))
    }

    fn self_is_member_or_owner(&self) -> bool {
        let self_vk = self.self_sk.verifying_key();
        self_vk == self.current_owner_key()
            || self
                .board_state
                .members
                .members
                .iter()
                .any(|member| member.member.member_vk == self_vk)
    }

    fn apply_pq_delta(
        &mut self,
        delta: plaza_core::board_state::pq_secrets::PqSecretsDelta,
    ) -> Result<(), String> {
        let params = self.parameters();
        let before = self.board_state.clone();
        self.board_state
            .apply_delta(
                &before,
                &params,
                &Some(plaza_core::board_state::ChatBoardStateV1Delta {
                    pq_secrets: Some(delta),
                    ..Default::default()
                }),
            )
            .map_err(|error| format!("PQ secret delta rejected: {error}"))
    }

    /// Publish this member's ML-KEM key on a private board. Idempotent.
    pub fn ensure_pq_key(&mut self) -> bool {
        let has_restricted = !self.restricted_categories().is_empty();
        let self_id = MemberId::from(&self.self_sk.verifying_key());
        // Trash managers need a KEM key even on a public board, so the trash
        // secret can be sealed to them.
        let is_trash_manager = self.board_state.roles.can_manage_trash(&self_id);
        let is_owner = self.is_current_owner();
        let is_admin = self
            .board_state
            .admin
            .admins
            .iter()
            .any(|admin| admin.admin.id() == self_id);
        if !(self.is_private() || has_restricted || is_trash_manager || is_owner || is_admin)
            || !self.self_is_member_or_owner()
        {
            return false;
        }
        let self_key = self.self_sk.clone();
        let mut changed = self.publish_pq_key(&self_key, self_id);
        // The owner key never posts, but it manages the trash. Publish its KEM
        // key too, or a key rotation after removing the last profile manager
        // finds nobody to seal the new trash key to.
        if is_owner {
            let owner_key = self.owner_key().clone();
            let owner_id = self.current_owner_id();
            if owner_key.verifying_key() != self.self_sk.verifying_key() {
                changed |= self.publish_pq_key(&owner_key, owner_id);
            }
        }
        changed
    }

    fn publish_pq_key(&mut self, signing_key: &SigningKey, member_id: MemberId) -> bool {
        let ek = crate::util::pq::encapsulation_key(signing_key);
        let existing = self.board_state.pq_secrets.key_for(member_id);
        if existing.map(|key| key.ek == ek).unwrap_or(false) {
            return false;
        }
        let version = existing.map(|key| key.version + 1).unwrap_or(1);
        let entry = plaza_core::board_state::pq_secrets::AuthorizedPqMemberKey::new(
            plaza_core::board_state::pq_secrets::PqMemberKey {
                member_id,
                ek,
                version,
            },
            signing_key,
        );
        self.apply_pq_delta(plaza_core::board_state::pq_secrets::PqSecretsDelta {
            keys: vec![entry],
            sets: vec![],
        })
        .is_ok()
    }

    /// Decrypt the board-secret blobs (X25519 and hybrid PQ) for this member.
    /// Used on initial load and on every update that may carry a new version.
    pub fn decrypt_board_secrets(&mut self) {
        if !self.is_private() {
            return;
        }
        use crate::util::ecies::decrypt_secret_from_member_blob;
        use x25519_dalek::PublicKey as X25519PublicKey;

        let member_id = MemberId::from(&self.self_sk.verifying_key());
        let current_version = self.board_state.secrets.current_version;
        let member_secrets: Vec<(u32, Vec<u8>, [u8; 12], [u8; 32])> = self
            .board_state
            .secrets
            .encrypted_secrets
            .iter()
            .filter(|secret| secret.secret.member_id == member_id)
            .map(|secret| {
                (
                    secret.secret.secret_version,
                    secret.secret.ciphertext.clone(),
                    secret.secret.nonce,
                    secret.secret.sender_ephemeral_public_key,
                )
            })
            .collect();
        for (version, ciphertext, nonce, ephemeral_key_bytes) in member_secrets {
            let ephemeral = X25519PublicKey::from(ephemeral_key_bytes);
            match decrypt_secret_from_member_blob(&ciphertext, &nonce, &ephemeral, &self.self_sk) {
                Ok(secret) => self.set_secret(secret, version),
                Err(error) => {
                    dioxus::logger::tracing::warn!(
                        "Failed to decrypt board secret v{}: {}",
                        version,
                        error
                    );
                }
            }
        }
        self.current_secret_version = Some(current_version);
        self.decrypt_pq_board_secrets();
        self.decrypt_pq_trash_secret();
    }

    /// Try the PQ sets for the board secret. Old versions stay in `secrets`.
    pub fn decrypt_pq_board_secrets(&mut self) {
        if !self.is_private() {
            return;
        }
        let self_id = MemberId::from(&self.self_sk.verifying_key());
        let sets: Vec<(u32, plaza_core::board_state::pq_secrets::PqSealedSecret)> = self
            .board_state
            .pq_secrets
            .sets
            .iter()
            .filter(|entry| {
                matches!(
                    entry.set.scope,
                    plaza_core::board_state::pq_secrets::PqScope::Board
                )
            })
            .flat_map(|entry| {
                entry
                    .set
                    .secrets
                    .iter()
                    .filter(|secret| secret.member_id == self_id)
                    .map(|secret| (entry.set.secret_version, secret.clone()))
            })
            .collect();
        for (version, sealed) in sets {
            match crate::util::pq::open_secret(&self.self_sk, &sealed) {
                Ok(secret) => self.set_secret(secret, version),
                Err(error) => {
                    dioxus::logger::tracing::warn!(
                        "Could not open PQ board secret v{}: {}",
                        version,
                        error
                    );
                }
            }
        }
    }

    /// Open the PQ sets for the moderator trash key.
    pub fn decrypt_pq_trash_secret(&mut self) {
        use plaza_core::board_state::pq_secrets::PqScope;
        let self_id = MemberId::from(&self.self_sk.verifying_key());
        let Some(latest) = self
            .board_state
            .pq_secrets
            .sets
            .iter()
            .filter(|entry| matches!(entry.set.scope, PqScope::Trash))
            .max_by_key(|entry| entry.set.version)
        else {
            return;
        };
        // The visible profile is the normal key holder. The owner key also
        // holds the trash key on a split board, and the owner must keep access
        // even after removing its profile from the list.
        let mut candidates = vec![(self_id, self.self_sk.clone())];
        if self.is_current_owner() {
            candidates.push((self.current_owner_id(), self.owner_key().clone()));
        }
        let opened = candidates.iter().find_map(|(id, key)| {
            latest
                .set
                .secrets
                .iter()
                .find(|secret| secret.member_id == *id)
                .and_then(|secret| crate::util::pq::open_secret(key, secret).ok())
        });
        match opened {
            Some(key) => {
                self.trash_secret = Some((latest.set.secret_version, key));
                self.trash_secrets.insert(latest.set.secret_version, key);
            }
            None => {
                // A newer set without our record means access was revoked. Older
                // keys stay: they only open items sealed before the rotation.
                self.trash_secrets.remove(&latest.set.secret_version);
                self.trash_secret = None;
            }
        }
    }

    /// Open the PQ sets for restricted categories.
    pub fn decrypt_pq_category_secrets(&mut self) {
        use plaza_core::board_state::pq_secrets::PqScope;
        let self_id = MemberId::from(&self.self_sk.verifying_key());
        let mut items = Vec::new();
        for entry in &self.board_state.pq_secrets.sets {
            if let PqScope::Category(category_id) = &entry.set.scope {
                if let Some(secret) = entry
                    .set
                    .secrets
                    .iter()
                    .find(|secret| secret.member_id == self_id)
                {
                    items.push((*category_id, entry.set.secret_version, secret.clone()));
                }
            }
        }
        for (category_id, version, sealed) in items {
            match crate::util::pq::open_secret(&self.self_sk, &sealed) {
                Ok(secret) => match self.category_secrets.get(&category_id).copied() {
                    Some((current_version, _current_key)) if current_version > version => {
                        self.old_category_secrets
                            .entry(category_id)
                            .or_default()
                            .insert(version, secret);
                    }
                    Some((current_version, _current_key)) if current_version == version => {}
                    Some((current_version, current_key)) => {
                        self.old_category_secrets
                            .entry(category_id)
                            .or_default()
                            .insert(current_version, current_key);
                        self.category_secrets.insert(category_id, (version, secret));
                    }
                    None => {
                        self.category_secrets.insert(category_id, (version, secret));
                    }
                },
                Err(error) => {
                    dioxus::logger::tracing::warn!(
                        "Could not open PQ category secret v{}: {}",
                        version,
                        error
                    );
                }
            }
        }
    }

    /// Seal every restricted category key to the readers that have a PQ key.
    /// Owner or members of a key-distribution role can sign these sets.
    pub fn generate_missing_pq_category_secrets(&mut self) -> bool {
        use plaza_core::board_state::pq_secrets::{
            AuthorizedPqSecretSet, PqScope, PqSecretSet, PqSecretsDelta, PqSuite,
        };
        use std::collections::HashSet;

        if !self.can_distribute_category_keys() {
            return false;
        }
        let categories = self.restricted_categories();
        if categories.is_empty() {
            return false;
        }
        self.ensure_pq_key();
        let owner_id = MemberId::from(&self.owner_vk);
        let mut sets = Vec::new();

        for (category_id, category) in categories {
            let Some((secret_version, secret)) = self.category_secret(&category_id) else {
                continue;
            };
            let readers = self.category_readers(&category);
            let mut recipients = Vec::new();
            for member_id in readers {
                let verifying_key = if member_id == owner_id {
                    Some(self.owner_vk)
                } else {
                    self.board_state
                        .members
                        .members
                        .iter()
                        .find(|member| MemberId::from(&member.member.member_vk) == member_id)
                        .map(|member| member.member.member_vk)
                };
                if let (Some(verifying_key), Some(key)) = (
                    verifying_key,
                    self.board_state.pq_secrets.key_for(member_id),
                ) {
                    recipients.push((member_id, verifying_key, key.ek.clone()));
                }
            }
            if recipients.is_empty() {
                continue;
            }

            let existing = self
                .board_state
                .pq_secrets
                .sets
                .iter()
                .filter(|entry| {
                    entry.set.scope == PqScope::Category(category_id)
                        && entry.set.secret_version == secret_version
                })
                .max_by_key(|entry| entry.set.version);
            let covered: HashSet<MemberId> = existing
                .map(|entry| {
                    entry
                        .set
                        .secrets
                        .iter()
                        .map(|secret| secret.member_id)
                        .collect()
                })
                .unwrap_or_default();
            let all_hybrid = existing
                .map(|entry| {
                    entry
                        .set
                        .secrets
                        .iter()
                        .all(|secret| matches!(secret.suite, PqSuite::Hybrid))
                })
                .unwrap_or(false);
            if all_hybrid
                && recipients
                    .iter()
                    .all(|(member_id, _, _)| covered.contains(member_id))
            {
                continue;
            }

            let next_set_version = self
                .board_state
                .pq_secrets
                .sets
                .iter()
                .filter(|entry| entry.set.scope == PqScope::Category(category_id))
                .map(|entry| entry.set.version)
                .max()
                .unwrap_or(0)
                + 1;

            let mut sealed = Vec::new();
            for (member_id, verifying_key, ek) in recipients {
                match crate::util::pq::seal_secret(&secret, &ek, member_id, &verifying_key) {
                    Ok(record) => sealed.push(record),
                    Err(error) => {
                        dioxus::logger::tracing::warn!(
                            "Could not seal category key for {}: {}",
                            member_id,
                            error
                        );
                    }
                }
            }
            if sealed.is_empty() {
                continue;
            }
            let self_id = MemberId::from(&self.self_sk.verifying_key());
            sets.push(
                AuthorizedPqSecretSet::new(
                    PqSecretSet {
                        scope: PqScope::Category(category_id),
                        version: next_set_version,
                        secret_version,
                        secrets: sealed,
                        signed_at: chrono::Utc::now().timestamp_millis(),
                    },
                    &self.self_sk,
                )
                .with_optional_authority(
                    plaza_core::board_state::roles::distributor_authority_proof(
                        &self.board_state,
                        &self_id,
                    ),
                ),
            );
        }

        if sets.is_empty() {
            return false;
        }
        self.apply_pq_delta(PqSecretsDelta { keys: vec![], sets })
            .is_ok()
    }

    /// Owner-only: seal the current board secret to every member that has a
    /// PQ key. Members without a key keep using the X25519 blob.
    pub fn generate_missing_pq_secrets(&mut self) -> bool {
        use plaza_core::board_state::pq_secrets::{
            AuthorizedPqSecretSet, PqScope, PqSecretSet, PqSecretsDelta, PqSuite,
        };
        use std::collections::HashSet;

        if !self.is_private() || !self.is_current_owner() {
            return false;
        }
        let Some((secret, secret_version)) = self.get_secret().map(|(s, v)| (*s, v)) else {
            return false;
        };
        if self
            .board_state
            .pq_secrets
            .key_for(MemberId::from(&self.owner_vk))
            .is_none()
        {
            self.ensure_pq_key();
        }

        let mut live: Vec<MemberId> = self
            .board_state
            .members
            .members
            .iter()
            .map(|member| MemberId::from(&member.member.member_vk))
            .collect();
        live.push(MemberId::from(&self.owner_vk));
        live.sort_by_key(|member| member.0 .0);
        live.dedup();

        let owner_id = MemberId::from(&self.owner_vk);
        let mut recipients = Vec::new();
        for member_id in live {
            let verifying_key = if member_id == owner_id {
                Some(self.owner_vk)
            } else {
                self.board_state
                    .members
                    .members
                    .iter()
                    .find(|member| MemberId::from(&member.member.member_vk) == member_id)
                    .map(|member| member.member.member_vk)
            };
            if let (Some(verifying_key), Some(key)) = (
                verifying_key,
                self.board_state.pq_secrets.key_for(member_id),
            ) {
                recipients.push((member_id, verifying_key, key.ek.clone()));
            }
        }
        if recipients.is_empty() {
            return false;
        }

        let existing_for_version = self
            .board_state
            .pq_secrets
            .sets
            .iter()
            .filter(|entry| {
                matches!(entry.set.scope, PqScope::Board)
                    && entry.set.secret_version == secret_version
            })
            .max_by_key(|entry| entry.set.version);
        let covered: HashSet<MemberId> = existing_for_version
            .map(|entry| {
                entry
                    .set
                    .secrets
                    .iter()
                    .map(|secret| secret.member_id)
                    .collect()
            })
            .unwrap_or_default();
        let all_hybrid = existing_for_version
            .map(|entry| {
                entry
                    .set
                    .secrets
                    .iter()
                    .all(|secret| matches!(secret.suite, PqSuite::Hybrid))
            })
            .unwrap_or(false);
        if all_hybrid
            && recipients
                .iter()
                .all(|(member_id, _, _)| covered.contains(member_id))
        {
            return false;
        }

        let next_set_version = self
            .board_state
            .pq_secrets
            .sets
            .iter()
            .filter(|entry| matches!(entry.set.scope, PqScope::Board))
            .map(|entry| entry.set.version)
            .max()
            .unwrap_or(0)
            + 1;

        let mut sealed = Vec::new();
        for (member_id, verifying_key, ek) in recipients {
            match crate::util::pq::seal_secret(&secret, &ek, member_id, &verifying_key) {
                Ok(record) => sealed.push(record),
                Err(error) => {
                    dioxus::logger::tracing::warn!(
                        "Could not seal the board secret for {}: {}",
                        member_id,
                        error
                    );
                }
            }
        }
        if sealed.is_empty() {
            return false;
        }
        let self_id = MemberId::from(&self.self_sk.verifying_key());
        let set = AuthorizedPqSecretSet::new(
            PqSecretSet {
                scope: PqScope::Board,
                version: next_set_version,
                secret_version,
                secrets: sealed,
                signed_at: chrono::Utc::now().timestamp_millis(),
            },
            &self.self_sk,
        )
        .with_optional_authority(plaza_core::board_state::roles::admin_authority_proof(
            &self.board_state,
            &self_id,
        ));
        self.apply_pq_delta(PqSecretsDelta {
            keys: vec![],
            sets: vec![set],
        })
        .is_ok()
    }

    /// Set/add a board secret for a specific version
    pub fn set_secret(&mut self, secret: [u8; 32], version: u32) {
        self.secrets.insert(version, secret);
        // Update current version if this is a newer version
        if self.current_secret_version.is_none_or(|v| version >= v) {
            self.current_secret_version = Some(version);
            self.last_secret_rotation = Some(get_current_system_time());
        }
    }

    /// Check if the secret needs rotation (weekly rotation or never rotated)
    /// Only applies to private boards owned by this user
    pub fn needs_secret_rotation(&self) -> bool {
        // Only check for private boards
        if !self.is_private() {
            return false;
        }

        // Only the owner can rotate
        if !self.is_current_owner() {
            return false;
        }

        // Check if we have a last rotation time
        match self.last_secret_rotation {
            None => {
                // Never rotated, check if board has been around for a week
                // Get the creation time from the first secret version
                if let Some(first_version) = self.board_state.secrets.versions.first() {
                    let creation_time = first_version.record.created_at;
                    if let Ok(duration) = get_current_system_time().duration_since(creation_time) {
                        // Rotate if it's been more than 7 days since creation
                        return duration.as_secs() > 7 * 24 * 60 * 60;
                    }
                }
                false
            }
            Some(last_rotation) => {
                // Check if it's been more than 7 days since last rotation
                if let Ok(duration) = get_current_system_time().duration_since(last_rotation) {
                    duration.as_secs() > 7 * 24 * 60 * 60
                } else {
                    false
                }
            }
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

    /// Whether a section allows images, following the signed on/off actions.
    pub fn section_images_allowed(&self, section: &MessageId) -> bool {
        let parameters = self.board_parameters();
        self.board_state
            .recent_messages
            .section_allows_images(&self.board_state, &parameters, section)
    }

    /// Whether the composer may offer the auto-moderated topic option here.
    /// The section override wins over the board configuration; a sealed
    /// section record falls back to the board default. Private boards and
    /// restricted sections are offered too: the flag rides in the signed
    /// public metadata, so the contract can enforce it without the body.
    pub fn auto_moderated_topics_enabled(&self, section: Option<&MessageId>) -> bool {
        self.board_state
            .recent_messages
            .section_auto_moderated_topics(&self.board_state, &self.board_parameters(), section)
    }

    /// Whether the owner enabled reactions for this board.
    pub fn reactions_enabled(&self) -> bool {
        self.board_state.configuration.configuration.reactions_enabled
    }

    /// The nickname to show for a member: a moderator override first, then the
    /// member's own published name.
    pub fn display_nickname(&self, member_id: MemberId) -> Option<String> {
        if let Some(override_name) = self
            .board_state
            .recent_messages
            .nickname_override(&member_id)
        {
            return Some(override_name.nickname.clone());
        }
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

    /// Key to seal an image attached in `section`, or to a reply of `target`.
    /// The section key comes first, then the board secret of a private board.
    pub fn image_upload_secret(
        &self,
        section: Option<&MessageId>,
        target: Option<&MessageId>,
    ) -> Option<([u8; 32], u32)> {
        if let Some(target) = target {
            if let Some((_, key, version)) = self.posting_secret_for(target) {
                return Some((key, version));
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
        if !plaza_core::board_state::message::author_may_attach_images(
            &self.board_state,
            &parameters,
            &self_id,
            section,
        ) {
            return false;
        }
        match section {
            Some(section) => self.board_state.recent_messages.section_allows_images(
                &self.board_state,
                &parameters,
                section,
            ),
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
                let (ciphertext, nonce, ephemeral_key) =
                    encrypt_secret_for_member(&new_secret, &member_vk);

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
                let (ciphertext, nonce, ephemeral_key) =
                    encrypt_secret_for_member(board_secret, &member_vk);

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
                let (ciphertext, nonce, ephemeral_key) =
                    encrypt_secret_for_member(secret, &member.member.member_vk);
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

pub struct CurrentBoard {
    pub owner_key: Option<VerifyingKey>,
}

impl CurrentBoard {
    pub fn owner_id(&self) -> Option<MemberId> {
        self.owner_key.map(|vk| vk.into())
    }

    pub fn owner_key(&self) -> Option<&VerifyingKey> {
        self.owner_key.as_ref()
    }
}

impl PartialEq for CurrentBoard {
    fn eq(&self, other: &Self) -> bool {
        self.owner_key == other.owner_key
    }
}

/// A reusable identity: a display name and a signing key. Stored only on this
/// device; it is never published. Reusing a profile on several boards makes
/// the same member id appear on each; using another profile keeps them apart.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IdentityProfile {
    pub id: String,
    pub name: String,
    pub signing_key: SigningKey,
    /// Last local rename, in milliseconds since the epoch. The merge keeps the
    /// newest name when two tabs saved different ones.
    #[serde(default)]
    pub updated_at: u64,
}

impl IdentityProfile {
    pub fn new(name: String, signing_key: SigningKey) -> Self {
        let id = bs58::encode(signing_key.verifying_key().as_bytes()).into_string();
        Self {
            id,
            name,
            signing_key,
            updated_at: profile_stamp(),
        }
    }

    /// A board-scoped signing key for this profile. The result is deterministic
    /// per board and cannot be turned back into the root key, so two boards
    /// that use different derived keys are not cryptographically linked.
    pub fn derive_for_board(&self, board_owner_vk: &VerifyingKey) -> SigningKey {
        let material =
            [self.signing_key.to_bytes().as_slice(), board_owner_vk.as_bytes()].concat();
        let bytes = blake3::derive_key("freetalk-profile-board-v1", &material);
        SigningKey::from_bytes(&bytes)
    }
}

/// How a new board treats the chosen profile. Public boards always use the
/// root key; on a private board the default derives a board-specific key.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BoardIdentityMode {
    /// Use a key derived from the profile, keeping this board unlinkable.
    #[default]
    Derived,
    /// Use the profile's root key, linking this board to the others.
    Same,
}

/// Which boards a profile signs on, split by what that reveals.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProfileLinkability {
    /// Public boards signed with the profile's root key.
    pub public_boards: Vec<VerifyingKey>,
    /// Private boards signed with the profile's root key.
    pub private_boards: Vec<VerifyingKey>,
    /// Private boards signed with a key derived from the profile.
    pub derived_boards: Vec<VerifyingKey>,
    /// The same root key is visible on a public and on a private board.
    pub linked_across: bool,
}

fn profile_stamp() -> u64 {
    crate::util::get_current_system_time()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Boards {
    pub map: HashMap<VerifyingKey, BoardData>,
    #[serde(default)]
    pub current_board_key: Option<VerifyingKey>,
    /// Reusable identities created on this device.
    #[serde(default)]
    pub profiles: Vec<IdentityProfile>,
    /// Boards the user left on this device. A stale tab must not resurrect
    /// them when its save merges the stored map.
    #[serde(default)]
    pub removed: Vec<VerifyingKey>,
    /// Boards whose contract key changed due to WASM update.
    /// Each entry is (owner_vk, old_contract_key) for boards where the owner
    /// should send an upgrade pointer to the old contract.
    #[serde(skip)]
    pub migrated_boards: Vec<(VerifyingKey, ContractKey)>,
    /// Image hashes this device refuses to download or show, independent of
    /// any board.
    #[serde(default)]
    pub blocked_image_hashes: Vec<[u8; 32]>,
    /// Renew old uploaded images automatically. Off by default; at most a
    /// small batch per day when on.
    #[serde(default)]
    pub auto_renew_images: bool,
    /// Last automatic renewal pass, in ms since the Unix epoch.
    #[serde(default)]
    pub last_auto_renew_at: i64,
    /// Images this device uploaded, used for renewal and reuse.
    ///
    /// Kept in memory only: the entries carry raw blob state up to 24 MiB and
    /// are stored under their own delegate key, so loading the board list does
    /// not wait for them. The field still deserializes so a blob written by an
    /// older version can be migrated; new saves omit it.
    #[serde(default, skip_serializing)]
    pub owned_images: Vec<OwnedImage>,
}

impl PartialEq for Boards {
    fn eq(&self, other: &Self) -> bool {
        self.map == other.map
            && self.removed == other.removed
            && self.blocked_image_hashes == other.blocked_image_hashes
            && self.owned_images == other.owned_images
    }
}

impl Boards {
    /// Decode the stored blob even when one board is incompatible. A board
    /// written by an older schema (the ids changed before v95) must not take
    /// the whole device's board list down with it: keep every board that
    /// still decodes and report the rest.
    /// A board present in the map was re-added (import or rejoin); its old
    /// removal tombstone must not drop it on the next load.
    pub fn clear_removed_for_present(&mut self) {
        self.removed.retain(|key| !self.map.contains_key(key));
    }

    /// Recompute each board contract key from the bundled wasm. A mismatch
    /// means the board was built with an older contract: remember the old key
    /// for the upgrade pointer and use the new key from now on.
    pub fn refresh_contract_keys(&mut self) {
        let mut changed = 0usize;
        let mut queued = 0usize;
        let expected: Vec<(VerifyingKey, ContractKey)> = self
            .map
            .keys()
            .map(|owner| (*owner, crate::util::owner_vk_to_contract_key(owner)))
            .collect();
        for (owner, expected) in expected {
            if let Some(board) = self.map.get_mut(&owner) {
                if board.contract_key != expected {
                    changed += 1;
                    // Only the owner can sign the upgrade pointer; other
                    // clients update the key silently.
                    if board.is_current_owner() {
                        self.migrated_boards.push((owner, board.contract_key));
                        queued += 1;
                    }
                    board.contract_key = expected;
                }
            }
        }
        if changed > 0 {
            dioxus::logger::tracing::info!(
                "Rekey refresh: {changed} changed, {queued} queued"
            );
        }
    }

    pub fn decode(bytes: &[u8]) -> Option<Boards> {
        use dioxus::logger::tracing::warn;

        if let Ok(mut boards) = ciborium::de::from_reader::<Boards, _>(bytes) {
            boards.clear_removed_for_present();
            boards.refresh_contract_keys();
            return Some(boards);
        }
        let value: ciborium::value::Value = ciborium::de::from_reader(bytes).ok()?;
        let entries = value.as_map()?;
        let mut boards = Boards {
            map: HashMap::new(),
            current_board_key: None,
            profiles: Vec::new(),
            removed: Vec::new(),
            migrated_boards: Vec::new(),
            blocked_image_hashes: Vec::new(),
            auto_renew_images: false,
            last_auto_renew_at: 0,
            owned_images: Vec::new(),
        };
        let mut dropped = 0usize;
        for (key, value) in entries {
            match key.as_text() {
                Some("map") => {
                    let Some(map) = value.as_map() else { continue };
                    for (board_key, board_value) in map {
                        let Ok(owner) = board_key.deserialized::<VerifyingKey>() else {
                            dropped += 1;
                            continue;
                        };
                        match board_value.deserialized::<BoardData>() {
                            Ok(board) => {
                                boards.map.insert(owner, board);
                            }
                            Err(error) => {
                                dropped += 1;
                                warn!(
                                    "Dropping stored board {}: {error}",
                                    MemberId::from(&owner)
                                );
                            }
                        }
                    }
                }
                Some("current_board_key") => {
                    boards.current_board_key = value.deserialized().ok();
                }
                Some("removed") => {
                    boards.removed = value.deserialized().unwrap_or_default();
                }
                Some("owned_images") => {
                    boards.owned_images = value.deserialized().unwrap_or_default();
                }
                _ => {}
            }
        }
        if dropped > 0 {
            warn!("Dropped {dropped} stored board(s) written by an incompatible version");
        }
        boards.clear_removed_for_present();
        boards.refresh_contract_keys();
        Some(boards)
    }

    pub fn create_new_board_with_name(
        &mut self,
        self_sk: SigningKey,
        name: String,
        nickname: String,
        is_private: bool,
    ) -> VerifyingKey {
        // Old callers use one key for ownership and posts. New boards can
        // choose a separate owner key and a reusable profile.
        let profile = IdentityProfile::new(nickname.clone(), self_sk.clone());
        // The key is freshly made for this board, so reusing it links nothing.
        self.create_new_board_with_identity(
            self_sk,
            profile,
            BoardIdentityMode::Same,
            name,
            nickname,
            is_private,
        )
    }

    /// Store a profile once, keyed by its verifying key. When two tabs know
    /// the same key, the newer rename wins; a tie is broken by the name so
    /// both tabs converge.
    pub fn remember_profile(&mut self, profile: IdentityProfile) {
        let vk = profile.signing_key.verifying_key();
        if let Some(existing) = self
            .profiles
            .iter_mut()
            .find(|existing| existing.signing_key.verifying_key() == vk)
        {
            let newer = profile.updated_at > existing.updated_at
                || (profile.updated_at == existing.updated_at && profile.name > existing.name);
            if newer {
                existing.name = profile.name;
                existing.updated_at = profile.updated_at;
            }
            return;
        }
        self.profiles.push(profile);
    }

    /// Rename a stored profile. Signing keys do not change, so the member id
    /// stays the same on every board.
    pub fn rename_profile(&mut self, id: &str, name: String) -> bool {
        let Some(profile) = self.profiles.iter_mut().find(|p| p.id == id) else {
            return false;
        };
        profile.name = name;
        profile.updated_at = profile_stamp();
        true
    }

    /// Drop a profile from this device. Boards already using its key keep it.
    pub fn forget_profile(&mut self, id: &str) -> bool {
        let before = self.profiles.len();
        self.profiles.retain(|p| p.id != id);
        before != self.profiles.len()
    }

    /// The stored profile a board posts as. Newer boards name it; boards from
    /// before the link fall back to a key match.
    pub fn profile_for_board(&self, board: &BoardData) -> Option<&IdentityProfile> {
        if let Some(id) = board.profile_id.as_deref() {
            if let Some(profile) = self.profiles.iter().find(|profile| profile.id == id) {
                return Some(profile);
            }
        }
        self.profiles
            .iter()
            .find(|profile| profile.signing_key == board.self_sk)
    }

    /// Where a profile is visible: root key on public or private boards, and
    /// derived keys on private boards. The root key on a public board and on
    /// a private board links the same person across both.
    pub fn profile_linkability(&self, profile: &IdentityProfile) -> ProfileLinkability {
        let root_vk = profile.signing_key.verifying_key();
        let mut linkability = ProfileLinkability::default();
        for (owner, board) in &self.map {
            let uses_root = board.self_sk.verifying_key() == root_vk;
            let named_here = board.profile_id.as_deref() == Some(profile.id.as_str());
            if !uses_root && !named_here {
                continue;
            }
            if uses_root {
                if board.is_private() {
                    linkability.private_boards.push(*owner);
                } else {
                    linkability.public_boards.push(*owner);
                }
            } else if board.self_sk.verifying_key()
                == profile.derive_for_board(&board.owner_vk).verifying_key()
            {
                linkability.derived_boards.push(*owner);
            }
        }
        linkability.public_boards.sort_by_key(|vk| vk.to_bytes());
        linkability.private_boards.sort_by_key(|vk| vk.to_bytes());
        linkability.derived_boards.sort_by_key(|vk| vk.to_bytes());
        linkability.linked_across =
            !linkability.public_boards.is_empty() && !linkability.private_boards.is_empty();
        linkability
    }

    /// Root profile to publish with an identity export, when this board names
    /// one and it is still stored here.
    pub fn export_root_profile(&self, board: &BoardData) -> Option<IdentityProfile> {
        let id = board.profile_id.as_deref()?;
        self.profiles
            .iter()
            .find(|profile| profile.id == id)
            .cloned()
    }

    /// Register the root profile carried by an identity export. Returns the
    /// id the imported board should record, or `None` for older exports that
    /// only carry the board key.
    pub fn register_imported_profile(
        &mut self,
        export: &plaza_core::board_state::identity::IdentityExport,
    ) -> Option<String> {
        let id = export.profile_id.clone()?;
        let signing_key = export.profile_signing_key.clone()?;
        let name = export
            .profile_name
            .clone()
            .unwrap_or_else(|| "Imported identity".to_string());
        let mut profile = IdentityProfile::new(name, signing_key);
        // Keep the exported id so `profile_for_board` resolves the link even
        // if the key bytes were produced by another client.
        profile.id = id.clone();
        self.remember_profile(profile);
        Some(id)
    }

    /// Create a board owned by `owner_sk`, with `profile` as its member and
    /// administrator. Reusing a profile on several boards links their member
    /// ids; a new profile keeps them apart. A private board in the default
    /// mode signs with a key derived from the profile instead.
    pub fn create_new_board_with_identity(
        &mut self,
        owner_sk: SigningKey,
        profile: IdentityProfile,
        identity_mode: BoardIdentityMode,
        name: String,
        nickname: String,
        is_private: bool,
    ) -> VerifyingKey {
        use dioxus::logger::tracing::info;
        info!(
            "🟢 create_new_board_with_identity called: name='{}', nickname='{}', is_private={}",
            name, nickname, is_private
        );

        let owner_vk = owner_sk.verifying_key();
        let self_sk = if is_private
            && identity_mode == BoardIdentityMode::Derived
            && profile.signing_key.verifying_key() != owner_vk
        {
            profile.derive_for_board(&owner_vk)
        } else {
            profile.signing_key.clone()
        };
        let profile_vk = self_sk.verifying_key();
        let has_separate_profile = profile_vk != owner_vk;
        let mut board_state = ChatBoardStateV1::default();

        // Generate board secret if private
        info!("🟢 Creating privacy mode and secrets...");
        let (privacy_mode, board_secret, board_secret_version) = if is_private {
            info!("🟢 Generating private board secret...");
            // Generate a random 32-byte secret
            let secret = crate::util::ecies::generate_board_secret();

            // Encrypt the secret for the owner using ECIES
            let (ciphertext, nonce, ephemeral_key) = encrypt_secret_for_member(&secret, &owner_vk);

            // Create the secret version record
            let secret_version = SecretVersionRecordV1 {
                version: 0,
                cipher_spec: BoardCipherSpec::Aes256Gcm,
                created_at: get_current_system_time(),
                category_id: None,
            };

            let authorized_version =
                AuthorizedSecretVersionRecord::new(secret_version, &owner_sk);

            // Create encrypted secret for the owner
            let encrypted_secret = EncryptedSecretForMemberV1 {
                member_id: owner_vk.into(),
                secret_version: 0,
                ciphertext,
                nonce,
                sender_ephemeral_public_key: ephemeral_key.to_bytes(),
                provider: owner_vk.into(),
                category_id: None,
            };

            let authorized_encrypted_secret =
                AuthorizedEncryptedSecretForMember::new(encrypted_secret, &owner_sk);

            // Add to board state
            board_state.secrets.versions.push(authorized_version);
            board_state
                .secrets
                .encrypted_secrets
                .push(authorized_encrypted_secret);

            if has_separate_profile {
                let (profile_ciphertext, profile_nonce, profile_ephemeral) =
                    encrypt_secret_for_member(&secret, &profile_vk);
                let profile_secret = EncryptedSecretForMemberV1 {
                    member_id: profile_vk.into(),
                    secret_version: 0,
                    ciphertext: profile_ciphertext,
                    nonce: profile_nonce,
                    sender_ephemeral_public_key: profile_ephemeral.to_bytes(),
                    provider: owner_vk.into(),
                    category_id: None,
                };
                board_state.secrets.encrypted_secrets.push(
                    AuthorizedEncryptedSecretForMember::new(profile_secret, &owner_sk),
                );
            }
            board_state.secrets.current_version = 0;

            info!("🟢 Private board secret generated and encrypted");
            (PrivacyMode::Private, Some(secret), Some(0u32))
        } else {
            info!("🟢 Public board, no secret needed");
            (PrivacyMode::Public, None, None)
        };

        // Set initial configuration with privacy mode
        info!("🟢 Creating configuration...");
        let config = Configuration {
            owner_member_id: owner_vk.into(),
            privacy_mode,
            display: BoardDisplayMetadata {
                name: if let Some(ref secret) = board_secret {
                    // Encrypt board name for private boards
                    use crate::util::ecies::encrypt_with_symmetric_key;
                    let (ciphertext, nonce) =
                        encrypt_with_symmetric_key(secret, name.as_bytes(), 0);
                    SealedBytes::Private {
                        ciphertext,
                        nonce,
                        secret_version: 0,
                        declared_len_bytes: name.len() as u32,
                    }
                } else {
                    SealedBytes::public(name.into_bytes())
                },
                description: None,
            },
            updated_at: get_current_system_time(),
            ..Configuration::default()
        };
        board_state.configuration = AuthorizedConfigurationV1::new(config, &owner_sk);

        // Add the profile to member_info; the owner key is not a member.
        let owner_info = MemberInfo {
            member_id: profile_vk.into(),
            version: 0,
            preferred_nickname: if let Some(ref secret) = board_secret {
                // Encrypt nickname for private boards
                use crate::util::ecies::encrypt_with_symmetric_key;
                let (ciphertext, nonce) =
                    encrypt_with_symmetric_key(secret, nickname.as_bytes(), 0);
                SealedBytes::Private {
                    ciphertext,
                    nonce,
                    secret_version: 0,
                    declared_len_bytes: nickname.len() as u32,
                }
            } else {
                SealedBytes::public(nickname.into_bytes())
            },
        };
        let authorized_profile_info = AuthorizedMemberInfo::new(owner_info, &self_sk);
        board_state
            .member_info
            .member_info
            .push(authorized_profile_info.clone());

        let self_authorized_member = if has_separate_profile {
            // The contract keeps the owner out of the members list. The chosen
            // profile becomes a member and an administrator.
            let member = Member {
                owner_member_id: owner_vk.into(),
                invited_by: owner_vk.into(),
                member_vk: profile_vk,
                join_proof: None,
            };
            let authorized = AuthorizedMember::new(member, &owner_sk);
            board_state.members.members.push(authorized.clone());
            let admin = Admin {
                member_id: profile_vk.into(),
                generation: 0,
                signed_at: get_current_system_time(),
            };
            board_state
                .admin
                .admins
                .push(AuthorizedAdmin::new(admin, &owner_sk));
            Some(authorized)
        } else {
            None
        };

        // Remember the root profile so it can be reused on another board. A
        // derived board key is never stored as a profile of its own.
        let profile_id = profile.id.clone();
        self.remember_profile(profile);

        // Generate contract key for the board
        info!("🟢 Generating contract key...");
        let parameters = ChatBoardParametersV1 { owner: owner_vk };
        let params_bytes = to_cbor_vec(&parameters);
        let contract_code = ContractCode::from(BOARD_CONTRACT_WASM);
        // Use the full ContractKey constructor that includes the code hash
        let contract_key =
            ContractKey::from_params_and_code(Parameters::from(params_bytes), &contract_code);
        info!("🟢 Contract key generated: {:?}", contract_key);

        info!("🟢 Creating BoardData struct...");
        let secrets = if let Some(secret) = board_secret {
            let mut map = HashMap::new();
            map.insert(0, secret);
            map
        } else {
            HashMap::new()
        };
        let mut board_data = BoardData {
            owner_vk,
            board_state,
            self_sk,
            owner_sk: Some(owner_sk),
            profile_id: Some(profile_id),
            contract_key,
            last_read_message_id: None,
            secrets,
            current_secret_version: board_secret_version,
            last_secret_rotation: if board_secret_version.is_some() {
                Some(get_current_system_time())
            } else {
                None
            },
            key_migrated_to_delegate: false, // Will be checked/migrated on startup
            self_authorized_member,
            invite_chain: vec![],
            self_member_info: Some(authorized_profile_info),
            spectator: false,
            category_secrets: HashMap::new(),
            old_category_secrets: HashMap::new(),
            trash_secret: None,
            trash_secrets: HashMap::new(),
            collapsed_groups: Vec::new(),
            last_visit: 0,
            read_categories: HashMap::new(),
            draft: None,
            drafts: Vec::new(),
            trash_retention_days: 0,
            pending_uploads: Vec::new(),
            pending_send: None,
            subscribed_categories: Vec::new(),
        };

        if board_data.is_private() {
            board_data.ensure_pq_key();
            board_data.generate_missing_pq_secrets();
        }

        info!("🟢 Inserting board into map...");
        self.removed.retain(|vk| *vk != owner_vk);
        self.map.insert(owner_vk, board_data);
        info!("🟢 create_new_board_with_name completed successfully, returning owner_vk");
        owner_vk
    }

    /// Merge the other Boards into this Boards (eg. when Boards are loaded from storage)
    pub fn merge(&mut self, other: Boards) -> Result<(), String> {
        // A board the user left stays gone even when an older snapshot still
        // carries it.
        for key in other.removed {
            if !self.removed.contains(&key) {
                self.removed.push(key);
            }
        }
        // The device denylist follows the union rule: a hash blocked on
        // another tab or in an older snapshot stays blocked here.
        for hash in other.blocked_image_hashes {
            if !self.blocked_image_hashes.contains(&hash) {
                self.blocked_image_hashes.push(hash);
            }
        }
        // Profiles are local and merge by signing key, newest rename first.
        for profile in other.profiles {
            self.remember_profile(profile);
        }
        // Carry contract-key migrations found while decoding; otherwise the
        // upgrade pointer is lost between the load and the synchronizer.
        let incoming_migrations = other.migrated_boards.len();
        for entry in other.migrated_boards {
            if !self
                .migrated_boards
                .iter()
                .any(|(owner, key)| *owner == entry.0 && key.id() == entry.1.id())
            {
                self.migrated_boards.push(entry);
            }
        }
        // Own uploads follow the union rule too; keep the fresher copy when
        // both sides know the same blob.
        for entry in other.owned_images {
            match self
                .owned_images
                .iter_mut()
                .find(|existing| existing.image.instance == entry.image.instance)
            {
                Some(existing) => {
                    if entry.renewed_at > existing.renewed_at {
                        *existing = entry;
                    }
                }
                None => self.owned_images.push(entry),
            }
        }
        for (vk, mut board_data) in other.map {
            if self.removed.contains(&vk) {
                continue;
            }
            // Signing paths use owner_vk as the delegate board key. An entry whose
            // field disagrees with its map key signs with the wrong key, and the
            // contract rejects every update. Repair it when the stored state
            // confirms that the entry belongs to the map key.
            if board_data.owner_vk != vk {
                let state_owner = board_data
                    .board_state
                    .configuration
                    .configuration
                    .owner_member_id;
                if state_owner == MemberId::from(&vk) {
                    dioxus::logger::tracing::error!(
                        "Board entry {:?} carries a stale owner_vk; repairing it from the map key",
                        MemberId::from(&vk)
                    );
                    board_data.owner_vk = vk;
                } else {
                    dioxus::logger::tracing::error!(
                        "Board entry {:?} belongs to a different owner {:?}; updates would be signed with the wrong key",
                        MemberId::from(&vk),
                        MemberId::from(&board_data.owner_vk)
                    );
                }
            }

            // Capture the old contract key before regeneration
            let old_contract_key = board_data.contract_key;

            // Regenerate contract_key to ensure it matches the current bundled WASM
            // This handles the case where boards were stored with an older WASM version
            board_data.regenerate_contract_key();
            // Stored state carries category keys; open them on load so the UI can
            // show restricted categories without waiting for a network round trip.
            board_data.decrypt_board_secrets();
            board_data.decrypt_category_secrets();
            // Moderation actions are stored as messages; recompute the derived
            // deleted/edited state so a loaded board reflects them immediately.
            board_data.rebuild_actions_with_local_secrets(&ChatBoardParametersV1 { owner: vk });

            // If the contract key changed (WASM was updated), track for upgrade pointer
            if old_contract_key != board_data.contract_key {
                if board_data.is_current_owner() {
                    self.migrated_boards.push((vk, old_contract_key));
                    dioxus::logger::tracing::info!(
                        "Rekey merge: board +1, {} total queued",
                        self.migrated_boards.len()
                    );
                }
            }

            // If not already in the map, add the board
            if let std::collections::hash_map::Entry::Vacant(e) = self.map.entry(vk) {
                e.insert(board_data);
            } else {
                // If the board is already in the map, merge in the new data
                let self_board_data = self.map.get_mut(&vk).unwrap();
                if self_board_data.self_sk != board_data.self_sk {
                    // The visible identity is a local choice and can be
                    // switched; keep the incoming profile and its membership
                    // data, and keep an owner key from either side.
                    self_board_data.self_sk = board_data.self_sk.clone();
                    self_board_data.profile_id = board_data.profile_id.clone();
                    self_board_data.self_authorized_member =
                        board_data.self_authorized_member.clone();
                    self_board_data.self_member_info = board_data.self_member_info.clone();
                    if board_data.owner_sk.is_some() {
                        self_board_data.owner_sk = board_data.owner_sk.clone();
                    }
                }
                self_board_data.board_state.merge(
                    &self_board_data.board_state.clone(),
                    &ChatBoardParametersV1 { owner: vk },
                    &board_data.board_state,
                )?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plaza_core::board_state::configuration::{AuthorizedConfigurationV1, Configuration};
    use plaza_core::board_state::identity::IdentityExport;
    use plaza_core::board_state::member::{AuthorizedMember, Member, MemberId};

    fn empty_boards() -> Boards {
        Boards {
            map: HashMap::new(),
            current_board_key: None,
            profiles: Vec::new(),
            removed: Vec::new(),
            migrated_boards: Vec::new(),
            blocked_image_hashes: Vec::new(),
            auto_renew_images: false,
            last_auto_renew_at: 0,
            owned_images: Vec::new(),
        }
    }

    /// The image index lives under its own delegate key, so the board map does
    /// not carry its megabytes. A blob from before the split still loads and
    /// keeps its entries for the migration.
    #[test]
    fn a_board_can_have_a_separate_owner_and_profile() {
        let mut rng = rand::thread_rng();
        let owner_sk = SigningKey::generate(&mut rng);
        let profile = IdentityProfile::new(
            "Shared profile".to_string(),
            SigningKey::generate(&mut rng),
        );
        let profile_vk = profile.signing_key.verifying_key();
        let mut boards = Boards {
            map: HashMap::new(),
            current_board_key: None,
            profiles: Vec::new(),
            removed: Vec::new(),
            migrated_boards: Vec::new(),
            blocked_image_hashes: Vec::new(),
            auto_renew_images: false,
            last_auto_renew_at: 0,
            owned_images: Vec::new(),
        };
        let owner_vk = owner_sk.verifying_key();
        let key = boards.create_new_board_with_identity(
            owner_sk,
            profile,
            BoardIdentityMode::Same,
            "Shared board".to_string(),
            "Shared profile".to_string(),
            false,
        );
        assert_eq!(key, owner_vk);
        let board = boards.map.get(&key).expect("board inserted");
        assert!(board.owner_sk.is_some());
        assert_eq!(board.owner_key().verifying_key(), owner_vk);
        assert_eq!(board.self_sk.verifying_key(), profile_vk);
        assert!(board
            .board_state
            .members
            .members
            .iter()
            .any(|member| member.member.member_vk == profile_vk));
        assert!(board
            .board_state
            .admin
            .admins
            .iter()
            .any(|admin| admin.admin.member_id == MemberId::from(&profile_vk)));
        let parameters = ChatBoardParametersV1 { owner: owner_vk };
        board
            .board_state
            .verify(&board.board_state, &parameters)
            .expect("board state verifies");
    }

    /// Management records use the owner key when this client holds it, and the
    /// profile key (as a named member) otherwise.
    #[test]
    fn management_signing_uses_the_key_that_holds_the_authority() {
        let mut rng = rand::thread_rng();
        let owner_sk = SigningKey::generate(&mut rng);
        let profile_sk = SigningKey::generate(&mut rng);
        let member_sk = SigningKey::generate(&mut rng);
        let mut boards = Boards {
            map: HashMap::new(),
            current_board_key: None,
            profiles: Vec::new(),
            removed: Vec::new(),
            migrated_boards: Vec::new(),
            blocked_image_hashes: Vec::new(),
            auto_renew_images: false,
            last_auto_renew_at: 0,
            owned_images: Vec::new(),
        };
        let key = boards.create_new_board_with_identity(
            owner_sk.clone(),
            IdentityProfile::new("Owner profile".to_string(), profile_sk),
            BoardIdentityMode::Same,
            "Board".to_string(),
            "Owner".to_string(),
            false,
        );

        let owner_view = boards.map.get(&key).unwrap().clone();
        let (signing_key, signer) = owner_view.management_signer();
        assert_eq!(signing_key.verifying_key(), owner_sk.verifying_key());
        assert_eq!(signer, None, "the owner signs without an authority proof");

        // A member only ever holds its own key.
        let mut member_view = owner_view;
        member_view.self_sk = member_sk.clone();
        member_view.owner_sk = None;
        let (signing_key, signer) = member_view.management_signer();
        assert_eq!(signing_key.verifying_key(), member_sk.verifying_key());
        assert_eq!(signer, Some(MemberId::from(&member_sk.verifying_key())));
    }

    /// The owner's profile is a member like any other: if the contract prunes
    /// its record, the stored signed membership puts it back.
    #[test]
    fn a_split_owner_profile_can_republish_its_membership() {
        let mut rng = rand::thread_rng();
        let owner_sk = SigningKey::generate(&mut rng);
        let profile_sk = SigningKey::generate(&mut rng);
        let profile_vk = profile_sk.verifying_key();
        let mut boards = Boards {
            map: HashMap::new(),
            current_board_key: None,
            profiles: Vec::new(),
            removed: Vec::new(),
            migrated_boards: Vec::new(),
            blocked_image_hashes: Vec::new(),
            auto_renew_images: false,
            last_auto_renew_at: 0,
            owned_images: Vec::new(),
        };
        let key = boards.create_new_board_with_identity(
            owner_sk,
            IdentityProfile::new("Profile".to_string(), profile_sk),
            BoardIdentityMode::Same,
            "Board".to_string(),
            "Profile".to_string(),
            false,
        );
        let mut board = boards.map.get(&key).unwrap().clone();
        assert!(board.self_authorized_member.is_some());

        // The contract pruned the profile because it had no recent messages.
        board.board_state.members.members.clear();
        let (members, member_info) = crate::util::messaging::self_membership_delta(&board)
            .expect("the stored record is republished");

        let before = board.board_state.clone();
        board
            .board_state
            .apply_delta(
                &before,
                &ChatBoardParametersV1 { owner: key },
                &Some(plaza_core::board_state::ChatBoardStateV1Delta {
                    members: Some(members),
                    member_info: Some(member_info),
                    ..Default::default()
                }),
            )
            .expect("the republished membership verifies");
        assert!(board
            .board_state
            .members
            .members
            .iter()
            .any(|member| member.member.member_vk == profile_vk));
    }

    /// The owner key, not the visible profile, signs an admin revocation.
    #[test]
    fn a_split_owner_can_revoke_an_admin() {
        use plaza_core::board_state::admin::{AdminsDelta, AuthorizedAdminRevocation};

        let mut rng = rand::thread_rng();
        let owner_sk = SigningKey::generate(&mut rng);
        let profile_sk = SigningKey::generate(&mut rng);
        let profile_id = MemberId::from(&profile_sk.verifying_key());
        let mut boards = Boards {
            map: HashMap::new(),
            current_board_key: None,
            profiles: Vec::new(),
            removed: Vec::new(),
            migrated_boards: Vec::new(),
            blocked_image_hashes: Vec::new(),
            auto_renew_images: false,
            last_auto_renew_at: 0,
            owned_images: Vec::new(),
        };
        let key = boards.create_new_board_with_identity(
            owner_sk,
            IdentityProfile::new("Profile".to_string(), profile_sk),
            BoardIdentityMode::Same,
            "Board".to_string(),
            "Profile".to_string(),
            false,
        );
        let board = boards.map.get_mut(&key).unwrap();
        assert!(board.is_current_owner());
        assert!(board
            .board_state
            .admin
            .admins
            .iter()
            .any(|admin| admin.admin.id() == profile_id));

        let generation = board.board_state.admin.next_generation(&profile_id);
        let revocation =
            AuthorizedAdminRevocation::new(profile_id, generation, board.owner_key());
        let before = board.board_state.clone();
        board
            .board_state
            .apply_delta(
                &before,
                &ChatBoardParametersV1 { owner: key },
                &Some(plaza_core::board_state::ChatBoardStateV1Delta {
                    admin: Some(AdminsDelta::revocation(vec![revocation])),
                    ..Default::default()
                }),
            )
            .expect("the owner revocation verifies");

        assert!(board.board_state.admin.admins.is_empty());
        assert!(board.board_state.admin.is_revoked(&profile_id));
    }

    /// A handover to this client's own profile must make the profile the
    /// owner even though `owner_sk` still holds the old owner key.
    #[test]
    fn a_handover_to_the_own_profile_makes_the_profile_the_owner() {
        use plaza_core::board_state::ownership::{
            AuthorizedOwnerTransfer, OutgoingOwnerAction, OwnerTransferV1, OwnershipDelta,
        };

        let mut rng = rand::thread_rng();
        let owner_sk = SigningKey::generate(&mut rng);
        let profile_sk = SigningKey::generate(&mut rng);
        let profile_vk = profile_sk.verifying_key();
        let profile_id = MemberId::from(&profile_vk);
        let mut boards = Boards {
            map: HashMap::new(),
            current_board_key: None,
            profiles: Vec::new(),
            removed: Vec::new(),
            migrated_boards: Vec::new(),
            blocked_image_hashes: Vec::new(),
            auto_renew_images: false,
            last_auto_renew_at: 0,
            owned_images: Vec::new(),
        };
        let key = boards.create_new_board_with_identity(
            owner_sk.clone(),
            IdentityProfile::new("Profile".to_string(), profile_sk),
            BoardIdentityMode::Same,
            "Board".to_string(),
            "Profile".to_string(),
            false,
        );
        let board = boards.map.get_mut(&key).unwrap();
        let params = ChatBoardParametersV1 { owner: key };
        let now = get_current_system_time();
        let transfer = AuthorizedOwnerTransfer::new(
            OwnerTransferV1 {
                from: MemberId::from(key),
                to: profile_id,
                to_key: profile_vk,
                generation: 1,
                transferred_at: now + std::time::Duration::from_millis(2),
                outgoing: OutgoingOwnerAction::KeepAdmin,
            },
            &owner_sk,
        );

        let before = board.board_state.clone();
        board
            .board_state
            .apply_delta(
                &before,
                &params,
                &Some(plaza_core::board_state::ChatBoardStateV1Delta {
                    ownership: Some(OwnershipDelta {
                        transfers: vec![transfer],
                        deactivations: Vec::new(),
                    }),
                    ..Default::default()
                }),
            )
            .expect("the handover to the profile applies");

        assert_eq!(board.current_owner_key(), profile_vk);
        assert!(board.is_current_owner());
        assert_eq!(board.owner_key().verifying_key(), profile_vk);
        board
            .board_state
            .verify(&board.board_state, &params)
            .expect("the board verifies after the handover");
    }

    /// Deactivating both the owner key and the visible profile is accepted
    /// when the board goes to a third member.
    #[test]
    fn deactivating_both_keys_on_handover_verifies() {
        use plaza_core::board_state::admin::{Admin, AuthorizedAdmin};
        use plaza_core::board_state::ownership::{
            AuthorizedKeyDeactivation, AuthorizedOwnerTransfer, KeyDeactivationV1,
            OutgoingOwnerAction, OwnerTransferV1, OwnershipDelta,
        };

        let mut rng = rand::thread_rng();
        let owner_sk = SigningKey::generate(&mut rng);
        let owner_vk = owner_sk.verifying_key();
        let profile_sk = SigningKey::generate(&mut rng);
        let profile_vk = profile_sk.verifying_key();
        let profile_id = MemberId::from(&profile_vk);
        let third_sk = SigningKey::generate(&mut rng);
        let third_vk = third_sk.verifying_key();
        let third_id = MemberId::from(&third_vk);
        let mut boards = Boards {
            map: HashMap::new(),
            current_board_key: None,
            profiles: Vec::new(),
            removed: Vec::new(),
            migrated_boards: Vec::new(),
            blocked_image_hashes: Vec::new(),
            auto_renew_images: false,
            last_auto_renew_at: 0,
            owned_images: Vec::new(),
        };
        let key = boards.create_new_board_with_identity(
            owner_sk.clone(),
            IdentityProfile::new("Profile".to_string(), profile_sk.clone()),
            BoardIdentityMode::Same,
            "Board".to_string(),
            "Profile".to_string(),
            false,
        );
        let board = boards.map.get_mut(&key).unwrap();
        let params = ChatBoardParametersV1 { owner: key };
        let now = get_current_system_time();

        // A third member, promoted to admin so it can receive the board.
        let member = Member {
            owner_member_id: MemberId::from(key),
            invited_by: MemberId::from(key),
            member_vk: third_vk,
            join_proof: None,
        };
        let admin = Admin {
            member_id: third_id,
            generation: 0,
            signed_at: now,
        };
        board
            .board_state
            .members
            .members
            .push(plaza_core::board_state::member::AuthorizedMember::new(
                member, &owner_sk,
            ));
        board
            .board_state
            .admin
            .admins
            .push(AuthorizedAdmin::new(admin, &owner_sk));
        // Cleanup keeps an owner-invited member that has a nickname.
        board
            .board_state
            .member_info
            .member_info
            .push(plaza_core::board_state::member_info::AuthorizedMemberInfo::new_with_member_key(
                plaza_core::board_state::member_info::MemberInfo {
                    member_id: third_id,
                    version: 0,
                    preferred_nickname: plaza_core::board_state::privacy::SealedBytes::public(
                        b"Third".to_vec(),
                    ),
                },
                &third_sk,
            ));

        let transfer = AuthorizedOwnerTransfer::new(
            OwnerTransferV1 {
                from: MemberId::from(key),
                to: third_id,
                to_key: third_vk,
                generation: 1,
                transferred_at: now + std::time::Duration::from_millis(2),
                outgoing: OutgoingOwnerAction::Deactivate,
            },
            &owner_sk,
        );
        let deactivations = vec![
            AuthorizedKeyDeactivation::new(
                KeyDeactivationV1 {
                    member: MemberId::from(key),
                    key: owner_vk,
                    generation: 1,
                    deactivated_at: now,
                },
                &owner_sk,
            ),
            AuthorizedKeyDeactivation::new(
                KeyDeactivationV1 {
                    member: profile_id,
                    key: profile_vk,
                    generation: 1,
                    deactivated_at: now,
                },
                &profile_sk,
            ),
        ];
        let mut trial = board.board_state.ownership.clone();
        trial.transfers.push(transfer.clone());
        trial.deactivations.extend(deactivations.clone());
        trial
            .verify(&board.board_state, &params)
            .expect("the test transfer verifies");

        let before = board.board_state.clone();
        board
            .board_state
            .apply_delta(
                &before,
                &params,
                &Some(plaza_core::board_state::ChatBoardStateV1Delta {
                    ownership: Some(OwnershipDelta {
                        transfers: vec![transfer],
                        deactivations,
                    }),
                    ..Default::default()
                }),
            )
            .expect("the handover with both deactivations applies");

        assert_eq!(board.current_owner_key(), third_vk);
        assert!(
            board
                .board_state
                .members
                .members
                .iter()
                .any(|member| member.member.id() == third_id),
            "the new owner stays in the members list"
        );
        assert!(board
            .board_state
            .ownership
            .is_deactivated_now(&MemberId::from(key)));
        assert!(board.board_state.ownership.is_deactivated_now(&profile_id));
        board
            .board_state
            .verify(&board.board_state, &params)
            .expect("the board verifies after the deactivations");
    }

    /// Two tabs renamed the same profile: the newer name wins on merge.
    #[test]
    fn a_newer_profile_rename_wins_on_merge() {
        let mut rng = rand::thread_rng();
        let profile = IdentityProfile::new(
            "Old".to_string(),
            SigningKey::generate(&mut rng),
        );
        let mut local = Boards {
            map: HashMap::new(),
            current_board_key: None,
            profiles: vec![profile.clone()],
            removed: Vec::new(),
            migrated_boards: Vec::new(),
            blocked_image_hashes: Vec::new(),
            auto_renew_images: false,
            last_auto_renew_at: 0,
            owned_images: Vec::new(),
        };
        local.profiles[0].updated_at = 10;
        let mut other = Boards {
            map: HashMap::new(),
            current_board_key: None,
            profiles: vec![profile],
            removed: Vec::new(),
            migrated_boards: Vec::new(),
            blocked_image_hashes: Vec::new(),
            auto_renew_images: false,
            last_auto_renew_at: 0,
            owned_images: Vec::new(),
        };
        other.profiles[0].name = "New".to_string();
        other.profiles[0].updated_at = 20;

        local.merge(other).expect("the profiles merge");
        assert_eq!(local.profiles.len(), 1);
        assert_eq!(local.profiles[0].name, "New");
        assert_eq!(local.profiles[0].updated_at, 20);
    }

    /// A profile that is already a member can take over posting on the open
    /// board without leaving it.
    #[test]
    fn switch_profile_uses_an_existing_member() {
        use plaza_core::board_state::member::AuthorizedMember;
        use plaza_core::board_state::member_info::{AuthorizedMemberInfo, MemberInfo};
        use plaza_core::board_state::privacy::SealedBytes;

        let mut rng = rand::thread_rng();
        let owner_sk = SigningKey::generate(&mut rng);
        let profile_sk = SigningKey::generate(&mut rng);
        let second_sk = SigningKey::generate(&mut rng);
        let second_vk = second_sk.verifying_key();
        let second_id = MemberId::from(&second_vk);
        let mut boards = Boards {
            map: HashMap::new(),
            current_board_key: None,
            profiles: Vec::new(),
            removed: Vec::new(),
            migrated_boards: Vec::new(),
            blocked_image_hashes: Vec::new(),
            auto_renew_images: false,
            last_auto_renew_at: 0,
            owned_images: Vec::new(),
        };
        let key = boards.create_new_board_with_identity(
            owner_sk.clone(),
            IdentityProfile::new("First".to_string(), profile_sk),
            BoardIdentityMode::Same,
            "Board".to_string(),
            "First".to_string(),
            false,
        );
        let board = boards.map.get_mut(&key).unwrap();
        board
            .board_state
            .members
            .members
            .push(AuthorizedMember::new(
                Member {
                    owner_member_id: MemberId::from(key),
                    invited_by: MemberId::from(key),
                    member_vk: second_vk,
                    join_proof: None,
                },
                &owner_sk,
            ));
        board
            .board_state
            .member_info
            .member_info
            .push(AuthorizedMemberInfo::new_with_member_key(
                MemberInfo {
                    member_id: second_id,
                    version: 0,
                    preferred_nickname: SealedBytes::public(b"Second".to_vec()),
                },
                &second_sk,
            ));

        assert!(board.switch_profile(&second_sk).is_ok());
        assert_eq!(board.self_sk.verifying_key(), second_vk);
        assert!(board.self_authorized_member.is_some());
        assert!(board.can_participate().is_ok());
        assert!(board.switch_profile(&SigningKey::generate(&mut rng)).is_err());
    }

    /// A profile switch changes `self_sk`; the save merge must accept it and
    /// keep the new identity instead of dropping the board.
    #[test]
    fn merge_accepts_a_profile_switch() {
        use plaza_core::board_state::member::AuthorizedMember;

        let mut rng = rand::thread_rng();
        let owner_sk = SigningKey::generate(&mut rng);
        let first_sk = SigningKey::generate(&mut rng);
        let second_sk = SigningKey::generate(&mut rng);
        let second_vk = second_sk.verifying_key();
        let mut boards = Boards {
            map: HashMap::new(),
            current_board_key: None,
            profiles: Vec::new(),
            removed: Vec::new(),
            migrated_boards: Vec::new(),
            blocked_image_hashes: Vec::new(),
            auto_renew_images: false,
            last_auto_renew_at: 0,
            owned_images: Vec::new(),
        };
        let key = boards.create_new_board_with_identity(
            owner_sk.clone(),
            IdentityProfile::new("First".to_string(), first_sk),
            BoardIdentityMode::Same,
            "Board".to_string(),
            "First".to_string(),
            false,
        );
        let board = boards.map.get_mut(&key).unwrap();
        board
            .board_state
            .members
            .members
            .push(AuthorizedMember::new(
                Member {
                    owner_member_id: MemberId::from(key),
                    invited_by: MemberId::from(key),
                    member_vk: second_vk,
                    join_proof: None,
                },
                &owner_sk,
            ));
        board.switch_profile(&second_sk).expect("the profile switches");
        boards.current_board_key = Some(key);

        let mut stored = Boards {
            map: HashMap::new(),
            current_board_key: Some(key),
            profiles: boards.profiles.clone(),
            removed: Vec::new(),
            migrated_boards: Vec::new(),
            blocked_image_hashes: Vec::new(),
            auto_renew_images: false,
            last_auto_renew_at: 0,
            owned_images: Vec::new(),
        };
        let mut old_board = boards.map.get(&key).cloned().unwrap();
        old_board.self_sk = SigningKey::generate(&mut rng);
        stored.map.insert(key, old_board);

        stored.merge(boards).expect("the switch merges");
        assert_eq!(
            stored.map.get(&key).unwrap().self_sk.verifying_key(),
            second_vk
        );
        assert!(stored.map.get(&key).unwrap().owner_sk.is_some());
    }

    #[test]
    fn owned_images_are_saved_outside_the_boards_blob() {
        let owned = OwnedImage {
            image: plaza_core::board_state::images::ImageRef {
                instance: [7u8; 32],
                sha256: [8u8; 32],
                mime: "image/webp".to_string(),
                width: 10,
                height: 10,
                bytes: 2,
                alt: String::new(),
                display: 0,
                sealed: false,
                animated: false,
                nsfw: false,
                thumb: None,
                placement: Default::default(),
                align: Default::default(),
            },
            parameters: vec![1],
            state: vec![2, 3],
            chunks: Vec::new(),
            uploaded_at: 1,
            renewed_at: 1,
        };
        let boards = Boards {
            map: HashMap::new(),
            current_board_key: None,
            profiles: Vec::new(),
            removed: Vec::new(),
            migrated_boards: Vec::new(),
            blocked_image_hashes: Vec::new(),
            auto_renew_images: false,
            last_auto_renew_at: 0,
            owned_images: vec![owned.clone()],
        };
        let mut buffer = Vec::new();
        ciborium::ser::into_writer(&boards, &mut buffer).unwrap();
        let decoded: Boards = ciborium::from_reader(&buffer[..]).unwrap();
        assert!(decoded.owned_images.is_empty());

        // Older versions wrote the field into the same blob.
        #[derive(Serialize)]
        struct LegacyBoards {
            map: HashMap<VerifyingKey, BoardData>,
            current_board_key: Option<VerifyingKey>,
            removed: Vec<VerifyingKey>,
            blocked_image_hashes: Vec<[u8; 32]>,
            owned_images: Vec<OwnedImage>,
        }
        let legacy = LegacyBoards {
            map: HashMap::new(),
            current_board_key: None,
            removed: Vec::new(),
            blocked_image_hashes: Vec::new(),
            owned_images: vec![owned],
        };
        let mut legacy_buffer = Vec::new();
        ciborium::ser::into_writer(&legacy, &mut legacy_buffer).unwrap();
        let decoded = Boards::decode(&legacy_buffer).expect("legacy blob decodes");
        assert_eq!(decoded.owned_images.len(), 1);
    }

    /// The composer queues can hold 24 MiB of file bytes; they are stored
    /// under their own key too, so the board map stays small.
    #[test]
    fn pending_uploads_are_saved_outside_the_boards_blob() {
        let mut rng = rand::thread_rng();
        let owner_sk = SigningKey::generate(&mut rng);
        let mut boards = Boards {
            map: HashMap::new(),
            current_board_key: None,
            profiles: Vec::new(),
            removed: Vec::new(),
            migrated_boards: Vec::new(),
            blocked_image_hashes: Vec::new(),
            auto_renew_images: false,
            last_auto_renew_at: 0,
            owned_images: Vec::new(),
        };
        let key =
            boards.create_new_board_with_name(owner_sk, "Queue".to_string(), "alice".to_string(), false);
        boards
            .map
            .get_mut(&key)
            .unwrap()
            .pending_uploads
            .push(PendingUpload {
                id: "p1".to_string(),
                name: "photo.png".to_string(),
                alt: "photo".to_string(),
                nsfw: false,
                mime: "image/png".to_string(),
                width: 2,
                height: 2,
                animated: false,
                bytes: vec![1, 2, 3],
                secret: None,
                image: None,
            });

        let mut buffer = Vec::new();
        ciborium::ser::into_writer(&boards, &mut buffer).unwrap();
        let decoded: Boards = ciborium::from_reader(&buffer[..]).unwrap();
        assert!(decoded.map[&key].pending_uploads.is_empty());
    }

    /// A suspended member keeps the role assignment but loses its powers until
    /// the suspension ends. The contract still verifies records signed before
    /// it against the raw roles.
    #[test]
    fn a_suspension_hides_role_powers_until_it_ends() {
        use plaza_core::board_state::member_moderation::{
            AuthorizedSuspension, SuspensionV1,
        };
        use plaza_core::board_state::reports::ReportReason;
        use plaza_core::board_state::roles::{
            AuthorizedRole, AuthorizedRoleAssignment, Role, RoleAssignment,
        };

        let mut rng = rand::thread_rng();
        let owner_sk = SigningKey::generate(&mut rng);
        let member_sk = SigningKey::generate(&mut rng);
        let member = MemberId::from(&member_sk.verifying_key());
        let role_id = [7u8; 16];
        let mut state = ChatBoardStateV1::default();
        state.roles.roles.push(AuthorizedRole::new(
            Role {
                id: role_id,
                name: "moderator".to_string(),
                generation: 1,
                can_manage_access: false,
                can_distribute_keys: false,
                can_edit_posts: false,
                can_delete_posts: false,
                can_close_posts: false,
                can_pin_posts: true,
                can_move_posts: false,
                can_manage_trash: true,
                can_attach_images: false,
                can_retire_images: false,
                scope: Vec::new(),
                deleted: false,
                signed_at: get_current_system_time(),
            },
            &owner_sk,
        ));
        state
            .roles
            .assignments
            .push(AuthorizedRoleAssignment::new(
                RoleAssignment {
                    role_id,
                    member_id: member,
                    generation: 1,
                    revoked: false,
                    signed_at: get_current_system_time(),
                },
                &owner_sk,
            ));
        assert!(can_manage_trash(&state, member));

        let now = chrono::Utc::now().timestamp_millis();
        state
            .suspensions
            .suspensions
            .push(AuthorizedSuspension::new(
                SuspensionV1 {
                    target: member,
                    reason: ReportReason::Spam,
                    until: now + 60_000,
                    created_at: now,
                    generation: 1,
                },
                &owner_sk,
            ));
        assert!(is_suspended_now(&state, member));
        assert!(!can_manage_trash(&state, member));
        assert!(!has_moderation_power(&state, member, ModerationPower::Pin, &[]));
        assert!(state.roles.can_manage_trash(&member), "the role stays");

        // Lifting writes a past `until`, which ends the suspension.
        state.suspensions.suspensions.clear();
        state
            .suspensions
            .suspensions
            .push(AuthorizedSuspension::new(
                SuspensionV1 {
                    target: member,
                    reason: ReportReason::Spam,
                    until: now - 1_000,
                    created_at: now - 60_000,
                    generation: 2,
                },
                &owner_sk,
            ));
        assert!(!is_suspended_now(&state, member));
        assert!(can_manage_trash(&state, member));
        assert!(has_moderation_power(&state, member, ModerationPower::Pin, &[]));
    }

    /// A board written by an older schema must not cost the whole list: the
    /// lenient decode keeps every entry that still deserializes.
    #[test]
    fn an_incompatible_stored_board_does_not_drop_the_others() {
        let mut rng = rand::thread_rng();
        let owner_sk = SigningKey::generate(&mut rng);
        let mut boards = Boards {
            map: HashMap::new(),
            current_board_key: None,
            profiles: Vec::new(),
            removed: Vec::new(),
            migrated_boards: Vec::new(),
            blocked_image_hashes: Vec::new(),
            auto_renew_images: false,
            last_auto_renew_at: 0,
            owned_images: Vec::new(),
        };
        let key = boards.create_new_board_with_name(
            owner_sk,
            "Kept".to_string(),
            "alice".to_string(),
            false,
        );

        let mut value = ciborium::value::Value::serialized(&boards).expect("boards serialize");
        let entries = value.as_map_mut().expect("boards are a map");
        let map_value = entries
            .iter_mut()
            .find(|(key, _)| key.as_text() == Some("map"))
            .map(|(_, value)| value)
            .expect("map entry");
        let map = map_value.as_map_mut().expect("board map");
        let old_owner = SigningKey::generate(&mut rng).verifying_key();
        map.push((
            ciborium::value::Value::serialized(&old_owner).expect("owner key serializes"),
            ciborium::value::Value::Text("written by an old schema".to_string()),
        ));

        let mut bytes = Vec::new();
        ciborium::into_writer(&value, &mut bytes).expect("encode");
        let decoded = Boards::decode(&bytes).expect("the blob decodes per board");
        assert!(decoded.map.contains_key(&key), "the compatible board survives");
        assert_eq!(decoded.map.len(), 1);
    }

    /// A freshly created board must already be a cleanup fixpoint: the contract
    /// rejects published states that cleanup would change, so a PUT of a
    /// non-normalized new board would never be accepted.
    #[test]
    fn test_new_board_state_is_normalized() {
        let mut rng = rand::thread_rng();
        for private in [false, true] {
            let owner_sk = SigningKey::generate(&mut rng);
            let mut boards = Boards {
                map: HashMap::new(),
                current_board_key: None,
                profiles: Vec::new(),
                removed: Vec::new(),
                migrated_boards: vec![],
                blocked_image_hashes: Vec::new(),
                auto_renew_images: false,
                last_auto_renew_at: 0,
                owned_images: Vec::new(),
            };
            let key = boards.create_new_board_with_name(
                owner_sk.clone(),
                "Normalized?".to_string(),
                "alice".to_string(),
                private,
            );
            let params = ChatBoardParametersV1 { owner: key };
            let board = boards.map.get(&key).unwrap();
            let mut normalized = board.board_state.clone();
            normalized
                .normalize(&params)
                .expect("cleanup must succeed on a fresh board");
            assert_eq!(
                normalized,
                board.board_state,
                "a freshly created {} board must be a cleanup fixpoint",
                if private { "private" } else { "public" }
            );
        }
    }

    /// Two participants: the owner creates a private board, the invitee joins,
    /// and both read the encrypted board name and a private post while an
    /// outsider cannot. This is the data path the "Private board" checkbox
    /// drives.
    #[test]
    fn test_private_board_is_readable_by_members_only() {
        use crate::util::ecies::{
            decrypt_secret_from_member_blob, decrypt_with_symmetric_key, seal_bytes, unseal_bytes,
        };
        use plaza_core::board_state::privacy::SealedBytes;
        use plaza_core::board_state::ChatBoardStateV1Delta;

        let mut rng = rand::thread_rng();
        let owner_sk = SigningKey::generate(&mut rng);
        let mut boards = Boards {
            map: HashMap::new(),
            current_board_key: None,
            profiles: Vec::new(),
            removed: Vec::new(),
            migrated_boards: vec![],
            blocked_image_hashes: Vec::new(),
            auto_renew_images: false,
            last_auto_renew_at: 0,
            owned_images: Vec::new(),
        };

        let key = boards.create_new_board_with_name(
            owner_sk.clone(),
            "Secret Plans".to_string(),
            "alice".to_string(),
            true,
        );
        let board = boards.map.get(&key).expect("board created");
        assert!(board.is_private(), "board must be created private");
        let (secret, version) = board.get_secret().expect("owner holds the secret");
        let secret = *secret;
        assert!(
            board
                .board_state
                .pq_secrets
                .keys
                .iter()
                .any(|entry| entry.key.member_id == MemberId::from(&key)),
            "the owner must publish a PQ key"
        );
        assert!(
            board.board_state.pq_secrets.sets.iter().any(|entry| {
                matches!(
                    entry.set.scope,
                    plaza_core::board_state::pq_secrets::PqScope::Board
                ) && entry
                    .set
                    .secrets
                    .iter()
                    .any(|secret| secret.member_id == MemberId::from(&key))
            }),
            "the owner must receive a PQ-sealed board secret"
        );
        board
            .board_state
            .verify(&board.board_state, &ChatBoardParametersV1 { owner: key })
            .expect("the PQ records verify in the contract state");

        // The owner reads the sealed board name.
        match &board.board_state.configuration.configuration.display.name {
            SealedBytes::Private {
                ciphertext,
                nonce,
                secret_version,
                ..
            } => assert_eq!(
                decrypt_with_symmetric_key(&secret, ciphertext, nonce, *secret_version).unwrap(),
                b"Secret Plans"
            ),
            _ => panic!("a private board name must be sealed"),
        }

        // The invitee joins with their own key.
        let invitee_sk = SigningKey::generate(&mut rng);
        let invitee_id: MemberId = invitee_sk.verifying_key().into();
        let owner_id: MemberId = key.into();
        let board = boards.map.get_mut(&key).unwrap();
        board
            .board_state
            .members
            .members
            .push(AuthorizedMember::new(
                Member {
                    owner_member_id: owner_id,
                    invited_by: owner_id,
                    member_vk: invitee_sk.verifying_key(),
                    join_proof: None,
                },
                &owner_sk,
            ));

        // A member with no messages is pruned by post-apply cleanup. Give the
        // invitee one post so they stay in the state, as a real client would.
        board.board_state.recent_messages.messages.push(
            plaza_core::board_state::message::AuthorizedMessageV1::new(
                plaza_core::board_state::message::MessageV1 {
                    images: Vec::new(),
                    board_owner: owner_id,
                    author: invitee_id,
                    time: get_current_system_time(),
                    content: plaza_core::board_state::message::BoardMessageBody::public(
                        "hello".to_string(),
                        String::new(),
                    ),
                    reply_to: None,
                    topic_id: None,
                    topic_public_key: None,
                    topic_proof: None,
                    section_id: None,
                    section_auto_moderated: None,
                    auto_moderated: false,
                },
                &invitee_sk,
            ),
        );

        // The owner distributes the secret (same call the sync path makes when
        // a member joins) and applies it to the board state.
        let state_before = board.board_state.clone();
        let secrets_delta = board
            .generate_missing_member_secrets()
            .expect("the invitee needs an encrypted secret");
        board
            .board_state
            .apply_delta(
                &state_before,
                &ChatBoardParametersV1 { owner: key },
                &Some(ChatBoardStateV1Delta {
                    secrets: Some(secrets_delta),
                    ..Default::default()
                }),
            )
            .expect("the secrets delta applies cleanly");

        let blob = board
            .board_state
            .secrets
            .encrypted_secrets
            .iter()
            .find(|s| s.secret.member_id == invitee_id)
            .expect("the applied state carries the invitee's secret");
        assert_eq!(blob.secret.secret_version, version);
        let ephemeral = x25519_dalek::PublicKey::from(blob.secret.sender_ephemeral_public_key);
        let invitee_secret = decrypt_secret_from_member_blob(
            &blob.secret.ciphertext,
            &blob.secret.nonce,
            &ephemeral,
            &invitee_sk,
        )
        .expect("the invitee decrypts the board secret");
        assert_eq!(invitee_secret, secret, "both clients share the secret");

        // The invitee publishes its PQ key, the owner re-seals the board
        // secret, and the invitee opens it from the PQ set.
        use plaza_core::board_state::pq_secrets::{
            AuthorizedPqMemberKey, PqMemberKey, PqSecretsDelta,
        };
        let invitee_pq_key = AuthorizedPqMemberKey::new(
            PqMemberKey {
                member_id: invitee_id,
                ek: crate::util::pq::encapsulation_key(&invitee_sk),
                version: 1,
            },
            &invitee_sk,
        );
        assert!(
            board
                .board_state
                .members
                .members
                .iter()
                .any(|member| member.member.id() == invitee_id),
            "the invitee is in the members list before the PQ key"
        );
        let state_before = board.board_state.clone();
        board
            .board_state
            .apply_delta(
                &state_before,
                &ChatBoardParametersV1 { owner: key },
                &Some(ChatBoardStateV1Delta {
                    pq_secrets: Some(PqSecretsDelta {
                        keys: vec![invitee_pq_key],
                        sets: vec![],
                    }),
                    ..Default::default()
                }),
            )
            .expect("the invitee KEM key applies");

        assert!(
            board.generate_missing_pq_secrets(),
            "the owner seals the secret to the invitee key"
        );

        let mut invitee_view = board.clone();
        invitee_view.self_sk = invitee_sk.clone();
        invitee_view.secrets.clear();
        invitee_view.current_secret_version = None;
        invitee_view.decrypt_pq_board_secrets();
        assert_eq!(
            invitee_view.get_secret().map(|(secret, _)| *secret),
            Some(secret),
            "the invitee opens the PQ-sealed secret"
        );

        // A private post from the owner opens for the invitee, not for others.
        let post = seal_bytes(b"hello from the owner", &secret, version);
        assert_eq!(
            unseal_bytes(&post, Some(&invitee_secret)).unwrap(),
            b"hello from the owner"
        );
        assert!(
            unseal_bytes(&post, Some(&[9u8; 32])).is_err(),
            "an outsider without the secret must not read the post"
        );
    }

    /// A restricted category shares its key with the members of the chosen
    /// roles only. Members of the roles read the real name and its posts; other
    /// board members see the placeholder and cannot open them.
    #[test]
    fn restricted_category_reaches_only_role_members() {
        use crate::util::ecies::seal_bytes;
        use plaza_core::board_state::category_secrets::CategorySecretsDelta;
        use plaza_core::board_state::content::{
            CategoryContentV1, CATEGORY_CONTENT_VERSION, CONTENT_TYPE_CATEGORY,
        };
        use plaza_core::board_state::message::{AuthorizedMessageV1, BoardMessageBody, MessageV1};
        use plaza_core::board_state::roles::{
            AuthorizedRole, AuthorizedRoleAssignment, Role, RoleAssignment, RolesDelta,
        };
        use plaza_core::board_state::ChatBoardStateV1Delta;

        let mut rng = rand::thread_rng();
        let owner_sk = SigningKey::generate(&mut rng);
        let invitee_sk = SigningKey::generate(&mut rng);
        let outsider_sk = SigningKey::generate(&mut rng);

        let mut boards = Boards {
            map: HashMap::new(),
            current_board_key: None,
            profiles: Vec::new(),
            removed: Vec::new(),
            migrated_boards: vec![],
            blocked_image_hashes: Vec::new(),
            auto_renew_images: false,
            last_auto_renew_at: 0,
            owned_images: Vec::new(),
        };
        let key = boards.create_new_board_with_name(
            owner_sk.clone(),
            "Public Board".to_string(),
            "alice".to_string(),
            false,
        );
        let params = ChatBoardParametersV1 { owner: key };
        let owner_id: MemberId = key.into();
        let invitee_id: MemberId = invitee_sk.verifying_key().into();
        let role_id = [7u8; 16];

        let board = boards.map.get_mut(&key).unwrap();
        board
            .board_state
            .members
            .members
            .push(AuthorizedMember::new(
                Member {
                    owner_member_id: owner_id,
                    invited_by: owner_id,
                    member_vk: invitee_sk.verifying_key(),
                    join_proof: None,
                },
                &owner_sk,
            ));

        let before = board.board_state.clone();
        board
            .board_state
            .apply_delta(
                &before,
                &params,
                &Some(ChatBoardStateV1Delta {
                    roles: Some(RolesDelta {
                        roles: vec![AuthorizedRole::new(
                            Role {
                                id: role_id,
                                name: "Members".to_string(),
                                generation: 0,
                                can_manage_access: false,
                                can_distribute_keys: true,
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
                                signed_at: get_current_system_time(),
                            },
                            &owner_sk,
                        )],
                        assignments: vec![AuthorizedRoleAssignment::new(
                            RoleAssignment {
                                role_id,
                                member_id: invitee_id,
                                generation: 1,
                                revoked: false,
                                signed_at: get_current_system_time(),
                            },
                            &owner_sk,
                        )],
                    }),
                    // A member with no messages is pruned by cleanup, so keep
                    // the invitee alive with one post, as a real board would.
                    recent_messages: Some(vec![AuthorizedMessageV1::new(
                        MessageV1 {
                            images: Vec::new(),
                            board_owner: owner_id,
                            author: invitee_id,
                            content: BoardMessageBody::public(String::new(), "hello".to_string()),
                            time: get_current_system_time(),
                            reply_to: None,
                            topic_id: None,
                            topic_public_key: None,
                            topic_proof: None,
                            section_id: None,
                            section_auto_moderated: None,
                            auto_moderated: false,
                        },
                        &invitee_sk,
                    )]),
                    ..Default::default()
                }),
            )
            .expect("roles apply");

        // The category the create-category modal builds for a restricted entry.
        let category_secret = [3u8; 32];
        let sealed_name = seal_bytes(b"Members only", &category_secret, 0);
        let category = CategoryContentV1::new(
            "Restricted category".to_string(),
            None,
            "#6366f1".to_string(),
        )
        .with_allowed_roles(vec![role_id], sealed_name, true);
        let message = MessageV1 {
            images: Vec::new(),
            board_owner: owner_id,
            author: owner_id,
            content: BoardMessageBody::public_raw(
                CONTENT_TYPE_CATEGORY,
                CATEGORY_CONTENT_VERSION,
                category.encode(),
            ),
            time: get_current_system_time(),
            reply_to: None,
            topic_id: None,
            topic_public_key: None,
            topic_proof: None,
            section_id: None,
            section_auto_moderated: None,
            auto_moderated: false,
        };
        let authorized = AuthorizedMessageV1::new(message, &owner_sk);
        let category_id = authorized.id();

        let readers = board.category_readers(&category);
        assert!(readers.contains(&invitee_id));
        let secret_set = board.new_category_secret_set(&category_id, &category_secret, 0, &readers);

        let before = board.board_state.clone();
        board
            .board_state
            .apply_delta(
                &before,
                &params,
                &Some(ChatBoardStateV1Delta {
                    recent_messages: Some(vec![authorized]),
                    category_secrets: Some(CategorySecretsDelta {
                        sets: vec![secret_set],
                    }),
                    ..Default::default()
                }),
            )
            .expect("category and its secret set apply");
        board.decrypt_category_secrets();
        assert_eq!(
            board.category_secret(&category_id),
            Some((0, category_secret)),
            "the owner keeps the key"
        );

        // Publish the invitee's PQ key and seal the category key to it with
        // the hybrid set.
        use plaza_core::board_state::pq_secrets::{
            AuthorizedPqMemberKey, PqMemberKey, PqScope, PqSecretsDelta,
        };
        let invitee_pq_key = AuthorizedPqMemberKey::new(
            PqMemberKey {
                member_id: invitee_id,
                ek: crate::util::pq::encapsulation_key(&invitee_sk),
                version: 1,
            },
            &invitee_sk,
        );
        let before = board.board_state.clone();
        board
            .board_state
            .apply_delta(
                &before,
                &params,
                &Some(ChatBoardStateV1Delta {
                    pq_secrets: Some(PqSecretsDelta {
                        keys: vec![invitee_pq_key],
                        sets: vec![],
                    }),
                    ..Default::default()
                }),
            )
            .expect("the invitee PQ key applies");
        assert!(
            board.generate_missing_pq_category_secrets(),
            "the owner seals the category key to the invitee"
        );
        assert!(board.board_state.pq_secrets.sets.iter().any(|entry| {
            entry.set.scope == PqScope::Category(category_id)
                && entry
                    .set
                    .secrets
                    .iter()
                    .any(|secret| secret.member_id == invitee_id)
        }));

        let owner_view = boards.map.get(&key).unwrap().clone();
        let content = owner_view
            .board_state
            .recent_messages
            .messages
            .iter()
            .find(|m| m.id() == category_id)
            .expect("category message present")
            .message
            .content
            .clone();
        let owner_category = owner_view
            .readable_category(&category_id, &content)
            .expect("owner reads it");
        assert_eq!(owner_category.name, "Members only");

        // The invitee decrypts their blob and sees the same name.
        let mut invitee_view = owner_view.clone();
        invitee_view.self_sk = invitee_sk.clone();
        invitee_view.owner_sk = None;
        invitee_view.category_secrets.clear();
        invitee_view.decrypt_pq_category_secrets();
        assert_eq!(
            invitee_view.category_secret(&category_id),
            Some((0, category_secret))
        );
        let invitee_category = invitee_view
            .readable_category(&category_id, &content)
            .expect("invitee reads it");
        assert_eq!(invitee_category.name, "Members only");

        // The outsider is a board member but not in the role: no blob.
        let outsider_id: MemberId = outsider_sk.verifying_key().into();
        let mut outsider_view = owner_view.clone();
        outsider_view.self_sk = outsider_sk.clone();
        outsider_view.owner_sk = None;
        outsider_view.category_secrets.clear();
        outsider_view.decrypt_category_secrets();
        assert!(outsider_view.category_secret(&category_id).is_none());
        assert!(!outsider_view.can_read_category(&category_id, &content));
        let outsider_category = outsider_view
            .readable_category(&category_id, &content)
            .expect("placeholder still decodes");
        assert_eq!(outsider_category.name, "Restricted category");

        // A post sealed with the category key opens only for key holders.
        let category_post = seal_bytes(b"members only post", &category_secret, 0);
        let plaintext =
            crate::util::ecies::unseal_bytes(&category_post, Some(&category_secret)).unwrap();
        assert_eq!(plaintext, b"members only post");

        // Adding a member to the role later: the owner's next distribution
        // carries the key, and the new member can read the category.
        let board = boards.map.get_mut(&key).unwrap();
        board
            .board_state
            .members
            .members
            .push(AuthorizedMember::new(
                Member {
                    owner_member_id: owner_id,
                    invited_by: owner_id,
                    member_vk: outsider_sk.verifying_key(),
                    join_proof: None,
                },
                &owner_sk,
            ));
        let before = board.board_state.clone();
        board
            .board_state
            .apply_delta(
                &before,
                &params,
                &Some(ChatBoardStateV1Delta {
                    roles: Some(RolesDelta {
                        roles: vec![],
                        assignments: vec![AuthorizedRoleAssignment::new(
                            RoleAssignment {
                                role_id,
                                member_id: outsider_id,
                                generation: 1,
                                revoked: false,
                                signed_at: get_current_system_time(),
                            },
                            &owner_sk,
                        )],
                    }),
                    recent_messages: Some(vec![AuthorizedMessageV1::new(
                        MessageV1 {
                            images: Vec::new(),
                            board_owner: owner_id,
                            author: outsider_id,
                            content: BoardMessageBody::public(
                                String::new(),
                                "joined the role".to_string(),
                            ),
                            time: get_current_system_time(),
                            reply_to: None,
                            topic_id: None,
                            topic_public_key: None,
                            topic_proof: None,
                            section_id: None,
                            section_auto_moderated: None,
                            auto_moderated: false,
                        },
                        &outsider_sk,
                    )]),
                    ..Default::default()
                }),
            )
            .expect("the role grant applies");

        // The distribution comes from the invitee, a member of the role with
        // the key-distribution permission, not from the owner.
        let mut distributor_view = boards.map.get(&key).unwrap().clone();
        distributor_view.self_sk = invitee_sk.clone();
        distributor_view.owner_sk = None;
        distributor_view.category_secrets.clear();
        distributor_view.decrypt_category_secrets();
        assert_eq!(
            distributor_view.category_secret(&category_id),
            Some((0, category_secret)),
            "the distributor holds the category key"
        );

        let delta = distributor_view
            .generate_missing_category_secrets()
            .expect("the new role member needs the category key");
        let blob = delta.sets[0]
            .encrypted_secrets
            .iter()
            .find(|blob| blob.secret.member_id == outsider_id)
            .expect("the outsider is the missing recipient");
        assert_eq!(blob.signer, Some(invitee_id));

        let board = boards.map.get_mut(&key).unwrap();
        let before = board.board_state.clone();
        board
            .board_state
            .apply_delta(
                &before,
                &params,
                &Some(ChatBoardStateV1Delta {
                    category_secrets: Some(delta),
                    ..Default::default()
                }),
            )
            .expect("the distribution applies");

        let mut newcomer = boards.map.get(&key).unwrap().clone();
        newcomer.self_sk = outsider_sk;
        newcomer.owner_sk = None;
        newcomer.category_secrets.clear();
        newcomer.decrypt_category_secrets();
        assert_eq!(
            newcomer.category_secret(&category_id),
            Some((0, category_secret)),
            "the new role member can read the category"
        );
    }

    /// Regression test for #85: accepting an invitation for a board that already
    /// exists in the boards map must update self_sk so can_send_message() passes.
    #[test]
    fn test_can_send_message_after_self_sk_update() {
        let mut rng = rand::thread_rng();

        // Create owner
        let owner_sk = SigningKey::generate(&mut rng);
        let owner_vk = owner_sk.verifying_key();

        // Create board state with owner config
        let config = AuthorizedConfigurationV1::new(Configuration::default(), &owner_sk);
        let mut board_state = ChatBoardStateV1 {
            configuration: config,
            ..Default::default()
        };

        // Create an invitee and add them as a member
        let invitee_sk = SigningKey::generate(&mut rng);
        let invitee_vk = invitee_sk.verifying_key();
        let member = Member {
            owner_member_id: owner_vk.into(),
            invited_by: owner_vk.into(),
            member_vk: invitee_vk,
            join_proof: None,
        };
        let authorized_member = AuthorizedMember::new(member, &owner_sk);
        board_state.members.members.push(authorized_member);

        // Create BoardData with a STALE self_sk (different from the invitee key)
        let stale_sk = SigningKey::generate(&mut rng);
        let params = ChatBoardParametersV1 { owner: owner_vk };
        let params_bytes = to_cbor_vec(&params);
        let contract_code = ContractCode::from(BOARD_CONTRACT_WASM);
        let contract_key =
            ContractKey::from_params_and_code(Parameters::from(params_bytes), &contract_code);

        let mut board_data = BoardData {
            owner_vk,
            board_state,
            self_sk: stale_sk,
            owner_sk: None,
            profile_id: None,
            contract_key,
            last_read_message_id: None,
            secrets: HashMap::new(),
            category_secrets: HashMap::new(),
            old_category_secrets: HashMap::new(),
            trash_secret: None,
            trash_secrets: HashMap::new(),
            collapsed_groups: Vec::new(),
            last_visit: 0,
            read_categories: HashMap::new(),
            draft: None,
            drafts: Vec::new(),
            trash_retention_days: 0,
            pending_uploads: Vec::new(),
            pending_send: None,
            subscribed_categories: Vec::new(),
            current_secret_version: None,
            last_secret_rotation: None,
            key_migrated_to_delegate: false,
            self_authorized_member: None,
            invite_chain: vec![],
            self_member_info: None,
            spectator: false,
        };

        // With stale key, user should NOT be recognized as a member
        assert_eq!(
            board_data.can_send_message(),
            Err(SendMessageError::UserNotMember)
        );

        // After updating self_sk to the invitee's key, user should be a member
        board_data.self_sk = invitee_sk;
        assert_eq!(board_data.can_send_message(), Ok(()));
    }

    /// Test that capture_self_membership_data captures and updates member_info.
    #[test]
    fn test_capture_self_membership_data_preserves_nickname() {
        use plaza_core::board_state::privacy::SealedBytes;

        let mut rng = rand::thread_rng();
        let owner_sk = SigningKey::generate(&mut rng);
        let owner_vk = owner_sk.verifying_key();
        let invitee_sk = SigningKey::generate(&mut rng);
        let invitee_vk = invitee_sk.verifying_key();
        let member_id = MemberId::from(&invitee_vk);

        let config = AuthorizedConfigurationV1::new(Configuration::default(), &owner_sk);
        let mut board_state = ChatBoardStateV1 {
            configuration: config,
            ..Default::default()
        };

        // Add invitee as member
        let member = Member {
            owner_member_id: owner_vk.into(),
            invited_by: owner_vk.into(),
            member_vk: invitee_vk,
            join_proof: None,
        };
        board_state
            .members
            .members
            .push(AuthorizedMember::new(member, &owner_sk));

        // Add member_info with a custom nickname
        let info = MemberInfo {
            member_id,
            version: 0,
            preferred_nickname: SealedBytes::public("Alice".to_string().into_bytes()),
        };
        let authorized_info = AuthorizedMemberInfo::new_with_member_key(info, &invitee_sk);
        board_state.member_info.member_info.push(authorized_info);

        let params = ChatBoardParametersV1 { owner: owner_vk };
        let params_bytes = to_cbor_vec(&params);
        let contract_code = ContractCode::from(BOARD_CONTRACT_WASM);
        let contract_key =
            ContractKey::from_params_and_code(Parameters::from(params_bytes), &contract_code);

        let mut board_data = BoardData {
            owner_vk,
            board_state,
            self_sk: invitee_sk.clone(),
            owner_sk: None,
            profile_id: None,
            contract_key,
            last_read_message_id: None,
            secrets: HashMap::new(),
            category_secrets: HashMap::new(),
            old_category_secrets: HashMap::new(),
            trash_secret: None,
            trash_secrets: HashMap::new(),
            collapsed_groups: Vec::new(),
            last_visit: 0,
            read_categories: HashMap::new(),
            draft: None,
            drafts: Vec::new(),
            trash_retention_days: 0,
            pending_uploads: Vec::new(),
            pending_send: None,
            subscribed_categories: Vec::new(),
            current_secret_version: None,
            last_secret_rotation: None,
            key_migrated_to_delegate: false,
            self_authorized_member: None,
            invite_chain: vec![],
            self_member_info: None,
            spectator: false,
        };

        // Before capture, self_member_info should be None
        assert!(board_data.self_member_info.is_none());

        // Capture should populate self_member_info
        board_data.capture_self_membership_data(&params);
        assert!(board_data.self_member_info.is_some());
        let stored = board_data.self_member_info.as_ref().unwrap();
        assert_eq!(stored.member_info.member_id, member_id);
        assert_eq!(stored.member_info.version, 0);

        // Simulate nickname edit: update member_info in board_state with higher version
        let updated_info = MemberInfo {
            member_id,
            version: 1,
            preferred_nickname: SealedBytes::public("Bob".to_string().into_bytes()),
        };
        let updated_authorized =
            AuthorizedMemberInfo::new_with_member_key(updated_info, &invitee_sk);
        board_data.board_state.member_info.member_info[0] = updated_authorized;

        // Re-capture should update to latest version
        board_data.capture_self_membership_data(&params);
        let stored = board_data.self_member_info.as_ref().unwrap();
        assert_eq!(stored.member_info.version, 1);
    }

    #[test]
    fn test_is_awaiting_initial_sync() {
        let mut rng = rand::thread_rng();
        let owner_sk = SigningKey::generate(&mut rng);
        let owner_vk = owner_sk.verifying_key();
        let invitee_sk = SigningKey::generate(&mut rng);

        let params = ChatBoardParametersV1 { owner: owner_vk };
        let params_bytes = to_cbor_vec(&params);
        let contract_code = ContractCode::from(BOARD_CONTRACT_WASM);
        let contract_key =
            ContractKey::from_params_and_code(Parameters::from(params_bytes), &contract_code);

        let make_board = |sk: SigningKey, members: Vec<AuthorizedMember>| {
            let config = AuthorizedConfigurationV1::new(Configuration::default(), &owner_sk);
            let mut board_state = ChatBoardStateV1 {
                configuration: config,
                ..Default::default()
            };
            board_state.members.members = members;
            BoardData {
                owner_vk,
                board_state,
                self_sk: sk,
                owner_sk: None,
                profile_id: None,
                contract_key,
                last_read_message_id: None,
                secrets: HashMap::new(),
                category_secrets: HashMap::new(),
                old_category_secrets: HashMap::new(),

                trash_secret: None,
                trash_secrets: HashMap::new(),

                collapsed_groups: Vec::new(),
                last_visit: 0,
                read_categories: HashMap::new(),
                draft: None,
                drafts: Vec::new(),
                trash_retention_days: 0,
                pending_uploads: Vec::new(),
                pending_send: None,
                subscribed_categories: Vec::new(),
                current_secret_version: None,
                last_secret_rotation: None,
                key_migrated_to_delegate: false,
                self_authorized_member: None,
                invite_chain: vec![],
                self_member_info: None,
                spectator: false,
            }
        };

        // Owner with empty members: NOT awaiting sync (owner created the board)
        let owner_board = make_board(owner_sk.clone(), vec![]);
        assert!(!owner_board.is_awaiting_initial_sync());

        // Imported board with empty members: IS awaiting sync
        let imported_board = make_board(invitee_sk.clone(), vec![]);
        assert!(imported_board.is_awaiting_initial_sync());

        // Imported board after sync (members populated): NOT awaiting sync
        let member = Member {
            owner_member_id: owner_vk.into(),
            invited_by: owner_vk.into(),
            member_vk: invitee_sk.verifying_key(),
            join_proof: None,
        };
        let auth_member = AuthorizedMember::new(member, &owner_sk);
        let synced_board = make_board(invitee_sk.clone(), vec![auth_member]);
        assert!(!synced_board.is_awaiting_initial_sync());

        // Synced board with members pruned but messages present: NOT awaiting sync
        let mut pruned_board = make_board(invitee_sk, vec![]);
        use plaza_core::board_state::message::{AuthorizedMessageV1, BoardMessageBody, MessageV1};
        let dummy_msg = AuthorizedMessageV1 {
            message: MessageV1 {
                images: Vec::new(),
                board_owner: owner_vk.into(),
                author: owner_vk.into(),
                content: BoardMessageBody::public(String::new(), "test".to_string()),
                time: std::time::SystemTime::UNIX_EPOCH,
                reply_to: None,
                topic_id: None,
                topic_public_key: None,
                topic_proof: None,
                section_id: None,
                section_auto_moderated: None,
                auto_moderated: false,
            },
            signature: ed25519_dalek::Signature::from_bytes(&[0u8; 64]),
        };
        pruned_board
            .board_state
            .recent_messages
            .messages
            .push(dummy_msg);
        assert!(!pruned_board.is_awaiting_initial_sync());
    }

    /// The board-scoped key is stable for one board, differs between boards,
    /// and is not the root key.
    #[test]
    fn profile_derivation_is_deterministic_and_board_scoped() {
        let mut rng = rand::thread_rng();
        let profile = IdentityProfile::new("Profile".to_string(), SigningKey::generate(&mut rng));
        let board_a = SigningKey::generate(&mut rng).verifying_key();
        let board_b = SigningKey::generate(&mut rng).verifying_key();

        let first = profile.derive_for_board(&board_a);
        let again = profile.derive_for_board(&board_a);
        let other = profile.derive_for_board(&board_b);

        assert_eq!(first.to_bytes(), again.to_bytes());
        assert_ne!(first.to_bytes(), other.to_bytes());
        assert_ne!(first.verifying_key(), profile.signing_key.verifying_key());
    }

    /// A private board in derived mode signs as a board key; the root profile
    /// stays local and is reachable through `profile_id`.
    #[test]
    fn a_private_board_can_use_a_derived_profile_key() {
        let mut rng = rand::thread_rng();
        let owner_sk = SigningKey::generate(&mut rng);
        let profile = IdentityProfile::new("Shared".to_string(), SigningKey::generate(&mut rng));
        let root_vk = profile.signing_key.verifying_key();
        let mut boards = empty_boards();

        let key = boards.create_new_board_with_identity(
            owner_sk,
            profile.clone(),
            BoardIdentityMode::Derived,
            "Private".to_string(),
            "Shared".to_string(),
            true,
        );
        let board = boards.map.get(&key).unwrap();
        let derived_vk = profile.derive_for_board(&key).verifying_key();

        assert_ne!(board.self_sk.verifying_key(), root_vk);
        assert_eq!(board.self_sk.verifying_key(), derived_vk);
        assert_eq!(board.profile_id.as_deref(), Some(profile.id.as_str()));
        assert!(!board.uses_same_identity_as(&profile));
        assert!(board
            .board_state
            .members
            .members
            .iter()
            .any(|member| member.member.member_vk == derived_vk));
        assert!(board
            .board_state
            .admin
            .admins
            .iter()
            .any(|admin| admin.admin.member_id == MemberId::from(&derived_vk)));
        assert!(!board
            .board_state
            .member_info
            .member_info
            .iter()
            .any(|info| info.member_info.member_id == MemberId::from(&root_vk)));
        board
            .board_state
            .verify(&board.board_state, &ChatBoardParametersV1 { owner: key })
            .expect("the derived membership verifies");
        assert_eq!(
            boards.profile_for_board(board).map(|p| p.id.clone()),
            Some(profile.id.clone())
        );
    }

    /// Public boards keep the root key. Private boards signed with the same
    /// root key are flagged; derived boards are not.
    #[test]
    fn profile_linkability_flags_a_shared_root_key_across_privacy_modes() {
        let mut rng = rand::thread_rng();
        let profile = IdentityProfile::new("Shared".to_string(), SigningKey::generate(&mut rng));
        let mut boards = empty_boards();

        let public_key = boards.create_new_board_with_identity(
            SigningKey::generate(&mut rng),
            profile.clone(),
            BoardIdentityMode::Derived,
            "Public".to_string(),
            "Shared".to_string(),
            false,
        );
        let derived_key = boards.create_new_board_with_identity(
            SigningKey::generate(&mut rng),
            profile.clone(),
            BoardIdentityMode::Derived,
            "Derived private".to_string(),
            "Shared".to_string(),
            true,
        );

        assert_eq!(
            boards.map[&public_key].self_sk.verifying_key(),
            profile.signing_key.verifying_key()
        );
        let linkability = boards.profile_linkability(&profile);
        assert_eq!(linkability.public_boards, vec![public_key]);
        assert!(linkability.private_boards.is_empty());
        assert_eq!(linkability.derived_boards, vec![derived_key]);
        assert!(!linkability.linked_across);

        // Same identity on a private board: the root key now appears on both.
        let same_key = boards.create_new_board_with_identity(
            SigningKey::generate(&mut rng),
            profile.clone(),
            BoardIdentityMode::Same,
            "Same private".to_string(),
            "Shared".to_string(),
            true,
        );
        let linkability = boards.profile_linkability(&profile);
        assert_eq!(
            boards.map[&same_key].self_sk.verifying_key(),
            profile.signing_key.verifying_key()
        );
        assert_eq!(linkability.private_boards, vec![same_key]);
        assert!(linkability.linked_across);
        assert_eq!(linkability.derived_boards, vec![derived_key]);
    }

    /// A derived board exports its root profile; importing it restores the
    /// profile id, the root key and the owner key path.
    #[test]
    fn an_identity_export_roundtrips_the_root_profile() {
        let mut rng = rand::thread_rng();
        let owner_sk = SigningKey::generate(&mut rng);
        let owner_vk = owner_sk.verifying_key();
        let profile = IdentityProfile::new("Root".to_string(), SigningKey::generate(&mut rng));
        let mut boards = empty_boards();

        let key = boards.create_new_board_with_identity(
            owner_sk,
            profile.clone(),
            BoardIdentityMode::Derived,
            "Private".to_string(),
            "Root".to_string(),
            true,
        );
        let board = boards.map.get(&key).unwrap();
        let root = boards
            .export_root_profile(board)
            .expect("the board names its root profile");
        let export = IdentityExport {
            board_owner: key,
            signing_key: board.self_sk.clone(),
            owner_signing_key: Some(board.owner_key().clone()),
            authorized_member: board.self_authorized_member.clone().unwrap(),
            invite_chain: board.invite_chain.clone(),
            member_info: board.self_member_info.clone(),
            board_name: Some("Private".to_string()),
            category_keys: Vec::new(),
            board_secrets: Vec::new(),
            current_board_secret: None,
            profile_id: Some(root.id.clone()),
            profile_name: Some(root.name.clone()),
            profile_signing_key: Some(root.signing_key.clone()),
        };
        let decoded =
            IdentityExport::from_armored_string(&export.to_armored_string()).expect("decodes");

        let mut imported = empty_boards();
        let profile_id = imported
            .register_imported_profile(&decoded)
            .expect("the root profile is registered");
        let mut imported_board = board.clone();
        imported_board.self_sk = decoded.signing_key.clone();
        imported_board.owner_sk = decoded.owner_signing_key.clone();
        imported_board.profile_id = Some(profile_id.clone());
        imported.map.insert(key, imported_board);

        let resolved = imported
            .profile_for_board(&imported.map[&key])
            .expect("the board resolves to its root profile");
        assert_eq!(resolved.id, profile_id);
        assert_eq!(
            resolved.signing_key.to_bytes(),
            profile.signing_key.to_bytes()
        );
        assert_eq!(
            imported.map[&key].self_sk.verifying_key(),
            root.derive_for_board(&key).verifying_key()
        );
        assert_eq!(
            imported.map[&key].owner_sk.as_ref().map(|key| key.verifying_key()),
            Some(owner_vk)
        );
    }
}
