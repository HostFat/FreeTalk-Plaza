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
use plaza_core::board_state::member::AuthorizedMember;
use plaza_core::board_state::member::MemberId;
use plaza_core::board_state::member_info::{AuthorizedMemberInfo, MemberInfo};
use plaza_core::board_state::message::{BoardMessageBody, MessageId, SecretScope};
use plaza_core::board_state::privacy::{
    BoardCipherSpec, BoardDisplayMetadata, PrivacyMode, SealedBytes,
};
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

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct BoardData {
    pub owner_vk: VerifyingKey,
    pub board_state: ChatBoardStateV1,
    pub self_sk: SigningKey,
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
}

impl BoardData {
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
                    Some((best_version, best_key)) if best_version >= version => {
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
                let (secret, _) = self.body_secret(content)?;
                let bytes = decrypt_with_symmetric_key(&secret, ciphertext, nonce).ok()?;
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
            if let Some((_, key)) = self.category_secret(category_id) {
                if let Ok(bytes) = crate::util::ecies::unseal_bytes(sealed, Some(&key)) {
                    if let Ok(name) = String::from_utf8(bytes) {
                        category.name = name;
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
                provider: MemberId::from(&self.self_sk.verifying_key()),
            };
            let self_id = MemberId::from(&self.self_sk.verifying_key());
            encrypted_secrets.push(if self_id == owner_id {
                AuthorizedEncryptedSecretForMember::new(record, &self.self_sk)
            } else {
                AuthorizedEncryptedSecretForMember::signed_by(record, self_id, &self.self_sk)
            });
        }

        let versions = if include_version {
            vec![AuthorizedSecretVersionRecord::new(
                SecretVersionRecordV1 {
                    version,
                    cipher_spec: BoardCipherSpec::Aes256Gcm,
                    created_at: get_current_system_time(),
                },
                &self.self_sk,
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
        if self.self_sk.verifying_key() != self.owner_vk {
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
                    let (key, _) = self.body_secret(&message.message.content)?;
                    decrypt_with_symmetric_key(&key, ciphertext, nonce)
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
                            decrypt_with_symmetric_key(&key, &ciphertext, &nonce)
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
        for flag in &self.board_state.moderation.flags {
            if flag.flag.closed {
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
        self.board_state
            .recent_messages
            .rebuild_actions_state_with_permissions(
                &decrypted_actions,
                Some(owner_id),
                Some(&admin_ids),
                Some(&moderation),
            );
    }

    /// Whether this client may sign category key distributions: the owner, or
    /// a member of a role the owner allowed to distribute keys.
    pub fn can_distribute_category_keys(&self) -> bool {
        if self.self_sk.verifying_key() == self.owner_vk {
            return true;
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
        let is_owner = self.self_sk.verifying_key() == self.owner_vk;

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
        let is_owner = self.self_sk.verifying_key() == self.owner_vk;
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
        if self.owner_vk != self.self_sk.verifying_key() {
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

        // Owner can always send
        if verifying_key == self.owner_vk {
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

        // Owner can always participate
        if verifying_key == self.owner_vk {
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
        let owner_id = MemberId::from(&self.owner_vk);

        // Owner can always create categories
        if self_id == owner_id {
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
        if verifying_key == self.owner_vk {
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
        if self.owner_vk != self.self_sk.verifying_key() {
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
        };

        let authorized_version = AuthorizedSecretVersionRecord::new(secret_version, &self.self_sk);

        // Get all current members, excluding banned members
        let banned_members: std::collections::HashSet<MemberId> = self
            .board_state
            .bans
            .0
            .iter()
            .map(|b| b.ban.banned_user)
            .collect();

        let current_members: Vec<MemberId> = self
            .board_state
            .members
            .members
            .iter()
            .map(|m| MemberId::from(&m.member.member_vk))
            .filter(|id| !banned_members.contains(id))
            .collect();

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
                };

                let authorized_encrypted_secret =
                    AuthorizedEncryptedSecretForMember::new(encrypted_secret, &self.self_sk);

                new_encrypted_secrets.push(authorized_encrypted_secret);
            }
        }

        // Update our local secrets (add new version, keep old ones for decryption)
        self.secrets.insert(new_version, new_secret);
        self.current_secret_version = Some(new_version);
        self.last_secret_rotation = Some(get_current_system_time());

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
                };

                let authorized_encrypted_secret =
                    AuthorizedEncryptedSecretForMember::new(encrypted_secret, &self.self_sk);

                new_encrypted_secrets.push(authorized_encrypted_secret);
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

#[derive(Clone, Serialize, Deserialize)]
pub struct Boards {
    pub map: HashMap<VerifyingKey, BoardData>,
    #[serde(default)]
    pub current_board_key: Option<VerifyingKey>,
    /// Boards whose contract key changed due to WASM update.
    /// Each entry is (owner_vk, old_contract_key) for boards where the owner
    /// should send an upgrade pointer to the old contract.
    #[serde(skip)]
    pub migrated_boards: Vec<(VerifyingKey, ContractKey)>,
}

impl PartialEq for Boards {
    fn eq(&self, other: &Self) -> bool {
        self.map == other.map
    }
}

impl Boards {
    pub fn create_new_board_with_name(
        &mut self,
        self_sk: SigningKey,
        name: String,
        nickname: String,
        is_private: bool,
    ) -> VerifyingKey {
        use dioxus::logger::tracing::info;
        info!(
            "🟢 create_new_board_with_name called: name='{}', nickname='{}', is_private={}",
            name, nickname, is_private
        );

        let owner_vk = self_sk.verifying_key();
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
            };

            let authorized_version = AuthorizedSecretVersionRecord::new(secret_version, &self_sk);

            // Create encrypted secret for the owner
            let encrypted_secret = EncryptedSecretForMemberV1 {
                member_id: owner_vk.into(),
                secret_version: 0,
                ciphertext,
                nonce,
                sender_ephemeral_public_key: ephemeral_key.to_bytes(),
                provider: owner_vk.into(),
            };

            let authorized_encrypted_secret =
                AuthorizedEncryptedSecretForMember::new(encrypted_secret, &self_sk);

            // Add to board state
            board_state.secrets.versions.push(authorized_version);
            board_state
                .secrets
                .encrypted_secrets
                .push(authorized_encrypted_secret);
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
                    let (ciphertext, nonce) = encrypt_with_symmetric_key(secret, name.as_bytes());
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
            ..Configuration::default()
        };
        board_state.configuration = AuthorizedConfigurationV1::new(config, &self_sk);

        // Add owner to member_info
        let owner_info = MemberInfo {
            member_id: owner_vk.into(),
            version: 0,
            preferred_nickname: if let Some(ref secret) = board_secret {
                // Encrypt nickname for private boards
                use crate::util::ecies::encrypt_with_symmetric_key;
                let (ciphertext, nonce) = encrypt_with_symmetric_key(secret, nickname.as_bytes());
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
        let authorized_owner_info = AuthorizedMemberInfo::new(owner_info, &self_sk);
        board_state
            .member_info
            .member_info
            .push(authorized_owner_info);

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
        let board_data = BoardData {
            owner_vk,
            board_state,
            self_sk,
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
            self_authorized_member: None,    // Owner doesn't need this
            invite_chain: vec![],
            self_member_info: None,
            category_secrets: HashMap::new(),
            old_category_secrets: HashMap::new(),
            collapsed_groups: Vec::new(),
            last_visit: 0,
            read_categories: HashMap::new(),
            draft: None,
            subscribed_categories: Vec::new(),
        };

        info!("🟢 Inserting board into map...");
        self.map.insert(owner_vk, board_data);
        info!("🟢 create_new_board_with_name completed successfully, returning owner_vk");
        owner_vk
    }

    /// Merge the other Boards into this Boards (eg. when Boards are loaded from storage)
    pub fn merge(&mut self, other: Boards) -> Result<(), String> {
        for (vk, mut board_data) in other.map {
            // Capture the old contract key before regeneration
            let old_contract_key = board_data.contract_key;

            // Regenerate contract_key to ensure it matches the current bundled WASM
            // This handles the case where boards were stored with an older WASM version
            board_data.regenerate_contract_key();
            // Stored state carries category keys; open them on load so the UI can
            // show restricted categories without waiting for a network round trip.
            board_data.decrypt_category_secrets();

            // If the contract key changed (WASM was updated), track for upgrade pointer
            if old_contract_key != board_data.contract_key {
                self.migrated_boards.push((vk, old_contract_key));
            }

            // If not already in the map, add the board
            if let std::collections::hash_map::Entry::Vacant(e) = self.map.entry(vk) {
                e.insert(board_data);
            } else {
                // If the board is already in the map, merge in the new data
                let self_board_data = self.map.get_mut(&vk).unwrap();
                if self_board_data.self_sk != board_data.self_sk {
                    return Err("self_sk is different".to_string());
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
    use plaza_core::board_state::member::{AuthorizedMember, Member, MemberId};

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
                migrated_boards: vec![],
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
            migrated_boards: vec![],
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

        // The owner reads the sealed board name.
        match &board.board_state.configuration.configuration.display.name {
            SealedBytes::Private {
                ciphertext, nonce, ..
            } => assert_eq!(
                decrypt_with_symmetric_key(&secret, ciphertext, nonce).unwrap(),
                b"Secret Plans"
            ),
            _ => panic!("a private board name must be sealed"),
        }

        // The invitee joins with their own key.
        let invitee_sk = SigningKey::generate(&mut rng);
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

        let invitee_id: MemberId = invitee_sk.verifying_key().into();
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
        use crate::util::ecies::{decrypt_with_symmetric_key, seal_bytes};
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
            migrated_boards: vec![],
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
                                scope: Vec::new(),
                                deleted: false,
                            },
                            &owner_sk,
                        )],
                        assignments: vec![AuthorizedRoleAssignment::new(
                            RoleAssignment {
                                role_id,
                                member_id: invitee_id,
                                generation: 1,
                                revoked: false,
                            },
                            &owner_sk,
                        )],
                    }),
                    // A member with no messages is pruned by cleanup, so keep
                    // the invitee alive with one post, as a real board would.
                    recent_messages: Some(vec![AuthorizedMessageV1::new(
                        MessageV1 {
                            board_owner: owner_id,
                            author: invitee_id,
                            content: BoardMessageBody::public(String::new(), "hello".to_string()),
                            time: get_current_system_time(),
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
            board_owner: owner_id,
            author: owner_id,
            content: BoardMessageBody::public_raw(
                CONTENT_TYPE_CATEGORY,
                CATEGORY_CONTENT_VERSION,
                category.encode(),
            ),
            time: get_current_system_time(),
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
        invitee_view.category_secrets.clear();
        invitee_view.decrypt_category_secrets();
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
        let plaintext = decrypt_with_symmetric_key(
            &category_secret,
            match &category_post {
                plaza_core::board_state::privacy::SealedBytes::Private { ciphertext, .. } => {
                    ciphertext
                }
                _ => unreachable!(),
            },
            match &category_post {
                plaza_core::board_state::privacy::SealedBytes::Private { nonce, .. } => nonce,
                _ => unreachable!(),
            },
        )
        .unwrap();
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
                            },
                            &owner_sk,
                        )],
                    }),
                    recent_messages: Some(vec![AuthorizedMessageV1::new(
                        MessageV1 {
                            board_owner: owner_id,
                            author: outsider_id,
                            content: BoardMessageBody::public(
                                String::new(),
                                "joined the role".to_string(),
                            ),
                            time: get_current_system_time(),
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
            contract_key,
            last_read_message_id: None,
            secrets: HashMap::new(),
            category_secrets: HashMap::new(),
            old_category_secrets: HashMap::new(),
            collapsed_groups: Vec::new(),
            last_visit: 0,
            read_categories: HashMap::new(),
            draft: None,
            subscribed_categories: Vec::new(),
            current_secret_version: None,
            last_secret_rotation: None,
            key_migrated_to_delegate: false,
            self_authorized_member: None,
            invite_chain: vec![],
            self_member_info: None,
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
            contract_key,
            last_read_message_id: None,
            secrets: HashMap::new(),
            category_secrets: HashMap::new(),
            old_category_secrets: HashMap::new(),
            collapsed_groups: Vec::new(),
            last_visit: 0,
            read_categories: HashMap::new(),
            draft: None,
            subscribed_categories: Vec::new(),
            current_secret_version: None,
            last_secret_rotation: None,
            key_migrated_to_delegate: false,
            self_authorized_member: None,
            invite_chain: vec![],
            self_member_info: None,
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
                contract_key,
                last_read_message_id: None,
                secrets: HashMap::new(),
                category_secrets: HashMap::new(),
                old_category_secrets: HashMap::new(),
                collapsed_groups: Vec::new(),
                last_visit: 0,
                read_categories: HashMap::new(),
                draft: None,
                subscribed_categories: Vec::new(),
                current_secret_version: None,
                last_secret_rotation: None,
                key_migrated_to_delegate: false,
                self_authorized_member: None,
                invite_chain: vec![],
                self_member_info: None,
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
                board_owner: owner_vk.into(),
                author: owner_vk.into(),
                content: BoardMessageBody::public(String::new(), "test".to_string()),
                time: std::time::SystemTime::UNIX_EPOCH,
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
}
