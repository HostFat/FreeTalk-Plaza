//! Board, restricted-category, and post-quantum secret management for `BoardData`.

use super::*;

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

    /// Every restricted section on this board, projected into `CategoryContentV1`
    /// for role-based key distribution and rotation.
    pub fn restricted_categories(&self) -> Vec<(MessageId, CategoryContentV1)> {
        self.board_state
            .sections
            .sections
            .iter()
            .filter(|entry| !entry.section.deleted && !entry.section.allowed_roles.is_empty())
            .map(|entry| {
                let section = &entry.section;
                let category = CategoryContentV1 {
                    name: section.name.clone(),
                    description: section.description.clone(),
                    icon: section.icon.clone(),
                    color: section.color.clone(),
                    parent_category_id: section.parent,
                    allowed_roles: section.allowed_roles.clone(),
                    sealed_name: section.sealed_name.clone(),
                    hidden: section.hidden,
                    is_group: section.is_group,
                    images_allowed: section.images_allowed,
                    auto_moderated_topics: section.auto_moderated_topics,
                };
                (section.id, category)
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

    pub(super) fn category_secret_records(
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
            && self.board_state.topics.entries.is_empty()
            && self.board_state.sections.sections.is_empty()
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

    pub(super) fn self_is_member_or_owner(&self) -> bool {
        let self_vk = self.self_sk.verifying_key();
        self_vk == self.current_owner_key()
            || self
                .board_state
                .members
                .members
                .iter()
                .any(|member| member.member.member_vk == self_vk)
    }

    pub(super) fn apply_pq_delta(
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

    pub(super) fn publish_pq_key(&mut self, signing_key: &SigningKey, member_id: MemberId) -> bool {
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

    /// Recover the board key with any identity this device holds.
    ///
    /// `secrets` is skipped when the delegate blob is loaded, so a reload
    /// starts with no board key. The active profile may have no recipient
    /// blob, for example after joining as a new identity, while the owner key
    /// or another stored profile can still open the board. Try all of them
    /// before reporting the board as "key missing".
    pub fn decrypt_board_secrets_with_extra_keys(&mut self, extra_keys: &[SigningKey]) {
        if !self.is_private() {
            return;
        }
        use crate::util::ecies::decrypt_secret_from_member_blob;
        use x25519_dalek::PublicKey as X25519PublicKey;

        let mut candidates: Vec<SigningKey> = Vec::new();
        let mut add = |key: &SigningKey| {
            if !candidates
                .iter()
                .any(|known| known.verifying_key() == key.verifying_key())
            {
                candidates.push(key.clone());
            }
        };
        add(&self.self_sk);
        if let Some(owner) = &self.owner_sk {
            add(owner);
        }
        for key in extra_keys {
            add(key);
        }

        let current_version = self.board_state.secrets.current_version;
        for key in &candidates {
            let member_id = MemberId::from(&key.verifying_key());
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
                if let Ok(secret) =
                    decrypt_secret_from_member_blob(&ciphertext, &nonce, &ephemeral, key)
                {
                    self.set_secret(secret, version);
                }
            }
        }
        self.current_secret_version = Some(current_version);
        for key in &candidates {
            self.decrypt_pq_board_secrets_for_key(key);
        }
        self.decrypt_pq_trash_secret();
    }

    /// Try the PQ sets for the board secret. Old versions stay in `secrets`.
    pub fn decrypt_pq_board_secrets(&mut self) {
        if !self.is_private() {
            return;
        }
        let self_sk = self.self_sk.clone();
        self.decrypt_pq_board_secrets_for_key(&self_sk);
    }

    pub(super) fn decrypt_pq_board_secrets_for_key(&mut self, signing_key: &SigningKey) {
        let member_id = MemberId::from(&signing_key.verifying_key());
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
                    .filter(|secret| secret.member_id == member_id)
                    .map(|secret| (entry.set.secret_version, secret.clone()))
            })
            .collect();
        for (version, sealed) in sets {
            match crate::util::pq::open_secret(signing_key, &sealed) {
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
}
