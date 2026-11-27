//! Multi-board collection, identity profiles, and board lifecycle helpers.

use super::*;

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
    /// Optional Freenet Mail address. Kept on this device and published only
    /// on boards where the user enables visibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mail_address: Option<String>,
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
            mail_address: None,
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

pub(super) fn profile_stamp() -> u64 {
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
    /// Local display order for the board switcher.
    #[serde(default)]
    pub board_order: Vec<VerifyingKey>,
    /// Boards hidden from the main switcher but kept on this device.
    #[serde(default)]
    pub archived: Vec<VerifyingKey>,
    /// Per-device UI feature flags.
    #[serde(default)]
    pub client_features: ClientFeatures,
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
            && self.board_order == other.board_order
            && self.archived == other.archived
            && self.client_features == other.client_features
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

    /// Display order for the switcher. Keys missing from the saved order keep
    /// the map's deterministic order at the end.
    pub fn ordered_keys(&self) -> Vec<VerifyingKey> {
        let mut keys: Vec<VerifyingKey> = self
            .board_order
            .iter()
            .copied()
            .filter(|key| self.map.contains_key(key))
            .collect();
        let mut extra: Vec<VerifyingKey> = self
            .map
            .keys()
            .copied()
            .filter(|key| !keys.contains(key))
            .collect();
        extra.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        keys.extend(extra);
        keys
    }

    /// Move one visible board one slot up (`delta = -1`) or down (`delta = 1`).
    pub fn move_board(&mut self, key: VerifyingKey, delta: isize) {
        let mut keys: Vec<VerifyingKey> = self
            .ordered_keys()
            .into_iter()
            .filter(|candidate| !self.is_archived(*candidate))
            .collect();
        let Some(index) = keys.iter().position(|candidate| *candidate == key) else {
            return;
        };
        let target = index as isize + delta;
        if target < 0 || target >= keys.len() as isize {
            return;
        }
        keys.swap(index, target as usize);
        self.board_order = keys;
    }

    pub fn set_archived(&mut self, key: VerifyingKey, archived: bool) {
        if archived {
            if !self.archived.contains(&key) {
                self.archived.push(key);
            }
        } else {
            self.archived.retain(|candidate| *candidate != key);
        }
    }

    pub fn is_archived(&self, key: VerifyingKey) -> bool {
        self.archived.contains(&key)
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
                board.backfill_owner_profile();
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
            board_order: Vec::new(),
            archived: Vec::new(),
            client_features: ClientFeatures::default(),
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
                Some("profiles") => {
                    boards.profiles = value.deserialized().unwrap_or_default();
                }
                Some("board_order") => {
                    boards.board_order = value.deserialized().unwrap_or_default();
                }
                Some("archived") => {
                    boards.archived = value.deserialized().unwrap_or_default();
                }
                Some("owned_images") => {
                    boards.owned_images = value.deserialized().unwrap_or_default();
                }
                Some("client_features") => {
                    boards.client_features = value.deserialized().unwrap_or_default();
                }
                Some("blocked_image_hashes") => {
                    boards.blocked_image_hashes = value.deserialized().unwrap_or_default();
                }
                Some("auto_renew_images") => {
                    boards.auto_renew_images = value.deserialized().unwrap_or(false);
                }
                Some("last_auto_renew_at") => {
                    boards.last_auto_renew_at = value.deserialized().unwrap_or(0);
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
            if profile.mail_address.is_some() {
                existing.mail_address = profile.mail_address;
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

    /// Store or clear the profile's Freenet Mail address. Publishing it on a
    /// board is a separate, explicit action.
    pub fn set_profile_mail_address(&mut self, id: &str, address: Option<String>) -> bool {
        let Some(profile) = self.profiles.iter_mut().find(|p| p.id == id) else {
            return false;
        };
        profile.mail_address = address;
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
        if self.client_features.topic_boards {
            // Topic boards are section-sharded by default. The older
            // `sectioned_boards` flag stays in the stored features so a
            // device that predates this change still deserializes.
            board_state.mode = plaza_core::board_state::BoardModeV1::SectionedTopicIndex;
        }

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

        // New section-sharded boards start with a General section. The owner
        // signs the section record; topics created in it carry an owner-signed
        // snapshot.
        let mut general_section: Option<
            plaza_core::board_state::sections::AuthorizedSectionV1,
        > = None;
        if board_state.mode == plaza_core::board_state::BoardModeV1::SectionedTopicIndex {
            use plaza_core::board_state::message::MessageId;
            use plaza_core::board_state::privacy::SealedBytes;
            use plaza_core::board_state::sections::{
                AuthorizedSectionV1, SectionV1,
            };
            use rand::RngCore;
            let mut section_bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut section_bytes);
            let version = board_secret_version.unwrap_or(0);
            let sealed_name = board_secret.map(|secret| {
                let (ciphertext, nonce) =
                    crate::util::ecies::encrypt_with_symmetric_key(
                        &secret, b"General", version,
                    );
                SealedBytes::private(ciphertext, nonce, version, 7)
            });
            let section_id = MessageId::from_bytes(section_bytes);
            let child_contract = Some(*crate::components::app::section_contract::section_key(
                owner_vk,
                section_id,
            )
            .id());
            let section = SectionV1 {
                id: section_id,
                parent: None,
                name: "General".to_string(),
                description: None,
                icon: None,
                color: "#6366f1".to_string(),
                allowed_roles: Vec::new(),
                sealed_name,
                hidden: false,
                is_group: false,
                images_allowed: true,
                auto_moderated_topics: None,
                generation: 1,
                deleted: false,
                contract: child_contract,
                signed_at: get_current_system_time(),
            };
            let authorized = AuthorizedSectionV1::new(section, &owner_sk, None);
            board_state.sections.sections.push(authorized.clone());
            general_section = Some(authorized);
        }

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
            owner_profile_id: Some(profile_id.clone()),
            profile_id: Some(profile_id),
            contract_key,
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
            collapsed_groups: Vec::new(),
            last_visit: 0,
            topic_read: HashMap::new(),
            topic_drafts: HashMap::new(),
            pending_uploads: Vec::new(),
            subscribed_categories: Vec::new(),
            notification_mode: NotificationMode::All,
            mail_visibility: MailVisibility::Hidden,
            nickname_requests: Vec::new(),
        };

        if board_data.is_private() {
            board_data.ensure_pq_key();
            board_data.generate_missing_pq_secrets();
        }
        board_data.refresh_authority_root();

        info!("🟢 Inserting board into map...");
        self.removed.retain(|vk| *vk != owner_vk);
        self.map.insert(owner_vk, board_data);
        if let Some(section) = general_section {
            if let Some(state) = self
                .map
                .get(&owner_vk)
                .map(|board| board.board_state.clone())
            {
                let topic_pages = self.map.get(&owner_vk).map(|board| {
                    plaza_core::board_state::pages::AuthorizedTopicPageListV1::new(
                        section.section.id,
                        Vec::new(),
                        crate::components::app::section_contract::current_topic_page_size(),
                        board.owner_key(),
                        plaza_core::board_state::rate_limit::system_time_ms(
                            get_current_system_time(),
                        ),
                    )
                });
                crate::util::safe_spawn_local(async move {
                    if let Err(error) = crate::components::app::section_contract::create_section_board(
                        owner_vk,
                        &section,
                        &state,
                        topic_pages,
                    )
                    .await
                    {
                        dioxus::logger::tracing::warn!(
                            "General section child was not created: {error}"
                        );
                    }
                });
            }
        }
        info!("🟢 create_new_board_with_name completed successfully, returning owner_vk");
        owner_vk
    }

    /// Merge the other Boards into this Boards (eg. when Boards are loaded from storage)
    pub fn merge(&mut self, other: Boards) -> Result<(), String> {
        // Top-level UI preferences live on this device. When the in-memory
        // copy has no value yet (initial delegate load), take the stored one.
        if self.board_order.is_empty() {
            self.board_order = other.board_order.clone();
        }
        if self.archived.is_empty() {
            self.archived = other.archived.clone();
        }
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
                    let was_published = existing.published || entry.published;
                    if entry.renewed_at > existing.renewed_at {
                        *existing = entry;
                    }
                    existing.published = was_published;
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
                    if board_data.owner_profile_id.is_some() {
                        self_board_data.owner_profile_id =
                            board_data.owner_profile_id.clone();
                    }
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
