//! Persistent DM state owned by the delegate.
//!
//! One entry per derived DM identity lets a device hold the DMs of several
//! Plaza profiles. Devices, conversation keys, index and block list are scoped
//! to the identity; operations remain pure and testable without a runtime.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signer, SigningKey};
use ml_kem::kem::{Decapsulate, KeyExport};
use ml_kem::{B32, DecapsulationKey, EncapsulationKey, MlKem768, Seed};
use plaza_dm_core::delegate::*;
use plaza_dm_core::{
    AuthorizedDmDevice, AuthorizedDmMember, AuthorizedDmMessage, AuthorizedSealedDmKey,
    DmContractId, DmDevice, DmDeviceId, DmIdentityId, DmInvite, DmMember, DmMembersV1, DmMessage,
    DmMessageId, DmMetaV1, DmParamsV1, DmRole, DmStateDeltaV1, DmStateV1, SealedDmKey,
    CONTENT_TYPE_ATTACHMENT, CONTENT_TYPE_SYSTEM, CONTENT_TYPE_TEXT,
    KEY_SUITE_X25519_MLKEM768_XCHACHA20,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalDevice {
    pub device: DmDevice,
    pub label: String,
    pub signing_seed: [u8; 32],
    pub x25519_seed: [u8; 32],
    pub kem_seed: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalKey {
    pub contract_key: DmContractId,
    pub key_version: u32,
    pub key: [u8; 32],
    pub created_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DmIdentityStateV1 {
    pub identity_seed: [u8; 32],
    pub devices: Vec<LocalDevice>,
    pub conversations: Vec<DmConversationInfo>,
    pub keys: Vec<LocalKey>,
    pub blocked: Vec<DmIdentityId>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct DmDelegateStateV1 {
    pub version: u32,
    /// Last identity initialized on this device. Used by join links that open
    /// without a selected board.
    #[serde(default)]
    pub active_identity: Option<DmIdentityId>,
    pub identities: Vec<DmIdentityStateV1>,
}

impl DmIdentityStateV1 {
    pub fn identity(&self) -> DmIdentityId {
        identity_public(&self.identity_seed)
    }

    fn device_infos(&self) -> Vec<DmDeviceInfo> {
        self.devices
            .iter()
            .map(|local| DmDeviceInfo {
                device: local.device.clone(),
                label: local.label.clone(),
            })
            .collect()
    }

    fn create_device(
        &mut self,
        label: String,
        signing_seed: [u8; 32],
        x25519_seed: [u8; 32],
        kem_seed: Vec<u8>,
        created_at: i64,
    ) -> DmDelegateResponseMsg {
        if label.len() > 64 {
            return DmDelegateResponseMsg::error("device label is too long");
        }
        let Ok(kem_seed_array) = <[u8; 64]>::try_from(kem_seed.as_slice()) else {
            return DmDelegateResponseMsg::error("ML-KEM seed must be 64 bytes");
        };
        let signing = SigningKey::from_bytes(&signing_seed);
        let device_id = signing.verifying_key().to_bytes();
        if self
            .devices
            .iter()
            .any(|local| local.device.device_id == device_id)
        {
            return DmDelegateResponseMsg::error("device already exists");
        }
        let x25519_secret = x25519_dalek::StaticSecret::from(x25519_seed);
        let x25519_pk = x25519_dalek::PublicKey::from(&x25519_secret).to_bytes();
        let kem_ek = ml_kem_encapsulation_key(&kem_seed_array);
        let device = DmDevice {
            device_id,
            signing_key: device_id,
            x25519_pk,
            kem_ek,
            created_at,
            revoked_at: None,
        };
        self.devices.push(LocalDevice {
            device: device.clone(),
            label: label.clone(),
            signing_seed,
            x25519_seed,
            kem_seed,
        });
        DmDelegateResponseMsg::DeviceCreated { device, label }
    }

    fn revoke_device(
        &mut self,
        device_id: DmDeviceId,
        revoked_at: i64,
    ) -> DmDelegateResponseMsg {
        let Some(local) = self
            .devices
            .iter_mut()
            .find(|local| local.device.device_id == device_id)
        else {
            return DmDelegateResponseMsg::error("device not found");
        };
        if local.device.revoked_at.is_none() {
            local.device.revoked_at = Some(revoked_at);
        }
        DmDelegateResponseMsg::Ok
    }

    fn active_device(&self, device_id: &DmDeviceId) -> Result<&LocalDevice, DmDelegateResponseMsg> {
        let Some(local) = self
            .devices
            .iter()
            .find(|local| &local.device.device_id == device_id)
        else {
            return Err(DmDelegateResponseMsg::error("device not found"));
        };
        if local.device.revoked_at.is_some() {
            return Err(DmDelegateResponseMsg::error("device is revoked"));
        }
        Ok(local)
    }

    fn sign_identity(&self, bytes: &[u8]) -> DmDelegateResponseMsg {
        let signature = SigningKey::from_bytes(&self.identity_seed).sign(bytes);
        DmDelegateResponseMsg::Signature { signature }
    }

    fn sign_device(&self, device_id: DmDeviceId, bytes: &[u8]) -> DmDelegateResponseMsg {
        let local = match self.active_device(&device_id) {
            Ok(local) => local,
            Err(error) => return error,
        };
        let signature = SigningKey::from_bytes(&local.signing_seed).sign(bytes);
        DmDelegateResponseMsg::Signature { signature }
    }

    fn create_conversation_state(
        &self,
        device_id: DmDeviceId,
        conversation_id: [u8; 32],
        created_at: i64,
    ) -> DmDelegateResponseMsg {
        let local = match self.active_device(&device_id) {
            Ok(local) => local,
            Err(error) => return error,
        };
        let identity_sk = SigningKey::from_bytes(&self.identity_seed);
        let authorized_device =
            AuthorizedDmDevice::new(local.device.clone(), &identity_sk);
        let member = DmMember {
            identity: self.identity(),
            version: 0,
            role: DmRole::Creator,
            joined_at: created_at,
            devices: vec![authorized_device],
            left_at: None,
        };
        let state = DmStateV1 {
            meta: DmMetaV1 {
                conversation_id,
                created_at,
                state_version: 1,
                name: None,
            },
            members: DmMembersV1 {
                members: vec![AuthorizedDmMember::new(member, &identity_sk)],
            },
            ..Default::default()
        };
        DmDelegateResponseMsg::StateCreated { state }
    }

    fn create_invite(
        &self,
        invite_id: [u8; 32],
        token: [u8; 32],
        created_at: i64,
        expires_at: i64,
        bound_identity: Option<DmIdentityId>,
    ) -> DmDelegateResponseMsg {
        let identity_sk = SigningKey::from_bytes(&self.identity_seed);
        let invite = DmInvite::new(
            invite_id,
            &identity_sk,
            &token,
            created_at,
            expires_at,
            bound_identity,
        );
        DmDelegateResponseMsg::InviteCreated { invite }
    }

    fn create_join_member(
        &self,
        device_id: DmDeviceId,
        created_at: i64,
    ) -> DmDelegateResponseMsg {
        let local = match self.active_device(&device_id) {
            Ok(local) => local,
            Err(error) => return error,
        };
        let identity_sk = SigningKey::from_bytes(&self.identity_seed);
        let authorized_device =
            AuthorizedDmDevice::new(local.device.clone(), &identity_sk);
        let member = DmMember {
            identity: self.identity(),
            version: 0,
            role: DmRole::Member,
            joined_at: created_at,
            devices: vec![authorized_device],
            left_at: None,
        };
        DmDelegateResponseMsg::JoinMemberCreated {
            member: AuthorizedDmMember::new(member, &identity_sk),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn store_conversation_key(
        &mut self,
        contract_key: DmContractId,
        conversation_id: [u8; 32],
        key_version: u32,
        key: [u8; 32],
        peer: DmIdentityId,
        title: Option<String>,
        generation: u32,
        created_at: i64,
    ) -> DmDelegateResponseMsg {
        if key == [0u8; 32] {
            return DmDelegateResponseMsg::error("conversation key is empty");
        }
        if let Some(existing) = self.keys.iter().find(|existing| {
            existing.contract_key == contract_key && existing.key_version == key_version
        }) {
            if existing.key != key {
                return DmDelegateResponseMsg::error(
                    "a different key already exists for this version",
                );
            }
        } else {
            self.keys.push(LocalKey {
                contract_key,
                key_version,
                key,
                created_at,
            });
        }

        if let Some(conversation) = self
            .conversations
            .iter_mut()
            .find(|conversation| conversation.contract_key == contract_key)
        {
            if !conversation.key_versions.contains(&key_version) {
                conversation.key_versions.push(key_version);
                conversation.key_versions.sort_unstable();
            }
            conversation.conversation_id = conversation_id;
            conversation.peer = peer;
            if title.is_some() {
                conversation.title = title;
            }
            conversation.generation = conversation.generation.max(generation);
            conversation.last_message_at = conversation.last_message_at.max(created_at);
        } else {
            self.conversations.push(DmConversationInfo {
                contract_key,
                conversation_id,
                peer,
                title,
                generation,
                last_message_at: created_at,
                last_message_id: None,
                unread: 0,
                key_versions: vec![key_version],
                draft: None,
            });
        }
        DmDelegateResponseMsg::Ok
    }

    fn get_conversation_key(
        &self,
        contract_key: DmContractId,
        key_version: u32,
    ) -> DmDelegateResponseMsg {
        let key = self
            .keys
            .iter()
            .find(|key| key.contract_key == contract_key && key.key_version == key_version)
            .map(|key| key.key);
        DmDelegateResponseMsg::ConversationKey {
            key,
            key_version: Some(key_version),
        }
    }

    fn get_latest_conversation_key(&self, contract_key: DmContractId) -> DmDelegateResponseMsg {
        let latest = self
            .keys
            .iter()
            .filter(|key| key.contract_key == contract_key)
            .max_by_key(|key| key.key_version);
        DmDelegateResponseMsg::ConversationKey {
            key: latest.map(|key| key.key),
            key_version: latest.map(|key| key.key_version),
        }
    }

    fn sorted_conversations(&self) -> Vec<DmConversationInfo> {
        let mut conversations = self.conversations.clone();
        conversations.sort_by_key(|conversation| std::cmp::Reverse(conversation.last_message_at));
        conversations
    }

    fn update_read(
        &mut self,
        contract_key: DmContractId,
        last_message: DmMessageId,
        unread: u32,
        updated_at: i64,
    ) -> DmDelegateResponseMsg {
        let Some(conversation) = self
            .conversations
            .iter_mut()
            .find(|conversation| conversation.contract_key == contract_key)
        else {
            return DmDelegateResponseMsg::error("conversation not found");
        };
        conversation.last_message_id = Some(last_message);
        conversation.unread = unread;
        conversation.last_message_at = conversation.last_message_at.max(updated_at);
        DmDelegateResponseMsg::Ok
    }

    fn set_draft(
        &mut self,
        contract_key: DmContractId,
        draft: Option<String>,
    ) -> DmDelegateResponseMsg {
        let Some(conversation) = self
            .conversations
            .iter_mut()
            .find(|conversation| conversation.contract_key == contract_key)
        else {
            return DmDelegateResponseMsg::error("conversation not found");
        };
        conversation.draft = draft.filter(|draft| !draft.is_empty());
        DmDelegateResponseMsg::Ok
    }

    fn set_blocked(&mut self, target: DmIdentityId, blocked: bool) -> DmDelegateResponseMsg {
        self.blocked.retain(|existing| *existing != target);
        if blocked {
            self.blocked.push(target);
            self.blocked.sort_unstable();
        }
        DmDelegateResponseMsg::Ok
    }

    fn remove_conversation(&mut self, contract_key: DmContractId) -> DmDelegateResponseMsg {
        self.conversations
            .retain(|conversation| conversation.contract_key != contract_key);
        self.keys
            .retain(|key| key.contract_key != contract_key);
        DmDelegateResponseMsg::Ok
    }

    fn key_for(&self, contract_key: DmContractId, key_version: u32) -> Option<[u8; 32]> {
        self.keys
            .iter()
            .find(|key| key.contract_key == contract_key && key.key_version == key_version)
            .map(|key| key.key)
    }

    #[allow(clippy::too_many_arguments)]
    fn seal_conversation_key(
        &self,
        sealer_device: DmDeviceId,
        contract_key: DmContractId,
        key_version: u32,
        target_member: DmIdentityId,
        target_device: DmDeviceId,
        target_x25519_pk: [u8; 32],
        target_kem_ek: Vec<u8>,
        ephemeral_seed: [u8; 32],
        kem_seed: [u8; 32],
        nonce: [u8; 24],
        sealed_at: i64,
    ) -> DmDelegateResponseMsg {
        let Some(key) = self.key_for(contract_key, key_version) else {
            return DmDelegateResponseMsg::error("conversation key not found");
        };
        let sealer = match self.active_device(&sealer_device) {
            Ok(device) => device,
            Err(error) => return error,
        };
        let ek = match ml_kem_encapsulation_key_from_bytes(&target_kem_ek) {
            Ok(ek) => ek,
            Err(error) => return DmDelegateResponseMsg::error(error),
        };
        let ephemeral = x25519_dalek::StaticSecret::from(ephemeral_seed);
        let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral);
        let recipient = x25519_dalek::PublicKey::from(target_x25519_pk);
        let x25519_shared = ephemeral.diffie_hellman(&recipient);
        let (kem_ciphertext, kem_shared) =
            ek.encapsulate_deterministic(&B32::from(kem_seed));
        let sealed = match seal_key_bytes(
            &key,
            x25519_shared.as_bytes(),
            kem_shared.as_slice(),
            &sealed_key_aad(contract_key, key_version, target_member, target_device),
            &nonce,
        ) {
            Ok(sealed) => sealed,
            Err(error) => return DmDelegateResponseMsg::error(error),
        };
        let record = SealedDmKey {
            key_version,
            member: target_member,
            device: target_device,
            suite: KEY_SUITE_X25519_MLKEM768_XCHACHA20,
            ephemeral_x25519_pk: ephemeral_public.to_bytes(),
            kem_ciphertext: kem_ciphertext.as_slice().to_vec(),
            ciphertext: sealed,
            nonce,
            sealed_at,
        };
        let authorized = AuthorizedSealedDmKey::new(
            record,
            &SigningKey::from_bytes(&sealer.signing_seed),
        );
        DmDelegateResponseMsg::SealedKey { key: authorized }
    }

    fn open_conversation_key(
        &mut self,
        device_id: DmDeviceId,
        contract_key: DmContractId,
        record: &SealedDmKey,
    ) -> DmDelegateResponseMsg {
        if record.member != self.identity() || record.device != device_id {
            return DmDelegateResponseMsg::error("sealed key targets another device");
        }
        if record.suite != KEY_SUITE_X25519_MLKEM768_XCHACHA20 {
            return DmDelegateResponseMsg::error("unsupported sealed key suite");
        }
        let device = match self.active_device(&device_id) {
            Ok(device) => device,
            Err(error) => return error,
        };
        let Ok(kem_seed) = <[u8; 64]>::try_from(device.kem_seed.as_slice()) else {
            return DmDelegateResponseMsg::error("stored ML-KEM seed is invalid");
        };
        let decapsulation = DecapsulationKey::<MlKem768>::from_seed(Seed::from(kem_seed));
        let kem_shared = match decapsulation.decapsulate_slice(&record.kem_ciphertext) {
            Ok(shared) => shared,
            Err(_) => return DmDelegateResponseMsg::error("invalid ML-KEM ciphertext"),
        };
        let own = x25519_dalek::StaticSecret::from(device.x25519_seed);
        let ephemeral = x25519_dalek::PublicKey::from(record.ephemeral_x25519_pk);
        let x25519_shared = own.diffie_hellman(&ephemeral);
        let key = match open_key_bytes(
            &record.ciphertext,
            x25519_shared.as_bytes(),
            kem_shared.as_slice(),
            &sealed_key_aad(
                contract_key,
                record.key_version,
                record.member,
                record.device,
            ),
            &record.nonce,
        ) {
            Ok(key) => key,
            Err(error) => return DmDelegateResponseMsg::error(error),
        };
        if let Some(existing) = self.key_for(contract_key, record.key_version) {
            if existing != key {
                return DmDelegateResponseMsg::error(
                    "a different key is already stored for this version",
                );
            }
        } else {
            self.keys.push(LocalKey {
                contract_key,
                key_version: record.key_version,
                key,
                created_at: record.sealed_at,
            });
        }
        DmDelegateResponseMsg::ConversationKey {
            key: Some(key),
            key_version: Some(record.key_version),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn encrypt_message(
        &self,
        device_id: DmDeviceId,
        contract_key: DmContractId,
        key_version: u32,
        plaintext: &[u8],
        content_type: u16,
        reply_to: Option<DmMessageId>,
        created_at: i64,
        nonce: [u8; 24],
    ) -> DmDelegateResponseMsg {
        let Some(key) = self.key_for(contract_key, key_version) else {
            return DmDelegateResponseMsg::error("conversation key not found");
        };
        if !(CONTENT_TYPE_TEXT..=CONTENT_TYPE_ATTACHMENT).contains(&content_type) {
            return DmDelegateResponseMsg::error("unsupported content type");
        }
        let device = match self.active_device(&device_id) {
            Ok(device) => device,
            Err(error) => return error,
        };
        let author = self.identity();
        let aad = message_aad(
            contract_key,
            author,
            device_id,
            key_version,
            created_at,
            content_type,
            reply_to,
        );
        let ciphertext = match encrypt_bytes(&key, plaintext, &aad, &nonce) {
            Ok(ciphertext) => ciphertext,
            Err(error) => return DmDelegateResponseMsg::error(error),
        };
        let message = DmMessage {
            id: [0u8; 32],
            author,
            device: device_id,
            key_version,
            created_at,
            content_type,
            ciphertext,
            nonce,
            reply_to,
            declared_len: plaintext.len() as u32,
        };
        let authorized = AuthorizedDmMessage::new(
            message,
            &SigningKey::from_bytes(&device.signing_seed),
        );
        DmDelegateResponseMsg::MessageCreated {
            message: authorized,
        }
    }

    fn decrypt_message(
        &self,
        contract_key: DmContractId,
        message: &AuthorizedDmMessage,
    ) -> DmDelegateResponseMsg {
        let Some(key) = self.key_for(contract_key, message.message.key_version) else {
            return DmDelegateResponseMsg::error("conversation key not found");
        };
        if !matches!(
            message.message.content_type,
            CONTENT_TYPE_TEXT | CONTENT_TYPE_SYSTEM | CONTENT_TYPE_ATTACHMENT
        ) {
            return DmDelegateResponseMsg::error("unsupported content type");
        }
        let aad = message_aad(
            contract_key,
            message.message.author,
            message.message.device,
            message.message.key_version,
            message.message.created_at,
            message.message.content_type,
            message.message.reply_to,
        );
        match decrypt_bytes(
            &key,
            &message.message.ciphertext,
            &aad,
            &message.message.nonce,
        ) {
            Ok(bytes) => DmDelegateResponseMsg::Plaintext { bytes },
            Err(error) => DmDelegateResponseMsg::error(error),
        }
    }

    fn to_backup(&self) -> DmIdentityBackup {
        DmIdentityBackup {
            identity_seed: self.identity_seed,
            devices: self
                .devices
                .iter()
                .map(|local| DmDeviceBackup {
                    device: local.device.clone(),
                    label: local.label.clone(),
                    signing_seed: local.signing_seed,
                    x25519_seed: local.x25519_seed,
                    kem_seed: local.kem_seed.clone(),
                })
                .collect(),
            conversations: self.conversations.clone(),
            keys: self
                .keys
                .iter()
                .map(|key| DmKeyBackup {
                    contract_key: key.contract_key,
                    key_version: key.key_version,
                    key: key.key,
                    created_at: key.created_at,
                })
                .collect(),
            blocked: self.blocked.clone(),
        }
    }

    fn merge_backup(&mut self, backup: DmIdentityBackup) {
        for device in backup.devices {
            if !self
                .devices
                .iter()
                .any(|local| local.device.device_id == device.device.device_id)
            {
                self.devices.push(LocalDevice {
                    device: device.device,
                    label: device.label,
                    signing_seed: device.signing_seed,
                    x25519_seed: device.x25519_seed,
                    kem_seed: device.kem_seed,
                });
            }
        }
        for key in backup.keys {
            if !self.keys.iter().any(|existing| {
                existing.contract_key == key.contract_key
                    && existing.key_version == key.key_version
            }) {
                self.keys.push(LocalKey {
                    contract_key: key.contract_key,
                    key_version: key.key_version,
                    key: key.key,
                    created_at: key.created_at,
                });
            }
        }
        for conversation in backup.conversations {
            if let Some(existing) = self
                .conversations
                .iter_mut()
                .find(|existing| existing.contract_key == conversation.contract_key)
            {
                if conversation.last_message_at > existing.last_message_at {
                    *existing = conversation;
                }
            } else {
                self.conversations.push(conversation);
            }
        }
        for identity in backup.blocked {
            if !self.blocked.contains(&identity) {
                self.blocked.push(identity);
            }
        }
        self.blocked.sort_unstable();
    }
}

impl DmDelegateStateV1 {
    pub fn identity(&self, identity: &DmIdentityId) -> Option<&DmIdentityStateV1> {
        self.identities
            .iter()
            .find(|state| &state.identity() == identity)
    }

    fn identity_mut(&mut self, identity: &DmIdentityId) -> Option<&mut DmIdentityStateV1> {
        self.identities
            .iter_mut()
            .find(|state| &state.identity() == identity)
    }

    fn require_identity(
        &mut self,
        identity: &DmIdentityId,
    ) -> Result<&mut DmIdentityStateV1, DmDelegateResponseMsg> {
        self.identity_mut(identity)
            .ok_or_else(|| DmDelegateResponseMsg::error("DM identity is not initialized"))
    }

    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(self, &mut bytes)
            .map_err(|error| format!("encode delegate state: {error}"))?;
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        ciborium::de::from_reader(bytes).map_err(|error| format!("decode delegate state: {error}"))
    }

    pub fn apply(&mut self, request: DmDelegateRequestMsg) -> DmDelegateResponseMsg {
        match request {
            DmDelegateRequestMsg::GetActiveIdentity => DmDelegateResponseMsg::ActiveIdentity {
                identity: self.active_identity,
            },
            DmDelegateRequestMsg::GetStatus { identity } => {
                let Some(state) = self.identity(&identity) else {
                    return DmDelegateResponseMsg::error("DM identity is not initialized");
                };
                DmDelegateResponseMsg::Status {
                    identity,
                    devices: state.device_infos(),
                    conversations: state.conversations.len(),
                    blocked: state.blocked.len(),
                }
            }
            DmDelegateRequestMsg::Reset { identity } => {
                if let Some(identity) = identity {
                    self.identities.retain(|state| state.identity() != identity);
                    if self.active_identity == Some(identity) {
                        self.active_identity = None;
                    }
                } else {
                    self.identities.clear();
                    self.active_identity = None;
                }
                self.version = self.version.saturating_add(1);
                DmDelegateResponseMsg::Ok
            }
            DmDelegateRequestMsg::InitIdentity { identity_seed } => {
                let identity = identity_public(&identity_seed);
                if let Some(existing) = self.identity(&identity) {
                    if existing.identity_seed != identity_seed {
                        return DmDelegateResponseMsg::error(
                            "DM identity seed does not match the stored identity",
                        );
                    }
                } else {
                    self.identities.push(DmIdentityStateV1 {
                        identity_seed,
                        devices: Vec::new(),
                        conversations: Vec::new(),
                        keys: Vec::new(),
                        blocked: Vec::new(),
                    });
                }
                self.active_identity = Some(identity);
                self.version = self.version.saturating_add(1);
                DmDelegateResponseMsg::Ok
            }
            DmDelegateRequestMsg::CreateDevice {
                identity,
                label,
                signing_seed,
                x25519_seed,
                kem_seed,
                created_at,
            } => {
                let state = match self.require_identity(&identity) {
                    Ok(state) => state,
                    Err(error) => return error,
                };
                let response =
                    state.create_device(label, signing_seed, x25519_seed, kem_seed, created_at);
                if matches!(response, DmDelegateResponseMsg::DeviceCreated { .. }) {
                    self.version = self.version.saturating_add(1);
                }
                response
            }
            DmDelegateRequestMsg::ListDevices { identity } => {
                let Some(state) = self.identity(&identity) else {
                    return DmDelegateResponseMsg::error("DM identity is not initialized");
                };
                DmDelegateResponseMsg::Devices {
                    devices: state.device_infos(),
                }
            }
            DmDelegateRequestMsg::RevokeDevice {
                identity,
                device_id,
                revoked_at,
            } => {
                let state = match self.require_identity(&identity) {
                    Ok(state) => state,
                    Err(error) => return error,
                };
                let response = state.revoke_device(device_id, revoked_at);
                if matches!(response, DmDelegateResponseMsg::Ok) {
                    self.version = self.version.saturating_add(1);
                }
                response
            }
            DmDelegateRequestMsg::SignIdentity { identity, bytes } => {
                let Some(state) = self.identity(&identity) else {
                    return DmDelegateResponseMsg::error("DM identity is not initialized");
                };
                state.sign_identity(&bytes)
            }
            DmDelegateRequestMsg::SignDevice {
                identity,
                device_id,
                bytes,
            } => {
                let Some(state) = self.identity(&identity) else {
                    return DmDelegateResponseMsg::error("DM identity is not initialized");
                };
                state.sign_device(device_id, &bytes)
            }
            DmDelegateRequestMsg::CreateConversation {
                identity,
                device_id,
                conversation_id,
                created_at,
            } => {
                let Some(state) = self.identity(&identity) else {
                    return DmDelegateResponseMsg::error("DM identity is not initialized");
                };
                state.create_conversation_state(device_id, conversation_id, created_at)
            }
            DmDelegateRequestMsg::CreateInvite {
                identity,
                invite_id,
                token,
                created_at,
                expires_at,
                bound_identity,
            } => {
                let Some(state) = self.identity(&identity) else {
                    return DmDelegateResponseMsg::error("DM identity is not initialized");
                };
                state.create_invite(invite_id, token, created_at, expires_at, bound_identity)
            }
            DmDelegateRequestMsg::CreateJoinMember {
                identity,
                device_id,
                conversation_id: _,
                created_at,
            } => {
                let Some(state) = self.identity(&identity) else {
                    return DmDelegateResponseMsg::error("DM identity is not initialized");
                };
                state.create_join_member(device_id, created_at)
            }
            DmDelegateRequestMsg::StoreConversationKey {
                identity,
                contract_key,
                conversation_id,
                key_version,
                key,
                peer,
                title,
                generation,
                created_at,
            } => {
                let state = match self.require_identity(&identity) {
                    Ok(state) => state,
                    Err(error) => return error,
                };
                let response = state.store_conversation_key(
                    contract_key,
                    conversation_id,
                    key_version,
                    key,
                    peer,
                    title,
                    generation,
                    created_at,
                );
                if matches!(response, DmDelegateResponseMsg::Ok) {
                    self.version = self.version.saturating_add(1);
                }
                response
            }
            DmDelegateRequestMsg::GetConversationKey {
                identity,
                contract_key,
                key_version,
            } => match self.identity(&identity) {
                Some(state) => state.get_conversation_key(contract_key, key_version),
                None => DmDelegateResponseMsg::error("DM identity is not initialized"),
            },
            DmDelegateRequestMsg::GetLatestConversationKey {
                identity,
                contract_key,
            } => match self.identity(&identity) {
                Some(state) => state.get_latest_conversation_key(contract_key),
                None => DmDelegateResponseMsg::error("DM identity is not initialized"),
            },
            DmDelegateRequestMsg::ListConversations { identity } => {
                let Some(state) = self.identity(&identity) else {
                    return DmDelegateResponseMsg::error("DM identity is not initialized");
                };
                DmDelegateResponseMsg::Conversations {
                    conversations: state.sorted_conversations(),
                }
            }
            DmDelegateRequestMsg::UpdateRead {
                identity,
                contract_key,
                last_message,
                unread,
                updated_at,
            } => {
                let state = match self.require_identity(&identity) {
                    Ok(state) => state,
                    Err(error) => return error,
                };
                let response = state.update_read(contract_key, last_message, unread, updated_at);
                if matches!(response, DmDelegateResponseMsg::Ok) {
                    self.version = self.version.saturating_add(1);
                }
                response
            }
            DmDelegateRequestMsg::SetDraft {
                identity,
                contract_key,
                draft,
            } => {
                let state = match self.require_identity(&identity) {
                    Ok(state) => state,
                    Err(error) => return error,
                };
                let response = state.set_draft(contract_key, draft);
                if matches!(response, DmDelegateResponseMsg::Ok) {
                    self.version = self.version.saturating_add(1);
                }
                response
            }
            DmDelegateRequestMsg::BlockIdentity {
                identity,
                target,
                blocked,
            } => {
                let state = match self.require_identity(&identity) {
                    Ok(state) => state,
                    Err(error) => return error,
                };
                let response = state.set_blocked(target, blocked);
                self.version = self.version.saturating_add(1);
                response
            }
            DmDelegateRequestMsg::ListBlocked { identity } => {
                let Some(state) = self.identity(&identity) else {
                    return DmDelegateResponseMsg::error("DM identity is not initialized");
                };
                DmDelegateResponseMsg::Blocked {
                    identities: state.blocked.clone(),
                }
            }
            DmDelegateRequestMsg::RemoveConversation {
                identity,
                contract_key,
            } => {
                let state = match self.require_identity(&identity) {
                    Ok(state) => state,
                    Err(error) => return error,
                };
                let response = state.remove_conversation(contract_key);
                self.version = self.version.saturating_add(1);
                response
            }
            DmDelegateRequestMsg::SealConversationKey {
                identity,
                sealer_device,
                contract_key,
                key_version,
                target_member,
                target_device,
                target_x25519_pk,
                target_kem_ek,
                ephemeral_seed,
                kem_seed,
                nonce,
                sealed_at,
            } => {
                let Some(state) = self.identity(&identity) else {
                    return DmDelegateResponseMsg::error("DM identity is not initialized");
                };
                state.seal_conversation_key(
                    sealer_device,
                    contract_key,
                    key_version,
                    target_member,
                    target_device,
                    target_x25519_pk,
                    target_kem_ek,
                    ephemeral_seed,
                    kem_seed,
                    nonce,
                    sealed_at,
                )
            }
            DmDelegateRequestMsg::OpenConversationKey {
                identity,
                device_id,
                contract_key,
                record,
            } => {
                let state = match self.require_identity(&identity) {
                    Ok(state) => state,
                    Err(error) => return error,
                };
                let response = state.open_conversation_key(device_id, contract_key, &record);
                if matches!(response, DmDelegateResponseMsg::ConversationKey { .. }) {
                    self.version = self.version.saturating_add(1);
                }
                response
            }
            DmDelegateRequestMsg::EncryptMessage {
                identity,
                device_id,
                contract_key,
                key_version,
                plaintext,
                content_type,
                reply_to,
                created_at,
                nonce,
            } => {
                let Some(state) = self.identity(&identity) else {
                    return DmDelegateResponseMsg::error("DM identity is not initialized");
                };
                state.encrypt_message(
                    device_id,
                    contract_key,
                    key_version,
                    &plaintext,
                    content_type,
                    reply_to,
                    created_at,
                    nonce,
                )
            }
            DmDelegateRequestMsg::DecryptMessage {
                identity,
                contract_key,
                message,
            } => {
                let Some(state) = self.identity(&identity) else {
                    return DmDelegateResponseMsg::error("DM identity is not initialized");
                };
                state.decrypt_message(contract_key, &message)
            }
            DmDelegateRequestMsg::ExportBackup => {
                let backup = DmBackupV1 {
                    version: DM_DELEGATE_STORAGE_VERSION,
                    identities: self.identities.iter().map(|state| state.to_backup()).collect(),
                };
                let mut bytes = Vec::new();
                if let Err(error) = ciborium::ser::into_writer(&backup, &mut bytes) {
                    return DmDelegateResponseMsg::error(format!("encode backup: {error}"));
                }
                DmDelegateResponseMsg::Backup { bytes }
            }
            DmDelegateRequestMsg::ImportBackup { bytes } => {
                let backup: DmBackupV1 = match ciborium::de::from_reader(bytes.as_slice()) {
                    Ok(backup) => backup,
                    Err(error) => {
                        return DmDelegateResponseMsg::error(format!("decode backup: {error}"));
                    }
                };
                if backup.version > DM_DELEGATE_STORAGE_VERSION {
                    return DmDelegateResponseMsg::error("backup comes from a newer version");
                }
                for identity in backup.identities {
                    let id = identity_public(&identity.identity_seed);
                    if let Some(existing) = self.identity_mut(&id) {
                        existing.merge_backup(identity);
                    } else {
                        let mut state = DmIdentityStateV1 {
                            identity_seed: identity.identity_seed,
                            devices: Vec::new(),
                            conversations: Vec::new(),
                            keys: Vec::new(),
                            blocked: Vec::new(),
                        };
                        state.merge_backup(identity);
                        self.identities.push(state);
                    }
                }
                self.version = self.version.saturating_add(1);
                DmDelegateResponseMsg::Ok
            }
        }
    }
}

fn identity_public(seed: &[u8; 32]) -> DmIdentityId {
    // The client derives the DM identity seed from the profile root before
    // sending it. The delegate uses the seed directly.
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

fn ml_kem_encapsulation_key(seed: &[u8; 64]) -> Vec<u8> {
    let decapsulation = DecapsulationKey::<MlKem768>::from_seed(Seed::from(*seed));
    decapsulation.encapsulation_key().to_bytes().to_vec()
}

fn ml_kem_encapsulation_key_from_bytes(
    bytes: &[u8],
) -> Result<EncapsulationKey<MlKem768>, String> {
    let array = ml_kem::array::Array::try_from(bytes)
        .map_err(|_| "invalid ML-KEM encapsulation key".to_string())?;
    EncapsulationKey::<MlKem768>::new(&array)
        .map_err(|_| "invalid ML-KEM encapsulation key".to_string())
}

fn derive_hybrid_key(x25519_shared: &[u8], kem_shared: &[u8]) -> [u8; 32] {
    let mut combined = Vec::with_capacity(x25519_shared.len() + kem_shared.len());
    combined.extend_from_slice(x25519_shared);
    combined.extend_from_slice(kem_shared);
    blake3::derive_key("plaza-dm-sealed-key-v1", &combined)
}

fn sealed_key_aad(
    contract_key: DmContractId,
    key_version: u32,
    member: DmIdentityId,
    device: DmDeviceId,
) -> Vec<u8> {
    let mut aad = b"plaza-dm-sealed-key-v1".to_vec();
    aad.extend_from_slice(&contract_key);
    aad.extend_from_slice(&key_version.to_le_bytes());
    aad.extend_from_slice(&member);
    aad.extend_from_slice(&device);
    aad
}

fn message_aad(
    contract_key: DmContractId,
    author: DmIdentityId,
    device: DmDeviceId,
    key_version: u32,
    created_at: i64,
    content_type: u16,
    reply_to: Option<DmMessageId>,
) -> Vec<u8> {
    let mut aad = b"plaza-dm-message-v1".to_vec();
    aad.extend_from_slice(&contract_key);
    aad.extend_from_slice(&author);
    aad.extend_from_slice(&device);
    aad.extend_from_slice(&key_version.to_le_bytes());
    aad.extend_from_slice(&created_at.to_le_bytes());
    aad.extend_from_slice(&content_type.to_le_bytes());
    match reply_to {
        Some(id) => {
            aad.push(1);
            aad.extend_from_slice(&id);
        }
        None => aad.push(0),
    }
    aad
}

fn seal_key_bytes(
    key: &[u8; 32],
    x25519_shared: &[u8],
    kem_shared: &[u8],
    aad: &[u8],
    nonce: &[u8; 24],
) -> Result<Vec<u8>, String> {
    let derived = derive_hybrid_key(x25519_shared, kem_shared);
    XChaCha20Poly1305::new((&derived).into())
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: key.as_slice(),
                aad,
            },
        )
        .map_err(|_| "could not seal the conversation key".to_string())
}

fn open_key_bytes(
    ciphertext: &[u8],
    x25519_shared: &[u8],
    kem_shared: &[u8],
    aad: &[u8],
    nonce: &[u8; 24],
) -> Result<[u8; 32], String> {
    let derived = derive_hybrid_key(x25519_shared, kem_shared);
    let plaintext = XChaCha20Poly1305::new((&derived).into())
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| "could not open the conversation key".to_string())?;
    let key: [u8; 32] = plaintext
        .try_into()
        .map_err(|_| "unexpected conversation key length".to_string())?;
    Ok(key)
}

fn encrypt_bytes(
    key: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
    nonce: &[u8; 24],
) -> Result<Vec<u8>, String> {
    XChaCha20Poly1305::new((&(*key)).into())
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| "could not encrypt the message".to_string())
}

fn decrypt_bytes(
    key: &[u8; 32],
    ciphertext: &[u8],
    aad: &[u8],
    nonce: &[u8; 24],
) -> Result<Vec<u8>, String> {
    XChaCha20Poly1305::new((&(*key)).into())
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| "could not decrypt the message".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Verifier, VerifyingKey};

    #[test]
    fn two_delegates_join_seal_and_exchange_a_message() {
        let mut alice = DmDelegateStateV1::default();
        let alice_id = init(&mut alice, [11u8; 32]);
        let alice_device = create_device_with(
            &mut alice,
            alice_id,
            [21u8; 32],
            [31u8; 32],
            vec![41u8; 64],
        );
        let mut contract = match alice.apply(DmDelegateRequestMsg::CreateConversation {
            identity: alice_id,
            device_id: alice_device.device_id,
            conversation_id: [7u8; 32],
            created_at: 1_000,
        }) {
            DmDelegateResponseMsg::StateCreated { state } => state,
            other => panic!("conversation state missing: {other:?}"),
        };
        let params = DmParamsV1::default();
        let response = alice.apply(DmDelegateRequestMsg::StoreConversationKey {
            identity: alice_id,
            contract_key: [1u8; 32],
            conversation_id: [7u8; 32],
            key_version: 0,
            key: [9u8; 32],
            peer: [0u8; 32],
            title: None,
            generation: 0,
            created_at: 1_000,
        });
        assert!(matches!(response, DmDelegateResponseMsg::Ok));

        let mut bob = DmDelegateStateV1::default();
        let bob_id = init(&mut bob, [44u8; 32]);
        let bob_device = create_device_with(
            &mut bob,
            bob_id,
            [22u8; 32],
            [32u8; 32],
            vec![42u8; 64],
        );
        let member = match bob.apply(DmDelegateRequestMsg::CreateJoinMember {
            identity: bob_id,
            device_id: bob_device.device_id,
            conversation_id: [7u8; 32],
            created_at: 1_100,
        }) {
            DmDelegateResponseMsg::JoinMemberCreated { member } => member,
            other => panic!("join member missing: {other:?}"),
        };
        contract
            .apply_delta(
                &params,
                &DmStateDeltaV1 {
                    members: Some(vec![member]),
                    ..Default::default()
                },
            )
            .expect("the second member joins the contract");
        assert_eq!(contract.members.members.len(), 2);

        let sealed = match alice.apply(DmDelegateRequestMsg::SealConversationKey {
            identity: alice_id,
            sealer_device: alice_device.device_id,
            contract_key: [1u8; 32],
            key_version: 0,
            target_member: bob_id,
            target_device: bob_device.device_id,
            target_x25519_pk: bob_device.x25519_pk,
            target_kem_ek: bob_device.kem_ek,
            ephemeral_seed: [5u8; 32],
            kem_seed: [6u8; 32],
            nonce: [7u8; 24],
            sealed_at: 1_200,
        }) {
            DmDelegateResponseMsg::SealedKey { key } => key,
            other => panic!("sealed key missing: {other:?}"),
        };
        let opened = bob.apply(DmDelegateRequestMsg::OpenConversationKey {
            identity: bob_id,
            device_id: bob_device.device_id,
            contract_key: [1u8; 32],
            record: sealed.record,
        });
        let DmDelegateResponseMsg::ConversationKey { key, .. } = opened else {
            panic!("opened key missing: {opened:?}");
        };
        assert_eq!(key, Some([9u8; 32]));

        let encrypted = match alice.apply(DmDelegateRequestMsg::EncryptMessage {
            identity: alice_id,
            device_id: alice_device.device_id,
            contract_key: [1u8; 32],
            key_version: 0,
            plaintext: b"two identities, one message".to_vec(),
            content_type: CONTENT_TYPE_TEXT,
            reply_to: None,
            created_at: 1_300,
            nonce: [3u8; 24],
        }) {
            DmDelegateResponseMsg::MessageCreated { message } => message,
            other => panic!("message missing: {other:?}"),
        };
        contract
            .apply_delta(
                &params,
                &DmStateDeltaV1 {
                    messages: Some(vec![encrypted.clone()]),
                    ..Default::default()
                },
            )
            .expect("the encrypted message enters the contract");

        let decrypted = bob.apply(DmDelegateRequestMsg::DecryptMessage {
            identity: bob_id,
            contract_key: [1u8; 32],
            message: encrypted,
        });
        let DmDelegateResponseMsg::Plaintext { bytes } = decrypted else {
            panic!("plaintext missing: {decrypted:?}");
        };
        assert_eq!(bytes, b"two identities, one message");
    }

    fn init(state: &mut DmDelegateStateV1, seed: [u8; 32]) -> DmIdentityId {
        let response = state.apply(DmDelegateRequestMsg::InitIdentity {
            identity_seed: seed,
        });
        assert!(matches!(response, DmDelegateResponseMsg::Ok));
        identity_public(&seed)
    }

    #[test]
    fn the_hybrid_seal_opens_on_the_target_device_and_messages_round_trip() {
        let mut state = DmDelegateStateV1::default();
        let first = init(&mut state, [11u8; 32]);
        let second = init(&mut state, [44u8; 32]);
        let first_device = create_device_with(
            &mut state,
            first,
            [21u8; 32],
            [31u8; 32],
            vec![41u8; 64],
        );
        let second_device = create_device_with(
            &mut state,
            second,
            [22u8; 32],
            [32u8; 32],
            vec![42u8; 64],
        );
        store_key(&mut state, first, [1u8; 32], [9u8; 32]);

        let response = state.apply(DmDelegateRequestMsg::SealConversationKey {
            identity: first,
            sealer_device: first_device.device_id,
            contract_key: [1u8; 32],
            key_version: 0,
            target_member: second,
            target_device: second_device.device_id,
            target_x25519_pk: second_device.x25519_pk,
            target_kem_ek: second_device.kem_ek,
            ephemeral_seed: [7u8; 32],
            kem_seed: [8u8; 32],
            nonce: [9u8; 24],
            sealed_at: 1_100,
        });
        let DmDelegateResponseMsg::SealedKey { key } = response else {
            panic!("sealed key missing: {response:?}");
        };
        let sealer_vk = VerifyingKey::from_bytes(&first_device.signing_key).unwrap();
        key.verify(&sealer_vk).expect("sealed key signature");

        let response = state.apply(DmDelegateRequestMsg::OpenConversationKey {
            identity: second,
            device_id: second_device.device_id,
            contract_key: [1u8; 32],
            record: key.record,
        });
        let DmDelegateResponseMsg::ConversationKey { key, key_version } = response else {
            panic!("opened key missing: {response:?}");
        };
        assert_eq!(key, Some([9u8; 32]));
        assert_eq!(key_version, Some(0));

        let response = state.apply(DmDelegateRequestMsg::EncryptMessage {
            identity: first,
            device_id: first_device.device_id,
            contract_key: [1u8; 32],
            key_version: 0,
            plaintext: b"hello from the hybrid seal".to_vec(),
            content_type: CONTENT_TYPE_TEXT,
            reply_to: None,
            created_at: 1_200,
            nonce: [3u8; 24],
        });
        let DmDelegateResponseMsg::MessageCreated { message } = response else {
            panic!("message missing: {response:?}");
        };
        assert_ne!(message.message.ciphertext, b"hello from the hybrid seal");

        let response = state.apply(DmDelegateRequestMsg::DecryptMessage {
            identity: second,
            contract_key: [1u8; 32],
            message,
        });
        let DmDelegateResponseMsg::Plaintext { bytes } = response else {
            panic!("plaintext missing: {response:?}");
        };
        assert_eq!(bytes, b"hello from the hybrid seal");
    }

    #[test]
    fn a_tampered_seal_or_wrong_device_is_rejected() {
        let mut state = DmDelegateStateV1::default();
        let first = init(&mut state, [11u8; 32]);
        let second = init(&mut state, [44u8; 32]);
        let first_device = create_device_with(
            &mut state,
            first,
            [21u8; 32],
            [31u8; 32],
            vec![41u8; 64],
        );
        let second_device = create_device_with(
            &mut state,
            second,
            [22u8; 32],
            [32u8; 32],
            vec![42u8; 64],
        );
        store_key(&mut state, first, [1u8; 32], [9u8; 32]);
        let DmDelegateResponseMsg::SealedKey { key } =
            state.apply(DmDelegateRequestMsg::SealConversationKey {
                identity: first,
                sealer_device: first_device.device_id,
                contract_key: [1u8; 32],
                key_version: 0,
                target_member: second,
                target_device: second_device.device_id,
                target_x25519_pk: second_device.x25519_pk,
                target_kem_ek: second_device.kem_ek,
                ephemeral_seed: [7u8; 32],
                kem_seed: [8u8; 32],
                nonce: [9u8; 24],
                sealed_at: 1_100,
            })
        else {
            panic!("sealed key missing");
        };

        let mut tampered = key.record.clone();
        tampered.ciphertext[0] ^= 0xff;
        let response = state.apply(DmDelegateRequestMsg::OpenConversationKey {
            identity: second,
            device_id: second_device.device_id,
            contract_key: [1u8; 32],
            record: tampered,
        });
        assert!(matches!(response, DmDelegateResponseMsg::Error { .. }));

        let response = state.apply(DmDelegateRequestMsg::OpenConversationKey {
            identity: first,
            device_id: first_device.device_id,
            contract_key: [1u8; 32],
            record: key.record,
        });
        assert!(matches!(response, DmDelegateResponseMsg::Error { .. }));
    }

    fn create_device_with(
        state: &mut DmDelegateStateV1,
        identity: DmIdentityId,
        signing_seed: [u8; 32],
        x25519_seed: [u8; 32],
        kem_seed: Vec<u8>,
    ) -> DmDevice {
        let response = state.apply(DmDelegateRequestMsg::CreateDevice {
            identity,
            label: "Test".to_string(),
            signing_seed,
            x25519_seed,
            kem_seed,
            created_at: 1_000,
        });
        let DmDelegateResponseMsg::DeviceCreated { device, .. } = response else {
            panic!("device not created: {response:?}");
        };
        device
    }

    fn device(state: &mut DmDelegateStateV1, identity: DmIdentityId) -> DmDevice {
        let response = state.apply(DmDelegateRequestMsg::CreateDevice {
            identity,
            label: "Laptop".to_string(),
            signing_seed: identity,
            x25519_seed: [55u8; 32],
            kem_seed: vec![33u8; 64],
            created_at: 1_000,
        });
        let DmDelegateResponseMsg::DeviceCreated { device, .. } = response else {
            panic!("device not created: {response:?}");
        };
        device
    }

    fn store_key(
        state: &mut DmDelegateStateV1,
        identity: DmIdentityId,
        contract_key: DmContractId,
        key: [u8; 32],
    ) -> DmDelegateResponseMsg {
        state.apply(DmDelegateRequestMsg::StoreConversationKey {
            identity,
            contract_key,
            conversation_id: [2u8; 32],
            key_version: 0,
            key,
            peer: [3u8; 32],
            title: Some("Peer".to_string()),
            generation: 0,
            created_at: 1_000,
        })
    }

    #[test]
    fn two_profiles_have_independent_devices_and_keys() {
        let mut state = DmDelegateStateV1::default();
        let first = init(&mut state, [11u8; 32]);
        let second = init(&mut state, [44u8; 32]);
        assert_eq!(state.identities.len(), 2);
        assert_ne!(first, second);

        let first_device = device(&mut state, first);
        let second_device = device(&mut state, second);
        assert_ne!(first_device.device_id, second_device.device_id);

        let response = store_key(&mut state, first, [1u8; 32], [9u8; 32]);
        assert!(matches!(response, DmDelegateResponseMsg::Ok));
        let response = store_key(&mut state, second, [1u8; 32], [8u8; 32]);
        assert!(matches!(response, DmDelegateResponseMsg::Ok));

        let first_key = state.apply(DmDelegateRequestMsg::GetConversationKey {
            identity: first,
            contract_key: [1u8; 32],
            key_version: 0,
        });
        let DmDelegateResponseMsg::ConversationKey { key, .. } = first_key else {
            panic!("first key missing");
        };
        assert_eq!(key, Some([9u8; 32]));
        let second_key = state.apply(DmDelegateRequestMsg::GetConversationKey {
            identity: second,
            contract_key: [1u8; 32],
            key_version: 0,
        });
        let DmDelegateResponseMsg::ConversationKey { key, .. } = second_key else {
            panic!("second key missing");
        };
        assert_eq!(key, Some([8u8; 32]));

        let first_status = state.apply(DmDelegateRequestMsg::GetStatus { identity: first });
        let DmDelegateResponseMsg::Status {
            conversations,
            devices,
            ..
        } = first_status
        else {
            panic!("status missing");
        };
        assert_eq!(conversations, 1);
        assert_eq!(devices.len(), 1);
    }

    #[test]
    fn resetting_one_profile_keeps_the_other() {
        let mut state = DmDelegateStateV1::default();
        let first = init(&mut state, [11u8; 32]);
        let second = init(&mut state, [44u8; 32]);
        device(&mut state, first);
        device(&mut state, second);
        state.apply(DmDelegateRequestMsg::Reset {
            identity: Some(first),
        });
        assert!(state.identity(&first).is_none());
        assert!(state.identity(&second).is_some());

        state.apply(DmDelegateRequestMsg::Reset { identity: None });
        assert!(state.identities.is_empty());
    }

    #[test]
    fn backup_restores_every_profile() {
        let mut state = DmDelegateStateV1::default();
        let first = init(&mut state, [11u8; 32]);
        let second = init(&mut state, [44u8; 32]);
        device(&mut state, first);
        device(&mut state, second);
        store_key(&mut state, first, [1u8; 32], [9u8; 32]);
        store_key(&mut state, second, [2u8; 32], [8u8; 32]);

        let DmDelegateResponseMsg::Backup { bytes } =
            state.apply(DmDelegateRequestMsg::ExportBackup)
        else {
            panic!("backup missing");
        };
        let mut restored = DmDelegateStateV1::default();
        let response = restored.apply(DmDelegateRequestMsg::ImportBackup { bytes });
        assert!(matches!(response, DmDelegateResponseMsg::Ok));
        assert_eq!(restored.identities.len(), 2);
        assert!(restored.identity(&first).is_some());
        assert!(restored.identity(&second).is_some());
        assert_eq!(
            restored
                .identity(&first)
                .unwrap()
                .keys
                .first()
                .map(|key| key.key),
            Some([9u8; 32])
        );
    }

    #[test]
    fn an_unknown_profile_is_rejected() {
        let mut state = DmDelegateStateV1::default();
        let response = state.apply(DmDelegateRequestMsg::ListDevices {
            identity: [99u8; 32],
        });
        assert!(matches!(response, DmDelegateResponseMsg::Error { .. }));
    }

    #[test]
    fn signing_uses_the_selected_identity() {
        let mut state = DmDelegateStateV1::default();
        let first = init(&mut state, [11u8; 32]);
        let second = init(&mut state, [44u8; 32]);
        let payload = b"hello";
        let response = state.apply(DmDelegateRequestMsg::SignIdentity {
            identity: second,
            bytes: payload.to_vec(),
        });
        let DmDelegateResponseMsg::Signature { signature } = response else {
            panic!("signature missing");
        };
        VerifyingKey::from_bytes(&second)
            .unwrap()
            .verify(payload, &signature)
            .unwrap();
        assert!(VerifyingKey::from_bytes(&first)
            .unwrap()
            .verify(payload, &signature)
            .is_err());
    }
}
