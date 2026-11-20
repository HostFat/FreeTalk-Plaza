//! Persistent DM state owned by the delegate.
//!
//! One entry per derived DM identity lets a device hold the DMs of several
//! Plaza profiles. Devices, conversation keys, index and block list are scoped
//! to the identity; operations remain pure and testable without a runtime.

use ed25519_dalek::{Signer, SigningKey};
use ml_kem::kem::KeyExport;
use ml_kem::{DecapsulationKey, MlKem768, Seed};
use plaza_dm_core::delegate::*;
use plaza_dm_core::{
    DmContractId, DmDevice, DmDeviceId, DmIdentityId, DmMessageId,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalDevice {
    pub device: DmDevice,
    pub label: String,
    pub signing_seed: [u8; 32],
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
        let kem_ek = ml_kem_encapsulation_key(&kem_seed_array);
        let device = DmDevice {
            device_id,
            signing_key: device_id,
            kem_ek,
            created_at,
            revoked_at: None,
        };
        self.devices.push(LocalDevice {
            device: device.clone(),
            label: label.clone(),
            signing_seed,
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
                } else {
                    self.identities.clear();
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
                self.version = self.version.saturating_add(1);
                DmDelegateResponseMsg::Ok
            }
            DmDelegateRequestMsg::CreateDevice {
                identity,
                label,
                signing_seed,
                kem_seed,
                created_at,
            } => {
                let state = match self.require_identity(&identity) {
                    Ok(state) => state,
                    Err(error) => return error,
                };
                let response = state.create_device(label, signing_seed, kem_seed, created_at);
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Verifier, VerifyingKey};

    fn init(state: &mut DmDelegateStateV1, seed: [u8; 32]) -> DmIdentityId {
        let response = state.apply(DmDelegateRequestMsg::InitIdentity {
            identity_seed: seed,
        });
        assert!(matches!(response, DmDelegateResponseMsg::Ok));
        identity_public(&seed)
    }

    fn device(state: &mut DmDelegateStateV1, identity: DmIdentityId) -> DmDevice {
        let response = state.apply(DmDelegateRequestMsg::CreateDevice {
            identity,
            label: "Laptop".to_string(),
            signing_seed: identity,
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
