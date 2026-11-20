//! Persistent DM state owned by the delegate.
//!
//! The delegate stores the identity seed, device seeds, conversation keys and
//! the local index. Operations are pure so the same state machine is testable
//! without a Freenet runtime.

use ed25519_dalek::{Signer, SigningKey};
use ml_kem::kem::KeyExport;
use ml_kem::{DecapsulationKey, MlKem768, Seed};
use plaza_dm_core::delegate::*;
use plaza_dm_core::{DmContractId, DmDevice, DmDeviceId, DmIdentityId, DmMessageId};
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

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct DmDelegateStateV1 {
    pub version: u32,
    pub identity_seed: Option<[u8; 32]>,
    pub devices: Vec<LocalDevice>,
    pub conversations: Vec<DmConversationInfo>,
    pub keys: Vec<LocalKey>,
    pub blocked: Vec<DmIdentityId>,
}

impl DmDelegateStateV1 {
    pub fn identity_public(&self) -> Option<[u8; 32]> {
        self.identity_seed
            .map(|seed| SigningKey::from_bytes(&seed).verifying_key().to_bytes())
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
            DmDelegateRequestMsg::GetStatus => DmDelegateResponseMsg::Status {
                identity: self.identity_public(),
                devices: self.device_infos(),
                conversations: self.conversations.len(),
                blocked: self.blocked.len(),
            },
            DmDelegateRequestMsg::InitIdentity { identity_seed } => {
                if self
                    .identity_seed
                    .is_some_and(|existing| existing != identity_seed)
                {
                    return DmDelegateResponseMsg::error(
                        "a different DM identity is already initialized",
                    );
                }
                self.identity_seed = Some(identity_seed);
                self.version = self.version.saturating_add(1);
                DmDelegateResponseMsg::Ok
            }
            DmDelegateRequestMsg::CreateDevice {
                label,
                signing_seed,
                kem_seed,
                created_at,
            } => self.create_device(label, signing_seed, kem_seed, created_at),
            DmDelegateRequestMsg::ListDevices => DmDelegateResponseMsg::Devices {
                devices: self.device_infos(),
            },
            DmDelegateRequestMsg::RevokeDevice {
                device_id,
                revoked_at,
            } => self.revoke_device(device_id, revoked_at),
            DmDelegateRequestMsg::SignIdentity { bytes } => self.sign_identity(&bytes),
            DmDelegateRequestMsg::SignDevice { device_id, bytes } => {
                self.sign_device(device_id, &bytes)
            }
            DmDelegateRequestMsg::StoreConversationKey {
                contract_key,
                conversation_id,
                key_version,
                key,
                peer,
                title,
                generation,
                created_at,
            } => self.store_conversation_key(
                contract_key,
                conversation_id,
                key_version,
                key,
                peer,
                title,
                generation,
                created_at,
            ),
            DmDelegateRequestMsg::GetConversationKey {
                contract_key,
                key_version,
            } => self.get_conversation_key(contract_key, key_version),
            DmDelegateRequestMsg::GetLatestConversationKey { contract_key } => {
                self.get_latest_conversation_key(contract_key)
            }
            DmDelegateRequestMsg::ListConversations => DmDelegateResponseMsg::Conversations {
                conversations: self.sorted_conversations(),
            },
            DmDelegateRequestMsg::UpdateRead {
                contract_key,
                last_message,
                unread,
                updated_at,
            } => self.update_read(contract_key, last_message, unread, updated_at),
            DmDelegateRequestMsg::SetDraft {
                contract_key,
                draft,
            } => self.set_draft(contract_key, draft),
            DmDelegateRequestMsg::BlockIdentity { identity, blocked } => {
                self.set_blocked(identity, blocked)
            }
            DmDelegateRequestMsg::ListBlocked => DmDelegateResponseMsg::Blocked {
                identities: self.blocked.clone(),
            },
            DmDelegateRequestMsg::RemoveConversation { contract_key } => {
                self.remove_conversation(contract_key)
            }
            DmDelegateRequestMsg::ExportBackup => self.export_backup(),
            DmDelegateRequestMsg::ImportBackup { bytes } => self.import_backup(&bytes),
        }
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
        self.version = self.version.saturating_add(1);
        DmDelegateResponseMsg::DeviceCreated { device, label }
    }

    fn revoke_device(&mut self, device_id: DmDeviceId, revoked_at: i64) -> DmDelegateResponseMsg {
        let Some(local) = self
            .devices
            .iter_mut()
            .find(|local| local.device.device_id == device_id)
        else {
            return DmDelegateResponseMsg::error("device not found");
        };
        if local.device.revoked_at.is_none() {
            local.device.revoked_at = Some(revoked_at);
            self.version = self.version.saturating_add(1);
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
        let Some(seed) = self.identity_seed else {
            return DmDelegateResponseMsg::error("DM identity is not initialized");
        };
        let signature = SigningKey::from_bytes(&seed).sign(bytes);
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
        self.version = self.version.saturating_add(1);
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
        self.version = self.version.saturating_add(1);
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
        self.version = self.version.saturating_add(1);
        DmDelegateResponseMsg::Ok
    }

    fn set_blocked(&mut self, identity: DmIdentityId, blocked: bool) -> DmDelegateResponseMsg {
        self.blocked.retain(|existing| *existing != identity);
        if blocked {
            self.blocked.push(identity);
            self.blocked.sort_unstable();
        }
        self.version = self.version.saturating_add(1);
        DmDelegateResponseMsg::Ok
    }

    fn remove_conversation(&mut self, contract_key: DmContractId) -> DmDelegateResponseMsg {
        self.conversations
            .retain(|conversation| conversation.contract_key != contract_key);
        self.keys.retain(|key| key.contract_key != contract_key);
        self.version = self.version.saturating_add(1);
        DmDelegateResponseMsg::Ok
    }

    fn export_backup(&self) -> DmDelegateResponseMsg {
        let backup = DmBackupV1 {
            version: DM_DELEGATE_STORAGE_VERSION,
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
        };
        let mut bytes = Vec::new();
        if let Err(error) = ciborium::ser::into_writer(&backup, &mut bytes) {
            return DmDelegateResponseMsg::error(format!("encode backup: {error}"));
        }
        DmDelegateResponseMsg::Backup { bytes }
    }

    fn import_backup(&mut self, bytes: &[u8]) -> DmDelegateResponseMsg {
        let backup: DmBackupV1 = match ciborium::de::from_reader(bytes) {
            Ok(backup) => backup,
            Err(error) => {
                return DmDelegateResponseMsg::error(format!("decode backup: {error}"));
            }
        };
        if backup.version > DM_DELEGATE_STORAGE_VERSION {
            return DmDelegateResponseMsg::error("backup comes from a newer version");
        }
        if let (Some(local), Some(incoming)) = (self.identity_seed, backup.identity_seed) {
            if local != incoming {
                return DmDelegateResponseMsg::error("backup belongs to a different DM identity");
            }
        } else if self.identity_seed.is_none() {
            self.identity_seed = backup.identity_seed;
        }

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
                existing.contract_key == key.contract_key && existing.key_version == key.key_version
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
        self.version = self.version.saturating_add(1);
        DmDelegateResponseMsg::Ok
    }
}

fn ml_kem_encapsulation_key(seed: &[u8; 64]) -> Vec<u8> {
    let decapsulation = DecapsulationKey::<MlKem768>::from_seed(Seed::from(*seed));
    decapsulation.encapsulation_key().to_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Verifier, VerifyingKey};

    fn identity_seed() -> [u8; 32] {
        [11u8; 32]
    }

    fn device_seeds() -> ([u8; 32], Vec<u8>) {
        ([22u8; 32], vec![33u8; 64])
    }

    fn initialized() -> DmDelegateStateV1 {
        let mut state = DmDelegateStateV1::default();
        assert!(matches!(
            state.apply(DmDelegateRequestMsg::InitIdentity {
                identity_seed: identity_seed()
            }),
            DmDelegateResponseMsg::Ok
        ));
        state
    }

    #[test]
    fn identity_and_devices_are_stored() {
        let mut state = initialized();
        let (signing_seed, kem_seed) = device_seeds();
        let response = state.apply(DmDelegateRequestMsg::CreateDevice {
            label: "Laptop".to_string(),
            signing_seed,
            kem_seed,
            created_at: 1_000,
        });
        let DmDelegateResponseMsg::DeviceCreated { device, .. } = response else {
            panic!("device not created: {response:?}");
        };
        assert_eq!(device.signing_key, device.device_id);
        assert_eq!(device.kem_ek.len(), 1184);

        let public = state.identity_public().unwrap();
        assert_eq!(
            public,
            SigningKey::from_bytes(&identity_seed())
                .verifying_key()
                .to_bytes()
        );
        let status = state.apply(DmDelegateRequestMsg::GetStatus);
        let DmDelegateResponseMsg::Status { devices, .. } = status else {
            panic!("status missing");
        };
        assert_eq!(devices.len(), 1);
    }

    #[test]
    fn the_delegate_signs_with_identity_and_device() {
        let mut state = initialized();
        let (signing_seed, kem_seed) = device_seeds();
        let response = state.apply(DmDelegateRequestMsg::CreateDevice {
            label: "Laptop".to_string(),
            signing_seed,
            kem_seed,
            created_at: 1_000,
        });
        let DmDelegateResponseMsg::DeviceCreated { device, .. } = response else {
            panic!("device not created");
        };
        let payload = b"hello dm";

        let identity_signature = state.apply(DmDelegateRequestMsg::SignIdentity {
            bytes: payload.to_vec(),
        });
        let DmDelegateResponseMsg::Signature { signature } = identity_signature else {
            panic!("identity signature missing");
        };
        VerifyingKey::from_bytes(&state.identity_public().unwrap())
            .unwrap()
            .verify(payload, &signature)
            .unwrap();

        let device_signature = state.apply(DmDelegateRequestMsg::SignDevice {
            device_id: device.device_id,
            bytes: payload.to_vec(),
        });
        let DmDelegateResponseMsg::Signature { signature } = device_signature else {
            panic!("device signature missing");
        };
        VerifyingKey::from_bytes(&device.signing_key)
            .unwrap()
            .verify(payload, &signature)
            .unwrap();
    }

    #[test]
    fn conversation_keys_and_index_are_persistent() {
        let mut state = initialized();
        let response = state.apply(DmDelegateRequestMsg::StoreConversationKey {
            contract_key: [1u8; 32],
            conversation_id: [2u8; 32],
            key_version: 0,
            key: [9u8; 32],
            peer: [3u8; 32],
            title: Some("Alice".to_string()),
            generation: 0,
            created_at: 1_000,
        });
        assert!(matches!(response, DmDelegateResponseMsg::Ok));

        let response = state.apply(DmDelegateRequestMsg::GetConversationKey {
            contract_key: [1u8; 32],
            key_version: 0,
        });
        let DmDelegateResponseMsg::ConversationKey { key, .. } = response else {
            panic!("key missing");
        };
        assert_eq!(key, Some([9u8; 32]));

        let response = state.apply(DmDelegateRequestMsg::UpdateRead {
            contract_key: [1u8; 32],
            last_message: [4u8; 32],
            unread: 0,
            updated_at: 1_100,
        });
        assert!(matches!(response, DmDelegateResponseMsg::Ok));
        let response = state.apply(DmDelegateRequestMsg::SetDraft {
            contract_key: [1u8; 32],
            draft: Some("draft".to_string()),
        });
        assert!(matches!(response, DmDelegateResponseMsg::Ok));

        let response = state.apply(DmDelegateRequestMsg::ListConversations);
        let DmDelegateResponseMsg::Conversations { conversations } = response else {
            panic!("conversations missing");
        };
        assert_eq!(conversations.len(), 1);
        assert_eq!(conversations[0].unread, 0);
        assert_eq!(conversations[0].draft.as_deref(), Some("draft"));
    }

    #[test]
    fn revoked_devices_cannot_sign() {
        let mut state = initialized();
        let (signing_seed, kem_seed) = device_seeds();
        let response = state.apply(DmDelegateRequestMsg::CreateDevice {
            label: "Laptop".to_string(),
            signing_seed,
            kem_seed,
            created_at: 1_000,
        });
        let DmDelegateResponseMsg::DeviceCreated { device, .. } = response else {
            panic!("device not created");
        };
        let response = state.apply(DmDelegateRequestMsg::RevokeDevice {
            device_id: device.device_id,
            revoked_at: 1_100,
        });
        assert!(matches!(response, DmDelegateResponseMsg::Ok));
        let response = state.apply(DmDelegateRequestMsg::SignDevice {
            device_id: device.device_id,
            bytes: b"after revoke".to_vec(),
        });
        assert!(matches!(response, DmDelegateResponseMsg::Error { .. }));
    }

    #[test]
    fn backup_round_trip_restores_identity_devices_and_keys() {
        let mut state = initialized();
        let (signing_seed, kem_seed) = device_seeds();
        state.apply(DmDelegateRequestMsg::CreateDevice {
            label: "Laptop".to_string(),
            signing_seed,
            kem_seed,
            created_at: 1_000,
        });
        state.apply(DmDelegateRequestMsg::StoreConversationKey {
            contract_key: [1u8; 32],
            conversation_id: [2u8; 32],
            key_version: 0,
            key: [9u8; 32],
            peer: [3u8; 32],
            title: None,
            generation: 0,
            created_at: 1_000,
        });
        state.apply(DmDelegateRequestMsg::BlockIdentity {
            identity: [5u8; 32],
            blocked: true,
        });

        let response = state.apply(DmDelegateRequestMsg::ExportBackup);
        let DmDelegateResponseMsg::Backup { bytes } = response else {
            panic!("backup missing");
        };
        let mut restored = DmDelegateStateV1::default();
        let response = restored.apply(DmDelegateRequestMsg::ImportBackup { bytes });
        assert!(matches!(response, DmDelegateResponseMsg::Ok));
        assert_eq!(restored.identity_public(), state.identity_public());
        assert_eq!(restored.devices.len(), 1);
        assert_eq!(restored.keys.len(), 1);
        assert_eq!(restored.conversations.len(), 1);
        assert_eq!(restored.blocked, vec![[5u8; 32]]);
    }

    #[test]
    fn importing_a_different_identity_is_rejected() {
        let mut state = initialized();
        let mut other = DmDelegateStateV1::default();
        other.apply(DmDelegateRequestMsg::InitIdentity {
            identity_seed: [99u8; 32],
        });
        let response = other.apply(DmDelegateRequestMsg::ExportBackup);
        let DmDelegateResponseMsg::Backup { bytes } = response else {
            panic!("backup missing");
        };
        let response = state.apply(DmDelegateRequestMsg::ImportBackup { bytes });
        assert!(matches!(response, DmDelegateResponseMsg::Error { .. }));
    }

    #[test]
    fn a_different_key_for_the_same_version_is_rejected() {
        let mut state = initialized();
        state.apply(DmDelegateRequestMsg::StoreConversationKey {
            contract_key: [1u8; 32],
            conversation_id: [2u8; 32],
            key_version: 0,
            key: [9u8; 32],
            peer: [3u8; 32],
            title: None,
            generation: 0,
            created_at: 1_000,
        });
        let response = state.apply(DmDelegateRequestMsg::StoreConversationKey {
            contract_key: [1u8; 32],
            conversation_id: [2u8; 32],
            key_version: 0,
            key: [8u8; 32],
            peer: [3u8; 32],
            title: None,
            generation: 0,
            created_at: 1_000,
        });
        assert!(matches!(response, DmDelegateResponseMsg::Error { .. }));
    }
}
