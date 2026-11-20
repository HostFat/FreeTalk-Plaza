//! Request/response types shared by the DM delegate and the client.
//!
//! The delegate owns the private seeds: per-profile identities, per-device
//! signing/encapsulation seeds and per-conversation keys. The client sends
//! public device records and asks the delegate to sign bytes; private seeds
//! never leave the delegate.

use crate::{
    DmContractId, DmDevice, DmDeviceId, DmIdentityId, DmMessageId,
};
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};

pub const DM_DELEGATE_STORAGE_VERSION: u16 = 2;

/// Wire envelope for correlation. The delegate echoes the id in the response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DmDelegateEnvelope {
    pub request_id: u64,
    pub request: DmDelegateRequestMsg,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DmDelegateResponseEnvelope {
    pub request_id: u64,
    pub response: DmDelegateResponseMsg,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DmDelegateRequestMsg {
    GetStatus {
        identity: DmIdentityId,
    },
    /// Clear one identity, or every identity when `identity` is `None`.
    Reset {
        identity: Option<DmIdentityId>,
    },
    /// Store the 32-byte seed of the identity key derived from the profile.
    /// The same seed is idempotent; a different profile adds a new map entry.
    InitIdentity {
        identity_seed: [u8; 32],
    },
    /// The client generates the seeds; the delegate derives the public device
    /// record and keeps the private material.
    CreateDevice {
        identity: DmIdentityId,
        label: String,
        signing_seed: [u8; 32],
        /// 64-byte ML-KEM seed as bytes; serde has no array impl for 64.
        kem_seed: Vec<u8>,
        created_at: i64,
    },
    ListDevices {
        identity: DmIdentityId,
    },
    RevokeDevice {
        identity: DmIdentityId,
        device_id: DmDeviceId,
        revoked_at: i64,
    },
    SignIdentity {
        identity: DmIdentityId,
        bytes: Vec<u8>,
    },
    SignDevice {
        identity: DmIdentityId,
        device_id: DmDeviceId,
        bytes: Vec<u8>,
    },
    StoreConversationKey {
        identity: DmIdentityId,
        contract_key: DmContractId,
        conversation_id: [u8; 32],
        key_version: u32,
        key: [u8; 32],
        peer: DmIdentityId,
        title: Option<String>,
        generation: u32,
        created_at: i64,
    },
    GetConversationKey {
        identity: DmIdentityId,
        contract_key: DmContractId,
        key_version: u32,
    },
    GetLatestConversationKey {
        identity: DmIdentityId,
        contract_key: DmContractId,
    },
    ListConversations {
        identity: DmIdentityId,
    },
    UpdateRead {
        identity: DmIdentityId,
        contract_key: DmContractId,
        last_message: DmMessageId,
        unread: u32,
        updated_at: i64,
    },
    SetDraft {
        identity: DmIdentityId,
        contract_key: DmContractId,
        draft: Option<String>,
    },
    BlockIdentity {
        identity: DmIdentityId,
        target: DmIdentityId,
        blocked: bool,
    },
    ListBlocked {
        identity: DmIdentityId,
    },
    RemoveConversation {
        identity: DmIdentityId,
        contract_key: DmContractId,
    },
    ExportBackup,
    ImportBackup {
        bytes: Vec<u8>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DmDeviceInfo {
    pub device: DmDevice,
    pub label: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DmConversationInfo {
    pub contract_key: DmContractId,
    pub conversation_id: [u8; 32],
    pub peer: DmIdentityId,
    pub title: Option<String>,
    pub generation: u32,
    pub last_message_at: i64,
    pub last_message_id: Option<DmMessageId>,
    pub unread: u32,
    pub key_versions: Vec<u32>,
    pub draft: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DmDeviceBackup {
    pub device: DmDevice,
    pub label: String,
    pub signing_seed: [u8; 32],
    pub kem_seed: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DmKeyBackup {
    pub contract_key: DmContractId,
    pub key_version: u32,
    pub key: [u8; 32],
    pub created_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DmIdentityBackup {
    pub identity_seed: [u8; 32],
    pub devices: Vec<DmDeviceBackup>,
    pub conversations: Vec<DmConversationInfo>,
    pub keys: Vec<DmKeyBackup>,
    pub blocked: Vec<DmIdentityId>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct DmBackupV1 {
    pub version: u16,
    pub identities: Vec<DmIdentityBackup>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DmDelegateResponseMsg {
    Status {
        identity: DmIdentityId,
        devices: Vec<DmDeviceInfo>,
        conversations: usize,
        blocked: usize,
    },
    DeviceCreated {
        device: DmDevice,
        label: String,
    },
    Devices {
        devices: Vec<DmDeviceInfo>,
    },
    Signature {
        signature: Signature,
    },
    ConversationKey {
        key: Option<[u8; 32]>,
        key_version: Option<u32>,
    },
    Conversations {
        conversations: Vec<DmConversationInfo>,
    },
    Blocked {
        identities: Vec<DmIdentityId>,
    },
    Backup {
        bytes: Vec<u8>,
    },
    Ok,
    Error {
        message: String,
    },
}

impl DmDelegateResponseMsg {
    pub fn error(message: impl Into<String>) -> Self {
        Self::Error {
            message: message.into(),
        }
    }
}
