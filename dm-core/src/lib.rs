//! Skeleton of the `plaza-dm` conversation contract.
//!
//! The types and validation here are the contract boundary: state, deltas,
//! membership, invites, sealed keys, messages, read state and generations.
//! Encryption and delegate storage live outside this crate; this layer only
//! verifies signatures, authorization, sizes and monotonic versions.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_MEMBERS: usize = 2;
pub const MAX_DEVICES_PER_MEMBER: usize = 8;
pub const MAX_INVITES: usize = 8;
pub const MAX_MESSAGES: usize = 500;
pub const MAX_MESSAGE_BYTES: usize = 8192;
pub const MAX_KEY_CIPHERTEXT_BYTES: usize = 4096;
pub const MAX_KEM_EK_BYTES: usize = 2048;
pub const MAX_STATE_BYTES: usize = 1_048_576;
pub const MAX_NAME_BYTES: usize = 256;

pub const CONTENT_TYPE_TEXT: u16 = 1;
pub const CONTENT_TYPE_SYSTEM: u16 = 2;
pub const CONTENT_TYPE_ATTACHMENT: u16 = 3;

pub const KEY_SUITE_X25519_MLKEM768_XCHACHA20: u16 = 1;

pub type DmIdentityId = [u8; 32];
pub type DmDeviceId = [u8; 32];
pub type DmMessageId = [u8; 32];
pub type DmContractId = [u8; 32];

fn zero_signature() -> Signature {
    Signature::from_bytes(&[0u8; 64])
}

fn sign_value<T: Serialize>(value: &T, signing_key: &SigningKey) -> Signature {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes).expect("serialization should not fail");
    signing_key.sign(&bytes)
}

fn verify_value<T: Serialize>(
    value: &T,
    signature: &Signature,
    verifying_key: &VerifyingKey,
) -> Result<(), String> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes)
        .map_err(|error| format!("serialization failed: {error}"))?;
    verifying_key
        .verify(&bytes, signature)
        .map_err(|error| format!("invalid signature: {error}"))
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    ciborium::de::from_reader(bytes).map_err(|error| format!("decode failed: {error}"))
}

pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes)
        .map_err(|error| format!("encode failed: {error}"))?;
    Ok(bytes)
}

pub fn decode_state(bytes: &[u8]) -> Result<DmStateV1, String> {
    decode(bytes)
}

pub fn decode_params(bytes: &[u8]) -> Result<DmParamsV1, String> {
    decode(bytes)
}

pub fn decode_delta(bytes: &[u8]) -> Result<DmStateDeltaV1, String> {
    decode(bytes)
}

pub fn decode_summary(bytes: &[u8]) -> Result<DmStateSummaryV1, String> {
    decode(bytes)
}

pub fn vk_from_bytes(bytes: &[u8; 32]) -> Result<VerifyingKey, String> {
    VerifyingKey::from_bytes(bytes).map_err(|error| format!("invalid verifying key: {error}"))
}

pub fn identity_id(signing_key: &SigningKey) -> DmIdentityId {
    signing_key.verifying_key().to_bytes()
}

pub fn device_id(signing_key: &SigningKey) -> DmDeviceId {
    signing_key.verifying_key().to_bytes()
}

pub fn token_hash(token: &[u8; 32]) -> [u8; 32] {
    *blake3::hash(token).as_bytes()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DmParamsV1 {
    pub protocol_version: u16,
    pub contract_secret: [u8; 32],
}

impl Default for DmParamsV1 {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            contract_secret: [0u8; 32],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DmRole {
    Creator,
    Member,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DmMetaV1 {
    pub conversation_id: [u8; 32],
    pub created_at: i64,
    /// Monotonic state version. Every accepted update increases it.
    pub state_version: u32,
    /// Optional conversation name, already sealed by the client.
    pub name: Option<Vec<u8>>,
}

impl Default for DmMetaV1 {
    fn default() -> Self {
        Self {
            conversation_id: [0u8; 32],
            created_at: 0,
            state_version: 0,
            name: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DmDevice {
    pub device_id: DmDeviceId,
    pub signing_key: [u8; 32],
    pub kem_ek: Vec<u8>,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthorizedDmDevice {
    pub device: DmDevice,
    pub signature: Signature,
}

impl AuthorizedDmDevice {
    pub fn new(device: DmDevice, identity_signing_key: &SigningKey) -> Self {
        let signature = sign_value(&device, identity_signing_key);
        Self { device, signature }
    }

    pub fn verify_with_identity(&self, identity: &DmIdentityId) -> Result<(), String> {
        if self.device.device_id != self.device.signing_key {
            return Err("device id does not match its signing key".to_string());
        }
        verify_value(&self.device, &self.signature, &vk_from_bytes(identity)?)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DmMember {
    pub identity: DmIdentityId,
    pub version: u32,
    pub role: DmRole,
    pub joined_at: i64,
    pub devices: Vec<AuthorizedDmDevice>,
    pub left_at: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthorizedDmMember {
    pub member: DmMember,
    pub signature: Signature,
}

impl AuthorizedDmMember {
    pub fn new(member: DmMember, identity_signing_key: &SigningKey) -> Self {
        let signature = sign_value(&member, identity_signing_key);
        Self { member, signature }
    }

    pub fn verify(&self) -> Result<(), String> {
        verify_value(
            &self.member,
            &self.signature,
            &vk_from_bytes(&self.member.identity)?,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct DmMembersV1 {
    pub members: Vec<AuthorizedDmMember>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DmInvite {
    pub invite_id: [u8; 32],
    pub created_by: DmIdentityId,
    pub token_hash: [u8; 32],
    pub created_at: i64,
    pub expires_at: i64,
    pub used_at: Option<i64>,
    pub used_by: Option<DmIdentityId>,
    pub bound_identity: Option<DmIdentityId>,
    pub signature: Signature,
}

impl DmInvite {
    pub fn new(
        invite_id: [u8; 32],
        created_by: &SigningKey,
        token: &[u8; 32],
        created_at: i64,
        expires_at: i64,
        bound_identity: Option<DmIdentityId>,
    ) -> Self {
        let mut invite = Self {
            invite_id,
            created_by: identity_id(created_by),
            token_hash: token_hash(token),
            created_at,
            expires_at,
            used_at: None,
            used_by: None,
            bound_identity,
            signature: zero_signature(),
        };
        invite.signature = sign_value(&unsigned_invite(&invite), created_by);
        invite
    }

    pub fn verify(&self, creator: &DmIdentityId) -> Result<(), String> {
        if self.token_hash == [0u8; 32] {
            return Err("empty invite token hash".to_string());
        }
        if self.expires_at <= self.created_at {
            return Err("invite does not expire after creation".to_string());
        }
        verify_value(
            &unsigned_invite(self),
            &self.signature,
            &vk_from_bytes(creator)?,
        )
    }

    /// Mark the invite as used and re-sign it with the creator's key. The
    /// first accepted use wins; clients merge older records only while
    /// `used_at` is still empty.
    pub fn mark_used(
        &mut self,
        used_by: DmIdentityId,
        used_at: i64,
        creator_signing_key: &SigningKey,
    ) {
        self.used_at = Some(used_at);
        self.used_by = Some(used_by);
        self.signature = sign_value(&unsigned_invite(self), creator_signing_key);
    }
}

fn unsigned_invite(invite: &DmInvite) -> DmInvite {
    let mut copy = invite.clone();
    copy.signature = zero_signature();
    copy
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct DmInvitesV1 {
    pub invites: Vec<DmInvite>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SealedDmKey {
    pub key_version: u32,
    pub member: DmIdentityId,
    pub device: DmDeviceId,
    pub suite: u16,
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 24],
    pub sealed_at: i64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthorizedSealedDmKey {
    pub record: SealedDmKey,
    pub signer: DmDeviceId,
    pub signature: Signature,
}

impl AuthorizedSealedDmKey {
    pub fn new(record: SealedDmKey, signer: &SigningKey) -> Self {
        let signature = sign_value(&record, signer);
        Self {
            record,
            signer: device_id(signer),
            signature,
        }
    }

    pub fn verify(&self, signer_vk: &VerifyingKey) -> Result<(), String> {
        if self.signer != signer_vk.to_bytes() {
            return Err("sealed key signer does not match".to_string());
        }
        verify_value(&self.record, &self.signature, signer_vk)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct DmKeysV1 {
    pub keys: Vec<AuthorizedSealedDmKey>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DmMessage {
    pub id: DmMessageId,
    pub author: DmIdentityId,
    pub device: DmDeviceId,
    pub key_version: u32,
    pub created_at: i64,
    pub content_type: u16,
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 24],
    pub reply_to: Option<DmMessageId>,
    pub declared_len: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthorizedDmMessage {
    pub message: DmMessage,
    pub signature: Signature,
}

impl AuthorizedDmMessage {
    pub fn new(mut message: DmMessage, device_signing_key: &SigningKey) -> Self {
        if message.device != device_id(device_signing_key) {
            // Keep the constructor honest even in tests.
            message.device = device_id(device_signing_key);
        }
        message.id = [0u8; 32];
        let signature = sign_value(&message, device_signing_key);
        message.id = *blake3::hash(&signature.to_bytes()).as_bytes();
        Self { message, signature }
    }

    fn unsigned(&self) -> DmMessage {
        let mut copy = self.message.clone();
        copy.id = [0u8; 32];
        copy
    }

    pub fn verify(&self, device_vk: &VerifyingKey) -> Result<(), String> {
        if self.message.id != *blake3::hash(&self.signature.to_bytes()).as_bytes() {
            return Err("message id does not match its signature".to_string());
        }
        if self.message.device != device_vk.to_bytes() {
            return Err("message device does not match the signing key".to_string());
        }
        verify_value(&self.unsigned(), &self.signature, device_vk)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct DmMessagesV1 {
    pub messages: Vec<AuthorizedDmMessage>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DmReadEntry {
    pub member: DmIdentityId,
    pub device: DmDeviceId,
    pub last_message: DmMessageId,
    pub version: u32,
    pub updated_at: i64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthorizedDmRead {
    pub entry: DmReadEntry,
    pub signature: Signature,
}

impl AuthorizedDmRead {
    pub fn new(entry: DmReadEntry, device_signing_key: &SigningKey) -> Self {
        let signature = sign_value(&entry, device_signing_key);
        Self { entry, signature }
    }

    pub fn verify(&self, device_vk: &VerifyingKey) -> Result<(), String> {
        verify_value(&self.entry, &self.signature, device_vk)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct DmReadV1 {
    pub entries: Vec<AuthorizedDmRead>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DmGenerationV1 {
    pub generation: u32,
    pub previous_contract: Option<DmContractId>,
    pub next_contract: Option<DmContractId>,
    pub closed_at: Option<i64>,
    pub signer: DmDeviceId,
    pub signature: Signature,
}

impl Default for DmGenerationV1 {
    fn default() -> Self {
        Self {
            generation: 0,
            previous_contract: None,
            next_contract: None,
            closed_at: None,
            signer: [0u8; 32],
            signature: zero_signature(),
        }
    }
}

impl DmGenerationV1 {
    pub fn new(
        generation: u32,
        previous_contract: Option<DmContractId>,
        next_contract: Option<DmContractId>,
        closed_at: Option<i64>,
        signer: &SigningKey,
    ) -> Self {
        let mut value = Self {
            generation,
            previous_contract,
            next_contract,
            closed_at,
            signer: device_id(signer),
            signature: zero_signature(),
        };
        value.signature = sign_value(&unsigned_generation(&value), signer);
        value
    }

    pub fn verify(&self, signer_vk: &VerifyingKey) -> Result<(), String> {
        if self.signer != signer_vk.to_bytes() {
            return Err("generation signer does not match".to_string());
        }
        verify_value(&unsigned_generation(self), &self.signature, signer_vk)
    }
}

fn unsigned_generation(value: &DmGenerationV1) -> DmGenerationV1 {
    let mut copy = value.clone();
    copy.signature = zero_signature();
    copy
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DmStateV1 {
    pub meta: DmMetaV1,
    pub members: DmMembersV1,
    pub invites: DmInvitesV1,
    pub keys: DmKeysV1,
    pub messages: DmMessagesV1,
    pub read: DmReadV1,
    pub generation: DmGenerationV1,
}

impl Default for DmStateV1 {
    fn default() -> Self {
        Self {
            meta: DmMetaV1::default(),
            members: DmMembersV1::default(),
            invites: DmInvitesV1::default(),
            keys: DmKeysV1::default(),
            messages: DmMessagesV1::default(),
            read: DmReadV1::default(),
            generation: DmGenerationV1::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct DmStateDeltaV1 {
    pub meta: Option<DmMetaV1>,
    pub members: Option<Vec<AuthorizedDmMember>>,
    pub invites: Option<Vec<DmInvite>>,
    pub keys: Option<Vec<AuthorizedSealedDmKey>>,
    pub messages: Option<Vec<AuthorizedDmMessage>>,
    pub read: Option<Vec<AuthorizedDmRead>>,
    pub generation: Option<DmGenerationV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DmStateSummaryV1 {
    pub state_version: u32,
}

impl DmStateV1 {
    pub fn new(
        conversation_id: [u8; 32],
        identity: &SigningKey,
        device: &SigningKey,
        kem_ek: Vec<u8>,
        now: i64,
    ) -> Self {
        let identity_id = identity_id(identity);
        let device = DmDevice {
            device_id: device_id(device),
            signing_key: device.verifying_key().to_bytes(),
            kem_ek,
            created_at: now,
            revoked_at: None,
        };
        let member = DmMember {
            identity: identity_id,
            version: 0,
            role: DmRole::Creator,
            joined_at: now,
            devices: vec![AuthorizedDmDevice::new(device, identity)],
            left_at: None,
        };
        Self {
            meta: DmMetaV1 {
                conversation_id,
                created_at: now,
                state_version: 1,
                name: None,
            },
            members: DmMembersV1 {
                members: vec![AuthorizedDmMember::new(member, identity)],
            },
            invites: DmInvitesV1::default(),
            keys: DmKeysV1::default(),
            messages: DmMessagesV1::default(),
            read: DmReadV1::default(),
            generation: DmGenerationV1::default(),
        }
    }

    pub fn member(&self, identity: &DmIdentityId) -> Option<&DmMember> {
        self.members
            .members
            .iter()
            .find(|member| &member.member.identity == identity)
            .map(|member| &member.member)
    }

    pub fn device(&self, member: &DmIdentityId, device: &DmDeviceId) -> Option<&DmDevice> {
        self.member(member)?
            .devices
            .iter()
            .find(|authorized| &authorized.device.device_id == device)
            .map(|authorized| &authorized.device)
    }

    pub fn device_vk(
        &self,
        member: &DmIdentityId,
        device: &DmDeviceId,
        at: i64,
    ) -> Result<VerifyingKey, String> {
        let member = self
            .member(member)
            .ok_or_else(|| "member not found".to_string())?;
        if member.left_at.is_some_and(|left| left <= at) {
            return Err("member had already left".to_string());
        }
        let device = member
            .devices
            .iter()
            .find(|authorized| &authorized.device.device_id == device)
            .ok_or_else(|| "device not found".to_string())?;
        if device.device.created_at > at {
            return Err("device did not exist yet".to_string());
        }
        if device
            .device
            .revoked_at
            .is_some_and(|revoked| revoked <= at)
        {
            return Err("device was already revoked".to_string());
        }
        vk_from_bytes(&device.device.signing_key)
    }

    /// Any member's device can sign a key-sealing record or a generation
    /// pointer. Find the owning member first, then apply the same time rules.
    pub fn device_vk_any(&self, device: &DmDeviceId, at: i64) -> Result<VerifyingKey, String> {
        for authorized in &self.members.members {
            if authorized
                .member
                .devices
                .iter()
                .any(|candidate| &candidate.device.device_id == device)
            {
                return self.device_vk(&authorized.member.identity, device, at);
            }
        }
        Err("device not found".to_string())
    }

    pub fn verify(&self, params: &DmParamsV1) -> Result<(), String> {
        if params.protocol_version != PROTOCOL_VERSION {
            return Err("unsupported protocol version".to_string());
        }
        if let Some(name) = &self.meta.name {
            if name.len() > MAX_NAME_BYTES {
                return Err("conversation name is too large".to_string());
            }
        }
        self.verify_members()?;
        self.verify_invites()?;
        self.verify_keys()?;
        self.verify_messages()?;
        self.verify_read()?;
        self.verify_generation()?;
        Ok(())
    }

    fn verify_members(&self) -> Result<(), String> {
        if self.members.members.is_empty() {
            return Err("conversation has no members".to_string());
        }
        if self.members.members.len() > MAX_MEMBERS {
            return Err("too many members".to_string());
        }
        let mut identities = HashSet::new();
        let mut creators = 0usize;
        for authorized in &self.members.members {
            authorized.verify()?;
            let member = &authorized.member;
            if !identities.insert(member.identity) {
                return Err("duplicate member identity".to_string());
            }
            if matches!(member.role, DmRole::Creator) {
                creators += 1;
            }
            if member.devices.len() > MAX_DEVICES_PER_MEMBER {
                return Err("too many devices for a member".to_string());
            }
            let mut devices = HashSet::new();
            for device in &member.devices {
                if !devices.insert(device.device.device_id) {
                    return Err("duplicate device id".to_string());
                }
                device.verify_with_identity(&member.identity)?;
                if device.device.kem_ek.len() > MAX_KEM_EK_BYTES {
                    return Err("device kem key is too large".to_string());
                }
            }
        }
        if creators != 1 {
            return Err("conversation must have exactly one creator".to_string());
        }
        Ok(())
    }

    fn verify_invites(&self) -> Result<(), String> {
        if self.invites.invites.len() > MAX_INVITES {
            return Err("too many invites".to_string());
        }
        let mut ids = HashSet::new();
        for invite in &self.invites.invites {
            if !ids.insert(invite.invite_id) {
                return Err("duplicate invite id".to_string());
            }
            let creator = self
                .member(&invite.created_by)
                .ok_or_else(|| "invite creator is not a member".to_string())?;
            invite.verify(&creator.identity)?;
            if invite.used_at.is_some() && invite.used_by.is_none() {
                return Err("used invite has no user".to_string());
            }
            if let Some(used_by) = invite.used_by {
                if self.member(&used_by).is_none() {
                    return Err("invite was used by a non-member".to_string());
                }
            }
        }
        Ok(())
    }

    fn verify_keys(&self) -> Result<(), String> {
        let mut seen = HashSet::new();
        for authorized in &self.keys.keys {
            let record = &authorized.record;
            if record.suite != KEY_SUITE_X25519_MLKEM768_XCHACHA20 {
                return Err("unsupported key suite".to_string());
            }
            if record.ciphertext.len() > MAX_KEY_CIPHERTEXT_BYTES {
                return Err("sealed key is too large".to_string());
            }
            let signer_vk = self.device_vk_any(&authorized.signer, record.sealed_at)?;
            authorized.verify(&signer_vk)?;
            if self.device(&record.member, &record.device).is_none() {
                return Err("sealed key targets a missing device".to_string());
            }
            if !seen.insert((record.key_version, record.member, record.device)) {
                return Err("duplicate sealed key".to_string());
            }
        }
        Ok(())
    }

    fn verify_messages(&self) -> Result<(), String> {
        if self.messages.messages.len() > MAX_MESSAGES {
            return Err("message cap reached".to_string());
        }
        let ids: HashSet<_> = self
            .messages
            .messages
            .iter()
            .map(|message| message.message.id)
            .collect();
        if ids.len() != self.messages.messages.len() {
            return Err("duplicate message id".to_string());
        }
        for authorized in &self.messages.messages {
            let message = &authorized.message;
            if message.declared_len as usize > MAX_MESSAGE_BYTES
                || message.ciphertext.len() > MAX_MESSAGE_BYTES
            {
                return Err("message is too large".to_string());
            }
            if !(CONTENT_TYPE_TEXT..=CONTENT_TYPE_ATTACHMENT).contains(&message.content_type) {
                return Err("unsupported message content type".to_string());
            }
            if let Some(reply) = message.reply_to {
                if !ids.contains(&reply) {
                    return Err("reply target is not in this conversation".to_string());
                }
            }
            let vk = self.device_vk(&message.author, &message.device, message.created_at)?;
            authorized.verify(&vk)?;
        }
        Ok(())
    }

    fn verify_read(&self) -> Result<(), String> {
        let messages: HashSet<_> = self
            .messages
            .messages
            .iter()
            .map(|message| message.message.id)
            .collect();
        for authorized in &self.read.entries {
            let entry = &authorized.entry;
            let vk = self.device_vk(&entry.member, &entry.device, entry.updated_at)?;
            authorized.verify(&vk)?;
            if entry.last_message != [0u8; 32] && !messages.contains(&entry.last_message) {
                return Err("read state points to an unknown message".to_string());
            }
        }
        Ok(())
    }

    fn verify_generation(&self) -> Result<(), String> {
        let generation = &self.generation;
        if generation.generation == 0 && generation.signature == zero_signature() {
            return Ok(());
        }
        let at = generation.closed_at.unwrap_or(i64::MAX);
        let vk = self.device_vk_any(&generation.signer, at)?;
        generation.verify(&vk)
    }

    pub fn summarize(&self) -> DmStateSummaryV1 {
        DmStateSummaryV1 {
            state_version: self.meta.state_version,
        }
    }

    pub fn full_delta(&self, state_version: u32) -> DmStateDeltaV1 {
        DmStateDeltaV1 {
            meta: Some(DmMetaV1 {
                state_version,
                ..self.meta.clone()
            }),
            members: Some(self.members.members.clone()),
            invites: Some(self.invites.invites.clone()),
            keys: Some(self.keys.keys.clone()),
            messages: Some(self.messages.messages.clone()),
            read: Some(self.read.entries.clone()),
            generation: Some(self.generation.clone()),
        }
    }

    pub fn delta(&self, summary: &DmStateSummaryV1) -> Option<DmStateDeltaV1> {
        if summary.state_version >= self.meta.state_version {
            None
        } else {
            Some(self.full_delta(self.meta.state_version))
        }
    }

    pub fn apply_delta(
        &mut self,
        params: &DmParamsV1,
        delta: &DmStateDeltaV1,
    ) -> Result<(), String> {
        if let Some(meta) = &delta.meta {
            if meta.conversation_id != self.meta.conversation_id {
                return Err("conversation id mismatch".to_string());
            }
            if meta.state_version <= self.meta.state_version {
                return Err("state version must increase".to_string());
            }
        }

        let mut next = self.clone();
        if let Some(meta) = &delta.meta {
            next.meta = meta.clone();
        } else {
            next.meta.state_version = next.meta.state_version.saturating_add(1);
        }
        if let Some(members) = &delta.members {
            next.merge_members(members)?;
        }
        if let Some(invites) = &delta.invites {
            next.merge_invites(invites)?;
        }
        if let Some(keys) = &delta.keys {
            next.merge_keys(keys)?;
        }
        if let Some(messages) = &delta.messages {
            next.merge_messages(messages)?;
        }
        if let Some(read) = &delta.read {
            next.merge_read(read)?;
        }
        if let Some(generation) = &delta.generation {
            next.merge_generation(generation)?;
        }
        next.verify(params)?;
        *self = next;
        Ok(())
    }

    pub fn merge(&mut self, params: &DmParamsV1, other: &DmStateV1) -> Result<(), String> {
        if other.meta.conversation_id != self.meta.conversation_id {
            return Err("conversation id mismatch".to_string());
        }
        let version = self.meta.state_version.max(other.meta.state_version) + 1;
        let delta = other.full_delta(version);
        self.apply_delta(params, &delta)
    }

    fn merge_members(&mut self, incoming: &[AuthorizedDmMember]) -> Result<(), String> {
        for authorized in incoming {
            authorized.verify()?;
            let identity = authorized.member.identity;
            if let Some(existing) = self
                .members
                .members
                .iter_mut()
                .find(|existing| existing.member.identity == identity)
            {
                if authorized.member.version > existing.member.version {
                    *existing = authorized.clone();
                } else if authorized.member.version == existing.member.version
                    && authorized.member != existing.member
                {
                    return Err("conflicting member versions".to_string());
                }
            } else {
                self.members.members.push(authorized.clone());
            }
        }
        self.members
            .members
            .sort_by_key(|member| member.member.identity);
        Ok(())
    }

    fn merge_invites(&mut self, incoming: &[DmInvite]) -> Result<(), String> {
        for invite in incoming {
            let creator = self
                .member(&invite.created_by)
                .ok_or_else(|| "invite creator is not a member".to_string())?;
            invite.verify(&creator.identity)?;
            if let Some(existing) = self
                .invites
                .invites
                .iter_mut()
                .find(|existing| existing.invite_id == invite.invite_id)
            {
                if existing.used_at.is_some() {
                    continue;
                }
                let mut merged = invite.clone();
                merged.used_at = existing.used_at.or(invite.used_at);
                merged.used_by = existing.used_by.or(invite.used_by);
                *existing = merged;
            } else {
                self.invites.invites.push(invite.clone());
            }
        }
        self.invites.invites.sort_by_key(|invite| invite.invite_id);
        Ok(())
    }

    fn merge_keys(&mut self, incoming: &[AuthorizedSealedDmKey]) -> Result<(), String> {
        for authorized in incoming {
            let record = &authorized.record;
            let signer_vk = self.device_vk_any(&authorized.signer, record.sealed_at)?;
            authorized.verify(&signer_vk)?;
            if self.keys.keys.iter().any(|existing| {
                existing.record.key_version == record.key_version
                    && existing.record.member == record.member
                    && existing.record.device == record.device
            }) {
                continue;
            }
            self.keys.keys.push(authorized.clone());
        }
        self.keys
            .keys
            .sort_by_key(|key| (key.record.key_version, key.record.member, key.record.device));
        Ok(())
    }

    fn merge_messages(&mut self, incoming: &[AuthorizedDmMessage]) -> Result<(), String> {
        for authorized in incoming {
            if self
                .messages
                .messages
                .iter()
                .any(|existing| existing.message.id == authorized.message.id)
            {
                continue;
            }
            if self.messages.messages.len() >= MAX_MESSAGES {
                return Err("message cap reached; create a new generation".to_string());
            }
            let vk = self.device_vk(
                &authorized.message.author,
                &authorized.message.device,
                authorized.message.created_at,
            )?;
            authorized.verify(&vk)?;
            self.messages.messages.push(authorized.clone());
        }
        self.messages
            .messages
            .sort_by_key(|message| (message.message.created_at, message.message.id));
        Ok(())
    }

    fn merge_read(&mut self, incoming: &[AuthorizedDmRead]) -> Result<(), String> {
        for authorized in incoming {
            let entry = &authorized.entry;
            let vk = self.device_vk(&entry.member, &entry.device, entry.updated_at)?;
            authorized.verify(&vk)?;
            if let Some(existing) = self.read.entries.iter_mut().find(|existing| {
                existing.entry.member == entry.member && existing.entry.device == entry.device
            }) {
                if entry.version > existing.entry.version {
                    *existing = authorized.clone();
                }
            } else {
                self.read.entries.push(authorized.clone());
            }
        }
        self.read
            .entries
            .sort_by_key(|entry| (entry.entry.member, entry.entry.device));
        Ok(())
    }

    fn merge_generation(&mut self, incoming: &DmGenerationV1) -> Result<(), String> {
        if incoming.generation == 0 && incoming.signature == zero_signature() {
            return Ok(());
        }
        let at = incoming.closed_at.unwrap_or(i64::MAX);
        let vk = self.device_vk_any(&incoming.signer, at)?;
        incoming.verify(&vk)?;
        if incoming.generation > self.generation.generation {
            self.generation = incoming.clone();
        }
        Ok(())
    }
}
