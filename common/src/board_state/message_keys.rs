//! Per-message content keys, wrapped for one section.
//!
//! Message bodies are encrypted with a random item key. A grant wraps that key
//! under the section secret, so a message can move between sections with
//! different keys without changing the author's signature: the mover adds a
//! grant for the destination section. Deleting all grants is the
//! crypto-shredding step.

use crate::board_state::member::MemberId;
use crate::board_state::message::MessageId;
use crate::board_state::moderation::category_chain;
use crate::board_state::roles::{
    is_board_admin, resolve_signer_key, verify_admin_authority, verify_moderation_authority,
    AuthorityProof, ModerationPower,
};
use crate::board_state::ChatBoardParametersV1;
use crate::util::{sign_struct, verify_struct};
use crate::ChatBoardStateV1;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use freenet_scaffold::ComposableState;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct MessageKeyGrantV1 {
    pub message_id: MessageId,
    /// Section this copy of the key opens; `None` is the board root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section: Option<MessageId>,
    pub wrapped_key: Vec<u8>,
    pub wrapped_nonce: [u8; 12],
    pub secret_version: u32,
    pub generation: u64,
    pub created_at: i64,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedMessageKeyGrant {
    pub grant: MessageKeyGrantV1,
    pub signature: Signature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<MemberId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_key: Option<VerifyingKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<Box<AuthorityProof>>,
}

impl AuthorizedMessageKeyGrant {
    pub fn new(grant: MessageKeyGrantV1, signing_key: &SigningKey) -> Self {
        Self {
            signature: sign_struct(&grant, signing_key),
            grant,
            signer: Some(MemberId::from(&signing_key.verifying_key())),
            signer_key: Some(signing_key.verifying_key()),
            authority: None,
        }
    }

    pub fn with_optional_authority(mut self, proof: Option<AuthorityProof>) -> Self {
        self.authority = proof.map(Box::new);
        self
    }

    pub fn signer_id(&self, parameters: &ChatBoardParametersV1) -> MemberId {
        self.signer.unwrap_or_else(|| parameters.owner_id())
    }

    fn verify_signature_with(&self, key: &VerifyingKey) -> Result<(), String> {
        verify_struct(&self.grant, &self.signature, key)
            .map_err(|e| format!("Invalid message key grant signature: {e}"))
    }
}

#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Eq, Debug)]
pub struct MessageKeysV1 {
    #[serde(default)]
    pub grants: Vec<AuthorizedMessageKeyGrant>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct MessageKeyState {
    pub secret_version: u32,
    pub generation: u64,
    #[serde(default)]
    pub digest: i64,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct MessageKeysSummary {
    pub grants: BTreeMap<(MessageId, Option<MessageId>), MessageKeyState>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct MessageKeysDelta {
    #[serde(default)]
    pub grants: Vec<AuthorizedMessageKeyGrant>,
}

fn digest<T: serde::Serialize>(value: &T) -> i64 {
    let mut bytes = Vec::new();
    let _ = ciborium::ser::into_writer(value, &mut bytes);
    freenet_scaffold::util::fast_hash(&bytes).0
}

impl MessageKeysV1 {
    /// The latest grant for a message and section.
    pub fn grant_for(
        &self,
        message: &MessageId,
        section: Option<&MessageId>,
    ) -> Option<&AuthorizedMessageKeyGrant> {
        self.grants
            .iter()
            .filter(|entry| {
                entry.grant.message_id == *message && entry.grant.section.as_ref() == section
            })
            .max_by_key(|entry| entry.grant.generation)
    }
}

fn verify_grant(
    state: &ChatBoardStateV1,
    parameters: &ChatBoardParametersV1,
    entry: &AuthorizedMessageKeyGrant,
) -> Result<(), String> {
    let grant = &entry.grant;
    let signer = entry.signer_id(parameters);
    let key = resolve_signer_key(state, parameters, &signer, entry.signer_key.as_ref())?;
    entry.verify_signature_with(&key)?;

    let message = state
        .recent_messages
        .messages
        .iter()
        .find(|message| message.id() == grant.message_id)
        .ok_or("Key grant targets a missing message")?;

    if grant.generation == 0 {
        return Err("Key grant needs a generation".to_string());
    }
    if grant.wrapped_key.len() < 32 || grant.wrapped_key.len() > 4096 {
        return Err("Wrapped message key size is invalid".to_string());
    }

    let routes = state.moderation.routes_map();
    let chain = match grant.section {
        None => Vec::new(),
        Some(section) => {
            let route = routes.get(&section).ok_or("Key grant section is missing")?;
            if !route.is_category {
                return Err("Key grant section is not a category".to_string());
            }
            category_chain(&routes, &section)
        }
    };

    let at = crate::board_state::rate_limit::system_time_from_ms(entry.grant.created_at);
    let is_author = message.message.author == signer;
    let is_admin = signer == state.ownership.owner_at(parameters, at)
        || is_board_admin(state, &signer)
        || verify_admin_authority(state, parameters, &signer, entry.authority.as_deref(), 8, at)
            .is_ok();
    let can_move = verify_moderation_authority(
        state,
        parameters,
        &signer,
        ModerationPower::Move,
        &chain,
        entry.authority.as_deref(),
        at,
    )
    .is_ok();

    if !is_author && !is_admin && !can_move {
        return Err("Signer cannot grant a key for this section".to_string());
    }
    Ok(())
}

impl ComposableState for MessageKeysV1 {
    type ParentState = ChatBoardStateV1;
    type Summary = MessageKeysSummary;
    type Delta = MessageKeysDelta;
    type Parameters = ChatBoardParametersV1;

    fn verify(
        &self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
    ) -> Result<(), String> {
        let mut keys = std::collections::HashSet::new();
        for entry in &self.grants {
            if !keys.insert((entry.grant.message_id, entry.grant.section)) {
                return Err("Duplicate key grant for one message and section".to_string());
            }
            verify_grant(parent_state, parameters, entry)?;
        }
        Ok(())
    }

    fn summarize(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
    ) -> Self::Summary {
        let mut grants = BTreeMap::new();
        for entry in &self.grants {
            grants.insert(
                (entry.grant.message_id, entry.grant.section),
                MessageKeyState {
                    secret_version: entry.grant.secret_version,
                    generation: entry.grant.generation,
                    digest: digest(&entry.grant),
                },
            );
        }
        MessageKeysSummary { grants }
    }

    fn delta(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
        old_state: &Self::Summary,
    ) -> Option<Self::Delta> {
        let grants = self
            .grants
            .iter()
            .filter(|entry| {
                old_state
                    .grants
                    .get(&(entry.grant.message_id, entry.grant.section))
                    .map(|old| {
                        old.generation < entry.grant.generation
                            || (old.generation == entry.grant.generation
                                && old.digest != digest(&entry.grant))
                    })
                    .unwrap_or(true)
            })
            .cloned()
            .collect::<Vec<_>>();
        if grants.is_empty() {
            None
        } else {
            Some(MessageKeysDelta { grants })
        }
    }

    fn apply_delta(
        &mut self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
        delta: &Option<Self::Delta>,
    ) -> Result<(), String> {
        let Some(delta) = delta else {
            return Ok(());
        };
        for entry in &delta.grants {
            verify_grant(parent_state, parameters, entry)?;
            let key = (entry.grant.message_id, entry.grant.section);
            match self
                .grants
                .iter()
                .find(|existing| (existing.grant.message_id, existing.grant.section) == key)
            {
                Some(existing)
                    if existing.grant.generation > entry.grant.generation
                        || (existing.grant.generation == entry.grant.generation
                            && digest(&existing.grant) <= digest(&entry.grant)) => {}
                _ => {
                    self.grants.retain(|existing| {
                        (existing.grant.message_id, existing.grant.section) != key
                    });
                    self.grants.push(entry.clone());
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board_state::configuration::{AuthorizedConfigurationV1, Configuration};
    use crate::board_state::member::{AuthorizedMember, Member};
    use crate::board_state::message::{
        AuthorizedMessageV1, BoardMessageBody, MessageV1, MessagesV1,
    };
    use ed25519_dalek::SigningKey;

    fn params(owner: &SigningKey) -> ChatBoardParametersV1 {
        ChatBoardParametersV1 {
            owner: owner.verifying_key(),
        }
    }

    fn board(owner: &SigningKey) -> ChatBoardStateV1 {
        ChatBoardStateV1 {
            configuration: AuthorizedConfigurationV1::new(Configuration::default(), owner),
            ..Default::default()
        }
    }

    fn member(sk: &SigningKey, owner_id: MemberId, owner: &SigningKey) -> AuthorizedMember {
        AuthorizedMember::new(
            Member {
                owner_member_id: owner_id,
                invited_by: owner_id,
                member_vk: sk.verifying_key(),
                join_proof: None,
            },
            owner,
        )
    }

    fn post(sk: &SigningKey, owner_id: MemberId) -> AuthorizedMessageV1 {
        AuthorizedMessageV1::new(
            MessageV1 {
                images: Vec::new(),
                board_owner: owner_id,
                author: MemberId::from(&sk.verifying_key()),
                time: std::time::SystemTime::now(),
                content: BoardMessageBody::public("t".to_string(), "body".to_string()),
            },
            sk,
        )
    }

    fn grant(message_id: MessageId, generation: u64) -> MessageKeyGrantV1 {
        MessageKeyGrantV1 {
            message_id,
            section: None,
            wrapped_key: vec![1u8; 48],
            wrapped_nonce: [2u8; 12],
            secret_version: 1,
            generation,
            created_at: 1,
        }
    }

    #[test]
    fn author_can_grant_and_a_stranger_cannot() {
        let owner = SigningKey::from_bytes(&[1u8; 32]);
        let author = SigningKey::from_bytes(&[2u8; 32]);
        let stranger = SigningKey::from_bytes(&[3u8; 32]);
        let parameters = params(&owner);
        let owner_id = parameters.owner_id();
        let author_id = MemberId::from(&author.verifying_key());
        let mut state = board(&owner);
        state
            .members
            .members
            .push(member(&author, owner_id, &owner));
        state
            .members
            .members
            .push(member(&stranger, owner_id, &owner));
        let message = post(&author, owner_id);
        let message_id = message.id();
        state.recent_messages = MessagesV1 {
            messages: vec![message],
            ..Default::default()
        };

        let author_grant = AuthorizedMessageKeyGrant::new(grant(message_id, 1), &author);
        state.message_keys.grants.push(author_grant);
        state
            .message_keys
            .verify(&state.clone(), &parameters)
            .expect("author can grant");

        let stranger_grant = AuthorizedMessageKeyGrant::new(grant(message_id, 2), &stranger);
        assert!(verify_grant(&state, &parameters, &stranger_grant).is_err());
        let _ = author_id;
    }
}
