//! Reusable invite links.
//!
//! A link carries a random signing key; the board state stores its public key
//! together with the role the link grants and an optional use cap. Whoever holds
//! the link signs their own join request with it, so the state never contains a
//! secret and a leaked state cannot mint joins.
//!
//! Expiry is enforced by clients, not by the contract: the contract has no
//! trusted clock, and checking `SystemTime::now` in validation would make peers
//! disagree.

use crate::board_state::member::MemberId;
use crate::board_state::roles::RoleId;
use crate::board_state::ChatBoardParametersV1;
use crate::util::{sign_struct, verify_struct};
use crate::ChatBoardStateV1;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use freenet_scaffold::ComposableState;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::SystemTime;

pub type TokenId = [u8; 16];

/// Domain separation for the proof a joiner signs with the link key.
pub fn join_message(board: &VerifyingKey, member_vk: &VerifyingKey) -> Vec<u8> {
    let mut message = b"freetalk-plaza-join-v1".to_vec();
    message.extend_from_slice(board.as_bytes());
    message.extend_from_slice(member_vk.as_bytes());
    message
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct InviteToken {
    pub id: TokenId,
    /// Public half of the key embedded in the link.
    pub verifying_key: VerifyingKey,
    /// Role granted to whoever joins through this link.
    pub role_id: RoleId,
    /// `None` means unlimited until the token is revoked.
    pub max_uses: Option<u32>,
    pub not_after: Option<SystemTime>,
    pub generation: u64,
    pub deleted: bool,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedInviteToken {
    pub token: InviteToken,
    pub signature: Signature,
}

impl AuthorizedInviteToken {
    pub fn new(token: InviteToken, owner_sk: &SigningKey) -> Self {
        Self {
            signature: sign_struct(&token, owner_sk),
            token,
        }
    }

    pub fn verify_signature(&self, owner_vk: &VerifyingKey) -> Result<(), String> {
        verify_struct(&self.token, &self.signature, owner_vk)
            .map_err(|e| format!("Invalid invite token signature: {}", e))
    }
}

/// Proof that the joiner holds the link key, stored with the member record.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct JoinProof {
    pub token_id: TokenId,
    pub token_signature: Signature,
}

impl std::hash::Hash for JoinProof {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.token_id.hash(state);
        self.token_signature.to_bytes().hash(state);
    }
}

impl JoinProof {
    pub fn new(token_id: TokenId, token_key: &SigningKey, message: &[u8]) -> Self {
        Self {
            token_id,
            token_signature: sign_struct(&message.to_vec(), token_key),
        }
    }

    pub fn verify(&self, token_vk: &VerifyingKey, message: &[u8]) -> Result<(), String> {
        verify_struct(&message.to_vec(), &self.token_signature, token_vk)
            .map_err(|e| format!("Invalid invite proof: {}", e))
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct InviteTokensV1 {
    pub tokens: Vec<AuthorizedInviteToken>,
}

impl ComposableState for InviteTokensV1 {
    type ParentState = ChatBoardStateV1;
    type Summary = InviteTokensSummary;
    type Delta = InviteTokensDelta;
    type Parameters = ChatBoardParametersV1;

    fn verify(
        &self,
        _parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
    ) -> Result<(), String> {
        let mut ids = std::collections::HashSet::new();
        for token in &self.tokens {
            token.verify_signature(&parameters.owner)?;
            if !ids.insert(token.token.id) {
                return Err("Duplicate invite token".to_string());
            }
        }
        Ok(())
    }

    fn summarize(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
    ) -> Self::Summary {
        let mut states = BTreeMap::new();
        for token in &self.tokens {
            states.insert(
                token.token.id,
                TokenState {
                    generation: token.token.generation,
                    deleted: token.token.deleted,
                },
            );
        }
        InviteTokensSummary { states }
    }

    fn delta(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
        old_state_summary: &Self::Summary,
    ) -> Option<Self::Delta> {
        let tokens = self
            .tokens
            .iter()
            .filter(|t| {
                old_state_summary
                    .states
                    .get(&t.token.id)
                    .map(|s| s.generation < t.token.generation)
                    .unwrap_or(true)
            })
            .cloned()
            .collect::<Vec<_>>();
        if tokens.is_empty() {
            None
        } else {
            Some(InviteTokensDelta { tokens })
        }
    }

    fn apply_delta(
        &mut self,
        _parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
        delta: &Option<Self::Delta>,
    ) -> Result<(), String> {
        if let Some(delta) = delta {
            for token in &delta.tokens {
                token.verify_signature(&parameters.owner)?;
                match self.tokens.iter().find(|t| t.token.id == token.token.id) {
                    Some(existing) if existing.token.generation >= token.token.generation => {
                        continue
                    }
                    _ => {}
                }
                self.tokens.retain(|t| t.token.id != token.token.id);
                self.tokens.push(token.clone());
            }
            self.tokens.sort_by_key(|t| t.token.id);
        }
        Ok(())
    }
}

impl InviteTokensV1 {
    /// Active token, i.e. not deleted. Expiry is the client's business.
    pub fn token(&self, id: &TokenId) -> Option<&InviteToken> {
        self.tokens
            .iter()
            .find(|t| t.token.id == *id && !t.token.deleted)
            .map(|t| &t.token)
    }

    pub fn token_including_deleted(&self, id: &TokenId) -> Option<&InviteToken> {
        self.tokens
            .iter()
            .find(|t| t.token.id == *id)
            .map(|t| &t.token)
    }

    pub fn next_generation(&self, id: &TokenId) -> u64 {
        self.tokens
            .iter()
            .find(|t| t.token.id == *id)
            .map(|t| t.token.generation + 1)
            .unwrap_or(1)
    }

    pub fn active_tokens(&self) -> Vec<&InviteToken> {
        self.tokens
            .iter()
            .filter(|t| !t.token.deleted)
            .map(|t| &t.token)
            .collect()
    }
}

/// One member joined through a link; used to count uses.
pub fn members_joined_via(
    members: &[crate::board_state::member::AuthorizedMember],
    token_id: &TokenId,
) -> Vec<MemberId> {
    members
        .iter()
        .filter(|m| {
            m.member
                .join_proof
                .as_ref()
                .map(|p| p.token_id == *token_id)
                .unwrap_or(false)
        })
        .map(|m| m.member.id())
        .collect()
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct InviteTokensSummary {
    pub states: BTreeMap<TokenId, TokenState>,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub struct TokenState {
    pub generation: u64,
    pub deleted: bool,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct InviteTokensDelta {
    pub tokens: Vec<AuthorizedInviteToken>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board_state::configuration::{AuthorizedConfigurationV1, Configuration};
    use crate::board_state::member::{AuthorizedMember, Member};
    use crate::board_state::roles::{AuthorizedRole, Role};
    use freenet_scaffold::ComposableState;

    fn owner() -> SigningKey {
        SigningKey::from_bytes(&[1u8; 32])
    }

    fn token_key() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    fn params(owner: &SigningKey) -> ChatBoardParametersV1 {
        ChatBoardParametersV1 {
            owner: owner.verifying_key(),
        }
    }

    fn base_state(owner: &SigningKey, role_id: RoleId, max_uses: Option<u32>) -> ChatBoardStateV1 {
        let mut state = ChatBoardStateV1 {
            configuration: AuthorizedConfigurationV1::new(Configuration::default(), owner),
            ..Default::default()
        };
        state.roles.roles.push(AuthorizedRole::new(
            Role {
                id: role_id,
                name: "membro".to_string(),
                generation: 1,
                can_manage_access: false,
                deleted: false,
            },
            owner,
        ));
        state.invites.tokens.push(AuthorizedInviteToken::new(
            InviteToken {
                id: [3u8; 16],
                verifying_key: token_key().verifying_key(),
                role_id,
                max_uses,
                not_after: None,
                generation: 1,
                deleted: false,
            },
            owner,
        ));
        state
    }

    fn joining_member(seed: u8, owner_id: MemberId) -> AuthorizedMember {
        let member_sk = SigningKey::from_bytes(&[seed; 32]);
        let proof = JoinProof::new(
            [3u8; 16],
            &token_key(),
            &join_message(&owner().verifying_key(), &member_sk.verifying_key()),
        );
        let member = Member {
            owner_member_id: owner_id,
            invited_by: MemberId::from(&member_sk.verifying_key()),
            member_vk: member_sk.verifying_key(),
            join_proof: Some(proof),
        };
        AuthorizedMember::new(member, &member_sk)
    }

    #[test]
    fn a_token_join_verifies() {
        let owner = owner();
        let role_id = [5u8; 16];
        let params = params(&owner);
        let mut state = base_state(&owner, role_id, Some(2));
        state
            .members
            .members
            .push(joining_member(7, params.owner_id()));

        state.verify(&state.clone(), &params).unwrap();
    }

    #[test]
    fn a_forged_proof_is_rejected() {
        let owner = owner();
        let role_id = [5u8; 16];
        let params = params(&owner);
        let mut state = base_state(&owner, role_id, Some(2));

        let member_sk = SigningKey::from_bytes(&[7u8; 32]);
        let wrong_key = SigningKey::from_bytes(&[8u8; 32]);
        let proof = JoinProof::new(
            [3u8; 16],
            &wrong_key,
            &join_message(&owner.verifying_key(), &member_sk.verifying_key()),
        );
        let member = Member {
            owner_member_id: params.owner_id(),
            invited_by: MemberId::from(&member_sk.verifying_key()),
            member_vk: member_sk.verifying_key(),
            join_proof: Some(proof),
        };
        state
            .members
            .members
            .push(AuthorizedMember::new(member, &member_sk));

        assert!(state.verify(&state.clone(), &params).is_err());
    }

    #[test]
    fn a_revoked_or_missing_role_token_blocks_the_join() {
        let owner = owner();
        let role_id = [5u8; 16];
        let params = params(&owner);

        // Deleted token.
        let mut state = base_state(&owner, role_id, Some(2));
        state.invites.tokens[0].token.deleted = true;
        state
            .members
            .members
            .push(joining_member(7, params.owner_id()));
        assert!(state.verify(&state.clone(), &params).is_err());

        // Token whose role no longer exists.
        let mut state = base_state(&owner, role_id, Some(2));
        state.roles.roles.clear();
        state
            .members
            .members
            .push(joining_member(7, params.owner_id()));
        assert!(state.verify(&state.clone(), &params).is_err());
    }

    #[test]
    fn the_use_cap_is_enforced_deterministically() {
        let owner = owner();
        let role_id = [5u8; 16];
        let params = params(&owner);
        let mut state = base_state(&owner, role_id, Some(1));
        state
            .members
            .members
            .push(joining_member(7, params.owner_id()));
        state
            .members
            .members
            .push(joining_member(8, params.owner_id()));

        state.enforce_invite_caps();
        assert_eq!(state.members.members.len(), 1, "cap of one use applies");
        state.verify(&state.clone(), &params).unwrap();
    }
}
