//! Board ownership can move from one key to another without changing the
//! contract parameters (the board identity). The chain of signed transfers is
//! part of the state, so every peer agrees on who the owner is and on who it
//! was at any signed time.
//!
//! A transfer is unilateral: the current owner signs it. Records the owner
//! signed before the transfer keep verifying through the historical lookup;
//! the old key cannot sign anything new.
//!
//! Deactivations are per board and signed by the key itself. They cut the
//! future, not the past: records dated before the deactivation stay valid,
//! and a deactivated key can never sign again on this board.

use crate::board_state::member::MemberId;
use crate::board_state::rate_limit::system_time_ms;
use crate::board_state::{ChatBoardParametersV1, ChatBoardStateV1};
use crate::util::{sign_struct, verify_struct};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use freenet_scaffold::ComposableState;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

pub const MAX_OWNER_TRANSFERS: usize = 256;

/// One step of the ownership chain.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct OwnerTransferV1 {
    /// Owner at the time of the signature.
    pub from: MemberId,
    /// Successor; must be a current admin.
    pub to: MemberId,
    /// The successor's verifying key, so the chain is self-contained.
    pub to_key: VerifyingKey,
    /// 1 for the first transfer out of the founding owner, then 2, 3, ...
    pub generation: u64,
    pub transferred_at: SystemTime,
    /// What the outgoing owner chose for itself.
    #[serde(default)]
    pub outgoing: OutgoingOwnerAction,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum OutgoingOwnerAction {
    /// Keep the admin record, signed while still owner.
    #[default]
    KeepAdmin,
    /// Drop the admin record and stay a plain member.
    Member,
    /// Stay visible as a deactivated identity.
    Deactivate,
}

impl OwnerTransferV1 {
    pub fn digest(&self) -> u64 {
        let mut bytes = Vec::new();
        let _ = ciborium::ser::into_writer(self, &mut bytes);
        freenet_scaffold::util::fast_hash(&bytes).0 as u64
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedOwnerTransfer {
    pub transfer: OwnerTransferV1,
    pub signature: Signature,
}

impl AuthorizedOwnerTransfer {
    pub fn new(transfer: OwnerTransferV1, owner_sk: &SigningKey) -> Self {
        Self {
            signature: sign_struct(&transfer, owner_sk),
            transfer,
        }
    }

    pub fn verify_signature(&self, owner_key: &VerifyingKey) -> Result<(), String> {
        verify_struct(&self.transfer, &self.signature, owner_key)
            .map_err(|e| format!("Invalid owner transfer signature: {e}"))
    }
}

/// A key says it stops signing on this board. Per board by design: the same
/// key may own or join other boards.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct KeyDeactivationV1 {
    pub member: MemberId,
    /// The key being retired; must match the member's key.
    pub key: VerifyingKey,
    pub generation: u64,
    pub deactivated_at: SystemTime,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedKeyDeactivation {
    pub deactivation: KeyDeactivationV1,
    pub signature: Signature,
}

impl AuthorizedKeyDeactivation {
    pub fn new(deactivation: KeyDeactivationV1, signing_key: &SigningKey) -> Self {
        Self {
            signature: sign_struct(&deactivation, signing_key),
            deactivation,
        }
    }

    pub fn verify_signature(&self) -> Result<(), String> {
        verify_struct(
            &self.deactivation,
            &self.signature,
            &self.deactivation.key,
        )
        .map_err(|e| format!("Invalid deactivation signature: {e}"))
    }
}

#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
pub struct OwnershipV1 {
    pub transfers: Vec<AuthorizedOwnerTransfer>,
    pub deactivations: Vec<AuthorizedKeyDeactivation>,
}

impl OwnershipV1 {
    pub fn is_empty(&self) -> bool {
        self.transfers.is_empty() && self.deactivations.is_empty()
    }

    /// Owner id at the end of the chain.
    pub fn current_owner(&self, parameters: &ChatBoardParametersV1) -> MemberId {
        self.transfers
            .last()
            .map(|entry| entry.transfer.to)
            .unwrap_or_else(|| parameters.owner_id())
    }

    /// Owner key at the end of the chain.
    pub fn current_owner_key(&self, parameters: &ChatBoardParametersV1) -> VerifyingKey {
        self.transfers
            .last()
            .map(|entry| entry.transfer.to_key)
            .unwrap_or(parameters.owner)
    }

    /// Owner at a signed instant. Records without a timestamp (epoch) are
    /// treated as written before any transfer.
    pub fn owner_at(&self, parameters: &ChatBoardParametersV1, at: SystemTime) -> MemberId {
        let at_ms = system_time_ms(at);
        self.transfers
            .iter()
            .filter(|entry| system_time_ms(entry.transfer.transferred_at) <= at_ms)
            .last()
            .map(|entry| entry.transfer.to)
            .unwrap_or_else(|| parameters.owner_id())
    }

    pub fn owner_key_at(
        &self,
        parameters: &ChatBoardParametersV1,
        at: SystemTime,
    ) -> VerifyingKey {
        let at_ms = system_time_ms(at);
        self.transfers
            .iter()
            .filter(|entry| system_time_ms(entry.transfer.transferred_at) <= at_ms)
            .last()
            .map(|entry| entry.transfer.to_key)
            .unwrap_or(parameters.owner)
    }

    /// Whether the member has been an owner of this board.
    pub fn was_owner(&self, member: &MemberId) -> bool {
        self.transfers
            .iter()
            .any(|entry| entry.transfer.from == *member)
    }

    /// The key a member used as owner, if it ever was one.
    pub fn owner_key_of(&self, member: &MemberId) -> Option<VerifyingKey> {
        self.transfers
            .iter()
            .find(|entry| entry.transfer.to == *member)
            .map(|entry| entry.transfer.to_key)
    }

    /// Latest deactivation for a member.
    pub fn deactivation_of(&self, member: &MemberId) -> Option<&AuthorizedKeyDeactivation> {
        self.deactivations
            .iter()
            .filter(|entry| entry.deactivation.member == *member)
            .max_by_key(|entry| {
                (
                    entry.deactivation.generation,
                    system_time_ms(entry.deactivation.deactivated_at),
                )
            })
    }

    /// Whether the member retired its key at or before `at`.
    pub fn is_deactivated_at(&self, member: &MemberId, at: SystemTime) -> bool {
        let at_ms = system_time_ms(at);
        self.deactivations.iter().any(|entry| {
            entry.deactivation.member == *member
                && system_time_ms(entry.deactivation.deactivated_at) <= at_ms
        })
    }

    pub fn is_deactivated_now(&self, member: &MemberId) -> bool {
        self.deactivation_of(member).is_some()
    }

    /// Verify the whole chain: generations start at one, each step is signed
    /// by the owner of the previous step, the successor was an admin with a
    /// known key, and times never go backwards.
    pub fn verify(
        &self,
        state: &ChatBoardStateV1,
        parameters: &ChatBoardParametersV1,
    ) -> Result<(), String> {
        let mut from = parameters.owner_id();
        let mut from_key = parameters.owner;
        let mut generation = 1u64;
        let mut last_time = 0i64;

        for entry in &self.transfers {
            let transfer = &entry.transfer;
            if transfer.from != from {
                return Err("Owner transfer chain is broken".to_string());
            }
            if transfer.generation != generation {
                return Err("Owner transfer generation is not sequential".to_string());
            }
            let at = system_time_ms(transfer.transferred_at);
            if at < last_time {
                return Err("Owner transfer time goes backwards".to_string());
            }
            entry.verify_signature(&from_key)?;
            if transfer.to == transfer.from {
                return Err("An owner cannot transfer the board to itself".to_string());
            }

            // The successor must be a member whose key is the one named, and
            // an admin at the time of the transfer. The founding owner counts
            // as a member even after cleanup drops its record: once it owns the
            // board again the owner is implicit, and a return transfer names
            // exactly it.
            let member_key = match state
                .members
                .members
                .iter()
                .find(|member| member.member.id() == transfer.to)
            {
                Some(member) => member.member.member_vk,
                None if transfer.to == parameters.owner_id() => parameters.owner,
                None => {
                    return Err("Owner transfer target is not a member".to_string());
                }
            };
            if member_key != transfer.to_key {
                return Err("Owner transfer target key does not match the member".to_string());
            }
            let admin_signed_at = match state
                .admin
                .admins
                .iter()
                .find(|admin| admin.admin.id() == transfer.to)
            {
                Some(admin) => Some(system_time_ms(admin.admin.signed_at)),
                // A revocation recorded after the transfer removed the record,
                // but the appointment still existed at the transfer time.
                None if state.admin.revoked.iter().any(|revocation| {
                    revocation.id() == transfer.to
                        && system_time_ms(revocation.revocation.signed_at) > at
                }) => None,
                // The founding owner is the board's root authority and needs
                // no appointment of its own.
                None if transfer.to == parameters.owner_id() => None,
                None => {
                    return Err("Owner transfer target is not an admin".to_string());
                }
            };
            if let Some(admin_signed_at) = admin_signed_at {
                if admin_signed_at > at {
                    return Err(
                        "Owner transfer target became admin after the transfer".to_string()
                    );
                }
                let revoked_before = state.admin.revoked.iter().any(|revocation| {
                    revocation.id() == transfer.to
                        && system_time_ms(revocation.revocation.signed_at) <= at
                });
                if revoked_before {
                    return Err("Owner transfer target was not an admin at the transfer".to_string());
                }
            }

            from = transfer.to;
            from_key = transfer.to_key;
            generation += 1;
            last_time = at;
        }

        // Deactivations name their key, sign with it, and cannot retire the
        // current owner (the board would lose its only authority).
        for entry in &self.deactivations {
            entry.verify_signature()?;
            if entry.deactivation.member == from {
                return Err("The current owner cannot deactivate its key".to_string());
            }
            let expected = if entry.deactivation.member == parameters.owner_id() {
                Some(parameters.owner)
            } else {
                self.owner_key_of(&entry.deactivation.member).or_else(|| {
                    state
                        .members
                        .members
                        .iter()
                        .find(|member| member.member.id() == entry.deactivation.member)
                        .map(|member| member.member.member_vk)
                })
            };
            match expected {
                Some(key) if key == entry.deactivation.key => {}
                Some(_) => return Err("Deactivation key does not match the member".to_string()),
                None => return Err("Deactivation targets an unknown key".to_string()),
            }
        }

        Ok(())
    }

    /// Keep one transfer per generation (lowest digest wins, so concurrent
    /// transfers converge), drop the tail that no longer verifies, and keep
    /// the latest deactivation per member.
    pub fn cleanup(&mut self, state: &ChatBoardStateV1, parameters: &ChatBoardParametersV1) {
        self.transfers
            .sort_by_key(|entry| (entry.transfer.generation, entry.transfer.digest()));
        self.transfers
            .dedup_by_key(|entry| entry.transfer.generation);
        self.transfers.truncate(MAX_OWNER_TRANSFERS);
        while !self.transfers.is_empty() && self.verify(state, parameters).is_err() {
            self.transfers.pop();
        }

        self.deactivations.sort_by(|a, b| {
            a.deactivation
                .member
                .0
                 .0
                .cmp(&b.deactivation.member.0 .0)
                .then(b.deactivation.generation.cmp(&a.deactivation.generation))
        });
        self.deactivations
            .dedup_by_key(|entry| entry.deactivation.member);

        let all = std::mem::take(&mut self.deactivations);
        let mut kept = Vec::new();
        for entry in all {
            self.deactivations = kept.clone();
            self.deactivations.push(entry.clone());
            if self.verify(state, parameters).is_ok() {
                kept.push(entry);
            }
        }
        self.deactivations = kept;
    }
}

#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
pub struct OwnershipSummary {
    pub transfers: Vec<u64>,
    pub deactivations: Vec<(MemberId, u64)>,
}

#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
pub struct OwnershipDelta {
    pub transfers: Vec<AuthorizedOwnerTransfer>,
    pub deactivations: Vec<AuthorizedKeyDeactivation>,
}

impl OwnershipV1 {
    fn transfer_digests(&self) -> Vec<u64> {
        self.transfers
            .iter()
            .map(|entry| entry.transfer.digest())
            .collect()
    }

    fn deactivation_digests(&self) -> Vec<(MemberId, u64)> {
        self.deactivations
            .iter()
            .map(|entry| {
                let mut bytes = Vec::new();
                let _ = ciborium::ser::into_writer(entry, &mut bytes);
                (
                    entry.deactivation.member,
                    freenet_scaffold::util::fast_hash(&bytes).0 as u64,
                )
            })
            .collect()
    }
}

impl ComposableState for OwnershipV1 {
    type ParentState = ChatBoardStateV1;
    type Summary = OwnershipSummary;
    type Delta = OwnershipDelta;
    type Parameters = ChatBoardParametersV1;

    fn verify(
        &self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
    ) -> Result<(), String> {
        OwnershipV1::verify(self, parent_state, parameters)
    }

    fn summarize(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
    ) -> Self::Summary {
        OwnershipSummary {
            transfers: self.transfer_digests(),
            deactivations: self.deactivation_digests(),
        }
    }

    fn delta(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
        old_state_summary: &Self::Summary,
    ) -> Option<Self::Delta> {
        let transfers: Vec<_> = self
            .transfers
            .iter()
            .filter(|entry| !old_state_summary.transfers.contains(&entry.transfer.digest()))
            .cloned()
            .collect();
        let current_deactivations = self.deactivation_digests();
        let deactivations: Vec<_> = self
            .deactivations
            .iter()
            .filter(|entry| {
                let digest = current_deactivations
                    .iter()
                    .find(|(member, _)| *member == entry.deactivation.member)
                    .map(|(_, digest)| *digest)
                    .unwrap_or_default();
                !old_state_summary
                    .deactivations
                    .iter()
                    .any(|(member, old)| *member == entry.deactivation.member && *old == digest)
            })
            .cloned()
            .collect();
        if transfers.is_empty() && deactivations.is_empty() {
            None
        } else {
            Some(OwnershipDelta {
                transfers,
                deactivations,
            })
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
        let mut trial = self.clone();
        trial.transfers.extend(delta.transfers.iter().cloned());
        trial
            .deactivations
            .extend(delta.deactivations.iter().cloned());
        trial.cleanup(parent_state, parameters);
        // A delta may extend the chain, never shorten an accepted one. When a
        // record elsewhere in the update invalidates an earlier transfer (a
        // newer admin appointment for the member that transfer handed the board
        // to), cleanup would drop it and hand the board back. Keep the chain.
        let keeps_accepted_chain = trial.transfers.len() >= self.transfers.len()
            && trial.transfers[..self.transfers.len()] == self.transfers[..];
        if keeps_accepted_chain && trial.verify(parent_state, parameters).is_ok() {
            *self = trial;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board_state::admin::{
        Admin, AdminRevocation, AdminsDelta, AuthorizedAdmin, AuthorizedAdminRevocation,
    };
    use crate::board_state::configuration::{AuthorizedConfigurationV1, Configuration};
    use crate::board_state::member::{AuthorizedMember, Member, MembersDelta};
    use crate::board_state::message::{AuthorizedMessageV1, BoardMessageBody, MessageV1};
    use crate::board_state::roles::verify_admin_authority;
    use crate::board_state::ChatBoardStateV1Delta;
    use crate::ChatBoardStateV1;
    use ed25519_dalek::SigningKey;

    struct Fixture {
        state: ChatBoardStateV1,
        parameters: ChatBoardParametersV1,
        owner_sk: SigningKey,
        owner_id: MemberId,
        admin_sk: SigningKey,
        admin_id: MemberId,
        now: SystemTime,
    }

    fn fixture() -> Fixture {
        let owner_sk = SigningKey::from_bytes(&[1u8; 32]);
        let admin_sk = SigningKey::from_bytes(&[2u8; 32]);
        let owner_id = MemberId::from(&owner_sk.verifying_key());
        let admin_id = MemberId::from(&admin_sk.verifying_key());
        let parameters = ChatBoardParametersV1 {
            owner: owner_sk.verifying_key(),
        };
        let mut state = ChatBoardStateV1 {
            configuration: AuthorizedConfigurationV1::new(Configuration::default(), &owner_sk),
            ..Default::default()
        };
        state.members.members.push(AuthorizedMember::new(
            Member {
                owner_member_id: owner_id,
                invited_by: owner_id,
                member_vk: admin_sk.verifying_key(),
                join_proof: None,
            },
            &owner_sk,
        ));
        // A message keeps the admin member from being pruned by the cleanup.
        state
            .recent_messages
            .messages
            .push(AuthorizedMessageV1::new(
                MessageV1 {
                    images: Vec::new(),
                    board_owner: owner_id,
                    author: admin_id,
                    time: SystemTime::UNIX_EPOCH,
                    content: BoardMessageBody::public("t".to_string(), "b".to_string()),
                    reply_to: None,
                    topic_id: None,
                    auto_moderated: false,
                },
                &admin_sk,
            ));
        state.admin.admins.push(AuthorizedAdmin::new(
            Admin {
                member_id: admin_id,
                generation: 1,
                signed_at: SystemTime::UNIX_EPOCH,
            },
            &owner_sk,
        ));
        Fixture {
            state,
            parameters,
            owner_sk,
            owner_id,
            admin_sk,
            admin_id,
            now: SystemTime::now(),
        }
    }

    fn transfer(
        from: MemberId,
        to: MemberId,
        to_key: VerifyingKey,
        generation: u64,
        at: SystemTime,
        signer: &SigningKey,
    ) -> AuthorizedOwnerTransfer {
        transfer_with_outgoing(
            from,
            to,
            to_key,
            generation,
            at,
            signer,
            OutgoingOwnerAction::KeepAdmin,
        )
    }

    fn transfer_with_outgoing(
        from: MemberId,
        to: MemberId,
        to_key: VerifyingKey,
        generation: u64,
        at: SystemTime,
        signer: &SigningKey,
        outgoing: OutgoingOwnerAction,
    ) -> AuthorizedOwnerTransfer {
        AuthorizedOwnerTransfer::new(
            OwnerTransferV1 {
                from,
                to,
                to_key,
                generation,
                transferred_at: at,
                outgoing,
            },
            signer,
        )
    }

    fn apply(state: &mut ChatBoardStateV1, parameters: &ChatBoardParametersV1, delta: OwnershipDelta) {
        let parent = state.clone();
        state
            .apply_delta(
                &parent,
                parameters,
                &Some(ChatBoardStateV1Delta {
                    ownership: Some(delta),
                    ..Default::default()
                }),
            )
            .expect("ownership delta applies");
    }

    #[test]
    fn a_transfer_moves_the_owner_and_keeps_the_board() {
        let mut fixture = fixture();
        let state_before = fixture.state.clone();
        apply(
            &mut fixture.state,
            &fixture.parameters,
            OwnershipDelta {
                transfers: vec![transfer(
                    fixture.owner_id,
                    fixture.admin_id,
                    fixture.admin_sk.verifying_key(),
                    1,
                    fixture.now,
                    &fixture.owner_sk,
                )],
                deactivations: Vec::new(),
            },
        );

        assert_eq!(
            fixture.state.ownership.current_owner(&fixture.parameters),
            fixture.admin_id
        );
        // Configuration, members and admins written before the transfer stay.
        assert_eq!(
            fixture.state.recent_messages.messages.len(),
            state_before.recent_messages.messages.len()
        );
        assert_eq!(fixture.state.admin.admins.len(), 1);
        fixture
            .state
            .verify(&fixture.state.clone(), &fixture.parameters)
            .expect("the state verifies after the transfer");

        let later = fixture.now + std::time::Duration::from_secs(60);
        verify_admin_authority(
            &fixture.state,
            &fixture.parameters,
            &fixture.admin_id,
            None,
            8,
            later,
        )
        .expect("the new owner holds the owner powers");
        assert!(verify_admin_authority(
            &fixture.state,
            &fixture.parameters,
            &fixture.owner_id,
            None,
            8,
            later,
        )
        .is_err());
    }

    /// The transfer screen sends the outgoing owner's admin record in the same
    /// update as the transfer: it is signed while the founder still owns the
    /// board, so the delta cannot wait for the transfer to be recorded.
    #[test]
    fn an_invalid_state_cannot_wipe_the_accepted_chain() {
        let fixture = fixture();
        let mut ownership = OwnershipV1::default();
        ownership
            .apply_delta(
                &fixture.state,
                &fixture.parameters,
                &Some(OwnershipDelta {
                    transfers: vec![transfer(
                        fixture.owner_id,
                        fixture.admin_id,
                        fixture.admin_sk.verifying_key(),
                        1,
                        fixture.now,
                        &fixture.owner_sk,
                    )],
                    deactivations: Vec::new(),
                }),
            )
            .unwrap();
        assert_eq!(ownership.transfers.len(), 1);

        // A later "keep admin" bundle re-issued the new owner's record with a
        // newer timestamp: the accepted transfer no longer verifies.
        let mut later = fixture.state.clone();
        later.admin.admins = vec![AuthorizedAdmin::new(
            Admin {
                member_id: fixture.admin_id,
                generation: 2,
                signed_at: fixture.now + std::time::Duration::from_secs(3600),
            },
            &fixture.owner_sk,
        )];

        ownership
            .apply_delta(
                &later,
                &fixture.parameters,
                &Some(OwnershipDelta {
                    transfers: Vec::new(),
                    deactivations: Vec::new(),
                }),
            )
            .unwrap();

        assert_eq!(
            ownership.transfers.len(),
            1,
            "the accepted transfer is kept even when it stops verifying"
        );
        assert_eq!(
            ownership.current_owner(&fixture.parameters),
            fixture.admin_id
        );
    }

    #[test]
    fn the_founding_owner_keeps_admin_rights_across_the_transfer() {
        let mut fixture = fixture();
        let parent = fixture.state.clone();
        // The UI signs the outgoing record first and dates the transfer two
        // milliseconds later, so the record resolves the founder as authority.
        let transferred_at = fixture.now + std::time::Duration::from_millis(2);
        let outgoing_admin = AuthorizedAdmin::new(
            Admin {
                member_id: fixture.owner_id,
                generation: 1,
                signed_at: fixture.now,
            },
            &fixture.owner_sk,
        );

        fixture
            .state
            .apply_delta(
                &parent,
                &fixture.parameters,
                &Some(ChatBoardStateV1Delta {
                    ownership: Some(OwnershipDelta {
                        transfers: vec![transfer(
                            fixture.owner_id,
                            fixture.admin_id,
                            fixture.admin_sk.verifying_key(),
                            1,
                            transferred_at,
                            &fixture.owner_sk,
                        )],
                        deactivations: Vec::new(),
                    }),
                    admin: Some(AdminsDelta::new(vec![outgoing_admin])),
                    members: Some(MembersDelta::new(vec![AuthorizedMember::new(
                        Member {
                            owner_member_id: fixture.owner_id,
                            invited_by: fixture.owner_id,
                            member_vk: fixture.owner_sk.verifying_key(),
                            join_proof: None,
                        },
                        &fixture.owner_sk,
                    )])),
                    ..Default::default()
                }),
            )
            .expect("the transfer and the outgoing admin record apply together");

        assert!(
            fixture
                .state
                .members
                .members
                .iter()
                .any(|member| member.member.id() == fixture.owner_id),
            "the former owner stays a member"
        );

        assert!(fixture
            .state
            .admin
            .admins
            .iter()
            .any(|admin| admin.admin.id() == fixture.owner_id));
        fixture
            .state
            .verify(&fixture.state.clone(), &fixture.parameters)
            .expect("the state verifies after the transfer");

        let later = fixture.now + std::time::Duration::from_secs(60);
        verify_admin_authority(
            &fixture.state,
            &fixture.parameters,
            &fixture.owner_id,
            None,
            8,
            later,
        )
        .expect("the former owner keeps its admin powers");
    }

    /// The UI bundle for "I become a plain member": the outgoing owner keeps
    /// its member record and loses its admin appointment.
    #[test]
    fn the_old_owner_can_step_down_to_a_plain_member() {
        let mut fixture = fixture();
        let first_sign = fixture.now;
        let first_at = first_sign + std::time::Duration::from_millis(2);
        // The founder hands the board over and stays admin: the bundle carries
        // its member record and its appointment.
        let parent = fixture.state.clone();
        fixture
            .state
            .apply_delta(
                &parent,
                &fixture.parameters,
                &Some(ChatBoardStateV1Delta {
                    ownership: Some(OwnershipDelta {
                        transfers: vec![transfer(
                            fixture.owner_id,
                            fixture.admin_id,
                            fixture.admin_sk.verifying_key(),
                            1,
                            first_at,
                            &fixture.owner_sk,
                        )],
                        deactivations: Vec::new(),
                    }),
                    members: Some(MembersDelta::new(vec![AuthorizedMember::new(
                        Member {
                            owner_member_id: fixture.owner_id,
                            invited_by: fixture.owner_id,
                            member_vk: fixture.owner_sk.verifying_key(),
                            join_proof: None,
                        },
                        &fixture.owner_sk,
                    )])),
                    admin: Some(AdminsDelta::new(vec![AuthorizedAdmin::new(
                        Admin {
                            member_id: fixture.owner_id,
                            generation: fixture.state.admin.next_generation(&fixture.owner_id),
                            signed_at: first_sign,
                        },
                        &fixture.owner_sk,
                    )])),
                    ..Default::default()
                }),
            )
            .expect("the first transfer applies");

        // The admin hands the board back and steps down to a plain member.
        let back_sign = first_at + std::time::Duration::from_secs(60);
        let back_at = back_sign + std::time::Duration::from_millis(2);
        let revocation = AdminRevocation {
            member_id: fixture.admin_id,
            generation: fixture.state.admin.next_generation(&fixture.admin_id),
            signed_at: back_sign,
        };
        let parent = fixture.state.clone();
        fixture
            .state
            .apply_delta(
                &parent,
                &fixture.parameters,
                &Some(ChatBoardStateV1Delta {
                    ownership: Some(OwnershipDelta {
                        transfers: vec![transfer_with_outgoing(
                            fixture.admin_id,
                            fixture.owner_id,
                            fixture.owner_sk.verifying_key(),
                            2,
                            back_at,
                            &fixture.admin_sk,
                            OutgoingOwnerAction::Member,
                        )],
                        deactivations: Vec::new(),
                    }),
                    admin: Some(AdminsDelta::revocation(vec![
                        AuthorizedAdminRevocation::with_signature(
                            revocation.clone(),
                            sign_struct(&revocation, &fixture.admin_sk),
                        ),
                    ])),
                    ..Default::default()
                }),
            )
            .expect("the handover back with a plain-member outcome applies");

        assert_eq!(
            fixture.state.ownership.current_owner(&fixture.parameters),
            fixture.owner_id
        );
        assert!(
            fixture
                .state
                .admin
                .admins
                .iter()
                .all(|admin| admin.admin.id() != fixture.admin_id),
            "the outgoing owner lost its appointment"
        );
        assert!(
            fixture
                .state
                .members
                .members
                .iter()
                .any(|member| member.member.id() == fixture.admin_id),
            "the outgoing owner stays a member"
        );
        fixture
            .state
            .normalize(&fixture.parameters)
            .expect("cleanup accepts the stepped-down owner");
        fixture
            .state
            .verify(&fixture.state.clone(), &fixture.parameters)
            .expect("the state verifies after the handover");
        assert_eq!(
            fixture.state.ownership.transfers.len(),
            2,
            "cleanup kept the chain"
        );

        // The former owner can no longer transfer: the delta changes nothing.
        let late = back_sign + std::time::Duration::from_secs(60);
        let parent = fixture.state.clone();
        fixture
            .state
            .apply_delta(
                &parent,
                &fixture.parameters,
                &Some(ChatBoardStateV1Delta {
                    ownership: Some(OwnershipDelta {
                        transfers: vec![transfer(
                            fixture.admin_id,
                            fixture.admin_id,
                            fixture.admin_sk.verifying_key(),
                            3,
                            late,
                            &fixture.admin_sk,
                        )],
                        deactivations: Vec::new(),
                    }),
                    ..Default::default()
                }),
            )
            .expect("a refused ownership delta is not an apply error");
        assert_eq!(
            fixture.state.ownership.transfers.len(),
            2,
            "the stepped-down admin cannot transfer"
        );
        assert_eq!(
            fixture.state.ownership.current_owner(&fixture.parameters),
            fixture.owner_id
        );
    }

    /// The UI bundle for "I deactivate my key on this board": the outgoing
    /// owner retires its key and its appointment.
    #[test]
    fn the_old_owner_can_deactivate_its_key() {
        let mut fixture = fixture();
        let first_sign = fixture.now;
        let first_at = first_sign + std::time::Duration::from_millis(2);
        apply(
            &mut fixture.state,
            &fixture.parameters,
            OwnershipDelta {
                transfers: vec![transfer(
                    fixture.owner_id,
                    fixture.admin_id,
                    fixture.admin_sk.verifying_key(),
                    1,
                    first_at,
                    &fixture.owner_sk,
                )],
                deactivations: Vec::new(),
            },
        );

        let back_sign = first_at + std::time::Duration::from_secs(60);
        let back_at = back_sign + std::time::Duration::from_millis(2);
        let revocation = AdminRevocation {
            member_id: fixture.admin_id,
            generation: fixture.state.admin.next_generation(&fixture.admin_id),
            signed_at: back_sign,
        };
        let parent = fixture.state.clone();
        fixture
            .state
            .apply_delta(
                &parent,
                &fixture.parameters,
                &Some(ChatBoardStateV1Delta {
                    ownership: Some(OwnershipDelta {
                        transfers: vec![transfer_with_outgoing(
                            fixture.admin_id,
                            fixture.owner_id,
                            fixture.owner_sk.verifying_key(),
                            2,
                            back_at,
                            &fixture.admin_sk,
                            OutgoingOwnerAction::Deactivate,
                        )],
                        deactivations: vec![AuthorizedKeyDeactivation::new(
                            KeyDeactivationV1 {
                                member: fixture.admin_id,
                                key: fixture.admin_sk.verifying_key(),
                                generation: 1,
                                deactivated_at: back_sign,
                            },
                            &fixture.admin_sk,
                        )],
                    }),
                    admin: Some(AdminsDelta::revocation(vec![
                        AuthorizedAdminRevocation::with_signature(
                            revocation.clone(),
                            sign_struct(&revocation, &fixture.admin_sk),
                        ),
                    ])),
                    ..Default::default()
                }),
            )
            .expect("the handover back with a deactivation applies");

        assert_eq!(
            fixture.state.ownership.current_owner(&fixture.parameters),
            fixture.owner_id
        );
        assert!(fixture
            .state
            .ownership
            .is_deactivated_now(&fixture.admin_id));
        assert_eq!(fixture.state.ownership.deactivations.len(), 1);
        assert!(fixture
            .state
            .admin
            .admins
            .iter()
            .all(|admin| admin.admin.id() != fixture.admin_id));
        fixture
            .state
            .normalize(&fixture.parameters)
            .expect("cleanup accepts the deactivated owner");
        fixture
            .state
            .verify(&fixture.state.clone(), &fixture.parameters)
            .expect("the state verifies with a deactivated outgoing owner");
    }

    #[test]
    fn the_board_can_return_to_the_founding_owner() {
        let mut fixture = fixture();
        let first_at = fixture.now;
        apply(
            &mut fixture.state,
            &fixture.parameters,
            OwnershipDelta {
                transfers: vec![transfer(
                    fixture.owner_id,
                    fixture.admin_id,
                    fixture.admin_sk.verifying_key(),
                    1,
                    first_at,
                    &fixture.owner_sk,
                )],
                deactivations: Vec::new(),
            },
        );

        // The new owner hands the board back to the founder, who is no longer
        // on the members list by then: the owner is implicit.
        let back_at = first_at + std::time::Duration::from_secs(60);
        apply(
            &mut fixture.state,
            &fixture.parameters,
            OwnershipDelta {
                transfers: vec![transfer(
                    fixture.admin_id,
                    fixture.owner_id,
                    fixture.owner_sk.verifying_key(),
                    2,
                    back_at,
                    &fixture.admin_sk,
                )],
                deactivations: Vec::new(),
            },
        );

        assert_eq!(
            fixture.state.ownership.current_owner(&fixture.parameters),
            fixture.owner_id
        );
        fixture
            .state
            .normalize(&fixture.parameters)
            .expect("cleanup accepts the returned board");
        fixture
            .state
            .verify(&fixture.state.clone(), &fixture.parameters)
            .expect("the state verifies after the return transfer");
    }

    #[test]
    fn the_new_owner_can_transfer_again() {        let mut fixture = fixture();
        let second_sk = SigningKey::from_bytes(&[3u8; 32]);
        let second_id = MemberId::from(&second_sk.verifying_key());
        fixture.state.members.members.push(AuthorizedMember::new(
            Member {
                owner_member_id: fixture.owner_id,
                invited_by: fixture.admin_id,
                member_vk: second_sk.verifying_key(),
                join_proof: None,
            },
            &fixture.admin_sk,
        ));
        fixture.state.admin.admins.push(AuthorizedAdmin::new(
            Admin {
                member_id: second_id,
                generation: 1,
                signed_at: fixture.now,
            },
            &fixture.admin_sk,
        ));
        fixture
            .state
            .recent_messages
            .messages
            .push(AuthorizedMessageV1::new(
                MessageV1 {
                    images: Vec::new(),
                    board_owner: fixture.owner_id,
                    author: second_id,
                    time: SystemTime::UNIX_EPOCH,
                    content: BoardMessageBody::public("t2".to_string(), "b".to_string()),
                    reply_to: None,
                    topic_id: None,
                    auto_moderated: false,
                },
                &second_sk,
            ));

        apply(
            &mut fixture.state,
            &fixture.parameters,
            OwnershipDelta {
                transfers: vec![
                    transfer(
                        fixture.owner_id,
                        fixture.admin_id,
                        fixture.admin_sk.verifying_key(),
                        1,
                        fixture.now,
                        &fixture.owner_sk,
                    ),
                    transfer(
                        fixture.admin_id,
                        second_id,
                        second_sk.verifying_key(),
                        2,
                        fixture.now + std::time::Duration::from_secs(1),
                        &fixture.admin_sk,
                    ),
                ],
                deactivations: Vec::new(),
            },
        );

        assert_eq!(
            fixture.state.ownership.current_owner(&fixture.parameters),
            second_id
        );
        fixture
            .state
            .verify(&fixture.state.clone(), &fixture.parameters)
            .expect("the chain verifies");
    }

    #[test]
    fn a_promotion_then_transfer_in_two_updates_succeeds() {
        let mut fixture = fixture();
        fixture.state.admin.admins.clear();
        let now = std::time::SystemTime::now();
        let parent = fixture.state.clone();
        fixture
            .state
            .apply_delta(
                &parent,
                &fixture.parameters,
                &Some(ChatBoardStateV1Delta {
                    admin: Some(crate::board_state::admin::AdminsDelta::new(vec![
                        AuthorizedAdmin::new(
                            Admin {
                                member_id: fixture.admin_id,
                                generation: 1,
                                signed_at: now,
                            },
                            &fixture.owner_sk,
                        ),
                    ])),
                    ..Default::default()
                }),
            )
            .expect("promotion applies");

        apply(
            &mut fixture.state,
            &fixture.parameters,
            OwnershipDelta {
                transfers: vec![transfer(
                    fixture.owner_id,
                    fixture.admin_id,
                    fixture.admin_sk.verifying_key(),
                    1,
                    now + std::time::Duration::from_millis(2),
                    &fixture.owner_sk,
                )],
                deactivations: Vec::new(),
            },
        );

        assert_eq!(
            fixture.state.ownership.current_owner(&fixture.parameters),
            fixture.admin_id,
            "the transfer must survive cleanup"
        );
    }

    #[test]
    fn a_transfer_target_must_be_an_admin() {
        let mut fixture = fixture();
        fixture.state.admin.admins.clear();
        let parent = fixture.state.clone();
        let error = fixture
            .state
            .apply_delta(
                &parent,
                &fixture.parameters,
                &Some(ChatBoardStateV1Delta {
                    ownership: Some(OwnershipDelta {
                        transfers: vec![transfer(
                            fixture.owner_id,
                            fixture.admin_id,
                            fixture.admin_sk.verifying_key(),
                            1,
                            fixture.now,
                            &fixture.owner_sk,
                        )],
                        deactivations: Vec::new(),
                    }),
                    ..Default::default()
                }),
            );
        // cleanup drops the record, so the state keeps the founding owner.
        assert_eq!(
            fixture.state.ownership.current_owner(&fixture.parameters),
            fixture.owner_id
        );
        let _ = error;
    }

    #[test]
    fn a_deactivated_key_cannot_sign_later() {
        let mut fixture = fixture();
        apply(
            &mut fixture.state,
            &fixture.parameters,
            OwnershipDelta {
                transfers: vec![transfer(
                    fixture.owner_id,
                    fixture.admin_id,
                    fixture.admin_sk.verifying_key(),
                    1,
                    fixture.now,
                    &fixture.owner_sk,
                )],
                deactivations: vec![AuthorizedKeyDeactivation::new(
                    KeyDeactivationV1 {
                        member: fixture.owner_id,
                        key: fixture.owner_sk.verifying_key(),
                        generation: 1,
                        deactivated_at: fixture.now,
                    },
                    &fixture.owner_sk,
                )],
            },
        );

        let later = fixture.now + std::time::Duration::from_secs(60);
        assert!(fixture
            .state
            .ownership
            .is_deactivated_at(&fixture.owner_id, later));
        assert!(verify_admin_authority(
            &fixture.state,
            &fixture.parameters,
            &fixture.owner_id,
            None,
            8,
            later,
        )
        .is_err());
        // The retired key cannot vouch for later records, but the board with
        // the new owner stays valid.
        assert!(fixture
            .state
            .verify(&fixture.state.clone(), &fixture.parameters)
            .is_ok());
    }
}

