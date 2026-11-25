//! Sections (categories and groups) in the board index.

use crate::board_state::member::MemberId;
use crate::board_state::message::MessageId;
use crate::board_state::privacy::SealedBytes;
use crate::board_state::roles::{
    resolve_signer_key, verify_admin_authority, AuthorityProof, RoleId,
};
use crate::board_state::ChatBoardParametersV1;
use crate::board_state::ChatBoardStateV1;
use crate::util::{sign_struct, verify_struct};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use freenet_scaffold::ComposableState;
use freenet_stdlib::prelude::ContractInstanceId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::time::SystemTime;

pub const MAX_SECTIONS: usize = 500;
pub const MAX_SECTION_NAME: usize = 200;
pub const MAX_SECTION_DESCRIPTION: usize = 2_000;
pub const MAX_SECTION_CHAIN: usize = 64;

pub type SectionId = MessageId;

/// Parameters of a section child board. The parent board keeps its existing
/// owner-only parameters.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct SectionParametersV1 {
    pub owner: VerifyingKey,
    pub section: SectionId,
    /// Topic-entry page; 0 is the section manifest itself.
    #[serde(default)]
    pub page: u32,
}

impl SectionParametersV1 {
    pub fn owner_id(&self) -> MemberId {
        self.owner.into()
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct SectionV1 {
    pub id: SectionId,
    pub parent: Option<SectionId>,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    pub color: String,
    #[serde(default)]
    pub allowed_roles: Vec<RoleId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed_name: Option<SealedBytes>,
    #[serde(default)]
    pub hidden: bool,
    #[serde(default)]
    pub is_group: bool,
    #[serde(default = "default_true")]
    pub images_allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_moderated_topics: Option<bool>,
    pub generation: u64,
    #[serde(default)]
    pub deleted: bool,
    /// Child board that owns this section's topic index.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract: Option<ContractInstanceId>,
    #[serde(default = "epoch", skip_serializing_if = "is_epoch")]
    pub signed_at: SystemTime,
}

fn default_true() -> bool {
    true
}

fn epoch() -> SystemTime {
    SystemTime::UNIX_EPOCH
}

fn is_epoch(value: &SystemTime) -> bool {
    *value == SystemTime::UNIX_EPOCH
}

impl SectionV1 {
    pub fn verify_basics(&self) -> Result<(), String> {
        if self.generation == 0 {
            return Err("section generation must be positive".to_string());
        }
        if self.name.chars().count() > MAX_SECTION_NAME {
            return Err("section name is too long".to_string());
        }
        if self
            .description
            .as_ref()
            .is_some_and(|value| value.chars().count() > MAX_SECTION_DESCRIPTION)
        {
            return Err("section description is too long".to_string());
        }
        if self.parent == Some(self.id) {
            return Err("a section cannot be its own parent".to_string());
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct AuthorizedSectionV1 {
    pub section: SectionV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<MemberId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_key: Option<VerifyingKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<Box<AuthorityProof>>,
    pub signature: Signature,
}

impl AuthorizedSectionV1 {
    pub fn new(
        section: SectionV1,
        signing_key: &SigningKey,
        authority: Option<AuthorityProof>,
    ) -> Self {
        let signer = MemberId::from(&signing_key.verifying_key());
        Self {
            signature: sign_struct(&section, signing_key),
            section,
            signer: Some(signer),
            signer_key: Some(signing_key.verifying_key()),
            authority: authority.map(Box::new),
        }
    }

    pub fn signer_id(&self, parameters: &ChatBoardParametersV1) -> MemberId {
        self.signer.unwrap_or_else(|| parameters.owner_id())
    }

    pub fn digest(&self) -> i64 {
        let mut bytes = Vec::new();
        let _ = ciborium::ser::into_writer(&self.section, &mut bytes);
        freenet_scaffold::util::fast_hash(&bytes).0
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct SectionsV1 {
    pub sections: Vec<AuthorizedSectionV1>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct SectionState {
    pub generation: u64,
    pub deleted: bool,
    pub digest: i64,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct SectionsSummary {
    pub sections: BTreeMap<SectionId, SectionState>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct SectionsDelta {
    pub sections: Vec<AuthorizedSectionV1>,
}

impl SectionsV1 {
    pub fn section(&self, id: &SectionId) -> Option<&SectionV1> {
        self.sections
            .iter()
            .find(|entry| entry.section.id == *id && !entry.section.deleted)
            .map(|entry| &entry.section)
    }

    pub fn section_including_deleted(&self, id: &SectionId) -> Option<&SectionV1> {
        self.sections
            .iter()
            .find(|entry| entry.section.id == *id)
            .map(|entry| &entry.section)
    }

    pub fn exists(&self, id: &SectionId) -> bool {
        self.section(id).is_some()
    }

    /// The section followed by its ancestors, stopping at a missing or
    /// deleted parent.
    pub fn chain(&self, id: &SectionId) -> Vec<SectionId> {
        let mut chain = Vec::new();
        let mut current = Some(*id);
        for _ in 0..MAX_SECTION_CHAIN {
            let Some(section_id) = current else {
                break;
            };
            if chain.contains(&section_id) {
                break;
            }
            let Some(section) = self.section(&section_id) else {
                break;
            };
            chain.push(section_id);
            current = section.parent;
        }
        chain
    }

    pub fn next_generation(&self, id: &SectionId) -> u64 {
        self.section_including_deleted(id)
            .map(|section| section.generation + 1)
            .unwrap_or(1)
    }

    fn verify_entry(
        &self,
        state: &ChatBoardStateV1,
        parameters: &ChatBoardParametersV1,
        entry: &AuthorizedSectionV1,
    ) -> Result<(), String> {
        entry.section.verify_basics()?;
        let signer = entry.signer_id(parameters);
        let key = resolve_signer_key(state, parameters, &signer, entry.signer_key.as_ref())?;
        verify_struct(&entry.section, &entry.signature, &key)
            .map_err(|error| format!("invalid section signature: {error}"))?;
        verify_admin_authority(
            state,
            parameters,
            &signer,
            entry.authority.as_deref(),
            8,
            entry.section.signed_at,
        )
    }

    fn sort(&mut self) {
        self.sections
            .sort_by_key(|entry| (entry.section.id.0 .0, entry.section.generation));
    }

    fn retain_valid(
        &mut self,
        state: &ChatBoardStateV1,
        parameters: &ChatBoardParametersV1,
    ) {
        let mut sections = std::mem::take(&mut self.sections);
        sections.retain(|entry| self.verify_entry(state, parameters, entry).is_ok());
        self.sections = sections;
        self.sort();
        self.sections.dedup_by_key(|entry| entry.section.id);
    }
}

impl ComposableState for SectionsV1 {
    type ParentState = ChatBoardStateV1;
    type Summary = SectionsSummary;
    type Delta = SectionsDelta;
    type Parameters = ChatBoardParametersV1;

    fn verify(
        &self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
    ) -> Result<(), String> {
        if self.sections.len() > MAX_SECTIONS {
            return Err("too many sections".to_string());
        }
        let mut ids = HashSet::new();
        for entry in &self.sections {
            if !ids.insert(entry.section.id) {
                return Err("duplicate section".to_string());
            }
            self.verify_entry(parent_state, parameters, entry)?;
        }
        // Parent links must not form a cycle.
        for entry in &self.sections {
            let mut seen = HashSet::new();
            let mut current = entry.section.parent;
            for _ in 0..MAX_SECTION_CHAIN {
                let Some(id) = current else {
                    break;
                };
                if id == entry.section.id {
                    return Err("section parent cycle".to_string());
                }
                if !seen.insert(id) {
                    return Err("section parent cycle".to_string());
                }
                current = self
                    .section_including_deleted(&id)
                    .and_then(|section| section.parent);
            }
        }
        Ok(())
    }

    fn summarize(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
    ) -> Self::Summary {
        SectionsSummary {
            sections: self
                .sections
                .iter()
                .map(|entry| {
                    (
                        entry.section.id,
                        SectionState {
                            generation: entry.section.generation,
                            deleted: entry.section.deleted,
                            digest: entry.digest(),
                        },
                    )
                })
                .collect(),
        }
    }

    fn delta(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
        old_state_summary: &Self::Summary,
    ) -> Option<Self::Delta> {
        let sections: Vec<_> = self
            .sections
            .iter()
            .filter(|entry| {
                let state = SectionState {
                    generation: entry.section.generation,
                    deleted: entry.section.deleted,
                    digest: entry.digest(),
                };
                old_state_summary
                    .sections
                    .get(&entry.section.id)
                    .map(|known| *known != state)
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        if sections.is_empty() {
            None
        } else {
            Some(SectionsDelta { sections })
        }
    }

    fn apply_delta(
        &mut self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
        delta: &Option<Self::Delta>,
    ) -> Result<(), String> {
        if let Some(delta) = delta {
            for entry in &delta.sections {
                self.verify_entry(parent_state, parameters, entry)?;
                match self
                    .sections
                    .iter_mut()
                    .find(|existing| existing.section.id == entry.section.id)
                {
                    Some(existing) => {
                        let take = entry.section.generation > existing.section.generation
                            || (entry.section.generation == existing.section.generation
                                && entry.section.deleted && !existing.section.deleted)
                            || (entry.section.generation == existing.section.generation
                                && entry.section.deleted == existing.section.deleted
                                && entry.digest() < existing.digest());
                        if take {
                            *existing = entry.clone();
                        }
                    }
                    None => self.sections.push(entry.clone()),
                }
            }
        }
        if self.sections.len() > MAX_SECTIONS {
            return Err("too many sections".to_string());
        }
        self.sort();
        self.sections.dedup_by_key(|entry| entry.section.id);
        Ok(())
    }
}

impl SectionsV1 {
    pub fn cleanup(
        &mut self,
        state: &ChatBoardStateV1,
        parameters: &ChatBoardParametersV1,
    ) {
        self.retain_valid(state, parameters);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board_state::configuration::{
        AuthorizedConfigurationV1, Configuration,
    };
    use crate::board_state::member::{AuthorizedMember, Member};
    use ed25519_dalek::SigningKey;

    fn owner() -> SigningKey {
        SigningKey::from_bytes(&[1u8; 32])
    }

    fn member() -> SigningKey {
        SigningKey::from_bytes(&[2u8; 32])
    }

    fn params() -> ChatBoardParametersV1 {
        ChatBoardParametersV1 {
            owner: owner().verifying_key(),
        }
    }

    fn board() -> ChatBoardStateV1 {
        let owner = owner();
        let member = member();
        let owner_id = MemberId::from(&owner.verifying_key());
        let mut state = ChatBoardStateV1 {
            configuration: AuthorizedConfigurationV1::new(
                Configuration::default(),
                &owner,
            ),
            ..Default::default()
        };
        state.members.members.push(AuthorizedMember::new(
            Member {
                owner_member_id: owner_id,
                invited_by: owner_id,
                member_vk: member.verifying_key(),
                join_proof: None,
            },
            &owner,
        ));
        state
    }

    fn section(id: u8, parent: Option<u8>) -> SectionV1 {
        SectionV1 {
            id: SectionId::from_bytes([id; 32]),
            parent: parent.map(|value| SectionId::from_bytes([value; 32])),
            name: format!("section {id}"),
            description: None,
            icon: None,
            color: "#6366f1".to_string(),
            allowed_roles: Vec::new(),
            sealed_name: None,
            hidden: false,
            is_group: false,
            images_allowed: true,
            auto_moderated_topics: None,
            generation: 1,
            deleted: false,
            contract: None,
            signed_at: SystemTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn the_owner_creates_a_section() {
        let state = board();
        let mut sections = SectionsV1::default();
        sections.sections.push(AuthorizedSectionV1::new(
            section(1, None),
            &owner(),
            None,
        ));
        sections.verify(&state, &params()).unwrap();
        assert!(sections.exists(&SectionId::from_bytes([1u8; 32])));
    }

    #[test]
    fn a_member_cannot_create_a_section() {
        let state = board();
        let mut sections = SectionsV1::default();
        sections.sections.push(AuthorizedSectionV1::new(
            section(1, None),
            &member(),
            None,
        ));
        assert!(sections.verify(&state, &params()).is_err());
    }

    #[test]
    fn a_parent_cycle_is_rejected() {
        let state = board();
        let mut sections = SectionsV1::default();
        sections.sections.push(AuthorizedSectionV1::new(
            section(1, Some(2)),
            &owner(),
            None,
        ));
        sections.sections.push(AuthorizedSectionV1::new(
            section(2, Some(1)),
            &owner(),
            None,
        ));
        assert!(sections.verify(&state, &params()).is_err());
    }

    #[test]
    fn a_newer_generation_wins() {
        let state = board();
        let mut sections = SectionsV1::default();
        sections.sections.push(AuthorizedSectionV1::new(
            section(1, None),
            &owner(),
            None,
        ));
        let mut renamed = section(1, None);
        renamed.name = "renamed".to_string();
        renamed.generation = 2;
        let delta = SectionsDelta {
            sections: vec![AuthorizedSectionV1::new(
                renamed,
                &owner(),
                None,
            )],
        };
        sections
            .apply_delta(&state, &params(), &Some(delta))
            .unwrap();
        assert_eq!(
            sections.section(&SectionId::from_bytes([1u8; 32])).unwrap().name,
            "renamed"
        );
    }

    #[test]
    fn the_chain_includes_ancestors() {
        let state = board();
        let mut sections = SectionsV1::default();
        sections.sections.push(AuthorizedSectionV1::new(
            section(1, None),
            &owner(),
            None,
        ));
        sections.sections.push(AuthorizedSectionV1::new(
            section(2, Some(1)),
            &owner(),
            None,
        ));
        sections.verify(&state, &params()).unwrap();
        let chain = sections.chain(&SectionId::from_bytes([2u8; 32]));
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[1], SectionId::from_bytes([1u8; 32]));
    }
}
