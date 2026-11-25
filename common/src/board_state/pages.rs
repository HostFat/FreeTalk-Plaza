//! Topic-entry pages of a section.
//!
//! A section manifest (page 0) keeps the authority and an owner-signed list of
//! extra page numbers. Each page is a separate section contract with
//! parameters `{ owner, section, page }`; new topics go to the active page and
//! an update touches one page instead of the whole section index.

use crate::board_state::member::MemberId;
use crate::board_state::rate_limit::system_time_from_ms;
use crate::board_state::sections::SectionId;
use crate::board_state::ChatBoardParametersV1;
use crate::util::{sign_struct, verify_struct};
use crate::ChatBoardStateV1;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use freenet_scaffold::ComposableState;
use serde::{Deserialize, Serialize};

pub const MAX_TOPIC_PAGES: usize = 1_000;
/// Default number of topics in a page. New sections sign this value.
pub const DEFAULT_TOPIC_PAGE_SIZE: u32 = 200;
/// Largest page size a section may sign. The page contract enforces the same
/// bound, so a client cannot grow a page past it.
pub const MAX_TOPIC_PAGE_SIZE: u32 = 500;
/// Hard cap on the entries of one section page, enforced by the contract.
pub const MAX_TOPICS_PER_PAGE: usize = MAX_TOPIC_PAGE_SIZE as usize;

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct TopicPageListDataV1 {
    pub section: SectionId,
    /// Number of topics a page holds before the owner creates the next one.
    /// Signed so every client agrees on where a page ends.
    #[serde(default = "default_topic_page_size")]
    pub page_size: u32,
    /// Extra pages; page 0 is the section manifest itself.
    pub pages: Vec<u32>,
    pub updated_at: i64,
}

fn default_topic_page_size() -> u32 {
    DEFAULT_TOPIC_PAGE_SIZE
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedTopicPageListV1 {
    pub data: TopicPageListDataV1,
    pub signer: MemberId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_key: Option<VerifyingKey>,
    pub signature: Signature,
}

impl AuthorizedTopicPageListV1 {
    pub fn new(
        section: SectionId,
        mut pages: Vec<u32>,
        page_size: u32,
        owner: &SigningKey,
        updated_at: i64,
    ) -> Self {
        pages.retain(|page| *page > 0);
        pages.sort_unstable();
        pages.dedup();
        let data = TopicPageListDataV1 {
            section,
            page_size: page_size.clamp(1, MAX_TOPIC_PAGE_SIZE),
            pages,
            updated_at,
        };
        Self {
            signature: sign_struct(&data, owner),
            data,
            signer: MemberId::from(&owner.verifying_key()),
            signer_key: Some(owner.verifying_key()),
        }
    }

    pub fn verify(&self, owner_key: &VerifyingKey) -> Result<(), String> {
        if self.signer != MemberId::from(owner_key) {
            return Err("topic pages are signed by someone other than the owner".to_string());
        }
        if self.data.pages.len() > MAX_TOPIC_PAGES {
            return Err("too many topic pages".to_string());
        }
        if self.data.page_size == 0 || self.data.page_size > MAX_TOPIC_PAGE_SIZE {
            return Err("the topic page size is out of range".to_string());
        }
        if self.data.pages.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err("topic pages are not sorted and unique".to_string());
        }
        if self.data.pages.iter().any(|page| *page == 0) {
            return Err("page 0 is the section manifest".to_string());
        }
        verify_struct(&self.data, &self.signature, owner_key)
            .map_err(|error| format!("invalid topic page signature: {error}"))
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct TopicPageListV1(pub Option<AuthorizedTopicPageListV1>);

impl TopicPageListV1 {
    /// Page 0 plus the owner-signed extra pages.
    pub fn pages(&self) -> Vec<u32> {
        let mut pages = vec![0u32];
        if let Some(list) = &self.0 {
            pages.extend(list.data.pages.iter().copied());
        }
        pages
    }

    pub fn section(&self) -> Option<SectionId> {
        self.0.as_ref().map(|list| list.data.section)
    }

    /// Signed page size, when the manifest carries a page list.
    pub fn page_size(&self) -> Option<u32> {
        self.0.as_ref().map(|list| list.data.page_size)
    }

    pub fn is_none(&self) -> bool {
        self.0.is_none()
    }
}

impl ComposableState for TopicPageListV1 {
    type ParentState = ChatBoardStateV1;
    type Summary = Option<AuthorizedTopicPageListV1>;
    type Delta = AuthorizedTopicPageListV1;
    type Parameters = ChatBoardParametersV1;

    fn verify(
        &self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
    ) -> Result<(), String> {
        let Some(list) = &self.0 else {
            return Ok(());
        };
        let owner_key = parent_state
            .ownership
            .owner_key_at(parameters, system_time_from_ms(list.data.updated_at));
        list.verify(&owner_key)
    }

    fn summarize(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
    ) -> Self::Summary {
        self.0.clone()
    }

    fn delta(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
        old_state_summary: &Self::Summary,
    ) -> Option<Self::Delta> {
        let current = self.0.as_ref()?;
        match old_state_summary {
            Some(previous) if previous.data.updated_at >= current.data.updated_at => None,
            _ => Some(current.clone()),
        }
    }

    fn apply_delta(
        &mut self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
        delta: &Option<Self::Delta>,
    ) -> Result<(), String> {
        if let Some(list) = delta {
            self.0 = Some(list.clone());
        }
        self.verify(parent_state, parameters)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use freenet_scaffold::ComposableState;

    fn params(owner: &SigningKey) -> ChatBoardParametersV1 {
        ChatBoardParametersV1 {
            owner: owner.verifying_key(),
        }
    }

    #[test]
    fn a_signed_page_list_verifies() {
        let owner = SigningKey::from_bytes(&[1u8; 32]);
        let section = SectionId::from_bytes([7u8; 32]);
        let list =
            AuthorizedTopicPageListV1::new(section, vec![2, 1, 2, 0], 50, &owner, 10);
        let state = TopicPageListV1(Some(list));
        let parent = ChatBoardStateV1::default();
        state.verify(&parent, &params(&owner)).unwrap();
        assert_eq!(state.pages(), vec![0, 1, 2]);
        assert_eq!(state.page_size(), Some(50));
    }

    #[test]
    fn a_page_size_out_of_range_is_rejected() {
        let owner = SigningKey::from_bytes(&[1u8; 32]);
        let section = SectionId::from_bytes([7u8; 32]);
        let mut state = TopicPageListV1(Some(AuthorizedTopicPageListV1::new(
            section,
            vec![1],
            50,
            &owner,
            10,
        )));
        if let Some(list) = &mut state.0 {
            list.data.page_size = 0;
        }
        let parent = ChatBoardStateV1::default();
        assert!(state.verify(&parent, &params(&owner)).is_err());

        if let Some(list) = &mut state.0 {
            list.data.page_size = MAX_TOPIC_PAGE_SIZE + 1;
        }
        assert!(state.verify(&parent, &params(&owner)).is_err());
    }

    #[test]
    fn a_new_page_size_is_clamped_to_the_contract_bound() {
        let owner = SigningKey::from_bytes(&[1u8; 32]);
        let section = SectionId::from_bytes([7u8; 32]);
        let list =
            AuthorizedTopicPageListV1::new(section, vec![1], u32::MAX, &owner, 10);
        assert_eq!(list.data.page_size, MAX_TOPIC_PAGE_SIZE);
    }

    #[test]
    fn a_tampered_page_list_is_rejected() {
        let owner = SigningKey::from_bytes(&[1u8; 32]);
        let section = SectionId::from_bytes([7u8; 32]);
        let mut state = TopicPageListV1(Some(AuthorizedTopicPageListV1::new(
            section,
            vec![1],
            50,
            &owner,
            10,
        )));
        if let Some(list) = &mut state.0 {
            list.data.pages.push(2);
        }
        let parent = ChatBoardStateV1::default();
        assert!(state.verify(&parent, &params(&owner)).is_err());
    }
}
