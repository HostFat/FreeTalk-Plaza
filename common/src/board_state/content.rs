//! Structured content types for topic polls and section/category metadata.
//!
//! # Extensibility
//!
//! - New fields on existing types: Just add them with `#[serde(default)]` (old clients ignore unknown fields)

use crate::board_state::message::MessageId;
use serde::{Deserialize, Serialize};
use unicode_segmentation::UnicodeSegmentation;

pub const MAX_POLL_OPTIONS: usize = 10;
pub const MAX_POLL_OPTION_LEN: usize = 100;
pub const MAX_POLL_TITLE_LEN: usize = 100;
pub const MAX_POLL_DESCRIPTION_LEN: usize = 2000;

/// When the tally of a poll is shown to readers.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum PollResultsVisibility {
    #[default]
    Always,
    AfterVote,
    AfterClose,
}

/// Poll post content. Votes are separate topic actions.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct PollContentV1 {
    pub title: String,
    pub description: String,
    pub options: Vec<String>,
    /// Unix milliseconds after which votes are ignored.
    pub closes_at: Option<i64>,
    pub multiselect: bool,
    /// Older polls omit the field and keep showing results.
    #[serde(default)]
    pub results_visibility: PollResultsVisibility,
    /// The author moderates replies to this topic. Omitted at false so older
    /// polls keep their bytes.
    #[serde(default, skip_serializing_if = "is_false")]
    pub auto_moderated: bool,
    /// Section this poll belongs to. Omitted at the board root so old polls
    /// keep their bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category_id: Option<MessageId>,
    /// Optional topic membership key carried with legacy poll payloads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic_membership_key: Option<ed25519_dalek::SigningKey>,
}

impl PollContentV1 {
    pub fn new(
        title: String,
        description: String,
        options: Vec<String>,
        closes_at: Option<i64>,
        multiselect: bool,
    ) -> Self {
        Self {
            title,
            description,
            options,
            closes_at,
            multiselect,
            results_visibility: PollResultsVisibility::Always,
            auto_moderated: false,
            category_id: None,
            topic_membership_key: None,
        }
    }

    pub fn with_category(mut self, category_id: Option<MessageId>) -> Self {
        self.category_id = category_id;
        self
    }

    /// Attach the topic capability key. Its public half is published on the
    /// poll message.
    pub fn with_topic_membership_key(
        mut self,
        key: Option<ed25519_dalek::SigningKey>,
    ) -> Self {
        self.topic_membership_key = key;
        self
    }

    pub fn with_results_visibility(mut self, visibility: PollResultsVisibility) -> Self {
        self.results_visibility = visibility;
        self
    }

    /// Let the topic author delete replies.
    pub fn with_auto_moderated(mut self, auto_moderated: bool) -> Self {
        self.auto_moderated = auto_moderated;
        self
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.title.trim().is_empty() {
            return Err("A poll needs a question".to_string());
        }
        if self.title.chars().count() > MAX_POLL_TITLE_LEN {
            return Err(format!(
                "Poll title is longer than {} characters",
                MAX_POLL_TITLE_LEN
            ));
        }
        if self.description.chars().count() > MAX_POLL_DESCRIPTION_LEN {
            return Err(format!(
                "Poll description is longer than {} characters",
                MAX_POLL_DESCRIPTION_LEN
            ));
        }
        if self.options.len() < 2 {
            return Err("A poll needs at least two options".to_string());
        }
        if self.options.len() > MAX_POLL_OPTIONS {
            return Err(format!(
                "A poll can have at most {} options",
                MAX_POLL_OPTIONS
            ));
        }
        let mut seen = std::collections::HashSet::new();
        for option in &self.options {
            let trimmed = option.trim();
            if trimmed.is_empty() {
                return Err("Poll options cannot be empty".to_string());
            }
            if trimmed.chars().count() > MAX_POLL_OPTION_LEN {
                return Err(format!(
                    "Poll options are limited to {} characters",
                    MAX_POLL_OPTION_LEN
                ));
            }
            if !seen.insert(trimmed.to_lowercase()) {
                return Err("Poll options must be different".to_string());
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        encode_cbor(self)
    }

    pub fn decode(data: &[u8]) -> Result<Self, String> {
        decode_cbor(data, "PollContentV1")
    }
}

/// A vote for a poll. Indexes refer to the poll options.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct PollVoteV1 {
    pub poll: MessageId,
    pub options: Vec<u16>,
    pub generation: u64,
    pub created_at: i64,
}

impl PollVoteV1 {
    pub fn encode(&self) -> Vec<u8> {
        encode_cbor(self)
    }

    pub fn decode(data: &[u8]) -> Result<Self, String> {
        decode_cbor(data, "PollVoteV1")
    }

    /// Check one vote against the poll it targets. The caller also checks the
    /// deadline, so a late vote is ignored rather than treated as corrupt.
    pub fn validate_for(&self, poll: &PollContentV1) -> Result<(), String> {
        if self.options.is_empty() {
            return Err("A vote needs at least one option".to_string());
        }
        if !poll.multiselect && self.options.len() != 1 {
            return Err("This poll accepts one option per vote".to_string());
        }
        let mut seen = std::collections::HashSet::new();
        for index in &self.options {
            if *index as usize >= poll.options.len() {
                return Err("Vote option is out of range".to_string());
            }
            if !seen.insert(*index) {
                return Err("Vote repeats an option".to_string());
            }
        }
        Ok(())
    }
}

/// Encode a value to CBOR bytes
fn encode_cbor<T: Serialize>(value: &T) -> Vec<u8> {
    let mut data = Vec::new();
    ciborium::into_writer(value, &mut data).expect("CBOR serialization should not fail");
    data
}

/// Decode a value from CBOR bytes
fn decode_cbor<T: serde::de::DeserializeOwned>(data: &[u8], type_name: &str) -> Result<T, String> {
    ciborium::from_reader(data).map_err(|e| format!("Failed to decode {}: {}", type_name, e))
}

/// Keeps new default fields out of the bytes that signatures cover.
pub(crate) fn is_false(value: &bool) -> bool {
    !*value
}

pub(crate) fn is_true(value: &bool) -> bool {
    *value
}

fn default_true() -> bool {
    true
}

/// Category/section metadata used by ACL and display helpers.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct CategoryContentV1 {
    /// Category name/title
    pub name: String,
    /// Optional description
    pub description: Option<String>,
    /// Optional icon (emoji)
    pub icon: Option<String>,
    /// Color for UI display (hex like "#6366f1")
    pub color: String,
    /// Parent category ID (None for top-level categories)
    pub parent_category_id: Option<MessageId>,
    /// Roles allowed to read and post here. Empty means everyone on the board.
    /// Omitted when empty so old signed categories round-trip unchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_roles: Vec<crate::board_state::roles::RoleId>,
    /// Sealed real name, used when `allowed_roles` is not empty. Only members
    /// holding the category secret can read it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed_name: Option<crate::board_state::privacy::SealedBytes>,
    /// Keep the category out of listings for members without the secret.
    #[serde(default, skip_serializing_if = "is_false")]
    pub hidden: bool,
    /// A group is a homepage-only heading that contains sections. Groups have
    /// no posts. Omitted at false so old categories keep their bytes.
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_group: bool,
    /// Whether posts in this section may carry images. True unless the owner
    /// disables it; omitted at true so old categories keep their bytes.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub images_allowed: bool,
    /// Section override for auto-moderated topics. `None` inherits the board
    /// configuration; omitted when unset so old categories keep their bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_moderated_topics: Option<bool>,
}

impl CategoryContentV1 {
    /// Create a new category. Color is required.
    pub fn new(name: String, description: Option<String>, color: String) -> Self {
        Self {
            name,
            description,
            icon: None,
            color,
            parent_category_id: None,
            allowed_roles: Vec::new(),
            sealed_name: None,
            hidden: false,
            is_group: false,
            images_allowed: true,
            auto_moderated_topics: None,
        }
    }

    /// Turn image attachments on or off for this section.
    pub fn with_images_allowed(mut self, allowed: bool) -> Self {
        self.images_allowed = allowed;
        self
    }

    /// Override the board's auto-moderated topic capability for this section.
    pub fn with_auto_moderated_topics(mut self, allowed: Option<bool>) -> Self {
        self.auto_moderated_topics = allowed;
        self
    }

    /// Turn this category into a homepage group. Groups are never restricted
    /// and never contain posts.
    pub fn with_group(mut self) -> Self {
        self.is_group = true;
        self.allowed_roles.clear();
        self.sealed_name = None;
        self.hidden = false;
        self
    }

    /// Restrict the category to the given roles. The real name must be supplied
    /// sealed; `name` is only a placeholder for clients without the secret.
    pub fn with_allowed_roles(
        mut self,
        roles: Vec<crate::board_state::roles::RoleId>,
        sealed_name: crate::board_state::privacy::SealedBytes,
        hidden: bool,
    ) -> Self {
        self.allowed_roles = roles;
        self.sealed_name = Some(sealed_name);
        self.hidden = hidden;
        self
    }

    pub fn is_restricted(&self) -> bool {
        !self.allowed_roles.is_empty()
    }

    /// Set the icon, enforcing that it is exactly one grapheme cluster.
    /// If the input contains multiple graphemes, only the first is used.
    /// If the input is empty, no icon is set.
    pub fn with_icon(mut self, icon: String) -> Self {
        self.icon = normalize_icon(&icon);
        self
    }

    pub fn with_parent(mut self, parent_id: MessageId) -> Self {
        self.parent_category_id = Some(parent_id);
        self
    }

    pub fn encode(&self) -> Vec<u8> {
        encode_cbor(self)
    }

    pub fn decode(data: &[u8]) -> Result<Self, String> {
        decode_cbor(data, "CategoryContentV1")
    }
}

/// Normalize an icon string to exactly one grapheme cluster.
/// Returns None if the input is empty, otherwise returns the first grapheme.
pub fn normalize_icon(icon: &str) -> Option<String> {
    let trimmed = icon.trim();
    if trimmed.is_empty() {
        return None;
    }
    trimmed.graphemes(true).next().map(|g| g.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_message_id() -> MessageId {
        MessageId::from_bytes([1u8; 32])
    }

    #[test]
    fn test_category_content_roundtrip() {
        let category = CategoryContentV1::new(
            "General".to_string(),
            Some("General discussion".to_string()),
            "#6366f1".to_string(),
        )
        .with_icon("💬".to_string());
        let encoded = category.encode();
        let decoded = CategoryContentV1::decode(&encoded).unwrap();
        assert_eq!(category, decoded);
        assert_eq!(decoded.name, "General");
        assert_eq!(decoded.icon, Some("💬".to_string()));
        assert_eq!(decoded.color, "#6366f1".to_string());
    }

    /// The new flags stay out of the bytes at their defaults, so old signed
    /// polls and sections keep verifying.
    #[test]
    fn auto_moderation_fields_are_omitted_at_their_defaults() {
        let poll = PollContentV1::new(
            "Question".to_string(),
            "Body".to_string(),
            vec!["A".to_string(), "B".to_string()],
            None,
            false,
        );
        assert!(!poll.auto_moderated);
        assert!(poll.clone().with_auto_moderated(true).auto_moderated);

        let section = CategoryContentV1::new(
            "General".to_string(),
            None,
            "#6366f1".to_string(),
        );
        assert_eq!(section.auto_moderated_topics, None);
        let mut bytes = Vec::new();
        ciborium::into_writer(&section, &mut bytes).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("auto_moderated_topics"));

        let open = section.with_auto_moderated_topics(Some(true));
        let decoded = CategoryContentV1::decode(&open.encode()).unwrap();
        assert_eq!(decoded.auto_moderated_topics, Some(true));
    }

    /// The topic membership key rides with the content and stays out of the
    /// bytes when unset, so old signed content keeps verifying.
    #[test]
    fn topic_membership_key_roundtrips_and_is_omitted_when_unset() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let poll = PollContentV1::new(
            "Question".to_string(),
            "Body".to_string(),
            vec!["A".to_string(), "B".to_string()],
            None,
            false,
        );
        let mut bytes = Vec::new();
        ciborium::into_writer(&poll, &mut bytes).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("topic_membership_key"));

        let with_key = poll.with_topic_membership_key(Some(key.clone()));
        let decoded = PollContentV1::decode(&with_key.encode()).unwrap();
        assert_eq!(
            decoded.topic_membership_key.map(|key| key.verifying_key()),
            Some(key.verifying_key())
        );
    }

    #[test]
    fn test_category_with_parent() {
        let parent_id = test_message_id();
        let category =
            CategoryContentV1::new("Subcategory".to_string(), None, "#ef4444".to_string())
                .with_parent(parent_id);
        let encoded = category.encode();
        let decoded = CategoryContentV1::decode(&encoded).unwrap();
        assert_eq!(decoded.parent_category_id, Some(parent_id));
    }

    /// Adding `is_group` must not change the bytes of existing categories.
    #[test]
    fn a_category_without_group_roundtrips_unchanged() {
        let category = CategoryContentV1::new(
            "General".to_string(),
            Some("General discussion".to_string()),
            "#6366f1".to_string(),
        );
        let mut bytes = Vec::new();
        ciborium::into_writer(&category, &mut bytes).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("is_group"));

        let decoded: CategoryContentV1 = ciborium::from_reader(&bytes[..]).unwrap();
        let mut again = Vec::new();
        ciborium::into_writer(&decoded, &mut again).unwrap();
        assert_eq!(bytes, again);
    }

    #[test]
    fn a_group_roundtrips() {
        let group = CategoryContentV1::new(
            "Local".to_string(),
            Some("Language sections".to_string()),
            "#6366f1".to_string(),
        )
        .with_group();
        assert!(group.is_group);
        let decoded = CategoryContentV1::decode(&group.encode()).unwrap();
        assert!(decoded.is_group);
    }
}

#[cfg(test)]
mod poll_tests {
    use super::*;

    fn poll(multiselect: bool) -> PollContentV1 {
        PollContentV1::new(
            "Best option?".to_string(),
            "Pick one".to_string(),
            vec!["A".to_string(), "B".to_string(), "C".to_string()],
            None,
            multiselect,
        )
    }

    #[test]
    fn poll_visibility_roundtrips() {
        let visible = poll(false).with_results_visibility(PollResultsVisibility::AfterVote);
        assert_eq!(
            PollContentV1::decode(&visible.encode())
                .unwrap()
                .results_visibility,
            PollResultsVisibility::AfterVote
        );
        assert_eq!(
            poll(false).results_visibility,
            PollResultsVisibility::Always
        );
    }

    #[test]
    fn poll_roundtrips_and_validates_options() {
        let poll = poll(false);
        assert!(poll.validate().is_ok());
        assert_eq!(poll, PollContentV1::decode(&poll.encode()).unwrap());

        let mut duplicate = poll.clone();
        duplicate.options = vec!["A".to_string(), "a".to_string()];
        assert!(duplicate.validate().is_err());

        let mut one = poll;
        one.options = vec!["Only".to_string()];
        assert!(one.validate().is_err());
    }

    #[test]
    fn votes_check_the_range_and_the_option_count() {
        let poll = poll(false);
        let vote = PollVoteV1 {
            poll: MessageId::from_bytes([9u8; 32]),
            options: vec![1],
            generation: 1,
            created_at: 10,
        };
        assert!(vote.validate_for(&poll).is_ok());

        let mut outside = vote.clone();
        outside.options = vec![3];
        assert!(outside.validate_for(&poll).is_err());

        let mut many = vote;
        many.options = vec![0, 1];
        assert!(many.validate_for(&poll).is_err());
        let multiselect = PollContentV1::new(
            "Best option?".to_string(),
            String::new(),
            vec!["A".to_string(), "B".to_string(), "C".to_string()],
            None,
            true,
        );
        assert!(many.validate_for(&multiselect).is_ok());
    }
}
