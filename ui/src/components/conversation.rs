use crate::components::app::receive_times::get_delay_secs;
use crate::components::app::{
    Route, BOARDS, CONVERSATION_PINNED, CURRENT_BOARD, INTERCEPTED_JOIN_TOKEN,
    MEMBER_INFO_MODAL,
};
use crate::util::avatar::get_avatar;
use crate::util::ecies::unseal_bytes_with_secrets;
use crate::util::images::{request_image, ImageStatus, IMAGES};
use crate::util::member_id_to_color;
use crate::util::messaging::{prepare_message, publish_prepared, ReplyContext};
use crate::util::{format_utc_as_full_datetime, format_utc_as_local_time};
pub mod emoji_picker;
pub mod image_attachment;
mod message_actions;
pub mod message_input;
mod not_member_notification;
pub mod poll_view;
use self::emoji_picker::FREQUENT_EMOJIS;
use self::image_attachment::ImageAttachment;
use self::not_member_notification::NotMemberNotification;
use crate::board_data::SendMessageError;
use crate::components::conversation::message_input::PostInput;
use chrono::{DateTime, Utc};
use dioxus::prelude::*;
use ed25519_dalek::VerifyingKey;
use plaza_core::board_state::content::CategoryContentV1;
use plaza_core::board_state::images::{ImageAlign, ImagePlacement, ImageRef};
use plaza_core::board_state::member::MemberId;
use plaza_core::board_state::message::{BoardMessageBody, MessageId, SecretScope};
use plaza_core::board_state::roles::RoleId;
use std::collections::HashMap;
use wasm_bindgen_futures::spawn_local;

/// One member's current vote in a poll.
#[derive(Clone, PartialEq, Debug)]
pub struct PollBallot {
    pub voter: MemberId,
    pub options: Vec<u16>,
    pub generation: u64,
    pub created_at: i64,
}

/// Poll question data with the latest vote per member.
#[derive(Clone, PartialEq, Debug)]
pub struct PollData {
    pub title: String,
    pub description: String,
    pub options: Vec<String>,
    pub closes_at: Option<i64>,
    pub multiselect: bool,
    pub results_visibility: plaza_core::board_state::content::PollResultsVisibility,
    pub votes: Vec<PollBallot>,
    /// The poll content was replaced after creation.
    pub edited: bool,
}

impl PollData {
    pub fn is_closed(&self, now_ms: i64) -> bool {
        self.closes_at
            .map(|closes| now_ms > closes)
            .unwrap_or(false)
    }

    /// Votes cast before the deadline, one per member.
    pub fn counted(&self) -> impl Iterator<Item = &PollBallot> {
        self.votes.iter().filter(|ballot| {
            self.closes_at
                .map(|closes| ballot.created_at <= closes)
                .unwrap_or(true)
        })
    }

    pub fn counts(&self) -> Vec<usize> {
        let mut counts = vec![0usize; self.options.len()];
        for ballot in self.counted() {
            for index in &ballot.options {
                if let Some(count) = counts.get_mut(*index as usize) {
                    *count += 1;
                }
            }
        }
        counts
    }

    pub fn my_ballot(&self, voter: MemberId) -> Option<&PollBallot> {
        self.votes.iter().find(|ballot| ballot.voter == voter)
    }
}

/// One saved version of an edited message, reconstructed from the signed edit
/// actions still present in the board state.
#[derive(Clone, PartialEq, Debug)]
pub struct EditVersion {
    pub time: DateTime<Utc>,
    pub author_name: String,
    pub title: String,
    pub text: String,
}

/// A single message for display
#[derive(Clone, PartialEq, Debug)]
pub struct MessageData {
    pub message_id: MessageId,
    pub author_id: MemberId,
    pub author_name: String,
    pub is_self: bool,
    pub title_text: String,
    pub content_text: String,
    pub content_html: String,
    pub time: DateTime<Utc>,
    pub time_clamped: bool,
    pub edited: bool,
    /// Original content first, then each edit that is still in the state.
    pub edit_history: Vec<EditVersion>,
    pub reactions: HashMap<String, Vec<MemberId>>,
    pub reply_to_message_id: Option<MessageId>,
    /// Root topic this message belongs to, when the author published it.
    pub topic_id: Option<MessageId>,
    pub reply_to_author: Option<String>,
    pub reply_to_preview: Option<String>,
    pub receive_delay_secs: Option<i64>,
    /// Section this message was posted in, independent of reply links.
    pub category_id: Option<MessageId>,
    /// Whether this message is a category
    pub is_category: bool,
    /// Category name (if is_category)
    pub category_name: Option<String>,
    /// Category description (if is_category)
    pub category_description: Option<String>,
    /// Category icon emoji (if is_category)
    pub category_icon: Option<String>,
    /// Category color hex (if is_category)
    pub category_color: Option<String>,
    /// Parent category ID (if this is a subcategory)
    pub parent_category_id: Option<MessageId>,
    /// Roles allowed in this category (empty for public categories)
    pub category_allowed_roles: Vec<RoleId>,
    /// Category is hidden from members without its secret
    pub category_hidden: bool,
    /// Category is restricted and we do not hold its secret
    pub category_locked: bool,
    /// Category is a homepage group containing sections
    pub is_group: bool,
    /// Section override for auto-moderated topics; `None` inherits the board.
    pub category_auto_moderated_topics: Option<bool>,
    /// Post is pinned in its section
    pub is_pinned: bool,
    /// Post is closed: readable but not editable, deletable or reactable
    pub is_closed: bool,
    /// Post waits for a moderator before other members see it
    pub is_pending: bool,
    /// Post is announced above every section
    pub is_announced: bool,
    /// Poll question and current votes
    pub poll: Option<PollData>,
    /// Destination topic when this topic was merged
    pub merged_into: Option<MessageId>,
    /// Images attached to this post.
    pub images: Vec<plaza_core::board_state::images::ImageRef>,
    /// The topic was created with the auto-moderated flag.
    pub is_auto_moderated: bool,
    /// The viewer wrote the auto-moderated topic this message replies under,
    /// so they may delete it (never the topic itself).
    pub can_delete_as_topic_author: bool,
}

/// A message with its nested replies
#[derive(Clone, PartialEq, Debug)]
pub struct MessageWithReplies {
    pub message: MessageData,
    pub replies: Vec<MessageWithReplies>,
}

impl MessageData {
    /// Check if this message is a top-level post (not a reply to another message)
    pub fn is_top_level_post(&self) -> bool {
        self.reply_to_message_id.is_none()
    }

    /// Get a string ID suitable for use in URLs/routes
    pub fn id_string(&self) -> String {
        self.message_id.to_string()
    }
}

/// Build a flat list of all messages
pub fn get_all_messages(
    state: &plaza_core::ChatBoardStateV1,
    self_member_id: MemberId,
    secrets: &HashMap<u32, [u8; 32]>,
    category_secrets: &HashMap<MessageId, (u32, [u8; 32])>,
    old_category_secrets: &HashMap<MessageId, HashMap<u32, [u8; 32]>>,
) -> Vec<MessageData> {
    let mut messages = Vec::new();
    let owner_id = state.configuration.configuration.owner_member_id;
    let routes = state.moderation.routes_map();
    // Public topic membership keys. A claimed topic link counts only when the
    // reply proves it with the matching key.
    let topic_keys: HashMap<MessageId, VerifyingKey> = state
        .recent_messages
        .messages
        .iter()
        .filter_map(|message| {
            message
                .message
                .topic_public_key
                .map(|key| (message.id(), key))
        })
        .collect();
    // Messages that claim a topic link even when the proof is missing, so a
    // bad link never falls back to the reply body for the delete rule.
    let claimed_topic_links: std::collections::HashSet<MessageId> = state
        .recent_messages
        .messages
        .iter()
        .filter(|message| message.message.topic_id.is_some())
        .map(|message| message.id())
        .collect();
    // Older sealed replies have no public link the contract could follow, so
    // they carry no auto-moderation rule.
    let sealed_legacy_replies: std::collections::HashSet<MessageId> = state
        .recent_messages
        .messages
        .iter()
        .filter(|message| {
            message.message.topic_id.is_none() && message.message.content.is_private()
        })
        .map(|message| message.id())
        .collect();
    let is_admin = state
        .admin
        .admins
        .iter()
        .any(|admin| admin.admin.id() == self_member_id);

    // Latest vote per member and poll. Ties prefer the later timestamp, then
    // the lower message id, so peers that see votes in any order agree.
    let mut ballots: HashMap<MessageId, HashMap<MemberId, PollBallot>> = HashMap::new();
    for message in &state.recent_messages.messages {
        let Some(vote) = decrypt_poll_vote(
            &message.message.content,
            secrets,
            category_secrets,
            old_category_secrets,
        ) else {
            continue;
        };
        let ballot = PollBallot {
            voter: message.message.author,
            options: vote.options,
            generation: vote.generation,
            created_at: vote.created_at,
        };
        let by_voter = ballots.entry(vote.poll).or_default();
        let replace = by_voter.get(&ballot.voter).map_or(true, |old| {
            (ballot.generation, ballot.created_at) > (old.generation, old.created_at)
        });
        if replace {
            by_voter.insert(ballot.voter, ballot);
        }
    }

    let name_of = |author: MemberId| -> String {
        if let Some(override_name) = state.recent_messages.nickname_override(&author) {
            return override_name.nickname.clone();
        }
        state
            .member_info
            .member_info
            .iter()
            .find(|info| info.member_info.member_id == author)
            .map(|info| {
                match unseal_bytes_with_secrets(&info.member_info.preferred_nickname, secrets) {
                    Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
                    Err(_) => info.member_info.preferred_nickname.to_string_lossy(),
                }
            })
            .unwrap_or_else(|| "Unknown".to_string())
    };

    // Every member with a nickname is mentionable. The owner may have no
    // member record, so add it explicitly.
    let mut mention_names = Vec::new();
    for info in &state.member_info.member_info {
        let id = info.member_info.member_id;
        mention_names.push((id, name_of(id)));
    }
    for member in &state.members.members {
        let id = member.member.id();
        mention_names.push((id, name_of(id)));
    }
    mention_names.push((owner_id, name_of(owner_id)));
    let mentions = crate::util::mentions::MentionDirectory::from_names(mention_names);

    // Edit actions stay in `recent_messages`; each one carries the new content
    // and the signed author/time. The original message is the first version.
    let mut edits_by_target: HashMap<MessageId, Vec<EditVersion>> = HashMap::new();
    for message in &state.recent_messages.messages {
        let Some(action) = decrypt_action(
            &message.message.content,
            secrets,
            category_secrets,
            old_category_secrets,
        ) else {
            continue;
        };
        if action.action_type
            != plaza_core::board_state::content::ACTION_TYPE_EDIT
        {
            continue;
        }
        if let Some(payload) = action.edit_payload() {
            edits_by_target
                .entry(action.target.clone())
                .or_default()
                .push(EditVersion {
                    time: DateTime::<Utc>::from(message.message.time),
                    author_name: name_of(message.message.author),
                    title: payload.new_title,
                    text: payload.new_text,
                });
        }
    }
    for versions in edits_by_target.values_mut() {
        versions.sort_by_key(|version| version.time);
    }

    for message in state.recent_messages.display_messages() {
        if state.trash.is_trashed(&message.id()) {
            continue;
        }
        let author_id = message.message.author;
        let now = Utc::now();
        let raw_time = DateTime::<Utc>::from(message.message.time);
        let time_clamped = raw_time > now;
        let message_time = if time_clamped { now } else { raw_time };
        let message_id = message.id();
        let is_self = author_id == self_member_id;

        // Posts from untrusted authors wait for a moderator. The author and
        // moderators with delete power still see them.
        let is_pending =
            plaza_core::board_state::approvals::is_pending(state, owner_id, &message_id);
        if is_pending && !is_self {
            let chain = plaza_core::board_state::moderation::category_chain(&routes, &message_id);
            let can_moderate = self_member_id == owner_id
                || is_admin
                || crate::board_data::has_moderation_power(
                    state,
                    self_member_id,
                    plaza_core::board_state::roles::ModerationPower::Delete,
                    &chain,
                );
            if !can_moderate {
                continue;
            }
        }

        let author_name = if let Some(override_name) =
            state.recent_messages.nickname_override(&author_id)
        {
            override_name.nickname.clone()
        } else {
            state
                .member_info
                .member_info
                .iter()
                .find(|ami| ami.member_info.member_id == author_id)
                .map(|ami| {
                    match unseal_bytes_with_secrets(&ami.member_info.preferred_nickname, secrets) {
                        Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
                        Err(_) => ami.member_info.preferred_nickname.to_string_lossy(),
                    }
                })
                .unwrap_or_else(|| "Unknown".to_string())
        };

        let content_text = state
            .recent_messages
            .effective_text(message)
            .unwrap_or_else(|| {
                decrypt_message_content(
                    &message.message.content,
                    secrets,
                    category_secrets,
                    old_category_secrets,
                )
            });
        let content_html = mentions.render_html(
            &crate::util::image_tags::strip_valid(&content_text, message.message.images.len()),
            Some(self_member_id),
        );
        let title_text = decrypt_message_title(
            &message.message.content,
            secrets,
            category_secrets,
            old_category_secrets,
        );

        let reactions = state
            .recent_messages
            .reactions(&message_id)
            .cloned()
            .unwrap_or_default();

        let (reply_to_author, reply_to_preview, body_reply_target) = extract_reply_context(
            &message.message.content,
            secrets,
            category_secrets,
            old_category_secrets,
        );
        // The signed public link is authoritative; the body is the fallback
        // for replies written before the field existed.
        let reply_to_message_id = message.message.reply_to.or(body_reply_target);
        // On a private board a sealed body target without a topic membership
        // proof must not be displayed as a reply: otherwise a modified client
        // could evade the topic author's moderation by omitting topic_id.
        let category_ids: std::collections::HashSet<MessageId> = state
            .recent_messages
            .messages
            .iter()
            .filter(|m| {
                m.message.content.content_type()
                    == plaza_core::board_state::content::CONTENT_TYPE_CATEGORY
            })
            .map(|m| m.id())
            .collect();
        let private_board = state.configuration.configuration.privacy_mode
            == plaza_core::board_state::privacy::PrivacyMode::Private;
        let reply_to_message_id = if private_board
            && message.message.topic_id.is_none()
            && reply_to_message_id
                .as_ref()
                .is_some_and(|target| !category_ids.contains(target))
        {
            None
        } else {
            reply_to_message_id
        };
        let moved_parent = state.moderation.moved_to(&message_id).copied().flatten();
        let reply_to_message_id = moved_parent.or(reply_to_message_id);
        let merged_into = state.moderation.is_merged_into(&message_id);

        let send_time_ms = raw_time.timestamp_millis();
        let receive_delay_secs = get_delay_secs(&message_id, send_time_ms);

        // Extract category info (with edits applied)
        let category_info = extract_category_info(
            &message.message.content,
            secrets,
            category_secrets,
            old_category_secrets,
            &message_id,
        );
        let (
            is_category,
            category_name,
            category_description,
            category_icon,
            category_color,
            parent_category_id,
            category_allowed_roles,
            category_hidden,
            category_locked,
            category_is_group,
            category_auto_moderated_topics,
        ) = match category_info {
            Some(mut info) => {
                if let Some(edit) = state.recent_messages.edited_category(&message_id) {
                    // A sealed edit carries the real name encrypted; without
                    // the key we keep the placeholder the edit publishes.
                    match (edit.sealed_name.as_ref(), category_secrets.get(&message_id)) {
                        (Some(sealed), Some((_, key))) => {
                            if let Ok(bytes) = crate::util::ecies::unseal_bytes(sealed, Some(key)) {
                                if let Ok(name) = String::from_utf8(bytes) {
                                    info.name = Some(name);
                                }
                            }
                        }
                        (None, _) => info.name = Some(edit.new_name.clone()),
                        _ => {}
                    }
                    info.description = edit.new_description.clone();
                    info.icon = edit.new_icon.clone();
                    info.color = Some(edit.new_color.clone());
                    info.auto_moderated_topics = edit.auto_moderated_topics;
                    if edit.set_parent {
                        info.parent = edit.new_parent.clone();
                    }
                }
                (
                    true,
                    info.name,
                    info.description,
                    info.icon,
                    info.color,
                    info.parent,
                    info.allowed_roles,
                    info.hidden,
                    info.locked,
                    info.is_group,
                    info.auto_moderated_topics,
                )
            }
            None => (
                false,
                None,
                None,
                None,
                None,
                None,
                Vec::new(),
                false,
                false,
                false,
                None,
            ),
        };

        // Mark as edited if the post, category or poll was edited.
        let poll_was_edited = state.recent_messages.edited_poll(&message_id).is_some();
        let edited = state.recent_messages.is_edited(&message_id)
            || state.recent_messages.is_category_edited(&message_id)
            || poll_was_edited;

        let poll = state
            .recent_messages
            .edited_poll(&message_id)
            .cloned()
            .or_else(|| {
                decrypt_poll(
                    &message.message.content,
                    secrets,
                    category_secrets,
                    old_category_secrets,
                )
            })
            .map(|content| {
            let mut votes: Vec<PollBallot> = ballots
                .get(&message_id)
                .map(|votes| votes.values().cloned().collect())
                .unwrap_or_default();
            votes.sort_by_key(|ballot| ballot.voter);
            PollData {
                title: content.title,
                description: content.description,
                options: content.options,
                closes_at: content.closes_at,
                multiselect: content.multiselect,
                results_visibility: content.results_visibility,
                votes,
                edited: poll_was_edited,
            }
        });

        let edit_history = match edits_by_target.get(&message_id) {
            Some(versions) => {
                let mut history = Vec::with_capacity(versions.len() + 1);
                history.push(EditVersion {
                    time: message_time,
                    author_name: author_name.clone(),
                    title: decrypt_message_title(
                        &message.message.content,
                        secrets,
                        category_secrets,
                        old_category_secrets,
                    ),
                    text: decrypt_message_content(
                        &message.message.content,
                        secrets,
                        category_secrets,
                        old_category_secrets,
                    ),
                });
                history.extend(versions.iter().cloned());
                history
            }
            None => Vec::new(),
        };

        messages.push(MessageData {
            message_id,
            author_id,
            author_name,
            is_self,
            title_text,
            content_text,
            content_html,
            time: message_time,
            time_clamped,
            edited,
            edit_history,
            reactions,
            reply_to_message_id,
            // Only a link backed by a valid membership proof is a topic reply.
            topic_id: message.message.topic_id.clone().filter(|root| {
                topic_keys
                    .get(root)
                    .map(|key| message.message.has_valid_topic_proof(key))
                    .unwrap_or(false)
            }),
            reply_to_author,
            reply_to_preview,
            receive_delay_secs,
            category_id: routes.get(&message_id).and_then(|route| route.category_id),
            is_category,
            category_name,
            category_description,
            category_icon,
            category_color,
            parent_category_id,
            category_allowed_roles,
            category_hidden,
            category_locked,
            is_group: category_is_group,
            // The public section policy is the fallback when the content
            // cannot be read; an edit payload wins once one exists.
            category_auto_moderated_topics: if state
                .recent_messages
                .is_category_edited(&message_id)
            {
                category_auto_moderated_topics
            } else {
                message
                    .message
                    .section_auto_moderated
                    .or(category_auto_moderated_topics)
            },
            is_pinned: state.moderation.is_pinned(&message_id),
            is_closed: state.moderation.is_closed(&message_id),
            is_pending,
            is_announced: state.moderation.is_announced(&message_id),
            poll,
            merged_into,
            images: message.message.images.clone(),
            // The signed public flag covers sealed topics on private boards;
            // the body flag is the fallback for older public posts.
            is_auto_moderated: message.message.auto_moderated
                || decrypt_auto_moderated(
                    &message.message.content,
                    secrets,
                    category_secrets,
                    old_category_secrets,
                ),
            can_delete_as_topic_author: false,
        });
    }

    // A section whose parent was deleted must not disappear: show it as
    // ungrouped. This also recovers sections orphaned by older group deletes.
    let live_categories: std::collections::HashSet<MessageId> = messages
        .iter()
        .filter(|message| message.is_category)
        .map(|message| message.message_id.clone())
        .collect();
    for message in messages.iter_mut() {
        if !message.is_category {
            continue;
        }
        if let Some(parent) = message.parent_category_id.clone() {
            if !live_categories.contains(&parent) {
                message.parent_category_id = None;
            }
        }
    }

    // Auto-moderated topics: mark replies their author may delete. The public
    // topic link names the root directly; old messages walk their reply
    // target instead. Both links ride in public metadata, so sealed
    // private-board posts count.
    // A message that claims a topic link without a valid proof is not a reply
    // for this rule, so its body link is not followed either.
    let by_id: HashMap<
        MessageId,
        (Option<MessageId>, Option<MessageId>, bool, bool, bool, MemberId),
    > = messages
        .iter()
        .map(|message| {
            (
                message.message_id.clone(),
                (
                    message.reply_to_message_id.clone(),
                    message.topic_id.clone(),
                    message.is_auto_moderated,
                    claimed_topic_links.contains(&message.message_id),
                    sealed_legacy_replies.contains(&message.message_id),
                    message.author_id,
                ),
            )
        })
        .collect();
    for message in messages.iter_mut() {
        let mut current = message.message_id.clone();
        let mut root = None;
        for _ in 0..64 {
            let Some((parent, topic_id, _, claimed_link, sealed_legacy, _)) =
                by_id.get(&current)
            else {
                break;
            };
            if *claimed_link {
                root = topic_id.clone();
                break;
            }
            if *sealed_legacy {
                break;
            }
            match parent {
                Some(parent) => current = parent.clone(),
                None => {
                    root = Some(current.clone());
                    break;
                }
            }
        }
        if let Some(root) = root {
            if root != message.message_id {
                if let Some((_, _, true, _, _, author)) = by_id.get(&root) {
                    message.can_delete_as_topic_author = *author == self_member_id;
                }
            }
        }
    }

    messages
}

/// Build a tree of messages with their replies
/// If parent_id is None, returns top-level messages (those not replying to anything)
/// If parent_id is Some(id), returns only replies to that specific message
fn count_message_tree(nodes: &[MessageWithReplies]) -> usize {
    nodes
        .iter()
        .map(|node| 1 + count_message_tree(&node.replies))
        .sum()
}

pub fn build_reply_tree(
    all_messages: &[MessageData],
    parent_id: Option<&MessageId>,
) -> Vec<MessageWithReplies> {
    let mut visited = std::collections::HashSet::new();
    build_reply_tree_inner(all_messages, parent_id, &mut visited, 0)
}

fn build_reply_tree_inner(
    all_messages: &[MessageData],
    parent_id: Option<&MessageId>,
    visited: &mut std::collections::HashSet<MessageId>,
    depth: usize,
) -> Vec<MessageWithReplies> {
    // A malformed or hostile reply cycle must not recurse forever.
    if depth > 64 {
        return Vec::new();
    }
    let direct_replies: Vec<&MessageData> = all_messages
        .iter()
        .filter(|m| {
            m.reply_to_message_id.as_ref() == parent_id
                && !visited.contains(&m.message_id)
        })
        .collect();

    let mut sorted_replies: Vec<_> = direct_replies.into_iter().cloned().collect();
    sorted_replies.sort_by_key(|m| m.time);

    sorted_replies
        .into_iter()
        .map(|message| {
            visited.insert(message.message_id.clone());
            let nested_replies = build_reply_tree_inner(
                all_messages,
                Some(&message.message_id),
                visited,
                depth + 1,
            );
            MessageWithReplies {
                message,
                replies: nested_replies,
            }
        })
        .collect()
}

/// Secret that opens a body, chosen by the scope recorded on it.
/// Decode an action from a public or sealed message.
fn decrypt_action(
    content: &BoardMessageBody,
    secrets: &HashMap<u32, [u8; 32]>,
    category_secrets: &HashMap<MessageId, (u32, [u8; 32])>,
    old_category_secrets: &HashMap<MessageId, HashMap<u32, [u8; 32]>>,
) -> Option<plaza_core::board_state::content::ActionContentV1> {
    use plaza_core::board_state::content::{ActionContentV1, CONTENT_TYPE_ACTION};
    match content {
        BoardMessageBody::Public {
            content_type, data, ..
        } if *content_type == CONTENT_TYPE_ACTION => {
            match ActionContentV1::decode(data) {
                Ok(action) => Some(action),
                Err(error) => {
                    dioxus::logger::tracing::warn!(
                        "Action decode failed: {error}, data_len={}",
                        data.len()
                    );
                    None
                }
            }
        }
        BoardMessageBody::Public {
            content_type, data, ..
        } if *content_type
            == plaza_core::board_state::content::CONTENT_TYPE_MODERATION_ACTION =>
        {
            use plaza_core::board_state::content::ModerationActionV1;
            use plaza_core::board_state::privacy::SealedBytes;
            let envelope = ModerationActionV1::decode(data).ok()?;
            match &envelope.payload {
                SealedBytes::Public { value } => ActionContentV1::decode(value).ok(),
                SealedBytes::Private {
                    ciphertext,
                    nonce,
                    secret_version,
                    ..
                } => {
                    let category_key = category_secrets
                        .get(&envelope.target)
                        .filter(|(version, _)| version == secret_version)
                        .map(|(_, key)| *key)
                        .or_else(|| {
                            old_category_secrets
                                .get(&envelope.target)
                                .and_then(|versions| versions.get(secret_version))
                                .copied()
                        });
                    let key = category_key.or_else(|| secrets.get(secret_version).copied())?;
                    let plain = crate::util::ecies::decrypt_with_symmetric_key(
                        &key,
                        ciphertext,
                        nonce,
                        *secret_version,
                    )
                    .ok()?;
                    ActionContentV1::decode(&plain).ok()
                }
            }
        }
        BoardMessageBody::Private {
            content_type,
            ciphertext,
            nonce,
            secret_version,
            ..
        } if *content_type == CONTENT_TYPE_ACTION => {
            let secret = body_secret(content, secrets, category_secrets, old_category_secrets)?;
            let plain = crate::util::ecies::decrypt_with_symmetric_key(
                &secret,
                ciphertext.as_slice(),
                nonce,
                *secret_version,
            )
            .ok()?;
            ActionContentV1::decode(&plain).ok()
        }
        _ => None,
    }
}

fn body_secret(
    content: &BoardMessageBody,
    board_secrets: &HashMap<u32, [u8; 32]>,
    category_secrets: &HashMap<MessageId, (u32, [u8; 32])>,
    old_category_secrets: &HashMap<MessageId, HashMap<u32, [u8; 32]>>,
) -> Option<[u8; 32]> {
    match content {
        BoardMessageBody::Private {
            secret_version,
            secret_scope,
            ..
        } => match secret_scope {
            SecretScope::Board => board_secrets.get(secret_version).copied(),
            SecretScope::Category(id) => category_secrets
                .get(id)
                .filter(|(version, _)| version == secret_version)
                .map(|(_, key)| *key)
                .or_else(|| {
                    old_category_secrets
                        .get(id)
                        .and_then(|versions| versions.get(secret_version))
                        .copied()
                }),
        },
        BoardMessageBody::Public { .. } => None,
    }
}

fn decrypt_poll(
    content: &BoardMessageBody,
    secrets: &HashMap<u32, [u8; 32]>,
    category_secrets: &HashMap<MessageId, (u32, [u8; 32])>,
    old_category_secrets: &HashMap<MessageId, HashMap<u32, [u8; 32]>>,
) -> Option<plaza_core::board_state::content::PollContentV1> {
    use plaza_core::board_state::content::{PollContentV1, CONTENT_TYPE_POLL};
    match content {
        BoardMessageBody::Public {
            content_type, data, ..
        } if *content_type == CONTENT_TYPE_POLL => PollContentV1::decode(data).ok(),
        BoardMessageBody::Private {
            content_type,
            ciphertext,
            nonce,
            secret_version,
            ..
        } if *content_type == CONTENT_TYPE_POLL => {
            let secret = body_secret(content, secrets, category_secrets, old_category_secrets)?;
            let bytes = crate::util::ecies::decrypt_with_symmetric_key(
                &secret,
                ciphertext,
                nonce,
                *secret_version,
            )
            .ok()?;
            PollContentV1::decode(&bytes).ok()
        }
        _ => None,
    }
}

fn decrypt_auto_moderated(
    content: &BoardMessageBody,
    secrets: &HashMap<u32, [u8; 32]>,
    category_secrets: &HashMap<MessageId, (u32, [u8; 32])>,
    old_category_secrets: &HashMap<MessageId, HashMap<u32, [u8; 32]>>,
) -> bool {
    use plaza_core::board_state::content::{
        PollContentV1, TextContentV1, CONTENT_TYPE_POLL, CONTENT_TYPE_TEXT,
    };
    match content {
        BoardMessageBody::Public {
            content_type, data, ..
        } => match *content_type {
            CONTENT_TYPE_TEXT => TextContentV1::decode(data)
                .ok()
                .map(|text| text.auto_moderated)
                .unwrap_or(false),
            CONTENT_TYPE_POLL => PollContentV1::decode(data)
                .ok()
                .map(|poll| poll.auto_moderated)
                .unwrap_or(false),
            _ => false,
        },
        BoardMessageBody::Private {
            content_type,
            ciphertext,
            nonce,
            secret_version,
            ..
        } => {
            let Some(secret) =
                body_secret(content, secrets, category_secrets, old_category_secrets)
            else {
                return false;
            };
            let Ok(bytes) = crate::util::ecies::decrypt_with_symmetric_key(
                &secret,
                ciphertext,
                nonce,
                *secret_version,
            ) else {
                return false;
            };
            match *content_type {
                CONTENT_TYPE_TEXT => TextContentV1::decode(&bytes)
                    .ok()
                    .map(|text| text.auto_moderated)
                    .unwrap_or(false),
                CONTENT_TYPE_POLL => PollContentV1::decode(&bytes)
                    .ok()
                    .map(|poll| poll.auto_moderated)
                    .unwrap_or(false),
                _ => false,
            }
        }
    }
}

fn decrypt_poll_vote(
    content: &BoardMessageBody,
    secrets: &HashMap<u32, [u8; 32]>,
    category_secrets: &HashMap<MessageId, (u32, [u8; 32])>,
    old_category_secrets: &HashMap<MessageId, HashMap<u32, [u8; 32]>>,
) -> Option<plaza_core::board_state::content::PollVoteV1> {
    use plaza_core::board_state::content::{PollVoteV1, CONTENT_TYPE_POLL_VOTE};
    match content {
        BoardMessageBody::Public {
            content_type, data, ..
        } if *content_type == CONTENT_TYPE_POLL_VOTE => PollVoteV1::decode(data).ok(),
        BoardMessageBody::Private {
            content_type,
            ciphertext,
            nonce,
            secret_version,
            ..
        } if *content_type == CONTENT_TYPE_POLL_VOTE => {
            let secret = body_secret(content, secrets, category_secrets, old_category_secrets)?;
            let bytes = crate::util::ecies::decrypt_with_symmetric_key(
                &secret,
                ciphertext,
                nonce,
                *secret_version,
            )
            .ok()?;
            PollVoteV1::decode(&bytes).ok()
        }
        _ => None,
    }
}

fn decrypt_message_title(
    content: &BoardMessageBody,
    secrets: &HashMap<u32, [u8; 32]>,
    category_secrets: &HashMap<MessageId, (u32, [u8; 32])>,
    old_category_secrets: &HashMap<MessageId, HashMap<u32, [u8; 32]>>,
) -> String {
    use plaza_core::board_state::content::{
        PollContentV1, ReplyContentV1, TextContentV1, CONTENT_TYPE_POLL, CONTENT_TYPE_REPLY,
        CONTENT_TYPE_TEXT,
    };

    match content {
        BoardMessageBody::Public {
            content_type, data, ..
        } => {
            if *content_type == CONTENT_TYPE_TEXT {
                if let Ok(text_content) = TextContentV1::decode(data) {
                    return text_content.title;
                }
            }
            if *content_type == CONTENT_TYPE_REPLY {
                if let Ok(reply) = ReplyContentV1::decode(data) {
                    return reply.title;
                }
            }
            if *content_type == CONTENT_TYPE_POLL {
                if let Ok(poll) = PollContentV1::decode(data) {
                    return poll.title;
                }
            }
            String::new()
        }
        BoardMessageBody::Private {
            content_type,
            ciphertext,
            nonce,
            secret_version,
            ..
        } => {
            if let Some(secret) =
                body_secret(content, secrets, category_secrets, old_category_secrets)
            {
                use crate::util::ecies::decrypt_with_symmetric_key;
                if let Ok(decrypted_bytes) = decrypt_with_symmetric_key(
                    &secret,
                    ciphertext.as_slice(),
                    nonce,
                    *secret_version,
                ) {
                    if *content_type == CONTENT_TYPE_TEXT {
                        if let Ok(text_content) = TextContentV1::decode(&decrypted_bytes) {
                            return text_content.title;
                        }
                    }
                    if *content_type == CONTENT_TYPE_REPLY {
                        if let Ok(reply) = ReplyContentV1::decode(&decrypted_bytes) {
                            return reply.title;
                        }
                    }
                    if *content_type == CONTENT_TYPE_POLL {
                        if let Ok(poll) = PollContentV1::decode(&decrypted_bytes) {
                            return poll.title;
                        }
                    }
                }
            }
            String::new()
        }
    }
}

fn decrypt_message_content(
    content: &BoardMessageBody,
    secrets: &HashMap<u32, [u8; 32]>,
    category_secrets: &HashMap<MessageId, (u32, [u8; 32])>,
    old_category_secrets: &HashMap<MessageId, HashMap<u32, [u8; 32]>>,
) -> String {
    use plaza_core::board_state::content::{
        PollContentV1, ReplyContentV1, TextContentV1, CONTENT_TYPE_ACTION, CONTENT_TYPE_POLL,
        CONTENT_TYPE_REPLY, CONTENT_TYPE_TEXT,
    };

    match content {
        BoardMessageBody::Public {
            content_type, data, ..
        } => {
            if *content_type == CONTENT_TYPE_ACTION {
                return content.to_string_lossy();
            }
            if *content_type == CONTENT_TYPE_TEXT {
                if let Ok(text_content) = TextContentV1::decode(data) {
                    return text_content.content;
                }
            }
            if *content_type == CONTENT_TYPE_REPLY {
                if let Ok(reply) = ReplyContentV1::decode(data) {
                    return reply.content;
                }
            }
            if *content_type == CONTENT_TYPE_POLL {
                if let Ok(poll) = PollContentV1::decode(data) {
                    return poll.description;
                }
            }
            content.to_string_lossy()
        }
        BoardMessageBody::Private {
            content_type,
            ciphertext,
            nonce,
            secret_version,
            secret_scope,
            ..
        } => {
            if let Some(secret) =
                body_secret(content, secrets, category_secrets, old_category_secrets)
            {
                use crate::util::ecies::decrypt_with_symmetric_key;
                if let Ok(decrypted_bytes) = decrypt_with_symmetric_key(
                    &secret,
                    ciphertext.as_slice(),
                    nonce,
                    *secret_version,
                ) {
                    if *content_type == CONTENT_TYPE_TEXT {
                        if let Ok(text_content) = TextContentV1::decode(&decrypted_bytes) {
                            return text_content.content;
                        }
                    }
                    if *content_type == CONTENT_TYPE_REPLY {
                        if let Ok(reply) = ReplyContentV1::decode(&decrypted_bytes) {
                            return reply.content;
                        }
                    }
                    if *content_type == CONTENT_TYPE_POLL {
                        if let Ok(poll) = PollContentV1::decode(&decrypted_bytes) {
                            return poll.description;
                        }
                    }
                    return String::from_utf8_lossy(&decrypted_bytes).to_string();
                }
                content.to_string_lossy()
            } else {
                match secret_scope {
                    SecretScope::Board => format!(
                        "[Encrypted message - secret v{} not available (have: {:?})]",
                        secret_version,
                        secrets.keys().collect::<Vec<_>>()
                    ),
                    SecretScope::Category(_) => {
                        "[Restricted post - you do not have access to this category]".to_string()
                    }
                }
            }
        }
    }
}

fn extract_reply_context(
    content: &BoardMessageBody,
    secrets: &HashMap<u32, [u8; 32]>,
    category_secrets: &HashMap<MessageId, (u32, [u8; 32])>,
    old_category_secrets: &HashMap<MessageId, HashMap<u32, [u8; 32]>>,
) -> (Option<String>, Option<String>, Option<MessageId>) {
    use plaza_core::board_state::content::{ReplyContentV1, CONTENT_TYPE_REPLY};

    match content {
        BoardMessageBody::Public {
            content_type, data, ..
        } if *content_type == CONTENT_TYPE_REPLY => {
            if let Ok(reply) = ReplyContentV1::decode(data) {
                return (
                    Some(reply.target_author_name),
                    Some(reply.target_content_preview),
                    Some(reply.target_message_id),
                );
            }
        }
        BoardMessageBody::Private {
            content_type,
            ciphertext,
            nonce,
            secret_version,
            ..
        } if *content_type == CONTENT_TYPE_REPLY => {
            if let Some(secret) =
                body_secret(content, secrets, category_secrets, old_category_secrets)
            {
                use crate::util::ecies::decrypt_with_symmetric_key;
                if let Ok(decrypted_bytes) = decrypt_with_symmetric_key(
                    &secret,
                    ciphertext.as_slice(),
                    nonce,
                    *secret_version,
                ) {
                    if let Ok(reply) = ReplyContentV1::decode(&decrypted_bytes) {
                        return (
                            Some(reply.target_author_name),
                            Some(reply.target_content_preview),
                            Some(reply.target_message_id),
                        );
                    }
                }
            }
        }
        _ => {}
    }
    (None, None, None)
}

/// Decoded category metadata, with the sealed name opened when possible.
#[derive(Clone, PartialEq, Debug)]
pub struct CategoryInfo {
    pub name: Option<String>,
    pub description: Option<String>,
    pub icon: Option<String>,
    pub color: Option<String>,
    pub parent: Option<MessageId>,
    pub allowed_roles: Vec<RoleId>,
    pub hidden: bool,
    /// Homepage group that contains sections and has no posts
    pub is_group: bool,
    /// Restricted category whose key this client does not hold.
    pub locked: bool,
    /// Section override for auto-moderated topics; `None` inherits the board.
    pub auto_moderated_topics: Option<bool>,
}

/// Open a category's sealed name when its key is available.
fn open_category_name(
    mut category: CategoryContentV1,
    category_id: &MessageId,
    category_secrets: &HashMap<MessageId, (u32, [u8; 32])>,
    old_category_secrets: &HashMap<MessageId, HashMap<u32, [u8; 32]>>,
) -> CategoryContentV1 {
    if let Some(sealed) = category.sealed_name.as_ref() {
        let mut keys: Vec<[u8; 32]> = Vec::new();
        if let Some((_, key)) = category_secrets.get(category_id) {
            keys.push(*key);
        }
        if let Some(versions) = old_category_secrets.get(category_id) {
            keys.extend(versions.values().copied());
        }
        for key in keys {
            if let Ok(bytes) = crate::util::ecies::unseal_bytes(sealed, Some(&key)) {
                if let Ok(name) = String::from_utf8(bytes) {
                    category.name = name;
                    break;
                }
            }
        }
    }
    category
}

/// Extract category information from message content
fn extract_category_info(
    content: &BoardMessageBody,
    secrets: &HashMap<u32, [u8; 32]>,
    category_secrets: &HashMap<MessageId, (u32, [u8; 32])>,
    old_category_secrets: &HashMap<MessageId, HashMap<u32, [u8; 32]>>,
    message_id: &MessageId,
) -> Option<CategoryInfo> {
    use plaza_core::board_state::content::{CategoryContentV1, CONTENT_TYPE_CATEGORY};

    let category = match content {
        BoardMessageBody::Public {
            content_type, data, ..
        } if *content_type == CONTENT_TYPE_CATEGORY => CategoryContentV1::decode(data).ok()?,
        // Private boards seal their categories like any other content.
        BoardMessageBody::Private {
            content_type,
            ciphertext,
            nonce,
            secret_version,
            ..
        } if *content_type == CONTENT_TYPE_CATEGORY => {
            let secret = body_secret(content, secrets, category_secrets, old_category_secrets)?;
            let bytes = crate::util::ecies::decrypt_with_symmetric_key(
                &secret,
                ciphertext,
                nonce,
                *secret_version,
            )
            .ok()?;
            CategoryContentV1::decode(&bytes).ok()?
        }
        _ => return None,
    };

    let locked = category.is_restricted() && !category_secrets.contains_key(message_id);
    let category = open_category_name(category, message_id, category_secrets, old_category_secrets);
    Some(CategoryInfo {
        name: Some(category.name),
        description: category.description,
        icon: category.icon,
        color: Some(category.color),
        parent: category.parent_category_id,
        allowed_roles: category.allowed_roles,
        hidden: category.hidden,
        is_group: category.is_group,
        locked,
        auto_moderated_topics: category.auto_moderated_topics,
    })
}

/// Conversation component that shows replies to a specific parent message
/// If parent_message_id is None, this is a standalone conversation (legacy behavior)
/// If parent_message_id is Some(id), shows only replies to that message
#[component]
pub fn Conversation(
    #[props(default)] parent_message_id: Option<MessageId>,
    /// Default reply context - when set, new messages will be replies to this
    #[props(default)]
    default_reply_to: Option<ReplyContext>,
) -> Element {
    let current_board_data = {
        let current_board = CURRENT_BOARD.read();
        if let Some(key) = current_board.owner_key {
            let boards = BOARDS.read();
            boards.map.get(&key).cloned()
        } else {
            None
        }
    };

    let mut replying_to: Signal<Option<ReplyContext>> = use_signal(|| None);
    let mut pending_delete: Signal<Option<MessageId>> = use_signal(|| None);
    use_hook(|| {
        *CONVERSATION_PINNED.write() = true;
    });
    use_effect(move || {
        let intercepted = INTERCEPTED_JOIN_TOKEN.read().clone();
        if let Some(token) = intercepted {
            *INTERCEPTED_JOIN_TOKEN.write() = None;
            navigator().push(Route::JoinBoard { token });
        }
    });

    // Build message tree for the given parent
    let message_tree = use_memo({
        let parent_id = parent_message_id.clone();
        move || {
            let current_board = CURRENT_BOARD.read();
            if let Some(key) = current_board.owner_key {
                let boards = BOARDS.read();
                if let Some(board_data) = boards.map.get(&key) {
                    let self_member_id = MemberId::from(&board_data.self_sk.verifying_key());
                    let config = &board_data.board_state.configuration.configuration;
                    let max_title_size = config.max_title_size;
                    let max_message_size = config.max_message_size;
                    let all_messages = get_all_messages(
                        &board_data.board_state,
                        self_member_id,
                        &board_data.secrets,
                        &board_data.category_secrets,
                        &board_data.old_category_secrets,
                    );

                    // Build member name lookup
                    let member_names: HashMap<MemberId, String> = board_data
                        .board_state
                        .member_info
                        .member_info
                        .iter()
                        .map(|ami| {
                            let name = if let Some(override_name) = board_data
                                .board_state
                                .recent_messages
                                .nickname_override(&ami.member_info.member_id)
                            {
                                override_name.nickname.clone()
                            } else {
                                match unseal_bytes_with_secrets(
                                    &ami.member_info.preferred_nickname,
                                    &board_data.secrets,
                                ) {
                                    Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
                                    Err(_) => {
                                        ami.member_info.preferred_nickname.to_string_lossy()
                                    }
                                }
                            };
                            (ami.member_info.member_id, name)
                        })
                        .collect();

                    let tree = build_reply_tree(&all_messages, parent_id.as_ref());
                    return Some((
                        tree,
                        self_member_id,
                        member_names,
                        max_title_size,
                        max_message_size,
                    ));
                }
            }
            None
        }
    });

    let tree_count = message_tree
        .read()
        .as_ref()
        .map(|(tree, _, _, _, _)| count_message_tree(tree))
        .unwrap_or(0);
    use_effect(move || {
        let _ = tree_count;
        if *CONVERSATION_PINNED.read() {
            spawn_local(async move {
                futures_timer::Delay::new(std::time::Duration::from_millis(60)).await;
                crate::util::scroll_conversation_to_bottom("message-scroll");
            });
        }
    });

    // Handler for toggling a reaction
    let handle_toggle_reaction = move |target_message_id: MessageId, emoji: String| {
        if let Some(ctx) = crate::util::message_actions::ActionContext::from_current_board() {
            spawn_local(async move {
                crate::util::message_actions::toggle_reaction(ctx, target_message_id, emoji).await;
            });
        }
    };

    // Handler for deleting a message
    let handle_delete_message = move |target_message_id: MessageId| {
        if let Some(ctx) = crate::util::message_actions::ActionContext::from_current_board() {
            spawn_local(async move {
                crate::util::message_actions::delete_message(ctx, target_message_id).await;
            });
        }
    };

    // Handler for editing a message
    let handle_edit_message =
        move |target_message_id: MessageId, new_title: String, new_text: String| {
            if let Some(ctx) = crate::util::message_actions::ActionContext::from_current_board() {
                spawn_local(async move {
                    crate::util::message_actions::edit_message(
                        ctx,
                        target_message_id,
                        new_title,
                        new_text,
                    )
                    .await;
                });
            }
        };

    // Message sending handler. The result covers the local checks, so the
    // composer can keep the text; the publish outcome is reported from the
    // spawned task.
    let handle_send_message = {
        let current_board_data = current_board_data.clone();
        move |(title_text, message_text, reply_ctx, poll, images, auto_moderated): (
            String,
            String,
            Option<ReplyContext>,
            Option<crate::util::messaging::PollDraft>,
            Vec<plaza_core::board_state::images::ImageRef>,
            bool,
        )| -> Result<(), String> {
            let (Some(current_board), Some(current_board_data)) =
                (CURRENT_BOARD.read().owner_key, current_board_data.clone())
            else {
                return Err("No board selected".to_string());
            };
            let board_key = current_board_data.board_key();
            let self_sk = current_board_data.self_sk.clone();
            let board_state_clone = current_board_data.board_state.clone();
            let is_private = current_board_data.is_private();
            let secret_opt: Option<([u8; 32], u32)> = current_board_data
                .get_secret()
                .map(|(secret, version)| (*secret, version));
            // Replies to a restricted category, or to a post inside one,
            // are sealed with that category's key.
            let category_secret = reply_ctx
                .as_ref()
                .and_then(|reply| current_board_data.posting_secret_for(&reply.message_id));

            let category_id = crate::components::app::CURRENT_CATEGORY
                .read()
                .category_id
                .clone();
            let prepared = prepare_message(
                current_board,
                board_key,
                self_sk,
                board_state_clone,
                is_private,
                secret_opt,
                category_secret,
                category_id,
                title_text,
                message_text,
                reply_ctx,
                images,
                poll,
                auto_moderated,
                None,
            )?;
            spawn_local(async move {
                match publish_prepared(prepared).await {
                    Ok(()) => crate::components::app::toasts::show(
                        "Published. Syncing with the network…",
                    ),
                    Err(error) => {
                        crate::components::app::toasts::show_error(format!(
                            "Could not publish: {error}"
                        ));
                    }
                }
            });
            Ok(())
        }
    };

    rsx! {
        div { class: "flex flex-col h-full min-h-0",
            // Reply thread area
            div {
                class: "flex-1 overflow-y-auto",
                div { class: "max-w-4xl mx-auto px-4 py-4",
                    {
                        if current_board_data.is_some() {
                            match message_tree.read().as_ref() {
                                Some((tree, self_member_id, member_names, max_title_size, max_message_size)) if !tree.is_empty() => {
                                    let tree = tree.clone();
                                    let self_member_id = *self_member_id;
                                    let member_names = member_names.clone();
                                    let max_title_size = *max_title_size;
                                    let max_message_size = *max_message_size;
                                    let can_react = current_board_data
                                        .as_ref()
                                        .map(|board| board.may_write_content())
                                        .unwrap_or(false);
                                    Some(rsx! {
                                        div { class: "space-y-2",
                                            {tree.into_iter().map({
                                                let handle_toggle_reaction = handle_toggle_reaction.clone();
                                                let handle_edit_message = handle_edit_message.clone();
                                                let member_names = member_names.clone();
                                                move |msg_with_replies| {
                                                    let handle_toggle_reaction = handle_toggle_reaction.clone();
                                                    let handle_edit_message = handle_edit_message.clone();
                                                    let member_names = member_names.clone();
                                                    rsx! {
                                                        MessageCard {
                                                            message: msg_with_replies.message.clone(),
                                                            variant: MessageCardVariant::Reply,
                                                            self_member_id: self_member_id,
                                                            member_names: member_names,
                                                            replies: msg_with_replies.replies.clone(),
                                                            depth: 0,
                                                            max_title_size: max_title_size,
                                                            max_message_size: max_message_size,
                                                            can_react: can_react,
                                                            auto_load_images: *crate::util::images::AUTO_LOAD_IMAGES.read(),
                                                            on_react: move |(msg_id, emoji)| {
                                                                handle_toggle_reaction(msg_id, emoji);
                                                            },
                                                            on_request_delete: move |msg_id| {
                                                                pending_delete.set(Some(msg_id));
                                                            },
                                                            on_edit: move |(msg_id, new_title, new_text)| {
                                                                handle_edit_message(msg_id, new_title, new_text);
                                                            },
                                                            on_reply: move |ctx: ReplyContext| {
                                                                replying_to.set(Some(ctx));
                                                            },
                                                        }
                                                    }
                                                }
                                            })}
                                        }
                                    })
                                }
                                Some(_) => Some(rsx! {
                                    div { class: "flex flex-col items-center justify-center h-32 text-text-muted",
                                        p { "No replies yet." }
                                    }
                                }),
                                None => Some(rsx! {
                                    div { class: "flex flex-col items-center justify-center h-32 text-text-muted",
                                        p { "No messages." }
                                    }
                                })
                            }
                        } else {
                            None
                        }
                    }
                }
            }

            // Message input
            {
                match current_board_data.as_ref() {
                    Some(board_data) if board_data.is_awaiting_initial_sync() => {
                        rsx! {
                            div { class: "px-4 py-3 mx-4 mb-4 bg-surface rounded-lg text-sm text-text-muted flex items-center gap-3",
                                div { class: "animate-spin w-4 h-4 border-2 border-accent border-t-transparent rounded-full" }
                                span { "Syncing board state from the network... You'll be able to send messages once sync completes." }
                            }
                        }
                    },
                    Some(board_data) => {
                        match board_data.can_participate() {
                            Ok(()) => {
                                let max_title = board_data.board_state.configuration.configuration.max_title_size;
                                let max_message = board_data.board_state.configuration.configuration.max_message_size;
                                rsx! {
                                    div { class: "flex justify-center",
                                        PostInput {
                                            handle_send_message: move |msg: (
                                                String,
                                                String,
                                                Option<ReplyContext>,
                                                Option<crate::util::messaging::PollDraft>,
                                                Vec<plaza_core::board_state::images::ImageRef>,
                                                bool,
                                            )| {
                                                let handle = handle_send_message.clone();
                                                handle(msg)
                                            },
                                            replying_to: replying_to,
                                            on_request_edit_last: move |_| {},
                                            default_reply_to: default_reply_to.clone(),
                                            max_title_size: max_title,
                                            max_message_size: max_message,
                                        }
                                    }
                                }
                            },
                            Err(SendMessageError::UserSuspended) => rsx! {
                                div { class: "px-4 py-2 bg-error-bg text-red-700 dark:text-red-400 rounded-lg text-sm",
                                    "You are suspended and cannot post."
                                }
                            },
                            Err(SendMessageError::UserNotMember) => {
                                let user_vk = board_data.self_sk.verifying_key();
                                rsx! {
                                    NotMemberNotification {
                                        user_verifying_key: user_vk
                                    }
                                }
                            },
                            Err(SendMessageError::UserBanned) => rsx! {
                                div { class: "px-4 py-3 mx-4 mb-4 bg-error-bg text-red-700 dark:text-red-400 rounded-lg text-sm",
                                    "You have been banned from sending messages in this board."
                                }
                            },
                        }
                    },
                    None => rsx! {},
                }
            }

            // Delete confirmation modal
            if pending_delete.read().is_some() {
                div {
                    class: "fixed inset-0 bg-black/50 flex items-center justify-center z-50",
                    onclick: move |_| pending_delete.set(None),
                    div {
                        class: "bg-panel rounded-lg shadow-xl p-6 max-w-sm mx-4",
                        onclick: move |e| e.stop_propagation(),
                        h3 { class: "text-lg font-semibold text-text mb-2",
                            "Delete permanently?"
                        }
                        p { class: "text-text-muted text-sm mb-4",
                            "This message is removed for everyone and cannot be undone. It does not go to the trash."
                        }
                        div { class: "flex gap-3 justify-end",
                            button {
                                class: "px-4 py-2 rounded-lg bg-surface hover:bg-surface/80 text-text transition-colors",
                                onclick: move |_| pending_delete.set(None),
                                "Cancel"
                            }
                            button {
                                class: "px-4 py-2 rounded-lg bg-red-500 hover:bg-red-600 text-white transition-colors",
                                onclick: move |_| {
                                    let msg_id_opt = pending_delete.read().clone();
                                    if let Some(msg_id) = msg_id_opt {
                                        handle_delete_message(msg_id);
                                    }
                                    pending_delete.set(None);
                                },
                                "Delete permanently"
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Display variant for MessageCard
#[derive(Clone, Copy, PartialEq, Default)]
pub enum MessageCardVariant {
    /// Reply style: border-left, compact, indented
    #[default]
    Reply,
    /// Card style: full card with header, larger text
    Card,
}

/// Size variant for shared components
#[derive(Clone, Copy, PartialEq, Default)]
pub enum MessageSize {
    /// Compact size for reply style
    #[default]
    Compact,
    /// Normal size for card list view
    Normal,
    /// Large size for expanded card view
    Large,
}

/// Small preview in the topic list. The image contract is fetched only while
/// the row exists, and never for NSFW, retired or device-blocked images.
#[component]
pub fn TopicThumb(image: ImageRef) -> Element {
    let thumb = image.thumb.clone();
    let instance = image.instance;
    let nsfw = image.nsfw;
    let suppressed = use_memo({
        let thumb = thumb.clone();
        move || {
            if nsfw {
                return true;
            }
            let Some(thumb) = thumb.as_ref() else {
                return true;
            };
            let Some(key) = CURRENT_BOARD.read().owner_key else {
                return false;
            };
            BOARDS
                .read()
                .map
                .get(&key)
                .map(|board| {
                    board.board_state.image_retirements.is_retired(&instance)
                        || board
                            .board_state
                            .image_retirements
                            .is_hash_denied(&thumb.sha256)
                })
                .unwrap_or(false)
        }
    });
    let src = use_memo({
        let thumb = thumb.clone();
        move || {
            use base64::Engine;
            let thumb = thumb.as_ref()?;
            match IMAGES.read().get(&thumb.instance) {
                Some(entry) => match &entry.status {
                    ImageStatus::Ready(bytes) => Some(format!(
                        "data:image/webp;base64,{}",
                        base64::engine::general_purpose::STANDARD.encode(bytes)
                    )),
                    _ => None,
                },
                None => None,
            }
        }
    });
    use_effect({
        let thumb = thumb.clone();
        move || {
            if *suppressed.read() {
                return;
            }
            if let Some(thumb) = thumb.as_ref() {
                request_image(thumb.instance, thumb.sha256);
            }
        }
    });

    if *suppressed.read() {
        return rsx! {};
    }
    let source = src.read().clone();
    match source.as_ref() {
        Some(src) => rsx! {
            img {
                src: "{src}",
                alt: "",
                class: "w-12 h-12 rounded object-cover flex-shrink-0",
            }
        },
        None => rsx! {
            div { class: "w-12 h-12 rounded bg-surface border border-border flex-shrink-0" }
        },
    }
}

/// Shared header component for messages
#[component]
fn MessageHeader(
    author_id: MemberId,
    author_name: String,
    is_self: bool,
    time_str: String,
    full_time_str: String,
    time_clamped: bool,
    size: MessageSize,
    /// Post title, shown next to the author in card views
    #[props(default)]
    title: Option<String>,
    /// Message sent but not yet confirmed by the network
    #[props(default)]
    pending: bool,
    /// First image with a preview, shown in the topic list
    #[props(default)]
    thumb: Option<ImageRef>,
) -> Element {
    let (avatar_size, name_class) = match size {
        MessageSize::Compact => ("w-8 h-8", "text-sm font-medium text-text"),
        MessageSize::Normal => ("w-10 h-10", "text-base font-semibold text-text"),
        MessageSize::Large => ("w-12 h-12", "text-lg font-semibold text-text"),
    };

    let time_class = match size {
        MessageSize::Compact => {
            if time_clamped {
                "text-xs text-text-muted italic"
            } else {
                "text-xs text-text-muted"
            }
        }
        _ => {
            if time_clamped {
                "text-sm text-text-muted italic"
            } else {
                "text-sm text-text-muted"
            }
        }
    };

    rsx! {
        if let Some(image) = thumb.as_ref() {
            TopicThumb { image: image.clone() }
        }
        img {
            src: "{get_avatar(&author_id)}",
            alt: "Avatar",
            class: "{avatar_size} rounded-full"
        }
        div { class: if matches!(size, MessageSize::Compact) { "flex items-center gap-3" } else { "flex-1 min-w-0" },
            div { class: "flex items-center gap-2 min-w-0 flex-wrap",
                div {
                    class: "{name_class} cursor-pointer hover:text-accent transition-colors flex-shrink-0",
                    onclick: move |e| {
                        e.stop_propagation();
                        MEMBER_INFO_MODAL.with_mut(|signal| {
                            signal.member = Some(author_id);
                        });
                    },
                    "{author_name}"
                }
                if let Some(title) = title.as_ref() {
                    span { class: "text-text-muted flex-shrink-0", "·" }
                    span {
                        class: match size {
                            MessageSize::Compact => "truncate text-sm font-semibold text-text",
                            MessageSize::Normal => "truncate text-base font-semibold text-text",
                            MessageSize::Large => "truncate text-xl font-bold text-text",
                        },
                        title: "{title}",
                        "{title}"
                    }
                }
                if !matches!(size, MessageSize::Compact) {
                    span {
                        class: "text-xs text-text-muted flex-shrink-0",
                        title: "{full_time_str}",
                        if time_clamped { "~{time_str}" } else { "· {time_str}" }
                    }
                }
            }
            if is_self && matches!(size, MessageSize::Compact) {
                span { class: "text-xs text-accent", "(you)" }
            }
            if matches!(size, MessageSize::Compact) {
                    span {
                        class: "{time_class}",
                        title: "{full_time_str}",
                        if time_clamped { "~{time_str}" } else { "{time_str}" }
                    }
                    if pending {
                        span { class: "text-[10px] text-accent", "syncing…" }
                    }
            }
        }
    }
}

/// Truncate text to a maximum number of characters, adding ellipsis if truncated
fn truncate_text(text: &str, max_chars: usize) -> (String, bool) {
    if text.chars().count() <= max_chars {
        (text.to_string(), false)
    } else {
        let truncated: String = text.chars().take(max_chars).collect();
        (truncated + "…", true)
    }
}

/// Truncate text to a maximum number of lines and characters
fn truncate_content(text: &str, max_lines: usize, max_chars: usize) -> (String, bool) {
    let lines: Vec<&str> = text.lines().collect();
    let line_limited = if lines.len() > max_lines {
        lines[..max_lines].join("\n")
    } else {
        text.to_string()
    };

    let was_line_truncated = lines.len() > max_lines;
    let (result, was_char_truncated) = truncate_text(&line_limited, max_chars);
    (result, was_line_truncated || was_char_truncated)
}

/// Shared content display component (non-editing mode)
#[component]
fn MessageContentDisplay(
    title_text: String,
    content_html: String,
    content_text: String,
    #[props(default)]
    member_names: HashMap<MemberId, String>,
    #[props(default)]
    self_member_id: Option<MemberId>,
    edited: bool,
    #[props(default)]
    history: Vec<EditVersion>,
    size: MessageSize,
    expanded: bool,
    /// Card views show the title in the header instead
    #[props(default = true)]
    show_title: bool,
    /// Attachments, for `[img=n]` tags inside the text.
    #[props(default)]
    images: Vec<ImageRef>,
    #[props(default)]
    auto_load_images: bool,
) -> Element {
    let mut show_history = use_signal(|| false);
    let (title_class, content_class) = match size {
        MessageSize::Compact => (
            "font-semibold text-text mb-1",
            "prose prose-sm dark:prose-invert max-w-none",
        ),
        MessageSize::Normal => (
            "text-xl font-bold text-text mb-3",
            "prose prose-base dark:prose-invert max-w-none",
        ),
        MessageSize::Large => (
            "text-xl font-bold text-text mb-3",
            "prose prose-base dark:prose-invert max-w-none",
        ),
    };

    let edited_class = if matches!(size, MessageSize::Compact) {
        "text-xs ml-2 text-text-muted"
    } else {
        "text-sm ml-2 text-text-muted"
    };
    let text_class = if matches!(size, MessageSize::Compact) {
        "text-sm text-text"
    } else {
        "text-base text-text leading-relaxed"
    };

    // Truncate title and content for non-expanded card views
    let (display_title, _title_truncated) = if !expanded && matches!(size, MessageSize::Normal) {
        truncate_text(&title_text, 48)
    } else {
        (title_text.clone(), false)
    };

    // Truncate content for non-expanded card views (Normal size = PostsView cards)
    let mention_directory = crate::util::mentions::MentionDirectory::from_names(
        member_names
            .iter()
            .map(|(id, name)| (*id, name.clone())),
    );
    let (display_content_html, content_truncated) = if !expanded {
        // For truncation, work with plain text then render it with mentions.
        let (truncated_text, was_truncated) = truncate_content(&content_text, 8, 512);
        if was_truncated {
            (
                mention_directory.render_html(&truncated_text, self_member_id),
                true,
            )
        } else {
            (content_html.clone(), false)
        }
    } else {
        (content_html.clone(), false)
    };

    rsx! {
        // Title
        if show_title && !display_title.is_empty() {
            match size {
                MessageSize::Large if expanded => rsx! { h1 { class: "{title_class}", dir: "auto", "{display_title}" } },
                MessageSize::Compact => rsx! { h4 { class: "{title_class}", dir: "auto", "{display_title}" } },
                _ => rsx! { h2 { class: "{title_class}", dir: "auto", "{display_title}" } },
            }
        }
        // Content
        div { class: "{text_class}", dir: "auto",
            if expanded && content_text.contains("[img=") {
                for segment in crate::util::image_tags::parse(&content_text) {
                    match segment {
                        crate::util::image_tags::Segment::Text(text) => rsx! {
                            div {
                                class: "{content_class}",
                                dir: "auto",
                                dangerous_inner_html: "{mention_directory.render_html(&text, self_member_id)}"
                            }
                        },
                        crate::util::image_tags::Segment::Image { index, align } => {
                            if let Some(image) = images.get(index) {
                                rsx! {
                                    div {
                                        class: match align {
                                            ImageAlign::Left => "flex justify-start my-2",
                                            ImageAlign::Center => "flex justify-center my-2",
                                            ImageAlign::Right => "flex justify-end my-2",
                                        },
                                        ImageAttachment { image: image.clone(), auto_load: auto_load_images, gallery: images.clone() }
                                    }
                                }
                            } else {
                                // A tag that points at no attachment stays
                                // visible instead of disappearing.
                                let suffix = match align {
                                    ImageAlign::Left => " left",
                                    ImageAlign::Center => "",
                                    ImageAlign::Right => " right",
                                };
                                rsx! {
                                    span {
                                        class: "text-text-muted",
                                        "[img={index + 1}{suffix}]"
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                div {
                    class: "{content_class}",
                    dir: "auto",
                    dangerous_inner_html: "{display_content_html}"
                }
                if content_truncated {
                    span { class: "text-accent ml-1", "Read more →" }
                }
            }
            if edited {
                span { class: "{edited_class}", "(edited)" }
            }
            if !history.is_empty() {
                button {
                    r#type: "button",
                    class: "ml-1 text-xs text-accent hover:underline",
                    onclick: move |_| show_history.set(!show_history()),
                    "View {history.len()} versions"
                }
            }
            if show_history() {
                div { class: "mt-3 border-t border-border pt-2 space-y-2",
                    for (index, version) in history.iter().enumerate() {
                        div { class: "text-xs text-text-muted",
                            div { class: "flex items-baseline gap-2 flex-wrap",
                                span { class: "font-medium text-text",
                                    if index == 0 { "Original" } else { "Version {index + 1}" }
                                }
                                span { "by {version.author_name}" }
                                span { "· {format_utc_as_local_time(version.time.timestamp_millis())}" }
                            }
                            if !version.title.is_empty() {
                                p { class: "font-medium text-text mt-1", dir: "auto", "{version.title}" }
                            }
                            if !version.text.is_empty() {
                                p { class: "whitespace-pre-wrap mt-1", dir: "auto", "{version.text}" }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Shared edit form component
#[component]
fn MessageEditForm(
    edit_title: Signal<String>,
    edit_text: Signal<String>,
    editing: Signal<bool>,
    original_title: String,
    original_text: String,
    msg_id: MessageId,
    on_edit: Option<EventHandler<(MessageId, String, String)>>,
    size: MessageSize,
    /// Maximum title length (from board configuration)
    max_title_size: usize,
    /// Maximum message length (from board configuration)
    max_message_size: usize,
    #[props(default)]
    member_names: HashMap<MemberId, String>,
) -> Element {
    let mention_directory = use_memo(move || {
        crate::util::mentions::MentionDirectory::from_names(
            member_names
                .iter()
                .map(|(id, name)| (*id, name.clone())),
        )
    });
    let mut mention_autocomplete =
        use_signal(|| None::<crate::util::mentions::MentionAutocomplete>);
    let mention_context = mention_autocomplete.read().clone();
    let mention_items = mention_context
        .as_ref()
        .map(|context| mention_directory.read().search(&context.query))
        .unwrap_or_default();
    let (input_class, textarea_class, button_class, container_class) = match size {
        MessageSize::Compact => (
            "w-full p-2 rounded-lg text-sm bg-surface border border-border text-text",
            "w-full p-2 rounded-lg text-sm bg-surface border border-border text-text resize-y min-h-[80px]",
            "text-xs px-2 py-1 rounded",
            "space-y-2",
        ),
        _ => (
            "w-full p-3 rounded-lg bg-surface border border-border text-text",
            "w-full p-3 rounded-lg bg-surface border border-border text-text resize-y min-h-[120px]",
            "px-4 py-2 rounded-lg",
            "space-y-4",
        ),
    };

    let original_title_for_key = original_title.clone();
    let original_title_for_save = original_title.clone();
    let original_text_for_key = original_text.clone();
    let original_text_for_save = original_text.clone();
    let msg_id_for_key = msg_id.clone();
    let msg_id_for_save = msg_id.clone();

    // Use Ctrl+Enter for Card, Enter for Reply
    let use_ctrl = !matches!(size, MessageSize::Compact);

    // Check if content has changed (closure that can be called multiple times)
    let has_changes = {
        let original_title = original_title_for_key.clone();
        let original_text = original_text_for_key.clone();
        move || {
            let new_title = edit_title.read().clone();
            let new_text = edit_text.read().clone();
            !new_text.is_empty() && (new_title != original_title || new_text != original_text)
        }
    };

    // Check if within limits
    let within_limits = move || {
        edit_title.read().len() <= max_title_size && edit_text.read().len() <= max_message_size
    };

    // Compute derived state for the button
    let can_save = use_memo(move || {
        let new_title = edit_title.read().clone();
        let new_text = edit_text.read().clone();
        let changed = !new_text.is_empty()
            && (new_title != original_title_for_key || new_text != original_text_for_key);
        let valid =
            edit_title.read().len() <= max_title_size && edit_text.read().len() <= max_message_size;
        changed && valid
    });

    rsx! {
        div { class: "{container_class}",
            // Title input with character count
            div { class: "space-y-1",
                div { class: "flex items-center justify-between",
                    span { class: "text-xs text-text-muted", "Title (optional)" }
                    span {
                        class: if edit_title.read().len() > max_title_size { "text-xs text-red-400" } else { "text-xs text-text-muted" },
                        "{edit_title.read().len()}/{max_title_size}"
                    }
                }
                input {
                    r#type: "text",
                    class: "{input_class}",
                    placeholder: "Title (optional)",
                    maxlength: max_title_size as i64,
                    value: "{edit_title}",
                    oninput: move |e| {
                        // Strip newlines from title
                        let value = e.value().replace(['\n', '\r'], "");
                        edit_title.set(value);
                    },
                    onkeydown: move |e: KeyboardEvent| {
                        if e.key() == Key::Escape {
                            editing.set(false);
                        }
                    },
                }
            }
            // Content textarea with character count
            div { class: "space-y-1",
                div { class: "flex items-center justify-between",
                    span { class: "text-xs text-text-muted", "Content" }
                    span {
                        class: if edit_text.read().len() > max_message_size { "text-xs text-red-400" } else { "text-xs text-text-muted" },
                        "{edit_text.read().len()}/{max_message_size}"
                    }
                }
                div { class: "relative",
                    textarea {
                        id: "edit-message-input",
                        class: "{textarea_class}",
                        value: "{edit_text}",
                        onmounted: move |cx| {
                            let element = cx.data();
                            wasm_bindgen_futures::spawn_local(async move {
                                let _ = element.set_focus(true).await;
                            });
                        },
                        oninput: move |e| {
                            edit_text.set(e.value().clone());
                            #[cfg(target_arch = "wasm32")]
                            {
                                mention_autocomplete.set(
                                    crate::util::mentions::textarea_context(
                                        "edit-message-input",
                                    ),
                                );
                            }
                        },
                        onkeydown: move |e: KeyboardEvent| {
                            if let Some(context) = mention_context.clone() {
                                let items = mention_directory.read().search(&context.query);
                                match e.key() {
                                    Key::ArrowDown => {
                                        e.prevent_default();
                                        if !items.is_empty() {
                                            mention_autocomplete.with_mut(|state| {
                                                if let Some(state) = state {
                                                    state.selected =
                                                        (state.selected + 1) % items.len();
                                                }
                                            });
                                        }
                                        return;
                                    }
                                    Key::ArrowUp => {
                                        e.prevent_default();
                                        if !items.is_empty() {
                                            mention_autocomplete.with_mut(|state| {
                                                if let Some(state) = state {
                                                    state.selected = if state.selected == 0 {
                                                        items.len() - 1
                                                    } else {
                                                        state.selected - 1
                                                    };
                                                }
                                            });
                                        }
                                        return;
                                    }
                                    Key::Enter | Key::Tab => {
                                        let index =
                                            context.selected.min(items.len().saturating_sub(1));
                                        if let Some(member) = items.get(index) {
                                            e.prevent_default();
                                            let value = crate::util::mentions::replace_context(
                                                "edit-message-input",
                                                &context,
                                                member,
                                            );
                                            edit_text.set(value);
                                            mention_autocomplete.set(None);
                                            return;
                                        }
                                    }
                                    Key::Escape => {
                                        mention_autocomplete.set(None);
                                        e.prevent_default();
                                        return;
                                    }
                                    _ => {}
                                }
                            }
                            if e.key() == Key::Escape {
                                editing.set(false);
                            } else if e.key() == Key::Enter {
                                let should_submit = if use_ctrl {
                                    e.modifiers().ctrl() || e.modifiers().meta()
                                } else {
                                    !e.modifiers().shift()
                                };
                                if should_submit {
                                    e.prevent_default();
                                    if has_changes() && within_limits() {
                                        if let Some(ref handler) = on_edit {
                                            handler.call((msg_id_for_key.clone(), edit_title.read().clone(), edit_text.read().clone()));
                                        }
                                    }
                                    editing.set(false);
                                }
                            }
                        },
                    }
                    if let Some(context) = mention_context.clone() {
                        if !mention_items.is_empty() {
                            div {
                                class: "mention-autocomplete absolute left-0 right-0 top-full z-50 mt-1 max-h-64 overflow-y-auto rounded-lg border border-border bg-panel shadow-xl",
                                for (index, member) in mention_items.iter().enumerate() {
                                    button {
                                        r#type: "button",
                                        class: if index == context.selected {
                                            "mention-option flex w-full items-center px-3 py-2 text-left text-sm bg-accent text-white"
                                        } else {
                                            "mention-option flex w-full items-center px-3 py-2 text-left text-sm text-text hover:bg-surface-hover"
                                        },
                                        onmousedown: move |event| event.prevent_default(),
                                        onclick: {
                                            let member = member.clone();
                                            let context = context.clone();
                                            move |_| {
                                                let value = crate::util::mentions::replace_context(
                                                    "edit-message-input",
                                                    &context,
                                                    &member,
                                                );
                                                edit_text.set(value);
                                                mention_autocomplete.set(None);
                                            }
                                        },
                                        "@{member.name}"
                                    }
                                }
                                div { class: "px-3 py-1.5 text-[10px] text-text-muted border-t border-border",
                                    "↑↓ select · Enter insert · Esc close"
                                }
                            }
                        }
                    }
                }
            }
            div { class: if matches!(size, MessageSize::Compact) { "flex gap-2" } else { "flex gap-3" },
                button {
                    class: "{button_class} bg-surface hover:bg-border text-text",
                    onclick: move |_| editing.set(false),
                    "Cancel"
                }
                button {
                    class: "{button_class} bg-accent text-white disabled:opacity-50 disabled:cursor-not-allowed",
                    disabled: !*can_save.read(),
                    onclick: move |_| {
                        let new_title = edit_title.read().clone();
                        let new_text = edit_text.read().clone();
                        if !new_text.is_empty() && (new_title != original_title_for_save || new_text != original_text_for_save) && within_limits() {
                            if let Some(ref handler) = on_edit {
                                handler.call((msg_id_for_save.clone(), new_title, new_text));
                            }
                        }
                        editing.set(false);
                    },
                    "Save"
                }
            }
        }
    }
}

/// Shared reactions display component
#[component]
fn ReactionDisplay(
    reactions: HashMap<String, Vec<MemberId>>,
    self_member_id: MemberId,
    member_names: HashMap<MemberId, String>,
    msg_id: MessageId,
    on_react: Option<EventHandler<(MessageId, String)>>,
    size: MessageSize,
) -> Element {
    if reactions.is_empty() {
        return rsx! {};
    }

    let (container_class, badge_class, count_class) = match size {
        MessageSize::Compact => (
            "flex flex-wrap items-center gap-1 mt-2",
            "inline-flex items-center gap-0.5 text-sm",
            "text-xs text-text-muted",
        ),
        _ => (
            "flex flex-wrap items-center gap-2 px-6 pb-4",
            "inline-flex items-center gap-1 px-2 py-1 rounded-full bg-surface text-base",
            "text-sm text-text-muted",
        ),
    };

    let mut sorted: Vec<_> = reactions.iter().collect();
    sorted.sort_by_key(|(e, _)| e.as_str());
    let mut open_owners = use_signal(|| None::<String>);

    rsx! {
        div { class: "{container_class}",
            {sorted.into_iter().map(|(emoji, reactors)| {
                let count = reactors.len();
                let is_user = reactors.contains(&self_member_id);
                let emoji_click = emoji.clone();
                let msg_id_click = msg_id.clone();
                let names: Vec<String> = reactors.iter().map(|id| {
                    if *id == self_member_id {
                        "You".to_string()
                    } else if let Some(name) = member_names.get(id) {
                        name.clone()
                    } else {
                        "Unknown".to_string()
                    }
                }).collect();
                let tooltip = if is_user {
                    format!("{} (click to remove)", names.join(", "))
                } else {
                    format!("{} (click to add)", names.join(", "))
                };

                let highlight_class = if matches!(size, MessageSize::Compact) {
                    if is_user { "cursor-pointer underline decoration-accent" } else { "" }
                } else {
                    if is_user { "cursor-pointer ring-1 ring-accent" } else { "" }
                };

                rsx! {
                    span {
                        key: "{emoji}",
                        class: format!("{} {} reaction-chip", badge_class, highlight_class),
                        title: "{tooltip}",
                        onclick: move |e| {
                            e.stop_propagation();
                            // Clicking an existing chip either adds this user
                            // or removes their own reaction.
                            if let Some(ref handler) = on_react {
                                handler.call((msg_id_click.clone(), emoji_click.clone()));
                            }
                        },
                        "{emoji}"
                        span {
                            class: "{count_class} reaction-count px-1",
                            title: "Show who reacted",
                            aria_label: "Show who reacted",
                            onclick: {
                                let owners_emoji = emoji.clone();
                                move |event| {
                                    event.stop_propagation();
                                    open_owners.set(Some(owners_emoji.clone()));
                                }
                            },
                            "{count}"
                        }
                        span { class: "reaction-tooltip", "{tooltip}" }
                    }
                }
            })}
        }
        if let Some(emoji) = open_owners() {
            if let Some(reactors) = reactions.get(&emoji) {
                div {
                    class: "fixed inset-0 z-[70] flex items-center justify-center bg-black/40 p-4",
                    onclick: move |_| open_owners.set(None),
                    div {
                        class: "reaction-owners-popover w-full max-w-xs rounded-xl border border-border bg-panel p-4 shadow-xl",
                        onclick: move |event| event.stop_propagation(),
                        div { class: "mb-2 text-lg font-semibold text-text", "{emoji} reactions" }
                        div { class: "space-y-1",
                            for reactor in reactors {
                                div { class: "text-sm text-text",
                                    if *reactor == self_member_id {
                                        "You"
                                    } else {
                                        {member_names.get(reactor).cloned().unwrap_or_else(|| "Unknown".to_string())}
                                    }
                                }
                            }
                        }
                        button {
                            r#type: "button",
                            class: "mt-3 w-full rounded-lg bg-surface px-3 py-1.5 text-sm text-text hover:bg-surface-hover",
                            onclick: move |_| open_owners.set(None),
                            "Close"
                        }
                    }
                }
            }
        }
    }
}

/// Shared action buttons component (hover menu)
#[component]
fn ActionButtons(
    msg_id: MessageId,
    is_self: bool,
    title_text: String,
    content_text: String,
    author_name: String,
    content_preview: String,
    editing: Signal<bool>,
    edit_title: Signal<String>,
    edit_text: Signal<String>,
    is_hovered: Signal<bool>,
    on_react: Option<EventHandler<(MessageId, String)>>,
    on_reply: Option<EventHandler<ReplyContext>>,
    on_edit: Option<EventHandler<(MessageId, String, String)>>,
    on_request_delete: Option<EventHandler<MessageId>>,
    #[props(default)] can_moderate: bool,
    /// The viewer may delete this message without other moderation powers
    /// (the author of an auto-moderated topic, on its replies).
    #[props(default)] can_delete: bool,
    size: MessageSize,
) -> Element {
    // Create emoji picker state locally to ensure it's element-specific
    let mut open_emoji_picker = use_signal(|| false);

    let has_actions = on_react.is_some()
        || on_reply.is_some()
        || ((is_self || can_moderate || can_delete)
            && (on_edit.is_some() || on_request_delete.is_some()));

    if !has_actions || !*is_hovered.read() {
        return rsx! {};
    }

    let (container_class, button_class, picker_button_class, picker_grid_class) = match size {
        MessageSize::Compact => (
            "absolute right-2 top-2 flex gap-1 bg-panel rounded shadow border border-border px-1 py-0.5",
            "text-xs text-text-muted hover:text-accent px-1",
            "p-1 rounded hover:bg-surface text-lg",
            "grid gap-[2px]",
        ),
        _ => (
            "absolute right-4 top-4 flex gap-1 bg-panel rounded-lg shadow border border-border px-2 py-1",
            "text-sm text-text-muted hover:text-accent px-2",
            "p-2 rounded hover:bg-surface text-xl",
            "grid gap-1",
        ),
    };

    let msg_id_for_react = msg_id.clone();
    let msg_id_for_reply = msg_id.clone();
    let msg_id_for_delete = msg_id.clone();

    rsx! {
        div {
            class: "{container_class}",
            onclick: move |e| e.stop_propagation(),

            // React button with emoji picker
            if on_react.is_some() {
                div { class: "relative",
                    button {
                        class: "{button_class}",
                        onclick: move |_| open_emoji_picker.set(!open_emoji_picker()),
                        "+"
                    }
                    if *open_emoji_picker.read() {
                        div {
                            class: "fixed inset-0 z-40",
                            onclick: move |_| open_emoji_picker.set(false),
                        }
                        div {
                            class: "absolute right-0 top-full mt-1 p-1 bg-panel rounded shadow border border-border z-50 {picker_grid_class}",
                            style: "grid-template-columns: repeat(4, 1fr);",
                            {FREQUENT_EMOJIS.iter().map({
                                let msg_id = msg_id_for_react.clone();
                                move |emoji| {
                                    let e = emoji.to_string();
                                    let mid = msg_id.clone();
                                    rsx! {
                                        button {
                                            key: "{emoji}",
                                            class: "{picker_button_class}",
                                            onclick: move |_| {
                                                if let Some(ref handler) = on_react {
                                                    handler.call((mid.clone(), e.clone()));
                                                }
                                                open_emoji_picker.set(false);
                                            },
                                            "{emoji}"
                                        }
                                    }
                                }
                            })}
                        }
                    }
                }
            }

            // Reply button
            if let Some(ref reply_handler) = on_reply {
                button {
                    class: "{button_class}",
                    onclick: {
                        let handler = reply_handler.clone();
                        let msg_id = msg_id_for_reply.clone();
                        let author = author_name.clone();
                        let preview = content_preview.clone();
                        move |_| {
                            handler.call(ReplyContext {
                                message_id: msg_id.clone(),
                                author_name: author.clone(),
                                content_preview: preview.clone(),
                            });
                        }
                    },
                    "reply"
                }
            }

            // Edit button (own messages, or moderators)
            if (is_self || can_moderate) && on_edit.is_some() {
                button {
                    class: if matches!(size, MessageSize::Compact) { "text-xs text-text-muted hover:text-text px-1" } else { "text-sm text-text-muted hover:text-text px-2" },
                    onclick: {
                        let title = title_text.clone();
                        let text = crate::util::mentions::readable_mentions(&content_text);
                        move |_| {
                            edit_title.set(title.clone());
                            edit_text.set(text.clone());
                            editing.set(true);
                        }
                    },
                    "edit"
                }
            }
            // Delete button: the message author, moderators, and the author
            // of an auto-moderated topic acting on its replies.
            if is_self || can_moderate || can_delete {
                if let Some(ref delete_handler) = on_request_delete {
                    button {
                        class: if matches!(size, MessageSize::Compact) { "text-xs text-text-muted hover:text-red-500 px-1" } else { "text-sm text-text-muted hover:text-red-500 px-2" },
                        onclick: {
                            let handler = delete_handler.clone();
                            let msg_id = msg_id_for_delete.clone();
                            move |_| handler.call(msg_id.clone())
                        },
                        "delete"
                    }
                }
            }
        }
    }
}

/// Unified component for rendering messages in either card or reply style
/// Replaces both ReplyTreeNode and PostCard
#[component]
pub fn MessageCard(
    /// The message to display
    message: MessageData,
    /// Display variant (Card or Reply)
    #[props(default)]
    variant: MessageCardVariant,
    /// Self member ID for determining edit/delete permissions
    self_member_id: MemberId,
    /// Member names lookup for reaction tooltips
    #[props(default)]
    member_names: HashMap<MemberId, String>,
    /// Nested replies (for Reply variant)
    #[props(default)]
    replies: Vec<MessageWithReplies>,
    /// Nesting depth for indentation (Reply variant only)
    #[props(default = 0)]
    depth: u32,
    /// Whether this is expanded view with larger styling (Card variant only)
    #[props(default = false)]
    expanded: bool,
    /// Click handler for card navigation (Card variant only)
    #[props(default)]
    on_click: Option<EventHandler<()>>,
    /// Handler for reactions
    #[props(default)]
    on_react: Option<EventHandler<(MessageId, String)>>,
    /// Handler for delete requests
    #[props(default)]
    on_request_delete: Option<EventHandler<MessageId>>,
    /// Handler for edits (message_id, new_title, new_content)
    #[props(default)]
    on_edit: Option<EventHandler<(MessageId, String, String)>>,
    /// Handler for replies
    #[props(default)]
    on_reply: Option<EventHandler<ReplyContext>>,
    /// Whether to show replies section below (Card variant only)
    #[props(default = false)]
    show_replies: bool,
    /// Default reply context for replies section
    #[props(default)]
    default_reply_to: Option<ReplyContext>,
    /// Maximum title length (from board configuration)
    max_title_size: usize,
    /// Maximum message length (from board configuration)
    max_message_size: usize,
    /// Number of direct replies, shown as a summary in the post list
    #[props(default)]
    reply_count: usize,
    /// Last reply author and local time, shown next to the count
    #[props(default)]
    last_reply: Option<(String, String)>,
    /// Hide the body and show only the header/title (post list)
    #[props(default = false)]
    hide_content: bool,
    /// The viewer has moderation powers over this post
    #[props(default)]
    can_moderate: bool,
    /// The viewer may react; readers of a demo board may not
    #[props(default = true)]
    can_react: bool,
    /// Open attached images without a click (topic or profile preference).
    #[props(default)]
    auto_load_images: bool,
) -> Element {
    let msg = message.clone();
    let is_self = msg.is_self;

    // The owner can turn reactions off for the whole board.
    let reactions_enabled = use_memo(move || {
        let Some(key) = CURRENT_BOARD.read().owner_key else {
            return true;
        };
        BOARDS
            .read()
            .map
            .get(&key)
            .map(|board| board.reactions_enabled())
            .unwrap_or(true)
    });
    // A reader of a demo board sees existing reactions but cannot add one.
    let on_react = if can_react && *reactions_enabled.read() {
        on_react
    } else {
        None
    };

    let timestamp_ms = msg.time.timestamp_millis();
    let time_str = format_utc_as_local_time(timestamp_ms);
    let full_time_str = if msg.time_clamped {
        format!(
            "{} (sender's clock may be incorrect)",
            format_utc_as_full_datetime(timestamp_ms)
        )
    } else {
        format_utc_as_full_datetime(timestamp_ms)
    };

    let editing = use_signal(|| false);
    let edit_title = use_signal(String::new);
    let edit_text = use_signal(String::new);
    let mut is_hovered = use_signal(|| false);

    let msg_id = msg.message_id.clone();
    let pending = crate::components::app::PENDING_POSTS
        .read()
        .contains_key(&msg_id);
    let content_preview = msg.content_text.chars().take(100).collect::<String>();
    let author_id = msg.author_id;
    let author_name = msg.author_name.clone();
    let title_text = msg.title_text.clone();
    let content_html = msg.content_html.clone();
    let content_text = msg.content_text.clone();
    let edited = msg.edited;
    let reactions = msg.reactions.clone();
    let images = msg.images.clone();
    let tagged_images = crate::util::image_tags::tagged_indices(&msg.content_text);
    let before_images: Vec<ImageRef> = images
        .iter()
        .enumerate()
        .filter(|(index, image)| {
            image.placement == ImagePlacement::Before && !tagged_images.contains(index)
        })
        .map(|(_, image)| image.clone())
        .collect();
    let after_images: Vec<ImageRef> = images
        .iter()
        .enumerate()
        .filter(|(index, image)| {
            image.placement != ImagePlacement::Before && !tagged_images.contains(index)
        })
        .map(|(_, image)| image.clone())
        .collect();

    // A light preview for the compact post list, where the body is hidden.
    let preview_tooltip = if hide_content && !content_text.trim().is_empty() {
        let mut preview: String = content_text.chars().take(500).collect();
        if content_text.chars().count() > 500 {
            preview.push('…');
        }
        preview
    } else {
        String::new()
    };

    // In card views the title moves next to the author. Give untitled posts
    // something to show when the body is hidden.
    let header_title = if title_text.trim().is_empty() {
        "Untitled".to_string()
    } else if edited {
        format!("{title_text} (edited)")
    } else {
        title_text.clone()
    };
    let header_title = match (msg.is_pinned, msg.is_closed) {
        (true, true) => format!("📌 🔒 {header_title}"),
        (true, false) => format!("📌 {header_title}"),
        (false, true) => format!("🔒 {header_title}"),
        _ => header_title,
    };
    let header_title = if msg.is_auto_moderated {
        format!("🛡️ {header_title}")
    } else {
        header_title
    };

    // Determine size based on variant and expanded state
    let size = match variant {
        MessageCardVariant::Reply => MessageSize::Compact,
        MessageCardVariant::Card if expanded => MessageSize::Large,
        MessageCardVariant::Card => MessageSize::Normal,
    };

    match variant {
        MessageCardVariant::Reply => {
            // Indent based on depth (max 4 levels visually)
            let indent_class = match depth.min(2) {
                0 => "",
                1 => "ml-8",
                _ => "ml-16",
            };

            rsx! {
                div {
                    key: "{msg_id:?}",
                    class: "{indent_class}",
                    // Message card
                    div {
                        class: "relative border-l-2 pl-4 py-2 hover:bg-surface/30 transition-colors",
                        style: "border-color: {member_id_to_color(&author_id)};",
                        onmouseenter: move |_| is_hovered.set(true),
                        onmouseleave: move |_| is_hovered.set(false),

                        // Header
                        div { class: "flex items-center gap-3 mb-2",
                            MessageHeader {
                                author_id: author_id,
                                author_name: author_name.clone(),
                                is_self: is_self,
                                time_str: time_str.clone(),
                                full_time_str: full_time_str.clone(),
                                time_clamped: msg.time_clamped,
                                size: size,
                                pending: pending,
                                thumb: if hide_content {
                                    images.iter().find(|image| image.thumb.is_some()).cloned()
                                } else {
                                    None
                                },
                            }
                        }

                        // Content (or edit form)
                        if !before_images.is_empty() {
                            div { class: "mt-1 space-y-1",
                                for image in before_images.iter() {
                                    div {
                                        class: match image.align {
                                            ImageAlign::Left => "flex justify-start",
                                            ImageAlign::Center => "flex justify-center",
                                            ImageAlign::Right => "flex justify-end",
                                        },
                                        ImageAttachment { image: image.clone(), auto_load: auto_load_images, gallery: images.clone() }
                                    }
                                }
                            }
                        }
                        if *editing.read() {
                            MessageEditForm {
                                edit_title: edit_title,
                                edit_text: edit_text,
                                editing: editing,
                                original_title: title_text.clone(),
                                original_text: content_text.clone(),
                                msg_id: msg_id.clone(),
                                on_edit: on_edit.clone(),
                                size: size,
                                max_title_size: max_title_size,
                                max_message_size: max_message_size,
                                member_names: member_names.clone(),
                            }
                        } else {
                            MessageContentDisplay {
                                title_text: title_text.clone(),
                                content_html: content_html.clone(),
                                content_text: content_text.clone(),
                                member_names: member_names.clone(),
                                self_member_id: Some(self_member_id),
                                edited: edited,
                                history: msg.edit_history.clone(),
                                size: size,
                                expanded: false,
                                images: images.clone(),
                                auto_load_images: auto_load_images,
                            }
                        }

                        if !after_images.is_empty() {
                            div { class: "mt-1 space-y-1",
                                for image in after_images.iter() {
                                    div {
                                        class: match image.align {
                                            ImageAlign::Left => "flex justify-start",
                                            ImageAlign::Center => "flex justify-center",
                                            ImageAlign::Right => "flex justify-end",
                                        },
                                        ImageAttachment { image: image.clone(), auto_load: auto_load_images, gallery: images.clone() }
                                    }
                                }
                            }
                        }

                        // Reactions
                        if *reactions_enabled.read() {
                            ReactionDisplay {
                                reactions: reactions.clone(),
                                self_member_id: self_member_id,
                                member_names: member_names.clone(),
                                msg_id: msg_id.clone(),
                                on_react: on_react.clone(),
                                size: size,
                            }
                        }

                        // Action buttons
                        ActionButtons {
                            msg_id: msg_id.clone(),
                            is_self: is_self,
                            title_text: title_text.clone(),
                            content_text: content_text.clone(),
                            author_name: author_name.clone(),
                            content_preview: content_preview.clone(),
                            editing: editing,
                            edit_title: edit_title,
                            edit_text: edit_text,
                            is_hovered: is_hovered,
                            on_react: on_react.clone(),
                            on_reply: on_reply.clone(),
                            on_edit: on_edit.clone(),
                            on_request_delete: on_request_delete.clone(),
                            can_moderate: can_moderate,
                            can_delete: can_moderate || msg.can_delete_as_topic_author,
                            size: size,
                        }
                    }

                    // Nested replies (recursive)
                    if !replies.is_empty() {
                        div { class: "mt-1",
                            {replies.iter().map({
                                let member_names = member_names.clone();
                                move |reply| {
                                    let member_names = member_names.clone();
                                    rsx! {
                                        MessageCard {
                                            message: reply.message.clone(),
                                            variant: MessageCardVariant::Reply,
                                            self_member_id: self_member_id,
                                            member_names: member_names,
                                            replies: reply.replies.clone(),
                                            depth: depth + 1,
                                            max_title_size: max_title_size,
                                            max_message_size: max_message_size,
                                            auto_load_images: auto_load_images,
                                            can_moderate: can_moderate,
                                            can_react: can_react,
                                            on_react: on_react.clone(),
                                            on_request_delete: on_request_delete.clone(),
                                            on_edit: on_edit.clone(),
                                            on_reply: on_reply.clone(),
                                        }
                                    }
                                }
                            })}
                        }
                    }
                }
            }
        }

        MessageCardVariant::Card => {
            let (header_padding, content_padding) = if expanded {
                ("px-8 py-6", "px-8 py-8")
            } else {
                ("px-6 py-4", "px-6 py-6")
            };

            let card_class = if on_click.is_some() {
                "bg-panel rounded-2xl border border-border shadow-sm overflow-hidden hover:border-accent/50 transition-colors cursor-pointer"
            } else {
                "bg-panel rounded-2xl border border-border shadow-sm overflow-hidden"
            };

            // Create reply context for when show_replies is enabled
            let msg_id_for_replies = msg_id.clone();
            let reply_context_for_section = if show_replies {
                Some(ReplyContext {
                    message_id: msg_id.clone(),
                    author_name: author_name.clone(),
                    content_preview: content_preview.clone(),
                })
            } else {
                None
            };

            rsx! {
                div {
                    key: "{msg_id:?}",
                    class: "relative",
                    title: preview_tooltip,
                    onmouseenter: move |_| is_hovered.set(true),
                    onmouseleave: move |_| is_hovered.set(false),

                    div {
                        class: "{card_class}",
                        onclick: move |_| {
                            if let Some(ref handler) = on_click {
                                handler.call(());
                            }
                        },

                        // Header
                        div {
                            class: "flex items-center gap-4 {header_padding} border-b border-border bg-surface/30",
                            MessageHeader {
                                author_id: author_id,
                                author_name: author_name.clone(),
                                is_self: is_self,
                                time_str: time_str.clone(),
                                full_time_str: full_time_str.clone(),
                                time_clamped: msg.time_clamped,
                                size: size,
                                pending: pending,
                                title: Some(header_title.clone()),
                                thumb: if hide_content {
                                    images.iter().find(|image| image.thumb.is_some()).cloned()
                                } else {
                                    None
                                },
                            }
                        }

                        // Content. The post list hides it and shows only the
                        // title in the header.
                        if !hide_content {
                            div { class: "{content_padding}",
                                if msg.is_auto_moderated {
                                    p { class: "mb-2 text-xs text-text-muted",
                                        "🛡️ Auto-moderated: the author can delete replies. They never delete the topic this way."
                                    }
                                }
                                if !before_images.is_empty() {
                                    div { class: "mb-1 space-y-1",
                                        for image in before_images.iter() {
                                            div {
                                                class: match image.align {
                                                    ImageAlign::Left => "flex justify-start",
                                                    ImageAlign::Center => "flex justify-center",
                                                    ImageAlign::Right => "flex justify-end",
                                                },
                                                ImageAttachment { image: image.clone(), auto_load: auto_load_images, gallery: images.clone() }
                                            }
                                        }
                                    }
                                }
                                if *editing.read() {
                                    MessageEditForm {
                                        edit_title: edit_title,
                                        edit_text: edit_text,
                                        editing: editing,
                                        original_title: title_text.clone(),
                                        original_text: content_text.clone(),
                                        msg_id: msg_id.clone(),
                                        on_edit: on_edit.clone(),
                                        size: size,
                                        max_title_size: max_title_size,
                                        max_message_size: max_message_size,
                                        member_names: member_names.clone(),
                                    }
                                } else {
                                    MessageContentDisplay {
                                        title_text: title_text.clone(),
                                        content_html: content_html.clone(),
                                        content_text: content_text.clone(),
                                        member_names: member_names.clone(),
                                        self_member_id: Some(self_member_id),
                                        edited: edited,
                                        history: msg.edit_history.clone(),
                                        size: size,
                                        expanded: expanded,
                                        show_title: false,
                                        images: images.clone(),
                                        auto_load_images: auto_load_images,
                                    }
                                    if !hide_content {
                                        if let Some(poll) = msg.poll.as_ref() {
                                            poll_view::PollView {
                                                poll: poll.clone(),
                                                poll_id: msg_id,
                                                self_member_id: self_member_id,
                                                is_author: msg.is_self,
                                            }
                                        }
                                        if !after_images.is_empty() {
                                            div { class: "mt-1 space-y-1",
                                                for image in after_images.iter() {
                                                    div {
                                                        class: match image.align {
                                                            ImageAlign::Left => "flex justify-start",
                                                            ImageAlign::Center => "flex justify-center",
                                                            ImageAlign::Right => "flex justify-end",
                                                        },
                                                        ImageAttachment { image: image.clone(), auto_load: auto_load_images, gallery: images.clone() }
                                                    }
                                                }
                                            }
                                        }
                                    } else if !images.is_empty() {
                                        span { class: "ml-2 text-xs text-text-muted",
                                            "📷 {images.len()}"
                                        }
                                    }
                                }
                            }
                        }

                        if !msg.is_closed {
                            // Reactions
                            if *reactions_enabled.read() {
                                ReactionDisplay {
                                    reactions: reactions.clone(),
                                    self_member_id: self_member_id,
                                    member_names: member_names.clone(),
                                    msg_id: msg_id.clone(),
                                    on_react: on_react.clone(),
                                    size: size,
                                }
                            }

                            // Action buttons
                            ActionButtons {
                                msg_id: msg_id.clone(),
                                is_self: is_self,
                                title_text: title_text.clone(),
                                content_text: content_text.clone(),
                                author_name: author_name.clone(),
                                content_preview: content_preview.clone(),
                                editing: editing,
                                edit_title: edit_title,
                                edit_text: edit_text,
                                is_hovered: is_hovered,
                                on_react: on_react.clone(),
                                on_reply: on_reply.clone(),
                                on_edit: on_edit.clone(),
                                on_request_delete: on_request_delete.clone(),
                                can_moderate: can_moderate,
                                can_delete: can_moderate || msg.can_delete_as_topic_author,
                                size: size,
                            }
                        }

                        // Reply summary for the post list
                        if reply_count > 0 || last_reply.is_some() {
                            div { class: "px-6 py-2 border-t border-border bg-surface/20 flex flex-wrap items-center gap-2 text-xs text-text-muted",
                                span {
                                    if reply_count == 1 {
                                        "1 reply"
                                    } else {
                                        "{reply_count} replies"
                                    }
                                }
                                if let Some((author, time)) = last_reply.clone() {
                                    span { "· last reply {time} by {author}" }
                                }
                            }
                        }
                    }

                    // Replies section (if enabled)
                    if show_replies {
                        div { class: "mt-4",
                            h3 { class: "text-lg font-semibold text-text-muted border-b border-border pb-2 mb-4",
                                "Replies"
                            }
                            Conversation {
                                parent_message_id: Some(msg_id_for_replies),
                                default_reply_to: reply_context_for_section.or(default_reply_to),
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Get all top-level posts (messages that are not replies and not categories)
pub fn get_top_level_posts(all_messages: &[MessageData]) -> Vec<MessageData> {
    let mut posts: Vec<_> = all_messages
        .iter()
        .filter(|m| m.is_top_level_post() && !m.is_category && m.merged_into.is_none())
        .cloned()
        .collect();
    posts.sort_by_key(|m| std::cmp::Reverse(m.time));
    posts
}

/// Get all top-level categories (categories with no parent)
pub fn get_top_level_categories(all_messages: &[MessageData]) -> Vec<MessageData> {
    let mut categories: Vec<_> = all_messages
        .iter()
        .filter(|m| {
            m.is_category
                && m.parent_category_id.is_none()
                && !(m.category_hidden && m.category_locked)
        })
        .cloned()
        .collect();
    categories.sort_by_key(|m| m.time);
    categories
}

/// Get subcategories of a specific category
pub fn get_subcategories(
    all_messages: &[MessageData],
    category_id: &MessageId,
) -> Vec<MessageData> {
    let mut subcategories: Vec<_> = all_messages
        .iter()
        .filter(|m| {
            m.is_category
                && !m.is_group
                && m.parent_category_id.as_ref() == Some(category_id)
                && !(m.category_hidden && m.category_locked)
        })
        .cloned()
        .collect();
    subcategories.sort_by_key(|m| m.time);
    subcategories
}

/// Get posts within a category (non-category messages that reply to the category)
pub fn get_category_posts(
    all_messages: &[MessageData],
    category_id: &MessageId,
) -> Vec<MessageData> {
    let mut posts: Vec<_> = all_messages
        .iter()
        .filter(|m| {
            !m.is_category
                && m.merged_into.is_none()
                && (m.category_id.as_ref() == Some(category_id)
                    // Older posts used the category as their reply target.
                    || m.reply_to_message_id.as_ref() == Some(category_id))
        })
        .cloned()
        .collect();
    posts.sort_by_key(|m| std::cmp::Reverse(m.time));
    posts
}

#[cfg(test)]
mod category_tests {
    use super::extract_category_info;
    use crate::util::ecies::seal_bytes;
    use plaza_core::board_state::content::{
        CategoryContentV1, CATEGORY_CONTENT_VERSION, CONTENT_TYPE_CATEGORY,
    };
    use plaza_core::board_state::message::{BoardMessageBody, MessageId};
    use plaza_core::board_state::privacy::SealedBytes;
    use std::collections::HashMap;

    fn sealed_category(name: &str, secret: &[u8; 32]) -> BoardMessageBody {
        let cat = CategoryContentV1::new(name.to_string(), None, "#6366f1".to_string());
        let sealed = seal_bytes(&cat.encode(), secret, 0);
        match sealed {
            SealedBytes::Private {
                ciphertext,
                nonce,
                secret_version,
                ..
            } => BoardMessageBody::Private {
                content_type: CONTENT_TYPE_CATEGORY,
                content_version: CATEGORY_CONTENT_VERSION,
                ciphertext,
                nonce,
                secret_version,
                secret_scope: plaza_core::board_state::message::SecretScope::Board,
            },
            _ => unreachable!("seal_bytes always produces a private payload"),
        }
    }

    fn message_id() -> MessageId {
        MessageId::from_bytes([42u8; 32])
    }

    #[test]
    fn private_category_is_decoded_with_the_board_secret() {
        let secret = [7u8; 32];
        let content = sealed_category("Segreta", &secret);

        let mut secrets = HashMap::new();
        secrets.insert(0u32, secret);
        let info = extract_category_info(
            &content,
            &secrets,
            &HashMap::new(),
            &HashMap::new(),
            &message_id(),
        )
        .expect("category decodes");
        assert_eq!(info.name.as_deref(), Some("Segreta"));
        assert_eq!(info.color.as_deref(), Some("#6366f1"));
        assert!(!info.locked);

        // Without the secret the content is unreadable, so it is not listed as
        // a category at all.
        assert!(extract_category_info(
            &content,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            &message_id(),
        )
        .is_none());
    }

    #[test]
    fn restricted_category_name_opens_only_with_its_secret() {
        let category_secret = [9u8; 32];
        let id = message_id();
        let sealed_name = crate::util::ecies::seal_bytes(b"Members only", &category_secret, 0);
        let cat = CategoryContentV1::new(
            "Restricted category".to_string(),
            Some("desc".to_string()),
            "#6366f1".to_string(),
        )
        .with_allowed_roles(vec![[1u8; 16]], sealed_name, true);
        let content = BoardMessageBody::Public {
            content_type: CONTENT_TYPE_CATEGORY,
            content_version: CATEGORY_CONTENT_VERSION,
            data: cat.encode(),
        };

        let mut category_secrets = HashMap::new();
        category_secrets.insert(id.clone(), (0u32, category_secret));
        let readable = extract_category_info(
            &content,
            &HashMap::new(),
            &category_secrets,
            &HashMap::new(),
            &id,
        )
        .expect("category decodes");
        assert_eq!(readable.name.as_deref(), Some("Members only"));
        assert!(!readable.locked);
        assert!(readable.hidden);

        let outsider = extract_category_info(
            &content,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            &id,
        )
        .expect("placeholder is still visible");
        assert_eq!(outsider.name.as_deref(), Some("Restricted category"));
        assert!(outsider.locked);
    }
}
