use crate::components::app::receive_times::get_delay_secs;
use crate::util::ecies::unseal_bytes_with_secrets;
pub mod emoji_picker;
pub mod image_attachment;
use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use plaza_core::board_state::content::CategoryContentV1;
use plaza_core::board_state::member::MemberId;
use plaza_core::board_state::message::{BoardMessageBody, MessageId, SecretScope};
use plaza_core::board_state::roles::RoleId;
use std::collections::HashMap;

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
