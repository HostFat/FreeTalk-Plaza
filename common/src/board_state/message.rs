use crate::board_state::id::BoardId;
use crate::board_state::member::MemberId;
use crate::board_state::privacy::{PrivacyMode, SecretVersion};
use crate::board_state::ChatBoardParametersV1;
use crate::util::sign_struct;
use crate::util::{truncated_base64, verify_struct};
use crate::ChatBoardStateV1;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

use freenet_scaffold::ComposableState;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::time::SystemTime;

use crate::board_state::content::CategoryEditPayload;
use crate::board_state::content::{
    ReplyContentV1, TextContentV1, ACTION_TYPE_SET_SECTION_IMAGES, CONTENT_TYPE_REPLY,
    CONTENT_TYPE_TEXT,
};

/// Whether the author may attach images at all: owner, admin, or a role with
/// `can_attach_images` that covers `section`. The section rule is checked
/// separately and wins.
pub fn author_may_attach_images(
    state: &ChatBoardStateV1,
    parameters: &ChatBoardParametersV1,
    author: &MemberId,
    section: Option<&MessageId>,
) -> bool {
    if *author == state.ownership.current_owner(parameters)
        || crate::board_state::roles::is_board_admin(state, author)
    {
        return true;
    }
    state.roles.can_attach_images(author, section)
}

/// Section recorded in a message body, when the contract can read it. Private
/// posts in a restricted section carry the section in the secret scope.
fn body_section(content: &BoardMessageBody) -> Option<MessageId> {
    match content {
        BoardMessageBody::Public {
            content_type, data, ..
        } if *content_type == CONTENT_TYPE_TEXT => {
            TextContentV1::decode(data).ok().and_then(|text| text.category_id)
        }
        BoardMessageBody::Public {
            content_type, data, ..
        } if *content_type == crate::board_state::content::CONTENT_TYPE_POLL => {
            crate::board_state::content::PollContentV1::decode(data)
                .ok()
                .and_then(|poll| poll.category_id)
        }
        BoardMessageBody::Private { secret_scope, .. } => match secret_scope {
            crate::board_state::message::SecretScope::Category(id) => Some(id.clone()),
            crate::board_state::message::SecretScope::Board => None,
        },
        _ => None,
    }
}

fn body_reply_target(content: &BoardMessageBody) -> Option<MessageId> {
    match content {
        BoardMessageBody::Public {
            content_type, data, ..
        } if *content_type == CONTENT_TYPE_REPLY => {
            ReplyContentV1::decode(data).ok().map(|reply| reply.target_message_id)
        }
        _ => None,
    }
}

/// The creation-time auto-moderated flag of a topic, when the contract can
/// read the body. Sealed posts on private boards return `None`.
fn body_auto_moderated(content: &BoardMessageBody) -> Option<bool> {
    use crate::board_state::content::{
        PollContentV1, TextContentV1, CONTENT_TYPE_POLL, CONTENT_TYPE_TEXT,
    };
    match content {
        BoardMessageBody::Public {
            content_type, data, ..
        } => match *content_type {
            CONTENT_TYPE_TEXT => TextContentV1::decode(data).ok().map(|text| text.auto_moderated),
            CONTENT_TYPE_POLL => PollContentV1::decode(data).ok().map(|poll| poll.auto_moderated),
            _ => None,
        },
        _ => None,
    }
}

/// Public action carried by a message, whether it travels bare or inside the
/// moderation envelope. Sealed payloads need a client key and are skipped.
fn public_action(content: &BoardMessageBody) -> Option<crate::board_state::content::ActionContentV1> {
    use crate::board_state::content::{
        ActionContentV1, CONTENT_TYPE_MODERATION_ACTION,
    };
    use crate::board_state::privacy::SealedBytes;
    match content {
        BoardMessageBody::Public {
            content_type, data, ..
        } => {
            if *content_type == CONTENT_TYPE_MODERATION_ACTION {
                let envelope =
                    crate::board_state::content::ModerationActionV1::decode(data).ok()?;
                match envelope.payload {
                    SealedBytes::Public { value } => ActionContentV1::decode(&value).ok(),
                    SealedBytes::Private { .. } => None,
                }
            } else {
                match content.decode_content() {
                    Some(crate::board_state::content::DecodedContent::Action(action)) => {
                        Some(action)
                    }
                    _ => None,
                }
            }
        }
        BoardMessageBody::Private { .. } => None,
    }
}


/// Validate the image references of one message against the board limits.
pub fn validate_message_images(
    message: &MessageV1,
    configuration: &crate::board_state::configuration::Configuration,
    enforce_limits: bool,
) -> Result<(), String> {
    if message.images.is_empty() {
        return Ok(());
    }
    if message.content.is_action() || message.content.is_category() {
        return Err("Only posts and replies can carry images".to_string());
    }
    // Limits are a posting rule. Messages already in the accepted state stay
    // valid when the owner lowers a limit; only new messages are checked.
    if enforce_limits {
        let max_images = configuration.images_per_message() as usize;
        if message.images.len() > max_images {
            return Err(format!(
                "Too many images in one message: {} > {}",
                message.images.len(),
                max_images
            ));
        }
    }
    for image in &message.images {
        if enforce_limits {
            image.validate(
                configuration.image_byte_limit(),
                configuration.animated_image_byte_limit(),
            )?;
        } else {
            image.validate(u32::MAX, u32::MAX)?;
        }
    }
    Ok(())
}

/// In a read-only board only the current owner and admins add content.
/// Every write travels as a message (posts, replies, reactions, edits,
/// deletes, reports, categories), so this one check covers them all.
pub fn author_may_write(
    state: &ChatBoardStateV1,
    parameters: &ChatBoardParametersV1,
    author: MemberId,
) -> bool {
    if !state.configuration.configuration.read_only {
        return true;
    }
    if author == state.ownership.current_owner(parameters) {
        return true;
    }
    state
        .admin
        .admins
        .iter()
        .any(|admin| admin.admin.id() == author)
}

/// Author of the auto-moderated topic a reply descends from, if any. The
/// topic itself returns `None`: its author may delete replies, not the root.
fn auto_moderated_root_author(
    target: &MessageId,
    reply_parent: &HashMap<MessageId, MessageId>,
    roots: &HashMap<MessageId, MemberId>,
) -> Option<MemberId> {
    let mut current = target.clone();
    for _ in 0..64 {
        let parent = reply_parent.get(&current)?.clone();
        if let Some(author) = roots.get(&parent) {
            return Some(*author);
        }
        current = parent;
    }
    None
}

/// Computed state for message actions (edits, deletes, reactions)
/// This is rebuilt from action messages and not serialized
#[derive(Clone, PartialEq, Debug, Default)]
pub struct MessageActionsState {
    /// Messages that have been edited: message_id -> new text content
    pub edited_content: HashMap<MessageId, String>,
    /// Categories that have been edited: message_id -> edit payload
    pub edited_categories: HashMap<MessageId, CategoryEditPayload>,
    /// Polls whose content was replaced by their author before any vote.
    pub edited_polls: HashMap<MessageId, crate::board_state::content::PollContentV1>,
    /// Messages that have been deleted
    pub deleted: std::collections::HashSet<MessageId>,
    /// Reactions on messages: message_id -> (emoji -> list of reactors)
    pub reactions: HashMap<MessageId, HashMap<String, Vec<MemberId>>>,
    /// Moderator overrides of a member's displayed nickname.
    pub nickname_overrides: HashMap<MemberId, NicknameOverride>,
}

/// The last signed nickname override for one member. The member's own
/// `MemberInfo` record stays untouched, so the override is reversible.
#[derive(Clone, PartialEq, Debug)]
pub struct NicknameOverride {
    pub nickname: String,
    /// Signed time in milliseconds; the highest version wins.
    pub version: u64,
    pub set_by: MemberId,
    pub set_at: SystemTime,
}

/// Moderation grants used while rebuilding edits/deletes locally.
#[derive(Clone, Debug, Default)]
pub struct ModerationPermissions {
    pub closed: std::collections::HashSet<MessageId>,
    pub grants: Vec<ModerationGrant>,
    /// Target message -> category chain used for scope checks
    pub scope_chains: HashMap<MessageId, Vec<MessageId>>,
}

#[derive(Clone, Debug)]
pub struct ModerationGrant {
    pub member_id: MemberId,
    pub can_edit: bool,
    pub can_delete: bool,
    pub scope: Vec<MessageId>,
}

impl ModerationPermissions {
    pub fn can(&self, member: MemberId, edit: bool, target: &MessageId) -> bool {
        let chain = self.scope_chains.get(target);
        self.grants.iter().any(|grant| {
            grant.member_id == member
                && if edit {
                    grant.can_edit
                } else {
                    grant.can_delete
                }
                && (grant.scope.is_empty()
                    || grant.scope.iter().any(|scope_id| {
                        chain.map(|chain| chain.contains(scope_id)).unwrap_or(false)
                    }))
        })
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct MessagesV1 {
    pub messages: Vec<AuthorizedMessageV1>,
    /// Computed state from action messages (not serialized - rebuilt on each delta)
    #[serde(skip)]
    pub actions_state: MessageActionsState,
}

impl ComposableState for MessagesV1 {
    type ParentState = ChatBoardStateV1;
    type Summary = BTreeSet<MessageId>;
    type Delta = Vec<AuthorizedMessageV1>;
    type Parameters = ChatBoardParametersV1;

    fn verify(
        &self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
    ) -> Result<(), String> {
        let members_by_id = parent_state.members.members_by_member_id();
        let owner_id = parameters.owner_id();

        for message in &self.messages {
            if !author_may_write(parent_state, parameters, message.message.author) {
                return Err(format!(
                    "Board is read-only: {:?} cannot write",
                    message.message.author
                ));
            }
            let verifying_key = if message.message.author == owner_id {
                // Owner's messages are validated against the owner's key
                &parameters.owner
            } else if let Some(member) = members_by_id.get(&message.message.author) {
                // Regular member messages are validated against their member key
                &member.member.member_vk
            } else {
                return Err(format!(
                    "Message author not found: {:?}",
                    message.message.author
                ));
            };

            if message.validate(verifying_key).is_err() {
                return Err(format!("Invalid message signature: id:{:?}", message.id()));
            }

            self.validate_images(parent_state, parameters, message)?;
        }

        // A member may not hold more posts than the window allows. The check
        // uses the signed times, so every peer evaluates it the same way.
        let configuration = &parent_state.configuration.configuration;
        if let Some(author) = crate::board_state::rate_limit::exceeding_member(
            self.messages.iter().map(|message| {
                (
                    message.message.author,
                    crate::board_state::rate_limit::system_time_ms(message.message.time),
                )
            }),
            configuration.rate_window() as i64,
            configuration.post_limit() as usize,
        ) {
            return Err(format!("Author {author:?} exceeded the posting rate limit"));
        }

        Ok(())
    }

    fn summarize(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
    ) -> Self::Summary {
        self.messages.iter().map(|m| m.id()).collect()
    }

    fn delta(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
        old_state_summary: &Self::Summary,
    ) -> Option<Self::Delta> {
        let delta: Vec<AuthorizedMessageV1> = self
            .messages
            .iter()
            .filter(|m| !old_state_summary.contains(&m.id()))
            .cloned()
            .collect();
        if delta.is_empty() {
            None
        } else {
            Some(delta)
        }
    }

    fn apply_delta(
        &mut self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
        delta: &Option<Self::Delta>,
    ) -> Result<(), String> {
        let max_message_size = parent_state.configuration.configuration.max_message_size;
        let max_title_size = parent_state.configuration.configuration.max_title_size;
        let privacy_mode = &parent_state.configuration.configuration.privacy_mode;
        let current_secret_version = parent_state.secrets.current_version;

        // Validate message constraints before adding
        if let Some(delta) = delta {
            for msg in delta {
                if !author_may_write(parent_state, parameters, msg.message.author) {
                    return Err(format!(
                        "Board is read-only: {:?} cannot write",
                        msg.message.author
                    ));
                }
                self.validate_images(parent_state, parameters, msg)?;
                if !self.messages.iter().any(|existing| existing.id() == msg.id()) {
                    self.validate_auto_moderated(parent_state, msg)?;
                }
                let content = &msg.message.content;

                // Validate title constraints (for public text/reply messages)
                if let Some(title) = content.title() {
                    if title.len() > max_title_size {
                        return Err(format!(
                            "Title length {} exceeds maximum {}",
                            title.len(),
                            max_title_size
                        ));
                    }
                    if title.contains('\n') || title.contains('\r') {
                        return Err("Title cannot contain newlines".to_string());
                    }
                }

                match content {
                    BoardMessageBody::Private {
                        secret_version,
                        secret_scope,
                        ..
                    } => {
                        // Category-sealed content uses the category key, so the
                        // board secret version and distribution do not apply.
                        if *secret_scope == SecretScope::Board {
                            // In private mode, verify secret version matches current
                            if *privacy_mode == PrivacyMode::Private
                                && *secret_version != current_secret_version
                            {
                                return Err(format!(
                                    "Private message secret version {} does not match current version {}",
                                    secret_version, current_secret_version
                                ));
                            }

                            // Verify all current members have encrypted blobs for this version
                            let members = parent_state.members.members_by_member_id();
                            if !parent_state.secrets.has_complete_distribution(&members) {
                                return Err(
                                    "Cannot accept private messages: incomplete secret distribution"
                                        .to_string(),
                                );
                            }
                        }
                    }
                    BoardMessageBody::Public { .. } => {
                        // In private mode, reject ALL public messages including actions
                        // Privacy is a layer - everything in a private board must be encrypted
                        if *privacy_mode == PrivacyMode::Private {
                            return Err("Cannot send public messages in private board".to_string());
                        }
                    }
                }
            }

            // Deduplicate by message ID to prevent duplicate messages from race conditions
            let existing_ids: std::collections::HashSet<_> =
                self.messages.iter().map(|m| m.id()).collect();

            // Reject a burst before touching the state: no author may exceed
            // the configured posts per window once the delta is merged.
            let configuration = &parent_state.configuration.configuration;
            let incoming_ids: std::collections::HashSet<_> =
                delta.iter().map(|message| message.id()).collect();
            let mut times = Vec::with_capacity(self.messages.len() + delta.len());
            for message in &self.messages {
                if !incoming_ids.contains(&message.id()) {
                    times.push((
                        message.message.author,
                        crate::board_state::rate_limit::system_time_ms(message.message.time),
                    ));
                }
            }
            for message in delta {
                times.push((
                    message.message.author,
                    crate::board_state::rate_limit::system_time_ms(message.message.time),
                ));
            }
            if let Some(author) = crate::board_state::rate_limit::exceeding_member(
                times.into_iter(),
                configuration.rate_window() as i64,
                configuration.post_limit() as usize,
            ) {
                return Err(format!("Author {author:?} exceeded the posting rate limit"));
            }

            self.messages.extend(
                delta
                    .iter()
                    .filter(|msg| !existing_ids.contains(&msg.id()))
                    .cloned(),
            );
        }

        // Always enforce message constraints
        // Ensure there are no messages over the size limit
        self.messages
            .retain(|m| m.message.content.content_len() <= max_message_size);

        // Ensure all messages are signed by a valid member or the board owner, remove if not
        let members_by_id = parent_state.members.members_by_member_id();
        let owner_id = MemberId::from(&parameters.owner);
        self.messages.retain(|m| {
            members_by_id.contains_key(&m.message.author) || m.message.author == owner_id
        });

        // Sort messages by time, with MessageId as secondary sort for deterministic ordering
        // (CRDT convergence requirement - without this, ties produce non-deterministic order)
        self.messages.sort_by(|a, b| {
            a.message
                .time
                .cmp(&b.message.time)
                .then_with(|| a.id().cmp(&b.id()))
        });

        // Rebuild computed state from action messages
        let owner_id = parameters.owner_id();
        let admin_ids: std::collections::HashSet<MemberId> = parent_state
            .admin
            .admins
            .iter()
            .map(|admin| admin.admin.id())
            .collect();
        let member_ids: std::collections::HashSet<MemberId> = members_by_id.keys().copied().collect();
        self.rebuild_actions_state_with_permissions(
            &HashMap::new(),
            Some(owner_id),
            Some(&admin_ids),
            None,
            parent_state.configuration.configuration.reactions_enabled,
            Some(&member_ids),
        );

        Ok(())
    }
}

impl MessagesV1 {
    /// Rebuild the computed actions state by scanning all action messages.
    ///
    /// This method only processes PUBLIC action messages. For private boards,
    /// use `rebuild_actions_state_with_decrypted` and provide the decrypted
    /// content for each private action message.
    pub fn rebuild_actions_state(&mut self) {
        self.rebuild_actions_state_with_permissions(&HashMap::new(), None, None, None, true, None);
    }

    /// Rebuild actions state with decrypted content (for private boards).
    /// Use `rebuild_actions_state_with_permissions` if you need to allow
    /// owner/admin category edits.
    pub fn rebuild_actions_state_with_decrypted(
        &mut self,
        decrypted_content: &HashMap<MessageId, Vec<u8>>,
    ) {
        self.rebuild_actions_state_with_permissions(
            decrypted_content,
            None,
            None,
            None,
            true,
            None,
        );
    }

    /// Rebuild actions state with owner/admin permissions for category edits.
    ///
    /// `reactions_enabled` comes from the board configuration: when it is off,
    /// reaction actions are ignored (history included). `members` bounds the
    /// nickname override to current members.
    #[allow(clippy::too_many_arguments)]
    pub fn rebuild_actions_state_with_permissions(
        &mut self,
        decrypted_content: &HashMap<MessageId, Vec<u8>>,
        owner_id: Option<MemberId>,
        admin_ids: Option<&std::collections::HashSet<MemberId>>,
        moderation: Option<&ModerationPermissions>,
        reactions_enabled: bool,
        members: Option<&std::collections::HashSet<MemberId>>,
    ) {
        use crate::board_state::content::{
            ActionContentV1, DecodedContent, ModerationActionV1, ACTION_TYPE_DELETE,
            ACTION_TYPE_EDIT_POLL,
            ACTION_TYPE_EDIT, ACTION_TYPE_EDIT_CATEGORY, ACTION_TYPE_REACTION,
            ACTION_TYPE_REMOVE_REACTION, ACTION_TYPE_SET_NICKNAME,
        };
        use crate::board_state::privacy::SealedBytes;

        // Clear existing computed state
        self.actions_state = MessageActionsState::default();

        // Build a map of message_id -> author for authorization checks
        let message_authors: HashMap<MessageId, MemberId> = self
            .messages
            .iter()
            .filter(|m| !m.message.content.is_action())
            .map(|m| (m.id(), m.message.author))
            .collect();

        // Reply links and the topics whose authors may moderate descendants.
        let mut reply_parent: HashMap<MessageId, MessageId> = HashMap::new();
        let mut auto_moderated_roots: HashMap<MessageId, MemberId> = HashMap::new();
        for message in self.messages.iter() {
            let content = &message.message.content;
            if content.is_action() || content.is_category() {
                continue;
            }
            if let Some(target) = body_reply_target(content) {
                reply_parent.insert(message.id(), target);
            }
            if body_auto_moderated(content) == Some(true) {
                auto_moderated_roots.insert(message.id(), message.message.author);
            }
        }

        // Build a set of category message IDs for type checking
        let category_ids: std::collections::HashSet<MessageId> = self
            .messages
            .iter()
            .filter(|m| m.message.content.is_category())
            .map(|m| m.id())
            .collect();

        // Process action messages in timestamp order (messages are already sorted)
        for msg in &self.messages {
            let actor = msg.message.author;

            // Skip non-action messages
            if !msg.message.content.is_action() {
                continue;
            }

            // Decode the action content. A moderation action travels in an
            // envelope; its payload is either public or sealed locally in
            // `decrypted_content`.
            let action = if let Some(plaintext) = decrypted_content.get(&msg.id()) {
                match ActionContentV1::decode(plaintext) {
                    Ok(action) => action,
                    Err(_) => continue,
                }
            } else if let BoardMessageBody::Public {
                content_type, data, ..
            } = &msg.message.content
            {
                if *content_type
                    == crate::board_state::content::CONTENT_TYPE_MODERATION_ACTION
                {
                    let envelope = match ModerationActionV1::decode(data) {
                        Ok(envelope) => envelope,
                        Err(_) => continue,
                    };
                    match envelope.payload {
                        SealedBytes::Public { value } => {
                            match ActionContentV1::decode(&value) {
                                Ok(action) => action,
                                Err(_) => continue,
                            }
                        }
                        // A sealed payload needs the client-side key.
                        SealedBytes::Private { .. } => continue,
                    }
                } else {
                    match msg.message.content.decode_content() {
                        Some(DecodedContent::Action(action)) => action,
                        _ => continue,
                    }
                }
            } else {
                continue;
            };

            let target = &action.target;
            let is_privileged = owner_id == Some(actor)
                || admin_ids.map(|ids| ids.contains(&actor)).unwrap_or(false);
            let target_closed = moderation
                .map(|moderation| moderation.closed.contains(target))
                .unwrap_or(false);

            match action.action_type {
                ACTION_TYPE_EDIT => {
                    // Categories must use ACTION_TYPE_EDIT_CATEGORY instead
                    if category_ids.contains(target) || target_closed {
                        continue;
                    }
                    if let Some(&original_author) = message_authors.get(target) {
                        let allowed = actor == original_author
                            || is_privileged
                            || moderation
                                .map(|moderation| moderation.can(actor, true, target))
                                .unwrap_or(false);
                        if allowed && !self.actions_state.deleted.contains(target) {
                            if let Some(payload) = action.edit_payload() {
                                self.actions_state
                                    .edited_content
                                    .insert(target.clone(), payload.new_text);
                            }
                        }
                    }
                }
                ACTION_TYPE_EDIT_POLL => {
                    if target_closed {
                        continue;
                    }
                    // Author only. The client hides the action once a vote
                    // exists, so option indexes cannot move under a ballot.
                    if let Some(&original_author) = message_authors.get(target) {
                        if actor == original_author
                            && !self.actions_state.deleted.contains(target)
                        {
                            if let Some(poll) = action.poll_edit_payload() {
                                if poll.validate().is_ok() {
                                    let mut poll = poll;
                                    // The auto-moderated choice is made once,
                                    // at creation; an edit cannot change it.
                                    if let Some(original) =
                                        self.messages.iter().find(|m| m.id() == *target)
                                    {
                                        if let Some(created) =
                                            body_auto_moderated(&original.message.content)
                                        {
                                            poll.auto_moderated = created;
                                        }
                                    }
                                    self.actions_state
                                        .edited_polls
                                        .insert(target.clone(), poll);
                                }
                            }
                        }
                    }
                }
                ACTION_TYPE_DELETE => {
                    if target_closed {
                        continue;
                    }
                    if let Some(&original_author) = message_authors.get(target) {
                        // The author of an auto-moderated topic deletes replies
                        // under it, never the topic itself.
                        let topic_author = auto_moderated_root_author(
                            target,
                            &reply_parent,
                            &auto_moderated_roots,
                        );
                        let allowed = actor == original_author
                            || is_privileged
                            || moderation
                                .map(|moderation| moderation.can(actor, false, target))
                                .unwrap_or(false)
                            || (actor != original_author
                                && topic_author == Some(actor)
                                && !auto_moderated_roots.contains_key(target));
                        if allowed {
                            self.actions_state.deleted.insert(target.clone());
                            // Also remove any edited content for deleted messages
                            self.actions_state.edited_content.remove(target);
                            self.actions_state.edited_categories.remove(target);
                        }
                    }
                }
                ACTION_TYPE_REACTION => {
                    if !reactions_enabled {
                        continue;
                    }
                    // Anyone can add reactions to open, non-deleted messages
                    if !target_closed
                        && message_authors.contains_key(target)
                        && !self.actions_state.deleted.contains(target)
                    {
                        if let Some(payload) = action.reaction_payload() {
                            let reactions = self
                                .actions_state
                                .reactions
                                .entry(target.clone())
                                .or_default();
                            let reactors = reactions.entry(payload.emoji).or_default();
                            // Idempotent: only add if not already present
                            if !reactors.contains(&actor) {
                                reactors.push(actor);
                            }
                        }
                    }
                }
                ACTION_TYPE_REMOVE_REACTION => {
                    if !reactions_enabled {
                        continue;
                    }
                    // Users can only remove their own reactions
                    if target_closed {
                        continue;
                    }
                    if let Some(payload) = action.reaction_payload() {
                        if let Some(reactions) = self.actions_state.reactions.get_mut(target) {
                            if let Some(reactors) = reactions.get_mut(&payload.emoji) {
                                reactors.retain(|r| r != &actor);
                                // Clean up empty entries
                                if reactors.is_empty() {
                                    reactions.remove(&payload.emoji);
                                }
                            }
                            if reactions.is_empty() {
                                self.actions_state.reactions.remove(target);
                            }
                        }
                    }
                }
                ACTION_TYPE_EDIT_CATEGORY => {
                    // Only categories can be edited with this action type
                    if !category_ids.contains(target) {
                        continue;
                    }
                    // Owner, admins, or original author can edit categories
                    let is_owner = owner_id.map_or(false, |id| actor == id);
                    let is_admin = admin_ids.map_or(false, |ids| ids.contains(&actor));
                    let is_author = message_authors.get(target) == Some(&actor);

                    if is_owner || is_admin || is_author {
                        // Don't allow editing deleted categories
                        if !self.actions_state.deleted.contains(target) {
                            if let Some(payload) = action.category_edit_payload() {
                                self.actions_state
                                    .edited_categories
                                    .insert(target.clone(), payload);
                            }
                        }
                    }
                }
                ACTION_TYPE_SET_NICKNAME => {
                    if !is_privileged {
                        continue;
                    }
                    let Some(payload) = action.set_nickname_payload() else {
                        continue;
                    };
                    let target_is_member = owner_id == Some(payload.member_id)
                        || members
                            .map(|members| members.contains(&payload.member_id))
                            .unwrap_or(true);
                    if !target_is_member {
                        continue;
                    }
                    let version = crate::board_state::rate_limit::system_time_ms(
                        msg.message.time,
                    ) as u64;
                    let replace = self
                        .actions_state
                        .nickname_overrides
                        .get(&payload.member_id)
                        .map(|old| version >= old.version)
                        .unwrap_or(true);
                    if replace {
                        self.actions_state.nickname_overrides.insert(
                            payload.member_id,
                            NicknameOverride {
                                nickname: payload.nickname,
                                version,
                                set_by: actor,
                                set_at: msg.message.time,
                            },
                        );
                    }
                }
                _ => {
                    // Unknown action type - ignore for forward compatibility
                }
            }
        }
    }

    /// Check if a message has been edited
    pub fn is_edited(&self, message_id: &MessageId) -> bool {
        self.actions_state.edited_content.contains_key(message_id)
    }

    /// Check if a category has been edited
    pub fn is_category_edited(&self, message_id: &MessageId) -> bool {
        self.actions_state
            .edited_categories
            .contains_key(message_id)
    }

    /// Get the edited category payload if available
    pub fn edited_category(&self, message_id: &MessageId) -> Option<&CategoryEditPayload> {
        self.actions_state.edited_categories.get(message_id)
    }

    /// Poll content replaced by its author, if any.
    pub fn edited_poll(
        &self,
        message_id: &MessageId,
    ) -> Option<&crate::board_state::content::PollContentV1> {
        self.actions_state.edited_polls.get(message_id)
    }

    /// Check if a message has been deleted
    pub fn is_deleted(&self, message_id: &MessageId) -> bool {
        self.actions_state.deleted.contains(message_id)
    }

    /// Get the effective text content for a message (edited content if edited, original otherwise)
    /// Returns the text content as a string, or None if the message is encrypted/undecodable
    pub fn effective_text(&self, message: &AuthorizedMessageV1) -> Option<String> {
        let id = message.id();
        // Check if there's edited content first
        if let Some(edited_text) = self.actions_state.edited_content.get(&id) {
            return Some(edited_text.clone());
        }
        // Otherwise return the original content's text
        message.message.content.as_public_string()
    }

    /// Get reactions for a message
    pub fn reactions(&self, message_id: &MessageId) -> Option<&HashMap<String, Vec<MemberId>>> {
        self.actions_state.reactions.get(message_id)
    }

    /// Moderator nickname override for a member, if one was published.
    pub fn nickname_override(&self, member_id: &MemberId) -> Option<&NicknameOverride> {
        self.actions_state.nickname_overrides.get(member_id)
    }

    /// Whether a section lets authors moderate replies. The section override
    /// wins; without one the board configuration decides.
    pub fn section_auto_moderated_topics(
        &self,
        state: &ChatBoardStateV1,
        section: Option<&MessageId>,
    ) -> bool {
        let board_default = state.configuration.configuration.auto_moderated_topics;
        let Some(section) = section else {
            return board_default;
        };
        if let Some(edit) = self.actions_state.edited_categories.get(section) {
            if let Some(setting) = edit.auto_moderated_topics {
                return setting;
            }
        }
        self.category_content(section)
            .and_then(|category| category.auto_moderated_topics)
            .unwrap_or(board_default)
    }

    /// Only a topic with the creation-time flag set, inside a section whose
    /// effective capability is on, may enter the state.
    fn validate_auto_moderated(
        &self,
        state: &ChatBoardStateV1,
        message: &AuthorizedMessageV1,
    ) -> Result<(), String> {
        if body_auto_moderated(&message.message.content) != Some(true) {
            return Ok(());
        }
        // The incoming message is not in `self.messages` yet.
        let section = body_section(&message.message.content)
            .or_else(|| self.section_of_message(state, message));
        if self.section_auto_moderated_topics(state, section.as_ref()) {
            Ok(())
        } else {
            Err("This section does not allow auto-moderated topics".to_string())
        }
    }

    /// Get all non-deleted, non-action messages for display
    pub fn display_messages(&self) -> impl Iterator<Item = &AuthorizedMessageV1> {
        self.messages.iter().filter(|m| {
            !m.message.content.is_action() && !self.actions_state.deleted.contains(&m.id())
        })
    }

    /// Section a message belongs to. The signed route is authoritative; the
    /// message body is the fallback for records written before routes.
    pub fn section_of(
        &self,
        state: &ChatBoardStateV1,
        id: &MessageId,
    ) -> Option<MessageId> {
        let routes = state.moderation.routes_map();
        let mut current = id.clone();
        for _ in 0..64 {
            if let Some(route) = routes.get(&current) {
                if route.is_category {
                    return None;
                }
                if let Some(category) = route.category_id {
                    return Some(category);
                }
            }
            let message = self.messages.iter().find(|m| m.id() == current)?;
            if let Some(section) = body_section(&message.message.content) {
                return Some(section);
            }
            match body_reply_target(&message.message.content) {
                Some(target) => current = target,
                None => return None,
            }
        }
        None
    }

    fn section_of_message(
        &self,
        state: &ChatBoardStateV1,
        message: &AuthorizedMessageV1,
    ) -> Option<MessageId> {
        self.section_of(state, &message.id())
    }

    /// Category record of a section, when the contract can read it.
    pub fn category_content(
        &self,
        section: &MessageId,
    ) -> Option<crate::board_state::content::CategoryContentV1> {
        let message = self.messages.iter().find(|m| m.id() == *section)?;
        match message.message.content.decode_content() {
            Some(crate::board_state::content::DecodedContent::Category(category)) => {
                Some(category)
            }
            _ => None,
        }
    }

    /// Whether a section allows images. The last on/off action signed by the
    /// owner or an admin wins; without one the category record decides.
    pub fn section_allows_images(
        &self,
        state: &ChatBoardStateV1,
        parameters: &ChatBoardParametersV1,
        section: &MessageId,
    ) -> bool {
        let mut last: Option<(SystemTime, MessageId, bool)> = None;
        for message in &self.messages {
            let Some(action) = public_action(&message.message.content) else {
                continue;
            };
            if action.action_type != ACTION_TYPE_SET_SECTION_IMAGES
                || action.target != *section
            {
                continue;
            }
            let author = message.message.author;
            if author != state.ownership.current_owner(parameters)
                && !crate::board_state::roles::is_board_admin(state, &author)
            {
                continue;
            }
            let Some(setting) = action.section_images_payload() else {
                continue;
            };
            let key = (message.message.time, message.id());
            if last
                .as_ref()
                .map(|(time, id, _)| (message.message.time, message.id()) > (*time, *id))
                .unwrap_or(true)
            {
                last = Some((key.0, key.1, setting.allowed));
            }
        }
        match last {
            Some((_, _, allowed)) => allowed,
            None => self
                .category_content(section)
                .map(|category| category.images_allowed)
                .unwrap_or(true),
        }
    }

    /// Limits, author permission and section rule for one message's images.
    fn validate_images(
        &self,
        state: &ChatBoardStateV1,
        parameters: &ChatBoardParametersV1,
        message: &AuthorizedMessageV1,
    ) -> Result<(), String> {
        let is_new = !self
            .messages
            .iter()
            .any(|existing| existing.id() == message.id());
        validate_message_images(
            &message.message,
            &state.configuration.configuration,
            is_new,
        )?;
        if message.message.images.is_empty() {
            return Ok(());
        }
        let section = self.section_of_message(state, message);
        if !author_may_attach_images(
            state,
            parameters,
            &message.message.author,
            section.as_ref(),
        ) {
            return Err("This member may not attach images".to_string());
        }
        if let Some(section) = section {
            if !self.section_allows_images(state, parameters, &section) {
                return Err("This section does not allow images".to_string());
            }
        }
        Ok(())
    }
}

/// Message body that can be either public or private (encrypted).
///
/// Content is opaque to the contract - interpretation happens client-side.
/// This design enables adding new content types without contract redeployment.
///
/// # Content Types
/// - `content_type = 1`: Text message (TextContentV1)
/// - `content_type = 2`: Action on another message (ActionContentV1)
/// - Future types can be added without contract changes
///
/// # Extensibility
/// - New content types: Just use a new content_type number
/// - New action types: Just use a new action_type number within ActionContentV1
/// - New fields: Add to content structs (old clients ignore unknown fields)
/// - Breaking changes: Bump content_version
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum BoardMessageBody {
    /// Public (unencrypted) message
    Public {
        /// Content type identifier (see content module for constants)
        content_type: u32,
        /// Version of the content format
        content_version: u32,
        /// CBOR-encoded content bytes
        data: Vec<u8>,
    },
    /// Private (encrypted) message
    Private {
        /// Content type identifier (see content module for constants)
        content_type: u32,
        /// Version of the content format
        content_version: u32,
        /// Encrypted CBOR-encoded content
        ciphertext: Vec<u8>,
        /// Nonce used for encryption
        nonce: [u8; 12],
        /// Version of the board secret used for encryption
        secret_version: SecretVersion,
        /// Which secret sealed this message. Older messages use the board
        /// secret; restricted categories use their own. Omitted when it is the
        /// board scope so records signed before this field existed keep
        /// verifying byte for byte.
        #[serde(default, skip_serializing_if = "SecretScope::is_board")]
        secret_scope: SecretScope,
    },
}

/// Which key a private message is sealed with.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub enum SecretScope {
    #[default]
    Board,
    Category(MessageId),
}

impl SecretScope {
    fn is_board(&self) -> bool {
        matches!(self, SecretScope::Board)
    }
}

impl BoardMessageBody {
    /// Create a new public text message
    pub fn public(title: String, content: String) -> Self {
        use crate::board_state::content::{TextContentV1, CONTENT_TYPE_TEXT, TEXT_CONTENT_VERSION};
        let text_content = TextContentV1::new(title, content);
        Self::Public {
            content_type: CONTENT_TYPE_TEXT,
            content_version: TEXT_CONTENT_VERSION,
            data: text_content.encode(),
        }
    }

    /// Create a new public message with raw content
    pub fn public_raw(content_type: u32, content_version: u32, data: Vec<u8>) -> Self {
        Self::Public {
            content_type,
            content_version,
            data,
        }
    }

    /// Create a new private message
    pub fn private(
        content_type: u32,
        content_version: u32,
        ciphertext: Vec<u8>,
        nonce: [u8; 12],
        secret_version: SecretVersion,
    ) -> Self {
        Self::Private {
            content_type,
            content_version,
            ciphertext,
            nonce,
            secret_version,
            secret_scope: SecretScope::default(),
        }
    }

    /// Create a private text message (convenience method)
    pub fn private_text(
        ciphertext: Vec<u8>,
        nonce: [u8; 12],
        secret_version: SecretVersion,
    ) -> Self {
        use crate::board_state::content::{CONTENT_TYPE_TEXT, TEXT_CONTENT_VERSION};
        Self::Private {
            content_type: CONTENT_TYPE_TEXT,
            content_version: TEXT_CONTENT_VERSION,
            ciphertext,
            nonce,
            secret_version,
            secret_scope: SecretScope::default(),
        }
    }

    /// Create an edit action (public)
    pub fn edit(target: MessageId, new_title: String, new_text: String) -> Self {
        use crate::board_state::content::{
            ActionContentV1, ACTION_CONTENT_VERSION, CONTENT_TYPE_ACTION,
        };
        let action = ActionContentV1::edit(target, new_title, new_text);
        Self::Public {
            content_type: CONTENT_TYPE_ACTION,
            content_version: ACTION_CONTENT_VERSION,
            data: action.encode(),
        }
    }

    /// Create a delete action (public)
    pub fn delete(target: MessageId) -> Self {
        use crate::board_state::content::{
            ActionContentV1, ACTION_CONTENT_VERSION, CONTENT_TYPE_ACTION,
        };
        let action = ActionContentV1::delete(target);
        Self::Public {
            content_type: CONTENT_TYPE_ACTION,
            content_version: ACTION_CONTENT_VERSION,
            data: action.encode(),
        }
    }

    /// Create a reaction action (public)
    pub fn reaction(target: MessageId, emoji: String) -> Self {
        use crate::board_state::content::{
            ActionContentV1, ACTION_CONTENT_VERSION, CONTENT_TYPE_ACTION,
        };
        let action = ActionContentV1::reaction(target, emoji);
        Self::Public {
            content_type: CONTENT_TYPE_ACTION,
            content_version: ACTION_CONTENT_VERSION,
            data: action.encode(),
        }
    }

    /// Create a remove reaction action (public)
    pub fn remove_reaction(target: MessageId, emoji: String) -> Self {
        use crate::board_state::content::{
            ActionContentV1, ACTION_CONTENT_VERSION, CONTENT_TYPE_ACTION,
        };
        let action = ActionContentV1::remove_reaction(target, emoji);
        Self::Public {
            content_type: CONTENT_TYPE_ACTION,
            content_version: ACTION_CONTENT_VERSION,
            data: action.encode(),
        }
    }

    /// Create an edit category action (public)
    pub fn edit_category(
        target: MessageId,
        new_name: String,
        new_description: Option<String>,
        new_icon: Option<String>,
        new_color: String,
    ) -> Self {
        use crate::board_state::content::{
            ActionContentV1, ACTION_CONTENT_VERSION, CONTENT_TYPE_ACTION,
        };
        let action = ActionContentV1::edit_category(
            target,
            new_name,
            new_description,
            new_icon,
            new_color,
            None,
        );
        Self::Public {
            content_type: CONTENT_TYPE_ACTION,
            content_version: ACTION_CONTENT_VERSION,
            data: action.encode(),
        }
    }

    /// Create a public reply message
    pub fn reply(
        title: String,
        content: String,
        target_message_id: MessageId,
        target_author_name: String,
        target_content_preview: String,
    ) -> Self {
        use crate::board_state::content::{
            ReplyContentV1, CONTENT_TYPE_REPLY, REPLY_CONTENT_VERSION,
        };
        let reply = ReplyContentV1::new(
            title,
            content,
            target_message_id,
            target_author_name,
            target_content_preview,
        );
        Self::Public {
            content_type: CONTENT_TYPE_REPLY,
            content_version: REPLY_CONTENT_VERSION,
            data: reply.encode(),
        }
    }

    /// Create a public category message (for organizing posts)
    ///
    /// Only board owners and admins should create categories.
    /// The caller must verify permissions before calling this.
    pub fn category(
        name: String,
        description: Option<String>,
        icon: Option<String>,
        color: String,
        parent_category_id: Option<MessageId>,
    ) -> Self {
        use crate::board_state::content::{
            CategoryContentV1, CATEGORY_CONTENT_VERSION, CONTENT_TYPE_CATEGORY,
        };
        let mut cat = CategoryContentV1::new(name, description, color);
        if let Some(i) = icon {
            cat = cat.with_icon(i);
        }
        if let Some(p) = parent_category_id {
            cat = cat.with_parent(p);
        }
        Self::Public {
            content_type: CONTENT_TYPE_CATEGORY,
            content_version: CATEGORY_CONTENT_VERSION,
            data: cat.encode(),
        }
    }

    /// Create a private action message (encrypted)
    ///
    /// Use this for any action (edit, delete, reaction, remove_reaction) in a private board.
    /// The caller should:
    /// 1. Create the ActionContentV1 (e.g., `ActionContentV1::edit(target, new_text)`)
    /// 2. Encode it: `action.encode()`
    /// 3. Encrypt the bytes with the board secret
    /// 4. Pass the ciphertext here
    pub fn private_action(
        ciphertext: Vec<u8>,
        nonce: [u8; 12],
        secret_version: SecretVersion,
    ) -> Self {
        use crate::board_state::content::{ACTION_CONTENT_VERSION, CONTENT_TYPE_ACTION};
        Self::Private {
            content_type: CONTENT_TYPE_ACTION,
            content_version: ACTION_CONTENT_VERSION,
            ciphertext,
            nonce,
            secret_version,
            secret_scope: SecretScope::default(),
        }
    }

    /// Check if this is a public message
    pub fn is_public(&self) -> bool {
        matches!(self, Self::Public { .. })
    }

    /// Check if this is a private message
    pub fn is_private(&self) -> bool {
        matches!(self, Self::Private { .. })
    }

    /// Get the content type
    pub fn content_type(&self) -> u32 {
        match self {
            Self::Public { content_type, .. } | Self::Private { content_type, .. } => *content_type,
        }
    }

    /// Get the content version
    pub fn content_version(&self) -> u32 {
        match self {
            Self::Public {
                content_version, ..
            }
            | Self::Private {
                content_version, ..
            } => *content_version,
        }
    }

    /// Check if this is an action message (content_type = ACTION)
    pub fn is_action(&self) -> bool {
        use crate::board_state::content::{
            CONTENT_TYPE_ACTION, CONTENT_TYPE_MODERATION_ACTION, CONTENT_TYPE_POLL_VOTE,
        };
        matches!(
            self.content_type(),
            CONTENT_TYPE_ACTION | CONTENT_TYPE_MODERATION_ACTION | CONTENT_TYPE_POLL_VOTE
        )
    }

    /// Check if this is a category message (content_type = CATEGORY)
    pub fn is_category(&self) -> bool {
        use crate::board_state::content::CONTENT_TYPE_CATEGORY;
        self.content_type() == CONTENT_TYPE_CATEGORY
    }

    /// Decode the content (for public messages only)
    /// Returns None for private messages - decrypt first
    pub fn decode_content(&self) -> Option<crate::board_state::content::DecodedContent> {
        use crate::board_state::content::{
            ActionContentV1, CategoryContentV1, DecodedContent, ReplyContentV1, TextContentV1,
            CONTENT_TYPE_ACTION, CONTENT_TYPE_CATEGORY, CONTENT_TYPE_REPLY, CONTENT_TYPE_TEXT,
        };
        match self {
            Self::Public {
                content_type,
                content_version,
                data,
            } => match *content_type {
                CONTENT_TYPE_TEXT => TextContentV1::decode(data).ok().map(DecodedContent::Text),
                CONTENT_TYPE_ACTION => ActionContentV1::decode(data)
                    .ok()
                    .map(DecodedContent::Action),
                CONTENT_TYPE_REPLY => ReplyContentV1::decode(data).ok().map(DecodedContent::Reply),
                CONTENT_TYPE_CATEGORY => CategoryContentV1::decode(data)
                    .ok()
                    .map(DecodedContent::Category),
                _ => Some(DecodedContent::Unknown {
                    content_type: *content_type,
                    content_version: *content_version,
                }),
            },
            Self::Private { .. } => None,
        }
    }

    /// Get the target message ID if this is an action
    pub fn target_id(&self) -> Option<MessageId> {
        use crate::board_state::content::{ActionContentV1, CONTENT_TYPE_ACTION};
        match self {
            Self::Public {
                content_type, data, ..
            } if *content_type == CONTENT_TYPE_ACTION => {
                ActionContentV1::decode(data).ok().map(|a| a.target)
            }
            _ => None,
        }
    }

    /// Get the content length for validation (contract uses this for size limits)
    pub fn content_len(&self) -> usize {
        match self {
            Self::Public { data, .. } => data.len(),
            Self::Private { ciphertext, .. } => ciphertext.len(),
        }
    }

    /// Get the secret version (if private)
    pub fn secret_version(&self) -> Option<SecretVersion> {
        match self {
            Self::Public { .. } => None,
            Self::Private { secret_version, .. } => Some(*secret_version),
        }
    }

    /// Get a string representation for display purposes
    pub fn to_string_lossy(&self) -> String {
        match self {
            Self::Public { .. } => {
                if let Some(decoded) = self.decode_content() {
                    decoded.to_display_string()
                } else {
                    "[Failed to decode message]".to_string()
                }
            }
            Self::Private {
                ciphertext,
                secret_version,
                ..
            } => {
                format!(
                    "[Encrypted message: {} bytes, v{}]",
                    ciphertext.len(),
                    secret_version
                )
            }
        }
    }

    /// Try to get the public plaintext, returns None if private or not a text message
    pub fn as_public_string(&self) -> Option<String> {
        self.decode_content()
            .and_then(|c| c.as_text().map(|s| s.to_string()))
    }

    /// Extract title from the message content (for public messages only).
    /// Returns None for private messages or non-text/reply/category content.
    pub fn title(&self) -> Option<String> {
        use crate::board_state::content::{
            CategoryContentV1, PollContentV1, ReplyContentV1, TextContentV1, CONTENT_TYPE_CATEGORY,
            CONTENT_TYPE_POLL, CONTENT_TYPE_REPLY, CONTENT_TYPE_TEXT,
        };
        match self {
            Self::Public {
                content_type, data, ..
            } => match *content_type {
                CONTENT_TYPE_TEXT => TextContentV1::decode(data).ok().map(|t| t.title),
                CONTENT_TYPE_REPLY => ReplyContentV1::decode(data).ok().map(|r| r.title),
                CONTENT_TYPE_CATEGORY => CategoryContentV1::decode(data).ok().map(|c| c.name),
                CONTENT_TYPE_POLL => PollContentV1::decode(data).ok().map(|p| p.title),
                _ => None,
            },
            Self::Private { .. } => None,
        }
    }
}

impl fmt::Display for BoardMessageBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_lossy())
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct MessageV1 {
    pub board_owner: MemberId,
    pub author: MemberId,
    pub time: SystemTime,
    pub content: BoardMessageBody,
    /// Images attached to the post. Empty for actions and for messages written
    /// before images existed; skipped when empty so old signatures verify.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub images: Vec<crate::board_state::images::ImageRef>,
}

impl Default for MessageV1 {
    fn default() -> Self {
        Self {
            board_owner: MemberId::from_bytes([0u8; 32]),
            author: MemberId::from_bytes([0u8; 32]),
            time: SystemTime::UNIX_EPOCH,
            content: BoardMessageBody::public(String::new(), String::new()),
            images: Vec::new(),
        }
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthorizedMessageV1 {
    pub message: MessageV1,
    pub signature: Signature,
}

impl fmt::Debug for AuthorizedMessageV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizedMessage")
            .field("message", &self.message)
            .field(
                "signature",
                &format_args!("{}", truncated_base64(self.signature.to_bytes())),
            )
            .finish()
    }
}

#[derive(Eq, PartialEq, Hash, Serialize, Deserialize, Copy, Clone, Ord, PartialOrd)]
pub struct MessageId(pub BoardId);

impl MessageId {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(BoardId::from_bytes(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MessageId({})", self.0)
    }
}

impl std::str::FromStr for MessageId {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(Self(value.parse::<BoardId>()?))
    }
}

impl AuthorizedMessageV1 {
    pub fn new(message: MessageV1, signing_key: &SigningKey) -> Self {
        Self {
            message: message.clone(),
            signature: sign_struct(&message, signing_key),
        }
    }

    /// Create an AuthorizedMessageV1 with a pre-computed signature.
    /// Use this when signing is done externally (e.g., via delegate).
    pub fn with_signature(message: MessageV1, signature: Signature) -> Self {
        Self { message, signature }
    }

    pub fn validate(
        &self,
        verifying_key: &VerifyingKey,
    ) -> Result<(), ed25519_dalek::SignatureError> {
        verify_struct(&self.message, &self.signature, verifying_key)
    }

    pub fn id(&self) -> MessageId {
        MessageId(BoardId::hash(&self.signature.to_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board_state::admin::{Admin, AuthorizedAdmin};
    use crate::board_state::configuration::{AuthorizedConfigurationV1, Configuration};
    use crate::board_state::member::{AuthorizedMember, Member};
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use std::time::Duration;

    fn create_test_message(owner_id: MemberId, author_id: MemberId) -> MessageV1 {
        MessageV1 {
            images: Vec::new(),
            board_owner: owner_id,
            author: author_id,
            time: SystemTime::now(),
            content: BoardMessageBody::public(String::new(), "Test message".to_string()),
        }
    }

    /// Adding `secret_scope` must not change the bytes of older signed
    /// messages: the default board scope is skipped on serialization.
    #[test]
    fn board_scope_is_skipped_so_old_signatures_verify() {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let message = MessageV1 {
            images: Vec::new(),
            board_owner: MemberId::from(&signing_key.verifying_key()),
            author: MemberId::from(&signing_key.verifying_key()),
            content: BoardMessageBody::private_text(vec![1, 2, 3], [0u8; 12], 0),
            time: SystemTime::now(),
        };

        let mut original = Vec::new();
        ciborium::into_writer(&message, &mut original).unwrap();
        assert!(
            !String::from_utf8_lossy(&original).contains("secret_scope"),
            "the default scope must not appear in the signed bytes"
        );

        let decoded: MessageV1 = ciborium::from_reader(&original[..]).unwrap();
        let mut again = Vec::new();
        ciborium::into_writer(&decoded, &mut again).unwrap();
        assert_eq!(original, again, "round-tripping must keep the bytes");

        let signature = sign_struct(&message, &signing_key);
        assert!(verify_struct(&decoded, &signature, &signing_key.verifying_key()).is_ok());
    }

    #[test]
    fn test_messages_v1_default() {
        let default_messages = MessagesV1::default();
        assert!(default_messages.messages.is_empty());
    }

    /// One member posting faster than the configured window is rejected; the
    /// limit is evaluated on the signed times so every peer agrees.
    #[test]
    fn a_post_burst_is_rejected_by_the_rate_limit() {
        use crate::board_state::configuration::{AuthorizedConfigurationV1, Configuration};
        use crate::board_state::member::{AuthorizedMember, Member};

        let mut rng = OsRng;
        let owner_sk = SigningKey::generate(&mut rng);
        let author_sk = SigningKey::generate(&mut rng);
        let owner_id = MemberId::from(&owner_sk.verifying_key());
        let author_id = MemberId::from(&author_sk.verifying_key());
        let params = ChatBoardParametersV1 {
            owner: owner_sk.verifying_key(),
        };
        let mut state = ChatBoardStateV1 {
            // A small window keeps the test fast: every message is signed and
            // verified in debug builds.
            configuration: AuthorizedConfigurationV1::new(
                Configuration {
                    max_posts_per_window: 3,
                    updated_at: std::time::SystemTime::UNIX_EPOCH,
                    ..Configuration::default()
                },
                &owner_sk,
            ),
            ..Default::default()
        };
        state.members.members.push(AuthorizedMember::new(
            Member {
                owner_member_id: owner_id,
                invited_by: owner_id,
                member_vk: author_sk.verifying_key(),
                join_proof: None,
            },
            &owner_sk,
        ));

        let message = |index: u64| {
            AuthorizedMessageV1::new(
                MessageV1 {
                    images: Vec::new(),
                    board_owner: owner_id,
                    author: author_id,
                    // 100 ms apart: the whole burst fits one window.
                    time: SystemTime::UNIX_EPOCH + Duration::from_millis(index * 100),
                    content: BoardMessageBody::public(String::new(), "hi".to_string()),
                },
                &author_sk,
            )
        };
        let limit = state.configuration.configuration.post_limit() as usize;
        let mut messages = MessagesV1::default();
        for index in 0..limit {
            messages.messages.push(message(index as u64));
        }
        messages
            .verify(&state, &params)
            .expect("a burst at the limit is allowed");

        messages.messages.push(message(limit as u64));
        let error = messages
            .verify(&state, &params)
            .expect_err("one more post breaks the window");
        assert!(error.contains("rate limit"), "{error}");
    }

    /// A read-only board accepts content only from the current owner and the
    /// admins; every other member is refused in verification and in apply.
    #[test]
    fn a_read_only_board_accepts_only_the_owner_and_admins() {
        let owner = SigningKey::from_bytes(&[1u8; 32]);
        let member = SigningKey::from_bytes(&[2u8; 32]);
        let admin = SigningKey::from_bytes(&[3u8; 32]);
        let owner_id = MemberId::from(&owner.verifying_key());
        let parameters = ChatBoardParametersV1 {
            owner: owner.verifying_key(),
        };
        let mut configuration = Configuration::default();
        configuration.read_only = true;
        let mut state = ChatBoardStateV1 {
            configuration: AuthorizedConfigurationV1::new(configuration, &owner),
            ..Default::default()
        };
        for signer in [&member, &admin] {
            state.members.members.push(AuthorizedMember::new(
                Member {
                    owner_member_id: owner_id,
                    invited_by: owner_id,
                    member_vk: signer.verifying_key(),
                    join_proof: None,
                },
                &owner,
            ));
        }
        state.admin.admins.push(AuthorizedAdmin::new(
            Admin {
                member_id: MemberId::from(&admin.verifying_key()),
                generation: 1,
                signed_at: SystemTime::UNIX_EPOCH,
            },
            &owner,
        ));

        let post = |signer: &SigningKey| {
            AuthorizedMessageV1::new(
                MessageV1 {
                    images: Vec::new(),
                    board_owner: owner_id,
                    author: MemberId::from(&signer.verifying_key()),
                    time: SystemTime::UNIX_EPOCH + Duration::from_secs(1),
                    content: BoardMessageBody::public("t".to_string(), "b".to_string()),
                },
                signer,
            )
        };

        let mut refused = MessagesV1::default();
        refused.messages.push(post(&member));
        let error = refused
            .verify(&state, &parameters)
            .expect_err("a plain member cannot write on a read-only board");
        assert!(error.contains("read-only"), "{error}");
        assert!(
            refused
                .apply_delta(&state, &parameters, &Some(refused.messages.clone()))
                .is_err(),
            "the delta is refused too"
        );

        for signer in [&admin, &owner] {
            let mut allowed = MessagesV1::default();
            allowed.messages.push(post(signer));
            allowed
                .verify(&state, &parameters)
                .expect("the owner and admins write on a read-only board");
            allowed
                .apply_delta(&state, &parameters, &Some(allowed.messages.clone()))
                .expect("their delta applies");
        }
    }

    /// Images: a valid attachment passes, and every declared limit is enforced.
    #[test]
    fn images_are_validated_against_the_board_limits() {
        use crate::board_state::images::ImageRef;

        let owner = SigningKey::from_bytes(&[5u8; 32]);
        let owner_id = MemberId::from(&owner.verifying_key());
        let configuration = Configuration::default();
        let state = ChatBoardStateV1 {
            configuration: AuthorizedConfigurationV1::new(configuration.clone(), &owner),
            ..Default::default()
        };
        let parameters = ChatBoardParametersV1 {
            owner: owner.verifying_key(),
        };

        let image = |bytes: u32, animated: bool| ImageRef {
            instance: [7u8; 32],
            sha256: [9u8; 32],
            mime: "image/webp".to_string(),
            width: 800,
            height: 600,
            bytes,
            alt: "a cat on a keyboard".to_string(),
            display: 0,
            sealed: false,
            animated,
            nsfw: false,
            thumb: None,
            placement: Default::default(),
            align: Default::default(),
        };
        let message = |images: Vec<ImageRef>| {
            AuthorizedMessageV1::new(
                MessageV1 {
                    board_owner: owner_id,
                    author: owner_id,
                    time: SystemTime::UNIX_EPOCH + Duration::from_secs(1),
                    content: BoardMessageBody::public("t".to_string(), "b".to_string()),
                    images,
                },
                &owner,
            )
        };
        let verify = |images: Vec<ImageRef>| {
            let mut messages = MessagesV1::default();
            messages.messages.push(message(images));
            messages.verify(&state, &parameters)
        };
        // Limits apply when a new message arrives, not to the accepted state.
        let apply = |images: Vec<ImageRef>| {
            let mut messages = MessagesV1::default();
            let delta = vec![message(images)];
            messages.apply_delta(&state, &parameters, &Some(delta))
        };

        verify(vec![image(1024, false)]).expect("a valid image passes");
        apply(vec![image(1024, false)]).expect("a valid image applies");
        apply(vec![image(7 * 1024 * 1024, true)])
            .expect("an animated image up to 8 MiB passes");

        let too_many = apply(vec![image(1024, false); 5]).unwrap_err();
        assert!(too_many.contains("Too many images"), "{too_many}");

        let oversized = apply(vec![image(5 * 1024 * 1024, false)]).unwrap_err();
        assert!(oversized.contains("outside the allowed range"), "{oversized}");

        // A message already in the state keeps verifying after the owner
        // lowers a limit.
        verify(vec![image(5 * 1024 * 1024, false)])
            .expect("existing oversized images stay valid");

        let mut bad_mime = image(1024, false);
        bad_mime.mime = "image/svg+xml".to_string();
        assert!(verify(vec![bad_mime]).is_err(), "SVG is not allowed");

        let mut no_alt = image(1024, false);
        no_alt.alt = "  ".to_string();
        let missing_alt = verify(vec![no_alt]).unwrap_err();
        assert!(missing_alt.contains("alternative text"), "{missing_alt}");

        let mut bad_display = image(1024, false);
        bad_display.display = 10;
        assert!(verify(vec![bad_display]).is_err(), "display must be 25..100");

        // Images belong to posts, not to actions such as edits or reactions.
        let action = AuthorizedMessageV1::new(
            MessageV1 {
                board_owner: owner_id,
                author: owner_id,
                time: SystemTime::UNIX_EPOCH + Duration::from_secs(1),
                content: BoardMessageBody::delete(MessageId(BoardId::hash(b"target"))),
                images: vec![image(1024, false)],
            },
            &owner,
        );
        let mut messages = MessagesV1::default();
        messages.messages.push(action);
        let on_action = messages.verify(&state, &parameters).unwrap_err();
        assert!(on_action.contains("Only posts"), "{on_action}");
    }

    fn board_with_one_member() -> (
        SigningKey,
        SigningKey,
        ChatBoardStateV1,
        ChatBoardParametersV1,
        MemberId,
        MemberId,
    ) {
        let owner = SigningKey::from_bytes(&[21u8; 32]);
        let member = SigningKey::from_bytes(&[22u8; 32]);
        let owner_id = MemberId::from(&owner.verifying_key());
        let member_id = MemberId::from(&member.verifying_key());
        let mut state = ChatBoardStateV1 {
            configuration: AuthorizedConfigurationV1::new(Configuration::default(), &owner),
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
        let parameters = ChatBoardParametersV1 {
            owner: owner.verifying_key(),
        };
        (owner, member, state, parameters, owner_id, member_id)
    }

    fn grant_role(
        state: &mut ChatBoardStateV1,
        owner: &SigningKey,
        member: MemberId,
        edit: impl FnOnce(&mut crate::board_state::roles::Role),
    ) {
        use crate::board_state::roles::{
            AuthorizedRole, AuthorizedRoleAssignment, Role, RoleAssignment,
        };
        let mut role = Role {
            id: [31u8; 16],
            name: "images".to_string(),
            generation: 1,
            can_manage_access: false,
            can_distribute_keys: false,
            can_edit_posts: false,
            can_delete_posts: false,
            can_close_posts: false,
            can_pin_posts: false,
            can_move_posts: false,
            can_manage_trash: false,
            can_attach_images: false,
            can_retire_images: false,
            scope: Vec::new(),
            deleted: false,
            signed_at: SystemTime::UNIX_EPOCH,
        };
        edit(&mut role);
        state.roles.roles.push(AuthorizedRole::new(role, owner));
        state
            .roles
            .assignments
            .push(AuthorizedRoleAssignment::new(
                RoleAssignment {
                    role_id: [31u8; 16],
                    member_id: member,
                    generation: 1,
                    revoked: false,
                    signed_at: SystemTime::UNIX_EPOCH,
                },
                owner,
            ));
    }

    fn sample_image() -> crate::board_state::images::ImageRef {
        crate::board_state::images::ImageRef {
            instance: [41u8; 32],
            sha256: [42u8; 32],
            mime: "image/webp".to_string(),
            width: 400,
            height: 300,
            bytes: 2048,
            alt: "a screenshot".to_string(),
            display: 0,
            sealed: false,
            animated: false,
            nsfw: false,
            thumb: None,
            placement: Default::default(),
            align: Default::default(),
        }
    }

    fn category_message(
        owner: &SigningKey,
        owner_id: MemberId,
        allowed: bool,
        time: SystemTime,
    ) -> (AuthorizedMessageV1, MessageId) {
        use crate::board_state::content::{
            CategoryContentV1, CATEGORY_CONTENT_VERSION, CONTENT_TYPE_CATEGORY,
        };
        let category = CategoryContentV1::new(
            "Photos".to_string(),
            None,
            crate::board_state::content::DEFAULT_CATEGORY_COLOR.to_string(),
        )
        .with_images_allowed(allowed);
        let message = AuthorizedMessageV1::new(
            MessageV1 {
                board_owner: owner_id,
                author: owner_id,
                time,
                content: BoardMessageBody::public_raw(
                    CONTENT_TYPE_CATEGORY,
                    CATEGORY_CONTENT_VERSION,
                    category.encode(),
                ),
                images: Vec::new(),
            },
            owner,
        );
        let id = message.id();
        (message, id)
    }

    fn post_with_image(
        signer: &SigningKey,
        author: MemberId,
        owner_id: MemberId,
        section: Option<MessageId>,
        time: SystemTime,
    ) -> AuthorizedMessageV1 {
        use crate::board_state::content::{TextContentV1, TEXT_CONTENT_VERSION, CONTENT_TYPE_TEXT};
        let text = TextContentV1::new("t".to_string(), "b".to_string()).with_category(section);
        AuthorizedMessageV1::new(
            MessageV1 {
                board_owner: owner_id,
                author,
                time,
                content: BoardMessageBody::public_raw(
                    CONTENT_TYPE_TEXT,
                    TEXT_CONTENT_VERSION,
                    text.encode(),
                ),
                images: vec![sample_image()],
            },
            signer,
        )
    }

    #[test]
    fn a_role_scoped_to_a_section_allows_images_only_there() {
        use std::time::Duration;

        let (owner, member, state, parameters, owner_id, member_id) = board_with_one_member();
        let (cat_a, id_a) = category_message(&owner, owner_id, true, SystemTime::UNIX_EPOCH);
        let (cat_b, id_b) = category_message(
            &owner,
            owner_id,
            true,
            SystemTime::UNIX_EPOCH + Duration::from_secs(2),
        );

        let mut with_role = state.clone();
        grant_role(&mut with_role, &owner, member_id, |role| {
            role.can_attach_images = true;
            role.scope = vec![id_a.clone()];
        });

        let mut inside = MessagesV1::default();
        inside.messages.push(cat_a);
        inside.messages.push(cat_b);
        inside.messages.push(post_with_image(
            &member,
            member_id,
            owner_id,
            Some(id_a),
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        ));
        inside
            .verify(&with_role, &parameters)
            .expect("the scoped role covers section A");

        let mut outside = MessagesV1::default();
        outside.messages.push(post_with_image(
            &member,
            member_id,
            owner_id,
            Some(id_b),
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        ));
        let refused = outside
            .verify(&with_role, &parameters)
            .expect_err("the scoped role does not cover section B");
        assert!(refused.contains("may not attach images"), "{refused}");
    }

    #[test]
    fn a_member_needs_the_role_to_attach_images() {
        let (owner, member, state, parameters, owner_id, member_id) = board_with_one_member();

        let post = post_with_image(
            &member,
            member_id,
            owner_id,
            None,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        );
        let mut messages = MessagesV1::default();
        messages.messages.push(post.clone());
        let refused = messages
            .verify(&state, &parameters)
            .expect_err("a plain member cannot attach images");
        assert!(refused.contains("may not attach images"), "{refused}");

        let mut with_role = state.clone();
        grant_role(&mut with_role, &owner, member_id, |role| {
            role.can_attach_images = true
        });
        messages
            .verify(&with_role, &parameters)
            .expect("the role allows images");

        // The owner always may, and an admin does too.
        let owner_post = post_with_image(
            &owner,
            owner_id,
            owner_id,
            None,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        );
        let mut owner_messages = MessagesV1::default();
        owner_messages.messages.push(owner_post);
        owner_messages
            .verify(&state, &parameters)
            .expect("the owner may attach images");
    }

    #[test]
    fn a_section_can_forbid_images_and_the_section_wins_over_the_role() {
        use crate::board_state::content::{
            ActionContentV1, ACTION_CONTENT_VERSION, CONTENT_TYPE_ACTION,
        };

        let (owner, member, state, parameters, owner_id, member_id) = board_with_one_member();
        let (category, category_id) =
            category_message(&owner, owner_id, false, SystemTime::UNIX_EPOCH);
        let mut messages = MessagesV1::default();
        messages.messages.push(category);
        messages.messages.push(post_with_image(
            &owner,
            owner_id,
            owner_id,
            Some(category_id.clone()),
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        ));
        let refused = messages
            .verify(&state, &parameters)
            .expect_err("the owner cannot attach images in a section that forbids them");
        assert!(refused.contains("section does not allow images"), "{refused}");

        // A role with can_attach_images does not override the section.
        let mut with_role = state.clone();
        grant_role(&mut with_role, &owner, member_id, |role| {
            role.can_attach_images = true
        });
        messages.messages[1] = post_with_image(
            &member,
            member_id,
            owner_id,
            Some(category_id),
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        );
        let refused = messages
            .verify(&with_role, &parameters)
            .expect_err("the section still wins");
        assert!(refused.contains("section does not allow images"), "{refused}");

        // The section setting is a signed action, and a plain member cannot
        // turn images back on.
        let (allowed_category, allowed_id) =
            category_message(&owner, owner_id, true, SystemTime::UNIX_EPOCH);
        let action = |signer: &SigningKey, author: MemberId, allowed: bool| {
            AuthorizedMessageV1::new(
                MessageV1 {
                    board_owner: owner_id,
                    author,
                    time: SystemTime::UNIX_EPOCH + Duration::from_secs(5),
                    content: BoardMessageBody::public_raw(
                        CONTENT_TYPE_ACTION,
                        ACTION_CONTENT_VERSION,
                        ActionContentV1::set_section_images(allowed_id.clone(), allowed).encode(),
                    ),
                    images: Vec::new(),
                },
                signer,
            )
        };
        let mut closed = MessagesV1::default();
        closed.messages.push(allowed_category.clone());
        closed
            .messages
            .push(action(&owner, owner_id, false));
        closed.messages.push(post_with_image(
            &owner,
            owner_id,
            owner_id,
            Some(allowed_id.clone()),
            SystemTime::UNIX_EPOCH + Duration::from_secs(6),
        ));
        let refused = closed
            .verify(&state, &parameters)
            .expect_err("the owner's action closes the section");
        assert!(refused.contains("section does not allow images"), "{refused}");

        let mut ignored = MessagesV1::default();
        ignored.messages.push(allowed_category);
        ignored.messages.push(action(&member, member_id, false));
        ignored.messages.push(post_with_image(
            &member,
            member_id,
            owner_id,
            Some(allowed_id),
            SystemTime::UNIX_EPOCH + Duration::from_secs(6),
        ));
        let mut with_role = state.clone();
        grant_role(&mut with_role, &owner, member_id, |role| {
            role.can_attach_images = true
        });
        ignored
            .verify(&with_role, &parameters)
            .expect("a member cannot close a section for everyone");
    }

    #[test]
    fn test_authorized_message_v1_debug() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let owner_id = MemberId::from_bytes([0u8; 32]);
        let author_id = MemberId::from_bytes([1u8; 32]);

        let message = create_test_message(owner_id, author_id);
        let authorized_message = AuthorizedMessageV1::new(message, &signing_key);

        let debug_output = format!("{:?}", authorized_message);
        assert!(debug_output.contains("AuthorizedMessage"));
        assert!(debug_output.contains("message"));
        assert!(debug_output.contains("signature"));
    }

    #[test]
    fn test_authorized_message_new_and_validate() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let owner_id = MemberId::from_bytes([0u8; 32]);
        let author_id = MemberId::from_bytes([1u8; 32]);

        let message = create_test_message(owner_id, author_id);
        let authorized_message = AuthorizedMessageV1::new(message.clone(), &signing_key);

        assert_eq!(authorized_message.message, message);
        assert!(authorized_message.validate(&verifying_key).is_ok());

        // Test with wrong key
        let wrong_key = SigningKey::generate(&mut OsRng).verifying_key();
        assert!(authorized_message.validate(&wrong_key).is_err());

        // Test with tampered message
        let mut tampered_message = authorized_message.clone();
        tampered_message.message.content =
            BoardMessageBody::public(String::new(), "Tampered content".to_string());
        assert!(tampered_message.validate(&verifying_key).is_err());
    }

    #[test]
    fn test_message_id() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let owner_id = MemberId::from_bytes([0u8; 32]);
        let author_id = MemberId::from_bytes([1u8; 32]);

        let message = create_test_message(owner_id, author_id);
        let authorized_message = AuthorizedMessageV1::new(message, &signing_key);

        let id1 = authorized_message.id();
        let id2 = authorized_message.id();

        assert_eq!(id1, id2);

        // Test that different messages have different IDs
        let message2 = create_test_message(owner_id, author_id);
        let authorized_message2 = AuthorizedMessageV1::new(message2, &signing_key);
        assert_ne!(authorized_message.id(), authorized_message2.id());
    }

    #[test]
    fn test_messages_verify() {
        // Generate a new signing key and its corresponding verifying key for the owner
        let owner_signing_key = SigningKey::generate(&mut OsRng);
        let owner_verifying_key = owner_signing_key.verifying_key();
        let owner_id = MemberId::from(&owner_verifying_key);

        // Generate a signing key for the author
        let author_signing_key = SigningKey::generate(&mut OsRng);
        let author_verifying_key = author_signing_key.verifying_key();
        let author_id = MemberId::from(&author_verifying_key);

        // Create a test message and authorize it with the author's signing key
        let message = create_test_message(owner_id, author_id);
        let authorized_message = AuthorizedMessageV1::new(message, &author_signing_key);

        // Create a Messages struct with the authorized message
        let messages = MessagesV1 {
            messages: vec![authorized_message],
            ..Default::default()
        };

        // Set up a parent board_state (ChatBoardState) with the author as a member
        let mut parent_state = ChatBoardStateV1::default();
        let author_member = crate::board_state::member::Member {
            owner_member_id: owner_id,
            invited_by: owner_id,
            member_vk: author_verifying_key,
            join_proof: None,
        };
        let authorized_author =
            crate::board_state::member::AuthorizedMember::new(author_member, &owner_signing_key);
        parent_state.members.members = vec![authorized_author];

        // Set up parameters for verification
        let parameters = ChatBoardParametersV1 {
            owner: owner_verifying_key,
        };

        // Verify that a valid message passes verification
        assert!(
            messages.verify(&parent_state, &parameters).is_ok(),
            "Valid messages should pass verification: {:?}",
            messages.verify(&parent_state, &parameters)
        );

        // Test with invalid signature
        let mut invalid_messages = messages.clone();
        invalid_messages.messages[0].signature = Signature::from_bytes(&[0; 64]); // Replace with an invalid signature
        assert!(
            invalid_messages.verify(&parent_state, &parameters).is_err(),
            "Messages with invalid signature should fail verification"
        );

        // Test with non-existent author
        let non_existent_author_id =
            MemberId::from(&SigningKey::generate(&mut OsRng).verifying_key());
        let invalid_message = create_test_message(owner_id, non_existent_author_id);
        let invalid_authorized_message =
            AuthorizedMessageV1::new(invalid_message, &author_signing_key);
        let invalid_messages = MessagesV1 {
            messages: vec![invalid_authorized_message],
            ..Default::default()
        };
        assert!(
            invalid_messages.verify(&parent_state, &parameters).is_err(),
            "Messages with non-existent author should fail verification"
        );
    }

    #[test]
    fn test_messages_summarize() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let owner_id = MemberId::from_bytes([0u8; 32]);
        let author_id = MemberId::from_bytes([1u8; 32]);

        let message1 = create_test_message(owner_id, author_id);
        let message2 = create_test_message(owner_id, author_id);

        let authorized_message1 = AuthorizedMessageV1::new(message1, &signing_key);
        let authorized_message2 = AuthorizedMessageV1::new(message2, &signing_key);

        let messages = MessagesV1 {
            messages: vec![authorized_message1.clone(), authorized_message2.clone()],
            ..Default::default()
        };

        let parent_state = ChatBoardStateV1::default();
        let parameters = ChatBoardParametersV1 {
            owner: signing_key.verifying_key(),
        };

        let summary = messages.summarize(&parent_state, &parameters);
        assert_eq!(summary.len(), 2);
        // The summary is a set ordered by MessageId, not insertion order: peers
        // receive messages in different orders and must still produce identical
        // summary bytes.
        assert!(summary.contains(&authorized_message1.id()));
        assert!(summary.contains(&authorized_message2.id()));

        // Test empty messages
        let empty_messages = MessagesV1::default();
        let empty_summary = empty_messages.summarize(&parent_state, &parameters);
        assert!(empty_summary.is_empty());
    }

    #[test]
    fn test_messages_delta() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let owner_id = MemberId::from_bytes([0u8; 32]);
        let author_id = MemberId::from_bytes([1u8; 32]);

        let message1 = create_test_message(owner_id, author_id);
        let message2 = create_test_message(owner_id, author_id);
        let message3 = create_test_message(owner_id, author_id);

        let authorized_message1 = AuthorizedMessageV1::new(message1, &signing_key);
        let authorized_message2 = AuthorizedMessageV1::new(message2, &signing_key);
        let authorized_message3 = AuthorizedMessageV1::new(message3, &signing_key);

        let messages = MessagesV1 {
            messages: vec![
                authorized_message1.clone(),
                authorized_message2.clone(),
                authorized_message3.clone(),
            ],
            ..Default::default()
        };

        let parent_state = ChatBoardStateV1::default();
        let parameters = ChatBoardParametersV1 {
            owner: signing_key.verifying_key(),
        };

        // Test with partial old summary
        let old_summary: BTreeSet<MessageId> = [authorized_message1.id(), authorized_message2.id()]
            .into_iter()
            .collect();
        let delta = messages
            .delta(&parent_state, &parameters, &old_summary)
            .unwrap();
        assert_eq!(delta.len(), 1);
        assert_eq!(delta[0], authorized_message3);

        // Test with empty old summary
        let empty_summary: BTreeSet<MessageId> = BTreeSet::new();
        let full_delta = messages
            .delta(&parent_state, &parameters, &empty_summary)
            .unwrap();
        assert_eq!(full_delta.len(), 3);
        assert_eq!(full_delta, messages.messages);

        // Test with full old summary (no changes)
        let full_summary: BTreeSet<MessageId> = [
            authorized_message1.id(),
            authorized_message2.id(),
            authorized_message3.id(),
        ]
        .into_iter()
        .collect();
        let no_delta = messages.delta(&parent_state, &parameters, &full_summary);
        assert!(no_delta.is_none());
    }

    #[test]
    fn test_messages_apply_delta() {
        // Setup
        let owner_signing_key = SigningKey::generate(&mut OsRng);
        let owner_verifying_key = owner_signing_key.verifying_key();
        let owner_id = MemberId::from(&owner_verifying_key);

        let author_signing_key = SigningKey::generate(&mut OsRng);
        let author_verifying_key = author_signing_key.verifying_key();
        let author_id = MemberId::from(&author_verifying_key);

        let mut parent_state = ChatBoardStateV1::default();
        parent_state.configuration.configuration.max_message_size = 100;
        parent_state.members.members = vec![crate::board_state::member::AuthorizedMember {
            member: crate::board_state::member::Member {
                owner_member_id: owner_id,
                invited_by: owner_id,
                member_vk: author_verifying_key,
                join_proof: None,
            },
            signature: owner_signing_key.try_sign(&[0; 32]).unwrap(),
        }];

        let parameters = ChatBoardParametersV1 {
            owner: owner_verifying_key,
        };

        // Create messages
        let create_message = |time: SystemTime| {
            let message = MessageV1 {
                images: Vec::new(),
                board_owner: owner_id,
                author: author_id,
                time,
                content: BoardMessageBody::public(String::new(), "Test message".to_string()),
            };
            AuthorizedMessageV1::new(message, &author_signing_key)
        };

        let now = SystemTime::now();
        let message1 = create_message(now - Duration::from_secs(3));
        let message2 = create_message(now - Duration::from_secs(2));
        let message3 = create_message(now - Duration::from_secs(1));
        let message4 = create_message(now);

        // Initial board_state with 2 messages
        let mut messages = MessagesV1 {
            messages: vec![message1.clone(), message2.clone()],
            ..Default::default()
        };

        // Apply delta with 2 new messages
        let delta = vec![message3.clone(), message4.clone()];
        assert!(messages
            .apply_delta(&parent_state, &parameters, &Some(delta))
            .is_ok());

        // Check results - all messages are kept (no pruning)
        assert_eq!(
            messages.messages.len(),
            4,
            "Should have 4 messages after applying delta"
        );
        assert!(
            messages.messages.contains(&message1),
            "Message1 should be retained"
        );
        assert!(
            messages.messages.contains(&message2),
            "Message2 should be retained"
        );
        assert!(
            messages.messages.contains(&message3),
            "New message should be added"
        );
        assert!(
            messages.messages.contains(&message4),
            "Newest message should be added"
        );

        // Apply delta with an older message
        let old_message = create_message(now - Duration::from_secs(4));
        let delta = vec![old_message.clone()];
        assert!(messages
            .apply_delta(&parent_state, &parameters, &Some(delta))
            .is_ok());

        // Check results - all messages are kept (no pruning)
        assert_eq!(messages.messages.len(), 5, "Should have 5 messages");
        assert!(
            messages.messages.contains(&old_message),
            "Older message should be added"
        );
        assert!(
            messages.messages.contains(&message1),
            "Message1 should be retained"
        );
        assert!(
            messages.messages.contains(&message2),
            "Message2 should be retained"
        );
        assert!(
            messages.messages.contains(&message3),
            "Message3 should be retained"
        );
        assert!(
            messages.messages.contains(&message4),
            "Newest message should be retained"
        );
    }

    #[test]
    fn test_oversized_message_filtered_by_apply_delta() {
        let owner_sk = SigningKey::generate(&mut OsRng);
        let owner_vk = owner_sk.verifying_key();
        let owner_id = MemberId::from(&owner_vk);

        let author_sk = SigningKey::generate(&mut OsRng);
        let author_vk = author_sk.verifying_key();
        let author_id = MemberId::from(&author_vk);

        let mut parent_state = ChatBoardStateV1::default();
        parent_state.configuration.configuration.max_message_size = 50;
        parent_state.members.members = vec![crate::board_state::member::AuthorizedMember {
            member: crate::board_state::member::Member {
                owner_member_id: owner_id,
                invited_by: owner_id,
                member_vk: author_vk,
                join_proof: None,
            },
            signature: owner_sk.try_sign(&[0; 32]).unwrap(),
        }];

        let parameters = ChatBoardParametersV1 { owner: owner_vk };

        // Create a normal-sized message and an oversized message
        let small_msg = AuthorizedMessageV1::new(
            MessageV1 {
                images: Vec::new(),
                board_owner: owner_id,
                author: author_id,
                time: SystemTime::now(),
                content: BoardMessageBody::public(String::new(), "short".to_string()),
            },
            &author_sk,
        );
        let big_msg = AuthorizedMessageV1::new(
            MessageV1 {
                images: Vec::new(),
                board_owner: owner_id,
                author: author_id,
                time: SystemTime::now(),
                content: BoardMessageBody::public(String::new(), "x".repeat(100)),
            },
            &author_sk,
        );

        assert!(small_msg.message.content.content_len() <= 50);
        assert!(big_msg.message.content.content_len() > 50);

        let mut messages = MessagesV1::default();
        let delta = vec![small_msg.clone(), big_msg.clone()];
        assert!(messages
            .apply_delta(&parent_state, &parameters, &Some(delta))
            .is_ok());

        assert_eq!(
            messages.messages.len(),
            1,
            "Only small message should survive"
        );
        assert!(messages.messages.contains(&small_msg));
        assert!(
            !messages.messages.contains(&big_msg),
            "Oversized message should be filtered"
        );
    }

    #[test]
    fn test_message_author_preservation_across_users() {
        // Create two users
        let user1_sk = SigningKey::generate(&mut OsRng);
        let user1_vk = user1_sk.verifying_key();
        let user1_id = MemberId::from(&user1_vk);

        let user2_sk = SigningKey::generate(&mut OsRng);
        let user2_vk = user2_sk.verifying_key();
        let user2_id = MemberId::from(&user2_vk);

        let owner_sk = SigningKey::generate(&mut OsRng);
        let owner_vk = owner_sk.verifying_key();
        let owner_id = MemberId::from(&owner_vk);

        println!("User1 ID: {}", user1_id);
        println!("User2 ID: {}", user2_id);
        println!("Owner ID: {}", owner_id);

        // Create messages from different users
        let msg1 = MessageV1 {
            images: Vec::new(),
            board_owner: owner_id,
            author: user1_id,
            content: BoardMessageBody::public(String::new(), "Message from user1".to_string()),
            time: SystemTime::now(),
        };

        let msg2 = MessageV1 {
            images: Vec::new(),
            board_owner: owner_id,
            author: user2_id,
            content: BoardMessageBody::public(String::new(), "Message from user2".to_string()),
            time: SystemTime::now() + Duration::from_secs(1),
        };

        let auth_msg1 = AuthorizedMessageV1::new(msg1.clone(), &user1_sk);
        let auth_msg2 = AuthorizedMessageV1::new(msg2.clone(), &user2_sk);

        // Create a messages state with both messages
        let messages = MessagesV1 {
            messages: vec![auth_msg1.clone(), auth_msg2.clone()],
            ..Default::default()
        };

        // Verify authors are preserved
        assert_eq!(messages.messages.len(), 2);

        let stored_msg1 = &messages.messages[0];
        let stored_msg2 = &messages.messages[1];

        assert_eq!(
            stored_msg1.message.author, user1_id,
            "Message 1 author should be user1, but got {}",
            stored_msg1.message.author
        );
        assert_eq!(
            stored_msg2.message.author, user2_id,
            "Message 2 author should be user2, but got {}",
            stored_msg2.message.author
        );

        // Test that author IDs are different
        assert_ne!(user1_id, user2_id, "User IDs should be different");

        // Test Display implementation
        let user1_id_str = user1_id.to_string();
        let user2_id_str = user2_id.to_string();

        println!("User1 ID string: {}", user1_id_str);
        println!("User2 ID string: {}", user2_id_str);

        assert_ne!(
            user1_id_str, user2_id_str,
            "User ID strings should be different"
        );
    }

    #[test]
    fn test_edit_action() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let owner_id = MemberId::from(&verifying_key);
        let author_id = owner_id;

        // Create original message
        let original_msg = MessageV1 {
            images: Vec::new(),
            board_owner: owner_id,
            author: author_id,
            time: SystemTime::now(),
            content: BoardMessageBody::public(String::new(), "Original content".to_string()),
        };
        let auth_original = AuthorizedMessageV1::new(original_msg, &signing_key);
        let original_id = auth_original.id();

        // Create edit action
        let edit_msg = MessageV1 {
            images: Vec::new(),
            board_owner: owner_id,
            author: author_id,
            time: SystemTime::now() + Duration::from_secs(1),
            content: BoardMessageBody::edit(
                original_id.clone(),
                String::new(),
                "Edited content".to_string(),
            ),
        };
        let auth_edit = AuthorizedMessageV1::new(edit_msg, &signing_key);

        // Create messages state and rebuild
        let mut messages = MessagesV1 {
            messages: vec![auth_original.clone(), auth_edit],
            ..Default::default()
        };
        messages.rebuild_actions_state();

        // Verify edit was applied
        assert!(messages.is_edited(&original_id));
        let effective = messages.effective_text(&auth_original);
        assert_eq!(effective, Some("Edited content".to_string()));

        // Verify display_messages still shows the original message
        let display: Vec<_> = messages.display_messages().collect();
        assert_eq!(display.len(), 1);
    }

    #[test]
    fn test_edit_by_non_author_ignored() {
        let owner_sk = SigningKey::generate(&mut OsRng);
        let owner_vk = owner_sk.verifying_key();
        let owner_id = MemberId::from(&owner_vk);

        let other_sk = SigningKey::generate(&mut OsRng);
        let other_id = MemberId::from(&other_sk.verifying_key());

        // Create message by owner
        let original_msg = MessageV1 {
            images: Vec::new(),
            board_owner: owner_id,
            author: owner_id,
            time: SystemTime::now(),
            content: BoardMessageBody::public(String::new(), "Original content".to_string()),
        };
        let auth_original = AuthorizedMessageV1::new(original_msg, &owner_sk);
        let original_id = auth_original.id();

        // Create edit action by OTHER user (should be ignored)
        let edit_msg = MessageV1 {
            images: Vec::new(),
            board_owner: owner_id,
            author: other_id,
            time: SystemTime::now() + Duration::from_secs(1),
            content: BoardMessageBody::edit(
                original_id.clone(),
                String::new(),
                "Hacked content".to_string(),
            ),
        };
        let auth_edit = AuthorizedMessageV1::new(edit_msg, &other_sk);

        let mut messages = MessagesV1 {
            messages: vec![auth_original.clone(), auth_edit],
            ..Default::default()
        };
        messages.rebuild_actions_state();

        // Edit should be ignored - original content preserved
        assert!(!messages.is_edited(&original_id));
        let effective = messages.effective_text(&auth_original);
        assert_eq!(effective, Some("Original content".to_string()));
    }

    #[test]
    fn test_delete_action() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let owner_id = MemberId::from(&verifying_key);

        // Create original message
        let original_msg = MessageV1 {
            images: Vec::new(),
            board_owner: owner_id,
            author: owner_id,
            time: SystemTime::now(),
            content: BoardMessageBody::public(String::new(), "Will be deleted".to_string()),
        };
        let auth_original = AuthorizedMessageV1::new(original_msg, &signing_key);
        let original_id = auth_original.id();

        // Create delete action
        let delete_msg = MessageV1 {
            images: Vec::new(),
            board_owner: owner_id,
            author: owner_id,
            time: SystemTime::now() + Duration::from_secs(1),
            content: BoardMessageBody::delete(original_id.clone()),
        };
        let auth_delete = AuthorizedMessageV1::new(delete_msg, &signing_key);

        let mut messages = MessagesV1 {
            messages: vec![auth_original, auth_delete],
            ..Default::default()
        };
        messages.rebuild_actions_state();

        // Verify message is deleted
        assert!(messages.is_deleted(&original_id));

        // Verify display_messages excludes deleted message
        let display: Vec<_> = messages.display_messages().collect();
        assert_eq!(display.len(), 0);
    }

    #[test]
    fn test_envelope_delete_action_on_category() {
        use crate::board_state::content::{
            ActionContentV1, ModerationActionV1, ACTION_CONTENT_VERSION, ACTION_TYPE_DELETE,
            CONTENT_TYPE_MODERATION_ACTION,
        };
        use crate::board_state::privacy::SealedBytes;

        let signing_key = SigningKey::generate(&mut OsRng);
        let owner_id = MemberId::from(&signing_key.verifying_key());

        let category = MessageV1 {
            images: Vec::new(),
            board_owner: owner_id,
            author: owner_id,
            time: SystemTime::now(),
            content: BoardMessageBody::public_raw(4, 1, vec![0xa0]),
        };
        let auth_category = AuthorizedMessageV1::new(category, &signing_key);
        let category_id = auth_category.id();

        // The UI sends deletes inside a moderation envelope, not as a direct
        // action body.
        let envelope = ModerationActionV1::new(
            ACTION_TYPE_DELETE,
            category_id,
            SealedBytes::public(ActionContentV1::delete(category_id).encode()),
        );
        let delete_msg = MessageV1 {
            images: Vec::new(),
            board_owner: owner_id,
            author: owner_id,
            time: SystemTime::now() + Duration::from_secs(1),
            content: BoardMessageBody::public_raw(
                CONTENT_TYPE_MODERATION_ACTION,
                ACTION_CONTENT_VERSION,
                envelope.encode(),
            ),
        };
        let auth_delete = AuthorizedMessageV1::new(delete_msg, &signing_key);

        let mut messages = MessagesV1 {
            messages: vec![auth_category, auth_delete],
            ..Default::default()
        };
        messages.rebuild_actions_state();
        assert!(messages.is_deleted(&category_id));
        assert_eq!(messages.display_messages().count(), 0);
    }

    #[test]
    fn test_reaction_action() {
        let user1_sk = SigningKey::generate(&mut OsRng);
        let user1_id = MemberId::from(&user1_sk.verifying_key());

        let user2_sk = SigningKey::generate(&mut OsRng);
        let user2_id = MemberId::from(&user2_sk.verifying_key());

        let owner_id = user1_id;

        // Create original message
        let original_msg = MessageV1 {
            images: Vec::new(),
            board_owner: owner_id,
            author: user1_id,
            time: SystemTime::now(),
            content: BoardMessageBody::public(String::new(), "React to me!".to_string()),
        };
        let auth_original = AuthorizedMessageV1::new(original_msg, &user1_sk);
        let original_id = auth_original.id();

        // Create reaction from user2
        let reaction_msg = MessageV1 {
            images: Vec::new(),
            board_owner: owner_id,
            author: user2_id,
            time: SystemTime::now() + Duration::from_secs(1),
            content: BoardMessageBody::reaction(original_id.clone(), "👍".to_string()),
        };
        let auth_reaction = AuthorizedMessageV1::new(reaction_msg, &user2_sk);

        // Create another reaction from user1
        let reaction_msg2 = MessageV1 {
            images: Vec::new(),
            board_owner: owner_id,
            author: user1_id,
            time: SystemTime::now() + Duration::from_secs(2),
            content: BoardMessageBody::reaction(original_id.clone(), "👍".to_string()),
        };
        let auth_reaction2 = AuthorizedMessageV1::new(reaction_msg2, &user1_sk);

        let mut messages = MessagesV1 {
            messages: vec![auth_original, auth_reaction, auth_reaction2],
            ..Default::default()
        };
        messages.rebuild_actions_state();

        // Verify reactions
        let reactions = messages.reactions(&original_id).unwrap();
        let thumbs_up = reactions.get("👍").unwrap();
        assert_eq!(thumbs_up.len(), 2);
        assert!(thumbs_up.contains(&user1_id));
        assert!(thumbs_up.contains(&user2_id));
    }

    #[test]
    fn test_remove_reaction_action() {
        let user_sk = SigningKey::generate(&mut OsRng);
        let user_id = MemberId::from(&user_sk.verifying_key());
        let owner_id = user_id;

        // Create original message
        let original_msg = MessageV1 {
            images: Vec::new(),
            board_owner: owner_id,
            author: user_id,
            time: SystemTime::now(),
            content: BoardMessageBody::public(String::new(), "Test message".to_string()),
        };
        let auth_original = AuthorizedMessageV1::new(original_msg, &user_sk);
        let original_id = auth_original.id();

        // Add reaction
        let reaction_msg = MessageV1 {
            images: Vec::new(),
            board_owner: owner_id,
            author: user_id,
            time: SystemTime::now() + Duration::from_secs(1),
            content: BoardMessageBody::reaction(original_id.clone(), "❤️".to_string()),
        };
        let auth_reaction = AuthorizedMessageV1::new(reaction_msg, &user_sk);

        // Remove reaction
        let remove_msg = MessageV1 {
            images: Vec::new(),
            board_owner: owner_id,
            author: user_id,
            time: SystemTime::now() + Duration::from_secs(2),
            content: BoardMessageBody::remove_reaction(original_id.clone(), "❤️".to_string()),
        };
        let auth_remove = AuthorizedMessageV1::new(remove_msg, &user_sk);

        let mut messages = MessagesV1 {
            messages: vec![auth_original, auth_reaction, auth_remove],
            ..Default::default()
        };
        messages.rebuild_actions_state();

        // Verify reaction was removed
        assert!(messages.reactions(&original_id).is_none());
    }

    #[test]
    fn test_action_on_deleted_message_ignored() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let owner_id = MemberId::from(&verifying_key);

        // Create original message
        let original_msg = MessageV1 {
            images: Vec::new(),
            board_owner: owner_id,
            author: owner_id,
            time: SystemTime::now(),
            content: BoardMessageBody::public(String::new(), "Will be deleted".to_string()),
        };
        let auth_original = AuthorizedMessageV1::new(original_msg, &signing_key);
        let original_id = auth_original.id();

        // Delete it
        let delete_msg = MessageV1 {
            images: Vec::new(),
            board_owner: owner_id,
            author: owner_id,
            time: SystemTime::now() + Duration::from_secs(1),
            content: BoardMessageBody::delete(original_id.clone()),
        };
        let auth_delete = AuthorizedMessageV1::new(delete_msg, &signing_key);

        // Try to edit deleted message (should be ignored)
        let edit_msg = MessageV1 {
            images: Vec::new(),
            board_owner: owner_id,
            author: owner_id,
            time: SystemTime::now() + Duration::from_secs(2),
            content: BoardMessageBody::edit(
                original_id.clone(),
                String::new(),
                "Too late!".to_string(),
            ),
        };
        let auth_edit = AuthorizedMessageV1::new(edit_msg, &signing_key);

        let mut messages = MessagesV1 {
            messages: vec![auth_original, auth_delete, auth_edit],
            ..Default::default()
        };
        messages.rebuild_actions_state();

        // Message should be deleted, edit should be ignored
        assert!(messages.is_deleted(&original_id));
        assert!(!messages.is_edited(&original_id));
    }

    #[test]
    fn test_display_messages_filters_actions() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let owner_id = MemberId::from(&verifying_key);

        // Create regular message
        let msg1 = MessageV1 {
            images: Vec::new(),
            board_owner: owner_id,
            author: owner_id,
            time: SystemTime::now(),
            content: BoardMessageBody::public(String::new(), "Hello".to_string()),
        };
        let auth_msg1 = AuthorizedMessageV1::new(msg1, &signing_key);
        let msg1_id = auth_msg1.id();

        // Create reaction (action message)
        let reaction_msg = MessageV1 {
            images: Vec::new(),
            board_owner: owner_id,
            author: owner_id,
            time: SystemTime::now() + Duration::from_secs(1),
            content: BoardMessageBody::reaction(msg1_id, "👍".to_string()),
        };
        let auth_reaction = AuthorizedMessageV1::new(reaction_msg, &signing_key);

        // Create another regular message
        let msg2 = MessageV1 {
            images: Vec::new(),
            board_owner: owner_id,
            author: owner_id,
            time: SystemTime::now() + Duration::from_secs(2),
            content: BoardMessageBody::public(String::new(), "World".to_string()),
        };
        let auth_msg2 = AuthorizedMessageV1::new(msg2, &signing_key);

        let mut messages = MessagesV1 {
            messages: vec![auth_msg1, auth_reaction, auth_msg2],
            ..Default::default()
        };
        messages.rebuild_actions_state();

        // display_messages should only return regular messages, not actions
        let display: Vec<_> = messages.display_messages().collect();
        assert_eq!(display.len(), 2);
        assert_eq!(
            display[0].message.content.as_public_string(),
            Some("Hello".to_string())
        );
        assert_eq!(
            display[1].message.content.as_public_string(),
            Some("World".to_string())
        );
    }

    #[test]
    fn test_edit_action_on_category_ignored() {
        // Edit actions (ACTION_TYPE_EDIT) should be ignored when targeting a category
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let owner_id = MemberId::from(&verifying_key);

        // Create a category
        let category_msg = MessageV1 {
            images: Vec::new(),
            board_owner: owner_id,
            author: owner_id,
            time: SystemTime::now(),
            content: BoardMessageBody::category(
                "Test Category".to_string(),
                Some("Description".to_string()),
                None,
                "#ff0000".to_string(),
                None,
            ),
        };
        let auth_category = AuthorizedMessageV1::new(category_msg, &signing_key);
        let category_id = auth_category.id();

        // Try to edit the category using ACTION_TYPE_EDIT (wrong action type)
        let edit_msg = MessageV1 {
            images: Vec::new(),
            board_owner: owner_id,
            author: owner_id,
            time: SystemTime::now() + Duration::from_secs(1),
            content: BoardMessageBody::edit(
                category_id.clone(),
                String::new(),
                "Hacked content".to_string(),
            ),
        };
        let auth_edit = AuthorizedMessageV1::new(edit_msg, &signing_key);

        let mut messages = MessagesV1 {
            messages: vec![auth_category, auth_edit],
            ..Default::default()
        };
        messages.rebuild_actions_state();

        // Edit should be ignored - category should NOT appear as edited
        assert!(!messages.is_edited(&category_id));
    }

    #[test]
    fn test_edit_category_action_on_regular_message_ignored() {
        // Edit category actions (ACTION_TYPE_EDIT_CATEGORY) should be ignored when targeting a regular message
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let owner_id = MemberId::from(&verifying_key);

        // Create a regular text message
        let text_msg = MessageV1 {
            images: Vec::new(),
            board_owner: owner_id,
            author: owner_id,
            time: SystemTime::now(),
            content: BoardMessageBody::public(String::new(), "Regular message".to_string()),
        };
        let auth_text = AuthorizedMessageV1::new(text_msg, &signing_key);
        let text_id = auth_text.id();

        // Try to edit the text message using ACTION_TYPE_EDIT_CATEGORY (wrong action type)
        let edit_msg = MessageV1 {
            images: Vec::new(),
            board_owner: owner_id,
            author: owner_id,
            time: SystemTime::now() + Duration::from_secs(1),
            content: BoardMessageBody::edit_category(
                text_id.clone(),
                "Hacked name".to_string(),
                None,
                None,
                "#ff0000".to_string(),
            ),
        };
        let auth_edit = AuthorizedMessageV1::new(edit_msg, &signing_key);

        let mut messages = MessagesV1 {
            messages: vec![auth_text, auth_edit],
            ..Default::default()
        };
        messages.rebuild_actions_state();

        // Edit should be ignored - message should NOT appear as category-edited
        assert!(!messages.is_category_edited(&text_id));
    }

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn topic(
        signer: &SigningKey,
        author: MemberId,
        owner_id: MemberId,
        section: Option<MessageId>,
        auto_moderated: bool,
        time: SystemTime,
    ) -> AuthorizedMessageV1 {
        use crate::board_state::content::{TEXT_CONTENT_VERSION, CONTENT_TYPE_TEXT};
        let text = TextContentV1::new("Topic".to_string(), "Body".to_string())
            .with_category(section)
            .with_auto_moderated(auto_moderated);
        AuthorizedMessageV1::new(
            MessageV1 {
                board_owner: owner_id,
                author,
                time,
                content: BoardMessageBody::public_raw(
                    CONTENT_TYPE_TEXT,
                    TEXT_CONTENT_VERSION,
                    text.encode(),
                ),
                images: Vec::new(),
            },
            signer,
        )
    }

    fn poll_topic(
        signer: &SigningKey,
        author: MemberId,
        owner_id: MemberId,
        section: Option<MessageId>,
        auto_moderated: bool,
        time: SystemTime,
    ) -> AuthorizedMessageV1 {
        use crate::board_state::content::{
            PollContentV1, CONTENT_TYPE_POLL, POLL_CONTENT_VERSION,
        };
        let poll = PollContentV1::new(
            "Question".to_string(),
            "Body".to_string(),
            vec!["A".to_string(), "B".to_string()],
            None,
            false,
        )
        .with_category(section)
        .with_auto_moderated(auto_moderated);
        AuthorizedMessageV1::new(
            MessageV1 {
                board_owner: owner_id,
                author,
                time,
                content: BoardMessageBody::public_raw(
                    CONTENT_TYPE_POLL,
                    POLL_CONTENT_VERSION,
                    poll.encode(),
                ),
                images: Vec::new(),
            },
            signer,
        )
    }

    fn reply_to(
        signer: &SigningKey,
        author: MemberId,
        owner_id: MemberId,
        target: MessageId,
        time: SystemTime,
    ) -> AuthorizedMessageV1 {
        AuthorizedMessageV1::new(
            MessageV1 {
                board_owner: owner_id,
                author,
                time,
                content: BoardMessageBody::reply(
                    String::new(),
                    "Reply".to_string(),
                    target,
                    "Someone".to_string(),
                    "Preview".to_string(),
                ),
                images: Vec::new(),
            },
            signer,
        )
    }

    fn delete_by(
        signer: &SigningKey,
        author: MemberId,
        owner_id: MemberId,
        target: MessageId,
        time: SystemTime,
    ) -> AuthorizedMessageV1 {
        AuthorizedMessageV1::new(
            MessageV1 {
                board_owner: owner_id,
                author,
                time,
                content: BoardMessageBody::delete(target),
                images: Vec::new(),
            },
            signer,
        )
    }

    fn reaction_by(
        signer: &SigningKey,
        author: MemberId,
        owner_id: MemberId,
        target: MessageId,
        time: SystemTime,
    ) -> AuthorizedMessageV1 {
        AuthorizedMessageV1::new(
            MessageV1 {
                board_owner: owner_id,
                author,
                time,
                content: BoardMessageBody::reaction(target, "👍".to_string()),
                images: Vec::new(),
            },
            signer,
        )
    }

    fn nickname_by(
        signer: &SigningKey,
        author: MemberId,
        owner_id: MemberId,
        target: MemberId,
        nickname: &str,
        time: SystemTime,
    ) -> AuthorizedMessageV1 {
        use crate::board_state::content::{
            ActionContentV1, ACTION_CONTENT_VERSION, ACTION_TYPE_SET_NICKNAME,
            CONTENT_TYPE_MODERATION_ACTION,
        };
        let action = ActionContentV1::set_nickname(target, nickname.to_string());
        let envelope = crate::board_state::content::ModerationActionV1::new(
            ACTION_TYPE_SET_NICKNAME,
            action.target.clone(),
            crate::board_state::privacy::SealedBytes::public(action.encode()),
        );
        AuthorizedMessageV1::new(
            MessageV1 {
                board_owner: owner_id,
                author,
                time,
                content: BoardMessageBody::public_raw(
                    CONTENT_TYPE_MODERATION_ACTION,
                    ACTION_CONTENT_VERSION,
                    envelope.encode(),
                ),
                images: Vec::new(),
            },
            signer,
        )
    }

    fn category_with_auto(
        owner: &SigningKey,
        owner_id: MemberId,
        auto_moderated_topics: Option<bool>,
        time: SystemTime,
    ) -> (AuthorizedMessageV1, MessageId) {
        use crate::board_state::content::{
            CategoryContentV1, CATEGORY_CONTENT_VERSION, CONTENT_TYPE_CATEGORY,
        };
        let category = CategoryContentV1::new(
            "General".to_string(),
            None,
            crate::board_state::content::DEFAULT_CATEGORY_COLOR.to_string(),
        )
        .with_auto_moderated_topics(auto_moderated_topics);
        let message = AuthorizedMessageV1::new(
            MessageV1 {
                board_owner: owner_id,
                author: owner_id,
                time,
                content: BoardMessageBody::public_raw(
                    CONTENT_TYPE_CATEGORY,
                    CATEGORY_CONTENT_VERSION,
                    category.encode(),
                ),
                images: Vec::new(),
            },
            owner,
        );
        let id = message.id();
        (message, id)
    }

    struct Fixture {
        owner: SigningKey,
        author: SigningKey,
        stranger: SigningKey,
        state: ChatBoardStateV1,
        parameters: ChatBoardParametersV1,
        owner_id: MemberId,
        author_id: MemberId,
        stranger_id: MemberId,
    }

    /// The owner plus two invited members.
    fn board_fixture() -> Fixture {
        let owner = SigningKey::from_bytes(&[51u8; 32]);
        let author = SigningKey::from_bytes(&[52u8; 32]);
        let stranger = SigningKey::from_bytes(&[53u8; 32]);
        let owner_id = MemberId::from(&owner.verifying_key());
        let author_id = MemberId::from(&author.verifying_key());
        let stranger_id = MemberId::from(&stranger.verifying_key());
        let mut configuration = Configuration::default();
        configuration.owner_member_id = owner_id;
        let mut state = ChatBoardStateV1 {
            configuration: AuthorizedConfigurationV1::new(configuration, &owner),
            ..Default::default()
        };
        for signer in [&author, &stranger] {
            state.members.members.push(AuthorizedMember::new(
                Member {
                    owner_member_id: owner_id,
                    invited_by: owner_id,
                    member_vk: signer.verifying_key(),
                    join_proof: None,
                },
                &owner,
            ));
        }
        let parameters = ChatBoardParametersV1 {
            owner: owner.verifying_key(),
        };
        Fixture {
            owner,
            author,
            stranger,
            state,
            parameters,
            owner_id,
            author_id,
            stranger_id,
        }
    }

    fn apply_topic(
        state: &ChatBoardStateV1,
        parameters: &ChatBoardParametersV1,
        messages: &mut MessagesV1,
        message: AuthorizedMessageV1,
    ) -> Result<(), String> {
        messages.apply_delta(state, parameters, &Some(vec![message]))
    }

    fn rebuild(
        state: &ChatBoardStateV1,
        parameters: &ChatBoardParametersV1,
        messages: &mut MessagesV1,
        reactions: bool,
    ) {
        use std::collections::HashSet;
        let admins: HashSet<MemberId> = state
            .admin
            .admins
            .iter()
            .map(|admin| admin.admin.id())
            .collect();
        let members: HashSet<MemberId> = state
            .members
            .members
            .iter()
            .map(|member| member.member.id())
            .collect();
        messages.rebuild_actions_state_with_permissions(
            &HashMap::new(),
            Some(parameters.owner_id()),
            Some(&admins),
            None,
            reactions,
            Some(&members),
        );
    }

    #[test]
    fn auto_moderated_topics_follow_the_section_capability() {
        let fixture = board_fixture();
        let (open_message, open) =
            category_with_auto(&fixture.owner, fixture.owner_id, Some(true), at(1));
        let (closed_message, closed) =
            category_with_auto(&fixture.owner, fixture.owner_id, Some(false), at(2));
        let (inherited_message, inherited) =
            category_with_auto(&fixture.owner, fixture.owner_id, None, at(3));

        let base = |categories: Vec<AuthorizedMessageV1>| MessagesV1 {
            messages: categories,
            ..Default::default()
        };

        let mut messages = base(vec![
            open_message.clone(),
            closed_message.clone(),
            inherited_message.clone(),
        ]);
        apply_topic(
            &fixture.state,
            &fixture.parameters,
            &mut messages,
            topic(
                &fixture.author,
                fixture.author_id,
                fixture.owner_id,
                Some(open.clone()),
                true,
                at(10),
            ),
        )
        .expect("an open section accepts an auto-moderated topic");

        let mut messages = base(vec![
            open_message.clone(),
            closed_message.clone(),
            inherited_message.clone(),
        ]);
        let error = apply_topic(
            &fixture.state,
            &fixture.parameters,
            &mut messages,
            topic(
                &fixture.author,
                fixture.author_id,
                fixture.owner_id,
                Some(closed.clone()),
                true,
                at(11),
            ),
        )
        .expect_err("a closed section rejects the flag");
        assert!(error.contains("auto-moderated"), "{error}");

        // Polls carry the section too, so the same rule applies.
        let mut messages = base(vec![
            open_message.clone(),
            closed_message.clone(),
            inherited_message.clone(),
        ]);
        apply_topic(
            &fixture.state,
            &fixture.parameters,
            &mut messages,
            poll_topic(
                &fixture.author,
                fixture.author_id,
                fixture.owner_id,
                Some(closed.clone()),
                true,
                at(11),
            ),
        )
        .expect_err("a closed section rejects an auto-moderated poll");

        let mut messages = base(vec![
            open_message.clone(),
            closed_message.clone(),
            inherited_message.clone(),
        ]);
        apply_topic(
            &fixture.state,
            &fixture.parameters,
            &mut messages,
            topic(
                &fixture.author,
                fixture.author_id,
                fixture.owner_id,
                Some(inherited.clone()),
                true,
                at(12),
            ),
        )
        .expect("the section inherits the board setting");

        let mut messages = base(vec![
            open_message.clone(),
            closed_message.clone(),
            inherited_message.clone(),
        ]);
        apply_topic(
            &fixture.state,
            &fixture.parameters,
            &mut messages,
            topic(
                &fixture.author,
                fixture.author_id,
                fixture.owner_id,
                Some(closed.clone()),
                false,
                at(13),
            ),
        )
        .expect("a normal topic is always accepted");

        // Turning the board default off closes the root and inherited sections;
        // an explicit section override stays open.
        let mut state = fixture.state.clone();
        let mut config = state.configuration.configuration.clone();
        config.configuration_version += 1;
        config.auto_moderated_topics = false;
        state.configuration = AuthorizedConfigurationV1::new(config, &fixture.owner);

        let mut messages = base(vec![
            open_message.clone(),
            closed_message.clone(),
            inherited_message.clone(),
        ]);
        let error = apply_topic(
            &state,
            &fixture.parameters,
            &mut messages,
            topic(
                &fixture.author,
                fixture.author_id,
                fixture.owner_id,
                None,
                true,
                at(14),
            ),
        )
        .expect_err("the board root follows the board default");
        assert!(error.contains("auto-moderated"), "{error}");

        let mut messages = base(vec![
            open_message.clone(),
            closed_message.clone(),
            inherited_message.clone(),
        ]);
        apply_topic(
            &state,
            &fixture.parameters,
            &mut messages,
            topic(
                &fixture.author,
                fixture.author_id,
                fixture.owner_id,
                Some(inherited),
                true,
                at(15),
            ),
        )
        .expect_err("an inherited section follows the board default");

        let mut messages = base(vec![open_message, closed_message, inherited_message]);
        apply_topic(
            &state,
            &fixture.parameters,
            &mut messages,
            topic(
                &fixture.author,
                fixture.author_id,
                fixture.owner_id,
                Some(open),
                true,
                at(16),
            ),
        )
        .expect("an explicit section override wins");
    }

    #[test]
    fn an_auto_moderated_topic_author_deletes_replies_but_not_the_topic() {
        let fixture = board_fixture();
        let topic = topic(
            &fixture.author,
            fixture.author_id,
            fixture.owner_id,
            None,
            true,
            at(10),
        );
        let topic_id = topic.id();
        let reply = reply_to(
            &fixture.stranger,
            fixture.stranger_id,
            fixture.owner_id,
            topic_id.clone(),
            at(11),
        );
        let reply_id = reply.id();
        let nested = reply_to(
            &fixture.stranger,
            fixture.stranger_id,
            fixture.owner_id,
            reply_id.clone(),
            at(12),
        );
        let nested_id = nested.id();

        let mut messages = MessagesV1 {
            messages: vec![
                topic,
                reply,
                nested,
                delete_by(
                    &fixture.author,
                    fixture.author_id,
                    fixture.owner_id,
                    reply_id.clone(),
                    at(20),
                ),
                delete_by(
                    &fixture.author,
                    fixture.author_id,
                    fixture.owner_id,
                    nested_id.clone(),
                    at(21),
                ),
                // The auto-moderated privilege stops at the root; the author's
                // ordinary right to delete its own topic is unchanged.
                delete_by(
                    &fixture.stranger,
                    fixture.stranger_id,
                    fixture.owner_id,
                    topic_id.clone(),
                    at(22),
                ),
            ],
            ..Default::default()
        };
        rebuild(&fixture.state, &fixture.parameters, &mut messages, true);

        assert!(messages.is_deleted(&reply_id), "the reply is removed");
        assert!(messages.is_deleted(&nested_id), "a nested reply follows");
        assert!(
            !messages.is_deleted(&topic_id),
            "a stranger cannot delete the topic itself"
        );
    }

    #[test]
    fn a_stranger_cannot_delete_replies_on_an_auto_moderated_topic() {
        let fixture = board_fixture();
        let topic = topic(
            &fixture.author,
            fixture.author_id,
            fixture.owner_id,
            None,
            true,
            at(10),
        );
        let topic_id = topic.id();
        let reply = reply_to(
            &fixture.author,
            fixture.author_id,
            fixture.owner_id,
            topic_id.clone(),
            at(11),
        );
        let reply_id = reply.id();
        let mut messages = MessagesV1 {
            messages: vec![
                topic,
                reply,
                delete_by(
                    &fixture.stranger,
                    fixture.stranger_id,
                    fixture.owner_id,
                    reply_id.clone(),
                    at(20),
                ),
            ],
            ..Default::default()
        };
        rebuild(&fixture.state, &fixture.parameters, &mut messages, true);
        assert!(!messages.is_deleted(&reply_id));
    }

    #[test]
    fn a_normal_topic_does_not_grant_delete_power_to_its_author() {
        let fixture = board_fixture();
        let topic = topic(
            &fixture.author,
            fixture.author_id,
            fixture.owner_id,
            None,
            false,
            at(10),
        );
        let topic_id = topic.id();
        let reply = reply_to(
            &fixture.stranger,
            fixture.stranger_id,
            fixture.owner_id,
            topic_id.clone(),
            at(11),
        );
        let reply_id = reply.id();
        let mut messages = MessagesV1 {
            messages: vec![
                topic,
                reply,
                delete_by(
                    &fixture.author,
                    fixture.author_id,
                    fixture.owner_id,
                    reply_id.clone(),
                    at(20),
                ),
            ],
            ..Default::default()
        };
        rebuild(&fixture.state, &fixture.parameters, &mut messages, true);
        assert!(!messages.is_deleted(&reply_id));
    }

    #[test]
    fn only_owners_and_admins_set_nickname_overrides() {
        let mut fixture = board_fixture();
        fixture.state.admin.admins.push(AuthorizedAdmin::new(
            Admin {
                member_id: fixture.stranger_id,
                generation: 1,
                signed_at: SystemTime::UNIX_EPOCH,
            },
            &fixture.owner,
        ));

        let mut messages = MessagesV1 {
            messages: vec![
                // A plain member cannot override anyone, including itself.
                nickname_by(
                    &fixture.author,
                    fixture.author_id,
                    fixture.owner_id,
                    fixture.author_id,
                    "Self",
                    at(10),
                ),
                // The owner and an admin can.
                nickname_by(
                    &fixture.owner,
                    fixture.owner_id,
                    fixture.owner_id,
                    fixture.author_id,
                    "Owner name",
                    at(11),
                ),
                nickname_by(
                    &fixture.stranger,
                    fixture.stranger_id,
                    fixture.owner_id,
                    fixture.author_id,
                    "Admin name",
                    at(12),
                ),
                // A non-member is not a valid target.
                nickname_by(
                    &fixture.owner,
                    fixture.owner_id,
                    fixture.owner_id,
                    MemberId::from_bytes([99u8; 32]),
                    "Nobody",
                    at(13),
                ),
            ],
            ..Default::default()
        };
        rebuild(&fixture.state, &fixture.parameters, &mut messages, true);

        let applied = messages.nickname_override(&fixture.author_id).unwrap();
        assert_eq!(applied.nickname, "Admin name", "the highest version wins");
        assert_eq!(applied.set_by, fixture.stranger_id);
        assert!(
            messages
                .nickname_override(&MemberId::from_bytes([99u8; 32]))
                .is_none(),
            "a non-member gets no override"
        );
    }

    #[test]
    fn the_reaction_gate_ignores_history_and_new_reactions() {
        let fixture = board_fixture();
        let post = topic(
            &fixture.owner,
            fixture.owner_id,
            fixture.owner_id,
            None,
            false,
            at(1),
        );
        let post_id = post.id();
        let mut messages = MessagesV1 {
            messages: vec![
                post,
                reaction_by(
                    &fixture.stranger,
                    fixture.stranger_id,
                    fixture.owner_id,
                    post_id.clone(),
                    at(2),
                ),
            ],
            ..Default::default()
        };
        rebuild(&fixture.state, &fixture.parameters, &mut messages, true);
        assert!(messages.reactions(&post_id).is_some());

        rebuild(&fixture.state, &fixture.parameters, &mut messages, false);
        assert!(
            messages.reactions(&post_id).is_none(),
            "disabled reactions disappear, history included"
        );

        rebuild(&fixture.state, &fixture.parameters, &mut messages, true);
        assert_eq!(
            messages.reactions(&post_id).unwrap().get("👍").unwrap().len(),
            1
        );
    }

    #[test]
    fn a_sealed_nickname_action_applies_only_with_the_decrypted_payload() {
        let fixture = board_fixture();
        use crate::board_state::content::{
            ActionContentV1, ACTION_CONTENT_VERSION, ACTION_TYPE_SET_NICKNAME,
            CONTENT_TYPE_MODERATION_ACTION,
        };
        use crate::board_state::privacy::SealedBytes;

        let action = ActionContentV1::set_nickname(fixture.author_id, "Sealed name".to_string());
        let plaintext = action.encode();
        let envelope = crate::board_state::content::ModerationActionV1::new(
            ACTION_TYPE_SET_NICKNAME,
            action.target.clone(),
            SealedBytes::private(plaintext.clone(), [0u8; 12], 0, plaintext.len() as u32),
        );
        let message = AuthorizedMessageV1::new(
            MessageV1 {
                board_owner: fixture.owner_id,
                author: fixture.owner_id,
                time: at(10),
                content: BoardMessageBody::public_raw(
                    CONTENT_TYPE_MODERATION_ACTION,
                    ACTION_CONTENT_VERSION,
                    envelope.encode(),
                ),
                images: Vec::new(),
            },
            &fixture.owner,
        );
        let message_id = message.id();
        let mut messages = MessagesV1 {
            messages: vec![message],
            ..Default::default()
        };

        rebuild(&fixture.state, &fixture.parameters, &mut messages, true);
        assert!(
            messages.nickname_override(&fixture.author_id).is_none(),
            "a sealed payload needs the client key"
        );

        let mut decrypted = HashMap::new();
        decrypted.insert(message_id, plaintext);
        use std::collections::HashSet;
        let admins: HashSet<MemberId> = HashSet::new();
        let members: HashSet<MemberId> = fixture
            .state
            .members
            .members
            .iter()
            .map(|member| member.member.id())
            .collect();
        messages.rebuild_actions_state_with_permissions(
            &decrypted,
            Some(fixture.owner_id),
            Some(&admins),
            None,
            true,
            Some(&members),
        );
        assert_eq!(
            messages
                .nickname_override(&fixture.author_id)
                .map(|entry| entry.nickname.as_str()),
            Some("Sealed name")
        );
    }

    #[test]
    fn a_poll_edit_cannot_change_the_auto_moderated_flag() {
        use crate::board_state::content::{
            ActionContentV1, PollContentV1, ACTION_CONTENT_VERSION, CONTENT_TYPE_ACTION,
            CONTENT_TYPE_POLL, POLL_CONTENT_VERSION,
        };
        let fixture = board_fixture();
        let poll = PollContentV1::new(
            "Question".to_string(),
            "Body".to_string(),
            vec!["A".to_string(), "B".to_string()],
            None,
            false,
        )
        .with_auto_moderated(true);
        let original = AuthorizedMessageV1::new(
            MessageV1 {
                board_owner: fixture.owner_id,
                author: fixture.author_id,
                time: at(10),
                content: BoardMessageBody::public_raw(
                    CONTENT_TYPE_POLL,
                    POLL_CONTENT_VERSION,
                    poll.encode(),
                ),
                images: Vec::new(),
            },
            &fixture.author,
        );
        let poll_id = original.id();
        let mut replacement = poll.clone();
        replacement.auto_moderated = false;
        replacement.description = "Edited".to_string();
        let edit = AuthorizedMessageV1::new(
            MessageV1 {
                board_owner: fixture.owner_id,
                author: fixture.author_id,
                time: at(11),
                content: BoardMessageBody::public_raw(
                    CONTENT_TYPE_ACTION,
                    ACTION_CONTENT_VERSION,
                    ActionContentV1::edit_poll(poll_id.clone(), replacement).encode(),
                ),
                images: Vec::new(),
            },
            &fixture.author,
        );
        let mut messages = MessagesV1 {
            messages: vec![original, edit],
            ..Default::default()
        };
        rebuild(&fixture.state, &fixture.parameters, &mut messages, true);
        let edited = messages.edited_poll(&poll_id).expect("the edit applies");
        assert_eq!(edited.description, "Edited");
        assert!(edited.auto_moderated, "the creation-time flag is preserved");
    }

    #[test]
    fn a_section_override_wins_over_the_board_setting() {
        let mut fixture = board_fixture();
        let (closed_message, closed) =
            category_with_auto(&fixture.owner, fixture.owner_id, Some(false), at(1));
        let (open_message, open) =
            category_with_auto(&fixture.owner, fixture.owner_id, Some(true), at(2));
        let mut messages = MessagesV1 {
            messages: vec![closed_message, open_message],
            ..Default::default()
        };
        assert!(!messages.section_auto_moderated_topics(&fixture.state, Some(&closed)));
        assert!(messages.section_auto_moderated_topics(&fixture.state, None));

        let mut config = fixture.state.configuration.configuration.clone();
        config.configuration_version += 1;
        config.auto_moderated_topics = false;
        fixture.state.configuration = AuthorizedConfigurationV1::new(config, &fixture.owner);

        assert!(messages.section_auto_moderated_topics(&fixture.state, Some(&open)));
        assert!(!messages.section_auto_moderated_topics(&fixture.state, None));
    }
}
