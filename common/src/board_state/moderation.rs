//! Public moderation routing, post flags and contract-side permission checks.
//!
//! Routing records carry only IDs: which category contains a message, which
//! message it replies to, and whether a category is a group and its parent.
//! Post flags carry pinned/closed with a generation. Both are signed by the
//! actor and verified by the contract.

use crate::board_state::content::CONTENT_TYPE_MODERATION_ACTION;
use crate::board_state::member::MemberId;
use crate::board_state::message::MessageId;
use crate::board_state::roles::{signer_key, ModerationPower};
use crate::board_state::ChatBoardParametersV1;
use crate::util::{sign_struct, verify_struct};
use crate::ChatBoardStateV1;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use freenet_scaffold::ComposableState;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct MessageRoute {
    pub message_id: MessageId,
    pub reply_to: Option<MessageId>,
    pub category_id: Option<MessageId>,
    pub is_category: bool,
    pub parent_category_id: Option<MessageId>,
    pub is_group: bool,
    pub generation: u64,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedMessageRoute {
    pub route: MessageRoute,
    pub signature: Signature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<MemberId>,
}

impl AuthorizedMessageRoute {
    pub fn new(route: MessageRoute, signing_key: &SigningKey) -> Self {
        Self {
            signature: sign_struct(&route, signing_key),
            route,
            signer: None,
        }
    }

    pub fn signer_id(&self, parameters: &ChatBoardParametersV1) -> MemberId {
        self.signer.unwrap_or_else(|| parameters.owner_id())
    }

    pub fn verify_signature_with(&self, key: &VerifyingKey) -> Result<(), String> {
        verify_struct(&self.route, &self.signature, key)
            .map_err(|e| format!("Invalid message route signature: {}", e))
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct PostFlag {
    pub target: MessageId,
    pub pinned: bool,
    pub closed: bool,
    pub generation: u64,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedPostFlag {
    pub flag: PostFlag,
    pub signature: Signature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<MemberId>,
}

impl AuthorizedPostFlag {
    pub fn new(flag: PostFlag, signing_key: &SigningKey) -> Self {
        Self {
            signature: sign_struct(&flag, signing_key),
            flag,
            signer: None,
        }
    }

    pub fn signer_id(&self, parameters: &ChatBoardParametersV1) -> MemberId {
        self.signer.unwrap_or_else(|| parameters.owner_id())
    }

    pub fn verify_signature_with(&self, key: &VerifyingKey) -> Result<(), String> {
        verify_struct(&self.flag, &self.signature, key)
            .map_err(|e| format!("Invalid post flag signature: {}", e))
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct ModerationV1 {
    pub routes: Vec<AuthorizedMessageRoute>,
    pub flags: Vec<AuthorizedPostFlag>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct RouteState {
    pub reply_to: Option<MessageId>,
    pub category_id: Option<MessageId>,
    pub is_category: bool,
    pub parent_category_id: Option<MessageId>,
    pub is_group: bool,
    pub generation: u64,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct FlagState {
    pub pinned: bool,
    pub closed: bool,
    pub generation: u64,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct ModerationSummary {
    pub routes: BTreeMap<MessageId, RouteState>,
    pub flags: BTreeMap<MessageId, FlagState>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct ModerationDelta {
    #[serde(default)]
    pub routes: Vec<AuthorizedMessageRoute>,
    #[serde(default)]
    pub flags: Vec<AuthorizedPostFlag>,
}

fn route_map(routes: &[AuthorizedMessageRoute]) -> BTreeMap<MessageId, RouteState> {
    let mut map = BTreeMap::new();
    for route in routes {
        map.insert(
            route.route.message_id,
            RouteState {
                reply_to: route.route.reply_to,
                category_id: route.route.category_id,
                is_category: route.route.is_category,
                parent_category_id: route.route.parent_category_id,
                is_group: route.route.is_group,
                generation: route.route.generation,
            },
        );
    }
    map
}

fn flag_map(flags: &[AuthorizedPostFlag]) -> BTreeMap<MessageId, FlagState> {
    let mut map = BTreeMap::new();
    for flag in flags {
        map.insert(
            flag.flag.target,
            FlagState {
                pinned: flag.flag.pinned,
                closed: flag.flag.closed,
                generation: flag.flag.generation,
            },
        );
    }
    map
}

pub fn category_chain(
    routes: &BTreeMap<MessageId, RouteState>,
    target: &MessageId,
) -> Vec<MessageId> {
    let Some(route) = routes.get(target) else {
        return Vec::new();
    };
    let mut category = if route.is_category {
        Some(*target)
    } else {
        route.category_id
    };
    let mut chain = Vec::new();
    while let Some(id) = category {
        if chain.contains(&id) {
            break;
        }
        chain.push(id);
        category = routes.get(&id).and_then(|r| r.parent_category_id);
    }
    chain
}

fn is_owner_or_admin(
    state: &ChatBoardStateV1,
    parameters: &ChatBoardParametersV1,
    actor: &MemberId,
) -> bool {
    *actor == parameters.owner_id()
        || state
            .admin
            .admins
            .iter()
            .any(|admin| admin.admin.id() == *actor)
}

fn target_author(state: &ChatBoardStateV1, target: &MessageId) -> Option<MemberId> {
    state
        .recent_messages
        .messages
        .iter()
        .find(|message| message.id() == *target)
        .map(|message| message.message.author)
}

fn verify_route(
    state: &ChatBoardStateV1,
    parameters: &ChatBoardParametersV1,
    route: &AuthorizedMessageRoute,
) -> Result<(), String> {
    let signer = route.signer_id(parameters);
    let key = signer_key(state, parameters, &signer)?;
    route.verify_signature_with(&key)?;

    let message = state
        .recent_messages
        .messages
        .iter()
        .find(|message| message.id() == route.route.message_id)
        .ok_or("Message route targets a missing message")?;
    if message.message.author != signer {
        return Err("Message route must be signed by the message author".to_string());
    }
    if route.route.is_category {
        if message.message.content.content_type()
            != crate::board_state::content::CONTENT_TYPE_CATEGORY
        {
            return Err("Category route targets a non-category message".to_string());
        }
        if route.route.category_id != Some(route.route.message_id) {
            return Err("Category route must point to itself".to_string());
        }
        if route.route.is_group && route.route.parent_category_id.is_some() {
            return Err("A group cannot have a parent category".to_string());
        }
        if let Some(parent) = route.route.parent_category_id {
            let parent_message = state
                .recent_messages
                .messages
                .iter()
                .find(|message| message.id() == parent)
                .ok_or("Category parent is missing")?;
            if parent_message.message.content.content_type()
                != crate::board_state::content::CONTENT_TYPE_CATEGORY
            {
                return Err("Category parent is not a category".to_string());
            }
        }
    } else if route.route.is_group
        || route.route.parent_category_id.is_some()
        || route.route.category_id == Some(route.route.message_id)
    {
        return Err("Post route carries category-only fields".to_string());
    }
    Ok(())
}

fn check_flag_permission(
    state: &ChatBoardStateV1,
    parameters: &ChatBoardParametersV1,
    routes: &BTreeMap<MessageId, RouteState>,
    existing: Option<&FlagState>,
    flag: &PostFlag,
    signer: &MemberId,
) -> Result<(), String> {
    if is_owner_or_admin(state, parameters, signer) {
        return Ok(());
    }
    let current = existing.cloned().unwrap_or_default();
    let pinned_changed = current.pinned != flag.pinned;
    let closed_changed = current.closed != flag.closed;
    if !pinned_changed && !closed_changed {
        return Err("Post flag does not change anything".to_string());
    }
    let author = target_author(state, &flag.target);
    if closed_changed && author.as_ref() == Some(signer) {
        return Ok(());
    }
    let chain = category_chain(routes, &flag.target);
    if pinned_changed
        && state
            .roles
            .has_moderation_power(signer, ModerationPower::Pin, &chain)
    {
        return Ok(());
    }
    if closed_changed
        && state
            .roles
            .has_moderation_power(signer, ModerationPower::Close, &chain)
    {
        return Ok(());
    }
    Err("Signer cannot change this post flag".to_string())
}

fn verify_flag(
    state: &ChatBoardStateV1,
    parameters: &ChatBoardParametersV1,
    routes: &BTreeMap<MessageId, RouteState>,
    flag: &AuthorizedPostFlag,
) -> Result<(), String> {
    let signer = flag.signer_id(parameters);
    let key = signer_key(state, parameters, &signer)?;
    flag.verify_signature_with(&key)?;
    if target_author(state, &flag.flag.target).is_none() {
        return Err("Post flag targets a missing message".to_string());
    }
    let existing = state
        .moderation
        .flags
        .iter()
        .filter(|entry| entry.flag.target == flag.flag.target)
        .max_by_key(|entry| entry.flag.generation)
        .map(|entry| FlagState {
            pinned: entry.flag.pinned,
            closed: entry.flag.closed,
            generation: entry.flag.generation,
        });
    check_flag_permission(
        state,
        parameters,
        routes,
        existing.as_ref(),
        &flag.flag,
        &signer,
    )
}

impl ModerationV1 {
    pub fn route(&self, message_id: &MessageId) -> Option<&MessageRoute> {
        self.routes
            .iter()
            .filter(|route| route.route.message_id == *message_id)
            .max_by_key(|route| route.route.generation)
            .map(|route| &route.route)
    }

    pub fn flag_for(&self, target: &MessageId) -> Option<&PostFlag> {
        self.flags
            .iter()
            .filter(|flag| flag.flag.target == *target)
            .max_by_key(|flag| flag.flag.generation)
            .map(|flag| &flag.flag)
    }

    pub fn is_pinned(&self, target: &MessageId) -> bool {
        self.flag_for(target)
            .map(|flag| flag.pinned)
            .unwrap_or(false)
    }

    pub fn is_closed(&self, target: &MessageId) -> bool {
        self.flag_for(target)
            .map(|flag| flag.closed)
            .unwrap_or(false)
    }

    pub fn routes_map(&self) -> BTreeMap<MessageId, RouteState> {
        route_map(&self.routes)
    }

    /// Contract check for new action envelopes and replies to closed posts.
    pub fn validate_actions(
        &self,
        state: &ChatBoardStateV1,
        parameters: &ChatBoardParametersV1,
    ) -> Result<(), String> {
        let routes = route_map(&self.routes);
        let flags = flag_map(&self.flags);

        for message in &state.recent_messages.messages {
            let message_id = message.id();
            if let Some(route) = routes.get(&message_id) {
                if let Some(target) = route.reply_to {
                    if flags.get(&target).map(|flag| flag.closed).unwrap_or(false) {
                        return Err("Cannot reply to a closed post".to_string());
                    }
                }
            }

            let action = match &message.message.content {
                crate::board_state::message::BoardMessageBody::Public {
                    content_type,
                    data,
                    ..
                } if *content_type == CONTENT_TYPE_MODERATION_ACTION => {
                    crate::board_state::content::ModerationActionV1::decode(data).ok()
                }
                _ => None,
            };
            let Some(action) = action else {
                continue;
            };
            if flags
                .get(&action.target)
                .map(|flag| flag.closed)
                .unwrap_or(false)
            {
                return Err("Cannot modify a closed post".to_string());
            }
            let actor = message.message.author;
            if is_owner_or_admin(state, parameters, &actor) {
                continue;
            }
            if target_author(state, &action.target).as_ref() == Some(&actor) {
                continue;
            }
            let chain = category_chain(&routes, &action.target);
            let allowed =
                match action.action_type {
                    crate::board_state::content::ACTION_TYPE_EDIT => state
                        .roles
                        .has_moderation_power(&actor, ModerationPower::Edit, &chain),
                    crate::board_state::content::ACTION_TYPE_DELETE => state
                        .roles
                        .has_moderation_power(&actor, ModerationPower::Delete, &chain),
                    crate::board_state::content::ACTION_TYPE_REACTION
                    | crate::board_state::content::ACTION_TYPE_REMOVE_REACTION => true,
                    _ => false,
                };
            if !allowed {
                return Err("Actor cannot perform this moderation action".to_string());
            }
        }
        Ok(())
    }
}

impl ComposableState for ModerationV1 {
    type ParentState = ChatBoardStateV1;
    type Summary = ModerationSummary;
    type Delta = ModerationDelta;
    type Parameters = ChatBoardParametersV1;

    fn verify(
        &self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
    ) -> Result<(), String> {
        let mut ids = std::collections::HashSet::new();
        for route in &self.routes {
            if !ids.insert(route.route.message_id) {
                return Err("Duplicate message route".to_string());
            }
            verify_route(parent_state, parameters, route)?;
        }
        let routes = route_map(&self.routes);
        let mut flag_ids = std::collections::HashSet::new();
        for flag in &self.flags {
            if !flag_ids.insert(flag.flag.target) {
                return Err("Duplicate post flag".to_string());
            }
            verify_flag(parent_state, parameters, &routes, flag)?;
        }
        self.validate_actions(parent_state, parameters)
    }

    fn summarize(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
    ) -> Self::Summary {
        ModerationSummary {
            routes: route_map(&self.routes),
            flags: flag_map(&self.flags),
        }
    }

    fn delta(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
        old_state: &Self::Summary,
    ) -> Option<Self::Delta> {
        let routes: Vec<AuthorizedMessageRoute> = self
            .routes
            .iter()
            .filter(|route| {
                old_state
                    .routes
                    .get(&route.route.message_id)
                    .map(|old| old.generation < route.route.generation)
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        let flags: Vec<AuthorizedPostFlag> = self
            .flags
            .iter()
            .filter(|flag| {
                old_state
                    .flags
                    .get(&flag.flag.target)
                    .map(|old| old.generation < flag.flag.generation)
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        if routes.is_empty() && flags.is_empty() {
            None
        } else {
            Some(ModerationDelta { routes, flags })
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
        for route in &delta.routes {
            verify_route(parent_state, parameters, route)?;
            match self
                .routes
                .iter()
                .find(|existing| existing.route.message_id == route.route.message_id)
            {
                Some(existing) if existing.route.generation >= route.route.generation => {}
                _ => {
                    self.routes
                        .retain(|existing| existing.route.message_id != route.route.message_id);
                    self.routes.push(route.clone());
                }
            }
        }
        let routes = route_map(&self.routes);
        for flag in &delta.flags {
            verify_flag(parent_state, parameters, &routes, flag)?;
            match self
                .flags
                .iter()
                .find(|existing| existing.flag.target == flag.flag.target)
            {
                Some(existing) if existing.flag.generation >= flag.flag.generation => {}
                _ => {
                    self.flags
                        .retain(|existing| existing.flag.target != flag.flag.target);
                    self.flags.push(flag.clone());
                }
            }
        }
        Ok(())
    }
}
