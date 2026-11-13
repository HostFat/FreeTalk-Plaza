//! Public moderation routing, post flags and contract-side permission checks.
//!
//! Routing records carry only IDs: which category contains a message, which
//! message it replies to, and whether a category is a group and its parent.
//! Post flags carry pinned/closed with a generation. Both are signed by the
//! actor and verified by the contract.

use crate::board_state::content::CONTENT_TYPE_MODERATION_ACTION;
use crate::board_state::member::MemberId;
use crate::board_state::message::MessageId;
use crate::board_state::roles::{
    resolve_signer_key, verify_moderation_authority, AuthorityProof, ModerationPower,
};
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_key: Option<VerifyingKey>,
}

impl AuthorizedMessageRoute {
    pub fn new(route: MessageRoute, signing_key: &SigningKey) -> Self {
        Self {
            signature: sign_struct(&route, signing_key),
            route,
            signer: Some(MemberId::from(&signing_key.verifying_key())),
            signer_key: Some(signing_key.verifying_key()),
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

/// One moderation feature per record. Separate generations mean an author
/// closing a post cannot clear a moderator's pin or announcement.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum FeatureKind {
    Pinned,
    Closed,
    Announced,
    Merged,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct FeatureFlag {
    pub target: MessageId,
    pub kind: FeatureKind,
    pub value: bool,
    /// Destination topic when `kind = Merged` and `value = true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<MessageId>,
    pub generation: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub created_at: i64,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedFeatureFlag {
    pub flag: FeatureFlag,
    pub signature: Signature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<MemberId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_key: Option<VerifyingKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<Box<AuthorityProof>>,
}

impl AuthorizedFeatureFlag {
    pub fn new(flag: FeatureFlag, signing_key: &SigningKey) -> Self {
        Self {
            signature: sign_struct(&flag, signing_key),
            flag,
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

    pub fn verify_signature_with(&self, key: &VerifyingKey) -> Result<(), String> {
        verify_struct(&self.flag, &self.signature, key)
            .map_err(|e| format!("Invalid feature flag signature: {}", e))
    }
}

/// A moderator-signed change of a post's parent, used to move a topic to
/// another section, split a reply into a new topic, or move replies on merge.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct PostMove {
    pub target: MessageId,
    /// New parent: a category for a topic, a post for a reply. `None` moves a
    /// topic to the board root.
    pub new_parent: Option<MessageId>,
    pub generation: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub created_at: i64,
}

fn is_zero(value: &i64) -> bool {
    *value == 0
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedPostMove {
    pub change: PostMove,
    pub signature: Signature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<MemberId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_key: Option<VerifyingKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<Box<AuthorityProof>>,
}

impl AuthorizedPostMove {
    pub fn new(change: PostMove, signing_key: &SigningKey) -> Self {
        Self {
            signature: sign_struct(&change, signing_key),
            change,
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

    pub fn verify_signature_with(&self, key: &VerifyingKey) -> Result<(), String> {
        verify_struct(&self.change, &self.signature, key)
            .map_err(|e| format!("Invalid post move signature: {}", e))
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct ModerationV1 {
    pub routes: Vec<AuthorizedMessageRoute>,
    #[serde(default)]
    pub feature_flags: Vec<AuthorizedFeatureFlag>,
    #[serde(default)]
    pub moves: Vec<AuthorizedPostMove>,
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
pub struct FeatureFlagState {
    pub value: bool,
    pub destination: Option<MessageId>,
    pub generation: u64,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct MoveState {
    pub new_parent: Option<MessageId>,
    pub generation: u64,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct ModerationSummary {
    pub routes: BTreeMap<MessageId, RouteState>,
    pub feature_flags: BTreeMap<(MessageId, FeatureKind), FeatureFlagState>,
    pub moves: BTreeMap<MessageId, MoveState>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct ModerationDelta {
    #[serde(default)]
    pub routes: Vec<AuthorizedMessageRoute>,
    #[serde(default)]
    pub feature_flags: Vec<AuthorizedFeatureFlag>,
    #[serde(default)]
    pub moves: Vec<AuthorizedPostMove>,
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

fn feature_flag_map(
    flags: &[AuthorizedFeatureFlag],
) -> BTreeMap<(MessageId, FeatureKind), FeatureFlagState> {
    flags
        .iter()
        .map(|entry| {
            (
                (entry.flag.target, entry.flag.kind),
                FeatureFlagState {
                    value: entry.flag.value,
                    destination: entry.flag.destination,
                    generation: entry.flag.generation,
                },
            )
        })
        .collect()
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

pub(crate) fn is_owner_or_admin(
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
    let key = resolve_signer_key(state, parameters, &signer, route.signer_key.as_ref())?;
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

fn verify_feature_flag(
    state: &ChatBoardStateV1,
    parameters: &ChatBoardParametersV1,
    routes: &BTreeMap<MessageId, RouteState>,
    entry: &AuthorizedFeatureFlag,
) -> Result<(), String> {
    let signer = entry.signer_id(parameters);
    let key = resolve_signer_key(state, parameters, &signer, entry.signer_key.as_ref())?;
    entry.verify_signature_with(&key)?;
    let flag = &entry.flag;
    if flag.generation == 0 {
        return Err("Feature flag generation must be positive".to_string());
    }
    let Some(target) = state
        .recent_messages
        .messages
        .iter()
        .find(|message| message.id() == flag.target)
    else {
        return Err("Feature flag targets a missing message".to_string());
    };
    if target.message.content.is_category() {
        return Err("Feature flags apply to posts".to_string());
    }

    let chain = category_chain(routes, &flag.target);
    let proof = entry.authority.as_deref();
    match flag.kind {
        FeatureKind::Pinned => {
            verify_moderation_authority(
                state,
                parameters,
                &signer,
                ModerationPower::Pin,
                &chain,
                proof,
            )?;
            if flag.destination.is_some() {
                return Err("A pin has no destination".to_string());
            }
        }
        FeatureKind::Closed => {
            if target_author(state, &flag.target).as_ref() != Some(&signer) {
                verify_moderation_authority(
                    state,
                    parameters,
                    &signer,
                    ModerationPower::Close,
                    &chain,
                    proof,
                )?;
            }
            if flag.destination.is_some() {
                return Err("A close flag has no destination".to_string());
            }
        }
        FeatureKind::Announced => {
            crate::board_state::roles::verify_admin_authority(state, parameters, &signer, proof, 8)
                .map_err(|_| "Only the owner or an admin can announce a post".to_string())?;
            if flag.destination.is_some() {
                return Err("An announcement has no destination".to_string());
            }
        }
        FeatureKind::Merged => {
            if flag.value {
                let destination = flag
                    .destination
                    .ok_or("A merge needs a destination topic")?;
                if destination == flag.target {
                    return Err("A topic cannot be merged into itself".to_string());
                }
                let destination_message = state
                    .recent_messages
                    .messages
                    .iter()
                    .find(|message| message.id() == destination)
                    .ok_or("Merge destination is missing")?;
                if destination_message.message.content.is_category() {
                    return Err("Merge destination must be a topic".to_string());
                }
                let mut current = Some(destination);
                for _ in 0..64 {
                    let Some(id) = current else { break };
                    if id == flag.target {
                        return Err("Merge would create a cycle".to_string());
                    }
                    current = route_parent(routes, &id);
                }
                let destination_chain = category_chain(routes, &destination);
                verify_moderation_authority(
                    state,
                    parameters,
                    &signer,
                    ModerationPower::Move,
                    &chain,
                    proof,
                )
                .map_err(|_| "Signer cannot merge this post".to_string())?;
                verify_moderation_authority(
                    state,
                    parameters,
                    &signer,
                    ModerationPower::Move,
                    &destination_chain,
                    proof,
                )
                .map_err(|_| "Signer cannot merge this post".to_string())?;
            } else {
                if flag.destination.is_some() {
                    return Err("An unmerge has no destination".to_string());
                }
                verify_moderation_authority(
                    state,
                    parameters,
                    &signer,
                    ModerationPower::Move,
                    &chain,
                    proof,
                )
                .map_err(|_| "Signer cannot undo a merge".to_string())?;
            }
        }
    }
    Ok(())
}

fn move_map(moves: &[AuthorizedPostMove]) -> BTreeMap<MessageId, MoveState> {
    moves
        .iter()
        .map(|entry| {
            (
                entry.change.target,
                MoveState {
                    new_parent: entry.change.new_parent,
                    generation: entry.change.generation,
                },
            )
        })
        .collect()
}

fn route_parent(routes: &BTreeMap<MessageId, RouteState>, id: &MessageId) -> Option<MessageId> {
    routes.get(id).and_then(|route| {
        if route.is_category {
            route.parent_category_id
        } else {
            route.reply_to
        }
    })
}

fn verify_move(
    state: &ChatBoardStateV1,
    parameters: &ChatBoardParametersV1,
    routes: &BTreeMap<MessageId, RouteState>,
    entry: &AuthorizedPostMove,
) -> Result<(), String> {
    let signer = entry.signer_id(parameters);
    let key = resolve_signer_key(state, parameters, &signer, entry.signer_key.as_ref())?;
    entry.verify_signature_with(&key)?;
    let target = state
        .recent_messages
        .messages
        .iter()
        .find(|message| message.id() == entry.change.target)
        .ok_or("Post move targets a missing message")?;
    if target.message.content.is_category() {
        return Err("Categories are moved with their edit action".to_string());
    }
    match entry.change.new_parent {
        Some(parent_id) => {
            if parent_id == entry.change.target {
                return Err("A post cannot be moved under itself".to_string());
            }
            let parent = state
                .recent_messages
                .messages
                .iter()
                .find(|message| message.id() == parent_id)
                .ok_or("Post move parent is missing")?;
            if parent.message.content.is_action() {
                return Err("Post move parent is not a post or section".to_string());
            }
            let mut current = Some(parent_id);
            for _ in 0..64 {
                let Some(id) = current else {
                    break;
                };
                if id == entry.change.target {
                    return Err("Post move would create a cycle".to_string());
                }
                current = route_parent(routes, &id);
            }
            let from = category_chain(routes, &entry.change.target);
            let to = category_chain(routes, &parent_id);
            verify_moderation_authority(
                state,
                parameters,
                &signer,
                ModerationPower::Move,
                &from,
                entry.authority.as_deref(),
            )
            .map_err(|_| "Signer cannot move this post here".to_string())?;
            verify_moderation_authority(
                state,
                parameters,
                &signer,
                ModerationPower::Move,
                &to,
                entry.authority.as_deref(),
            )
            .map_err(|_| "Signer cannot move this post here".to_string())?;
        }
        None => {
            verify_moderation_authority(
                state,
                parameters,
                &signer,
                ModerationPower::Move,
                &[],
                entry.authority.as_deref(),
            )
            .map_err(|_| "Signer cannot move this post to the board root".to_string())?;
        }
    }
    Ok(())
}

impl ModerationV1 {
    pub fn moved_to(&self, target: &MessageId) -> Option<&Option<MessageId>> {
        self.moves
            .iter()
            .filter(|entry| entry.change.target == *target)
            .max_by_key(|entry| entry.change.generation)
            .map(|entry| &entry.change.new_parent)
    }

    pub fn is_merged_into(&self, target: &MessageId) -> Option<MessageId> {
        self.feature_flag_for(target, FeatureKind::Merged)
            .filter(|flag| flag.value)
            .and_then(|flag| flag.destination)
    }

    pub fn route(&self, message_id: &MessageId) -> Option<&MessageRoute> {
        self.routes
            .iter()
            .filter(|route| route.route.message_id == *message_id)
            .max_by_key(|route| route.route.generation)
            .map(|route| &route.route)
    }

    pub fn feature_flag_for(&self, target: &MessageId, kind: FeatureKind) -> Option<&FeatureFlag> {
        self.feature_flags
            .iter()
            .filter(|entry| entry.flag.target == *target && entry.flag.kind == kind)
            .max_by_key(|entry| entry.flag.generation)
            .map(|entry| &entry.flag)
    }

    pub fn is_pinned(&self, target: &MessageId) -> bool {
        self.feature_flag_for(target, FeatureKind::Pinned)
            .map(|flag| flag.value)
            .unwrap_or(false)
    }

    pub fn is_closed(&self, target: &MessageId) -> bool {
        self.feature_flag_for(target, FeatureKind::Closed)
            .map(|flag| flag.value)
            .unwrap_or(false)
    }

    pub fn is_announced(&self, target: &MessageId) -> bool {
        self.feature_flag_for(target, FeatureKind::Announced)
            .map(|flag| flag.value)
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
        let flags = feature_flag_map(&self.feature_flags);

        for message in &state.recent_messages.messages {
            let message_id = message.id();
            if let Some(route) = routes.get(&message_id) {
                if let Some(target) = route.reply_to {
                    if flags
                        .get(&(target, FeatureKind::Closed))
                        .map(|flag| flag.value)
                        .unwrap_or(false)
                    {
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
                .get(&(action.target, FeatureKind::Closed))
                .map(|flag| flag.value)
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

    /// Drop records whose message or signer is gone and keep one record per
    /// target. Deterministic, like the other state cleanups.
    pub fn cleanup(&mut self, state: &ChatBoardStateV1, parameters: &ChatBoardParametersV1) {
        use std::collections::HashSet;
        let live: HashSet<MessageId> = state
            .recent_messages
            .messages
            .iter()
            .map(|message| message.id())
            .collect();
        self.routes.retain(|entry| {
            live.contains(&entry.route.message_id) && verify_route(state, parameters, entry).is_ok()
        });
        self.routes.sort_by_key(|entry| {
            (
                entry.route.message_id.0 .0,
                entry.route.generation,
                entry.signer_id(parameters).0 .0,
            )
        });
        self.routes.dedup_by_key(|entry| entry.route.message_id);
        self.routes.sort_by_key(|entry| entry.route.message_id.0 .0);

        let routes = route_map(&self.routes);
        self.feature_flags.retain(|entry| {
            live.contains(&entry.flag.target)
                && verify_feature_flag(state, parameters, &routes, entry).is_ok()
        });
        self.feature_flags.sort_by_key(|entry| {
            (
                entry.flag.target.0 .0,
                entry.flag.kind,
                entry.flag.generation,
                entry.signer_id(parameters).0 .0,
            )
        });
        self.feature_flags
            .dedup_by_key(|entry| (entry.flag.target, entry.flag.kind));
        self.feature_flags
            .sort_by_key(|entry| (entry.flag.target.0 .0, entry.flag.kind));

        self.moves.retain(|entry| {
            live.contains(&entry.change.target)
                && verify_move(state, parameters, &routes, entry).is_ok()
        });
        self.moves.sort_by_key(|entry| {
            (
                entry.change.target.0 .0,
                entry.change.generation,
                entry.signer_id(parameters).0 .0,
            )
        });
        self.moves.dedup_by_key(|entry| entry.change.target);
        self.moves.sort_by_key(|entry| entry.change.target.0 .0);
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
        for flag in &self.feature_flags {
            if !flag_ids.insert((flag.flag.target, flag.flag.kind)) {
                return Err("Duplicate feature flag".to_string());
            }
            verify_feature_flag(parent_state, parameters, &routes, flag)?;
        }
        let mut move_ids = std::collections::HashSet::new();
        for entry in &self.moves {
            if !move_ids.insert(entry.change.target) {
                return Err("Duplicate post move".to_string());
            }
            verify_move(parent_state, parameters, &routes, entry)?;
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
            feature_flags: feature_flag_map(&self.feature_flags),
            moves: move_map(&self.moves),
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
        let flags: Vec<AuthorizedFeatureFlag> = self
            .feature_flags
            .iter()
            .filter(|entry| {
                old_state
                    .feature_flags
                    .get(&(entry.flag.target, entry.flag.kind))
                    .map(|old| {
                        old.generation < entry.flag.generation
                            || (old.generation == entry.flag.generation
                                && (old.value != entry.flag.value
                                    || old.destination != entry.flag.destination))
                    })
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        let moves: Vec<AuthorizedPostMove> = self
            .moves
            .iter()
            .filter(|entry| {
                old_state
                    .moves
                    .get(&entry.change.target)
                    .map(|old| old.generation < entry.change.generation)
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        if routes.is_empty() && flags.is_empty() && moves.is_empty() {
            None
        } else {
            Some(ModerationDelta {
                routes,
                feature_flags: flags,
                moves,
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
        for flag in &delta.feature_flags {
            verify_feature_flag(parent_state, parameters, &routes, flag)?;
            match self.feature_flags.iter().find(|existing| {
                existing.flag.target == flag.flag.target && existing.flag.kind == flag.flag.kind
            }) {
                Some(existing) if existing.flag.generation > flag.flag.generation => {}
                Some(existing)
                    if existing.flag.generation == flag.flag.generation
                        && existing.signature.to_bytes().as_slice()
                            <= flag.signature.to_bytes().as_slice() => {}
                _ => {
                    self.feature_flags.retain(|existing| {
                        !(existing.flag.target == flag.flag.target
                            && existing.flag.kind == flag.flag.kind)
                    });
                    self.feature_flags.push(flag.clone());
                }
            }
        }
        for entry in &delta.moves {
            verify_move(parent_state, parameters, &routes, entry)?;
            match self
                .moves
                .iter()
                .find(|existing| existing.change.target == entry.change.target)
            {
                Some(existing) if existing.change.generation >= entry.change.generation => {}
                _ => {
                    self.moves
                        .retain(|existing| existing.change.target != entry.change.target);
                    self.moves.push(entry.clone());
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
    use crate::board_state::member::{AuthorizedMember, Member, MembersV1};
    use crate::board_state::message::{
        AuthorizedMessageV1, BoardMessageBody, MessageV1, MessagesV1,
    };
    use crate::board_state::secret::BoardSecretsV1;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use std::time::SystemTime;

    struct Board {
        state: ChatBoardStateV1,
        parameters: ChatBoardParametersV1,
        owner_sk: SigningKey,
        member_sk: SigningKey,
        post: MessageId,
    }

    fn board() -> Board {
        let owner_sk = SigningKey::generate(&mut OsRng);
        let owner_vk = owner_sk.verifying_key();
        let owner_id = MemberId::from(&owner_vk);
        let parameters = ChatBoardParametersV1 { owner: owner_vk };
        let member_sk = SigningKey::generate(&mut OsRng);
        let member_vk = member_sk.verifying_key();
        let member_id = MemberId::from(&member_vk);

        let member = AuthorizedMember::new(
            Member {
                owner_member_id: owner_id,
                invited_by: owner_id,
                member_vk,
                join_proof: None,
            },
            &owner_sk,
        );
        let post = AuthorizedMessageV1::new(
            MessageV1 {
                board_owner: owner_id,
                author: member_id,
                time: SystemTime::now(),
                content: BoardMessageBody::public("Post".into(), "Body".into()),
            },
            &member_sk,
        );
        let post_id = post.id();

        let state = ChatBoardStateV1 {
            configuration: AuthorizedConfigurationV1::new(Configuration::default(), &owner_sk),
            members: MembersV1 {
                members: vec![member],
            },
            secrets: BoardSecretsV1::default(),
            recent_messages: MessagesV1 {
                messages: vec![post],
                ..Default::default()
            },
            ..Default::default()
        };

        Board {
            state,
            parameters,
            owner_sk,
            member_sk,
            post: post_id,
        }
    }

    #[test]
    fn member_routes_and_author_flags_use_the_member_key() {
        let mut board = board();
        let route = AuthorizedMessageRoute::new(
            MessageRoute {
                message_id: board.post,
                reply_to: None,
                category_id: None,
                is_category: false,
                parent_category_id: None,
                is_group: false,
                generation: 1,
            },
            &board.member_sk,
        );
        board.state.moderation.routes.push(route);
        board
            .state
            .moderation
            .verify(&board.state, &board.parameters)
            .expect("a member route is signed with the member key");

        let flag = AuthorizedFeatureFlag::new(
            FeatureFlag {
                target: board.post,
                kind: FeatureKind::Closed,
                value: true,
                destination: None,
                generation: 1,
                created_at: 1,
            },
            &board.member_sk,
        );
        board.state.moderation.feature_flags.push(flag);
        board
            .state
            .moderation
            .verify(&board.state, &board.parameters)
            .expect("the author can close their own post");
    }

    #[test]
    fn only_moderators_move_posts() {
        let mut board = board();
        let by_member = AuthorizedPostMove::new(
            PostMove {
                target: board.post,
                new_parent: None,
                generation: 1,
                created_at: 1,
            },
            &board.member_sk,
        );
        board.state.moderation.moves.push(by_member);
        assert!(board
            .state
            .moderation
            .verify(&board.state, &board.parameters)
            .is_err());

        board.state.moderation.moves.clear();
        let owner_move = AuthorizedPostMove::new(
            PostMove {
                target: board.post,
                new_parent: None,
                generation: 1,
                created_at: 1,
            },
            &board.owner_sk,
        );
        board.state.moderation.moves.push(owner_move);
        assert!(board
            .state
            .moderation
            .verify(&board.state, &board.parameters)
            .is_ok());
    }

    #[test]
    fn feature_flags_are_independent() {
        let mut board = board();
        let pinned = AuthorizedFeatureFlag::new(
            FeatureFlag {
                target: board.post,
                kind: FeatureKind::Pinned,
                value: true,
                destination: None,
                generation: 1,
                created_at: 1,
            },
            &board.owner_sk,
        );
        let closed = AuthorizedFeatureFlag::new(
            FeatureFlag {
                target: board.post,
                kind: FeatureKind::Closed,
                value: true,
                destination: None,
                generation: 1,
                created_at: 2,
            },
            &board.member_sk,
        );
        board.state.moderation.feature_flags.push(pinned);
        board.state.moderation.feature_flags.push(closed);
        board
            .state
            .moderation
            .verify(&board.state, &board.parameters)
            .expect("independent pin and close flags verify");
        assert!(board.state.moderation.is_pinned(&board.post));
        assert!(board.state.moderation.is_closed(&board.post));
    }

    #[test]
    fn scoped_pin_verifies_after_the_role_is_revoked() {
        use crate::board_state::roles::{
            moderation_authority_proof, AuthorizedRole, AuthorizedRoleAssignment, Role,
            RoleAssignment,
        };

        let mut board = board();
        let owner_id = MemberId::from(&board.owner_sk.verifying_key());
        let member_id = MemberId::from(&board.member_sk.verifying_key());
        let role_id = [3u8; 16];

        board.state.roles.roles.push(AuthorizedRole::new(
            Role {
                id: role_id,
                name: "pinner".to_string(),
                generation: 1,
                can_manage_access: false,
                can_distribute_keys: false,
                can_edit_posts: false,
                can_delete_posts: false,
                can_close_posts: false,
                can_pin_posts: true,
                can_move_posts: false,
                scope: Vec::new(),
                deleted: false,
            },
            &board.owner_sk,
        ));
        board
            .state
            .roles
            .assignments
            .push(AuthorizedRoleAssignment::new(
                RoleAssignment {
                    role_id,
                    member_id,
                    generation: 1,
                    revoked: false,
                },
                &board.owner_sk,
            ));

        let proof = moderation_authority_proof(&board.state, &member_id, ModerationPower::Pin, &[])
            .expect("the role grants pinning");
        board.state.moderation.feature_flags.push(
            AuthorizedFeatureFlag::new(
                FeatureFlag {
                    target: board.post,
                    kind: FeatureKind::Pinned,
                    value: true,
                    destination: None,
                    generation: 1,
                    created_at: 1,
                },
                &board.member_sk,
            )
            .with_optional_authority(Some(proof)),
        );
        board
            .state
            .verify(&board.state, &board.parameters)
            .expect("a scoped moderator may pin");

        // Revoke the role and prune the member; the proof keeps the pin valid.
        board
            .state
            .roles
            .assignments
            .retain(|a| a.assignment.member_id != member_id);
        board
            .state
            .roles
            .assignments
            .push(AuthorizedRoleAssignment::new(
                RoleAssignment {
                    role_id,
                    member_id,
                    generation: 2,
                    revoked: true,
                },
                &board.owner_sk,
            ));
        let _ = owner_id;
        board
            .state
            .verify(&board.state, &board.parameters)
            .expect("historical moderation authority keeps the pin verifiable");
    }

    #[test]
    fn members_cannot_announce_posts() {
        let mut board = board();
        let flag = AuthorizedFeatureFlag::new(
            FeatureFlag {
                target: board.post,
                kind: FeatureKind::Announced,
                value: true,
                destination: None,
                generation: 1,
                created_at: 1,
            },
            &board.member_sk,
        );
        board.state.moderation.feature_flags.push(flag);
        assert!(board
            .state
            .moderation
            .verify(&board.state, &board.parameters)
            .is_err());
    }
}
