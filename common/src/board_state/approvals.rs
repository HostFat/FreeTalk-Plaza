//! Approvals for posts written by untrusted (new) members.
//!
//! An approval is a signed record for one message. The contract verifies the
//! signer and the target; clients hide unapproved posts from members who have
//! no approved post yet.

use crate::board_state::member::MemberId;
use crate::board_state::message::MessageId;
use crate::board_state::moderation::{category_chain, is_owner_or_admin};
use crate::board_state::roles::{signer_key, ModerationPower};
use crate::board_state::ChatBoardParametersV1;
use crate::util::{sign_struct, verify_struct};
use crate::ChatBoardStateV1;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use freenet_scaffold::ComposableState;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct ApprovalV1 {
    pub target: MessageId,
    pub approved: bool,
    pub generation: u64,
    /// Section the approval applies to. Trust from an approved post covers only
    /// this section and its subsections, so a scoped moderator cannot vouch for
    /// an author board-wide. `None` means the board root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<MessageId>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedApproval {
    pub approval: ApprovalV1,
    pub signature: Signature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<MemberId>,
}

impl AuthorizedApproval {
    pub fn new(approval: ApprovalV1, signing_key: &SigningKey) -> Self {
        Self {
            signature: sign_struct(&approval, signing_key),
            approval,
            signer: Some(MemberId::from(&signing_key.verifying_key())),
        }
    }

    pub fn signer_id(&self, parameters: &ChatBoardParametersV1) -> MemberId {
        self.signer.unwrap_or_else(|| parameters.owner_id())
    }

    pub fn verify_signature_with(&self, key: &VerifyingKey) -> Result<(), String> {
        verify_struct(&self.approval, &self.signature, key)
            .map_err(|e| format!("Invalid approval signature: {}", e))
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct ApprovalsV1 {
    pub approvals: Vec<AuthorizedApproval>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct ApprovalState {
    pub approved: bool,
    pub generation: u64,
    #[serde(default)]
    pub digest: i64,
}

fn record_digest<T: serde::Serialize>(value: &T) -> i64 {
    let mut bytes = Vec::new();
    let _ = ciborium::ser::into_writer(value, &mut bytes);
    freenet_scaffold::util::fast_hash(&bytes).0
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct ApprovalsSummary {
    pub approvals: BTreeMap<MessageId, ApprovalState>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct ApprovalsDelta {
    #[serde(default)]
    pub approvals: Vec<AuthorizedApproval>,
}

fn approval_map(approvals: &[AuthorizedApproval]) -> BTreeMap<MessageId, ApprovalState> {
    approvals
        .iter()
        .map(|entry| {
            (
                entry.approval.target,
                ApprovalState {
                    approved: entry.approval.approved,
                    generation: entry.approval.generation,
                    digest: record_digest(&entry.approval),
                },
            )
        })
        .collect()
}

fn can_approve(
    state: &ChatBoardStateV1,
    parameters: &ChatBoardParametersV1,
    signer: &MemberId,
    target: &MessageId,
) -> bool {
    if is_owner_or_admin(state, parameters, signer) {
        return true;
    }
    let routes = state.moderation.routes_map();
    let chain = category_chain(&routes, target);
    state
        .roles
        .has_moderation_power(signer, ModerationPower::Delete, &chain)
}

/// Section a message belongs to: its nearest category, or `None` at the root.
pub fn message_scope(state: &ChatBoardStateV1, target: &MessageId) -> Option<MessageId> {
    category_chain(&state.moderation.routes_map(), target)
        .first()
        .copied()
}

fn verify_approval(
    state: &ChatBoardStateV1,
    parameters: &ChatBoardParametersV1,
    approval: &AuthorizedApproval,
) -> Result<(), String> {
    let signer = approval.signer_id(parameters);
    let key = signer_key(state, parameters, &signer)?;
    approval.verify_signature_with(&key)?;
    if !state
        .recent_messages
        .messages
        .iter()
        .any(|message| message.id() == approval.approval.target)
    {
        return Err("Approval targets a missing message".to_string());
    }
    let expected = message_scope(state, &approval.approval.target);
    if approval.approval.scope.is_some() && approval.approval.scope != expected {
        return Err("Approval scope is not the target's section".to_string());
    }
    if !can_approve(state, parameters, &signer, &approval.approval.target) {
        return Err("Signer cannot approve this post".to_string());
    }
    Ok(())
}

impl ApprovalsV1 {
    /// True when the message has an approval with `approved = true`.
    pub fn is_approved(&self, target: &MessageId) -> bool {
        self.approvals
            .iter()
            .filter(|entry| entry.approval.target == *target)
            .max_by_key(|entry| entry.approval.generation)
            .map(|entry| entry.approval.approved)
            .unwrap_or(false)
    }

    /// True when the author already has an approved post in the target's
    /// section or one of its ancestors. Confidence gained in one section does
    /// not cover another.
    pub fn author_is_trusted(
        &self,
        state: &ChatBoardStateV1,
        author: &MemberId,
        target: &MessageId,
    ) -> bool {
        let routes = state.moderation.routes_map();
        let target_chain = category_chain(&routes, target);
        self.approvals.iter().any(|entry| {
            if !entry.approval.approved {
                return false;
            }
            let approved_author = state
                .recent_messages
                .messages
                .iter()
                .find(|message| message.id() == entry.approval.target)
                .map(|message| message.message.author);
            if approved_author != Some(*author) {
                return false;
            }
            match entry.approval.scope {
                None => target_chain.is_empty(),
                Some(scope) => target_chain.contains(&scope),
            }
        })
    }

    /// Drop records whose target or signer is gone, and keep one record per
    /// target. Deterministic, so peers that merged in different orders converge.
    pub fn cleanup(&mut self, state: &ChatBoardStateV1, parameters: &ChatBoardParametersV1) {
        let live: HashSet<MessageId> = state
            .recent_messages
            .messages
            .iter()
            .map(|message| message.id())
            .collect();
        self.approvals.retain(|entry| {
            let signer = entry.signer_id(parameters);
            live.contains(&entry.approval.target)
                && signer_key(state, parameters, &signer).is_ok()
                && can_approve(state, parameters, &signer, &entry.approval.target)
        });
        self.approvals.sort_by_key(|entry| {
            (
                entry.approval.target.0 .0,
                entry.approval.generation,
                entry.signer_id(parameters).0 .0,
            )
        });
        self.approvals.dedup_by_key(|entry| entry.approval.target);
        self.approvals
            .sort_by_key(|entry| entry.approval.target.0 .0);
    }
}

impl ComposableState for ApprovalsV1 {
    type ParentState = ChatBoardStateV1;
    type Summary = ApprovalsSummary;
    type Delta = ApprovalsDelta;
    type Parameters = ChatBoardParametersV1;

    fn verify(
        &self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
    ) -> Result<(), String> {
        let mut targets = HashSet::new();
        for entry in &self.approvals {
            if !targets.insert(entry.approval.target) {
                return Err("Duplicate approval for one message".to_string());
            }
            verify_approval(parent_state, parameters, entry)?;
        }
        Ok(())
    }

    fn summarize(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
    ) -> Self::Summary {
        ApprovalsSummary {
            approvals: approval_map(&self.approvals),
        }
    }

    fn delta(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
        old_state: &Self::Summary,
    ) -> Option<Self::Delta> {
        let approvals: Vec<AuthorizedApproval> = self
            .approvals
            .iter()
            .filter(|entry| {
                old_state
                    .approvals
                    .get(&entry.approval.target)
                    .map(|old| {
                        old.generation < entry.approval.generation
                            || (old.generation == entry.approval.generation
                                && old.digest != record_digest(&entry.approval))
                    })
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        if approvals.is_empty() {
            None
        } else {
            Some(ApprovalsDelta { approvals })
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
        for entry in &delta.approvals {
            verify_approval(parent_state, parameters, entry)?;
            match self
                .approvals
                .iter()
                .find(|existing| existing.approval.target == entry.approval.target)
            {
                Some(existing)
                    if existing.approval.generation > entry.approval.generation
                        || (existing.approval.generation == entry.approval.generation
                            && (existing.approval.approved == false
                                || record_digest(&existing.approval)
                                    <= record_digest(&entry.approval))) => {}
                _ => {
                    self.approvals
                        .retain(|existing| existing.approval.target != entry.approval.target);
                    self.approvals.push(entry.clone());
                }
            }
        }
        Ok(())
    }
}

/// Whether this post waits for a moderator before other members can see it.
///
/// The author, the owner, admins and scoped moderators always see it. Any
/// author with an already approved post is trusted.
pub fn is_pending(state: &ChatBoardStateV1, owner: MemberId, target: &MessageId) -> bool {
    if !state.configuration.configuration.approval_required {
        return false;
    }
    let Some(message) = state
        .recent_messages
        .messages
        .iter()
        .find(|message| message.id() == *target)
    else {
        return false;
    };
    let author = message.message.author;
    if author == owner
        || state
            .admin
            .admins
            .iter()
            .any(|admin| admin.admin.id() == author)
    {
        return false;
    }
    let routes = state.moderation.routes_map();
    let chain = category_chain(&routes, target);
    if state
        .roles
        .has_moderation_power(&author, ModerationPower::Delete, &chain)
    {
        return false;
    }
    !state.approvals.is_approved(target)
        && !state.approvals.author_is_trusted(state, &author, target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board_state::configuration::{AuthorizedConfigurationV1, Configuration};
    use crate::board_state::member::{AuthorizedMember, Member, MembersV1};
    use crate::board_state::member_info::MemberInfoV1;
    use crate::board_state::message::{
        AuthorizedMessageV1, BoardMessageBody, MessageV1, MessagesV1,
    };
    use crate::board_state::moderation::{AuthorizedMessageRoute, MessageRoute};
    use crate::board_state::secret::BoardSecretsV1;
    use crate::ChatBoardStateV1;
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

        let mut config = Configuration::default();
        config.approval_required = true;
        let state = ChatBoardStateV1 {
            configuration: AuthorizedConfigurationV1::new(config, &owner_sk),
            members: MembersV1 {
                members: vec![member],
            },
            member_info: MemberInfoV1::default(),
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

    fn approval(board: &Board, approved: bool, generation: u64) -> ApprovalV1 {
        ApprovalV1 {
            target: board.post,
            approved,
            generation,
            scope: None,
        }
    }

    #[test]
    fn only_moderators_can_approve_and_approval_trusts_the_author() {
        let mut board = board();
        let member_id = MemberId::from(&board.member_sk.verifying_key());
        let owner_id = MemberId::from(&board.owner_sk.verifying_key());

        assert!(is_pending(&board.state, owner_id, &board.post));

        let by_member = AuthorizedApproval::new(approval(&board, true, 1), &board.member_sk);
        board.state.approvals.approvals.push(by_member);
        assert!(board
            .state
            .approvals
            .verify(&board.state, &board.parameters)
            .is_err());
        board.state.approvals.approvals.clear();

        let by_owner = AuthorizedApproval::new(approval(&board, true, 1), &board.owner_sk);
        board.state.approvals.approvals.push(by_owner);
        board
            .state
            .approvals
            .verify(&board.state, &board.parameters)
            .expect("the owner can approve a post");
        assert!(!is_pending(&board.state, owner_id, &board.post));
        assert!(board
            .state
            .approvals
            .author_is_trusted(&board.state, &member_id, &board.post));

        // A new post by a trusted author is not pending even without its own
        // approval record.
        let second = AuthorizedMessageV1::new(
            MessageV1 {
                board_owner: owner_id,
                author: member_id,
                time: SystemTime::now(),
                content: BoardMessageBody::public("Second".into(), "Body".into()),
            },
            &board.member_sk,
        );
        let second_id = second.id();
        board.state.recent_messages.messages.push(second);
        assert!(!is_pending(&board.state, owner_id, &second_id));
    }

    #[test]
    fn pending_is_false_without_the_setting() {
        let mut board = board();
        let owner_id = MemberId::from(&board.owner_sk.verifying_key());
        let mut config = board.state.configuration.configuration.clone();
        config.approval_required = false;
        config.configuration_version += 1;
        board.state.configuration = AuthorizedConfigurationV1::new(config, &board.owner_sk);
        assert!(!is_pending(&board.state, owner_id, &board.post));
    }

    fn add_category(
        board: &mut Board,
        owner_id: MemberId,
        name: &str,
        parent: Option<MessageId>,
    ) -> MessageId {
        let message = AuthorizedMessageV1::new(
            MessageV1 {
                board_owner: owner_id,
                author: owner_id,
                time: SystemTime::now(),
                content: BoardMessageBody::category(
                    name.to_string(),
                    None,
                    None,
                    "#ef4444".to_string(),
                    parent,
                ),
            },
            &board.owner_sk,
        );
        let id = message.id();
        board.state.recent_messages.messages.push(message);
        board
            .state
            .moderation
            .routes
            .push(AuthorizedMessageRoute::new(
                MessageRoute {
                    message_id: id,
                    reply_to: None,
                    category_id: Some(id),
                    is_category: true,
                    parent_category_id: parent,
                    is_group: false,
                    generation: 1,
                },
                &board.owner_sk,
            ));
        id
    }

    fn add_post_in(board: &mut Board, title: &str, category: Option<MessageId>) -> MessageId {
        let owner_id = MemberId::from(&board.owner_sk.verifying_key());
        let author = MemberId::from(&board.member_sk.verifying_key());
        let message = AuthorizedMessageV1::new(
            MessageV1 {
                board_owner: owner_id,
                author,
                time: SystemTime::now(),
                content: BoardMessageBody::public(title.to_string(), "Body".into()),
            },
            &board.member_sk,
        );
        let id = message.id();
        board.state.recent_messages.messages.push(message);
        board
            .state
            .moderation
            .routes
            .push(AuthorizedMessageRoute::new(
                MessageRoute {
                    message_id: id,
                    reply_to: None,
                    category_id: category,
                    is_category: false,
                    parent_category_id: None,
                    is_group: false,
                    generation: 1,
                },
                &board.member_sk,
            ));
        id
    }

    #[test]
    fn approval_trust_covers_only_its_section_and_subsections() {
        let mut board = board();
        let owner_id = MemberId::from(&board.owner_sk.verifying_key());
        let member_id = MemberId::from(&board.member_sk.verifying_key());

        let cat_a = add_category(&mut board, owner_id, "A", None);
        let cat_b = add_category(&mut board, owner_id, "B", None);
        let child_a = add_category(&mut board, owner_id, "A child", Some(cat_a));
        let post_a = add_post_in(&mut board, "In A", Some(cat_a));
        let post_child = add_post_in(&mut board, "In A child", Some(child_a));
        let post_b = add_post_in(&mut board, "In B", Some(cat_b));

        board
            .state
            .approvals
            .approvals
            .push(AuthorizedApproval::new(
                ApprovalV1 {
                    target: post_a,
                    approved: true,
                    generation: 1,
                    scope: Some(cat_a),
                },
                &board.owner_sk,
            ));
        board
            .state
            .approvals
            .verify(&board.state, &board.parameters)
            .expect("the owner may approve a scoped post");

        assert!(board
            .state
            .approvals
            .author_is_trusted(&board.state, &member_id, &post_child));
        assert!(!is_pending(&board.state, owner_id, &post_child));
        assert!(!is_pending(&board.state, owner_id, &post_a));
        assert!(!board
            .state
            .approvals
            .author_is_trusted(&board.state, &member_id, &post_b));
        assert!(is_pending(&board.state, owner_id, &post_b));
    }

    #[test]
    fn cleanup_drops_approvals_for_missing_posts() {
        let mut board = board();
        let by_owner = AuthorizedApproval::new(approval(&board, true, 1), &board.owner_sk);
        board.state.approvals.approvals.push(by_owner);
        board.state.recent_messages.messages.clear();
        let mut approvals = std::mem::take(&mut board.state.approvals);
        approvals.cleanup(&board.state, &board.parameters);
        assert!(approvals.approvals.is_empty());
    }
}
