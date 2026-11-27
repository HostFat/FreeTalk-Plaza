//! Verification and deterministic CRDT merge helpers for `plaza-topic`.

use crate::types::*;
use crate::{
    value_hash, AuthorizedAuthorityRootV1, MemberStatusProofV1, AUTHORITY_ROOT_VERSION,
    MAX_JOIN_DEPTH, MAX_POSTS, MAX_POST_BYTES,
};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use freenet_scaffold::ComposableState;
use plaza_core::board_state::admin::{AdminsV1, AuthorizedAdmin};
use plaza_core::board_state::ban::{BanRevocationsV1, BansV1};
use plaza_core::board_state::configuration::{AuthorizedConfigurationV1, Configuration};
use plaza_core::board_state::content::PollContentV1;
use plaza_core::board_state::images::ImageRef;
use plaza_core::board_state::invites::{join_message, AuthorizedInviteToken, JoinProof};
use plaza_core::board_state::member::{AuthorizedMember, MemberId, MembersV1};
use plaza_core::board_state::member_moderation::{AuthorizedSuspension, SuspensionsV1};
use plaza_core::board_state::message::MessageId;
use plaza_core::board_state::ownership::OwnershipV1;
use plaza_core::board_state::privacy::SealedBytes;
use plaza_core::board_state::rate_limit::{system_time_from_ms, system_time_ms};
use plaza_core::board_state::roles::{
    resolve_signer_key, verify_moderation_authority, AuthorityProof, AuthorizedRole,
    AuthorizedRoleAssignment, ModerationPower, RoleId, RolesV1,
};
use plaza_core::board_state::ChatBoardParametersV1;
use plaza_core::util::{sign_struct, verify_struct};
use plaza_core::ChatBoardStateV1;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::time::SystemTime;

pub(crate) fn build_board_view(
    authority: &TopicAuthorityV1,
    participants: &[AuthorizedParticipantV1],
    params: &TopicParamsV1,
) -> ChatBoardStateV1 {
    let mut configuration = Configuration::default();
    configuration.max_admins = 1_000_000;
    configuration.max_user_bans = 1_000_000;
    configuration.max_message_size = MAX_POST_BYTES;
    configuration.owner_member_id = params.owner_id();
    let dummy = SigningKey::from_bytes(&[0u8; 32]);
    let mut view = ChatBoardStateV1 {
        configuration: AuthorizedConfigurationV1::new(configuration, &dummy),
        ownership: authority.ownership.clone(),
        admin: authority.admins.clone(),
        roles: authority.roles.clone(),
        bans: authority.bans.clone(),
        ban_revocations: authority.ban_revocations.clone(),
        suspensions: authority.suspensions.clone(),
        ..Default::default()
    };
    let mut members: Vec<AuthorizedMember> = participants
        .iter()
        .map(|p| p.record.certificate.member.clone())
        .collect();
    for proof in &authority.member_proofs {
        view.roles.roles.extend(proof.status.roles.iter().cloned());
        view.roles
            .assignments
            .extend(proof.status.assignments.iter().cloned());
        view.bans.0.extend(proof.status.bans.iter().cloned());
        view.ban_revocations
            .revocations
            .extend(proof.status.revocations.iter().cloned());
        view.suspensions
            .suspensions
            .extend(proof.status.suspensions.iter().cloned());
        members.push(proof.status.member.clone());
    }
    let mut seen_members = HashSet::new();
    members.retain(|member| seen_members.insert(member.member.id()));
    view.members = MembersV1 { members };
    let mut seen_roles = HashSet::new();
    view.roles.roles.retain(|role| seen_roles.insert(role.role.id));
    let mut seen_assignments = HashSet::new();
    view.roles.assignments.retain(|assignment| {
        seen_assignments.insert((
            assignment.assignment.role_id,
            assignment.assignment.member_id,
            assignment.assignment.generation,
        ))
    });
    let mut seen_bans = HashSet::new();
    view.bans.0.retain(|ban| seen_bans.insert(ban.id()));
    let mut seen_revocations = HashSet::new();
    view.ban_revocations
        .revocations
        .retain(|revocation| seen_revocations.insert(revocation.revocation.ban_id.clone()));
    let mut seen_suspensions = HashSet::new();
    view.suspensions.suspensions.retain(|suspension| {
        seen_suspensions.insert((
            suspension.suspension.target,
            suspension.suspension.generation,
        ))
    });
    view
}

pub(crate) fn verify_participants_list(
    authority: &TopicAuthorityV1,
    participants: &[AuthorizedParticipantV1],
    params: &TopicParamsV1,
    board_params: &ChatBoardParametersV1,
) -> Result<(), String> {
    let mut ids = HashSet::new();
    let mut keys = HashSet::new();
    let mut cached_view: Option<ChatBoardStateV1> = None;
    for participant in participants {
        let record = &participant.record;
        if record.member_id != MemberId::from(&record.member_vk) {
            return Err("participant id does not match its key".to_string());
        }
        if record.certificate.member.member.id() != record.member_id {
            return Err("participant certificate is for another member".to_string());
        }
        if record.certificate.member.member.member_vk != record.member_vk {
            return Err("participant key does not match its certificate".to_string());
        }
        verify_struct(&record, &participant.signature, &record.member_vk)
            .map_err(|error| format!("invalid participant signature: {error}"))?;
        if !ids.insert(record.member_id) || !keys.insert(record.member_vk) {
            return Err("duplicate participant".to_string());
        }
        verify_participant_certificate(
            authority,
            participants,
            &mut cached_view,
            &record.certificate,
            record.joined_at,
            params,
            board_params,
        )?;
    }
    Ok(())
}

pub(crate) fn verify_participant_certificate(
    authority: &TopicAuthorityV1,
    participants: &[AuthorizedParticipantV1],
    cached_view: &mut Option<ChatBoardStateV1>,
    certificate: &ParticipantCertificateV1,
    joined_at: i64,
    params: &TopicParamsV1,
    board_params: &ChatBoardParametersV1,
) -> Result<(), String> {
    let owner_id = params.owner_id();
    let owner_key = authority
        .ownership
        .owner_key_at(board_params, system_time_from_ms(joined_at));
    let member = &certificate.member.member;
    if member.owner_member_id != owner_id {
        return Err("the member record belongs to another board".to_string());
    }

    if certificate.token.is_some() || certificate.join_proof.is_some() {
        let token = certificate
            .token
            .as_ref()
            .ok_or("a token join needs its token record")?;
        let proof = certificate
            .join_proof
            .as_ref()
            .ok_or("a token join needs its join proof")?;
        if member.invited_by != member.id() {
            return Err("a token-joined member must be self-signed".to_string());
        }
        certificate
            .member
            .verify_signature(&member.member_vk)
            .map_err(|error| format!("invalid token-joined member signature: {error}"))?;
        if token.token.deleted {
            return Err("the invite token is deleted".to_string());
        }
        if token.token.id != proof.token_id {
            return Err("the join proof names another token".to_string());
        }
        if let Some(not_after) = token.token.not_after {
            if system_time_ms(not_after) < joined_at {
                return Err("the invite token had expired".to_string());
            }
        }
        authority
            .roles
            .role(&token.token.role_id)
            .ok_or("the invite token grants a role that no longer exists")?;
        proof
            .verify(
                &token.token.verifying_key,
                &join_message(&params.board_owner, &member.member_vk),
            )
            .map_err(|error| format!("invalid join proof: {error}"))?;

        let signer = token.signer.unwrap_or(owner_id);
        let manager_at = system_time_from_ms(
            token
                .token
                .created_at
                .map(system_time_ms)
                .unwrap_or(joined_at),
        );
        let view = cached_view.get_or_insert_with(|| build_board_view(authority, participants, params));
        if signer == owner_id {
            let token_owner_key = authority.ownership.owner_key_at(board_params, manager_at);
            token
                .verify_signature(&token_owner_key)
                .map_err(|error| format!("invalid invite token signature: {error}"))?;
        } else {
            let key = resolve_signer_key(view, board_params, &signer, token.signer_key.as_ref())?;
            verify_struct(&token.token, &token.signature, &key)
                .map_err(|error| format!("invalid invite token signature: {error}"))?;
        }
        verify_token_manager_for(authority, view, &signer, token, board_params, manager_at)?;
        return Ok(());
    }

    // Invite chain up to the owner.
    let mut current = &certificate.member;
    let mut seen = HashSet::new();
    let current_owner = authority
        .ownership
        .owner_at(board_params, system_time_from_ms(joined_at));
    for _ in 0..MAX_JOIN_DEPTH {
        let current_member = &current.member;
        let inviter = current_member.invited_by;
        if inviter == owner_id {
            current
                .verify_signature(&params.board_owner)
                .map_err(|error| format!("invalid invite chain signature: {error}"))?;
            return Ok(());
        }
        if inviter == current_owner {
            current
                .verify_signature(&owner_key)
                .map_err(|error| format!("invalid invite chain signature: {error}"))?;
            return Ok(());
        }
        if !seen.insert(current_member.id()) {
            return Err("circular invite chain".to_string());
        }
        let parent = certificate
            .chain
            .iter()
            .find(|candidate| candidate.member.id() == inviter)
            .ok_or("the invite chain is incomplete")?;
        current
            .verify_signature(&parent.member.member_vk)
            .map_err(|error| format!("invalid invite chain signature: {error}"))?;
        current = parent;
    }
    Err("the invite chain is too deep".to_string())
}

pub(crate) fn verify_token_manager_for(
    authority: &TopicAuthorityV1,
    view: &ChatBoardStateV1,
    signer: &MemberId,
    token: &AuthorizedInviteToken,
    board_params: &ChatBoardParametersV1,
    at: SystemTime,
) -> Result<(), String> {
    if *signer == authority.ownership.owner_at(board_params, at) {
        return Ok(());
    }
    if verify_owner_or_admin(view, board_params, signer, token.authority.as_deref(), at).is_ok() {
        return Ok(());
    }
    if view.roles.can_manage_access(signer) {
        return Ok(());
    }
    if let Some(proof) = token.authority.as_deref() {
        if let Some(grant) = proof.grant.as_ref() {
            if grant.role.role.can_manage_access
                && !grant.role.role.deleted
                && grant.assignment.assignment.member_id == *signer
                && grant.assignment.assignment.role_id == grant.role.role.id
                && !grant.assignment.assignment.revoked
            {
                let role_signer = grant.role.signer_id(board_params);
                let role_key = resolve_signer_key(
                    view,
                    board_params,
                    &role_signer,
                    grant.role.signer_key.as_ref(),
                )?;
                grant.role.verify_signature_with(&role_key)?;
                verify_owner_or_admin(
                    view,
                    board_params,
                    &role_signer,
                    grant.role.authority.as_deref(),
                    grant.role.role.signed_at,
                )?;
                let assignment_signer = grant.assignment.signer_id(board_params);
                let assignment_key = resolve_signer_key(
                    view,
                    board_params,
                    &assignment_signer,
                    grant.assignment.signer_key.as_ref(),
                )?;
                verify_struct(
                    &grant.assignment.assignment,
                    &grant.assignment.signature,
                    &assignment_key,
                )
                .map_err(|error| format!("invalid role assignment signature: {error}"))?;
                if verify_owner_or_admin(
                    view,
                    board_params,
                    &assignment_signer,
                    grant.assignment.authority.as_deref(),
                    grant.assignment.assignment.signed_at,
                )
                .is_ok()
                    || view.roles.can_manage_access(&assignment_signer)
                {
                    return Ok(());
                }
            }
        }
    }
    Err("the invite token signer cannot manage access".to_string())
}

pub(crate) fn verify_authority_records(
    authority: &TopicAuthorityV1,
    view: &ChatBoardStateV1,
    board_params: &ChatBoardParametersV1,
) -> Result<(), String> {
    authority.ownership.verify(view, board_params)?;
    authority.admins.verify(view, board_params)?;
    authority.roles.verify(view, board_params)?;
    authority.bans.verify(view, board_params)?;
    authority.ban_revocations.verify(view, board_params)?;
    authority.suspensions.verify(view, board_params)?;
    if let Some(root) = &authority.root {
        if root.root.version != AUTHORITY_ROOT_VERSION {
            return Err("unsupported authority root version".to_string());
        }
        let owner_key = authority
            .ownership
            .owner_key_at(board_params, system_time_from_ms(root.root.epoch));
        root.verify(&owner_key)?;
        let mut seen_members = HashSet::new();
        let mut proof_roles = RolesV1::default();
        let mut proof_bans = BansV1(Vec::new());
        let mut proof_revocations = BanRevocationsV1 {
            revocations: Vec::new(),
        };
        let mut proof_suspensions = SuspensionsV1 {
            suspensions: Vec::new(),
        };
        for proof in &authority.member_proofs {
            proof.verify(&root.root)?;
            if !seen_members.insert(proof.status.member_id()) {
                return Err("duplicate authority proof".to_string());
            }
            proof_roles.roles.extend(proof.status.roles.iter().cloned());
            proof_roles
                .assignments
                .extend(proof.status.assignments.iter().cloned());
            proof_bans.0.extend(proof.status.bans.iter().cloned());
            proof_revocations
                .revocations
                .extend(proof.status.revocations.iter().cloned());
            proof_suspensions
                .suspensions
                .extend(proof.status.suspensions.iter().cloned());
        }
        let mut seen_roles = HashSet::new();
        proof_roles
            .roles
            .retain(|role| seen_roles.insert(role.role.id));
        let mut seen_assignments = HashSet::new();
        proof_roles.assignments.retain(|assignment| {
            seen_assignments.insert((
                assignment.assignment.role_id,
                assignment.assignment.member_id,
                assignment.assignment.generation,
            ))
        });
        let mut seen_bans = HashSet::new();
        proof_bans.0.retain(|ban| seen_bans.insert(ban.id()));
        let mut seen_revocations = HashSet::new();
        proof_revocations
            .revocations
            .retain(|revocation| seen_revocations.insert(revocation.revocation.ban_id.clone()));
        let mut seen_suspensions = HashSet::new();
        proof_suspensions.suspensions.retain(|suspension| {
            seen_suspensions.insert((
                suspension.suspension.target,
                suspension.suspension.generation,
            ))
        });
        proof_roles.verify(view, board_params)?;
        proof_bans.verify(view, board_params)?;
        proof_revocations.verify(view, board_params)?;
        proof_suspensions.verify(view, board_params)?;
    }
    if authority.source_configuration.is_none() && authority.policy.is_none() {
        return Err("the topic has no policy".to_string());
    }
    if let Some(source) = &authority.source_configuration {
        let at_ms = system_time_ms(source.configuration.updated_at);
        let owner_key = authority
            .ownership
            .owner_key_at(board_params, system_time_from_ms(at_ms));
        source
            .verify_signature(&owner_key)
            .map_err(|error| format!("invalid source configuration signature: {error}"))?;
    }
    if let Some(policy) = &authority.policy {
        let at_ms = policy.policy.updated_at;
        let owner_key = authority
            .ownership
            .owner_key_at(board_params, system_time_from_ms(at_ms));
        policy.verify(&owner_key, MemberId::from(&owner_key))?;
    }
    Ok(())
}

pub(crate) fn is_member_banned(
    authority: &TopicAuthorityV1,
    member: MemberId,
    at_ms: i64,
) -> bool {
    let revoked: HashSet<_> = authority
        .ban_revocations
        .revocations
        .iter()
        .map(|revocation| revocation.revocation.ban_id.clone())
        .chain(
            authority
                .member_proofs
                .iter()
                .flat_map(|proof| proof.status.revocations.iter())
                .map(|revocation| revocation.revocation.ban_id.clone()),
        )
        .collect();
    authority
        .bans
        .0
        .iter()
        .chain(
            authority
                .member_proofs
                .iter()
                .flat_map(|proof| proof.status.bans.iter()),
        )
        .any(|ban| {
            if ban.ban.banned_user != member {
                return false;
            }
            let banned_at = system_time_ms(ban.ban.banned_at);
            let expired = ban
                .ban
                .expires_at
                .map(|expires| system_time_ms(expires) <= at_ms)
                .unwrap_or(false);
            banned_at <= at_ms && !expired && !revoked.contains(&ban.id())
        })
}

pub(crate) fn is_member_suspended(
    authority: &TopicAuthorityV1,
    member: MemberId,
    at_ms: i64,
) -> bool {
    authority
        .suspensions
        .suspensions
        .iter()
        .chain(
            authority
                .member_proofs
                .iter()
                .flat_map(|proof| proof.status.suspensions.iter()),
        )
        .filter(|entry| entry.suspension.target == member && entry.suspension.created_at <= at_ms)
        .max_by_key(|entry| entry.suspension.generation)
        .map(|entry| entry.suspension.until > at_ms)
        .unwrap_or(false)
}

pub(crate) fn check_posts_rate_limit(
    authority: &TopicAuthorityV1,
    posts: &BTreeMap<MessageId, AuthorizedTopicPostV1>,
    incoming: &[AuthorizedTopicPostV1],
) -> Result<(), String> {
    let policy = authority.policy();
    if policy.max_posts_per_window == 0 || policy.rate_window_ms == 0 {
        return Ok(());
    }
    let window = policy.rate_window_ms.min(i64::MAX as u64) as i64;
    let limit = policy.max_posts_per_window as usize;
    for post in incoming {
        let author = post.post.author;
        let at = post.post.created_at;
        let floor = at.saturating_sub(window);
        let mut count = 0usize;
        for existing in posts.values() {
            if existing.post.author == author
                && existing.post.created_at <= at
                && existing.post.created_at >= floor
            {
                count += 1;
            }
        }
        if count > limit {
            return Err("the author exceeded the topic rate limit".to_string());
        }
    }
    Ok(())
}

pub(crate) fn post_cycle(posts: &BTreeMap<MessageId, AuthorizedTopicPostV1>, start: MessageId) -> bool {
    let mut seen = HashSet::new();
    let mut current = Some(start);
    for _ in 0..MAX_POSTS {
        let Some(id) = current else {
            return false;
        };
        if !seen.insert(id) {
            return true;
        }
        current = posts.get(&id).and_then(|post| post.post.parent);
    }
    true
}

pub(crate) fn verify_owner_or_admin(
    view: &ChatBoardStateV1,
    board_params: &ChatBoardParametersV1,
    signer: &MemberId,
    proof: Option<&AuthorityProof>,
    at: SystemTime,
) -> Result<(), String> {
    if view.ownership.is_deactivated_at(signer, at) {
        return Err("signer key was deactivated before this action".to_string());
    }
    if *signer == view.ownership.owner_at(board_params, at) {
        return Ok(());
    }
    let at_ms = system_time_ms(at);
    let revoked_at = |min_gen: u64| {
        view.admin.revoked.iter().any(|revocation| {
            revocation.id() == *signer
                && revocation.revocation.generation >= min_gen
                && (revocation.revocation.signed_at == SystemTime::UNIX_EPOCH
                    || system_time_ms(revocation.revocation.signed_at) <= at_ms)
        })
    };
    if view.admin.admins.iter().any(|admin| {
        admin.admin.id() == *signer
            && system_time_ms(admin.admin.signed_at) <= at_ms
            && !revoked_at(admin.admin.generation)
    }) {
        return Ok(());
    }
    if let Some(proof) = proof {
        if let Some(admin) = &proof.admin {
            let owner_key = view
                .ownership
                .owner_key_at(board_params, admin.admin.signed_at);
            admin.verify_signature(&owner_key)?;
            if admin.admin.id() == *signer
                && (admin.admin.signed_at == SystemTime::UNIX_EPOCH
                    || system_time_ms(admin.admin.signed_at) <= at_ms)
                && !revoked_at(admin.admin.generation)
            {
                return Ok(());
            }
        }
    }
    Err("signer is not the owner or an admin".to_string())
}

pub(crate) fn merge_authority(left: &TopicAuthorityV1, right: &TopicAuthorityV1) -> TopicAuthorityV1 {
    let ownership = merge_ownership(&left.ownership, &right.ownership);
    let policy = merge_policy(&left.policy, &right.policy);
    let source_configuration =
        merge_source_configuration(&left.source_configuration, &right.source_configuration);
    let (root, member_proofs) = merge_authority_root(left, right);
    TopicAuthorityV1 {
        ownership,
        admins: merge_admins(&left.admins, &right.admins),
        roles: merge_roles(&left.roles, &right.roles),
        bans: merge_bans(&left.bans, &right.bans),
        ban_revocations: merge_revocations(
            &left.ban_revocations,
            &right.ban_revocations,
        ),
        suspensions: merge_suspensions(&left.suspensions, &right.suspensions),
        policy,
        source_configuration,
        root,
        member_proofs,
    }
}

pub(crate) fn merge_authority_root(
    left: &TopicAuthorityV1,
    right: &TopicAuthorityV1,
) -> (Option<AuthorizedAuthorityRootV1>, Vec<MemberStatusProofV1>) {
    let root = match (left.root.as_ref(), right.root.as_ref()) {
        (None, None) => None,
        (Some(root), None) | (None, Some(root)) => Some(root.clone()),
        (Some(left), Some(right)) => {
            if right.root.epoch > left.root.epoch
                || (right.root.epoch == left.root.epoch
                    && right.root.digest < left.root.digest)
            {
                Some(right.clone())
            } else {
                Some(left.clone())
            }
        }
    };
    let Some(root) = root else {
        return (None, Vec::new());
    };
    let mut proofs: BTreeMap<MemberId, MemberStatusProofV1> = BTreeMap::new();
    for proof in left
        .member_proofs
        .iter()
        .chain(right.member_proofs.iter())
    {
        if proof.verify(&root.root).is_ok() {
            proofs.insert(proof.status.member_id(), proof.clone());
        }
    }
    (Some(root), proofs.into_values().collect())
}

pub(crate) fn merge_policy(
    left: &Option<AuthorizedTopicPolicyV1>,
    right: &Option<AuthorizedTopicPolicyV1>,
) -> Option<AuthorizedTopicPolicyV1> {
    match (left, right) {
        (None, other) | (other, None) => other.clone(),
        (Some(left), Some(right)) => {
            if right.policy.generation > left.policy.generation
                || (right.policy.generation == left.policy.generation
                    && value_hash(&right.signature) < value_hash(&left.signature))
            {
                Some(right.clone())
            } else {
                Some(left.clone())
            }
        }
    }
}

pub(crate) fn merge_source_configuration(
    left: &Option<AuthorizedConfigurationV1>,
    right: &Option<AuthorizedConfigurationV1>,
) -> Option<AuthorizedConfigurationV1> {
    match (left, right) {
        (None, other) | (other, None) => other.clone(),
        (Some(left), Some(right)) => {
            if right.configuration.configuration_version
                > left.configuration.configuration_version
                || (right.configuration.configuration_version
                    == left.configuration.configuration_version
                    && value_hash(&right.signature) < value_hash(&left.signature))
            {
                Some(right.clone())
            } else {
                Some(left.clone())
            }
        }
    }
}

pub(crate) fn merge_ownership(left: &OwnershipV1, right: &OwnershipV1) -> OwnershipV1 {
    let mut transfers: BTreeMap<u64, _> = BTreeMap::new();
    for entry in left.transfers.iter().chain(right.transfers.iter()) {
        let generation = entry.transfer.generation;
        match transfers.get(&generation) {
            Some(existing) if value_hash(existing) <= value_hash(entry) => {}
            _ => {
                transfers.insert(generation, entry.clone());
            }
        }
    }
    let mut deactivations: BTreeMap<(MemberId, u64), _> = BTreeMap::new();
    for entry in left.deactivations.iter().chain(right.deactivations.iter()) {
        let key = (entry.deactivation.member, entry.deactivation.generation);
        deactivations.entry(key).or_insert_with(|| entry.clone());
    }
    OwnershipV1 {
        transfers: transfers.into_values().collect(),
        deactivations: deactivations.into_values().collect(),
        succession_votes: Vec::new(),
    }
}

pub(crate) fn merge_admins(left: &AdminsV1, right: &AdminsV1) -> AdminsV1 {
    let mut grants: BTreeMap<MemberId, AuthorizedAdmin> = left
        .admins
        .iter()
        .map(|admin| (admin.admin.id(), admin.clone()))
        .collect();
    for admin in &right.admins {
        let id = admin.admin.id();
        match grants.get(&id) {
            Some(existing) if existing.admin.generation > admin.admin.generation => {}
            Some(existing)
                if existing.admin.generation == admin.admin.generation
                    && value_hash(&existing.signature) <= value_hash(&admin.signature) => {}
            _ => {
                grants.insert(id, admin.clone());
            }
        }
    }
    let mut revocations: BTreeMap<MemberId, _> = left
        .revoked
        .iter()
        .map(|entry| (entry.id(), entry.clone()))
        .collect();
    for revocation in &right.revoked {
        let id = revocation.id();
        match revocations.get(&id) {
            Some(existing)
                if existing.revocation.generation > revocation.revocation.generation => {}
            Some(existing)
                if existing.revocation.generation == revocation.revocation.generation
                    && value_hash(&existing.signature)
                        <= value_hash(&revocation.signature) => {}
            _ => {
                revocations.insert(id, revocation.clone());
            }
        }
    }
    let mut admins = AdminsV1::default();
    for (id, grant) in grants {
        match revocations.get(&id) {
            Some(revocation)
                if revocation.revocation.generation >= grant.admin.generation =>
            {
                admins.revoked.push(revocation.clone());
            }
            _ => admins.admins.push(grant),
        }
    }
    for (id, revocation) in revocations {
        if !admins.revoked.iter().any(|entry| entry.id() == id)
            && !admins.admins.iter().any(|entry| entry.admin.id() == id)
        {
            admins.revoked.push(revocation);
        }
    }
    admins.admins.sort_by_key(|entry| entry.admin.id());
    admins.revoked.sort_by_key(|entry| entry.id());
    admins
}

pub(crate) fn merge_roles(left: &RolesV1, right: &RolesV1) -> RolesV1 {
    let mut roles: BTreeMap<RoleId, AuthorizedRole> = BTreeMap::new();
    for role in left.roles.iter().chain(right.roles.iter()) {
        let id = role.role.id;
        match roles.get(&id) {
            Some(existing) if existing.role.generation > role.role.generation => {}
            Some(existing)
                if existing.role.generation == role.role.generation
                    && existing.role.deleted == role.role.deleted
                    && value_hash(&existing.signature) <= value_hash(&role.signature) => {}
            Some(existing)
                if existing.role.generation == role.role.generation
                    && existing.role.deleted
                    && !role.role.deleted => {}
            _ => {
                roles.insert(id, role.clone());
            }
        }
    }
    let mut assignments: BTreeMap<(RoleId, MemberId), AuthorizedRoleAssignment> =
        BTreeMap::new();
    for assignment in left.assignments.iter().chain(right.assignments.iter()) {
        let key = (
            assignment.assignment.role_id,
            assignment.assignment.member_id,
        );
        match assignments.get(&key) {
            Some(existing)
                if existing.assignment.generation > assignment.assignment.generation => {}
            Some(existing)
                if existing.assignment.generation == assignment.assignment.generation
                    && existing.assignment.revoked
                    && !assignment.assignment.revoked => {}
            Some(existing)
                if existing.assignment.generation == assignment.assignment.generation
                    && existing.assignment.revoked == assignment.assignment.revoked
                    && value_hash(&existing.signature) <= value_hash(&assignment.signature) => {}
            _ => {
                assignments.insert(key, assignment.clone());
            }
        }
    }
    RolesV1 {
        roles: roles.into_values().collect(),
        assignments: assignments.into_values().collect(),
    }
}

pub(crate) fn merge_bans(left: &BansV1, right: &BansV1) -> BansV1 {
    let mut bans: BTreeMap<_, _> = left
        .0
        .iter()
        .map(|ban| (ban.id(), ban.clone()))
        .collect();
    for ban in &right.0 {
        bans.entry(ban.id()).or_insert_with(|| ban.clone());
    }
    BansV1(bans.into_values().collect())
}

pub(crate) fn merge_revocations(
    left: &BanRevocationsV1,
    right: &BanRevocationsV1,
) -> BanRevocationsV1 {
    let mut revocations: BTreeMap<_, _> = left
        .revocations
        .iter()
        .map(|entry| (entry.revocation.ban_id.clone(), entry.clone()))
        .collect();
    for entry in &right.revocations {
        revocations
            .entry(entry.revocation.ban_id.clone())
            .or_insert_with(|| entry.clone());
    }
    BanRevocationsV1 {
        revocations: revocations.into_values().collect(),
    }
}

pub(crate) fn merge_suspensions(
    left: &SuspensionsV1,
    right: &SuspensionsV1,
) -> SuspensionsV1 {
    let mut suspensions: BTreeMap<MemberId, AuthorizedSuspension> = BTreeMap::new();
    for entry in left.suspensions.iter().chain(right.suspensions.iter()) {
        let target = entry.suspension.target;
        match suspensions.get(&target) {
            Some(existing)
                if existing.suspension.generation > entry.suspension.generation => {}
            Some(existing)
                if existing.suspension.generation == entry.suspension.generation
                    && value_hash(&existing.signature) <= value_hash(&entry.signature) => {}
            _ => {
                suspensions.insert(target, entry.clone());
            }
        }
    }
    SuspensionsV1 {
        suspensions: suspensions.into_values().collect(),
    }
}

pub(crate) fn merge_participant(
    participants: &mut Vec<AuthorizedParticipantV1>,
    incoming: &AuthorizedParticipantV1,
) {
    if let Some(existing) = participants
        .iter_mut()
        .find(|entry| entry.record.member_id == incoming.record.member_id)
    {
        if incoming.record.joined_at < existing.record.joined_at {
            *existing = incoming.clone();
        } else if incoming.record.joined_at == existing.record.joined_at
            && value_hash(incoming) < value_hash(existing)
        {
            *existing = incoming.clone();
        }
    } else {
        participants.push(incoming.clone());
    }
}

pub(crate) fn merge_trust(trust: &mut Vec<AuthorizedTrustV1>, incoming: &AuthorizedTrustV1) {
    if let Some(existing) = trust
        .iter_mut()
        .find(|entry| entry.trust.member_id == incoming.trust.member_id)
    {
        let replace = incoming.trust.generation > existing.trust.generation
            || (incoming.trust.generation == existing.trust.generation
                && !incoming.trust.trusted
                && existing.trust.trusted)
            || (incoming.trust.generation == existing.trust.generation
                && incoming.trust.trusted == existing.trust.trusted
                && value_hash(incoming) < value_hash(existing));
        if replace {
            *existing = incoming.clone();
        }
    } else {
        trust.push(incoming.clone());
    }
}

pub(crate) fn merge_approval(
    approvals: &mut Vec<AuthorizedTopicApprovalV1>,
    incoming: &AuthorizedTopicApprovalV1,
) {
    if let Some(existing) = approvals
        .iter_mut()
        .find(|entry| entry.approval.target == incoming.approval.target)
    {
        let replace = incoming.approval.generation > existing.approval.generation
            || (incoming.approval.generation == existing.approval.generation
                && !incoming.approval.approved
                && existing.approval.approved)
            || (incoming.approval.generation == existing.approval.generation
                && incoming.approval.approved == existing.approval.approved
                && value_hash(incoming) < value_hash(existing));
        if replace {
            *existing = incoming.clone();
        }
    } else {
        approvals.push(incoming.clone());
    }
}

pub(crate) fn merge_generation(
    left: &TopicGenerationV1,
    right: &TopicGenerationV1,
) -> TopicGenerationV1 {
    let key = |g: &TopicGenerationV1| {
        (
            g.part,
            g.next_part.unwrap_or(0),
            g.closed_at.is_some(),
            g.closed_at.map(std::cmp::Reverse),
            g.previous_hash,
        )
    };
    if key(right) > key(left) {
        right.clone()
    } else {
        left.clone()
    }
}
