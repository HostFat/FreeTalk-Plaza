use super::*;
use crate::board_state::ban::{AuthorizedUserBan, UserBan};
use crate::board_state::configuration::Configuration;
use crate::board_state::member::{AuthorizedMember, Member};
use crate::board_state::member_info::{AuthorizedMemberInfo, MemberInfo};
use ed25519_dalek::SigningKey;
use std::fmt::Debug;
use std::time::SystemTime;

#[test]
fn cleanup_is_idempotent_and_enforces_the_ban_cap() {
    let (mut state, parameters, owner_key) = create_empty_chat_board_state();
    let owner_id = parameters.owner_id();

    let member_key = SigningKey::generate(&mut rand::thread_rng());
    let member_id = MemberId::from(member_key.verifying_key());
    state.members.members.push(AuthorizedMember::new(
        Member {
            owner_member_id: owner_id,
            invited_by: owner_id,
            member_vk: member_key.verifying_key(),
            join_proof: None,
        },
        &owner_key,
    ));

    // Two bans over a cap of one, the owner's being the newest.
    let mut cfg = state.configuration.configuration.clone();
    cfg.max_user_bans = 1;
    cfg.configuration_version += 1;
    state.configuration = AuthorizedConfigurationV1::new(cfg, &owner_key);

    let at = |secs: u64| SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs);
    state.bans = BansV1(vec![
        AuthorizedUserBan::new(
            UserBan {
                owner_member_id: owner_id,
                banned_at: at(1),
                banned_user: MemberId::from_bytes([21u8; 32]),
                expires_at: None,
                target_member: None,
                invite_chain: Vec::new(),
            },
            member_id,
            &member_key,
        ),
        AuthorizedUserBan::new(
            UserBan {
                owner_member_id: owner_id,
                banned_at: at(2),
                banned_user: MemberId::from_bytes([23u8; 32]),
                expires_at: None,
                target_member: None,
                invite_chain: Vec::new(),
            },
            owner_id,
            &owner_key,
        ),
    ]);

    let mut once = state.clone();
    once.normalize(&parameters).unwrap();
    let mut twice = once.clone();
    twice.normalize(&parameters).unwrap();

    assert_eq!(once, twice, "cleanup must be a fixpoint");
    assert_eq!(once.bans.0.len(), 1, "the cap is enforced during cleanup");
    assert_eq!(
        once.bans.0[0].banned_by, owner_id,
        "the owner's ban survives the cap"
    );
}

#[test]
fn an_owner_invitation_survives_cleanup_until_the_first_message() {
    let (mut state, parameters, owner_key) = create_empty_chat_board_state();
    let owner_id = parameters.owner_id();
    let member_key = SigningKey::generate(&mut rand::thread_rng());
    let member_id = MemberId::from(member_key.verifying_key());
    state.members.members.push(AuthorizedMember::new(
        Member {
            owner_member_id: owner_id,
            invited_by: owner_id,
            member_vk: member_key.verifying_key(),
            join_proof: None,
        },
        &owner_key,
    ));
    // The invitee joins and publishes its nickname.
    state.member_info.member_info.push(
        AuthorizedMemberInfo::new_with_member_key(
            MemberInfo::new_public(member_id, 1, "Invitee".to_string()),
            &member_key,
        ),
    );

    state.normalize(&parameters).unwrap();

    assert!(
        state
            .members
            .members
            .iter()
            .any(|member| member.member.id() == member_id),
        "the invited identity is not pruned before it posts"
    );
    state
        .verify(&state, &parameters)
        .expect("the state with a pending invitation verifies");
}

#[test]
fn test_state() {
    let (state, parameters, owner_signing_key) = create_empty_chat_board_state();

    assert!(
        state.verify(&state, &parameters).is_ok(),
        "Empty state should verify"
    );

    // Test that the configuration can be updated
    let mut new_cfg = state.configuration.configuration.clone();
    new_cfg.configuration_version += 1;
    new_cfg.max_message_size = 5000; // Change from default
    let new_cfg = AuthorizedConfigurationV1::new(new_cfg, &owner_signing_key);

    let mut cfg_modified_state = state.clone();
    cfg_modified_state.configuration = new_cfg;
    test_apply_delta(state.clone(), cfg_modified_state, &parameters);
}

fn test_apply_delta<CS>(orig_state: CS, modified_state: CS, parameters: &CS::Parameters)
where
    CS: ComposableState<ParentState = CS> + Clone + PartialEq + Debug,
{
    let orig_verify_result = orig_state.verify(&orig_state, parameters);
    assert!(
        orig_verify_result.is_ok(),
        "Original state verification failed: {:?}",
        orig_verify_result.err()
    );

    let modified_verify_result = modified_state.verify(&modified_state, parameters);
    assert!(
        modified_verify_result.is_ok(),
        "Modified state verification failed: {:?}",
        modified_verify_result.err()
    );

    let delta = modified_state.delta(
        &orig_state,
        parameters,
        &orig_state.summarize(&orig_state, parameters),
    );

    println!("Delta: {:?}", delta);

    let mut new_state = orig_state.clone();
    let apply_delta_result = new_state.apply_delta(&orig_state, parameters, &delta);
    assert!(
        apply_delta_result.is_ok(),
        "Applying delta failed: {:?}",
        apply_delta_result.err()
    );

    assert_eq!(new_state, modified_state);
}
fn create_empty_chat_board_state() -> (ChatBoardStateV1, ChatBoardParametersV1, SigningKey) {
    // Create a test board_state with a single member and two messages, one written by
    // the owner and one by the member - the member must be invited by the owner
    let rng = &mut rand::thread_rng();
    let owner_signing_key = SigningKey::generate(rng);
    let owner_verifying_key = owner_signing_key.verifying_key();

    let config = AuthorizedConfigurationV1::new(Configuration::default(), &owner_signing_key);

    (
        ChatBoardStateV1 {
            configuration: config,
            bans: BansV1::default(),
            roles: RolesV1::default(),
            invites: InviteTokensV1::default(),
            members: MembersV1::default(),
            member_info: MemberInfoV1::default(),
            category_secrets: CategorySecretsV1::default(),
            secrets: BoardSecretsV1::default(),
            upgrade: OptionalUpgradeV1(None),
            ..Default::default()
        },
        ChatBoardParametersV1 {
            owner: owner_verifying_key,
        },
        owner_signing_key,
    )
}

/// Regression test: when a member who issued bans is subsequently banned themselves,
/// their bans become orphaned (banning member no longer in members list and not owner).
/// The post_apply_delta hook post_apply_cleanup must remove these to prevent verify() failure.
/// See: technic corrupted state incident (Feb 2026)
#[test]
fn test_orphaned_ban_cleanup_after_cascade_removal() {
    let rng = &mut rand::thread_rng();

    // Create owner
    let owner_sk = SigningKey::generate(rng);
    let owner_vk = owner_sk.verifying_key();
    let owner_id = MemberId::from(&owner_vk);
    let params = ChatBoardParametersV1 { owner: owner_vk };

    // Configuration allowing bans and members
    let config = Configuration {
        max_user_bans: 10,
        updated_at: std::time::SystemTime::UNIX_EPOCH,
        ..Default::default()
    };
    let auth_config = AuthorizedConfigurationV1::new(config, &owner_sk);

    // Create member A (invited by owner) and member B (invited by A)
    let a_sk = SigningKey::generate(rng);
    let a_vk = a_sk.verifying_key();
    let a_id = MemberId::from(&a_vk);

    let b_sk = SigningKey::generate(rng);
    let b_vk = b_sk.verifying_key();
    let b_id = MemberId::from(&b_vk);

    let member_a = AuthorizedMember::new(
        Member {
            owner_member_id: owner_id,
            invited_by: owner_id,
            member_vk: a_vk,
            join_proof: None,
        },
        &owner_sk,
    );

    let member_b = AuthorizedMember::new(
        Member {
            owner_member_id: owner_id,
            invited_by: a_id,
            member_vk: b_vk,
            join_proof: None,
        },
        &a_sk,
    );

    // A bans B (authorized because A is in B's invite chain)
    let ban_b_by_a = AuthorizedUserBan::new(
        UserBan {
            owner_member_id: owner_id,
            banned_at: std::time::SystemTime::now(),
            banned_user: b_id,
            expires_at: None,
            target_member: Some(member_b),
            invite_chain: vec![member_a.clone()],
        },
        a_id,
        &a_sk,
    );

    // Initial state: A is a member, B already removed (ban took effect)
    let initial_state = ChatBoardStateV1 {
        configuration: auth_config.clone(),
        bans: BansV1(vec![ban_b_by_a.clone()]),
        members: MembersV1 {
            members: vec![member_a.clone()],
        },
        ..Default::default()
    };

    assert!(
        initial_state.verify(&initial_state, &params).is_ok(),
        "Initial state should verify: {:?}",
        initial_state.verify(&initial_state, &params)
    );

    // Now owner bans A — this will cascade-remove A from members,
    // making A's ban of B orphaned (A is no longer in members and not owner)
    let ban_a_by_owner = AuthorizedUserBan::new(
        UserBan {
            owner_member_id: owner_id,
            banned_at: std::time::SystemTime::now() + std::time::Duration::from_secs(1),
            banned_user: a_id,
            expires_at: None,
            target_member: None,
            invite_chain: Vec::new(),
        },
        owner_id,
        &owner_sk,
    );

    // Modified state for delta computation: add owner's ban of A
    let modified_for_delta = ChatBoardStateV1 {
        configuration: auth_config,
        bans: BansV1(vec![ban_b_by_a.clone(), ban_a_by_owner.clone()]),
        members: MembersV1 {
            members: vec![member_a.clone()],
        },
        ..Default::default()
    };

    // Compute and apply delta
    let summary = initial_state.summarize(&initial_state, &params);
    let delta = modified_for_delta.delta(&initial_state, &params, &summary);

    let mut result_state = initial_state.clone();
    let apply_result = result_state.apply_delta(&initial_state, &params, &delta);
    assert!(
        apply_result.is_ok(),
        "apply_delta should succeed: {:?}",
        apply_result
    );

    // A should be removed (banned by owner)
    assert!(
        result_state.members.members.is_empty(),
        "A should be removed from members: {:?}",
        result_state.members.members
    );

    // Only owner's ban should remain — A's ban of B is orphaned and cleaned
    assert_eq!(
        result_state.bans.0.len(),
        1,
        "Only owner's ban should remain, orphaned ban cleaned: {:?}",
        result_state.bans.0
    );
    assert_eq!(
        result_state.bans.0[0].banned_by, owner_id,
        "Remaining ban should be by owner"
    );

    // Result state should pass verification
    assert!(
        result_state.verify(&result_state, &params).is_ok(),
        "Result state should verify after orphaned ban cleanup: {:?}",
        result_state.verify(&result_state, &params)
    );
}

#[test]
fn test_state_with_none_deltas() {
    let (state, parameters, owner_signing_key) = create_empty_chat_board_state();

    // Create a modified board_state with no changes (all deltas should be None)
    let modified_state = state.clone();

    // Apply the delta
    let summary = state.summarize(&state, &parameters);
    let delta = modified_state.delta(&state, &parameters, &summary);

    assert!(
        delta.is_none(),
        "Delta should be None when no changes are made"
    );

    // Now, let's modify only one field and check if other deltas are None
    let mut partially_modified_state = state.clone();
    let new_config = Configuration {
        configuration_version: 2,
        updated_at: std::time::SystemTime::UNIX_EPOCH,
        ..partially_modified_state.configuration.configuration.clone()
    };
    partially_modified_state.configuration =
        AuthorizedConfigurationV1::new(new_config, &owner_signing_key);

    let summary = state.summarize(&state, &parameters);
    let delta = partially_modified_state
        .delta(&state, &parameters, &summary)
        .unwrap();

    // Check that only the configuration delta is Some, and others are None
    assert!(
        delta.configuration.is_some(),
        "Configuration delta should be Some"
    );
    assert!(delta.bans.is_none(), "Bans delta should be None");
    assert!(delta.members.is_none(), "Members delta should be None");
    assert!(
        delta.member_info.is_none(),
        "Member info delta should be None"
    );
    assert!(delta.sections.is_none(), "Sections delta should be None");
    assert!(delta.topics.is_none(), "Topics delta should be None");
    assert!(delta.upgrade.is_none(), "Upgrade delta should be None");

    // Apply the partial delta
    let mut new_state = state.clone();
    new_state
        .apply_delta(&state, &parameters, &Some(delta))
        .unwrap();

    assert_eq!(
        new_state, partially_modified_state,
        "State should be partially modified"
    );
}

fn sign_owner_root(state: &mut ChatBoardStateV1, owner: &SigningKey) {
    let tree = crate::board_state::authority::AuthorityTreeV1::from_board(state);
    let mut root = tree.root(1_000);
    root.content_hash = tree.content_hash();
    state.authority_root = crate::board_state::authority::AuthorityRootStateV1(Some(
        crate::board_state::authority::AuthorizedAuthorityRootV1::new(root, owner),
    ));
}

#[test]
fn an_owner_root_skips_the_authority_record_signatures() {
    let (mut state, parameters, owner_key) = create_empty_chat_board_state();
    let member_key = SigningKey::generate(&mut rand::thread_rng());
    state.members.members.push(AuthorizedMember::new(
        Member {
            owner_member_id: parameters.owner_id(),
            invited_by: parameters.owner_id(),
            member_vk: member_key.verifying_key(),
            join_proof: None,
        },
        &owner_key,
    ));
    sign_owner_root(&mut state, &owner_key);
    state
        .verify_with_section(&parameters, None)
        .expect("the signed root and the records verify");

    // Change the signed member data. The root no longer commits to it, so
    // the board falls back to the full verification and rejects it.
    state.members.members[0].member.member_vk =
        SigningKey::generate(&mut rand::thread_rng()).verifying_key();
    assert!(
        state.verify_with_section(&parameters, None).is_err(),
        "a stale root must not hide an invalid record"
    );

    // Re-signing the root attests the new bytes: the owner is the board
    // authority, so the record signatures are not checked again.
    sign_owner_root(&mut state, &owner_key);
    state
        .verify_with_section(&parameters, None)
        .expect("the owner root attests the records");
}

#[test]
fn prune_expired_records_drops_old_suspensions_and_unreferenced_expired_invites_deterministically()
{
    use crate::board_state::invites::{AuthorizedInviteToken, InviteToken};
    use crate::board_state::member_moderation::{AuthorizedSuspension, SuspensionV1};
    use crate::board_state::rate_limit::system_time_from_ms;
    use crate::board_state::reports::ReportReason;

    let (mut state, parameters, owner_key) = create_empty_chat_board_state();
    let member_key = SigningKey::generate(&mut rand::thread_rng());
    let member_id = MemberId::from(&member_key.verifying_key());
    state.members.members.push(AuthorizedMember::new(
        Member {
            owner_member_id: parameters.owner_id(),
            invited_by: parameters.owner_id(),
            member_vk: member_key.verifying_key(),
            join_proof: None,
        },
        &owner_key,
    ));

    let now_ms = ChatBoardStateV1::EXPIRED_RECORD_RETENTION_MS * 3;
    state.configuration.configuration.updated_at = system_time_from_ms(now_ms);
    state.configuration =
        AuthorizedConfigurationV1::new(state.configuration.configuration.clone(), &owner_key);

    // Old expired suspension (> 30d ago) -> should be pruned.
    state.suspensions.suspensions.push(AuthorizedSuspension::new(
        SuspensionV1 {
            target: member_id,
            reason: ReportReason::Spam,
            created_at: 1_000,
            until: 2_000,
            generation: 1,
        },
        &owner_key,
    ));

    // Old expired invite token -> should be pruned; fresh token -> kept.
    let token_key = SigningKey::generate(&mut rand::thread_rng());
    state.invites.tokens.push(AuthorizedInviteToken::new(
        InviteToken {
            id: [1u8; 16],
            verifying_key: token_key.verifying_key(),
            role_id: [0u8; 16],
            max_uses: None,
            not_after: Some(system_time_from_ms(2_000)),
            generation: 1,
            deleted: false,
            label: "old".to_string(),
            created_at: Some(system_time_from_ms(1_000)),
            includes_category_keys: false,
        },
        &owner_key,
    ));
    state.invites.tokens.push(AuthorizedInviteToken::new(
        InviteToken {
            id: [2u8; 16],
            verifying_key: token_key.verifying_key(),
            role_id: [0u8; 16],
            max_uses: None,
            not_after: Some(system_time_from_ms(now_ms + 10_000)),
            generation: 1,
            deleted: false,
            label: "fresh".to_string(),
            created_at: Some(system_time_from_ms(now_ms)),
            includes_category_keys: false,
        },
        &owner_key,
    ));

    state.prune_expired_records(&parameters);
    assert!(state.suspensions.suspensions.is_empty());
    assert_eq!(state.invites.tokens.len(), 1);
    assert_eq!(state.invites.tokens[0].token.id, [2u8; 16]);
}
