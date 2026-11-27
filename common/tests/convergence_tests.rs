//! Convergence tests for River contract state
//!
//! These tests verify that CRDT operations produce the same result regardless
//! of the order in which deltas are applied. For a proper CRDT implementation:
//! - Commutativity: apply(delta_a, apply(delta_b, state)) == apply(delta_b, apply(delta_a, state))
//! - Idempotency: apply(delta, apply(delta, state)) == apply(delta, state)
//!
//! Non-convergence bugs occur when:
//! - Order-dependent truncation (first N items from unordered iteration)
//! - Tie-breaking without deterministic secondary sort keys
//! - Using non-deterministic data structures for selection

use ed25519_dalek::SigningKey;
use freenet_scaffold::ComposableState;
use plaza_core::board_state::ban::{AuthorizedUserBan, BansV1, UserBan};
use plaza_core::board_state::member::{
    AuthorizedMember, Member, MemberId, MembersDelta, MembersV1,
};
use plaza_core::board_state::message::MessageId;
use plaza_core::board_state::{ChatBoardParametersV1, ChatBoardStateV1};
use rand::rngs::OsRng;
use std::time::SystemTime;

/// Helper to create a test member that's invited by a given inviter
fn create_test_member(owner_id: MemberId, invited_by: MemberId) -> (Member, SigningKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let member = Member {
        owner_member_id: owner_id,
        invited_by,
        member_vk: verifying_key,
        join_proof: None,
    };
    (member, signing_key)
}

/// Helper to create a properly signed authorized member
fn create_authorized_member(member: Member, inviter_signing_key: &SigningKey) -> AuthorizedMember {
    AuthorizedMember::new(member, inviter_signing_key)
}

// =============================================================================
// MEMBER TRUNCATION CONVERGENCE TEST
// =============================================================================
//
// BUG LOCATION: member.rs:144-159
//
// The current implementation processes delta.added in iteration order:
//
//     for member in &delta.added {
//         if self.members.len() < max_members {
//             self.members.push(member.clone());
//         } else {
//             break;
//         }
//     }
//
// This means if we have capacity for 1 more member and receive delta [A, B]:
// - We add A, then break because we're at capacity
//
// If another peer receives delta [B, A]:
// - They add B, then break because they're at capacity
//
// Result: Different final states depending on delta order.
//
// Members are no longer pruned - all members are kept regardless of max_members

#[test]
fn test_member_add_order_convergence() {
    // Create owner
    let owner_signing_key = SigningKey::generate(&mut OsRng);
    let owner_verifying_key = owner_signing_key.verifying_key();
    let owner_id: MemberId = owner_verifying_key.into();

    // Create two members to be added
    let (member_a, _) = create_test_member(owner_id, owner_id);
    let (member_b, _) = create_test_member(owner_id, owner_id);

    let auth_member_a = create_authorized_member(member_a.clone(), &owner_signing_key);
    let auth_member_b = create_authorized_member(member_b.clone(), &owner_signing_key);

    let parent_state = ChatBoardStateV1::default();

    let parameters = ChatBoardParametersV1 {
        owner: owner_verifying_key,
    };

    // State A: Apply delta with order [member_a, member_b]
    let mut state_a = MembersV1::default();
    let delta_ab = MembersDelta::new(vec![auth_member_a.clone(), auth_member_b.clone()]);
    state_a
        .apply_delta(&parent_state, &parameters, &Some(delta_ab))
        .expect("apply_delta should succeed");

    // State B: Apply delta with order [member_b, member_a]
    let mut state_b = MembersV1::default();
    let delta_ba = MembersDelta::new(vec![auth_member_b.clone(), auth_member_a.clone()]);
    state_b
        .apply_delta(&parent_state, &parameters, &Some(delta_ba))
        .expect("apply_delta should succeed");

    // Both states should have all 2 members (no pruning)
    assert_eq!(state_a.members.len(), 2, "State A should have 2 members");
    assert_eq!(state_b.members.len(), 2, "State B should have 2 members");

    // CONVERGENCE CHECK: Both states should have the SAME members
    let mut ids_a: Vec<_> = state_a.members.iter().map(|m| m.member.id()).collect();
    let mut ids_b: Vec<_> = state_b.members.iter().map(|m| m.member.id()).collect();
    ids_a.sort();
    ids_b.sort();

    assert_eq!(
        ids_a, ids_b,
        "CONVERGENCE FAILURE: Different delta orders produced different final states!\n\
         State A members: {:?}\n\
         State B members: {:?}",
        ids_a, ids_b
    );
}

// =============================================================================
// MEMBER EXCESS REMOVAL CONVERGENCE TEST
// =============================================================================
//
// BUG LOCATION: member.rs:256-267
//
// The current implementation uses max_by_key to find the member with the longest
// invite chain to remove:
//
//     let member_to_remove = self.members.iter()
//         .max_by_key(|m| self.get_invite_chain(m, parameters).unwrap().len())
//         .unwrap().member.id();
//
// When multiple members have the same invite chain length, max_by_key returns
// an arbitrary one (the last one encountered during iteration).
//
// Members are no longer pruned - all members are kept

#[test]
fn test_member_convergence() {
    // Create owner
    let owner_signing_key = SigningKey::generate(&mut OsRng);
    let owner_verifying_key = owner_signing_key.verifying_key();
    let owner_id: MemberId = owner_verifying_key.into();

    // Create three members, all invited directly by owner
    let (member_a, _) = create_test_member(owner_id, owner_id);
    let (member_b, _) = create_test_member(owner_id, owner_id);
    let (member_c, _) = create_test_member(owner_id, owner_id);

    let auth_member_a = create_authorized_member(member_a.clone(), &owner_signing_key);
    let auth_member_b = create_authorized_member(member_b.clone(), &owner_signing_key);
    let auth_member_c = create_authorized_member(member_c.clone(), &owner_signing_key);

    let parent_state = ChatBoardStateV1::default();

    let parameters = ChatBoardParametersV1 {
        owner: owner_verifying_key,
    };

    // State A: Members in order [A, B, C]
    let mut state_a = MembersV1 {
        members: vec![
            auth_member_a.clone(),
            auth_member_b.clone(),
            auth_member_c.clone(),
        ],
    };
    state_a
        .apply_delta(&parent_state, &parameters, &None)
        .expect("apply_delta should succeed");

    // State B: Members in order [C, B, A] (reversed)
    let mut state_b = MembersV1 {
        members: vec![
            auth_member_c.clone(),
            auth_member_b.clone(),
            auth_member_a.clone(),
        ],
    };
    state_b
        .apply_delta(&parent_state, &parameters, &None)
        .expect("apply_delta should succeed");

    // All 3 members should be kept (no pruning)
    assert_eq!(state_a.members.len(), 3, "State A should have 3 members");
    assert_eq!(state_b.members.len(), 3, "State B should have 3 members");

    // CONVERGENCE CHECK: Both states should have the SAME members
    let mut ids_a: Vec<_> = state_a.members.iter().map(|m| m.member.id()).collect();
    let mut ids_b: Vec<_> = state_b.members.iter().map(|m| m.member.id()).collect();
    ids_a.sort();
    ids_b.sort();

    assert_eq!(ids_a, ids_b, "Both states should have the same members");
}

// =============================================================================
// BAN EXCESS ORDER CONVERGENCE TEST
// =============================================================================
//
// BUG LOCATION: ban.rs:199-205
//
// When bans exceed the maximum, the code removes the oldest bans:
//
//     let mut extra_bans_vec = self.0.clone();
//     extra_bans_vec.sort_by_key(|ban| ban.ban.banned_at);
//     extra_bans_vec.reverse();
//
//     for ban in extra_bans_vec.iter().take(extra_bans as usize) {
//         invalid_bans.insert(ban.id(), BanValidationError::ExceededMaximumBans);
//     }
//
// When multiple bans have the same timestamp, their relative order after sorting
// is undefined, leading to non-deterministic behavior.
//
// FIX: Add secondary sort by ban ID for deterministic ordering

#[test]
fn test_ban_excess_order_convergence() {
    // Create owner
    let owner_signing_key = SigningKey::generate(&mut OsRng);
    let owner_verifying_key = owner_signing_key.verifying_key();
    let owner_id: MemberId = owner_verifying_key.into();

    // Create members to ban
    let (member_a, _) = create_test_member(owner_id, owner_id);
    let (member_b, _) = create_test_member(owner_id, owner_id);
    let (member_c, _) = create_test_member(owner_id, owner_id);

    let auth_member_a = create_authorized_member(member_a.clone(), &owner_signing_key);
    let auth_member_b = create_authorized_member(member_b.clone(), &owner_signing_key);
    let auth_member_c = create_authorized_member(member_c.clone(), &owner_signing_key);

    // Use the SAME timestamp for all bans to trigger the bug
    let same_time = SystemTime::now();

    // Create three bans with identical timestamps
    let ban_a = AuthorizedUserBan::new(
        UserBan {
            owner_member_id: owner_id,
            banned_at: same_time,
            banned_user: member_a.id(),
            expires_at: None,
            target_member: None,
            invite_chain: Vec::new(),
        },
        owner_id,
        &owner_signing_key,
    );

    let ban_b = AuthorizedUserBan::new(
        UserBan {
            owner_member_id: owner_id,
            banned_at: same_time,
            banned_user: member_b.id(),
            expires_at: None,
            target_member: None,
            invite_chain: Vec::new(),
        },
        owner_id,
        &owner_signing_key,
    );

    let ban_c = AuthorizedUserBan::new(
        UserBan {
            owner_member_id: owner_id,
            banned_at: same_time,
            banned_user: member_c.id(),
            expires_at: None,
            target_member: None,
            invite_chain: Vec::new(),
        },
        owner_id,
        &owner_signing_key,
    );

    // Create parent state with max_user_bans = 2 (need to reject 1 of 3)
    let mut parent_state = ChatBoardStateV1::default();
    parent_state.configuration.configuration.max_user_bans = 2;
    parent_state.members = MembersV1 {
        members: vec![auth_member_a, auth_member_b, auth_member_c],
    };

    let parameters = ChatBoardParametersV1 {
        owner: owner_verifying_key,
    };

    // State A: Bans in order [A, B, C]
    let bans_a = BansV1(vec![ban_a.clone(), ban_b.clone(), ban_c.clone()]);

    // State B: Bans in order [C, B, A] (reversed)
    let bans_b = BansV1(vec![ban_c.clone(), ban_b.clone(), ban_a.clone()]);

    // Check which bans are considered invalid (excess) in each state
    // We can't directly call get_invalid_bans since it's private, but we can
    // test via verify() which internally calls it
    let result_a = bans_a.verify(&parent_state, &parameters);
    let result_b = bans_b.verify(&parent_state, &parameters);

    // Both should fail verification (too many bans)
    assert!(result_a.is_err(), "State A should fail verification");
    assert!(result_b.is_err(), "State B should fail verification");

    // The error messages should identify the SAME ban as excess
    // If they identify different bans, we have non-convergence
    let err_a = result_a.unwrap_err();
    let err_b = result_b.unwrap_err();

    // Extract the ban IDs from error messages for comparison
    // This is a heuristic check; a proper fix would expose the invalid ban set
    assert_eq!(
        err_a, err_b,
        "CONVERGENCE FAILURE: Different ban orders identified different excess bans!\n\
         Error A: {}\n\
         Error B: {}\n\
         All bans had the same timestamp, so tie-breaking was needed.",
        err_a, err_b
    );
}

// =============================================================================
// ADDITIONAL CONVERGENCE TESTS
// =============================================================================

/// Test that applying the same delta multiple times is idempotent
#[test]
fn test_member_delta_idempotency() {
    let owner_signing_key = SigningKey::generate(&mut OsRng);
    let owner_verifying_key = owner_signing_key.verifying_key();
    let owner_id: MemberId = owner_verifying_key.into();

    let (member_a, _) = create_test_member(owner_id, owner_id);
    let auth_member_a = create_authorized_member(member_a.clone(), &owner_signing_key);

    let parent_state = ChatBoardStateV1::default();

    let parameters = ChatBoardParametersV1 {
        owner: owner_verifying_key,
    };

    let mut state = MembersV1::default();
    let delta = MembersDelta::new(vec![auth_member_a.clone()]);

    // Apply delta first time
    state
        .apply_delta(&parent_state, &parameters, &Some(delta.clone()))
        .expect("first apply_delta should succeed");

    let state_after_first = state.clone();

    // Apply same delta again
    state
        .apply_delta(&parent_state, &parameters, &Some(delta))
        .expect("second apply_delta should succeed");

    // State should be unchanged (idempotent)
    assert_eq!(
        state.members.len(),
        state_after_first.members.len(),
        "Applying delta twice should be idempotent"
    );
    assert_eq!(
        state
            .members
            .iter()
            .map(|m| m.member.id())
            .collect::<Vec<_>>(),
        state_after_first
            .members
            .iter()
            .map(|m| m.member.id())
            .collect::<Vec<_>>(),
        "Applying delta twice should produce identical state"
    );
}

/// Test convergence with interleaved delta applications
#[test]
fn test_member_interleaved_deltas_convergence() {
    let owner_signing_key = SigningKey::generate(&mut OsRng);
    let owner_verifying_key = owner_signing_key.verifying_key();
    let owner_id: MemberId = owner_verifying_key.into();

    // Create four members
    let (member_a, _) = create_test_member(owner_id, owner_id);
    let (member_b, _) = create_test_member(owner_id, owner_id);
    let (member_c, _) = create_test_member(owner_id, owner_id);
    let (member_d, _) = create_test_member(owner_id, owner_id);

    let auth_a = create_authorized_member(member_a.clone(), &owner_signing_key);
    let auth_b = create_authorized_member(member_b.clone(), &owner_signing_key);
    let auth_c = create_authorized_member(member_c.clone(), &owner_signing_key);
    let auth_d = create_authorized_member(member_d.clone(), &owner_signing_key);

    let parent_state = ChatBoardStateV1::default();

    let parameters = ChatBoardParametersV1 {
        owner: owner_verifying_key,
    };

    // Peer 1: Apply [A, B] then [C, D]
    let mut state_1 = MembersV1::default();
    let delta_1 = MembersDelta::new(vec![auth_a.clone(), auth_b.clone()]);
    state_1
        .apply_delta(&parent_state, &parameters, &Some(delta_1))
        .expect("apply_delta should succeed");
    let delta_2 = MembersDelta::new(vec![auth_c.clone(), auth_d.clone()]);
    state_1
        .apply_delta(&parent_state, &parameters, &Some(delta_2))
        .expect("apply_delta should succeed");

    // Peer 2: Apply [C, D] then [A, B]
    let mut state_2 = MembersV1::default();
    let delta_1 = MembersDelta::new(vec![auth_c.clone(), auth_d.clone()]);
    state_2
        .apply_delta(&parent_state, &parameters, &Some(delta_1))
        .expect("apply_delta should succeed");
    let delta_2 = MembersDelta::new(vec![auth_a.clone(), auth_b.clone()]);
    state_2
        .apply_delta(&parent_state, &parameters, &Some(delta_2))
        .expect("apply_delta should succeed");

    // Both should converge to the same state
    let mut ids_1: Vec<_> = state_1.members.iter().map(|m| m.member.id()).collect();
    let mut ids_2: Vec<_> = state_2.members.iter().map(|m| m.member.id()).collect();
    ids_1.sort();
    ids_2.sort();

    assert_eq!(
        ids_1, ids_2,
        "CONVERGENCE FAILURE: Different delta application orders produced different states!\n\
         Peer 1 applied [A,B] then [C,D]: {:?}\n\
         Peer 2 applied [C,D] then [A,B]: {:?}",
        ids_1, ids_2
    );
}

// =============================================================================
// STRESS TESTS WITH REALISTIC SIZES
// =============================================================================

/// Stress test: 50+ members with various invite chain depths
/// Tests that convergence holds under realistic member counts
#[test]
fn test_member_convergence_stress_50_members() {
    let owner_signing_key = SigningKey::generate(&mut OsRng);
    let owner_verifying_key = owner_signing_key.verifying_key();
    let owner_id: MemberId = owner_verifying_key.into();

    // Create a hierarchy of members with varying invite chain depths
    // Level 0: members invited directly by owner
    // Level 1: members invited by level 0
    // Level 2: members invited by level 1
    // etc.

    let mut all_members: Vec<(AuthorizedMember, SigningKey)> = Vec::new();
    let mut level_0_members: Vec<(AuthorizedMember, SigningKey)> = Vec::new();

    // Create 15 level-0 members (invited by owner)
    for _ in 0..15 {
        let (member, signing_key) = create_test_member(owner_id, owner_id);
        let auth_member = create_authorized_member(member, &owner_signing_key);
        level_0_members.push((auth_member.clone(), signing_key.clone()));
        all_members.push((auth_member, signing_key));
    }

    // Create 20 level-1 members (invited by level-0 members)
    let mut level_1_members: Vec<(AuthorizedMember, SigningKey)> = Vec::new();
    for i in 0..20 {
        let inviter_idx = i % level_0_members.len();
        let inviter = &level_0_members[inviter_idx];
        let (member, signing_key) = create_test_member(owner_id, inviter.0.member.id());
        let auth_member = create_authorized_member(member, &inviter.1);
        level_1_members.push((auth_member.clone(), signing_key.clone()));
        all_members.push((auth_member, signing_key));
    }

    // Create 15 level-2 members (invited by level-1 members)
    for i in 0..15 {
        let inviter_idx = i % level_1_members.len();
        let inviter = &level_1_members[inviter_idx];
        let (member, signing_key) = create_test_member(owner_id, inviter.0.member.id());
        let auth_member = create_authorized_member(member, &inviter.1);
        all_members.push((auth_member, signing_key));
    }

    assert_eq!(all_members.len(), 50);

    // No pruning - all members kept
    let parent_state = ChatBoardStateV1::default();

    let parameters = ChatBoardParametersV1 {
        owner: owner_verifying_key,
    };

    // Create multiple permutations of the member list
    let auth_members: Vec<AuthorizedMember> = all_members.iter().map(|(m, _)| m.clone()).collect();

    // State A: Original order
    let mut state_a = MembersV1 {
        members: auth_members.clone(),
    };
    state_a
        .apply_delta(&parent_state, &parameters, &None)
        .expect("apply_delta should succeed");

    // State B: Reversed order
    let mut reversed = auth_members.clone();
    reversed.reverse();
    let mut state_b = MembersV1 { members: reversed };
    state_b
        .apply_delta(&parent_state, &parameters, &None)
        .expect("apply_delta should succeed");

    // State C: Shuffled order (rotate by 17)
    let mut rotated = auth_members.clone();
    rotated.rotate_left(17);
    let mut state_c = MembersV1 { members: rotated };
    state_c
        .apply_delta(&parent_state, &parameters, &None)
        .expect("apply_delta should succeed");

    // All states should have all 50 members (no pruning)
    assert_eq!(state_a.members.len(), 50, "State A should have 50 members");
    assert_eq!(state_b.members.len(), 50, "State B should have 50 members");
    assert_eq!(state_c.members.len(), 50, "State C should have 50 members");

    // All states should have the SAME members
    let mut ids_a: Vec<_> = state_a.members.iter().map(|m| m.member.id()).collect();
    let mut ids_b: Vec<_> = state_b.members.iter().map(|m| m.member.id()).collect();
    let mut ids_c: Vec<_> = state_c.members.iter().map(|m| m.member.id()).collect();
    ids_a.sort();
    ids_b.sort();
    ids_c.sort();

    assert_eq!(
        ids_a, ids_b,
        "CONVERGENCE FAILURE: State A and B have different members"
    );
    assert_eq!(
        ids_b, ids_c,
        "CONVERGENCE FAILURE: State B and C have different members"
    );
}

/// Stress test: Multiple bans with same timestamps
#[test]
fn test_ban_convergence_stress_same_timestamps() {
    use std::collections::HashSet;

    let owner_signing_key = SigningKey::generate(&mut OsRng);
    let owner_verifying_key = owner_signing_key.verifying_key();
    let owner_id: MemberId = owner_verifying_key.into();

    // Create 20 members
    let mut members: Vec<AuthorizedMember> = Vec::new();
    for _ in 0..20 {
        let (member, _) = create_test_member(owner_id, owner_id);
        let auth_member = create_authorized_member(member, &owner_signing_key);
        members.push(auth_member);
    }

    // Create 15 bans with the SAME timestamp
    let same_time = SystemTime::now();
    let mut bans: Vec<AuthorizedUserBan> = Vec::new();
    for member in members.iter().take(15) {
        let ban = AuthorizedUserBan::new(
            UserBan {
                owner_member_id: owner_id,
                banned_at: same_time,
                banned_user: member.member.id(),
                expires_at: None,
                target_member: None,
                invite_chain: Vec::new(),
            },
            owner_id,
            &owner_signing_key,
        );
        bans.push(ban);
    }

    // Set max_user_bans to 10 (need to reject 5)
    let mut parent_state = ChatBoardStateV1::default();
    parent_state.configuration.configuration.max_user_bans = 10;
    parent_state.members = MembersV1 {
        members: members.clone(),
    };

    let parameters = ChatBoardParametersV1 {
        owner: owner_verifying_key,
    };

    // Helper to extract BanIds from error message
    fn extract_ban_ids(err: &str) -> HashSet<String> {
        // Error format: "Invalid bans: BanId(BoardId(...)): ..."
        err.split("BanId(BoardId(")
            .skip(1)
            .filter_map(|s| s.split("))").next())
            .map(|s| s.to_string())
            .collect()
    }

    // State A: Original order
    let bans_a = BansV1(bans.clone());

    // State B: Reversed order
    let mut reversed = bans.clone();
    reversed.reverse();
    let bans_b = BansV1(reversed);

    // State C: Rotated order
    let mut rotated = bans.clone();
    rotated.rotate_left(7);
    let bans_c = BansV1(rotated);

    // All should fail verification identifying the same excess bans
    let err_a = bans_a.verify(&parent_state, &parameters).unwrap_err();
    let err_b = bans_b.verify(&parent_state, &parameters).unwrap_err();
    let err_c = bans_c.verify(&parent_state, &parameters).unwrap_err();

    // Extract the BanIds from each error (the error message order may vary due to HashMap)
    let ids_a = extract_ban_ids(&err_a);
    let ids_b = extract_ban_ids(&err_b);
    let ids_c = extract_ban_ids(&err_c);

    assert_eq!(
        ids_a, ids_b,
        "CONVERGENCE FAILURE: State A and B identified different excess bans"
    );
    assert_eq!(
        ids_b, ids_c,
        "CONVERGENCE FAILURE: State B and C identified different excess bans"
    );

    // Verify we identified exactly 5 excess bans
    assert_eq!(ids_a.len(), 5, "Should identify exactly 5 excess bans");
}

// =============================================================================
// PROPERTY-BASED STYLE TESTS
// =============================================================================

/// Property test: Any permutation of member additions should produce the same state
#[test]
fn test_member_permutation_convergence() {
    let owner_signing_key = SigningKey::generate(&mut OsRng);
    let owner_verifying_key = owner_signing_key.verifying_key();
    let owner_id: MemberId = owner_verifying_key.into();

    // Create 10 members
    let mut members: Vec<AuthorizedMember> = Vec::new();
    for _ in 0..10 {
        let (member, _) = create_test_member(owner_id, owner_id);
        let auth_member = create_authorized_member(member, &owner_signing_key);
        members.push(auth_member);
    }

    let parent_state = ChatBoardStateV1::default();

    let parameters = ChatBoardParametersV1 {
        owner: owner_verifying_key,
    };

    // Generate multiple permutations
    let permutations: Vec<Vec<AuthorizedMember>> = vec![
        members.clone(),
        members.iter().rev().cloned().collect(),
        {
            let mut p = members.clone();
            p.rotate_left(3);
            p
        },
        {
            let mut p = members.clone();
            p.rotate_right(5);
            p
        },
        {
            // Interleave odd and even indices
            let mut p: Vec<AuthorizedMember> = Vec::new();
            for i in (0..members.len()).step_by(2) {
                p.push(members[i].clone());
            }
            for i in (1..members.len()).step_by(2) {
                p.push(members[i].clone());
            }
            p
        },
    ];

    // Apply each permutation and collect resulting member IDs
    let mut results: Vec<Vec<MemberId>> = Vec::new();
    for perm in permutations {
        let mut state = MembersV1 { members: perm };
        state
            .apply_delta(&parent_state, &parameters, &None)
            .expect("apply_delta should succeed");
        let mut ids: Vec<_> = state.members.iter().map(|m| m.member.id()).collect();
        ids.sort();
        results.push(ids);
    }

    // All results should be identical
    let first = &results[0];
    for (i, result) in results.iter().enumerate().skip(1) {
        assert_eq!(
            first, result,
            "CONVERGENCE FAILURE: Permutation {} produced different result than permutation 0",
            i
        );
    }
}

/// Property test: Random operation sequences should converge
#[test]
fn test_random_operation_sequence_convergence() {
    use rand::seq::SliceRandom;
    use rand::SeedableRng;

    let owner_signing_key = SigningKey::generate(&mut OsRng);
    let owner_verifying_key = owner_signing_key.verifying_key();
    let owner_id: MemberId = owner_verifying_key.into();

    // Create a pool of members
    let mut member_pool: Vec<(AuthorizedMember, SigningKey)> = Vec::new();
    for _ in 0..20 {
        let (member, signing_key) = create_test_member(owner_id, owner_id);
        let auth_member = create_authorized_member(member, &owner_signing_key);
        member_pool.push((auth_member, signing_key));
    }

    let parent_state = ChatBoardStateV1::default();

    let parameters = ChatBoardParametersV1 {
        owner: owner_verifying_key,
    };

    // Create operation sequences (add members in different orders)
    let member_refs: Vec<&AuthorizedMember> = member_pool.iter().map(|(m, _)| m).collect();

    // Use a fixed seed for reproducibility
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);

    let mut sequences: Vec<Vec<AuthorizedMember>> = Vec::new();
    for _ in 0..5 {
        let mut seq: Vec<&AuthorizedMember> = member_refs.clone();
        seq.shuffle(&mut rng);
        sequences.push(seq.into_iter().cloned().collect());
    }

    // Apply each sequence via deltas
    let mut final_states: Vec<Vec<MemberId>> = Vec::new();
    for seq in sequences {
        let mut state = MembersV1::default();
        // Apply in batches of 4
        for chunk in seq.chunks(4) {
            let delta = MembersDelta::new(chunk.to_vec());
            state
                .apply_delta(&parent_state, &parameters, &Some(delta))
                .expect("apply_delta should succeed");
        }
        let mut ids: Vec<_> = state.members.iter().map(|m| m.member.id()).collect();
        ids.sort();
        final_states.push(ids);
    }

    // All final states should be identical
    let first = &final_states[0];
    for (i, state) in final_states.iter().enumerate().skip(1) {
        assert_eq!(
            first, state,
            "CONVERGENCE FAILURE: Sequence {} produced different final state",
            i
        );
    }
}

// =============================================================================
// EDGE CASE TESTS
// =============================================================================

/// Edge case: All members are kept
#[test]
fn test_member_exactly_at_capacity() {
    let owner_signing_key = SigningKey::generate(&mut OsRng);
    let owner_verifying_key = owner_signing_key.verifying_key();
    let owner_id: MemberId = owner_verifying_key.into();

    // Create exactly 5 members
    let mut members: Vec<AuthorizedMember> = Vec::new();
    for _ in 0..5 {
        let (member, _) = create_test_member(owner_id, owner_id);
        let auth_member = create_authorized_member(member, &owner_signing_key);
        members.push(auth_member);
    }

    let parent_state = ChatBoardStateV1::default();

    let parameters = ChatBoardParametersV1 {
        owner: owner_verifying_key,
    };

    // State A: Original order
    let mut state_a = MembersV1 {
        members: members.clone(),
    };
    state_a
        .apply_delta(&parent_state, &parameters, &None)
        .expect("apply_delta should succeed");

    // State B: Reversed order
    let mut reversed = members.clone();
    reversed.reverse();
    let mut state_b = MembersV1 { members: reversed };
    state_b
        .apply_delta(&parent_state, &parameters, &None)
        .expect("apply_delta should succeed");

    // Both should have exactly 5 members and the same members
    assert_eq!(state_a.members.len(), 5);
    assert_eq!(state_b.members.len(), 5);

    let mut ids_a: Vec<_> = state_a.members.iter().map(|m| m.member.id()).collect();
    let mut ids_b: Vec<_> = state_b.members.iter().map(|m| m.member.id()).collect();
    ids_a.sort();
    ids_b.sort();

    assert_eq!(ids_a, ids_b, "At capacity, all members should be preserved");
}

/// Edge case: Members beyond old capacity limit (no pruning now)
#[test]
fn test_member_one_over_capacity() {
    let owner_signing_key = SigningKey::generate(&mut OsRng);
    let owner_verifying_key = owner_signing_key.verifying_key();
    let owner_id: MemberId = owner_verifying_key.into();

    // Create 6 members
    let mut members: Vec<AuthorizedMember> = Vec::new();
    for _ in 0..6 {
        let (member, _) = create_test_member(owner_id, owner_id);
        let auth_member = create_authorized_member(member, &owner_signing_key);
        members.push(auth_member);
    }

    let parent_state = ChatBoardStateV1::default();

    let parameters = ChatBoardParametersV1 {
        owner: owner_verifying_key,
    };

    // State A: Original order
    let mut state_a = MembersV1 {
        members: members.clone(),
    };
    state_a
        .apply_delta(&parent_state, &parameters, &None)
        .expect("apply_delta should succeed");

    // State B: Reversed order
    let mut reversed = members.clone();
    reversed.reverse();
    let mut state_b = MembersV1 { members: reversed };
    state_b
        .apply_delta(&parent_state, &parameters, &None)
        .expect("apply_delta should succeed");

    // All 6 members should be kept (no pruning)
    assert_eq!(state_a.members.len(), 6);
    assert_eq!(state_b.members.len(), 6);

    let mut ids_a: Vec<_> = state_a.members.iter().map(|m| m.member.id()).collect();
    let mut ids_b: Vec<_> = state_b.members.iter().map(|m| m.member.id()).collect();
    ids_a.sort();
    ids_b.sort();

    assert_eq!(ids_a, ids_b, "All members should be preserved");
}

/// Edge case: Deep invite chains (10+ levels) - all kept now
#[test]
fn test_deep_invite_chains() {
    let owner_signing_key = SigningKey::generate(&mut OsRng);
    let owner_verifying_key = owner_signing_key.verifying_key();
    let owner_id: MemberId = owner_verifying_key.into();

    // Create a chain of 12 members, each inviting the next
    let mut chain: Vec<(AuthorizedMember, SigningKey)> = Vec::new();

    // First member invited by owner
    let (first_member, first_sk) = create_test_member(owner_id, owner_id);
    let first_auth = create_authorized_member(first_member.clone(), &owner_signing_key);
    chain.push((first_auth, first_sk));

    // Each subsequent member invited by the previous
    for _ in 1..12 {
        let (prev_auth, prev_sk) = chain.last().unwrap();
        let (member, signing_key) = create_test_member(owner_id, prev_auth.member.id());
        let auth_member = create_authorized_member(member, prev_sk);
        chain.push((auth_member, signing_key));
    }

    // Also create 3 members at depth 0 (invited by owner)
    let mut depth_0_members: Vec<AuthorizedMember> = Vec::new();
    for _ in 0..3 {
        let (member, _) = create_test_member(owner_id, owner_id);
        let auth_member = create_authorized_member(member, &owner_signing_key);
        depth_0_members.push(auth_member);
    }

    // Combine all members (12 + 3 = 15)
    let mut all_members: Vec<AuthorizedMember> = chain.iter().map(|(m, _)| m.clone()).collect();
    all_members.extend(depth_0_members);

    let parent_state = ChatBoardStateV1::default();

    let parameters = ChatBoardParametersV1 {
        owner: owner_verifying_key,
    };

    // All members should be kept (no pruning)
    let mut state_a = MembersV1 {
        members: all_members.clone(),
    };
    state_a
        .apply_delta(&parent_state, &parameters, &None)
        .expect("apply_delta should succeed");

    let mut reversed = all_members.clone();
    reversed.reverse();
    let mut state_b = MembersV1 { members: reversed };
    state_b
        .apply_delta(&parent_state, &parameters, &None)
        .expect("apply_delta should succeed");

    // All 15 members should be kept
    assert_eq!(state_a.members.len(), 15);
    assert_eq!(state_b.members.len(), 15);

    let mut ids_a: Vec<_> = state_a.members.iter().map(|m| m.member.id()).collect();
    let mut ids_b: Vec<_> = state_b.members.iter().map(|m| m.member.id()).collect();
    ids_a.sort();
    ids_b.sort();

    assert_eq!(ids_a, ids_b, "All members should be preserved");
}

/// Edge case: Concurrent adds and removals (via bans) - bans still remove members
#[test]
fn test_concurrent_adds_and_bans() {
    let owner_signing_key = SigningKey::generate(&mut OsRng);
    let owner_verifying_key = owner_signing_key.verifying_key();
    let owner_id: MemberId = owner_verifying_key.into();

    // Create 8 members
    let mut members: Vec<AuthorizedMember> = Vec::new();
    for _ in 0..8 {
        let (member, _) = create_test_member(owner_id, owner_id);
        let auth_member = create_authorized_member(member, &owner_signing_key);
        members.push(auth_member);
    }

    // Ban 2 of them
    let ban_time = SystemTime::now();
    let bans = BansV1(vec![
        AuthorizedUserBan::new(
            UserBan {
                owner_member_id: owner_id,
                banned_at: ban_time,
                banned_user: members[0].member.id(),
                expires_at: None,
                target_member: None,
                invite_chain: Vec::new(),
            },
            owner_id,
            &owner_signing_key,
        ),
        AuthorizedUserBan::new(
            UserBan {
                owner_member_id: owner_id,
                banned_at: ban_time,
                banned_user: members[1].member.id(),
                expires_at: None,
                target_member: None,
                invite_chain: Vec::new(),
            },
            owner_id,
            &owner_signing_key,
        ),
    ]);

    let mut parent_state = ChatBoardStateV1::default();
    parent_state.configuration.configuration.max_user_bans = 10;
    parent_state.bans = bans;

    let parameters = ChatBoardParametersV1 {
        owner: owner_verifying_key,
    };

    // Apply members in different orders
    let mut state_a = MembersV1 {
        members: members.clone(),
    };
    state_a
        .apply_delta(&parent_state, &parameters, &None)
        .expect("apply_delta should succeed");

    let mut reversed = members.clone();
    reversed.reverse();
    let mut state_b = MembersV1 { members: reversed };
    state_b
        .apply_delta(&parent_state, &parameters, &None)
        .expect("apply_delta should succeed");

    // Both should have 6 members (8 - 2 banned = 6, no capacity cap)
    assert_eq!(state_a.members.len(), 6);
    assert_eq!(state_b.members.len(), 6);

    // Banned members should not be present
    let ids_a: Vec<_> = state_a.members.iter().map(|m| m.member.id()).collect();
    assert!(!ids_a.contains(&members[0].member.id()));
    assert!(!ids_a.contains(&members[1].member.id()));

    let mut ids_a_sorted = ids_a.clone();
    let mut ids_b: Vec<_> = state_b.members.iter().map(|m| m.member.id()).collect();
    ids_a_sorted.sort();
    ids_b.sort();

    assert_eq!(ids_a_sorted, ids_b, "States should converge after bans");
}

// =============================================================================
// REGRESSION TESTS
// =============================================================================

/// All members are now kept (no pruning) - verify convergence
#[test]
fn test_regression_member_truncation_order_dependent() {
    let owner_signing_key = SigningKey::generate(&mut OsRng);
    let owner_verifying_key = owner_signing_key.verifying_key();
    let owner_id: MemberId = owner_verifying_key.into();

    // Create 5 members with same invite chain length
    let mut members: Vec<AuthorizedMember> = Vec::new();
    for _ in 0..5 {
        let (member, _) = create_test_member(owner_id, owner_id);
        let auth_member = create_authorized_member(member, &owner_signing_key);
        members.push(auth_member);
    }

    let parent_state = ChatBoardStateV1::default();

    let parameters = ChatBoardParametersV1 {
        owner: owner_verifying_key,
    };

    let mut state_a = MembersV1::default();
    let delta_a = MembersDelta::new(members.clone());
    state_a
        .apply_delta(&parent_state, &parameters, &Some(delta_a))
        .expect("apply_delta should succeed");

    let mut reversed = members.clone();
    reversed.reverse();
    let mut state_b = MembersV1::default();
    let delta_b = MembersDelta::new(reversed);
    state_b
        .apply_delta(&parent_state, &parameters, &Some(delta_b))
        .expect("apply_delta should succeed");

    // All 5 members should be kept (no pruning)
    assert_eq!(state_a.members.len(), 5);
    assert_eq!(state_b.members.len(), 5);

    // Both should have the SAME members
    let mut ids_a: Vec<_> = state_a.members.iter().map(|m| m.member.id()).collect();
    let mut ids_b: Vec<_> = state_b.members.iter().map(|m| m.member.id()).collect();
    ids_a.sort();
    ids_b.sort();

    assert_eq!(ids_a, ids_b, "All orderings should converge to same result");
}

/// All members are now kept (no pruning) - verify convergence
#[test]
fn test_regression_member_excess_removal_tiebreak() {
    let owner_signing_key = SigningKey::generate(&mut OsRng);
    let owner_verifying_key = owner_signing_key.verifying_key();
    let owner_id: MemberId = owner_verifying_key.into();

    // Create 10 members all at same depth (invited by owner)
    let mut members: Vec<AuthorizedMember> = Vec::new();
    for _ in 0..10 {
        let (member, _) = create_test_member(owner_id, owner_id);
        let auth_member = create_authorized_member(member, &owner_signing_key);
        members.push(auth_member);
    }

    let parent_state = ChatBoardStateV1::default();

    let parameters = ChatBoardParametersV1 {
        owner: owner_verifying_key,
    };

    // Test multiple orderings to ensure convergence
    let mut first_result: Option<Vec<MemberId>> = None;

    for rotation in 0..10 {
        let mut rotated = members.clone();
        rotated.rotate_left(rotation);

        let mut state = MembersV1 { members: rotated };
        state
            .apply_delta(&parent_state, &parameters, &None)
            .expect("apply_delta should succeed");

        // All 10 members should be kept
        assert_eq!(state.members.len(), 10);

        let mut ids: Vec<_> = state.members.iter().map(|m| m.member.id()).collect();
        ids.sort();

        if let Some(ref first) = first_result {
            assert_eq!(first, &ids, "All orderings should converge to same result");
        } else {
            first_result = Some(ids);
        }
    }
}

/// Regression test: Ban excess identification
/// Before fix: sort_by_key on timestamp was unstable for equal timestamps
/// After fix: Secondary sort by BanId provides deterministic ordering
#[test]
fn test_regression_ban_excess_identification() {
    use std::collections::HashSet;

    let owner_signing_key = SigningKey::generate(&mut OsRng);
    let owner_verifying_key = owner_signing_key.verifying_key();
    let owner_id: MemberId = owner_verifying_key.into();

    // Create members to ban
    let mut members: Vec<AuthorizedMember> = Vec::new();
    for _ in 0..10 {
        let (member, _) = create_test_member(owner_id, owner_id);
        let auth_member = create_authorized_member(member, &owner_signing_key);
        members.push(auth_member);
    }

    // Create 8 bans with identical timestamps
    let same_time = SystemTime::now();
    let mut bans: Vec<AuthorizedUserBan> = Vec::new();
    for member in members.iter().take(8) {
        let ban = AuthorizedUserBan::new(
            UserBan {
                owner_member_id: owner_id,
                banned_at: same_time,
                banned_user: member.member.id(),
                expires_at: None,
                target_member: None,
                invite_chain: Vec::new(),
            },
            owner_id,
            &owner_signing_key,
        );
        bans.push(ban);
    }

    let mut parent_state = ChatBoardStateV1::default();
    parent_state.configuration.configuration.max_user_bans = 5;
    parent_state.members = MembersV1 {
        members: members.clone(),
    };

    let parameters = ChatBoardParametersV1 {
        owner: owner_verifying_key,
    };

    // OLD BEHAVIOR (before fix):
    // sort_by_key with equal timestamps would produce unstable ordering,
    // meaning different orderings of the same bans could identify different
    // bans as "excess".

    // NEW BEHAVIOR (after fix):
    // Secondary sort by BanId ensures deterministic identification of excess bans.

    // Helper to extract BanIds from error message
    fn extract_ban_ids(err: &str) -> HashSet<String> {
        err.split("BanId(BoardId(")
            .skip(1)
            .filter_map(|s| s.split("))").next())
            .map(|s| s.to_string())
            .collect()
    }

    // Collect the sets of identified excess bans from multiple orderings
    let mut ban_id_sets: Vec<HashSet<String>> = Vec::new();

    for rotation in 0..8 {
        let mut rotated = bans.clone();
        rotated.rotate_left(rotation);
        let bans_state = BansV1(rotated);
        let err = bans_state.verify(&parent_state, &parameters).unwrap_err();
        ban_id_sets.push(extract_ban_ids(&err));
    }

    // All sets should identify the same BanIds as excess
    let first = &ban_id_sets[0];
    for (i, ban_ids) in ban_id_sets.iter().enumerate().skip(1) {
        assert_eq!(
            first, ban_ids,
            "REGRESSION: Ban excess identification is non-deterministic!\n\
             Rotation {} identified different excess bans. This would have failed before the fix.",
            i
        );
    }

    // Verify we identified exactly 3 excess bans (8 - 5 = 3)
    assert_eq!(first.len(), 3, "Should identify exactly 3 excess bans");
}

// =============================================================================
// SERIALIZED COMMUTATIVITY TEST
// =============================================================================
//
// This test verifies that merge(A,B) == merge(B,A) at the serialized byte level.
// This is the ultimate convergence test: two peers starting from different initial
// states must produce identical serialized output after merging the other's state.

use plaza_core::board_state::member_info::{AuthorizedMemberInfo, MemberInfo};

#[test]
fn test_full_state_merge_commutativity() {
    let owner_signing_key = SigningKey::generate(&mut OsRng);
    let owner_verifying_key = owner_signing_key.verifying_key();
    let owner_id: MemberId = owner_verifying_key.into();

    let parameters = ChatBoardParametersV1 {
        owner: owner_verifying_key,
    };

    // Create members
    let (member_a, member_a_sk) = create_test_member(owner_id, owner_id);
    let (member_b, member_b_sk) = create_test_member(owner_id, owner_id);
    let (member_c, _member_c_sk) = create_test_member(owner_id, owner_id);

    let auth_member_a = create_authorized_member(member_a.clone(), &owner_signing_key);
    let auth_member_b = create_authorized_member(member_b.clone(), &owner_signing_key);
    let auth_member_c = create_authorized_member(member_c.clone(), &owner_signing_key);

    // Create member info
    let info_a = AuthorizedMemberInfo::new_with_member_key(
        MemberInfo::new_public(member_a.id(), 1, "Alice".to_string()),
        &member_a_sk,
    );
    let info_b = AuthorizedMemberInfo::new_with_member_key(
        MemberInfo::new_public(member_b.id(), 1, "Bob".to_string()),
        &member_b_sk,
    );
    let owner_info = AuthorizedMemberInfo::new(
        MemberInfo::new_public(owner_id, 1, "Owner".to_string()),
        &owner_signing_key,
    );

    // ---- State A: has members [A, C], info [owner, A] ----
    let mut state_a = ChatBoardStateV1::default();
    state_a.configuration.configuration.max_message_size = 1000;
    state_a.members.members.push(auth_member_a.clone());
    state_a.members.members.push(auth_member_c.clone());
    state_a.member_info.member_info.push(owner_info.clone());
    state_a.member_info.member_info.push(info_a.clone());

    // ---- State B: has members [B, C], info [owner, B] ----
    let mut state_b = ChatBoardStateV1::default();
    state_b.configuration.configuration.max_message_size = 1000;
    state_b.members.members.push(auth_member_b.clone());
    state_b.members.members.push(auth_member_c.clone());
    state_b.member_info.member_info.push(owner_info.clone());
    state_b.member_info.member_info.push(info_b.clone());

    // ---- merge(A, B): start from A, merge in B ----
    let mut merged_ab = state_a.clone();
    merged_ab
        .merge(&state_a, &parameters, &state_b)
        .expect("merge A+B should succeed");

    // ---- merge(B, A): start from B, merge in A ----
    let mut merged_ba = state_b.clone();
    merged_ba
        .merge(&state_b, &parameters, &state_a)
        .expect("merge B+A should succeed");

    // Serialize both results
    let mut bytes_ab = Vec::new();
    ciborium::ser::into_writer(&merged_ab, &mut bytes_ab).expect("serialize merged_ab");
    let mut bytes_ba = Vec::new();
    ciborium::ser::into_writer(&merged_ba, &mut bytes_ba).expect("serialize merged_ba");

    // The serialized bytes must be identical
    assert_eq!(
        bytes_ab,
        bytes_ba,
        "COMMUTATIVITY FAILURE: merge(A,B) != merge(B,A) at byte level!\n\
         merged_ab members: {:?}\n\
         merged_ba members: {:?}\n\
         merged_ab member_info: {:?}\n\
         merged_ba member_info: {:?}",
        merged_ab
            .members
            .members
            .iter()
            .map(|m| m.member.id())
            .collect::<Vec<_>>(),
        merged_ba
            .members
            .members
            .iter()
            .map(|m| m.member.id())
            .collect::<Vec<_>>(),
        merged_ab
            .member_info
            .member_info
            .iter()
            .map(|i| i.member_info.member_id)
            .collect::<Vec<_>>(),
        merged_ba
            .member_info
            .member_info
            .iter()
            .map(|i| i.member_info.member_id)
            .collect::<Vec<_>>(),
    );
}

// =============================================================================
// REGRESSION TESTS
// =============================================================================

/// Regression test: Combined scenario testing all fixes together
/// This test exercises all the convergence fixes in a realistic scenario
#[test]
fn test_regression_combined_scenario() {
    let owner_signing_key = SigningKey::generate(&mut OsRng);
    let owner_verifying_key = owner_signing_key.verifying_key();
    let owner_id: MemberId = owner_verifying_key.into();

    // Create a realistic board state with:
    // - 30 members with varying invite depths
    // - 3 bans with same timestamps

    // Create member hierarchy
    let mut members: Vec<(AuthorizedMember, SigningKey)> = Vec::new();
    let mut level_0: Vec<(AuthorizedMember, SigningKey)> = Vec::new();

    // 10 level-0 members
    for _ in 0..10 {
        let (member, signing_key) = create_test_member(owner_id, owner_id);
        let auth_member = create_authorized_member(member, &owner_signing_key);
        level_0.push((auth_member.clone(), signing_key.clone()));
        members.push((auth_member, signing_key));
    }

    // 15 level-1 members
    for i in 0..15 {
        let inviter = &level_0[i % level_0.len()];
        let (member, signing_key) = create_test_member(owner_id, inviter.0.member.id());
        let auth_member = create_authorized_member(member, &inviter.1);
        members.push((auth_member, signing_key));
    }

    // 5 level-2 members (these should be removed first when over capacity)
    for i in 0..5 {
        let inviter = &members[10 + (i % 15)]; // Pick from level-1
        let (member, signing_key) = create_test_member(owner_id, inviter.0.member.id());
        let auth_member = create_authorized_member(member, &inviter.1);
        members.push((auth_member, signing_key));
    }

    assert_eq!(members.len(), 30);

    // Create bans (ban some level-2 members)
    let ban_time = SystemTime::now();
    let mut bans: Vec<AuthorizedUserBan> = Vec::new();
    for i in 0..3 {
        let ban = AuthorizedUserBan::new(
            UserBan {
                owner_member_id: owner_id,
                banned_at: ban_time,                        // Same timestamp
                banned_user: members[25 + i].0.member.id(), // Ban level-2 members
                expires_at: None,
                target_member: None,
                invite_chain: Vec::new(),
            },
            owner_id,
            &owner_signing_key,
        );
        bans.push(ban);
    }

    // Set up parent state with limits
    let mut parent_state = ChatBoardStateV1::default();
    parent_state.configuration.configuration.max_message_size = 1000;
    parent_state.configuration.configuration.max_user_bans = 10;
    parent_state.bans = BansV1(bans);

    let parameters = ChatBoardParametersV1 {
        owner: owner_verifying_key,
    };

    // Test convergence with multiple orderings
    let member_list: Vec<AuthorizedMember> = members.iter().map(|(m, _)| m.clone()).collect();

    let orderings = vec![
        member_list.clone(),
        member_list.iter().rev().cloned().collect(),
        {
            let mut m = member_list.clone();
            m.rotate_left(11);
            m
        },
    ];

    let mut final_states: Vec<Vec<MemberId>> = Vec::new();

    for member_ordering in orderings {
        let mut local_parent = parent_state.clone();
        local_parent.members = MembersV1 {
            members: member_ordering,
        };
        local_parent
            .members
            .apply_delta(&parent_state, &parameters, &None)
            .expect("members apply_delta should succeed");

        let mut member_ids: Vec<_> = local_parent
            .members
            .members
            .iter()
            .map(|m| m.member.id())
            .collect();
        member_ids.sort();

        final_states.push(member_ids);
    }

    // All final states should be identical
    let first_members = &final_states[0];
    for (i, members_result) in final_states.iter().enumerate().skip(1) {
        assert_eq!(
            first_members, members_result,
            "REGRESSION: Combined scenario - members don't converge for ordering {}",
            i
        );
    }
}

// =============================================================================
// BAN + MEMBER MERGE CONVERGENCE TESTS
// =============================================================================
//
// These tests verify that merging two diverged states with bans and members
// works correctly. The key issue: the #[composable] macro applies field deltas
// in declaration order (bans before members). When state B has a ban from
// member X who doesn't exist in state A, the ban delta is applied before the
// member delta adds X. verify() must tolerate this.
//
// BUG: Before the fix, verify() in ban.rs would fail with
// "Banning member MemberId(...) not found in members list" because it checked
// parent_state.members (pre-merge state A) for a member only present in state B.
//
// FIX: Skip signature verification for banning members not yet in the members
// list during merge. clean_orphaned_bans post-hook removes invalid bans after
// all fields are applied.

use plaza_core::board_state::configuration::{AuthorizedConfigurationV1, Configuration};

/// Helper to create a signed configuration for tests
fn create_test_config(owner_sk: &SigningKey) -> AuthorizedConfigurationV1 {
    AuthorizedConfigurationV1::new(
        Configuration {
            max_user_bans: 10,
            max_message_size: 1000,
            updated_at: std::time::SystemTime::UNIX_EPOCH,
            ..Default::default()
        },
        owner_sk,
    )
}

/// Regression test: merge two states where state B has bans from a member
/// not present in state A. This is the exact scenario that caused the
/// "Banning member not found" error in production (Feb 2026).
///
/// Scenario: State A is stale (8 hours old). Member X joined after the snapshot,
/// invited Y, then banned Y. State B reflects the current state with X present
/// and Y already removed (ban took effect). When A merges B, the ban delta
/// arrives before the member delta, and verify() must tolerate X not being in
/// A's members list.
#[test]
fn test_merge_with_bans_from_member_not_in_other_state() {
    let owner_sk = SigningKey::generate(&mut OsRng);
    let owner_vk = owner_sk.verifying_key();
    let owner_id: MemberId = owner_vk.into();

    let parameters = ChatBoardParametersV1 { owner: owner_vk };
    let config = create_test_config(&owner_sk);

    // Member X (invited by owner)
    let (member_x, member_x_sk) = create_test_member(owner_id, owner_id);
    let member_x_id = member_x.id();
    let auth_member_x = create_authorized_member(member_x.clone(), &owner_sk);

    // Member Y (invited by X — so X can ban Y)
    let (member_y, _) = create_test_member(owner_id, member_x_id);
    let member_y_id = member_y.id();
    let auth_member_y = create_authorized_member(member_y.clone(), &member_x_sk);

    // Member Z (invited by owner, present in both states)
    let (member_z, _member_z_sk) = create_test_member(owner_id, owner_id);
    let auth_member_z = create_authorized_member(member_z.clone(), &owner_sk);

    // X bans Y (X is in Y's invite chain since X invited Y)
    let ban_y_by_x = AuthorizedUserBan::new(
        UserBan {
            owner_member_id: owner_id,
            banned_at: SystemTime::now(),
            banned_user: member_y_id,
            expires_at: None,
            target_member: Some(auth_member_y),
            invite_chain: vec![auth_member_x.clone()],
        },
        member_x_id,
        &member_x_sk,
    );

    // ---- State A (stale): has Z only, no bans, never saw X or Y ----
    let state_a = ChatBoardStateV1 {
        configuration: config.clone(),
        members: MembersV1 {
            members: vec![auth_member_z.clone()],
        },
        ..Default::default()
    };

    // ---- State B (current): has X and Z; Y already removed by ban ----
    let state_b = ChatBoardStateV1 {
        configuration: config,
        members: MembersV1 {
            members: vec![auth_member_x.clone(), auth_member_z.clone()],
        },
        bans: BansV1(vec![ban_y_by_x.clone()]),
        ..Default::default()
    };

    // merge(A, B) — A doesn't have member X, but B's ban references X as banned_by.
    // The ban delta is applied BEFORE the member delta (field order in struct).
    // This is where the old code would fail with "Banning member not found".
    let mut merged_ab = state_a.clone();
    merged_ab
        .merge(&state_a, &parameters, &state_b)
        .expect("merge A+B should succeed — banning member X is added by members delta");

    // X should be in final state, Y was already removed, Z present
    let final_member_ids: Vec<MemberId> = merged_ab
        .members
        .members
        .iter()
        .map(|m| m.member.id())
        .collect();
    assert!(
        final_member_ids.contains(&member_x_id),
        "Member X should be present after merge"
    );
    assert!(
        !final_member_ids.contains(&member_y_id),
        "Member Y should not appear (already removed in state B)"
    );
    assert!(
        final_member_ids.contains(&member_z.id()),
        "Member Z should be present after merge"
    );

    // Ban should be retained since X is in final members
    assert_eq!(merged_ab.bans.0.len(), 1, "Ban should be retained");
    assert_eq!(merged_ab.bans.0[0].banned_by, member_x_id);

    // Final state must pass verification
    assert!(
        merged_ab.verify(&merged_ab, &parameters).is_ok(),
        "Merged state should verify: {:?}",
        merged_ab.verify(&merged_ab, &parameters)
    );
}

/// Commutativity test: merge(A,B) == merge(B,A) when states have diverged
/// with owner-issued bans. Both orderings must produce identical serialized output.
///
/// Uses owner bans to avoid invite chain complications — the key test here is
/// that merge with bans from unknown members is commutative.
#[test]
fn test_merge_commutativity_with_owner_bans() {
    let owner_sk = SigningKey::generate(&mut OsRng);
    let owner_vk = owner_sk.verifying_key();
    let owner_id: MemberId = owner_vk.into();

    let parameters = ChatBoardParametersV1 { owner: owner_vk };
    let config = create_test_config(&owner_sk);

    // All members invited by owner
    let (member_a, _member_a_sk) = create_test_member(owner_id, owner_id);
    let member_a_id = member_a.id();
    let auth_member_a = create_authorized_member(member_a.clone(), &owner_sk);

    let (member_b, _member_b_sk) = create_test_member(owner_id, owner_id);
    let auth_member_b = create_authorized_member(member_b.clone(), &owner_sk);

    let (member_c, _member_c_sk) = create_test_member(owner_id, owner_id);
    let auth_member_c = create_authorized_member(member_c.clone(), &owner_sk);

    let (member_d, _member_d_sk) = create_test_member(owner_id, owner_id);
    let member_d_id = member_d.id();
    let auth_member_d = create_authorized_member(member_d.clone(), &owner_sk);

    // Owner bans A (in state 2)
    let ban_a = AuthorizedUserBan::new(
        UserBan {
            owner_member_id: owner_id,
            banned_at: SystemTime::now(),
            banned_user: member_a_id,
            expires_at: None,
            target_member: None,
            invite_chain: Vec::new(),
        },
        owner_id,
        &owner_sk,
    );

    // Owner bans D (in state 1)
    let ban_d = AuthorizedUserBan::new(
        UserBan {
            owner_member_id: owner_id,
            banned_at: SystemTime::now() + std::time::Duration::from_secs(1),
            banned_user: member_d_id,
            expires_at: None,
            target_member: None,
            invite_chain: Vec::new(),
        },
        owner_id,
        &owner_sk,
    );

    // ---- State 1: has A, B, C; owner banned D (D removed) ----
    let state_1 = ChatBoardStateV1 {
        configuration: config.clone(),
        members: MembersV1 {
            members: vec![
                auth_member_a.clone(),
                auth_member_b.clone(),
                auth_member_c.clone(),
            ],
        },
        bans: BansV1(vec![ban_d.clone()]),
        ..Default::default()
    };

    // ---- State 2: has B, C, D; owner banned A (A removed) ----
    let state_2 = ChatBoardStateV1 {
        configuration: config,
        members: MembersV1 {
            members: vec![
                auth_member_b.clone(),
                auth_member_c.clone(),
                auth_member_d.clone(),
            ],
        },
        bans: BansV1(vec![ban_a.clone()]),
        ..Default::default()
    };

    // merge(1, 2)
    let mut merged_12 = state_1.clone();
    merged_12
        .merge(&state_1, &parameters, &state_2)
        .expect("merge 1+2 should succeed");

    // merge(2, 1)
    let mut merged_21 = state_2.clone();
    merged_21
        .merge(&state_2, &parameters, &state_1)
        .expect("merge 2+1 should succeed");

    // Both A and D should be banned, B and C should remain
    for (label, merged) in [("merged_12", &merged_12), ("merged_21", &merged_21)] {
        let ids: Vec<MemberId> = merged
            .members
            .members
            .iter()
            .map(|m| m.member.id())
            .collect();
        assert!(!ids.contains(&member_a_id), "{}: A should be banned", label);
        assert!(ids.contains(&member_b.id()), "{}: B should remain", label);
        assert!(ids.contains(&member_c.id()), "{}: C should remain", label);
        assert!(!ids.contains(&member_d_id), "{}: D should be banned", label);
        assert!(
            merged.verify(merged, &parameters).is_ok(),
            "{} should verify: {:?}",
            label,
            merged.verify(merged, &parameters)
        );
    }

    // Serialized bytes must be identical (commutativity)
    let mut bytes_12 = Vec::new();
    ciborium::ser::into_writer(&merged_12, &mut bytes_12).expect("serialize merged_12");
    let mut bytes_21 = Vec::new();
    ciborium::ser::into_writer(&merged_21, &mut bytes_21).expect("serialize merged_21");

    assert_eq!(
        bytes_12,
        bytes_21,
        "COMMUTATIVITY FAILURE: merge(1,2) != merge(2,1) with diverged owner bans!\n\
         merged_12 members: {:?}\nmerged_21 members: {:?}\n\
         merged_12 bans: {:?}\nmerged_21 bans: {:?}",
        merged_12
            .members
            .members
            .iter()
            .map(|m| m.member.id())
            .collect::<Vec<_>>(),
        merged_21
            .members
            .members
            .iter()
            .map(|m| m.member.id())
            .collect::<Vec<_>>(),
        merged_12
            .bans
            .0
            .iter()
            .map(|b| (b.banned_by, b.ban.banned_user))
            .collect::<Vec<_>>(),
        merged_21
            .bans
            .0
            .iter()
            .map(|b| (b.banned_by, b.ban.banned_user))
            .collect::<Vec<_>>(),
    );
}

/// Test cascade ban cleanup across merge: member A bans member B, then A
/// gets banned by owner. After merge, A's ban of B should be cleaned by
/// the orphaned bans hook.
#[test]
fn test_merge_cascade_ban_cleanup() {
    let owner_sk = SigningKey::generate(&mut OsRng);
    let owner_vk = owner_sk.verifying_key();
    let owner_id: MemberId = owner_vk.into();

    let parameters = ChatBoardParametersV1 { owner: owner_vk };
    let config = create_test_config(&owner_sk);

    // A (invited by owner), B (invited by A)
    let (member_a, member_a_sk) = create_test_member(owner_id, owner_id);
    let member_a_id = member_a.id();
    let auth_member_a = create_authorized_member(member_a.clone(), &owner_sk);

    let (member_b, _member_b_sk) = create_test_member(owner_id, member_a_id);
    let member_b_id = member_b.id();
    let auth_member_b = create_authorized_member(member_b.clone(), &member_a_sk);

    let (member_c, _member_c_sk) = create_test_member(owner_id, owner_id);
    let auth_member_c = create_authorized_member(member_c.clone(), &owner_sk);

    // A bans B
    let ban_b_by_a = AuthorizedUserBan::new(
        UserBan {
            owner_member_id: owner_id,
            banned_at: SystemTime::now(),
            banned_user: member_b_id,
            expires_at: None,
            target_member: None,
            invite_chain: Vec::new(),
        },
        member_a_id,
        &member_a_sk,
    );

    // Owner bans A
    let ban_a_by_owner = AuthorizedUserBan::new(
        UserBan {
            owner_member_id: owner_id,
            banned_at: SystemTime::now() + std::time::Duration::from_secs(1),
            banned_user: member_a_id,
            expires_at: None,
            target_member: None,
            invite_chain: Vec::new(),
        },
        owner_id,
        &owner_sk,
    );

    // ---- State old: A, B, C present, A banned B ----
    let state_old = ChatBoardStateV1 {
        configuration: config.clone(),
        members: MembersV1 {
            members: vec![
                auth_member_a.clone(),
                auth_member_b.clone(),
                auth_member_c.clone(),
            ],
        },
        bans: BansV1(vec![ban_b_by_a.clone()]),
        ..Default::default()
    };

    // ---- State new: same members but owner also bans A ----
    let state_new = ChatBoardStateV1 {
        configuration: config,
        members: MembersV1 {
            members: vec![
                auth_member_a.clone(),
                auth_member_b.clone(),
                auth_member_c.clone(),
            ],
        },
        bans: BansV1(vec![ban_b_by_a.clone(), ban_a_by_owner.clone()]),
        ..Default::default()
    };

    // Merge
    let mut merged = state_old.clone();
    merged
        .merge(&state_old, &parameters, &state_new)
        .expect("merge should succeed");

    // A should be removed (banned by owner). B also removed (invited by A, cascade).
    let final_ids: Vec<MemberId> = merged
        .members
        .members
        .iter()
        .map(|m| m.member.id())
        .collect();
    assert!(
        !final_ids.contains(&member_a_id),
        "A should be removed (banned by owner)"
    );
    assert!(
        !final_ids.contains(&member_b_id),
        "B should be cascade-removed (invited by banned A)"
    );
    assert!(
        final_ids.contains(&member_c.id()),
        "C should remain (invited by owner)"
    );

    // A's ban of B should be cleaned (A no longer a member and not owner)
    // Only owner's ban of A should remain
    assert_eq!(
        merged.bans.0.len(),
        1,
        "Only owner's ban should remain after orphan cleanup. Got: {:?}",
        merged
            .bans
            .0
            .iter()
            .map(|b| (b.banned_by, b.ban.banned_user))
            .collect::<Vec<_>>()
    );
    assert_eq!(merged.bans.0[0].banned_by, owner_id);

    // Must verify
    assert!(
        merged.verify(&merged, &parameters).is_ok(),
        "Merged state should verify: {:?}",
        merged.verify(&merged, &parameters)
    );
}

/// Test merge commutativity with cascade: owner bans a member who had
/// invited sub-members and issued bans. Both merge orderings must produce
/// identical results. This tests that verify_member_invite correctly handles
/// inviters that are also in the delta (both inviter and invitee being added
/// in the same merge).
#[test]
fn test_merge_cascade_ban_commutativity() {
    let owner_sk = SigningKey::generate(&mut OsRng);
    let owner_vk = owner_sk.verifying_key();
    let owner_id: MemberId = owner_vk.into();

    let parameters = ChatBoardParametersV1 { owner: owner_vk };
    let config = create_test_config(&owner_sk);

    // A (invited by owner), B (invited by A), C (invited by owner)
    let (member_a, member_a_sk) = create_test_member(owner_id, owner_id);
    let member_a_id = member_a.id();
    let auth_member_a = create_authorized_member(member_a.clone(), &owner_sk);

    let (member_b, _) = create_test_member(owner_id, member_a_id);
    let member_b_id = member_b.id();
    let auth_member_b = create_authorized_member(member_b.clone(), &member_a_sk);

    let (member_c, _) = create_test_member(owner_id, owner_id);
    let auth_member_c = create_authorized_member(member_c.clone(), &owner_sk);

    // A bans B
    let ban_b_by_a = AuthorizedUserBan::new(
        UserBan {
            owner_member_id: owner_id,
            banned_at: SystemTime::now(),
            banned_user: member_b_id,
            expires_at: None,
            target_member: None,
            invite_chain: Vec::new(),
        },
        member_a_id,
        &member_a_sk,
    );

    // Owner bans A
    let ban_a_by_owner = AuthorizedUserBan::new(
        UserBan {
            owner_member_id: owner_id,
            banned_at: SystemTime::now() + std::time::Duration::from_secs(1),
            banned_user: member_a_id,
            expires_at: None,
            target_member: None,
            invite_chain: Vec::new(),
        },
        owner_id,
        &owner_sk,
    );

    // ---- State S1: has A, B, C; A banned B ----
    let state_s1 = ChatBoardStateV1 {
        configuration: config.clone(),
        members: MembersV1 {
            members: vec![
                auth_member_a.clone(),
                auth_member_b.clone(),
                auth_member_c.clone(),
            ],
        },
        bans: BansV1(vec![ban_b_by_a.clone()]),
        ..Default::default()
    };

    // ---- State S2: has C only; owner banned A (B cascade-removed, A's ban orphaned) ----
    let state_s2 = ChatBoardStateV1 {
        configuration: config,
        members: MembersV1 {
            members: vec![auth_member_c.clone()],
        },
        bans: BansV1(vec![ban_a_by_owner.clone()]),
        ..Default::default()
    };

    // merge(S1, S2): S1 receives owner's ban of A
    let mut merged_12 = state_s1.clone();
    merged_12
        .merge(&state_s1, &parameters, &state_s2)
        .expect("merge S1+S2 should succeed");

    // merge(S2, S1): S2 receives A, B (where B's inviter A is also in delta)
    // This previously failed with "Inviter not found" because verify_member_invite
    // didn't check the delta for inviters.
    let mut merged_21 = state_s2.clone();
    merged_21
        .merge(&state_s2, &parameters, &state_s1)
        .expect("merge S2+S1 should succeed — inviter A is in same delta as B");

    // Both must verify
    assert!(
        merged_12.verify(&merged_12, &parameters).is_ok(),
        "merged_12 should verify: {:?}",
        merged_12.verify(&merged_12, &parameters)
    );
    assert!(
        merged_21.verify(&merged_21, &parameters).is_ok(),
        "merged_21 should verify: {:?}",
        merged_21.verify(&merged_21, &parameters)
    );

    // Commutativity: serialized bytes must be identical
    let mut bytes_12 = Vec::new();
    ciborium::ser::into_writer(&merged_12, &mut bytes_12).expect("serialize");
    let mut bytes_21 = Vec::new();
    ciborium::ser::into_writer(&merged_21, &mut bytes_21).expect("serialize");

    assert_eq!(
        bytes_12,
        bytes_21,
        "COMMUTATIVITY FAILURE: merge with cascade bans!\n\
         merged_12 members: {:?}\nmerged_21 members: {:?}\n\
         merged_12 bans: {:?}\nmerged_21 bans: {:?}",
        merged_12
            .members
            .members
            .iter()
            .map(|m| m.member.id())
            .collect::<Vec<_>>(),
        merged_21
            .members
            .members
            .iter()
            .map(|m| m.member.id())
            .collect::<Vec<_>>(),
        merged_12
            .bans
            .0
            .iter()
            .map(|b| (b.banned_by, b.ban.banned_user))
            .collect::<Vec<_>>(),
        merged_21
            .bans
            .0
            .iter()
            .map(|b| (b.banned_by, b.ban.banned_user))
            .collect::<Vec<_>>(),
    );
}

/// Test that owner bans work correctly across merge even when one state
/// has the banned member and the other doesn't.
#[test]
fn test_merge_owner_ban_across_diverged_states() {
    let owner_sk = SigningKey::generate(&mut OsRng);
    let owner_vk = owner_sk.verifying_key();
    let owner_id: MemberId = owner_vk.into();

    let parameters = ChatBoardParametersV1 { owner: owner_vk };
    let config = create_test_config(&owner_sk);

    let (member_a, _member_a_sk) = create_test_member(owner_id, owner_id);
    let member_a_id = member_a.id();
    let auth_member_a = create_authorized_member(member_a.clone(), &owner_sk);

    let (member_b, _member_b_sk) = create_test_member(owner_id, owner_id);
    let auth_member_b = create_authorized_member(member_b.clone(), &owner_sk);

    // Owner bans A
    let ban_a = AuthorizedUserBan::new(
        UserBan {
            owner_member_id: owner_id,
            banned_at: SystemTime::now(),
            banned_user: member_a_id,
            expires_at: None,
            target_member: None,
            invite_chain: Vec::new(),
        },
        owner_id,
        &owner_sk,
    );

    // State 1: has A and B (hasn't seen ban yet)
    let state_1 = ChatBoardStateV1 {
        configuration: config.clone(),
        members: MembersV1 {
            members: vec![auth_member_a.clone(), auth_member_b.clone()],
        },
        ..Default::default()
    };

    // State 2: has B only, owner banned A (A already removed)
    let state_2 = ChatBoardStateV1 {
        configuration: config,
        members: MembersV1 {
            members: vec![auth_member_b.clone()],
        },
        bans: BansV1(vec![ban_a.clone()]),
        ..Default::default()
    };

    // merge(1, 2)
    let mut merged_12 = state_1.clone();
    merged_12
        .merge(&state_1, &parameters, &state_2)
        .expect("merge 1+2 should succeed");

    // merge(2, 1)
    let mut merged_21 = state_2.clone();
    merged_21
        .merge(&state_2, &parameters, &state_1)
        .expect("merge 2+1 should succeed");

    // A should be banned in both
    for (label, merged) in [("merged_12", &merged_12), ("merged_21", &merged_21)] {
        let ids: Vec<MemberId> = merged
            .members
            .members
            .iter()
            .map(|m| m.member.id())
            .collect();
        assert!(!ids.contains(&member_a_id), "{}: A should be banned", label);
        assert!(ids.contains(&member_b.id()), "{}: B should remain", label);
        assert!(
            merged.verify(merged, &parameters).is_ok(),
            "{} should verify: {:?}",
            label,
            merged.verify(merged, &parameters)
        );
    }

    // Commutativity
    let mut bytes_12 = Vec::new();
    ciborium::ser::into_writer(&merged_12, &mut bytes_12).unwrap();
    let mut bytes_21 = Vec::new();
    ciborium::ser::into_writer(&merged_21, &mut bytes_21).unwrap();
    assert_eq!(bytes_12, bytes_21, "Owner ban merge must be commutative");
}

// =============================================================================
// ADMIN TESTS
// =============================================================================

use plaza_core::board_state::admin::{Admin, AdminsDelta, AdminsV1, AuthorizedAdmin};

/// An outgoing owner can keep its admin rights across a transfer, so the owner
/// is allowed to hold an admin record. Its owner powers never depend on it.
#[test]
fn test_owner_can_hold_an_admin_record() {
    let owner_sk = SigningKey::generate(&mut OsRng);
    let owner_vk = owner_sk.verifying_key();
    let owner_id: MemberId = owner_vk.into();

    let parameters = ChatBoardParametersV1 { owner: owner_vk };
    let parent_state = ChatBoardStateV1::default();

    let admin = Admin {
        member_id: owner_id,
        generation: 0,
        signed_at: std::time::SystemTime::UNIX_EPOCH,
    };
    let authorized_admin = AuthorizedAdmin::new(admin, &owner_sk);

    let mut admins = AdminsV1::default();
    let delta = AdminsDelta::new(vec![authorized_admin]);

    admins
        .apply_delta(&parent_state, &parameters, &Some(delta))
        .expect("the owner's admin record is accepted");
    assert_eq!(admins.admins.len(), 1);
    assert_eq!(admins.admins[0].admin.id(), owner_id);
}

/// Test that a regular member can be added as admin.
#[test]
fn test_member_can_be_added_as_admin() {
    let owner_sk = SigningKey::generate(&mut OsRng);
    let owner_vk = owner_sk.verifying_key();
    let owner_id: MemberId = owner_vk.into();

    let parameters = ChatBoardParametersV1 { owner: owner_vk };
    let parent_state = ChatBoardStateV1::default();

    // Create a regular member
    let (member, _member_sk) = create_test_member(owner_id, owner_id);
    let member_id = member.id();

    // Add member as admin (signed by owner)
    let admin = Admin {
        member_id,
        generation: 0,
        signed_at: std::time::SystemTime::UNIX_EPOCH,
    };
    let authorized_admin = AuthorizedAdmin::new(admin, &owner_sk);

    let mut admins = AdminsV1::default();
    let delta = AdminsDelta::new(vec![authorized_admin]);

    let result = admins.apply_delta(&parent_state, &parameters, &Some(delta));

    assert!(
        result.is_ok(),
        "Adding regular member as admin should succeed: {:?}",
        result
    );
    assert_eq!(admins.admins.len(), 1);
    assert_eq!(admins.admins[0].admin.member_id, member_id);
}

// =============================================================================
// HISTORICAL AUTHORITY CONVERGENCE
// =============================================================================
//
// A record signed by a scoped moderator carries a role-grant proof. Peers may
// receive the record and the role revocation in either order; both must keep
// the record and end in the same state.

#[test]
fn moderation_record_with_historical_authority_converges() {
    use plaza_core::board_state::configuration::{AuthorizedConfigurationV1, Configuration};
    use plaza_core::board_state::privacy::SealedBytes;
    use plaza_core::board_state::roles::{
        moderation_authority_proof, AuthorizedRole, AuthorizedRoleAssignment, ModerationPower,
        Role, RoleAssignment, RolesDelta,
    };
    use plaza_core::board_state::sections::{AuthorizedSectionV1, SectionV1, SectionsV1};
    use plaza_core::board_state::topics::{
        AuthorizedTopicEntryV1, AuthorizedTopicFlagV1, TopicEntryV1, TopicFlagKind, TopicFlagV1,
        TopicIndexDelta, TopicIndexV1, TOPIC_PROTOCOL_VERSION,
    };
    use plaza_core::board_state::ChatBoardStateV1Delta;
    use plaza_core::util::sign_struct;

    let owner_sk = SigningKey::generate(&mut OsRng);
    let owner_vk = owner_sk.verifying_key();
    let owner_id: MemberId = owner_vk.into();
    let parameters = ChatBoardParametersV1 { owner: owner_vk };

    let (author, author_sk) = create_test_member(owner_id, owner_id);
    let author_id = MemberId::from(&author.member_vk);
    let (moderator, moderator_sk) = create_test_member(owner_id, owner_id);
    let moderator_id = MemberId::from(&moderator.member_vk);
    let author_record = create_authorized_member(author, &owner_sk);
    let moderator_record = create_authorized_member(moderator, &owner_sk);

    let section_id = MessageId::from_bytes([5u8; 32]);
    let topic_id = MessageId::from_bytes([9u8; 32]);
    let section = AuthorizedSectionV1::new(
        SectionV1 {
            id: section_id,
            parent: None,
            name: "General".to_string(),
            description: None,
            icon: None,
            color: "#6366f1".to_string(),
            allowed_roles: Vec::new(),
            sealed_name: None,
            hidden: false,
            is_group: false,
            images_allowed: true,
            auto_moderated_topics: None,
            generation: 1,
            deleted: false,
            contract: None,
            signed_at: std::time::SystemTime::UNIX_EPOCH,
        },
        &owner_sk,
        None,
    );
    let topic = AuthorizedTopicEntryV1::new(
        TopicEntryV1 {
            topic_id,
            part: 0,
            protocol_version: TOPIC_PROTOCOL_VERSION,
            author: author_id,
            section: Some(section_id),
            section_chain: vec![section_id],
            title: SealedBytes::public(b"Hello".to_vec()),
            preview: SealedBytes::public(b"World".to_vec()),
            header_hash: [1u8; 32],
            created_at: 1,
            generation: 1,
        },
        &author_sk,
    );

    let role_id = [7u8; 16];
    let role = AuthorizedRole::new(
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
            can_manage_trash: false,
            can_attach_images: false,
            can_retire_images: false,
            scope: Vec::new(),
            deleted: false,
            signed_at: std::time::SystemTime::UNIX_EPOCH,
        },
        &owner_sk,
    );
    let assignment = |generation, revoked| {
        AuthorizedRoleAssignment::new(
            RoleAssignment {
                role_id,
                member_id: moderator_id,
                generation,
                revoked,
                signed_at: std::time::SystemTime::UNIX_EPOCH,
            },
            &owner_sk,
        )
    };

    let base = ChatBoardStateV1 {
        configuration: AuthorizedConfigurationV1::new(Configuration::default(), &owner_sk),
        members: MembersV1 {
            members: vec![author_record, moderator_record],
        },
        sections: SectionsV1 {
            sections: vec![section],
        },
        topics: TopicIndexV1 {
            entries: vec![topic],
            ..Default::default()
        },
        roles: plaza_core::board_state::roles::RolesV1 {
            roles: vec![role],
            assignments: vec![assignment(1, false)],
        },
        ..Default::default()
    };

    let proof =
        moderation_authority_proof(&base, &moderator_id, ModerationPower::Pin, &[section_id])
            .expect("the role grants pinning");
    let flag_value = TopicFlagV1 {
        topic_id,
        kind: TopicFlagKind::Pinned,
        value: true,
        destination: None,
        section: None,
        section_chain: Vec::new(),
        destination_sections: Vec::new(),
        part: None,
        scope_chain: vec![section_id],
        generation: 1,
        created_at: 1,
    };
    let flag = AuthorizedTopicFlagV1 {
        signature: sign_struct(&flag_value, &moderator_sk),
        flag: flag_value,
        signer: Some(moderator_id),
        signer_key: Some(moderator_sk.verifying_key()),
        authority: Some(Box::new(proof)),
    };

    let pin_delta = ChatBoardStateV1Delta {
        topics: Some(TopicIndexDelta {
            flags: vec![flag],
            ..Default::default()
        }),
        ..Default::default()
    };
    let revoke_delta = ChatBoardStateV1Delta {
        roles: Some(RolesDelta {
            roles: Vec::new(),
            assignments: vec![assignment(2, true)],
        }),
        ..Default::default()
    };

    let initial = base;
    let mut peer_a = initial.clone();
    let mut peer_b = initial.clone();

    // Peer A: pin first, then revocation.
    peer_a
        .apply_delta(&peer_a.clone(), &parameters, &Some(pin_delta.clone()))
        .expect("pin applies");
    let after_pin = peer_a.clone();
    peer_a
        .apply_delta(&after_pin, &parameters, &Some(revoke_delta.clone()))
        .expect("revocation applies");
    peer_a
        .verify(&peer_a, &parameters)
        .expect("peer A state verifies");

    // Peer B: revocation first, then the pin signed before it.
    peer_b
        .apply_delta(&peer_b.clone(), &parameters, &Some(revoke_delta))
        .expect("revocation applies first");
    let after_revoke = peer_b.clone();
    peer_b
        .apply_delta(&after_revoke, &parameters, &Some(pin_delta))
        .expect("historical pin still applies after the revocation");
    peer_b
        .verify(&peer_b, &parameters)
        .expect("peer B state verifies");

    assert_eq!(
        peer_a.topics.flags, peer_b.topics.flags,
        "both peers keep the same pin"
    );
    assert_eq!(
        peer_a.roles.assignments, peer_b.roles.assignments,
        "both peers keep the same revocation"
    );
}
