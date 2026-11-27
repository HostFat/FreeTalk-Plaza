use crate::*;
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

#[cfg(test)]
mod scale_bench {
    use super::tests::*;
    use super::*;
    use std::hint::black_box;
    use std::time::Instant;

    fn state_with_posts(count: usize) -> TopicStateV1 {
        let mut state = base_state();
        for index in 0..count {
            let entry = post(
                &member(),
                "reply",
                1_000 + index as i64 * 61_000,
                (index % 256) as u8,
            );
            state.posts.insert(entry.post.id(), entry);
        }
        state
    }

    /// `cargo test -p plaza-topic-core --release --lib -- --ignored --nocapture`
    #[test]
    #[ignore = "scale benchmark; run in release"]
    fn scale_topic_benchmark() {
        for count in [100usize, 200] {
            let state = state_with_posts(count);
            let params = params();
            state.verify(&params).unwrap();

            let mut bytes = Vec::new();
            let start = Instant::now();
            ciborium::ser::into_writer(&state, &mut bytes).unwrap();
            println!(
                "\ntopic: {count} post\nserializzazione: {:.1} ms, {} KiB",
                start.elapsed().as_secs_f64() * 1000.0,
                bytes.len() / 1024
            );

            let start = Instant::now();
            for _ in 0..5 {
                black_box(state.verify(&params).unwrap());
            }
            println!(
                "verify: {:.1} ms/op",
                start.elapsed().as_secs_f64() * 1000.0 / 5.0
            );

            let mut base = state_with_posts(count - 1);
            let delta = TopicDeltaV1 {
                posts: vec![post(
                    &member(),
                    "reply",
                    1_000 + (count - 1) as i64 * 61_000,
                    ((count - 1) % 256) as u8,
                )],
                ..Default::default()
            };
            let start = Instant::now();
            base.apply_delta(&params, &delta).unwrap();
            println!(
                "apply_delta (un post): {:.1} ms",
                start.elapsed().as_secs_f64() * 1000.0
            );

            let mut incremental = state_with_posts(count - 1);
            let start = Instant::now();
            incremental
                .apply_delta_incremental(&params, &delta)
                .unwrap();
            println!(
                "apply_delta_incremental (un post): {:.1} ms",
                start.elapsed().as_secs_f64() * 1000.0
            );
        }
    }
}

#[cfg(test)]
mod authority_root_tests {
    use super::tests::*;
    use super::*;

    fn topic_with_root() -> TopicStateV1 {
        let mut state = base_state();
        let member_record = state.participants[0].record.certificate.member.clone();
        let mut board = ChatBoardStateV1::default();
        board.members.members.push(member_record);
        let tree = AuthorityTreeV1::from_board(&board);
        let member_id = MemberId::from(&member().verifying_key());
        state.authority.roles = RolesV1::default();
        state.authority.bans = BansV1(Vec::new());
        state.authority.ban_revocations = BanRevocationsV1::default();
        state.authority.suspensions = SuspensionsV1::default();
        state.authority.root = Some(AuthorizedAuthorityRootV1::new(tree.root(1), &owner()));
        state.authority.member_proofs = tree.proofs_for([&member_id]);
        state
    }

    #[test]
    fn a_topic_with_a_root_and_proofs_verifies() {
        topic_with_root().verify(&params()).unwrap();
    }

    #[test]
    fn a_tampered_proof_is_rejected() {
        let mut state = topic_with_root();
        state.authority.member_proofs[0]
            .status
            .member
            .member
            .member_vk = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        assert!(state.verify(&params()).is_err());
    }
}

#[cfg(test)]
mod incremental_tests {
    use super::tests::*;
    use super::*;

    fn delta_with_post(entry: AuthorizedTopicPostV1) -> TopicDeltaV1 {
        TopicDeltaV1 {
            posts: vec![entry],
            ..Default::default()
        }
    }

    #[test]
    fn an_incremental_reply_is_accepted() {
        let mut state = base_state();
        let entry = post(&member(), "incremental", 1_000, 1);
        let id = entry.post.id();
        state
            .apply_delta_incremental(&params(), &delta_with_post(entry))
            .unwrap();
        assert!(state.posts.contains_key(&id));
        state.verify(&params()).unwrap();
    }

    #[test]
    fn an_incremental_post_with_a_bad_signature_is_rejected() {
        let mut state = base_state();
        let mut entry = post(&member(), "original", 1_000, 1);
        entry.post.content = SealedBytes::public(b"tampered".to_vec());
        let error = state
            .apply_delta_incremental(&params(), &delta_with_post(entry))
            .unwrap_err();
        assert!(error.contains("signature"), "{error}");
    }

    #[test]
    fn an_incremental_post_with_a_missing_parent_is_rejected() {
        let mut state = base_state();
        let mut value = post(&member(), "child", 1_000, 1).post;
        value.parent = Some(MessageId::from_bytes([9u8; 32]));
        let entry = AuthorizedTopicPostV1::new(value, &member());
        let error = state
            .apply_delta_incremental(&params(), &delta_with_post(entry))
            .unwrap_err();
        assert!(error.contains("parent"), "{error}");
    }

    #[test]
    fn an_incremental_action_without_authority_is_rejected() {
        let mut state = base_state();
        let owner_post = post(&owner(), "owner post", 1_000, 1);
        let target = owner_post.post.id();
        state.posts.insert(target, owner_post.clone());
        let delta = TopicDeltaV1 {
            actions: vec![action(
                &member(),
                TopicActionKind::Delete,
                target,
                1,
            )],
            ..Default::default()
        };
        let error = state
            .apply_delta_incremental(&params(), &delta)
            .unwrap_err();
        assert!(!error.is_empty(), "the action must be rejected");
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use plaza_core::board_state::ban::{AuthorizedUserBan, UserBan};
    use plaza_core::board_state::member::{AuthorizedMember, Member};
    use plaza_core::board_state::member_moderation::{
        AuthorizedSuspension, SuspensionV1,
    };
    use plaza_core::board_state::reports::ReportReason;
    use plaza_core::board_state::roles::{Role, RoleAssignment};
    use std::time::Duration;

    pub(crate) fn owner() -> SigningKey {
        SigningKey::from_bytes(&[1u8; 32])
    }

    pub(crate) fn member() -> SigningKey {
        SigningKey::from_bytes(&[2u8; 32])
    }

    pub(crate) fn other() -> SigningKey {
        SigningKey::from_bytes(&[3u8; 32])
    }

    pub(crate) fn owner_id() -> MemberId {
        MemberId::from(&owner().verifying_key())
    }

    pub(crate) fn member_id() -> MemberId {
        MemberId::from(&member().verifying_key())
    }

    pub(crate) fn params() -> TopicParamsV1 {
        TopicParamsV1::new(owner().verifying_key(), [7u8; 32], 0)
    }

    pub(crate) fn at(ms: i64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_millis(ms as u64)
    }

    pub(crate) fn policy(generation: u64) -> AuthorizedTopicPolicyV1 {
        AuthorizedTopicPolicyV1::new(
            TopicPolicyV1 {
                generation,
                updated_at: 1,
                ..Default::default()
            },
            &owner(),
        )
    }

    pub(crate) fn authority() -> TopicAuthorityV1 {
        TopicAuthorityV1 {
            policy: Some(policy(1)),
            ..Default::default()
        }
    }

    pub(crate) fn header(author: &SigningKey, section: Option<SectionId>) -> AuthorizedTopicHeaderV1 {
        AuthorizedTopicHeaderV1::new(
            TopicHeaderV1 {
                topic_id: [7u8; 32],
                author: MemberId::from(&author.verifying_key()),
                author_key: author.verifying_key(),
                section,
                section_chain: section.map(|id| vec![id]).unwrap_or_default(),
                title: SealedBytes::public(b"Title".to_vec()),
                body: SealedBytes::public(b"Body".to_vec()),
                auto_moderated: false,
                created_at: 1,
                nonce: [3u8; 16],
            },
            author,
        )
    }

    pub(crate) fn participant(sk: &SigningKey, joined_at: i64) -> AuthorizedParticipantV1 {
        let member_record = AuthorizedMember::new(
            Member {
                owner_member_id: owner_id(),
                invited_by: owner_id(),
                member_vk: sk.verifying_key(),
                join_proof: None,
            },
            &owner(),
        );
        let record = ParticipantRecordV1 {
            member_id: MemberId::from(&sk.verifying_key()),
            member_vk: sk.verifying_key(),
            certificate: ParticipantCertificateV1 {
                member: member_record,
                chain: Vec::new(),
                token: None,
                join_proof: None,
            },
            joined_at,
        };
        AuthorizedParticipantV1::new(record, sk)
    }

    pub(crate) fn post(sk: &SigningKey, content: &str, created_at: i64, nonce: u8) -> AuthorizedTopicPostV1 {
        AuthorizedTopicPostV1::new(
            TopicPostV1 {
                author: MemberId::from(&sk.verifying_key()),
                parent: None,
                content: SealedBytes::public(content.as_bytes().to_vec()),
                images: Vec::new(),
                created_at,
                nonce: [nonce; 16],
            },
            sk,
        )
    }

    pub(crate) fn base_state() -> TopicStateV1 {
        TopicStateV1 {
            header: Some(header(&owner(), None)),
            authority: authority(),
            participants: vec![participant(&member(), 1)],
            posts: BTreeMap::new(),
            generation: TopicGenerationV1::new(0),
            ..Default::default()
        }
    }

    pub(crate) fn action(
        signer: &SigningKey,
        kind: TopicActionKind,
        target: MessageId,
        generation: u64,
    ) -> AuthorizedTopicActionV1 {
        let value = TopicActionV1 {
            kind,
            target,
            payload: SealedBytes::public(Vec::new()),
            generation,
            created_at: 10,
            signer: MemberId::from(&signer.verifying_key()),
        };
        AuthorizedTopicActionV1 {
            signature: sign_struct(&value, signer),
            action: value,
            signer_key: Some(signer.verifying_key()),
            authority: None,
        }
    }

    #[test]
    fn a_minimal_topic_verifies() {
        let mut state = base_state();
        state.posts.insert(
            post(&member(), "hello", 10, 1).id(),
            post(&member(), "hello", 10, 1),
        );
        state.verify(&params()).unwrap();
    }

    #[test]
    fn a_tampered_post_is_rejected() {
        let mut state = base_state();
        let mut entry = post(&member(), "hello", 10, 1);
        entry.post.content = SealedBytes::public(b"other".to_vec());
        state.posts.insert(entry.id(), entry);
        assert!(state.verify(&params()).is_err());
    }

    #[test]
    fn a_post_from_an_outsider_is_rejected() {
        let mut state = base_state();
        let entry = post(&other(), "hello", 10, 1);
        state.posts.insert(entry.id(), entry);
        assert!(state.verify(&params()).is_err());
    }

    #[test]
    fn merge_collects_posts_from_both_sides() {
        let mut left = base_state();
        let a = post(&member(), "left", 10, 1);
        left.posts.insert(a.id(), a);
        let mut right = base_state();
        let b = post(&member(), "right", 20, 2);
        right.posts.insert(b.id(), b);
        left.merge(&params(), &right).unwrap();
        assert_eq!(left.posts.len(), 2);
        left.verify(&params()).unwrap();
    }

    #[test]
    fn delta_serves_the_missing_posts() {
        let left = base_state();
        let mut right = base_state();
        let b = post(&member(), "right", 20, 2);
        right.posts.insert(b.id(), b);
        let delta = right.delta(&left.summarize()).unwrap();
        let mut merged = left.clone();
        merged.apply_delta(&params(), &delta).unwrap();
        assert_eq!(merged.posts.len(), 1);
        merged.verify(&params()).unwrap();
    }

    #[test]
    fn an_author_can_delete_their_post() {
        let mut state = base_state();
        let entry = post(&member(), "hello", 10, 1);
        let id = entry.id();
        state.posts.insert(id, entry);
        state
            .actions
            .push(action(&member(), TopicActionKind::Delete, id, 1));
        state.verify(&params()).unwrap();
        assert!(state.is_deleted(id));
    }

    #[test]
    fn the_owner_can_delete_another_post() {
        let mut state = base_state();
        let entry = post(&member(), "hello", 10, 1);
        let id = entry.id();
        state.posts.insert(id, entry);
        state
            .actions
            .push(action(&owner(), TopicActionKind::Delete, id, 1));
        state.verify(&params()).unwrap();
        assert!(state.is_deleted(id));
    }

    #[test]
    fn an_outsider_cannot_delete_a_post() {
        let mut state = base_state();
        let entry = post(&member(), "hello", 10, 1);
        let id = entry.id();
        state.posts.insert(id, entry);
        state
            .actions
            .push(action(&other(), TopicActionKind::Delete, id, 1));
        assert!(state.verify(&params()).is_err());
    }

    #[test]
    fn a_ban_blocks_new_posts_but_not_old_ones() {
        let mut state = base_state();
        let entry = post(&member(), "before", 10, 1);
        state.posts.insert(entry.id(), entry);
        let ban = UserBan {
            owner_member_id: owner_id(),
            banned_at: at(20),
            banned_user: member_id(),
            expires_at: None,
            target_member: None,
            invite_chain: Vec::new(),
        };
        state
            .authority
            .bans
            .0
            .push(AuthorizedUserBan::new(ban, owner_id(), &owner()));
        state.verify(&params()).unwrap();

        let after = post(&member(), "after", 30, 2);
        state.posts.insert(after.id(), after);
        assert!(state.verify(&params()).is_err());
    }

    #[test]
    fn a_suspension_blocks_new_posts() {
        let mut state = base_state();
        state.authority.suspensions.suspensions.push(
            AuthorizedSuspension::new(
                SuspensionV1 {
                    target: member_id(),
                    reason: ReportReason::Spam,
                    until: 100,
                    created_at: 10,
                    generation: 1,
                },
                &owner(),
            ),
        );
        state.verify(&params()).unwrap();
        let entry = post(&member(), "suspended", 50, 1);
        state.posts.insert(entry.id(), entry);
        assert!(state.verify(&params()).is_err());
    }

    #[test]
    fn the_header_is_immutable() {
        let params = params();
        let mut state = base_state();
        let mut other_header = header(&owner(), None).header;
        other_header.nonce = [4u8; 16];
        let delta = TopicDeltaV1 {
            header: Some(AuthorizedTopicHeaderV1::new(other_header, &owner())),
            ..Default::default()
        };
        assert!(state.apply_delta(&params, &delta).is_err());
    }

    #[test]
    fn the_part_is_bound_to_the_parameters() {
        let mut state = base_state();
        state.generation.part = 1;
        assert!(state.verify(&params()).is_err());
    }

    #[test]
    fn state_and_delta_round_trip() {
        let state = base_state();
        let bytes = encode(&state).unwrap();
        assert_eq!(decode_state(&bytes).unwrap(), state);
        let delta = TopicDeltaV1 {
            header: state.header.clone(),
            ..Default::default()
        };
        let bytes = encode(&delta).unwrap();
        assert_eq!(decode_delta(&bytes).unwrap(), delta);
        let summary = state.summarize();
        let bytes = encode(&summary).unwrap();
        assert_eq!(decode_summary(&bytes).unwrap(), summary);
    }

    #[test]
    fn approvals_gate_untrusted_posts() {
        let mut state = base_state();
        let mut policy = state.authority.policy().clone();
        policy.approval_required = true;
        state.authority.policy = Some(AuthorizedTopicPolicyV1::new(policy, &owner()));

        let entry = post(&member(), "pending", 10, 1);
        let id = entry.id();
        state.posts.insert(id, entry.clone());
        state.verify(&params()).unwrap();
        assert!(!state.post_is_visible(&entry));

        let approval = TopicApprovalV1 {
            target: id,
            approved: true,
            generation: 1,
            scope: None,
            signed_by: owner_id(),
            created_at: 11,
        };
        state.approvals.push(AuthorizedTopicApprovalV1 {
            signature: sign_struct(&approval, &owner()),
            approval,
            signer_key: Some(owner().verifying_key()),
            authority: None,
        });
        state.verify(&params()).unwrap();
        assert!(state.post_is_visible(&entry));
    }

    #[test]
    fn section_acl_blocks_a_member_without_the_role() {
        let section = MessageId::from_bytes([9u8; 32]);
        let role_id = [5u8; 16];
        let snapshot = SectionSnapshotV1 {
            section,
            parent: None,
            chain: vec![section],
            allowed_roles: vec![role_id],
            sealed_name: None,
            hidden: false,
            images_allowed: true,
            auto_moderated_topics: None,
            generation: 1,
            signed_at: 1,
        };
        let mut state = base_state();
        state.header = Some(header(&owner(), Some(section)));
        state.section = Some(AuthorizedSectionSnapshotV1::new(
            snapshot,
            &owner(),
            None,
        ));
        state.verify(&params()).unwrap();

        let entry = post(&member(), "blocked", 10, 1);
        state.posts.insert(entry.id(), entry);
        assert!(state.verify(&params()).is_err());
    }

    #[test]
    fn the_section_acl_admits_the_role_member() {
        let section = MessageId::from_bytes([9u8; 32]);
        let role_id = [5u8; 16];
        let snapshot = SectionSnapshotV1 {
            section,
            parent: None,
            chain: vec![section],
            allowed_roles: vec![role_id],
            sealed_name: None,
            hidden: false,
            images_allowed: true,
            auto_moderated_topics: None,
            generation: 1,
            signed_at: 1,
        };
        let mut state = base_state();
        state.header = Some(header(&owner(), Some(section)));
        state.section = Some(AuthorizedSectionSnapshotV1::new(
            snapshot,
            &owner(),
            None,
        ));
        state.authority.roles.roles.push(AuthorizedRole::new(
            Role {
                id: role_id,
                name: "members".to_string(),
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
            },
            &owner(),
        ));
        state.authority.roles.assignments.push(
            AuthorizedRoleAssignment::new(
                RoleAssignment {
                    role_id,
                    member_id: member_id(),
                    generation: 1,
                    revoked: false,
                    signed_at: SystemTime::UNIX_EPOCH,
                },
                &owner(),
            ),
        );
        let entry = post(&member(), "allowed", 10, 1);
        state.posts.insert(entry.id(), entry);
        state.verify(&params()).unwrap();
    }

    #[test]
    fn the_rate_limit_rejects_a_burst() {
        let mut state = base_state();
        let mut policy = state.authority.policy().clone();
        policy.max_posts_per_window = 2;
        state.authority.policy = Some(AuthorizedTopicPolicyV1::new(policy, &owner()));
        let delta = TopicDeltaV1 {
            posts: vec![
                post(&member(), "one", 10, 1),
                post(&member(), "two", 20, 2),
                post(&member(), "three", 30, 3),
            ],
            ..Default::default()
        };
        assert!(state.apply_delta(&params(), &delta).is_err());
    }
}

#[cfg(test)]
mod phase1_extra_tests {
    use super::tests::*;
    use super::*;
    use plaza_core::board_state::admin::{Admin, AuthorizedAdmin};
    use plaza_core::board_state::invites::{
        join_message, AuthorizedInviteToken, InviteToken, JoinProof,
    };
    use plaza_core::board_state::member::{AuthorizedMember, Member};
    use plaza_core::board_state::roles::{
        AuthorizedRole, AuthorizedRoleAssignment, Role, RoleAssignment,
    };
    use std::time::SystemTime;

    #[test]
    fn a_tampered_header_is_rejected() {
        let mut state = base_state();
        state.header.as_mut().unwrap().header.title =
            SealedBytes::public(b"Other".to_vec());
        assert!(state.verify(&params()).is_err());
    }

    #[test]
    fn a_token_join_is_accepted() {
        let token_sk = SigningKey::from_bytes(&[4u8; 32]);
        let role_id = [5u8; 16];
        let mut state = base_state();
        state.authority.roles.roles.push(AuthorizedRole::new(
            role(role_id),
            &owner(),
        ));

        let token = InviteToken {
            id: [6u8; 16],
            verifying_key: token_sk.verifying_key(),
            role_id,
            max_uses: None,
            not_after: None,
            generation: 1,
            deleted: false,
            label: String::new(),
            created_at: Some(SystemTime::UNIX_EPOCH),
            includes_category_keys: false,
        };
        let authorized = AuthorizedInviteToken::new(token, &owner());
        let member_sk = other();
        let member_id = MemberId::from(&member_sk.verifying_key());
        let proof = JoinProof::new(
            [6u8; 16],
            &token_sk,
            &join_message(&owner().verifying_key(), &member_sk.verifying_key()),
        );
        let member_record = AuthorizedMember::new(
            Member {
                owner_member_id: owner_id(),
                invited_by: member_id,
                member_vk: member_sk.verifying_key(),
                join_proof: Some(proof.clone()),
            },
            &member_sk,
        );
        let record = ParticipantRecordV1 {
            member_id,
            member_vk: member_sk.verifying_key(),
            certificate: ParticipantCertificateV1 {
                member: member_record,
                chain: Vec::new(),
                token: Some(authorized),
                join_proof: Some(proof),
            },
            joined_at: 2,
        };
        state
            .participants
            .push(AuthorizedParticipantV1::new(record, &member_sk));
        state.verify(&params()).unwrap();
    }

    #[test]
    fn a_role_holder_can_moderate() {
        let role_id = [5u8; 16];
        let mut state = base_state();
        state.authority.roles.roles.push(AuthorizedRole::new(
            Role {
                can_delete_posts: true,
                ..role(role_id)
            },
            &owner(),
        ));
        state.authority.roles.assignments.push(
            AuthorizedRoleAssignment::new(
                RoleAssignment {
                    role_id,
                    member_id: member_id(),
                    generation: 1,
                    revoked: false,
                    signed_at: SystemTime::UNIX_EPOCH,
                },
                &owner(),
            ),
        );
        let target = state.header.as_ref().unwrap().header.id();
        state.actions.push(action(
            &member(),
            TopicActionKind::Delete,
            target,
            1,
        ));
        state.verify(&params()).unwrap();
        assert!(state.is_deleted(target));
    }

    #[test]
    fn an_admin_can_moderate() {
        let mut state = base_state();
        state.authority.admins.admins.push(AuthorizedAdmin::new(
            Admin {
                member_id: member_id(),
                generation: 1,
                signed_at: SystemTime::UNIX_EPOCH,
            },
            &owner(),
        ));
        let target = state.header.as_ref().unwrap().header.id();
        state.actions.push(action(
            &member(),
            TopicActionKind::Delete,
            target,
            1,
        ));
        state.verify(&params()).unwrap();
        assert!(state.is_deleted(target));
    }

    fn role(id: [u8; 16]) -> Role {
        Role {
            id,
            name: "moderator".to_string(),
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
        }
    }
}

#[cfg(test)]
mod phase1_policy_tests {
    use super::tests::*;
    use super::*;

    #[test]
    fn a_purged_topic_is_deleted() {
        let mut state = base_state();
        let target = state.header.as_ref().unwrap().header.id();
        state.actions.push(action(
            &owner(),
            TopicActionKind::Purge,
            target,
            1,
        ));
        state.verify(&params()).unwrap();
        assert!(state.is_deleted(target));
    }

    #[test]
    fn auto_moderated_topics_need_the_policy() {
        let mut state = base_state();
        let mut policy = state.authority.policy().clone();
        policy.auto_moderated_topics = false;
        state.authority.policy = Some(AuthorizedTopicPolicyV1::new(policy, &owner()));
        let header = state.header.as_mut().unwrap();
        header.header.auto_moderated = true;
        header.signature = sign_struct(&header.header, &owner());
        assert!(state.verify(&params()).is_err());
    }

    #[test]
    fn the_summary_tracks_approvals() {
        let mut state = base_state();
        let entry = post(&member(), "hello", 10, 1);
        let id = entry.id();
        state.posts.insert(id, entry);
        let approval = TopicApprovalV1 {
            target: id,
            approved: true,
            generation: 1,
            scope: None,
            signed_by: owner_id(),
            created_at: 11,
        };
        state.approvals.push(AuthorizedTopicApprovalV1 {
            signature: sign_struct(&approval, &owner()),
            approval,
            signer_key: Some(owner().verifying_key()),
            authority: None,
        });
        let summary = state.summarize();
        assert_eq!(summary.approvals.get(&id), Some(&1));
    }
}

#[cfg(test)]
mod member_topic_tests {
    use super::tests::*;
    use plaza_core::board_state::configuration::{
        AuthorizedConfigurationV1, Configuration,
    };
    use std::time::SystemTime;

    #[test]
    fn a_member_topic_can_use_the_owner_signed_board_config() {
        let mut state = base_state();
        let configuration = Configuration {
            owner_member_id: owner_id(),
            updated_at: SystemTime::UNIX_EPOCH,
            ..Default::default()
        };
        state.authority.policy = None;
        state.authority.source_configuration = Some(AuthorizedConfigurationV1::new(
            configuration,
            &owner(),
        ));
        state.header = Some(header(&member(), None));
        state.participants = vec![participant(&member(), 1)];
        state.verify(&params()).unwrap();
        assert_eq!(state.authority.policy().max_post_size, 10_000);
    }
}

#[cfg(test)]
mod edit_tests {
    use super::tests::*;
    use super::*;

    #[test]
    fn an_author_can_edit_a_post() {
        let mut state = base_state();
        let entry = post(&member(), "before", 10, 1);
        let id = entry.id();
        state.posts.insert(id, entry);
        state
            .actions
            .push(action(&member(), TopicActionKind::Edit, id, 1));
        state.verify(&params()).unwrap();
        assert!(state.latest_action(id, TopicActionKind::Edit).is_some());
    }

    #[test]
    fn an_outsider_cannot_edit_a_post() {
        let mut state = base_state();
        let entry = post(&member(), "before", 10, 1);
        let id = entry.id();
        state.posts.insert(id, entry);
        state
            .actions
            .push(action(&other(), TopicActionKind::Edit, id, 1));
        assert!(state.verify(&params()).is_err());
    }
}

#[cfg(test)]
mod approval_tests {
    use super::tests::*;
    use super::*;

    fn approval_state() -> (TopicStateV1, MessageId) {
        let mut state = base_state();
        let mut policy = state.authority.policy().clone();
        policy.approval_required = true;
        state.authority.policy = Some(AuthorizedTopicPolicyV1::new(policy, &owner()));
        let entry = post(&member(), "pending", 10, 1);
        let id = entry.id();
        state.posts.insert(id, entry);
        (state, id)
    }

    #[test]
    fn an_outsider_cannot_approve_a_post() {
        let (mut state, id) = approval_state();
        let approval = TopicApprovalV1 {
            target: id,
            approved: true,
            generation: 1,
            scope: None,
            signed_by: MemberId::from(&other().verifying_key()),
            created_at: 11,
        };
        state.approvals.push(AuthorizedTopicApprovalV1 {
            signature: sign_struct(&approval, &other()),
            approval,
            signer_key: Some(other().verifying_key()),
            authority: None,
        });
        assert!(state.verify(&params()).is_err());
    }

    #[test]
    fn a_rejected_post_stays_hidden() {
        let (mut state, id) = approval_state();
        let approval = TopicApprovalV1 {
            target: id,
            approved: false,
            generation: 1,
            scope: None,
            signed_by: owner_id(),
            created_at: 11,
        };
        state.approvals.push(AuthorizedTopicApprovalV1 {
            signature: sign_struct(&approval, &owner()),
            approval,
            signer_key: Some(owner().verifying_key()),
            authority: None,
        });
        state.verify(&params()).unwrap();
        assert!(!state.post_is_visible(state.posts.get(&id).unwrap()));
    }

    #[test]
    fn trust_makes_a_post_visible_without_an_approval() {
        let (mut state, id) = approval_state();
        let trust = TrustV1 {
            member_id: member_id(),
            trusted: true,
            generation: 1,
            signed_by: owner_id(),
            created_at: 11,
        };
        state.trust.push(AuthorizedTrustV1 {
            signature: sign_struct(&trust, &owner()),
            trust,
            signer_key: Some(owner().verifying_key()),
            authority: None,
        });
        state.verify(&params()).unwrap();
        assert!(state.post_is_visible(state.posts.get(&id).unwrap()));
    }
}

#[cfg(test)]
mod propagation_tests {
    use super::tests::*;
    use plaza_core::board_state::ban::{AuthorizedUserBan, UserBan};

    #[test]
    fn a_propagated_ban_blocks_later_posts() {
        let mut state = base_state();
        let before = post(&member(), "before", 10, 1);
        state.posts.insert(before.id(), before);
        state.verify(&params()).unwrap();

        let mut updated = state.authority.clone();
        updated.bans.0.push(AuthorizedUserBan::new(
            UserBan {
                owner_member_id: owner_id(),
                banned_at: at(20),
                banned_user: member_id(),
                expires_at: None,
                target_member: None,
                invite_chain: Vec::new(),
            },
            owner_id(),
            &owner(),
        ));
        state.authority = state.authority.merged_with(&updated);
        state.verify(&params()).unwrap();
        assert!(state.is_banned_member(member_id(), 30));

        let after = post(&member(), "after", 30, 2);
        state.posts.insert(after.id(), after);
        assert!(state.verify(&params()).is_err());
    }
}

#[cfg(test)]
mod role_propagation_tests {
    use super::tests::*;
    use super::*;
    use plaza_core::board_state::roles::{
        AuthorizedRole, AuthorizedRoleAssignment, Role, RoleAssignment,
    };
    use std::time::SystemTime;

    #[test]
    fn a_propagated_role_can_moderate() {
        let mut state = base_state();
        let role_id = [5u8; 16];
        let mut updated = state.authority.clone();
        updated.roles.roles.push(AuthorizedRole::new(
            Role {
                id: role_id,
                name: "Moderators".to_string(),
                generation: 1,
                can_manage_access: false,
                can_distribute_keys: false,
                can_edit_posts: false,
                can_delete_posts: true,
                can_close_posts: false,
                can_pin_posts: false,
                can_move_posts: false,
                can_manage_trash: false,
                can_attach_images: false,
                can_retire_images: false,
                scope: Vec::new(),
                deleted: false,
                signed_at: SystemTime::UNIX_EPOCH,
            },
            &owner(),
        ));
        updated.roles.assignments.push(AuthorizedRoleAssignment::new(
            RoleAssignment {
                role_id,
                member_id: member_id(),
                generation: 1,
                revoked: false,
                signed_at: SystemTime::UNIX_EPOCH,
            },
            &owner(),
        ));
        state.authority = state.authority.merged_with(&updated);
        let target = state.header.as_ref().unwrap().header.id();
        state
            .actions
            .push(action(&member(), TopicActionKind::Delete, target, 1));
        state.verify(&params()).unwrap();
        assert!(state.is_deleted(target));
    }
}

#[cfg(test)]
mod reaction_tests {
    use super::tests::*;
    use super::*;
    use plaza_core::board_state::ban::{AuthorizedUserBan, UserBan};

    fn state_with_post() -> (TopicStateV1, MessageId) {
        let mut state = base_state();
        let entry = post(&member(), "hello", 1, 1);
        let id = entry.id();
        state.posts.insert(id, entry);
        (state, id)
    }

    #[test]
    fn a_participant_can_react_and_vote() {
        let (mut state, id) = state_with_post();
        state.actions.push(action(&member(), TopicActionKind::React, id, 1));
        state.actions.push(action(&member(), TopicActionKind::Vote, id, 1));
        state.verify(&params()).unwrap();
    }

    #[test]
    fn an_outsider_cannot_react() {
        let (mut state, id) = state_with_post();
        state.actions.push(action(&other(), TopicActionKind::React, id, 1));
        assert!(state.verify(&params()).is_err());
    }

    #[test]
    fn a_banned_member_cannot_react() {
        let (mut state, id) = state_with_post();
        state.authority.bans.0.push(AuthorizedUserBan::new(
            UserBan {
                owner_member_id: owner_id(),
                banned_at: at(1),
                banned_user: member_id(),
                expires_at: None,
                target_member: None,
                invite_chain: Vec::new(),
            },
            owner_id(),
            &owner(),
        ));
        state.actions.push(action(&member(), TopicActionKind::React, id, 1));
        assert!(state.verify(&params()).is_err());
    }
}

#[cfg(test)]
mod move_merge_split_tests {
    use super::tests::*;
    use super::*;

    fn signed_action(
        signer: &SigningKey,
        kind: TopicActionKind,
        target: MessageId,
        payload: SealedBytes,
    ) -> AuthorizedTopicActionV1 {
        let value = TopicActionV1 {
            kind,
            target,
            payload,
            generation: 1,
            created_at: 1,
            signer: MemberId::from(&signer.verifying_key()),
        };
        AuthorizedTopicActionV1 {
            signature: sign_struct(&value, signer),
            action: value,
            signer_key: Some(signer.verifying_key()),
            authority: None,
        }
    }

    #[test]
    fn a_move_action_changes_the_effective_section() {
        let mut state = base_state();
        let section = MessageId::from_bytes([9u8; 32]);
        let snapshot = SectionSnapshotV1 {
            section,
            parent: None,
            chain: vec![section],
            allowed_roles: Vec::new(),
            sealed_name: None,
            hidden: false,
            images_allowed: true,
            auto_moderated_topics: None,
            generation: 1,
            signed_at: 1,
        };
        let payload = SealedBytes::public(encode(&snapshot).unwrap());
        let target = state.header.as_ref().unwrap().header.id();
        state.actions.push(signed_action(
            &owner(),
            TopicActionKind::Move,
            target,
            payload,
        ));
        state.verify(&params()).unwrap();
        assert_eq!(state.effective_section().unwrap().section, section);
    }

    #[test]
    fn a_merge_action_records_the_destination() {
        let mut state = base_state();
        let destination = MessageId::from_bytes([4u8; 32]);
        let target = state.header.as_ref().unwrap().header.id();
        state.actions.push(signed_action(
            &owner(),
            TopicActionKind::Merge,
            target,
            SealedBytes::public(destination.as_bytes().to_vec()),
        ));
        state.verify(&params()).unwrap();
        assert_eq!(state.merged_into(), Some(destination));
    }

    #[test]
    fn a_split_action_marks_the_reply() {
        let mut state = base_state();
        let entry = post(&member(), "reply", 1, 1);
        let id = entry.id();
        state.posts.insert(id, entry);
        let destination = MessageId::from_bytes([5u8; 32]);
        state.actions.push(signed_action(
            &owner(),
            TopicActionKind::Split,
            id,
            SealedBytes::public(destination.as_bytes().to_vec()),
        ));
        state.verify(&params()).unwrap();
        assert!(state.is_split(id));
        assert_eq!(state.split_target(id), Some(destination));
    }
}

#[cfg(test)]
mod continuation_tests {
    use super::tests::*;
    use super::*;

    #[test]
    fn a_continuation_part_needs_the_previous_hash() {
        let mut state = base_state();
        state.generation = TopicGenerationV1 {
            part: 1,
            closed_at: None,
            next_part: None,
            previous_hash: Some([1u8; 32]),
        };
        let params = TopicParamsV1::new(owner().verifying_key(), [7u8; 32], 1);
        state.verify(&params).unwrap();

        state.generation.previous_hash = None;
        assert!(state.verify(&params).is_err());
    }

    #[test]
    fn the_first_part_cannot_carry_a_previous_hash() {
        let mut state = base_state();
        state.generation.previous_hash = Some([1u8; 32]);
        assert!(state.verify(&params()).is_err());
    }
}
