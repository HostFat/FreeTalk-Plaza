//! Fast automated SLO regression suite for CI.
//!
//! Unlike `scale_multi_client` (which benchmarks 10,000-member full verifies and
//! takes ~2 minutes), `scale_slo` runs in a few seconds in `--release` and
//! enforces hard size/latency budgets across every sharded contract so future
//! changes cannot silently reintroduce O(N) blowups.
//!
//! Run with:
//! `cargo test -p plaza-core --test scale_slo --release -- --nocapture`

use ed25519_dalek::SigningKey;
use plaza_core::board_state::activity::{
    ActivityDeltaV1, ActivityEntryV1, ActivityParametersV1, ActivityStateV1, MAX_ACTIVITY_ENTRIES,
};
use plaza_core::board_state::authority::{
    AuthorityRootStateV1, AuthorityTreeV1, AuthorizedAuthorityRootV1,
};
use plaza_core::board_state::configuration::{AuthorizedConfigurationV1, Configuration};
use plaza_core::board_state::member::{AuthorizedMember, Member, MemberId};
use plaza_core::board_state::member_info::MemberInfo;
use plaza_core::board_state::member_shards::{
    member_shard_bucket, MemberProofV1, MemberShardDeltaV1, MemberShardEntryV1,
    MemberShardParametersV1, MemberShardStateV1, MEMBER_SHARD_COUNT,
};
use plaza_core::board_state::message::MessageId;
use plaza_core::board_state::privacy::SealedBytes;
use plaza_core::board_state::profiles::{
    profile_shard_bucket, ProfileDeltaV1, ProfileEntryV1, ProfileShardParametersV1, ProfileStateV1,
    PROFILE_SHARD_COUNT,
};
use plaza_core::board_state::rate_limit::system_time_from_ms;
use plaza_core::board_state::report_feed::{
    ModerationParametersV1, ReportFeedDeltaV1, ReportFeedStateV1,
};
use plaza_core::board_state::reports::ReportReason;
use plaza_core::board_state::section_pages::{
    AuthorizedSectionPageHeaderV1, AuthorizedSectionPageSealV1, SectionPageDeltaV1,
    SectionPageHeaderV1, SectionPageStateV1,
};
use plaza_core::board_state::sections::{AuthorizedSectionV1, SectionParametersV1, SectionV1};
use plaza_core::board_state::topics::{
    AuthorizedTopicActivityV1, AuthorizedTopicEntryV1, AuthorizedTopicReportResolutionV1,
    AuthorizedTopicReportV1, TopicActivityV1, TopicEntryV1, TopicReportResolutionV1, TopicReportV1,
};
use plaza_core::board_state::{BoardModeV1, ChatBoardParametersV1, ChatBoardStateV1};
use plaza_core::util::sign_struct;
use std::time::Instant;

fn cbor_len<T: serde::Serialize>(value: &T) -> usize {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes).expect("cbor serialize");
    bytes.len()
}

fn key_for(seed: u64) -> SigningKey {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes[31] = 0x5A;
    SigningKey::from_bytes(&bytes)
}

fn member_proof(owner: &SigningKey, member_sk: &SigningKey) -> (AuthorizedMember, MemberProofV1) {
    let owner_id = MemberId::from(&owner.verifying_key());
    let authorized = AuthorizedMember::new(
        Member {
            owner_member_id: owner_id,
            invited_by: owner_id,
            member_vk: member_sk.verifying_key(),
            join_proof: None,
        },
        owner,
    );
    let proof = MemberProofV1 {
        ownership_transfers: Vec::new(),
        transfer_admins: Vec::new(),
        membership: Some(Box::new(MemberShardEntryV1 {
            member: authorized.clone(),
            invite_chain: Vec::new(),
            invite_token: None,
            ownership_transfers: Vec::new(),
            transfer_admins: Vec::new(),
        })),
    };
    (authorized, proof)
}

#[test]
fn slo_compact_sealed_section_page_size_and_verify() {
    let owner = key_for(1);
    let section = MessageId::from_bytes([7u8; 32]);
    let params = SectionParametersV1 {
        owner: owner.verifying_key(),
        section,
        page: 1,
    };
    let header = AuthorizedSectionPageHeaderV1::new(
        SectionPageHeaderV1 {
            board: owner.verifying_key().to_bytes(),
            section,
            section_chain: vec![section],
            page: 1,
            page_size: 200,
            allowed_roles: Vec::new(),
            created_at: 1_000,
        },
        &owner,
    );
    let mut page = SectionPageStateV1 {
        header: Some(header),
        ..Default::default()
    };
    let mut authors = Vec::with_capacity(200);
    let mut entries = Vec::with_capacity(200);
    for i in 0..200u64 {
        let sk = key_for(100 + i);
        let (auth_member, _) = member_proof(&owner, &sk);
        authors.push(auth_member);
        let mut topic_bytes = [0u8; 32];
        topic_bytes[..8].copy_from_slice(&i.to_le_bytes());
        topic_bytes[31] = 0xAA;
        entries.push(AuthorizedTopicEntryV1::new(
            TopicEntryV1 {
                topic_id: MessageId::from_bytes(topic_bytes),
                part: 0,
                protocol_version: 1,
                author: MemberId::from(&sk.verifying_key()),
                section: Some(section),
                section_chain: vec![section],
                title: SealedBytes::public(b"SLO Topic Title".to_vec()),
                preview: SealedBytes::public(b"Short topic preview for SLO budget".to_vec()),
                header_hash: topic_bytes,
                created_at: 10_000 + i as i64,
                generation: 1,
            },
            &sk,
        ));
    }
    page.apply_delta(
        &params,
        &SectionPageDeltaV1 {
            authors,
            entries: entries[..199].to_vec(),
            ..Default::default()
        },
    )
    .unwrap();
    let one_topic_delta = SectionPageDeltaV1 {
        entries: vec![entries[199].clone()],
        ..Default::default()
    };
    let delta_bytes = cbor_len(&one_topic_delta);
    page.apply_delta(&params, &one_topic_delta).unwrap();
    let open_bytes = cbor_len(&page);

    let seal = AuthorizedSectionPageSealV1::new(&params, &page.entries, &owner, 50_000).unwrap();
    page.apply_delta(
        &params,
        &SectionPageDeltaV1 {
            seal: Some(seal),
            ..Default::default()
        },
    )
    .unwrap();
    let sealed_bytes = cbor_len(&page);
    let t0 = Instant::now();
    page.verify(&params).unwrap();
    let sealed_verify_ms = t0.elapsed().as_secs_f64() * 1_000.0;

    println!(
        "[SLO section_page] open={:.1} KiB, sealed={:.1} KiB, 1-topic delta={:.2} KiB, sealed_verify={:.2} ms",
        open_bytes as f64 / 1024.0,
        sealed_bytes as f64 / 1024.0,
        delta_bytes as f64 / 1024.0,
        sealed_verify_ms,
    );
    assert!(open_bytes <= 260 * 1024, "open section page exceeded 260 KiB: {open_bytes}");
    assert!(sealed_bytes <= 165 * 1024, "sealed section page exceeded 165 KiB: {sealed_bytes}");
    assert!(delta_bytes <= 2 * 1024, "1-topic delta exceeded 2 KiB: {delta_bytes}");
    if !cfg!(debug_assertions) {
        assert!(
            sealed_verify_ms <= 80.0,
            "sealed page verify exceeded 80 ms: {sealed_verify_ms:.2} ms"
        );
    }
}

#[test]
fn slo_sharded_members_and_profiles_budgets() {
    let owner = key_for(2);
    let mut member_buckets = vec![MemberShardStateV1::default(); MEMBER_SHARD_COUNT as usize];
    let mut profile_buckets = vec![ProfileStateV1::default(); PROFILE_SHARD_COUNT as usize];

    let total_members = 1_600u64; // ~50 per bucket -> fast in CI, verifies exact sharding ratio
    let mut last_join_delta = 0usize;
    let mut last_rename_delta = 0usize;
    for i in 0..total_members {
        let sk = key_for(1_000 + i);
        let id = MemberId::from(&sk.verifying_key());
        let (auth_member, proof) = member_proof(&owner, &sk);
        let m_bucket = member_shard_bucket(&id);
        let p_bucket = profile_shard_bucket(&id);
        assert_eq!(m_bucket, p_bucket);

        let m_delta = MemberShardDeltaV1 {
            entries: vec![MemberShardEntryV1 {
                member: auth_member,
                invite_chain: Vec::new(),
                invite_token: None,
                ownership_transfers: Vec::new(),
                transfer_admins: Vec::new(),
            }],
        };
        if i + 1 == total_members {
            last_join_delta = cbor_len(&m_delta);
        }
        member_buckets[m_bucket as usize]
            .apply_delta(
                &MemberShardParametersV1 {
                    owner: owner.verifying_key(),
                    bucket: m_bucket,
                },
                &m_delta,
            )
            .unwrap();

        let p_entry = ProfileEntryV1::new(
            MemberInfo {
                member_id: id,
                version: 1,
                preferred_nickname: SealedBytes::public(format!("User{i}").into_bytes()),
            },
            &sk,
        )
        .with_proof(proof);
        let p_delta = ProfileDeltaV1 {
            entries: vec![p_entry],
        };
        if i + 1 == total_members {
            last_rename_delta = cbor_len(&p_delta);
        }
        profile_buckets[p_bucket as usize]
            .apply_delta(
                &ProfileShardParametersV1 {
                    owner: owner.verifying_key(),
                    bucket: p_bucket,
                },
                &p_delta,
            )
            .unwrap();
    }

    let max_member_bucket = member_buckets.iter().map(cbor_len).max().unwrap();
    let max_profile_bucket = profile_buckets.iter().map(cbor_len).max().unwrap();
    println!(
        "[SLO shards @ {total_members} members] max_member_bucket={:.1} KiB (join={:.2} KiB), max_profile_bucket={:.1} KiB (rename={:.2} KiB)",
        max_member_bucket as f64 / 1024.0,
        last_join_delta as f64 / 1024.0,
        max_profile_bucket as f64 / 1024.0,
        last_rename_delta as f64 / 1024.0,
    );
    assert!(
        max_member_bucket <= 40 * 1024,
        "member shard bucket exceeded 40 KiB at 1600 members: {max_member_bucket}"
    );
    assert!(
        max_profile_bucket <= 80 * 1024,
        "profile shard bucket exceeded 80 KiB at 1600 members: {max_profile_bucket}"
    );
    assert!(last_join_delta <= 1024, "member join delta exceeded 1 KiB: {last_join_delta}");
    assert!(
        last_rename_delta <= 1536,
        "profile rename delta with MemberProofV1 exceeded 1.5 KiB: {last_rename_delta}"
    );
}

#[test]
fn slo_sharded_activity_and_moderation_feeds() {
    let owner = key_for(3);
    let section = MessageId::from_bytes([9u8; 32]);
    let act_params = ActivityParametersV1 {
        owner: owner.verifying_key(),
        section: Some(section),
    };
    let mod_params = ModerationParametersV1 {
        owner: owner.verifying_key(),
        section: Some(section),
    };

    let mut act_state = ActivityStateV1::default();
    let mut mod_state = ReportFeedStateV1::default();
    let mut one_act_delta = 0usize;
    let mut one_rep_delta = 0usize;

    for i in 0..MAX_ACTIVITY_ENTRIES as u64 {
        let sk = key_for(5_000 + i);
        let id = MemberId::from(&sk.verifying_key());
        let (_, proof) = member_proof(&owner, &sk);
        let mut topic_bytes = [0u8; 32];
        topic_bytes[..8].copy_from_slice(&i.to_le_bytes());
        topic_bytes[31] = 0xAA;
        let topic_id = MessageId::from_bytes(topic_bytes);

        let act_val = TopicActivityV1 {
            topic_id,
            last_activity: 100_000 + i as i64,
            last_post_id: None,
            reply_count: 1,
            pending_approvals: 0,
            generation: 1,
        };
        let act_entry = ActivityEntryV1 {
            topic_id,
            part: 0,
            activity: AuthorizedTopicActivityV1 {
                signature: sign_struct(&act_val, &sk),
                activity: act_val,
                signer: Some(id),
                signer_key: Some(sk.verifying_key()),
            },
            proof: Some(Box::new(proof.clone())),
        };
        let a_delta = ActivityDeltaV1 {
            entries: vec![act_entry],
        };
        if i + 1 == MAX_ACTIVITY_ENTRIES as u64 {
            one_act_delta = cbor_len(&a_delta);
        }
        act_state.apply_delta(&act_params, &a_delta).unwrap();

        let rep_val = TopicReportV1 {
            topic_id,
            post_id: None,
            reporter: id,
            reason: ReportReason::Spam,
            body: SealedBytes::public(b"Spam report".to_vec()),
            created_at: 200_000 + i as i64,
            generation: 1,
        };
        let rep = AuthorizedTopicReportV1 {
            signature: sign_struct(&rep_val, &sk),
            report: rep_val,
            signer_key: Some(sk.verifying_key()),
            proof: Some(Box::new(proof)),
        };
        let res_val = TopicReportResolutionV1 {
            topic_id,
            post_id: None,
            reporter: id,
            resolved_by: MemberId::from(&owner.verifying_key()),
            created_at: 200_500 + i as i64,
            generation: 1,
        };
        let res = AuthorizedTopicReportResolutionV1 {
            signature: sign_struct(&res_val, &owner),
            resolution: res_val,
            signer_key: Some(owner.verifying_key()),
            authority: None,
            ownership_transfers: Vec::new(),
            transfer_admins: Vec::new(),
        };
        let r_delta = ReportFeedDeltaV1 {
            reports: vec![rep],
            resolutions: vec![res],
        };
        if i + 1 == MAX_ACTIVITY_ENTRIES as u64 {
            one_rep_delta = cbor_len(&r_delta);
        }
        mod_state.apply_delta(&mod_params, &r_delta).unwrap();
    }

    let act_bytes = cbor_len(&act_state);
    let mod_bytes = cbor_len(&mod_state);
    println!(
        "[SLO feeds @ 200 entries] activity={:.1} KiB (delta={:.2} KiB), moderation={:.1} KiB (delta={:.2} KiB)",
        act_bytes as f64 / 1024.0,
        one_act_delta as f64 / 1024.0,
        mod_bytes as f64 / 1024.0,
        one_rep_delta as f64 / 1024.0,
    );
    assert!(act_bytes <= 220 * 1024, "activity feed exceeded 220 KiB: {act_bytes}");
    assert!(one_act_delta <= 1536, "1-entry activity delta exceeded 1.5 KiB: {one_act_delta}");
    assert!(mod_bytes <= 300 * 1024, "moderation feed (200+200) exceeded 300 KiB: {mod_bytes}");
    assert!(
        one_rep_delta <= 2048,
        "1-report+resolution delta exceeded 2 KiB: {one_rep_delta}"
    );
}

#[test]
fn slo_authority_root_fast_path() {
    let owner = key_for(4);
    let params = ChatBoardParametersV1 {
        owner: owner.verifying_key(),
    };
    let mut state = ChatBoardStateV1::default();
    state.mode = BoardModeV1::SectionedTopicIndex;
    state.configuration = AuthorizedConfigurationV1::new(Configuration::default(), &owner);
    let section_id = MessageId::from_bytes([12u8; 32]);
    state.sections.sections.push(AuthorizedSectionV1::new(
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
            signed_at: system_time_from_ms(1_000),
        },
        &owner,
        None,
    ));
    for i in 0..1_000u64 {
        let sk = key_for(20_000 + i);
        let (auth_member, _) = member_proof(&owner, &sk);
        state.members.members.push(auth_member);
    }
    let tree = AuthorityTreeV1::from_board(&state);
    let mut root = tree.root(2_000);
    root.content_hash = tree.content_hash();
    state.authority_root = AuthorityRootStateV1(Some(AuthorizedAuthorityRootV1::new(root, &owner)));

    let t0 = Instant::now();
    state.verify_with_section(&params, None).unwrap();
    let fast_ms = t0.elapsed().as_secs_f64() * 1_000.0;
    println!("[SLO authority_root @ 1000 members] fast_verify={fast_ms:.2} ms");
    if !cfg!(debug_assertions) {
        assert!(
            fast_ms <= 500.0,
            "authority root fast verify exceeded 500 ms at 1000 members: {fast_ms:.2} ms"
        );
    }
}
