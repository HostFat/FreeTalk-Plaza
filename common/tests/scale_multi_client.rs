//! Structural cost of a sectioned board with many members, sections and
//! subscribers. This is not a network simulation: it measures the state and
//! the update payloads that the node would broadcast, then multiplies them by
//! the subscriber and section counts.
//!
//! Run in release:
//! `cargo test -p plaza-core --test scale_multi_client --release -- --ignored --nocapture`

use ed25519_dalek::SigningKey;
use freenet_stdlib::prelude::ContractInstanceId;
use plaza_core::board_state::activity::{
    ActivityDeltaV1, ActivityEntryV1, ActivityStateV1, MAX_ACTIVITY_ENTRIES,
};
use plaza_core::board_state::authority::{
    AuthorizedAuthorityRootV1, AuthorityRootStateV1, AuthorityTreeV1,
};
use plaza_core::board_state::configuration::{AuthorizedConfigurationV1, Configuration};
use plaza_core::board_state::member::{AuthorizedMember, Member, MemberId};
use plaza_core::board_state::message::MessageId;
use plaza_core::board_state::privacy::SealedBytes;
use plaza_core::board_state::report_feed::{
    ReportFeedDeltaV1, ReportFeedStateV1, MAX_REPORT_FEED,
};
use plaza_core::board_state::reports::ReportReason;
use plaza_core::board_state::sections::{AuthorizedSectionV1, SectionV1};
use plaza_core::board_state::topics::{
    AuthorizedTopicActivityV1, AuthorizedTopicEntryV1, AuthorizedTopicFlagV1,
    AuthorizedTopicReportResolutionV1, AuthorizedTopicReportV1, TopicActivityV1,
    TopicEntryV1, TopicFlagKind, TopicFlagV1, TopicIndexDelta, TopicIndexV1,
    TopicReportResolutionV1, TopicReportV1,
};
use plaza_core::board_state::{
    BoardModeV1, ChatBoardParametersV1, ChatBoardStateV1,
};
use plaza_core::util::sign_struct;
use std::hint::black_box;
use std::time::{Instant, SystemTime};

fn owner() -> SigningKey {
    SigningKey::from_bytes(&[1u8; 32])
}

fn member_key(index: usize) -> SigningKey {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&(index as u64).to_le_bytes());
    seed[8] = 0x42;
    seed[9] = 0x7f;
    SigningKey::from_bytes(&seed)
}

fn section_seed(index: usize) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&(index as u64).to_le_bytes());
    seed[8] = 0x33;
    seed
}

fn topic_seed(index: usize) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&(index as u64).to_le_bytes());
    seed[8] = 0x11;
    seed
}

fn contract_seed(index: usize) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&(index as u64).to_le_bytes());
    seed[8] = 0x44;
    seed
}

fn section_value(index: usize) -> SectionV1 {
    SectionV1 {
        id: MessageId::from_bytes(section_seed(index)),
        parent: None,
        name: format!("Section {index}"),
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
        contract: Some(ContractInstanceId::new(contract_seed(index))),
        signed_at: SystemTime::UNIX_EPOCH,
    }
}

fn params() -> ChatBoardParametersV1 {
    ChatBoardParametersV1 {
        owner: owner().verifying_key(),
    }
}

/// Parent board: configuration, `members` signed members and `sections`
/// sections with a child contract each. It keeps no topics.
fn parent(sections: usize, members: usize) -> ChatBoardStateV1 {
    let owner = owner();
    let owner_id = MemberId::from(&owner.verifying_key());
    let mut state = ChatBoardStateV1 {
        configuration: AuthorizedConfigurationV1::new(
            Configuration {
                owner_member_id: owner_id,
                ..Configuration::default()
            },
            &owner,
        ),
        mode: BoardModeV1::SectionedTopicIndex,
        ..Default::default()
    };
    for index in 0..members {
        state.members.members.push(AuthorizedMember::new(
            Member {
                owner_member_id: owner_id,
                invited_by: owner_id,
                member_vk: member_key(index).verifying_key(),
                join_proof: None,
            },
            &owner,
        ));
    }
    for index in 0..sections {
        state.sections.sections.push(AuthorizedSectionV1::new(
            section_value(index),
            &owner,
            None,
        ));
    }
    state
}

fn entry(section: MessageId, index: usize, members: usize) -> AuthorizedTopicEntryV1 {
    let author_index = index % members;
    let author = member_key(author_index);
    let topic_seed = {
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&(index as u64).to_le_bytes());
        seed[8] = 0x11;
        seed
    };
    // Each author gets at most one topic per hour, so the rate limit passes.
    let created_at = 1_000_000 + (index / members) as i64 * 3_600_001;
    AuthorizedTopicEntryV1::new(
        TopicEntryV1 {
            topic_id: MessageId::from_bytes(topic_seed),
            part: 0,
            protocol_version: 1,
            author: MemberId::from(&author.verifying_key()),
            section: Some(section),
            section_chain: vec![section],
            title: SealedBytes::public(b"Title".to_vec()),
            preview: SealedBytes::public(b"Preview".to_vec()),
            header_hash: topic_seed,
            created_at,
            generation: 1,
        },
        &author,
    )
}

fn activity(
    _section: MessageId,
    index: usize,
    members: usize,
    generation: u64,
) -> AuthorizedTopicActivityV1 {
    let author = member_key(index % members);
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&(index as u64).to_le_bytes());
    seed[8] = 0x11;
    let value = TopicActivityV1 {
        topic_id: MessageId::from_bytes(seed),
        last_activity: 2_000_000 + index as i64,
        last_post_id: None,
        reply_count: 1,
        pending_approvals: 0,
        generation,
    };
    AuthorizedTopicActivityV1 {
        signature: sign_struct(&value, &author),
        activity: value,
        signer: Some(MemberId::from(&author.verifying_key())),
        signer_key: Some(author.verifying_key()),
    }
}

fn flag(section: MessageId, index: usize) -> AuthorizedTopicFlagV1 {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&(index as u64).to_le_bytes());
    seed[8] = 0x11;
    let value = TopicFlagV1 {
        topic_id: MessageId::from_bytes(seed),
        kind: TopicFlagKind::Pinned,
        value: true,
        destination: None,
        section: None,
        section_chain: Vec::new(),
        part: None,
        scope_chain: vec![section],
        generation: 1,
        created_at: 1,
    };
    AuthorizedTopicFlagV1 {
        signature: sign_struct(&value, &owner()),
        flag: value,
        signer: Some(MemberId::from(&owner().verifying_key())),
        signer_key: Some(owner().verifying_key()),
        authority: None,
    }
}

fn report(_section: MessageId, index: usize, members: usize) -> AuthorizedTopicReportV1 {
    let reporter = member_key(index % members);
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&(index as u64).to_le_bytes());
    seed[8] = 0x11;
    let value = TopicReportV1 {
        topic_id: MessageId::from_bytes(seed),
        post_id: Some(MessageId::from_bytes([0x55u8; 32])),
        reporter: MemberId::from(&reporter.verifying_key()),
        reason: ReportReason::Spam,
        body: SealedBytes::public(b"Report".to_vec()),
        created_at: 3_000_000 + index as i64,
        generation: 1,
    };
    AuthorizedTopicReportV1 {
        signature: sign_struct(&value, &reporter),
        report: value,
    }
}

/// One section child: the parent authority plus the topics of one section.
fn child(parent: ChatBoardStateV1, section_index: usize, topics: usize, members: usize) -> ChatBoardStateV1 {
    child_range(parent, section_index, 0, topics, members)
}

/// One section page: the parent authority plus a range of topic entries.
fn child_range(
    parent: ChatBoardStateV1,
    section_index: usize,
    start: usize,
    topics: usize,
    members: usize,
) -> ChatBoardStateV1 {
    let section_id = MessageId::from_bytes(section_seed(section_index));
    let mut state = parent;
    state.topics = TopicIndexV1::default();
    for index in start..start + topics {
        state.topics.entries.push(entry(section_id, index, members));
        state
            .topics
            .activity
            .push(activity(section_id, index, members, 1));
        state.topics.flags.push(flag(section_id, index));
        if index % 4 == 0 {
            state.topics.reports.push(report(section_id, index, members));
        }
    }
    state
}

fn serialized_len(state: &ChatBoardStateV1) -> usize {
    serialized_len_value(state)
}

fn serialized_len_value<T: serde::Serialize>(value: &T) -> usize {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes).unwrap();
    bytes.len()
}

fn activity_contract(members: usize) -> ActivityStateV1 {
    let entries = (0..MAX_ACTIVITY_ENTRIES)
        .map(|index| {
            let author = member_key(index % members);
            let topic_id = MessageId::from_bytes(topic_seed(index));
            let value = TopicActivityV1 {
                topic_id,
                last_activity: 1_000_000 + index as i64,
                last_post_id: None,
                reply_count: 1,
                pending_approvals: 0,
                generation: 1,
            };
            ActivityEntryV1 {
                topic_id,
                part: 0,
                activity: AuthorizedTopicActivityV1 {
                    signature: sign_struct(&value, &author),
                    activity: value,
                    signer: Some(MemberId::from(&author.verifying_key())),
                    signer_key: Some(author.verifying_key()),
                },
            }
        })
        .collect();
    let mut state = ActivityStateV1::default();
    state
        .apply_delta(&ActivityDeltaV1 { entries })
        .expect("the activity state verifies");
    state
}

fn moderation_feed() -> ReportFeedStateV1 {
    let owner_key = owner();
    let owner_id = MemberId::from(&owner_key.verifying_key());
    let mut reports = Vec::new();
    let mut resolutions = Vec::new();
    for index in 0..MAX_REPORT_FEED {
        let topic_id = MessageId::from_bytes(topic_seed(index));
        let report = TopicReportV1 {
            topic_id,
            post_id: None,
            reporter: owner_id,
            reason: ReportReason::Spam,
            body: SealedBytes::public(b"Spam".to_vec()),
            created_at: 1_000_000 + index as i64,
            generation: 1,
        };
        reports.push(AuthorizedTopicReportV1 {
            signature: sign_struct(&report, &owner_key),
            report,
        });
        let resolution = TopicReportResolutionV1 {
            topic_id,
            post_id: None,
            reporter: owner_id,
            resolved_by: owner_id,
            created_at: 2_000_000 + index as i64,
            generation: 1,
        };
        resolutions.push(AuthorizedTopicReportResolutionV1 {
            signature: sign_struct(&resolution, &owner_key),
            resolution,
            signer_key: Some(owner_key.verifying_key()),
            authority: None,
        });
    }
    let mut state = ReportFeedStateV1::default();
    state
        .apply_delta(&ReportFeedDeltaV1 {
            reports,
            resolutions,
        })
        .expect("the moderation feed verifies");
    state
}

fn verify_time(state: &ChatBoardStateV1, section: Option<MessageId>) -> f64 {
    let params = params();
    let start = Instant::now();
    black_box(state.verify_with_section(&params, section).unwrap());
    start.elapsed().as_secs_f64() * 1000.0
}

fn run(sections: usize, members: usize, topics: usize, subscribers: usize) {
    let parent = parent(sections, members);
    let parent_size = serialized_len(&parent);
    let parent_verify = verify_time(&parent, None);

    let child = child(parent.clone(), 0, topics, members);
    let section_id = MessageId::from_bytes(section_seed(0));
    let child_size = serialized_len(&child);
    let child_verify = verify_time(&child, Some(section_id));

    // The client now gives a child only the members its index references.
    let mut pruned = child.clone();
    let needed: std::collections::HashSet<MemberId> = child
        .topics
        .entries
        .iter()
        .map(|entry| entry.entry.author)
        .collect();
    pruned
        .members
        .members
        .retain(|member| needed.contains(&member.member.id()));
    let pruned_size = serialized_len(&pruned);
    let pruned_verify = verify_time(&pruned, Some(section_id));

    let delta = TopicIndexDelta {
        activity: vec![activity(section_id, 0, members, 2)],
        ..Default::default()
    };
    let mut fast = child.clone();
    let start = Instant::now();
    fast.apply_topics_delta(&params(), &delta).unwrap();
    let delta_ms = start.elapsed().as_secs_f64() * 1000.0;
    let start = Instant::now();
    for entry in &fast.topics.entries {
        black_box(entry.entry.section);
    }
    let layout_ms = start.elapsed().as_secs_f64() * 1000.0;

    let pruned_mib = pruned_size as f64 / (1024.0 * 1024.0);
    let parent_kib = parent_size as f64 / 1024.0;
    let activity = activity_contract(members);
    let activity_kib = serialized_len_value(&activity) as f64 / 1024.0;
    let activity_mib = activity_kib / 1024.0;

    println!("\n=== scenario ===");
    println!(
        "sections={sections} members={members} topics/section={topics} subscribers/section={subscribers}"
    );
    println!(
        "parent:   {:>7.1} KiB   verify {:>8.1} ms   (sections + members only)",
        parent_kib, parent_verify
    );
    println!(
        "child:    {:>7.1} KiB   verify {:>8.1} ms   (parent + one section index)",
        child_size as f64 / 1024.0,
        child_verify
    );
    println!(
        "pruned:   {:>7.1} KiB   verify {:>8.1} ms   (only members the index references)",
        pruned_size as f64 / 1024.0,
        pruned_verify
    );
    println!(
        "legacy section activity delta: {:>6.1} ms + {:>5.1} ms layout scan (no longer used)",
        delta_ms, layout_ms
    );
    println!(
        "activity contract: {:>7.1} KiB; fan-out {:.2} MiB per update ({MAX_ACTIVITY_ENTRIES} entries x {subscribers} subscribers)",
        activity_kib,
        activity_mib * subscribers as f64
    );
    println!(
        "storage:  {:>7.1} MiB across {sections} pruned children (O(sections x referenced members + sections^2))",
        pruned_mib * sections as f64
    );
    // The client sends a delta with the new entry, not the full index state.
    let new_topic = TopicIndexDelta {
        entries: vec![entry(section_id, topics, members)],
        ..Default::default()
    };
    let new_topic_kib = serialized_len_value(&new_topic) as f64 / 1024.0;
    let moderation = moderation_feed();
    let moderation_kib = serialized_len_value(&moderation) as f64 / 1024.0;
    let moderation_delta = ReportFeedDeltaV1 {
        reports: vec![moderation.reports[0].clone()],
        resolutions: Vec::new(),
    };
    let moderation_delta_kib = serialized_len_value(&moderation_delta) as f64 / 1024.0;
    println!(
        "moderation feed: {:>7.1} KiB (500 reports + 500 resolutions); new report delta {:.1} KiB, fan-out {:.2} MiB ({subscribers} subscribers)",
        moderation_kib,
        moderation_delta_kib,
        moderation_delta_kib / 1024.0 * subscribers as f64
    );
    println!(
        "board activity writes: 0 (a reply writes the topic and the activity contract)"
    );
    println!("board report writes: 0 (a report writes the moderation contract)");
    println!(
        "new topic delta: {:>6.1} KiB; fan-out {:.2} MiB ({subscribers} subscribers)",
        new_topic_kib,
        new_topic_kib / 1024.0 * subscribers as f64
    );
    println!(
        "new subscriber bootstrap: {:.1} KiB (pruned index state)",
        pruned_size as f64 / 1024.0
    );
    println!(
        "authority sync:  {:.2} MiB to all children (pruned state x {sections})",
        pruned_mib * sections as f64
    );

    println!(
        "authority propagation now reaches every topic with a Merkle root and \
         per-member proofs; role definitions remain in the topic"
    );
}

/// Compare one whole section index with one page of it. The page is the unit
/// a client loads for a new subscriber and the write target of a new topic.
fn page_scenario(members: usize, topics: usize, page_size: usize, subscribers: usize) {
    let parent = parent(1, members);
    let section_id = MessageId::from_bytes(section_seed(0));
    let mut whole = child(parent.clone(), 0, topics, members);
    let whole_needed: std::collections::HashSet<MemberId> = whole
        .topics
        .entries
        .iter()
        .map(|entry| entry.entry.author)
        .collect();
    whole
        .members
        .members
        .retain(|member| whole_needed.contains(&member.member.id()));
    let whole_kib = serialized_len(&whole) as f64 / 1024.0;
    let whole_verify = verify_time(&whole, Some(section_id));

    let page_start = topics.saturating_sub(page_size);
    let page_count = topics.div_ceil(page_size).max(1);
    let mut page = child_range(parent, 0, page_start, topics - page_start, members);
    // The client prunes child authority to the members its index references.
    let page_needed: std::collections::HashSet<MemberId> = page
        .topics
        .entries
        .iter()
        .map(|entry| entry.entry.author)
        .collect();
    page
        .members
        .members
        .retain(|member| page_needed.contains(&member.member.id()));
    let page_kib = serialized_len(&page) as f64 / 1024.0;
    let page_verify = verify_time(&page, Some(section_id));

    let delta = TopicIndexDelta {
        entries: vec![entry(section_id, topics, members)],
        ..Default::default()
    };
    let delta_kib = serialized_len_value(&delta) as f64 / 1024.0;

    println!("\n=== pages ===");
    println!(
        "members={members} topics/section={topics} page_size={page_size} pages={page_count} subscribers={subscribers}"
    );
    println!(
        "section:  {:>7.1} KiB   verify {:>8.1} ms   (all topics)",
        whole_kib, whole_verify
    );
    println!(
        "page:     {:>7.1} KiB   verify {:>8.1} ms   (topics {page_start}..{topics})",
        page_kib, page_verify
    );
    println!(
        "new topic delta: {:>6.1} KiB; fan-out {:.2} MiB ({subscribers} subscribers)",
        delta_kib,
        delta_kib / 1024.0 * subscribers as f64
    );
    println!(
        "new subscriber bootstrap: page {:.1} KiB instead of section {:.1} KiB",
        page_kib, whole_kib
    );
}

fn sign_owner_root(state: &mut ChatBoardStateV1) {
    let tree = AuthorityTreeV1::from_board(state);
    let mut root = tree.root(1_000);
    root.content_hash = tree.content_hash();
    state.authority_root = AuthorityRootStateV1(Some(AuthorizedAuthorityRootV1::new(
        root,
        &owner(),
    )));
}

fn membership_scenario(members: usize, sections: usize) {
    let mut board = parent(sections, members);
    let size = serialized_len(&board) as f64 / 1024.0;
    let full_verify = verify_time(&board, None);

    let start = Instant::now();
    let tree = AuthorityTreeV1::from_board(&board);
    black_box(tree.content_hash());
    let tree_ms = start.elapsed().as_secs_f64() * 1000.0;

    sign_owner_root(&mut board);
    let fast_verify = verify_time(&board, None);
    println!(
        "members={members:>6} sections={sections:>3} board={size:>8.1} KiB \
         full {full_verify:>8.1} ms tree {tree_ms:>7.1} ms fast {fast_verify:>7.1} ms"
    );
}

#[test]
#[ignore = "scale benchmark; run in release"]
fn scale_multi_client_benchmark() {
    for (sections, members, topics, subscribers) in [
        (20, 1_000, 200, 50),
        (100, 1_000, 200, 50),
    ] {
        run(sections, members, topics, subscribers);
    }
    page_scenario(1_000, 2_000, 200, 50);
}

#[test]
#[ignore = "scale benchmark; run in release"]
fn membership_scale_benchmark() {
    println!("\n=== membership ===");
    for members in [1_000, 5_000, 10_000] {
        membership_scenario(members, 10);
    }
    membership_scenario(10_000, 100);
}
