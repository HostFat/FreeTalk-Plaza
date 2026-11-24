//! Structural cost of a sectioned board with many members, sections and
//! subscribers. This is not a network simulation: it measures the state and
//! the update payloads that the node would broadcast, then multiplies them by
//! the subscriber and section counts.
//!
//! Run in release:
//! `cargo test -p plaza-core --test scale_multi_client --release -- --ignored --nocapture`

use ed25519_dalek::SigningKey;
use freenet_stdlib::prelude::ContractInstanceId;
use plaza_core::board_state::configuration::{AuthorizedConfigurationV1, Configuration};
use plaza_core::board_state::member::{AuthorizedMember, Member, MemberId};
use plaza_core::board_state::message::MessageId;
use plaza_core::board_state::privacy::SealedBytes;
use plaza_core::board_state::reports::ReportReason;
use plaza_core::board_state::sections::{AuthorizedSectionV1, SectionV1};
use plaza_core::board_state::topics::{
    AuthorizedTopicActivityV1, AuthorizedTopicEntryV1, AuthorizedTopicFlagV1,
    AuthorizedTopicReportV1, TopicActivityV1, TopicEntryV1, TopicFlagKind, TopicFlagV1,
    TopicIndexDelta, TopicIndexV1, TopicReportV1,
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
    let section_id = MessageId::from_bytes(section_seed(section_index));
    let mut state = parent;
    state.topics = TopicIndexV1::default();
    for index in 0..topics {
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
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(state, &mut bytes).unwrap();
    bytes.len()
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

    let child_mib = child_size as f64 / (1024.0 * 1024.0);
    let parent_kib = parent_size as f64 / 1024.0;

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
        "activity delta: {:>6.1} ms + {:>5.1} ms layout scan (vs full verify above)",
        delta_ms, layout_ms
    );
    println!(
        "storage:  {:>7.1} MiB across {sections} children (O(sections x members + sections^2))",
        child_mib * sections as f64
    );
    println!(
        "activity update: {:.2} MiB per coalesced window (child state x {subscribers} subscribers)",
        child_mib * subscribers as f64
    );
    println!(
        "new topic:       {:.2} MiB per subscriber fan-out",
        child_mib * subscribers as f64
    );
    println!(
        "authority sync:  {:.2} MiB to all children (child state x {sections})",
        child_mib * sections as f64
    );
    println!(
        "authority propagation to topics is capped at 100 topics today; \
         each topic also carries a copy of roles/bans/suspensions"
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
}
