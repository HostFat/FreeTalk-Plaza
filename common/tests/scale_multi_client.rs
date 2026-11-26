//! Structural cost of a sectioned board with many members, sections and
//! subscribers. This is not a network simulation: it measures the state and
//! the update payloads that the node would broadcast, then multiplies them by
//! the subscriber and section counts.
//!
//! Run in release:
//! `cargo test -p plaza-core --test scale_multi_client --release -- --ignored --nocapture`

use ed25519_dalek::SigningKey;
use freenet_scaffold::ComposableState;
use freenet_stdlib::prelude::ContractInstanceId;
use plaza_core::board_state::activity::{
    ActivityDeltaV1, ActivityEntryV1, ActivityParametersV1, ActivityStateV1, MAX_ACTIVITY_ENTRIES,
};
use plaza_core::board_state::authority::{
    AuthorizedAuthorityRootV1, AuthorityRootStateV1, AuthorityTreeV1,
};
use plaza_core::board_state::configuration::{AuthorizedConfigurationV1, Configuration};
use plaza_core::board_state::member::{AuthorizedMember, Member, MemberId};
use plaza_core::board_state::member_info::{AuthorizedMemberInfo, MemberInfo};
use plaza_core::board_state::member_shards::{
    member_shard_bucket, MemberProofV1, MemberShardDeltaV1, MemberShardEntryV1,
    MemberShardParametersV1, MemberShardStateV1, MEMBER_SHARD_COUNT,
};
use plaza_core::board_state::message::MessageId;
use plaza_core::board_state::privacy::SealedBytes;
use plaza_core::board_state::profiles::{
    profile_shard_bucket, ProfileDeltaV1, ProfileEntryV1, ProfileShardParametersV1,
    ProfileStateV1, PROFILE_SHARD_COUNT,
};
use plaza_core::board_state::report_feed::{
    ModerationParametersV1, ReportFeedDeltaV1, ReportFeedStateV1, MAX_REPORT_FEED,
};
use plaza_core::board_state::reports::ReportReason;
use plaza_core::board_state::section_pages::{
    AuthorizedSectionPageHeaderV1, AuthorizedSectionPageSealV1, SectionPageDeltaV1,
    SectionPageHeaderV1, SectionPageStateV1,
};
use plaza_core::board_state::sections::{AuthorizedSectionV1, SectionParametersV1, SectionV1};
use plaza_core::board_state::topics::{
    AuthorizedTopicActivityV1, AuthorizedTopicEntryV1, AuthorizedTopicFlagV1,
    AuthorizedTopicReportResolutionV1, AuthorizedTopicReportV1, TopicActivityV1,
    TopicEntryV1, TopicFlagKind, TopicFlagV1, TopicIndexDelta, TopicIndexV1,
    TopicReportResolutionV1, TopicReportV1,
};
use plaza_core::board_state::{
    BoardModeV1, ChatBoardParametersV1, ChatBoardStateV1, ChatBoardStateV1Delta,
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
        destination_sections: Vec::new(),
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
        signer_key: Some(reporter.verifying_key()),
        proof: None,
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

fn bench_member_proof(member_sk: &SigningKey) -> MemberProofV1 {
    let owner_sk = owner();
    let owner_id = MemberId::from(&owner_sk.verifying_key());
    MemberProofV1 {
        ownership_transfers: Vec::new(),
        transfer_admins: Vec::new(),
        membership: Some(Box::new(MemberShardEntryV1 {
            member: AuthorizedMember::new(
                Member {
                    owner_member_id: owner_id,
                    invited_by: owner_id,
                    member_vk: member_sk.verifying_key(),
                    join_proof: None,
                },
                &owner_sk,
            ),
            invite_chain: Vec::new(),
            invite_token: None,
            ownership_transfers: Vec::new(),
            transfer_admins: Vec::new(),
        })),
    }
}

fn activity_contract(members: usize, section: Option<MessageId>) -> ActivityStateV1 {
    let act_params = ActivityParametersV1 {
        owner: owner().verifying_key(),
        section,
    };
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
                proof: Some(Box::new(bench_member_proof(&author))),
            }
        })
        .collect();
    let mut state = ActivityStateV1::default();
    state
        .apply_delta(&act_params, &ActivityDeltaV1 { entries })
        .expect("the activity state verifies");
    state
}

fn moderation_feed(section: Option<MessageId>) -> ReportFeedStateV1 {
    let owner_key = owner();
    let owner_id = MemberId::from(&owner_key.verifying_key());
    let mod_params = ModerationParametersV1 {
        owner: owner_key.verifying_key(),
        section,
    };
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
            signer_key: Some(owner_key.verifying_key()),
            proof: None,
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
            ownership_transfers: Vec::new(),
            transfer_admins: Vec::new(),
        });
    }
    let mut state = ReportFeedStateV1::default();
    state
        .apply_delta(
            &mod_params,
            &ReportFeedDeltaV1 {
                reports,
                resolutions,
            },
        )
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

    // A child now keeps only its own section chain, and only the members its
    // index references.
    let mut compact = child.clone();
    compact.sections = parent.sections.chain_only(&section_id);
    let compact_size = serialized_len(&compact);
    let compact_verify = verify_time(&compact, Some(section_id));

    let mut pruned = compact.clone();
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
    let activity = activity_contract(members, Some(section_id));
    let activity_kib = serialized_len_value(&activity) as f64 / 1024.0;
    let activity_summary_kib = serialized_len_value(&activity.summarize()) as f64 / 1024.0;
    let mut activity_minus_one = activity.clone();
    activity_minus_one.entries.pop();
    let activity_inc_delta = activity
        .delta(&activity_minus_one.summarize())
        .expect("activity incremental delta");
    let activity_inc_delta_kib = serialized_len_value(&activity_inc_delta) as f64 / 1024.0;
    let activity_inc_mib = activity_inc_delta_kib / 1024.0;

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
        "compact:  {:>7.1} KiB   verify {:>8.1} ms   (own section chain, all members)",
        compact_size as f64 / 1024.0,
        compact_verify
    );
    println!(
        "pruned:   {:>7.1} KiB   verify {:>8.1} ms   (own chain + only referenced members)",
        pruned_size as f64 / 1024.0,
        pruned_verify
    );
    println!(
        "legacy section activity delta: {:>6.1} ms + {:>5.1} ms layout scan (no longer used)",
        delta_ms, layout_ms
    );
    println!(
        "activity contract: {:>7.1} KiB (summary {:.1} KiB); incremental 1-entry delta {:.2} KiB, fan-out {:.3} MiB ({MAX_ACTIVITY_ENTRIES} entries, {subscribers} subscribers)",
        activity_kib,
        activity_summary_kib,
        activity_inc_delta_kib,
        activity_inc_mib * subscribers as f64
    );
    println!(
        "storage:  {:>7.1} MiB across {sections} pruned children (O(sections + referenced members))",
        pruned_mib * sections as f64
    );
    // The client sends a delta with the new entry, not the full index state.
    let new_topic = TopicIndexDelta {
        entries: vec![entry(section_id, topics, members)],
        ..Default::default()
    };
    let new_topic_kib = serialized_len_value(&new_topic) as f64 / 1024.0;
    let moderation = moderation_feed(Some(section_id));
    let moderation_kib = serialized_len_value(&moderation) as f64 / 1024.0;
    let moderation_summary_kib = serialized_len_value(&moderation.summarize()) as f64 / 1024.0;
    let mut moderation_minus_one = moderation.clone();
    moderation_minus_one.resolutions.pop();
    let moderation_inc_delta = moderation
        .delta(&moderation_minus_one.summarize())
        .expect("moderation incremental delta");
    let moderation_inc_delta_kib = serialized_len_value(&moderation_inc_delta) as f64 / 1024.0;
    let moderation_delta = ReportFeedDeltaV1 {
        reports: vec![moderation.reports[0].clone()],
        resolutions: Vec::new(),
    };
    let moderation_delta_kib = serialized_len_value(&moderation_delta) as f64 / 1024.0;
    println!(
        "moderation feed: {:>7.1} KiB (summary {:.1} KiB, 500 reports + 500 resolutions); new report delta {:.2} KiB, sync delta {:.2} KiB, fan-out {:.3} MiB ({subscribers} subscribers)",
        moderation_kib,
        moderation_summary_kib,
        moderation_delta_kib,
        moderation_inc_delta_kib,
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

    // Compact extra page (`page > 0`): open vs sealed (`SectionPageStateV1`).
    let compact_params = SectionParametersV1 {
        owner: owner().verifying_key(),
        section: section_id,
        page: 1,
    };
    let mut compact_open = SectionPageStateV1 {
        header: Some(AuthorizedSectionPageHeaderV1::new(
            SectionPageHeaderV1 {
                board: owner().verifying_key().to_bytes(),
                section: section_id,
                section_chain: vec![section_id],
                page: 1,
                page_size: page_size as u32,
                allowed_roles: Vec::new(),
                created_at: 1_000,
            },
            &owner(),
        )),
        ..Default::default()
    };
    let owner_id = MemberId::from(&owner().verifying_key());
    let mut compact_entries = Vec::with_capacity(page_size);
    let mut compact_authors = Vec::new();
    let mut seen_authors = std::collections::HashSet::new();
    for index in page_start..topics {
        let e = entry(section_id, index, members);
        if seen_authors.insert(e.entry.author) {
            let author_sk = member_key(index % members);
            compact_authors.push(AuthorizedMember::new(
                Member {
                    owner_member_id: owner_id,
                    invited_by: owner_id,
                    member_vk: author_sk.verifying_key(),
                    join_proof: None,
                },
                &owner(),
            ));
        }
        compact_entries.push(e);
    }
    compact_open
        .apply_delta(
            &compact_params,
            &SectionPageDeltaV1 {
                authors: compact_authors,
                entries: compact_entries,
                ..Default::default()
            },
        )
        .expect("compact open page applies");
    let compact_open_kib = serialized_len_value(&compact_open) as f64 / 1024.0;
    let compact_open_summary_kib =
        serialized_len_value(&compact_open.summarize()) as f64 / 1024.0;
    let start = Instant::now();
    black_box(compact_open.verify(&compact_params).unwrap());
    let compact_open_verify = start.elapsed().as_secs_f64() * 1000.0;

    // Incremental 1-topic delta on an open compact page (199 -> 200).
    let mut compact_199 = SectionPageStateV1 {
        header: compact_open.header.clone(),
        ..Default::default()
    };
    let mut entries_199 = compact_open.entries.clone();
    let last_entry = entries_199.pop().unwrap();
    let last_author = compact_open
        .authors
        .iter()
        .find(|m| m.member.id() == last_entry.entry.author)
        .cloned()
        .unwrap();
    let authors_199: Vec<_> = compact_open
        .authors
        .iter()
        .filter(|m| m.member.id() != last_entry.entry.author)
        .cloned()
        .collect();
    compact_199
        .apply_delta(
            &compact_params,
            &SectionPageDeltaV1 {
                authors: authors_199,
                entries: entries_199,
                ..Default::default()
            },
        )
        .unwrap();
    let one_topic_delta = SectionPageDeltaV1 {
        authors: vec![last_author],
        entries: vec![last_entry],
        ..Default::default()
    };
    let compact_delta_kib = serialized_len_value(&one_topic_delta) as f64 / 1024.0;
    let start = Instant::now();
    compact_199
        .apply_delta(&compact_params, &one_topic_delta)
        .unwrap();
    let compact_delta_ms = start.elapsed().as_secs_f64() * 1000.0;

    // Owner seals the full page: duplicated authors are dropped.
    let mut compact_sealed = compact_open.clone();
    let seal = AuthorizedSectionPageSealV1::new(
        &compact_params,
        &compact_sealed.entries,
        &owner(),
        9_000_000,
    )
    .unwrap();
    compact_sealed
        .apply_delta(
            &compact_params,
            &SectionPageDeltaV1 {
                seal: Some(seal),
                ..Default::default()
            },
        )
        .unwrap();
    assert!(compact_sealed.authors.is_empty());
    let compact_sealed_kib = serialized_len_value(&compact_sealed) as f64 / 1024.0;
    let compact_sealed_summary_kib =
        serialized_len_value(&compact_sealed.summarize()) as f64 / 1024.0;
    let start = Instant::now();
    black_box(compact_sealed.verify(&compact_params).unwrap());
    let compact_sealed_verify = start.elapsed().as_secs_f64() * 1000.0;

    let legacy_total_mib = (page_kib * page_count as f64) / 1024.0;
    let compact_total_mib = if page_count <= 1 {
        page_kib / 1024.0
    } else {
        let sealed_pages = page_count.saturating_sub(2) as f64;
        (page_kib + sealed_pages * compact_sealed_kib + compact_open_kib) / 1024.0
    };

    println!("\n=== pages ===");
    println!(
        "members={members} topics/section={topics} page_size={page_size} pages={page_count} subscribers={subscribers}"
    );
    println!(
        "section:         {:>7.1} KiB   verify {:>8.1} ms   (all topics)",
        whole_kib, whole_verify
    );
    println!(
        "manifest (p0):   {:>7.1} KiB   verify {:>8.1} ms   (ChatBoardStateV1, topics {page_start}..{topics})",
        page_kib, page_verify
    );
    println!(
        "compact open:    {:>7.1} KiB   verify {:>8.1} ms   (summary {:.1} KiB; 1-topic delta {:.2} KiB in {:.2} ms)",
        compact_open_kib, compact_open_verify, compact_open_summary_kib, compact_delta_kib, compact_delta_ms
    );
    println!(
        "compact sealed:  {:>7.1} KiB   verify {:>8.2} ms   (summary {:.1} KiB; 0 duplicated authors)",
        compact_sealed_kib, compact_sealed_verify, compact_sealed_summary_kib
    );
    println!(
        "storage ({page_count} pages): {:.2} MiB compact (p0 + {} sealed + 1 open) vs {:.2} MiB legacy ({page_count} x pruned ChatBoardStateV1)",
        compact_total_mib,
        page_count.saturating_sub(2),
        legacy_total_mib
    );
    println!(
        "authority sync fan-out: 1 contract/section (manifest only) instead of {page_count} pages/section"
    );
    println!(
        "new topic delta: {:>6.1} KiB; fan-out {:.2} MiB ({subscribers} subscribers)",
        delta_kib,
        delta_kib / 1024.0 * subscribers as f64
    );
    println!(
        "new subscriber bootstrap: manifest {:.1} KiB + sealed page {:.1} KiB ({:.2} ms verify) instead of section {:.1} KiB",
        page_kib, compact_sealed_kib, compact_sealed_verify, whole_kib
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

fn profile_feed(members: usize) -> ProfileStateV1 {
    let mut state = ProfileStateV1::default();
    for index in 0..members {
        let key = member_key(index);
        let id = MemberId::from(&key.verifying_key());
        state.entries.push(
            ProfileEntryV1::new(
                MemberInfo::new_public(id, 1, format!("Member {index}")),
                &key,
            )
            .with_proof(bench_member_proof(&key)),
        );
    }
    state
}

fn membership_scenario(members: usize, sections: usize) {
    let mut board = parent(sections, members);
    let without_nicknames = serialized_len(&board);
    for index in 0..members {
        let key = member_key(index);
        let id = MemberId::from(&key.verifying_key());
        board.member_info.member_info.push(
            AuthorizedMemberInfo::new_with_member_key(
                MemberInfo::new_public(id, 1, format!("Member {index}")),
                &key,
            ),
        );
    }
    let size = serialized_len(&board) as f64 / 1024.0;
    let nickname_kib = (serialized_len(&board) - without_nicknames) as f64 / 1024.0;
    let full_verify = verify_time(&board, None);

    let start = Instant::now();
    let tree = AuthorityTreeV1::from_board(&board);
    black_box(tree.content_hash());
    let tree_ms = start.elapsed().as_secs_f64() * 1000.0;

    sign_owner_root(&mut board);
    let fast_verify = verify_time(&board, None);

    // A nickname change carries one record; only that record is verified.
    let key = member_key(0);
    let id = MemberId::from(&key.verifying_key());
    let updated = AuthorizedMemberInfo::new_with_member_key(
        MemberInfo::new_public(id, 2, "Renamed".to_string()),
        &key,
    );
    let nickname_delta = ChatBoardStateV1Delta {
        member_info: Some(vec![updated]),
        ..Default::default()
    };
    let mut changed = board.clone();
    changed
        .apply_delta(&board, &params(), &Some(nickname_delta.clone()))
        .expect("the nickname delta applies");
    let start = Instant::now();
    changed
        .verify_delta(&nickname_delta, &params())
        .expect("the nickname delta verifies");
    let nickname_delta_ms = start.elapsed().as_secs_f64() * 1000.0;

    let profiles = profile_feed(members);
    let profile_kib = serialized_len_value(&profiles) as f64 / 1024.0;
    let profile_delta = ProfileDeltaV1 {
        entries: vec![profiles.entries[0].clone()],
    };
    let profile_delta_kib = serialized_len_value(&profile_delta) as f64 / 1024.0;
    let board_without_nicknames = size - nickname_kib;

    // Sharded profile directory: distribute all `members` across
    // `PROFILE_SHARD_COUNT` deterministic buckets and measure one bucket.
    let owner_sk = owner();
    let owner_vk = owner_sk.verifying_key();
    let mut profile_shards: Vec<ProfileStateV1> = (0..PROFILE_SHARD_COUNT)
        .map(|_| ProfileStateV1::default())
        .collect();
    for entry in &profiles.entries {
        let bucket = profile_shard_bucket(&entry.member_id()) as usize;
        profile_shards[bucket].entries.push(entry.clone());
    }
    let profile_shard0_params = ProfileShardParametersV1 {
        owner: owner_vk,
        bucket: 0,
    };
    let profile_shard0_kib = serialized_len_value(&profile_shards[0]) as f64 / 1024.0;
    let profile_shard0_summary_kib =
        serialized_len_value(&profile_shards[0].summarize()) as f64 / 1024.0;
    let max_profile_shard_kib = profile_shards
        .iter()
        .map(|s| serialized_len_value(s) as f64 / 1024.0)
        .fold(0.0_f64, f64::max);
    let start = Instant::now();
    profile_shards[0]
        .verify(&profile_shard0_params)
        .expect("profile shard 0 verifies");
    let profile_shard0_verify_ms = start.elapsed().as_secs_f64() * 1000.0;
    let rename_sk = member_key(0);
    let rename_id = MemberId::from(&rename_sk.verifying_key());
    let rename_bucket = profile_shard_bucket(&rename_id);
    let rename_params = ProfileShardParametersV1 {
        owner: owner_vk,
        bucket: rename_bucket,
    };
    let rename_delta = ProfileDeltaV1 {
        entries: vec![ProfileEntryV1::new(
            MemberInfo::new_public(rename_id, 2, "Renamed".to_string()),
            &rename_sk,
        )
        .with_proof(bench_member_proof(&rename_sk))],
    };
    let mut target_profile_shard = profile_shards[rename_bucket as usize].clone();
    let before_summary = target_profile_shard.summarize();
    let start = Instant::now();
    target_profile_shard
        .apply_delta(&rename_params, &rename_delta)
        .expect("profile rename delta applies");
    let profile_delta_ms = start.elapsed().as_secs_f64() * 1000.0;
    let profile_sync_delta = target_profile_shard
        .delta(&before_summary)
        .expect("incremental profile sync delta");
    let profile_sync_delta_kib = serialized_len_value(&profile_sync_delta) as f64 / 1024.0;

    // Sharded member directory: distribute all `members` across
    // `MEMBER_SHARD_COUNT` deterministic buckets and measure one bucket.
    let mut shards: Vec<MemberShardStateV1> = (0..MEMBER_SHARD_COUNT)
        .map(|_| MemberShardStateV1::default())
        .collect();
    for member in &board.members.members {
        let bucket = member_shard_bucket(&member.member.id()) as usize;
        shards[bucket].entries.push(MemberShardEntryV1 {
            member: member.clone(),
            invite_chain: Vec::new(),
            invite_token: None,
            ownership_transfers: Vec::new(),
            transfer_admins: Vec::new(),
        });
    }
    let shard0_params = MemberShardParametersV1 {
        owner: owner_vk,
        bucket: 0,
    };
    let shard0_kib = serialized_len_value(&shards[0]) as f64 / 1024.0;
    let max_shard_kib = shards
        .iter()
        .map(|s| serialized_len_value(s) as f64 / 1024.0)
        .fold(0.0_f64, f64::max);
    let start = Instant::now();
    shards[0].verify(&shard0_params).expect("shard 0 verifies");
    let shard0_verify_ms = start.elapsed().as_secs_f64() * 1000.0;
    let extra_sk = member_key(members + 100_000);
    let extra_member = AuthorizedMember::new(
        Member {
            owner_member_id: MemberId::from(&owner_vk),
            invited_by: MemberId::from(&owner_vk),
            member_vk: extra_sk.verifying_key(),
            join_proof: None,
        },
        &owner_sk,
    );
    let extra_bucket = member_shard_bucket(&extra_member.member.id());
    let join_delta = MemberShardDeltaV1 {
        entries: vec![MemberShardEntryV1 {
            member: extra_member,
            invite_chain: Vec::new(),
            invite_token: None,
            ownership_transfers: Vec::new(),
            transfer_admins: Vec::new(),
        }],
    };
    let join_delta_kib = serialized_len_value(&join_delta) as f64 / 1024.0;
    let mut target_shard = shards[extra_bucket as usize].clone();
    let target_params = MemberShardParametersV1 {
        owner: owner_vk,
        bucket: extra_bucket,
    };
    let start = Instant::now();
    target_shard
        .apply_delta(&target_params, &join_delta)
        .expect("join delta applies");
    let join_delta_ms = start.elapsed().as_secs_f64() * 1000.0;

    println!(
        "members={members:>6} sections={sections:>3} board={size:>8.1} KiB \
         (nicknames {nickname_kib:>6.1} KiB, board without {board_without_nicknames:>8.1} KiB) \
         full {full_verify:>8.1} ms tree {tree_ms:>7.1} ms \
         fast {fast_verify:>7.1} ms nickname delta {nickname_delta_ms:>6.1} ms"
    );
    println!(
        "         profile shards ({PROFILE_SHARD_COUNT} buckets vs {profile_kib:.1} KiB monolithic): bucket0 {profile_shard0_kib:>6.1} KiB ({} profiles, summary {profile_shard0_summary_kib:>4.1} KiB, verify {profile_shard0_verify_ms:>6.1} ms), max bucket {max_profile_shard_kib:>6.1} KiB; rename delta {profile_delta_kib:>4.2} KiB ({profile_delta_ms:>4.2} ms), sync delta {profile_sync_delta_kib:>4.2} KiB; board nickname writes: 0",
        profile_shards[0].entries.len()
    );
    println!(
        "         member shards ({MEMBER_SHARD_COUNT} buckets): bucket0 {shard0_kib:>6.1} KiB ({} members, verify {shard0_verify_ms:>6.1} ms), max bucket {max_shard_kib:>6.1} KiB; join delta {join_delta_kib:>4.2} KiB ({join_delta_ms:>4.2} ms)",
        shards[0].entries.len()
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
