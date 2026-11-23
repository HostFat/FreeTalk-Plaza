//! Integration tests for the board index mode: sections and topic entries live
//! in one board state while the discussions themselves are separate contracts.

use ed25519_dalek::SigningKey;
use freenet_scaffold::ComposableState;
use plaza_core::board_state::configuration::{
    AuthorizedConfigurationV1, Configuration,
};
use plaza_core::board_state::member::{AuthorizedMember, Member, MemberId};
use plaza_core::board_state::message::MessageId;
use plaza_core::board_state::privacy::SealedBytes;
use plaza_core::board_state::reports::ReportReason;
use plaza_core::board_state::sections::{
    AuthorizedSectionV1, SectionV1,
};
use plaza_core::board_state::topics::{
    AuthorizedTopicActivityV1, AuthorizedTopicEntryV1,
    AuthorizedTopicFlagV1, AuthorizedTopicReportV1, TopicActivityV1, TopicEntryV1,
    TopicFlagKind, TopicFlagV1, TopicIndexDelta, TopicReportV1,
};
use plaza_core::board_state::{
    BoardModeV1, ChatBoardParametersV1, ChatBoardStateV1,
    ChatBoardStateV1Delta,
};
use plaza_core::util::sign_struct;
use std::time::SystemTime;

fn owner() -> SigningKey {
    SigningKey::from_bytes(&[1u8; 32])
}

fn member() -> SigningKey {
    SigningKey::from_bytes(&[2u8; 32])
}

fn params() -> ChatBoardParametersV1 {
    ChatBoardParametersV1 {
        owner: owner().verifying_key(),
    }
}

fn section(id: u8) -> SectionV1 {
    SectionV1 {
        id: MessageId::from_bytes([id; 32]),
        parent: None,
        name: format!("Section {id}"),
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
        signed_at: SystemTime::UNIX_EPOCH,
    }
}

fn topic_entry(section: MessageId) -> AuthorizedTopicEntryV1 {
    topic_entry_at(7, section, 1)
}

fn topic_entry_at(id: u8, section: MessageId, created_at: i64) -> AuthorizedTopicEntryV1 {
    AuthorizedTopicEntryV1::new(
        TopicEntryV1 {
            topic_id: MessageId::from_bytes([id; 32]),
            part: 0,
            protocol_version: 1,
            author: MemberId::from(&member().verifying_key()),
            section: Some(section),
            section_chain: vec![section],
            title: SealedBytes::public(b"Title".to_vec()),
            preview: SealedBytes::public(b"Preview".to_vec()),
            header_hash: [9u8; 32],
            created_at,
            generation: 1,
        },
        &member(),
    )
}

fn report(index: u8, created_at: i64) -> AuthorizedTopicReportV1 {
    let value = TopicReportV1 {
        topic_id: MessageId::from_bytes([7u8; 32]),
        post_id: Some(MessageId::from_bytes([index; 32])),
        reporter: MemberId::from(&member().verifying_key()),
        reason: ReportReason::Spam,
        body: SealedBytes::public(b"Report".to_vec()),
        created_at,
        generation: 1,
    };
    AuthorizedTopicReportV1 {
        signature: sign_struct(&value, &member()),
        report: value,
    }
}

fn activity() -> AuthorizedTopicActivityV1 {
    let value = TopicActivityV1 {
        topic_id: MessageId::from_bytes([7u8; 32]),
        last_activity: 20,
        last_post_id: None,
        reply_count: 1,
        pending_approvals: 0,
        generation: 1,
    };
    AuthorizedTopicActivityV1 {
        signature: sign_struct(&value, &member()),
        activity: value,
        signer: Some(MemberId::from(&member().verifying_key())),
        signer_key: Some(member().verifying_key()),
    }
}

fn pin() -> AuthorizedTopicFlagV1 {
    let value = TopicFlagV1 {
        topic_id: MessageId::from_bytes([7u8; 32]),
        kind: TopicFlagKind::Pinned,
        value: true,
        destination: None,
        section: None,
        section_chain: Vec::new(),
        part: None,
        scope_chain: vec![MessageId::from_bytes([5u8; 32])],
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

fn indexed_board() -> ChatBoardStateV1 {
    let owner = owner();
    let member = member();
    let owner_id = MemberId::from(&owner.verifying_key());
    let section_id = MessageId::from_bytes([5u8; 32]);
    let mut state = ChatBoardStateV1 {
        configuration: AuthorizedConfigurationV1::new(
            Configuration {
                owner_member_id: owner_id,
                ..Configuration::default()
            },
            &owner,
        ),
        mode: BoardModeV1::TopicIndex,
        ..Default::default()
    };
    state.members.members.push(AuthorizedMember::new(
        Member {
            owner_member_id: owner_id,
            invited_by: owner_id,
            member_vk: member.verifying_key(),
            join_proof: None,
        },
        &owner,
    ));
    state.sections.sections.push(AuthorizedSectionV1::new(
        section(5),
        &owner,
        None,
    ));
    state.topics.entries.push(topic_entry(section_id));
    state.topics.activity.push(activity());
    state.topics.flags.push(pin());
    state
}

#[test]
fn the_index_board_verifies() {
    let state = indexed_board();
    state.verify(&state, &params()).unwrap();
    assert_eq!(state.mode, BoardModeV1::TopicIndex);
    assert_eq!(state.topics.entries.len(), 1);
    assert_eq!(state.sections.sections.len(), 1);
    assert!(state.topics.is_pinned(&MessageId::from_bytes([7u8; 32])));
}

#[test]
fn a_member_without_messages_survives_index_cleanup() {
    let mut state = indexed_board();
    let delta = ChatBoardStateV1Delta {
        topics: Some(TopicIndexDelta {
            activity: vec![activity()],
            ..Default::default()
        }),
        ..Default::default()
    };
    let parent = state.clone();
    state.apply_delta(&parent, &params(), &Some(delta)).unwrap();
    assert_eq!(state.members.members.len(), 1);
    state.verify(&state, &params()).unwrap();
}

#[test]
fn a_sealed_title_round_trips_in_the_index() {
    let mut state = indexed_board();
    state.topics.entries[0].entry.title = SealedBytes::private(
        vec![1u8; 32],
        [2u8; 12],
        1,
        128,
    );
    // The entry was signed before the change, so re-sign it with the author.
    state.topics.entries[0].signature =
        sign_struct(&state.topics.entries[0].entry, &member());
    state.verify(&state, &params()).unwrap();

    let bytes = {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&state, &mut bytes).unwrap();
        bytes
    };
    let decoded: ChatBoardStateV1 =
        ciborium::de::from_reader(bytes.as_slice()).unwrap();
    assert!(decoded.topics.entries[0].entry.title.is_private());
}

#[test]
fn a_newer_topic_entry_generation_wins() {
    let mut state = indexed_board();
    let mut entry = topic_entry(MessageId::from_bytes([5u8; 32]));
    entry.entry.title = SealedBytes::public(b"Renamed".to_vec());
    entry.entry.generation = 2;
    entry.signature = sign_struct(&entry.entry, &member());
    let delta = ChatBoardStateV1Delta {
        topics: Some(TopicIndexDelta {
            entries: vec![entry],
            ..Default::default()
        }),
        ..Default::default()
    };
    let parent = state.clone();
    state.apply_delta(&parent, &params(), &Some(delta)).unwrap();
    assert_eq!(
        state.topics.entries[0].entry.generation,
        2
    );
    assert_eq!(
        state.topics.entries[0].entry.title,
        SealedBytes::public(b"Renamed".to_vec())
    );
}

#[test]
fn the_legacy_mode_still_verifies_with_empty_index_fields() {
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
        ..Default::default()
    };
    state.mode = BoardModeV1::LegacyMessages;
    state.verify(&state, &params()).unwrap();
    assert!(state.sections.sections.is_empty());
    assert!(state.topics.entries.is_empty());
}

#[test]
fn an_entry_with_the_wrong_section_chain_is_rejected() {
    let mut state = indexed_board();
    state.topics.entries[0].entry.section_chain = vec![MessageId::from_bytes([6u8; 32])];
    state.topics.entries[0].signature =
        sign_struct(&state.topics.entries[0].entry, &member());
    assert!(state.verify(&state, &params()).is_err());
}

#[test]
fn the_topic_creation_rate_is_enforced() {
    let mut state = indexed_board();
    let section_id = MessageId::from_bytes([5u8; 32]);
    state.topics.entries.clear();
    for index in 0..plaza_core::board_state::rate_limit::MAX_TOPICS_PER_WINDOW {
        state
            .topics
            .entries
            .push(topic_entry_at(index as u8, section_id, 1_000 + index as i64));
    }
    state.verify(&state, &params()).unwrap();

    state.topics.entries.push(topic_entry_at(
        plaza_core::board_state::rate_limit::MAX_TOPICS_PER_WINDOW as u8,
        section_id,
        1_100,
    ));
    let error = state.verify(&state, &params()).unwrap_err();
    assert!(error.contains("too many topics"), "{error}");
}

#[test]
fn the_report_rate_is_enforced() {
    let mut state = indexed_board();
    for index in 0..plaza_core::board_state::rate_limit::MAX_REPORTS_PER_WINDOW {
        state
            .topics
            .reports
            .push(report(index as u8, 1_000 + index as i64));
    }
    state.verify(&state, &params()).unwrap();

    state.topics.reports.push(report(
        plaza_core::board_state::rate_limit::MAX_REPORTS_PER_WINDOW as u8,
        1_100,
    ));
    let error = state.verify(&state, &params()).unwrap_err();
    assert!(error.contains("too many reports"), "{error}");
}
