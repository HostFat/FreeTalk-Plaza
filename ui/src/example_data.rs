use crate::util::random_full_name;
use crate::{
    board_data::{BoardData, Boards, IdentityProfile},
    constants::BOARD_CONTRACT_WASM,
    util::to_cbor_vec,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use freenet_scaffold::ComposableState;
use freenet_stdlib::prelude::{ContractCode, ContractKey, Parameters};
use plaza_core::board_state::configuration::*;
use plaza_core::board_state::member::*;
use plaza_core::board_state::member_info::*;
use plaza_core::board_state::message::MessageId;
use plaza_core::board_state::privacy::{BoardDisplayMetadata, PrivacyMode, SealedBytes};
use plaza_core::board_state::rate_limit::system_time_ms;
use plaza_core::board_state::sections::{AuthorizedSectionV1, SectionId, SectionV1};
use plaza_core::board_state::topics::{
    AuthorizedTopicActivityV1, AuthorizedTopicEntryV1, TopicActivityV1, TopicEntryV1,
    TOPIC_PROTOCOL_VERSION,
};
use plaza_core::board_state::{BoardModeV1, ChatBoardParametersV1};
use plaza_core::ChatBoardStateV1;
use plaza_topic_core::{
    AuthorizedParticipantV1, AuthorizedSectionSnapshotV1, AuthorizedTopicActionV1,
    AuthorizedTopicHeaderV1, AuthorizedTopicPolicyV1, AuthorizedTopicPostV1,
    ParticipantCertificateV1, ParticipantRecordV1, SectionSnapshotV1, TopicActionKind,
    TopicActionV1, TopicAuthorityV1, TopicGenerationV1, TopicHeaderV1, TopicParamsV1,
    TopicPolicyV1, TopicPostContentV1, TopicPostV1, TopicStateV1,
};
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct SeededData {
    sections: Vec<(VerifyingKey, SectionId, ChatBoardStateV1)>,
    topics: Vec<(VerifyingKey, MessageId, TopicStateV1)>,
}

static EXAMPLE_SEEDS: Mutex<Option<SeededData>> = Mutex::new(None);

/// Drain pre-built section manifests and topic heads into the Dioxus global
/// caches (`SECTION_BOARDS` and `TOPIC_CACHE`). Safe to call once on app mount.
#[cfg(target_arch = "wasm32")]
pub fn seed_example_caches() {
    use dioxus::prelude::ReadableExt;
    // Ensure `BOARDS` lazy initializer (`create_example_boards`) has run.
    let _ = crate::components::app::BOARDS.read();
    let seeded = EXAMPLE_SEEDS.lock().unwrap().take();
    let Some(seeded) = seeded else {
        return;
    };
    for (owner, section_id, manifest) in seeded.sections {
        crate::components::app::section_contract::seed_section_manifest(
            owner,
            section_id,
            manifest,
        );
    }
    for (owner, topic_id, state) in seeded.topics {
        crate::components::app::topic_contract::seed_topic_head(owner, topic_id, state);
    }
}

pub fn create_example_boards() -> Boards {
    let mut map = HashMap::new();
    let mut all_sections = Vec::new();
    let mut all_topics = Vec::new();

    // Board where you're just an observer (not a member)
    let board1 = create_board("Public Discussion Board", SelfIs::Observer);
    all_sections.extend(board1.sections);
    all_topics.extend(board1.topics);
    map.insert(board1.owner_vk, board1.board_data);

    // Board where you're a member (used by autoscroll, editing, invite-interceptor,
    // mentions, poll, section-policy, notifications, client-features)
    let board2 = create_board("Team Chat Board", SelfIs::Member);
    all_sections.extend(board2.sections);
    all_topics.extend(board2.topics);
    map.insert(board2.owner_vk, board2.board_data);

    // Board where you're the owner (used by identity-controls, reactions,
    // reaction-owners, touch-actions, device-drawer, mail-bridge)
    let board3 = create_board("Your Private Board", SelfIs::Owner);
    all_sections.extend(board3.sections);
    all_topics.extend(board3.topics);
    map.insert(board3.owner_vk, board3.board_data);

    // A member profile on a device that also holds the owner key. This is the
    // case where `is_current_owner()` is true but the visible profile is not
    // the owner: the crown and Manage must stay hidden.
    let board4 = create_board("Owner Key, Member Profile", SelfIs::MemberWithOwnerKey);
    all_sections.extend(board4.sections);
    all_topics.extend(board4.topics);
    map.insert(board4.owner_vk, board4.board_data);

    // A private board whose key is unavailable: the gate must show the
    // recovery screen instead of an endless loading spinner.
    let mut board5 = create_board("Missing Key Board", SelfIs::Owner);
    let signing_key = board5.board_data.self_sk.clone();
    board5
        .board_data
        .board_state
        .configuration
        .configuration
        .privacy_mode = PrivacyMode::Private;
    board5.board_data.board_state.configuration = AuthorizedConfigurationV1::new(
        board5
            .board_data
            .board_state
            .configuration
            .configuration
            .clone(),
        &signing_key,
    );
    board5.board_data.secrets.clear();
    board5.board_data.current_secret_version = None;
    board5.board_data.owner_sk = None;
    all_sections.extend(board5.sections);
    all_topics.extend(board5.topics);
    map.insert(board5.owner_vk, board5.board_data);

    *EXAMPLE_SEEDS.lock().unwrap() = Some(SeededData {
        sections: all_sections,
        topics: all_topics,
    });

    // Derive stored profiles so the device drawer can manage identities & Mail.
    let mut profiles: Vec<IdentityProfile> = Vec::new();
    for board in map.values() {
        let self_vk = board.self_sk.verifying_key();
        if !profiles
            .iter()
            .any(|profile| profile.signing_key.verifying_key() == self_vk)
        {
            let member_id = MemberId::from(&self_vk);
            let name = board
                .display_nickname(member_id)
                .unwrap_or_else(|| "You".to_string());
            let id = if board.profile_id.as_deref() == Some("member-profile") {
                "member-profile".to_string()
            } else {
                format!("profile-{}", bs58::encode(self_vk.as_bytes()).into_string())
            };
            profiles.push(IdentityProfile {
                id,
                name,
                signing_key: board.self_sk.clone(),
                mail_address: None,
                updated_at: 0,
            });
        }
        if let Some(owner_sk) = &board.owner_sk {
            let owner_vk = owner_sk.verifying_key();
            if !profiles
                .iter()
                .any(|profile| profile.signing_key.verifying_key() == owner_vk)
            {
                profiles.push(IdentityProfile {
                    id: "owner-profile".to_string(),
                    name: "OwnerP".to_string(),
                    signing_key: owner_sk.clone(),
                    mail_address: None,
                    updated_at: 0,
                });
            }
        }
    }

    Boards {
        map,
        current_board_key: None,
        profiles,
        removed: Vec::new(),
        board_order: Vec::new(),
        archived: Vec::new(),
        client_features: crate::board_data::ClientFeatures::default(),
        migrated_boards: Vec::new(),
        blocked_image_hashes: Vec::new(),
        auto_renew_images: false,
        last_auto_renew_at: 0,
        owned_images: Vec::new(),
    }
}

struct CreatedBoard {
    owner_vk: VerifyingKey,
    board_data: BoardData,
    sections: Vec<(VerifyingKey, SectionId, ChatBoardStateV1)>,
    topics: Vec<(VerifyingKey, MessageId, TopicStateV1)>,
}

#[derive(Debug, PartialEq)]
enum SelfIs {
    Observer,
    Member,
    Owner,
    MemberWithOwnerKey,
}

fn new_section(
    owner_vk: VerifyingKey,
    owner_sk: &SigningKey,
    name: &str,
    description: Option<&str>,
    color: &str,
    auto_moderated_topics: Option<bool>,
    now: SystemTime,
) -> AuthorizedSectionV1 {
    let mut id_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut id_bytes);
    let id = MessageId::from_bytes(id_bytes);
    let contract = Some(
        *crate::components::app::section_contract::section_key(owner_vk, id).id(),
    );
    let section = SectionV1 {
        id,
        parent: None,
        name: name.to_string(),
        description: description.map(|s| s.to_string()),
        icon: None,
        color: color.to_string(),
        allowed_roles: Vec::new(),
        sealed_name: None,
        hidden: false,
        is_group: false,
        images_allowed: true,
        auto_moderated_topics,
        generation: 1,
        deleted: false,
        contract,
        signed_at: now,
    };
    AuthorizedSectionV1::new(section, owner_sk, None)
}

fn section_manifest(
    parent: &ChatBoardStateV1,
    section: &AuthorizedSectionV1,
    entries: Vec<AuthorizedTopicEntryV1>,
    activity: Vec<AuthorizedTopicActivityV1>,
) -> ChatBoardStateV1 {
    let mut child = ChatBoardStateV1::default();
    child.mode = BoardModeV1::SectionedTopicIndex;
    child.configuration = parent.configuration.clone();
    child.ownership = parent.ownership.clone();
    child.admin = parent.admin.clone();
    child.members = parent.members.clone();
    child.sections = parent.sections.chain_only(&section.section.id);
    child.topics.entries = entries;
    child.topics.activity = activity;
    child
}

struct SeededTopic {
    topic_id: MessageId,
    entry: AuthorizedTopicEntryV1,
    activity: Option<AuthorizedTopicActivityV1>,
    state: TopicStateV1,
}

#[allow(clippy::too_many_arguments)]
fn build_seeded_topic(
    owner_vk: VerifyingKey,
    owner_sk: &SigningKey,
    board_config: &Configuration,
    section: &AuthorizedSectionV1,
    author_sk: &SigningKey,
    participants: Vec<AuthorizedParticipantV1>,
    title: &str,
    body: &str,
    created_at: i64,
    replies: Vec<(&SigningKey, &str, i64)>,
    header_reactions: Vec<(&SigningKey, &str, i64)>,
) -> SeededTopic {
    let mut topic_id_bytes = [0u8; 32];
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut topic_id_bytes);
    OsRng.fill_bytes(&mut nonce);
    let topic_id = MessageId::from_bytes(topic_id_bytes);
    let author_vk = author_sk.verifying_key();
    let author = MemberId::from(&author_vk);
    let section_id = section.section.id;

    let sealed_title = SealedBytes::public(title.as_bytes().to_vec());
    let sealed_body = SealedBytes::public(body.as_bytes().to_vec());
    let header = TopicHeaderV1 {
        topic_id: topic_id_bytes,
        author,
        author_key: author_vk,
        section: Some(section_id),
        section_chain: vec![section_id],
        title: sealed_title.clone(),
        body: sealed_body,
        auto_moderated: false,
        created_at,
        nonce,
    };
    let header_id = header.id();
    let header_hash = header.hash();
    let authorized_header = AuthorizedTopicHeaderV1::new(header, author_sk);

    let snapshot = SectionSnapshotV1 {
        section: section_id,
        parent: section.section.parent,
        chain: vec![section_id],
        allowed_roles: section.section.allowed_roles.clone(),
        sealed_name: section.section.sealed_name.clone(),
        hidden: section.section.hidden,
        images_allowed: section.section.images_allowed,
        auto_moderated_topics: section.section.auto_moderated_topics,
        generation: section.section.generation,
        signed_at: system_time_ms(section.section.signed_at),
    };
    let authorized_snapshot = AuthorizedSectionSnapshotV1::new(snapshot, owner_sk, None);

    let policy = TopicPolicyV1 {
        read_only: board_config.read_only,
        approval_required: board_config.approval_required,
        rate_window_ms: board_config.rate_window_ms,
        max_posts_per_window: board_config.max_posts_per_window,
        images_allowed: true,
        auto_moderated_topics: board_config.auto_moderated_topics,
        reactions_enabled: board_config.reactions_enabled,
        max_post_size: board_config.max_message_size,
        generation: (board_config.configuration_version as u64).max(1),
        updated_at: system_time_ms(board_config.updated_at),
    };
    let authority = TopicAuthorityV1 {
        policy: Some(AuthorizedTopicPolicyV1::new(policy, owner_sk)),
        ..Default::default()
    };

    let mut posts = std::collections::BTreeMap::new();
    let mut last_activity = created_at;
    let mut last_post_id: Option<MessageId> = None;
    let mut last_reply_signer = author_sk;
    for (reply_sk, reply_text, reply_at) in replies {
        let mut reply_nonce = [0u8; 16];
        OsRng.fill_bytes(&mut reply_nonce);
        let reply_author = MemberId::from(&reply_sk.verifying_key());
        let encoded_content = plaza_topic_core::encode(&TopicPostContentV1::Text(
            reply_text.to_string(),
        ))
        .expect("encode topic post content");
        let post = TopicPostV1 {
            author: reply_author,
            parent: None,
            content: SealedBytes::public(encoded_content),
            images: Vec::new(),
            created_at: reply_at,
            nonce: reply_nonce,
        };
        let authorized_post = AuthorizedTopicPostV1::new(post, reply_sk);
        let post_id = authorized_post.id();
        posts.insert(post_id, authorized_post);
        if reply_at >= last_activity {
            last_activity = reply_at;
            last_post_id = Some(post_id);
            last_reply_signer = reply_sk;
        }
    }

    let mut actions = Vec::new();
    let mut react_gen: HashMap<MemberId, u64> = HashMap::new();
    for (react_sk, emoji, react_at) in header_reactions {
        let react_vk = react_sk.verifying_key();
        let signer = MemberId::from(&react_vk);
        let generation = {
            let entry = react_gen.entry(signer).or_insert(0);
            *entry += 1;
            *entry
        };
        let action = TopicActionV1 {
            kind: TopicActionKind::React,
            target: header_id,
            payload: SealedBytes::public(emoji.as_bytes().to_vec()),
            generation,
            created_at: react_at,
            signer,
        };
        let signature = plaza_core::util::sign_struct(&action, react_sk);
        actions.push(AuthorizedTopicActionV1 {
            action,
            signer_key: Some(react_vk),
            authority: None,
            signature,
        });
    }

    let reply_count = posts.len() as u32;
    let state = TopicStateV1 {
        header: Some(authorized_header),
        section: Some(authorized_snapshot),
        authority,
        participants,
        trust: Vec::new(),
        posts,
        actions,
        approvals: Vec::new(),
        generation: TopicGenerationV1::new(0),
        ..Default::default()
    };

    let params = TopicParamsV1::new(owner_vk, topic_id_bytes, 0);
    if let Err(err) = state.verify(&params) {
        panic!("Seeded topic '{title}' failed to verify: {err}");
    }

    let preview: String = body.chars().take(200).collect();
    let entry = TopicEntryV1 {
        topic_id,
        part: 0,
        protocol_version: TOPIC_PROTOCOL_VERSION,
        author,
        section: Some(section_id),
        section_chain: vec![section_id],
        title: sealed_title,
        preview: SealedBytes::public(preview.into_bytes()),
        header_hash,
        created_at,
        generation: 1,
    };
    let authorized_entry = AuthorizedTopicEntryV1::new(entry, author_sk);

    let activity = if reply_count > 0 {
        let act = TopicActivityV1 {
            topic_id,
            last_post_id,
            last_activity,
            reply_count,
            pending_approvals: 0,
            generation: 1,
        };
        let signer_vk = last_reply_signer.verifying_key();
        Some(AuthorizedTopicActivityV1 {
            signature: plaza_core::util::sign_struct(&act, last_reply_signer),
            activity: act,
            signer: Some(MemberId::from(&signer_vk)),
            signer_key: Some(signer_vk),
        })
    } else {
        None
    };

    SeededTopic {
        topic_id,
        entry: authorized_entry,
        activity,
        state,
    }
}

fn make_participant(
    member: &AuthorizedMember,
    member_sk: &SigningKey,
    joined_at: i64,
) -> AuthorizedParticipantV1 {
    let record = ParticipantRecordV1 {
        member_id: member.member.id(),
        member_vk: member.member.member_vk,
        certificate: ParticipantCertificateV1 {
            member: member.clone(),
            chain: Vec::new(),
            token: None,
            join_proof: None,
        },
        joined_at,
    };
    AuthorizedParticipantV1::new(record, member_sk)
}

fn create_board(board_name: &str, self_is: SelfIs) -> CreatedBoard {
    let mut csprng = OsRng;
    let now = crate::util::get_current_system_time();
    let now_ms = system_time_ms(now);

    let self_sk = SigningKey::generate(&mut csprng);
    let self_vk = self_sk.verifying_key();
    let self_id = MemberId::from(&self_vk);

    let generated_owner_sk = SigningKey::generate(&mut csprng);
    let owner_sk = if self_is == SelfIs::Owner {
        &self_sk
    } else {
        &generated_owner_sk
    };
    let owner_vk = owner_sk.verifying_key();
    let owner_id = MemberId::from(&owner_vk);

    let mut board_state = ChatBoardStateV1::default();
    board_state.mode = BoardModeV1::SectionedTopicIndex;

    let mut config = Configuration::default();
    config.display = BoardDisplayMetadata {
        name: SealedBytes::public(board_name.as_bytes().to_vec()),
        description: None,
    };
    config.owner_member_id = owner_id;
    config.updated_at = now;
    board_state.configuration = AuthorizedConfigurationV1::new(config.clone(), owner_sk);

    let mut members = MembersV1::default();
    let mut member_info = MemberInfoV1::default();

    // Owner nickname
    member_info
        .member_info
        .push(AuthorizedMemberInfo::new_with_member_key(
            MemberInfo {
                member_id: owner_id,
                version: 0,
                preferred_nickname: SealedBytes::public(
                    (random_full_name() + " (Owner)").into_bytes(),
                ),
            },
            owner_sk,
        ));

    // Self as member when not owner
    let self_authorized_member = if matches!(self_is, SelfIs::Member | SelfIs::MemberWithOwnerKey) {
        let auth = AuthorizedMember::new(
            Member {
                owner_member_id: owner_id,
                invited_by: owner_id,
                member_vk: self_vk,
                join_proof: None,
            },
            owner_sk,
        );
        members.members.push(auth.clone());
        member_info
            .member_info
            .push(AuthorizedMemberInfo::new_with_member_key(
                MemberInfo {
                    member_id: self_id,
                    version: 0,
                    preferred_nickname: SealedBytes::public(
                        (random_full_name() + " (You)").into_bytes(),
                    ),
                },
                &self_sk,
            ));
        Some(auth)
    } else {
        None
    };

    // Always add another member so mentions, member lists, and reactions have peers
    let other_member_sk = SigningKey::generate(&mut csprng);
    let other_member_vk = other_member_sk.verifying_key();
    let other_member_id = MemberId::from(&other_member_vk);
    let inviter_id = if self_is == SelfIs::Owner {
        self_id
    } else {
        owner_id
    };
    let inviter_sk = if self_is == SelfIs::Owner {
        &self_sk
    } else {
        owner_sk
    };
    let other_authorized_member = AuthorizedMember::new(
        Member {
            owner_member_id: owner_id,
            invited_by: inviter_id,
            member_vk: other_member_vk,
            join_proof: None,
        },
        inviter_sk,
    );
    members.members.push(other_authorized_member.clone());
    member_info
        .member_info
        .push(AuthorizedMemberInfo::new_with_member_key(
            MemberInfo {
                member_id: other_member_id,
                version: 0,
                preferred_nickname: SealedBytes::public(
                    (random_full_name() + " (Member)").into_bytes(),
                ),
            },
            &other_member_sk,
        ));

    board_state.members = members;
    board_state.member_info = member_info;

    // Sections
    let general = new_section(
        owner_vk,
        owner_sk,
        "General",
        Some("General discussion"),
        "#6366f1",
        None,
        now,
    );
    board_state.sections.sections.push(general.clone());

    let no_auto = if board_name == "Team Chat Board" {
        let sec = new_section(
            owner_vk,
            owner_sk,
            "NoAuto",
            Some("Auto-moderated topics disabled"),
            "#f59e0b",
            Some(false),
            now,
        );
        board_state.sections.sections.push(sec.clone());
        Some(sec)
    } else {
        None
    };

    // Build participants list for seeded topics
    let mut base_participants = Vec::new();
    if let Some(ref self_member) = self_authorized_member {
        base_participants.push(make_participant(self_member, &self_sk, now_ms - 100_000));
    }
    base_participants.push(make_participant(
        &other_authorized_member,
        &other_member_sk,
        now_ms - 90_000,
    ));

    let mut general_entries = Vec::new();
    let mut general_activity = Vec::new();
    let mut seeded_topics = Vec::new();

    if board_name == "Team Chat Board" {
        // 1. Autoscroll topic with 25 replies so #message-scroll overflows & pins to bottom
        let autoscroll_replies: Vec<(&SigningKey, String, i64)> = (1..=25)
            .map(|i| {
                let sk = if i % 2 == 0 { &self_sk } else { &other_member_sk };
                (
                    sk,
                    format!("Autoscroll reply #{i} with enough content to fill the scroll view cleanly."),
                    now_ms - 60_000 + (i as i64) * 1_000,
                )
            })
            .collect();
        let autoscroll_refs: Vec<(&SigningKey, &str, i64)> = autoscroll_replies
            .iter()
            .map(|(sk, txt, ts)| (*sk, txt.as_str(), *ts))
            .collect();
        let t_auto = build_seeded_topic(
            owner_vk,
            owner_sk,
            &config,
            &general,
            &self_sk,
            base_participants.clone(),
            "Autoscroll topic",
            "Long discussion to verify opening pinned to the latest reply.",
            now_ms - 70_000,
            autoscroll_refs,
            Vec::new(),
        );
        general_entries.push(t_auto.entry);
        if let Some(act) = t_auto.activity {
            general_activity.push(act);
        }
        seeded_topics.push((owner_vk, t_auto.topic_id, t_auto.state));

        // 2. Invite link topic for invite-interceptor.spec.ts
        let t_invite = build_seeded_topic(
            owner_vk,
            owner_sk,
            &config,
            &general,
            &other_member_sk,
            base_participants.clone(),
            "Invite link",
            "Click here to test the interceptor: [Join the board](/#/join/not-a-valid-token)",
            now_ms - 50_000,
            Vec::new(),
            Vec::new(),
        );
        general_entries.push(t_invite.entry);
        if let Some(act) = t_invite.activity {
            general_activity.push(act);
        }
        seeded_topics.push((owner_vk, t_invite.topic_id, t_invite.state));
    } else if board_name == "Your Private Board" {
        // Reaction topic with 👍 from both owner (You) and other member + 1 reply
        let t_react = build_seeded_topic(
            owner_vk,
            owner_sk,
            &config,
            &general,
            &self_sk,
            base_participants.clone(),
            "Reaction topic",
            "Hover or click the reaction count below to inspect reactors.",
            now_ms - 40_000,
            vec![(&self_sk, "First reply in reaction topic.", now_ms - 30_000)],
            vec![
                (&self_sk, "👍", now_ms - 25_000),
                (&other_member_sk, "👍", now_ms - 20_000),
            ],
        );
        general_entries.push(t_react.entry);
        if let Some(act) = t_react.activity {
            general_activity.push(act);
        }
        seeded_topics.push((owner_vk, t_react.topic_id, t_react.state));
    } else {
        // Welcome topic on remaining fixture boards
        let t_welcome = build_seeded_topic(
            owner_vk,
            owner_sk,
            &config,
            &general,
            owner_sk,
            base_participants.clone(),
            "Welcome",
            "Welcome to this FreeTalk Plaza discussion board.",
            now_ms - 30_000,
            vec![(&other_member_sk, "Glad to be here!", now_ms - 20_000)],
            Vec::new(),
        );
        general_entries.push(t_welcome.entry);
        if let Some(act) = t_welcome.activity {
            general_activity.push(act);
        }
        seeded_topics.push((owner_vk, t_welcome.topic_id, t_welcome.state));
    }

    let mut seeded_sections = Vec::new();
    let general_manifest =
        section_manifest(&board_state, &general, general_entries, general_activity);
    let board_params = ChatBoardParametersV1 { owner: owner_vk };
    if let Err(err) = general_manifest.verify_with_section(&board_params, Some(general.section.id))
    {
        panic!("General section manifest for '{board_name}' failed to verify: {err}");
    }
    seeded_sections.push((owner_vk, general.section.id, general_manifest));

    if let Some(ref sec) = no_auto {
        let manifest = section_manifest(&board_state, sec, Vec::new(), Vec::new());
        if let Err(err) = manifest.verify_with_section(&board_params, Some(sec.section.id)) {
            panic!("NoAuto section manifest failed to verify: {err}");
        }
        seeded_sections.push((owner_vk, sec.section.id, manifest));
    }

    if let Err(err) = board_state.verify(&board_state, &board_params) {
        panic!("Failed to verify board state '{board_name}': {err}");
    }

    let parameters = ChatBoardParametersV1 { owner: owner_vk };
    let params_bytes = to_cbor_vec(&parameters);
    let contract_code = ContractCode::from(BOARD_CONTRACT_WASM);
    let contract_key =
        ContractKey::from_params_and_code(Parameters::from(params_bytes), &contract_code);

    let mut board_data = BoardData {
        owner_vk,
        board_state,
        self_sk: self_sk.clone(),
        owner_sk: if self_is == SelfIs::MemberWithOwnerKey {
            Some(owner_sk.clone())
        } else {
            None
        },
        owner_profile_id: if self_is == SelfIs::MemberWithOwnerKey {
            Some("owner-profile".to_string())
        } else {
            None
        },
        profile_id: if self_is == SelfIs::MemberWithOwnerKey {
            Some("member-profile".to_string())
        } else {
            None
        },
        contract_key,
        secrets: HashMap::new(),
        current_secret_version: None,
        last_secret_rotation: None,
        key_migrated_to_delegate: true,
        self_authorized_member,
        invite_chain: vec![],
        self_member_info: None,
        category_secrets: HashMap::new(),
        old_category_secrets: HashMap::new(),
        collapsed_groups: Vec::new(),
        last_visit: 0,
        topic_read: HashMap::new(),
        topic_drafts: HashMap::new(),
        pending_uploads: Vec::new(),
        subscribed_categories: Vec::new(),
        notification_mode: crate::board_data::NotificationMode::All,
        mail_visibility: Default::default(),
        nickname_requests: Vec::new(),
        spectator: false,
    };
    board_data.refresh_authority_root();

    CreatedBoard {
        owner_vk,
        board_data,
        sections: seeded_sections,
        topics: seeded_topics,
    }
}

#[allow(dead_code)]
fn get_time_from_millis(ms: u64) -> SystemTime {
    crate::util::get_current_system_time()
        - Duration::from_millis(
            crate::util::get_current_system_time()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::from_secs(0))
                .as_millis() as u64
                - ms,
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_example_boards() {
        let boards = create_example_boards();
        assert_eq!(boards.map.len(), 5);

        for (owner_vk, board_data) in boards.map.iter() {
            assert_eq!(board_data.board_state.mode, BoardModeV1::SectionedTopicIndex);
            let verification_result = board_data.board_state.verify(
                &board_data.board_state,
                &ChatBoardParametersV1 { owner: *owner_vk },
            );
            assert!(
                verification_result.is_ok(),
                "Board {} failed to verify: {:?}",
                bs58::encode(owner_vk.as_bytes()).into_string(),
                verification_result.err()
            );
            assert!(
                board_data
                    .board_state
                    .configuration
                    .configuration
                    .display
                    .name
                    .declared_len()
                    > 0
            );
            assert!(!board_data.board_state.members.members.is_empty());
            assert!(!board_data.board_state.member_info.member_info.is_empty());
            assert!(!board_data.board_state.sections.sections.is_empty());
        }

        let seeded = EXAMPLE_SEEDS.lock().unwrap();
        let seeded = seeded.as_ref().expect("seeded data populated");
        assert!(
            seeded.topics.iter().any(|(_, _, state)| {
                state
                    .actions
                    .iter()
                    .any(|a| a.action.kind == TopicActionKind::React)
            }),
            "the fixture must carry at least one signed topic reaction"
        );
    }
}
