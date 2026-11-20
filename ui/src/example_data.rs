use crate::util::random_full_name;
use crate::{
    board_data::{BoardData, Boards},
    constants::BOARD_CONTRACT_WASM,
    util::to_cbor_vec,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use freenet_scaffold::ComposableState;
use freenet_stdlib::prelude::{ContractCode, ContractKey, Parameters};
use lipsum::lipsum;
use plaza_core::board_state::ChatBoardParametersV1;
use plaza_core::{
    board_state::{
        configuration::*,
        content::{
            ActionContentV1, CategoryContentV1, ModerationActionV1, ACTION_CONTENT_VERSION,
            CATEGORY_CONTENT_VERSION, CONTENT_TYPE_CATEGORY, CONTENT_TYPE_MODERATION_ACTION,
        },
        member::*,
        member_info::*,
        message::*,
        privacy::{BoardDisplayMetadata, PrivacyMode, SealedBytes},
    },
    ChatBoardStateV1,
};
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn create_example_boards() -> Boards {
    let mut map = HashMap::new();

    // Board where you're just an observer (not a member)
    let board1 = create_board(&"Public Discussion Board".to_string(), SelfIs::Observer);
    map.insert(board1.owner_vk, board1.board_data);

    // Board where you're a member
    let board2 = create_board(&"Team Chat Board".to_string(), SelfIs::Member);
    map.insert(board2.owner_vk, board2.board_data);

    // Board where you're the owner
    let board3 = create_board(&"Your Private Board".to_string(), SelfIs::Owner);
    map.insert(board3.owner_vk, board3.board_data);

    // A member profile on a device that also holds the owner key. This is the
    // case where `is_current_owner()` is true but the visible profile is not
    // the owner: the crown and Manage must stay hidden.
    let board4 = create_board(
        &"Owner Key, Member Profile".to_string(),
        SelfIs::MemberWithOwnerKey,
    );
    map.insert(board4.owner_vk, board4.board_data);

    // A private board whose key is unavailable: the gate must show the
    // recovery screen instead of an endless loading spinner.
    let mut board5 = create_board(&"Missing Key Board".to_string(), SelfIs::Owner);
    let signing_key = board5.board_data.self_sk.clone();
    board5.board_data.board_state.configuration.configuration.privacy_mode =
        PrivacyMode::Private;
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
    map.insert(board5.owner_vk, board5.board_data);

    Boards {
        map,
        current_board_key: None,
        profiles: Vec::new(),
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
}

#[derive(Debug, PartialEq)]
enum SelfIs {
    Observer,
    Member,
    Owner,
    MemberWithOwnerKey,
}

// Function to create a board with an owner and members, self_is determines whether
// the user of the UI is the owner, a member, or an observer (not an owner or member)
fn create_board(board_name: &String, self_is: SelfIs) -> CreatedBoard {
    let mut csprng = OsRng;

    // Create self - the user actually using the app
    let self_sk = SigningKey::generate(&mut csprng);
    let self_vk = self_sk.verifying_key();
    let self_id = self_vk.into();

    // Create owner of the board
    let owner_sk = if self_is == SelfIs::Owner {
        &self_sk
    } else {
        &SigningKey::generate(&mut csprng)
    };
    let owner_vk = owner_sk.verifying_key();
    let owner_id = MemberId::from(&owner_vk);

    let mut board_state = ChatBoardStateV1::default();

    // Set configuration
    let mut config = Configuration::default();
    config.display = BoardDisplayMetadata {
        name: SealedBytes::public(board_name.clone().into_bytes()),
        description: None,
    };
    config.owner_member_id = owner_id;
    board_state.configuration = AuthorizedConfigurationV1::new(config, owner_sk);

    // Initialize member lists
    let mut members = MembersV1::default();
    let mut member_info = MemberInfoV1::default();

    // Always add owner to member_info
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

    // If self is a member but not the owner, add self
    if matches!(self_is, SelfIs::Member | SelfIs::MemberWithOwnerKey) {
        members.members.push(AuthorizedMember::new(
            Member {
                owner_member_id: owner_id,
                invited_by: owner_id,
                member_vk: self_vk.clone(),
                join_proof: None,
            },
            owner_sk,
        ));

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
    }

    // Always add another member to ensure the board has at least one member
    let other_member_sk = SigningKey::generate(&mut csprng);
    let other_member_vk = other_member_sk.verifying_key();
    let other_member_id = MemberId::from(&other_member_vk);

    // In boards where self is owner, other member should be invited by self
    // In other boards, other member should be invited by owner
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

    members.members.push(AuthorizedMember::new(
        Member {
            owner_member_id: owner_id,
            invited_by: inviter_id,
            member_vk: other_member_vk,
            join_proof: None,
        },
        inviter_sk,
    ));

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

    // Add members to the board
    board_state.members = members.clone();
    board_state.member_info = member_info.clone();

    // Create a map of member IDs to their signing keys for message creation
    let mut member_keys = HashMap::new();
    if matches!(self_is, SelfIs::Member | SelfIs::MemberWithOwnerKey) {
        member_keys.insert(self_id, self_sk.clone());
    }
    member_keys.insert(other_member_id, other_member_sk);

    // Add example messages
    add_example_messages(
        &mut board_state,
        &owner_id,
        owner_sk,
        &member_keys,
        board_name == "Team Chat Board",
    );

    let verification_result = board_state.verify(
        &board_state,
        &ChatBoardParametersV1 {
            owner: owner_vk.clone(),
        },
    );
    if !verification_result.is_ok() {
        panic!(
            "Failed to verify board state: {:?}",
            verification_result.err()
        );
    }

    // Generate contract key for the board
    let parameters = ChatBoardParametersV1 { owner: owner_vk };
    let params_bytes = to_cbor_vec(&parameters);
    let contract_code = ContractCode::from(BOARD_CONTRACT_WASM);
    // Use the full ContractKey constructor that includes the code hash
    let contract_key =
        ContractKey::from_params_and_code(Parameters::from(params_bytes), &contract_code);

    CreatedBoard {
        owner_vk,
        board_data: BoardData {
            owner_vk: owner_vk.clone(),
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
            last_read_message_id: None,
            secrets: std::collections::HashMap::new(),
            current_secret_version: None,
            last_secret_rotation: None,
            key_migrated_to_delegate: true, // Example data doesn't need migration
            self_authorized_member: None,
            invite_chain: vec![],
            self_member_info: None,
            category_secrets: std::collections::HashMap::new(),
            old_category_secrets: std::collections::HashMap::new(),
            trash_secret: None,
            trash_secrets: std::collections::HashMap::new(),
            collapsed_groups: Vec::new(),
            last_visit: 0,
            read_categories: std::collections::HashMap::new(),
            draft: None,
            drafts: Vec::new(),
            trash_retention_days: 0,
            pending_uploads: Vec::new(),
            pending_send: None,
            subscribed_categories: Vec::new(),
            notification_mode: crate::board_data::NotificationMode::All,
            nickname_requests: Vec::new(),
            spectator: false,
        },
    }
}

fn add_example_messages(
    board_state: &mut ChatBoardStateV1,
    owner_id: &MemberId,
    owner_key: &SigningKey,
    member_keys: &HashMap<MemberId, SigningKey>,
    with_sections: bool,
) {
    // Use a timestamp 24 hours ago as base time for messages
    let now = crate::util::get_current_system_time()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let base_time = now - (24 * 60 * 60 * 1000); // 24 hours ago in milliseconds

    let mut messages = MessagesV1::default();
    let mut current_time_ms = base_time;

    // A board with two sections for the Playwright composer tests: General
    // inherits the board policy (on), NoAuto overrides it to off.
    if with_sections {
        for (name, policy, age_ms) in [
            ("General", None, 2 * 60 * 60 * 1000),
            ("NoAuto", Some(false), 60 * 60 * 1000),
        ] {
            let mut category =
                CategoryContentV1::new(name.to_string(), None, "#6366f1".to_string());
            category.auto_moderated_topics = policy;
            let message = AuthorizedMessageV1::new(
                MessageV1 {
                    images: Vec::new(),
                    board_owner: *owner_id,
                    author: *owner_id,
                    time: get_time_from_millis(base_time.saturating_sub(age_ms)),
                    content: BoardMessageBody::public_raw(
                        CONTENT_TYPE_CATEGORY,
                        CATEGORY_CONTENT_VERSION,
                        category.encode(),
                    ),
                    reply_to: None,
                    topic_id: None,
                    topic_public_key: None,
                    topic_proof: None,
                    section_id: None,
                    section_auto_moderated: None,
                    auto_moderated: false,
                },
                owner_key,
            );
            messages.messages.push(message);
        }
    }

    // Verify owner exists in member_info but NOT in members list
    if !board_state
        .member_info
        .member_info
        .iter()
        .any(|m| m.member_info.member_id == *owner_id)
    {
        panic!("Owner ID not found in member_info: {}", owner_id);
    }
    if board_state
        .members
        .members
        .iter()
        .any(|m| m.member.id() == *owner_id)
    {
        panic!(
            "Owner ID found in members list when it should not be: {}",
            owner_id
        );
    }

    // Verify that all member_keys are valid and members exist
    for (member_id, signing_key) in member_keys.iter() {
        if MemberId::from(&signing_key.verifying_key()) != *member_id {
            panic!("Member ID does not match signing key");
        }

        // Verify they exist in members list (unless they're the owner)
        if *member_id != *owner_id
            && !board_state
                .members
                .members
                .iter()
                .any(|m| m.member.id() == *member_id)
        {
            panic!("Member ID not found in members list: {}", member_id);
        }
    }

    // Create a vec of possible authors (owner + members)
    let authors: Vec<(MemberId, &SigningKey)> = member_keys
        .iter()
        .map(|(id, key)| (*id, key))
        .chain(std::iter::once((*owner_id, owner_key)))
        .collect();

    let message_count = 6;

    for _ in 0..message_count {
        // Pick a random author
        let author_idx = rand::random::<usize>() % authors.len();
        let (author_id, signing_key) = authors[author_idx];

        // Generate message with random length (15-35 words)
        let word_count = rand::random::<u8>() % 21 + 15;
        let body = lipsum(word_count as usize);
        // Threads need a title; keep it short and derived from the body so the
        // fixture posts read like real ones.
        let title: String = body
            .split_whitespace()
            .take(4)
            .collect::<Vec<_>>()
            .join(" ");
        let msg = AuthorizedMessageV1::new(
            MessageV1 {
                images: Vec::new(),
                board_owner: *owner_id,
                author: author_id,
                time: get_time_from_millis(current_time_ms),
                content: BoardMessageBody::public(title, body),
                reply_to: None,
                topic_id: None,
                topic_public_key: None,
                topic_proof: None,
                section_id: None,
                section_auto_moderated: None,
                auto_moderated: false,
            },
            signing_key,
        );

        messages.messages.push(msg);

        // Add a more natural time gap between messages (30 sec to 15 min)
        current_time_ms += (rand::random::<u64>() % 870 + 30) * 1000;
    }

    // Add reactions to messages from OTHER members (not owner)
    // Rule: One reaction per user per message
    // In "Your Private Board" the owner IS self, so this shows self reacting to others
    let non_owner_ids: Vec<MessageId> = messages
        .messages
        .iter()
        .filter(|m| m.message.author != *owner_id)
        .map(|m| m.id())
        .collect();

    // Get a non-owner member ID for multi-user reaction demo
    let other_member_id = member_keys.keys().find(|id| *id != owner_id).cloned();

    if non_owner_ids.len() >= 1 {
        // First non-owner message: owner reacts with thumbs up, other member with
        // heart. These are signed action messages, not fixture-only state, so a
        // real toggle or a rebuilt actions_state keeps them.
        let msg_id = non_owner_ids[0].clone();
        push_example_reaction(
            &mut messages,
            owner_id,
            msg_id.clone(),
            *owner_id,
            owner_key,
            "👍",
            current_time_ms,
        );
        if let Some(other_id) = other_member_id {
            if let Some(key) = member_keys.get(&other_id) {
                push_example_reaction(
                    &mut messages,
                    owner_id,
                    msg_id,
                    other_id,
                    key,
                    "❤️",
                    current_time_ms + 1000,
                );
            }
        }
    }

    if non_owner_ids.len() >= 2 {
        // Second non-owner message: owner reacts with celebration
        let msg_id = non_owner_ids[1].clone();
        let mut reactions = HashMap::new();
        reactions.insert("🎉".to_string(), vec![*owner_id]);
        messages.actions_state.reactions.insert(msg_id, reactions);
    }

    // A stable topic for the Playwright reaction test. The other rules above
    // react to whichever message happened to be first; this title does not
    // depend on the generated lipsum order.
    if let Some(other_id) = other_member_id {
        if let Some(key) = member_keys.get(&other_id) {
            let message = AuthorizedMessageV1::new(
                MessageV1 {
                    images: Vec::new(),
                    board_owner: *owner_id,
                    author: other_id,
                    time: get_time_from_millis(current_time_ms + 5_000),
                    content: BoardMessageBody::public(
                        "Reaction topic".to_string(),
                        "This topic carries signed reactions for the Playwright test."
                            .to_string(),
                    ),
                    reply_to: None,
                    topic_id: None,
                    topic_public_key: None,
                    topic_proof: None,
                    section_id: None,
                    section_auto_moderated: None,
                    auto_moderated: false,
                },
                key,
            );
            let target = message.id();
            messages.messages.push(message);
            push_example_reaction(
                &mut messages,
                owner_id,
                target.clone(),
                *owner_id,
                owner_key,
                "👍",
                current_time_ms + 6_000,
            );
            push_example_reaction(
                &mut messages,
                owner_id,
                target,
                other_id,
                key,
                "❤️",
                current_time_ms + 7_000,
            );
        }
    }

    if with_sections {
        let owner_message = |title: &str, body: String, time_ms: u64, reply_to: Option<MessageId>| {
            AuthorizedMessageV1::new(
                MessageV1 {
                    images: Vec::new(),
                    board_owner: *owner_id,
                    author: *owner_id,
                    time: get_time_from_millis(time_ms),
                    content: BoardMessageBody::public(title.to_string(), body),
                    reply_to,
                    topic_id: None,
                    topic_public_key: None,
                    topic_proof: None,
                    section_id: None,
                    section_auto_moderated: None,
                    auto_moderated: false,
                },
                owner_key,
            )
        };

        let invite = owner_message(
            "Invite link",
            "[Join the board](#/join/not-a-valid-token)".to_string(),
            current_time_ms + 8_000,
            None,
        );
        messages.messages.push(invite);

        let autoscroll = owner_message(
            "Autoscroll topic",
            "Start of a long thread used by the autoscroll test.".to_string(),
            current_time_ms + 9_000,
            None,
        );
        let autoscroll_id = autoscroll.id();
        messages.messages.push(autoscroll);
        if let Some(other_id) = other_member_id {
            if let Some(key) = member_keys.get(&other_id) {
                for index in 0..24 {
                    messages.messages.push(AuthorizedMessageV1::new(
                        MessageV1 {
                            images: Vec::new(),
                            board_owner: *owner_id,
                            author: other_id,
                            time: get_time_from_millis(
                                current_time_ms + 10_000 + index * 100,
                            ),
                            content: BoardMessageBody::public(
                                String::new(),
                                format!("Autoscroll reply {}", index + 1),
                            ),
                            reply_to: Some(autoscroll_id.clone()),
                            topic_id: None,
                            topic_public_key: None,
                            topic_proof: None,
                            section_id: None,
                            section_auto_moderated: None,
                            auto_moderated: false,
                        },
                        key,
                    ));
                }
            }
        }
    }

    // Turn the signed action messages into the computed view the UI reads.
    let admins: std::collections::HashSet<MemberId> = board_state
        .admin
        .admins
        .iter()
        .map(|admin| admin.admin.id())
        .collect();
    let members: std::collections::HashSet<MemberId> = board_state
        .members
        .members
        .iter()
        .map(|member| member.member.id())
        .collect();
    messages.rebuild_actions_state_with_permissions(
        &HashMap::new(),
        Some(*owner_id),
        Some(&admins),
        None,
        true,
        Some(&members),
    );

    board_state.recent_messages = messages;
}

fn push_example_reaction(
    messages: &mut MessagesV1,
    owner_id: &MemberId,
    target: MessageId,
    author_id: MemberId,
    signing_key: &SigningKey,
    emoji: &str,
    time_ms: u64,
) {
    let action = ActionContentV1::reaction(target.clone(), emoji.to_string());
    let envelope = ModerationActionV1::new(
        action.action_type,
        action.target,
        SealedBytes::public(action.encode()),
    );
    messages.messages.push(AuthorizedMessageV1::new(
        MessageV1 {
            images: Vec::new(),
            board_owner: *owner_id,
            author: author_id,
            time: get_time_from_millis(time_ms),
            content: BoardMessageBody::public_raw(
                CONTENT_TYPE_MODERATION_ACTION,
                ACTION_CONTENT_VERSION,
                envelope.encode(),
            ),
            reply_to: None,
            topic_id: None,
            topic_public_key: None,
            topic_proof: None,
            section_id: None,
            section_auto_moderated: None,
            auto_moderated: false,
        },
        signing_key,
    ));
}

fn get_time_from_millis(ms: u64) -> SystemTime {
    // Use WASM-compatible time function
    crate::util::get_current_system_time()
        - Duration::from_millis(
            crate::util::get_current_system_time()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::from_secs(0))
                .as_millis() as u64
                - ms,
        )
}

// Test function to create the example data
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_example_boards() {
        let boards = create_example_boards();
        assert_eq!(boards.map.len(), 5);
        assert!(
            boards
                .map
                .values()
                .any(|board| !board.board_state.recent_messages.actions_state.reactions.is_empty()),
            "the fixture must carry at least one signed reaction"
        );

        for (owner_vk, board_data) in boards.map.iter() {
            // Verify the board state
            let verification_result = board_data.board_state.verify(
                &board_data.board_state,
                &ChatBoardParametersV1 {
                    owner: owner_vk.clone(),
                },
            );
            assert!(
                verification_result.is_ok(),
                "Board {} failed to verify: {:?}",
                bs58::encode(owner_vk.as_bytes()).into_string(),
                verification_result.err()
            );

            // Verify board has at least basic configuration
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

            // Verify members list exists
            assert!(!board_data.board_state.members.members.is_empty());

            // Verify member info exists
            assert!(!board_data.board_state.member_info.member_info.is_empty());
        }
    }
}
