use super::*;
use plaza_core::board_state::configuration::{AuthorizedConfigurationV1, Configuration};
use plaza_core::board_state::identity::IdentityExport;
use plaza_core::board_state::member::{AuthorizedMember, Member, MemberId};

fn empty_boards() -> Boards {
    Boards {
        map: HashMap::new(),
        current_board_key: None,
        profiles: Vec::new(),
        removed: Vec::new(),
        board_order: Vec::new(),
        archived: Vec::new(),
        client_features: ClientFeatures::default(),
        migrated_boards: Vec::new(),
        blocked_image_hashes: Vec::new(),
        auto_renew_images: false,
        last_auto_renew_at: 0,
        owned_images: Vec::new(),
    }
}

/// The image index lives under its own delegate key, so the board map does
/// not carry its megabytes. A blob from before the split still loads and
/// keeps its entries for the migration.
#[test]
fn a_board_can_have_a_separate_owner_and_profile() {
    let mut rng = rand::thread_rng();
    let owner_sk = SigningKey::generate(&mut rng);
    let profile = IdentityProfile::new(
        "Shared profile".to_string(),
        SigningKey::generate(&mut rng),
    );
    let profile_vk = profile.signing_key.verifying_key();
    let mut boards = Boards {
        map: HashMap::new(),
        current_board_key: None,
        profiles: Vec::new(),
        removed: Vec::new(),
        board_order: Vec::new(),
        archived: Vec::new(),
        client_features: ClientFeatures::default(),
        migrated_boards: Vec::new(),
        blocked_image_hashes: Vec::new(),
        auto_renew_images: false,
        last_auto_renew_at: 0,
        owned_images: Vec::new(),
    };
    let owner_vk = owner_sk.verifying_key();
    let key = boards.create_new_board_with_identity(
        owner_sk,
        profile,
        BoardIdentityMode::Same,
        "Shared board".to_string(),
        "Shared profile".to_string(),
        false,
    );
    assert_eq!(key, owner_vk);
    let board = boards.map.get(&key).expect("board inserted");
    assert!(board.owner_sk.is_some());
    assert_eq!(board.owner_key().verifying_key(), owner_vk);
    assert_eq!(board.self_sk.verifying_key(), profile_vk);
    assert!(board
        .board_state
        .members
        .members
        .iter()
        .any(|member| member.member.member_vk == profile_vk));
    assert!(board
        .board_state
        .admin
        .admins
        .iter()
        .any(|admin| admin.admin.member_id == MemberId::from(&profile_vk)));
    let parameters = ChatBoardParametersV1 { owner: owner_vk };
    board
        .board_state
        .verify(&board.board_state, &parameters)
        .expect("board state verifies");
}

/// Management records use the owner key when this client holds it, and the
/// profile key (as a named member) otherwise.
#[test]
fn management_signing_uses_the_key_that_holds_the_authority() {
    let mut rng = rand::thread_rng();
    let owner_sk = SigningKey::generate(&mut rng);
    let profile_sk = SigningKey::generate(&mut rng);
    let member_sk = SigningKey::generate(&mut rng);
    let mut boards = Boards {
        map: HashMap::new(),
        current_board_key: None,
        profiles: Vec::new(),
        removed: Vec::new(),
        board_order: Vec::new(),
        archived: Vec::new(),
        client_features: ClientFeatures::default(),
        migrated_boards: Vec::new(),
        blocked_image_hashes: Vec::new(),
        auto_renew_images: false,
        last_auto_renew_at: 0,
        owned_images: Vec::new(),
    };
    let key = boards.create_new_board_with_identity(
        owner_sk.clone(),
        IdentityProfile::new("Owner profile".to_string(), profile_sk),
        BoardIdentityMode::Same,
        "Board".to_string(),
        "Owner".to_string(),
        false,
    );

    let owner_view = boards.map.get(&key).unwrap().clone();
    let (signing_key, signer) = owner_view.management_signer();
    assert_eq!(signing_key.verifying_key(), owner_sk.verifying_key());
    assert_eq!(signer, None, "the owner signs without an authority proof");

    // A member only ever holds its own key.
    let mut member_view = owner_view;
    member_view.self_sk = member_sk.clone();
    member_view.owner_sk = None;
    let (signing_key, signer) = member_view.management_signer();
    assert_eq!(signing_key.verifying_key(), member_sk.verifying_key());
    assert_eq!(signer, Some(MemberId::from(&member_sk.verifying_key())));
}

/// The owner's profile is a member like any other: if the contract prunes
/// its record, the stored signed membership puts it back.
#[test]
fn a_split_owner_profile_can_republish_its_membership() {
    let mut rng = rand::thread_rng();
    let owner_sk = SigningKey::generate(&mut rng);
    let profile_sk = SigningKey::generate(&mut rng);
    let profile_vk = profile_sk.verifying_key();
    let mut boards = Boards {
        map: HashMap::new(),
        current_board_key: None,
        profiles: Vec::new(),
        removed: Vec::new(),
        board_order: Vec::new(),
        archived: Vec::new(),
        client_features: ClientFeatures::default(),
        migrated_boards: Vec::new(),
        blocked_image_hashes: Vec::new(),
        auto_renew_images: false,
        last_auto_renew_at: 0,
        owned_images: Vec::new(),
    };
    let key = boards.create_new_board_with_identity(
        owner_sk,
        IdentityProfile::new("Profile".to_string(), profile_sk),
        BoardIdentityMode::Same,
        "Board".to_string(),
        "Profile".to_string(),
        false,
    );
    let mut board = boards.map.get(&key).unwrap().clone();
    assert!(board.self_authorized_member.is_some());

    // The contract pruned the profile because it had no recent messages.
    board.board_state.members.members.clear();
    let (members, profile_info) = crate::util::messaging::self_membership_delta(&board)
        .expect("the stored record is republished");

    let before = board.board_state.clone();
    board
        .board_state
        .apply_delta(
            &before,
            &ChatBoardParametersV1 { owner: key },
            &Some(plaza_core::board_state::ChatBoardStateV1Delta {
                members: Some(members),
                member_info: Some(vec![profile_info]),
                ..Default::default()
            }),
        )
        .expect("the republished membership verifies");
    assert!(board
        .board_state
        .members
        .members
        .iter()
        .any(|member| member.member.member_vk == profile_vk));
}

/// The owner key, not the visible profile, signs an admin revocation.
#[test]
fn a_split_owner_can_revoke_an_admin() {
    use plaza_core::board_state::admin::{AdminsDelta, AuthorizedAdminRevocation};

    let mut rng = rand::thread_rng();
    let owner_sk = SigningKey::generate(&mut rng);
    let profile_sk = SigningKey::generate(&mut rng);
    let profile_id = MemberId::from(&profile_sk.verifying_key());
    let mut boards = Boards {
        map: HashMap::new(),
        current_board_key: None,
        profiles: Vec::new(),
        removed: Vec::new(),
        board_order: Vec::new(),
        archived: Vec::new(),
        client_features: ClientFeatures::default(),
        migrated_boards: Vec::new(),
        blocked_image_hashes: Vec::new(),
        auto_renew_images: false,
        last_auto_renew_at: 0,
        owned_images: Vec::new(),
    };
    let key = boards.create_new_board_with_identity(
        owner_sk,
        IdentityProfile::new("Profile".to_string(), profile_sk),
        BoardIdentityMode::Same,
        "Board".to_string(),
        "Profile".to_string(),
        false,
    );
    let board = boards.map.get_mut(&key).unwrap();
    assert!(board.is_current_owner());
    assert!(board
        .board_state
        .admin
        .admins
        .iter()
        .any(|admin| admin.admin.id() == profile_id));

    let generation = board.board_state.admin.next_generation(&profile_id);
    let revocation =
        AuthorizedAdminRevocation::new(profile_id, generation, board.owner_key());
    let before = board.board_state.clone();
    board
        .board_state
        .apply_delta(
            &before,
            &ChatBoardParametersV1 { owner: key },
            &Some(plaza_core::board_state::ChatBoardStateV1Delta {
                admin: Some(AdminsDelta::revocation(vec![revocation])),
                ..Default::default()
            }),
        )
        .expect("the owner revocation verifies");

    assert!(board.board_state.admin.admins.is_empty());
    assert!(board.board_state.admin.is_revoked(&profile_id));
}

/// A handover to this client's own profile must make the profile the
/// owner even though `owner_sk` still holds the old owner key.
#[test]
fn a_handover_to_the_own_profile_makes_the_profile_the_owner() {
    use plaza_core::board_state::ownership::{
        AuthorizedOwnerTransfer, OutgoingOwnerAction, OwnerTransferV1, OwnershipDelta,
    };

    let mut rng = rand::thread_rng();
    let owner_sk = SigningKey::generate(&mut rng);
    let profile_sk = SigningKey::generate(&mut rng);
    let profile_vk = profile_sk.verifying_key();
    let profile_id = MemberId::from(&profile_vk);
    let mut boards = Boards {
        map: HashMap::new(),
        current_board_key: None,
        profiles: Vec::new(),
        removed: Vec::new(),
        board_order: Vec::new(),
        archived: Vec::new(),
        client_features: ClientFeatures::default(),
        migrated_boards: Vec::new(),
        blocked_image_hashes: Vec::new(),
        auto_renew_images: false,
        last_auto_renew_at: 0,
        owned_images: Vec::new(),
    };
    let key = boards.create_new_board_with_identity(
        owner_sk.clone(),
        IdentityProfile::new("Profile".to_string(), profile_sk),
        BoardIdentityMode::Same,
        "Board".to_string(),
        "Profile".to_string(),
        false,
    );
    let board = boards.map.get_mut(&key).unwrap();
    let params = ChatBoardParametersV1 { owner: key };
    let now = get_current_system_time();
    let transfer = AuthorizedOwnerTransfer::new(
        OwnerTransferV1 {
            from: MemberId::from(key),
            to: profile_id,
            to_key: profile_vk,
            generation: 1,
            transferred_at: now + std::time::Duration::from_millis(2),
            outgoing: OutgoingOwnerAction::KeepAdmin,
        },
        &owner_sk,
    );

    let before = board.board_state.clone();
    board
        .board_state
        .apply_delta(
            &before,
            &params,
            &Some(plaza_core::board_state::ChatBoardStateV1Delta {
                ownership: Some(OwnershipDelta {
                    transfers: vec![transfer],
                    deactivations: Vec::new(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        )
        .expect("the handover to the profile applies");

    assert_eq!(board.current_owner_key(), profile_vk);
    assert!(board.is_current_owner());
    assert_eq!(board.owner_key().verifying_key(), profile_vk);
    board
        .board_state
        .verify(&board.board_state, &params)
        .expect("the board verifies after the handover");
}

/// Deactivating both the owner key and the visible profile is accepted
/// when the board goes to a third member.
#[test]
fn deactivating_both_keys_on_handover_verifies() {
    use plaza_core::board_state::admin::{Admin, AuthorizedAdmin};
    use plaza_core::board_state::ownership::{
        AuthorizedKeyDeactivation, AuthorizedOwnerTransfer, KeyDeactivationV1,
        OutgoingOwnerAction, OwnerTransferV1, OwnershipDelta,
    };

    let mut rng = rand::thread_rng();
    let owner_sk = SigningKey::generate(&mut rng);
    let owner_vk = owner_sk.verifying_key();
    let profile_sk = SigningKey::generate(&mut rng);
    let profile_vk = profile_sk.verifying_key();
    let profile_id = MemberId::from(&profile_vk);
    let third_sk = SigningKey::generate(&mut rng);
    let third_vk = third_sk.verifying_key();
    let third_id = MemberId::from(&third_vk);
    let mut boards = Boards {
        map: HashMap::new(),
        current_board_key: None,
        profiles: Vec::new(),
        removed: Vec::new(),
        board_order: Vec::new(),
        archived: Vec::new(),
        client_features: ClientFeatures::default(),
        migrated_boards: Vec::new(),
        blocked_image_hashes: Vec::new(),
        auto_renew_images: false,
        last_auto_renew_at: 0,
        owned_images: Vec::new(),
    };
    let key = boards.create_new_board_with_identity(
        owner_sk.clone(),
        IdentityProfile::new("Profile".to_string(), profile_sk.clone()),
        BoardIdentityMode::Same,
        "Board".to_string(),
        "Profile".to_string(),
        false,
    );
    let board = boards.map.get_mut(&key).unwrap();
    let params = ChatBoardParametersV1 { owner: key };
    let now = get_current_system_time();

    // A third member, promoted to admin so it can receive the board.
    let member = Member {
        owner_member_id: MemberId::from(key),
        invited_by: MemberId::from(key),
        member_vk: third_vk,
        join_proof: None,
    };
    let admin = Admin {
        member_id: third_id,
        generation: 0,
        signed_at: now,
    };
    board
        .board_state
        .members
        .members
        .push(plaza_core::board_state::member::AuthorizedMember::new(
            member, &owner_sk,
        ));
    board
        .board_state
        .admin
        .admins
        .push(AuthorizedAdmin::new(admin, &owner_sk));
    // Cleanup keeps an owner-invited member that has a nickname.
    board
        .board_state
        .member_info
        .member_info
        .push(plaza_core::board_state::member_info::AuthorizedMemberInfo::new_with_member_key(
            plaza_core::board_state::member_info::MemberInfo {
                member_id: third_id,
                version: 0,
                preferred_nickname: plaza_core::board_state::privacy::SealedBytes::public(
                    b"Third".to_vec(),
                ),
            },
            &third_sk,
        ));

    let transfer = AuthorizedOwnerTransfer::new(
        OwnerTransferV1 {
            from: MemberId::from(key),
            to: third_id,
            to_key: third_vk,
            generation: 1,
            transferred_at: now + std::time::Duration::from_millis(2),
            outgoing: OutgoingOwnerAction::Deactivate,
        },
        &owner_sk,
    );
    let deactivations = vec![
        AuthorizedKeyDeactivation::new(
            KeyDeactivationV1 {
                member: MemberId::from(key),
                key: owner_vk,
                generation: 1,
                deactivated_at: now,
            },
            &owner_sk,
        ),
        AuthorizedKeyDeactivation::new(
            KeyDeactivationV1 {
                member: profile_id,
                key: profile_vk,
                generation: 1,
                deactivated_at: now,
            },
            &profile_sk,
        ),
    ];
    let mut trial = board.board_state.ownership.clone();
    trial.transfers.push(transfer.clone());
    trial.deactivations.extend(deactivations.clone());
    trial
        .verify(&board.board_state, &params)
        .expect("the test transfer verifies");

    let before = board.board_state.clone();
    board
        .board_state
        .apply_delta(
            &before,
            &params,
            &Some(plaza_core::board_state::ChatBoardStateV1Delta {
                ownership: Some(OwnershipDelta {
                    transfers: vec![transfer],
                    deactivations,
                    ..Default::default()
                }),
                ..Default::default()
            }),
        )
        .expect("the handover with both deactivations applies");

    assert_eq!(board.current_owner_key(), third_vk);
    assert!(
        board
            .board_state
            .members
            .members
            .iter()
            .any(|member| member.member.id() == third_id),
        "the new owner stays in the members list"
    );
    assert!(board
        .board_state
        .ownership
        .is_deactivated_now(&MemberId::from(key)));
    assert!(board.board_state.ownership.is_deactivated_now(&profile_id));
    board
        .board_state
        .verify(&board.board_state, &params)
        .expect("the board verifies after the deactivations");
}

/// Two tabs renamed the same profile: the newer name wins on merge.
#[test]
fn a_newer_profile_rename_wins_on_merge() {
    let mut rng = rand::thread_rng();
    let profile = IdentityProfile::new(
        "Old".to_string(),
        SigningKey::generate(&mut rng),
    );
    let mut local = Boards {
        map: HashMap::new(),
        current_board_key: None,
        profiles: vec![profile.clone()],
        removed: Vec::new(),
        board_order: Vec::new(),
        archived: Vec::new(),
        client_features: ClientFeatures::default(),
        migrated_boards: Vec::new(),
        blocked_image_hashes: Vec::new(),
        auto_renew_images: false,
        last_auto_renew_at: 0,
        owned_images: Vec::new(),
    };
    local.profiles[0].updated_at = 10;
    let mut other = Boards {
        map: HashMap::new(),
        current_board_key: None,
        profiles: vec![profile],
        removed: Vec::new(),
        board_order: Vec::new(),
        archived: Vec::new(),
        client_features: ClientFeatures::default(),
        migrated_boards: Vec::new(),
        blocked_image_hashes: Vec::new(),
        auto_renew_images: false,
        last_auto_renew_at: 0,
        owned_images: Vec::new(),
    };
    other.profiles[0].name = "New".to_string();
    other.profiles[0].updated_at = 20;

    local.merge(other).expect("the profiles merge");
    assert_eq!(local.profiles.len(), 1);
    assert_eq!(local.profiles[0].name, "New");
    assert_eq!(local.profiles[0].updated_at, 20);
}

/// A profile that is already a member can take over posting on the open
/// board without leaving it.
#[test]
fn switch_profile_uses_an_existing_member() {
    use plaza_core::board_state::member::AuthorizedMember;
    use plaza_core::board_state::member_info::{AuthorizedMemberInfo, MemberInfo};
    use plaza_core::board_state::privacy::SealedBytes;

    let mut rng = rand::thread_rng();
    let owner_sk = SigningKey::generate(&mut rng);
    let profile_sk = SigningKey::generate(&mut rng);
    let second_sk = SigningKey::generate(&mut rng);
    let second_vk = second_sk.verifying_key();
    let second_id = MemberId::from(&second_vk);
    let mut boards = Boards {
        map: HashMap::new(),
        current_board_key: None,
        profiles: Vec::new(),
        removed: Vec::new(),
        board_order: Vec::new(),
        archived: Vec::new(),
        client_features: ClientFeatures::default(),
        migrated_boards: Vec::new(),
        blocked_image_hashes: Vec::new(),
        auto_renew_images: false,
        last_auto_renew_at: 0,
        owned_images: Vec::new(),
    };
    let key = boards.create_new_board_with_identity(
        owner_sk.clone(),
        IdentityProfile::new("First".to_string(), profile_sk),
        BoardIdentityMode::Same,
        "Board".to_string(),
        "First".to_string(),
        false,
    );
    let board = boards.map.get_mut(&key).unwrap();
    board
        .board_state
        .members
        .members
        .push(AuthorizedMember::new(
            Member {
                owner_member_id: MemberId::from(key),
                invited_by: MemberId::from(key),
                member_vk: second_vk,
                join_proof: None,
            },
            &owner_sk,
        ));
    board
        .board_state
        .member_info
        .member_info
        .push(AuthorizedMemberInfo::new_with_member_key(
            MemberInfo {
                member_id: second_id,
                version: 0,
                preferred_nickname: SealedBytes::public(b"Second".to_vec()),
            },
            &second_sk,
        ));

    assert!(board.switch_profile(&second_sk).is_ok());
    assert_eq!(board.self_sk.verifying_key(), second_vk);
    assert!(board.self_authorized_member.is_some());
    assert!(board.can_participate().is_ok());
    assert!(board.switch_profile(&SigningKey::generate(&mut rng)).is_err());
}

/// The client keeps the owner key when it switches to a member profile.
/// Owner controls must follow the visible profile, not that retained key.
#[test]
fn owner_controls_follow_the_active_profile_not_the_retained_owner_key() {
    use plaza_core::board_state::member::AuthorizedMember;

    let mut rng = rand::thread_rng();
    let owner_sk = SigningKey::generate(&mut rng);
    let first_sk = SigningKey::generate(&mut rng);
    let second_sk = SigningKey::generate(&mut rng);
    let second_vk = second_sk.verifying_key();
    let mut boards = empty_boards();
    let key = boards.create_new_board_with_identity(
        owner_sk.clone(),
        IdentityProfile::new("Owner".to_string(), first_sk),
        BoardIdentityMode::Same,
        "Board".to_string(),
        "Owner".to_string(),
        false,
    );
    let owner_profile_id = boards
        .map
        .get(&key)
        .unwrap()
        .owner_profile_id
        .clone()
        .expect("the creator profile is recorded");
    let board = boards.map.get_mut(&key).unwrap();
    board
        .board_state
        .members
        .members
        .push(AuthorizedMember::new(
            Member {
                owner_member_id: MemberId::from(key),
                invited_by: MemberId::from(key),
                member_vk: second_vk,
                join_proof: None,
            },
            &owner_sk,
        ));

    assert!(board.is_active_owner(), "the creator profile is the owner");
    assert!(board.is_current_owner());

    assert!(board.switch_profile(&second_sk).is_ok());
    board.profile_id = Some("member-profile".to_string());
    assert!(
        board.is_current_owner(),
        "the owner key is still available for management"
    );
    assert!(
        !board.is_active_owner(),
        "the member profile must not show owner controls"
    );

    board.profile_id = Some(owner_profile_id);
    assert!(board.is_active_owner(), "switching back restores the crown");
}

/// Boards written before `owner_profile_id` existed can still recover the
/// owner profile from the first admin when that admin is visible.
#[test]
fn a_legacy_board_backfills_the_first_admin_as_owner_profile() {
    let mut rng = rand::thread_rng();
    let owner_sk = SigningKey::generate(&mut rng);
    let profile = IdentityProfile::new("Owner".to_string(), SigningKey::generate(&mut rng));
    let mut boards = empty_boards();
    let key = boards.create_new_board_with_identity(
        owner_sk,
        profile.clone(),
        BoardIdentityMode::Same,
        "Board".to_string(),
        "Owner".to_string(),
        false,
    );
    let board = boards.map.get_mut(&key).unwrap();
    board.owner_profile_id = None;
    board.profile_id = Some(profile.id.clone());

    board.backfill_owner_profile();

    assert_eq!(
        board.owner_profile_id.as_deref(),
        Some(profile.id.as_str())
    );
    assert!(board.is_active_owner());
}

/// A profile switch changes `self_sk`; the save merge must accept it and
/// keep the new identity instead of dropping the board.
#[test]
fn merge_accepts_a_profile_switch() {
    use plaza_core::board_state::member::AuthorizedMember;

    let mut rng = rand::thread_rng();
    let owner_sk = SigningKey::generate(&mut rng);
    let first_sk = SigningKey::generate(&mut rng);
    let second_sk = SigningKey::generate(&mut rng);
    let second_vk = second_sk.verifying_key();
    let mut boards = Boards {
        map: HashMap::new(),
        current_board_key: None,
        profiles: Vec::new(),
        removed: Vec::new(),
        board_order: Vec::new(),
        archived: Vec::new(),
        client_features: ClientFeatures::default(),
        migrated_boards: Vec::new(),
        blocked_image_hashes: Vec::new(),
        auto_renew_images: false,
        last_auto_renew_at: 0,
        owned_images: Vec::new(),
    };
    let key = boards.create_new_board_with_identity(
        owner_sk.clone(),
        IdentityProfile::new("First".to_string(), first_sk),
        BoardIdentityMode::Same,
        "Board".to_string(),
        "First".to_string(),
        false,
    );
    let board = boards.map.get_mut(&key).unwrap();
    board
        .board_state
        .members
        .members
        .push(AuthorizedMember::new(
            Member {
                owner_member_id: MemberId::from(key),
                invited_by: MemberId::from(key),
                member_vk: second_vk,
                join_proof: None,
            },
            &owner_sk,
        ));
    board.switch_profile(&second_sk).expect("the profile switches");
    boards.current_board_key = Some(key);

    let mut stored = Boards {
        map: HashMap::new(),
        current_board_key: Some(key),
        profiles: boards.profiles.clone(),
        removed: Vec::new(),
        board_order: Vec::new(),
        archived: Vec::new(),
        client_features: ClientFeatures::default(),
        migrated_boards: Vec::new(),
        blocked_image_hashes: Vec::new(),
        auto_renew_images: false,
        last_auto_renew_at: 0,
        owned_images: Vec::new(),
    };
    let mut old_board = boards.map.get(&key).cloned().unwrap();
    old_board.self_sk = SigningKey::generate(&mut rng);
    stored.map.insert(key, old_board);

    stored.merge(boards).expect("the switch merges");
    assert_eq!(
        stored.map.get(&key).unwrap().self_sk.verifying_key(),
        second_vk
    );
    assert!(stored.map.get(&key).unwrap().owner_sk.is_some());
}

#[test]
fn owned_images_are_saved_outside_the_boards_blob() {
    let owned = OwnedImage {
        image: plaza_core::board_state::images::ImageRef {
            instance: [7u8; 32],
            sha256: [8u8; 32],
            mime: "image/webp".to_string(),
            width: 10,
            height: 10,
            bytes: 2,
            alt: String::new(),
            display: 0,
            sealed: false,
            animated: false,
            nsfw: false,
            thumb: None,
            placement: Default::default(),
            align: Default::default(),
        },
        parameters: vec![1],
        state: vec![2, 3],
        chunks: Vec::new(),
        uploaded_at: 1,
        renewed_at: 1,
        published: true,
    };
    let boards = Boards {
        map: HashMap::new(),
        current_board_key: None,
        profiles: Vec::new(),
        removed: Vec::new(),
        board_order: Vec::new(),
        archived: Vec::new(),
        client_features: ClientFeatures::default(),
        migrated_boards: Vec::new(),
        blocked_image_hashes: Vec::new(),
        auto_renew_images: false,
        last_auto_renew_at: 0,
        owned_images: vec![owned.clone()],
    };
    let mut buffer = Vec::new();
    ciborium::ser::into_writer(&boards, &mut buffer).unwrap();
    let decoded: Boards = ciborium::from_reader(&buffer[..]).unwrap();
    assert!(decoded.owned_images.is_empty());

    // Older versions wrote the field into the same blob.
    #[derive(Serialize)]
    struct LegacyBoards {
        map: HashMap<VerifyingKey, BoardData>,
        current_board_key: Option<VerifyingKey>,
        removed: Vec<VerifyingKey>,
        blocked_image_hashes: Vec<[u8; 32]>,
        owned_images: Vec<OwnedImage>,
    }
    let legacy = LegacyBoards {
        map: HashMap::new(),
        current_board_key: None,
        removed: Vec::new(),
        blocked_image_hashes: Vec::new(),
        owned_images: vec![owned],
    };
    let mut legacy_buffer = Vec::new();
    ciborium::ser::into_writer(&legacy, &mut legacy_buffer).unwrap();
    let decoded = Boards::decode(&legacy_buffer).expect("legacy blob decodes");
    assert_eq!(decoded.owned_images.len(), 1);
}

/// The composer queues can hold 24 MiB of file bytes; they are stored
/// under their own key too, so the board map stays small.
#[test]
fn pending_uploads_are_saved_outside_the_boards_blob() {
    let mut rng = rand::thread_rng();
    let owner_sk = SigningKey::generate(&mut rng);
    let mut boards = Boards {
        map: HashMap::new(),
        current_board_key: None,
        profiles: Vec::new(),
        removed: Vec::new(),
        board_order: Vec::new(),
        archived: Vec::new(),
        client_features: ClientFeatures::default(),
        migrated_boards: Vec::new(),
        blocked_image_hashes: Vec::new(),
        auto_renew_images: false,
        last_auto_renew_at: 0,
        owned_images: Vec::new(),
    };
    let key =
        boards.create_new_board_with_name(owner_sk, "Queue".to_string(), "alice".to_string(), false);
    boards
        .map
        .get_mut(&key)
        .unwrap()
        .pending_uploads
        .push(PendingUpload {
            id: "p1".to_string(),
            name: "photo.png".to_string(),
            alt: "photo".to_string(),
            nsfw: false,
            mime: "image/png".to_string(),
            width: 2,
            height: 2,
            animated: false,
            bytes: vec![1, 2, 3],
            secret: None,
            image: None,
        });

    let mut buffer = Vec::new();
    ciborium::ser::into_writer(&boards, &mut buffer).unwrap();
    let decoded: Boards = ciborium::from_reader(&buffer[..]).unwrap();
    assert!(decoded.map[&key].pending_uploads.is_empty());
}

/// A suspended member keeps the role assignment but loses its powers until
/// the suspension ends. The contract still verifies records signed before
/// it against the raw roles.
#[test]
fn a_suspension_hides_role_powers_until_it_ends() {
    use plaza_core::board_state::member_moderation::{
        AuthorizedSuspension, SuspensionV1,
    };
    use plaza_core::board_state::reports::ReportReason;
    use plaza_core::board_state::roles::{
        AuthorizedRole, AuthorizedRoleAssignment, Role, RoleAssignment,
    };

    let mut rng = rand::thread_rng();
    let owner_sk = SigningKey::generate(&mut rng);
    let member_sk = SigningKey::generate(&mut rng);
    let member = MemberId::from(&member_sk.verifying_key());
    let role_id = [7u8; 16];
    let mut state = ChatBoardStateV1::default();
    state.roles.roles.push(AuthorizedRole::new(
        Role {
            id: role_id,
            name: "moderator".to_string(),
            generation: 1,
            can_manage_access: false,
            can_distribute_keys: false,
            can_edit_posts: false,
            can_delete_posts: false,
            can_close_posts: false,
            can_pin_posts: true,
            can_move_posts: false,
            can_manage_trash: true,
            can_attach_images: false,
            can_retire_images: false,
            scope: Vec::new(),
            deleted: false,
            signed_at: get_current_system_time(),
        },
        &owner_sk,
    ));
    state
        .roles
        .assignments
        .push(AuthorizedRoleAssignment::new(
            RoleAssignment {
                role_id,
                member_id: member,
                generation: 1,
                revoked: false,
                signed_at: get_current_system_time(),
            },
            &owner_sk,
        ));
    assert!(can_manage_trash(&state, member));

    let now = chrono::Utc::now().timestamp_millis();
    state
        .suspensions
        .suspensions
        .push(AuthorizedSuspension::new(
            SuspensionV1 {
                target: member,
                reason: ReportReason::Spam,
                until: now + 60_000,
                created_at: now,
                generation: 1,
            },
            &owner_sk,
        ));
    assert!(is_suspended_now(&state, member));
    assert!(!can_manage_trash(&state, member));
    assert!(!has_moderation_power(&state, member, ModerationPower::Pin, &[]));
    assert!(state.roles.can_manage_trash(&member), "the role stays");

    // Lifting writes a past `until`, which ends the suspension.
    state.suspensions.suspensions.clear();
    state
        .suspensions
        .suspensions
        .push(AuthorizedSuspension::new(
            SuspensionV1 {
                target: member,
                reason: ReportReason::Spam,
                until: now - 1_000,
                created_at: now - 60_000,
                generation: 2,
            },
            &owner_sk,
        ));
    assert!(!is_suspended_now(&state, member));
    assert!(can_manage_trash(&state, member));
    assert!(has_moderation_power(&state, member, ModerationPower::Pin, &[]));
}

/// A board written by an older schema must not cost the whole list: the
/// lenient decode keeps every entry that still deserializes.
#[test]
fn an_incompatible_stored_board_does_not_drop_the_others() {
    let mut rng = rand::thread_rng();
    let owner_sk = SigningKey::generate(&mut rng);
    let mut boards = Boards {
        map: HashMap::new(),
        current_board_key: None,
        profiles: Vec::new(),
        removed: Vec::new(),
        board_order: Vec::new(),
        archived: Vec::new(),
        client_features: ClientFeatures::default(),
        migrated_boards: Vec::new(),
        blocked_image_hashes: Vec::new(),
        auto_renew_images: false,
        last_auto_renew_at: 0,
        owned_images: Vec::new(),
    };
    let key = boards.create_new_board_with_name(
        owner_sk,
        "Kept".to_string(),
        "alice".to_string(),
        false,
    );

    let mut value = ciborium::value::Value::serialized(&boards).expect("boards serialize");
    let entries = value.as_map_mut().expect("boards are a map");
    let map_value = entries
        .iter_mut()
        .find(|(key, _)| key.as_text() == Some("map"))
        .map(|(_, value)| value)
        .expect("map entry");
    let map = map_value.as_map_mut().expect("board map");
    let old_owner = SigningKey::generate(&mut rng).verifying_key();
    map.push((
        ciborium::value::Value::serialized(&old_owner).expect("owner key serializes"),
        ciborium::value::Value::Text("written by an old schema".to_string()),
    ));

    let mut bytes = Vec::new();
    ciborium::into_writer(&value, &mut bytes).expect("encode");
    let decoded = Boards::decode(&bytes).expect("the blob decodes per board");
    assert!(decoded.map.contains_key(&key), "the compatible board survives");
    assert_eq!(decoded.map.len(), 1);
}

/// A freshly created board must already be a cleanup fixpoint: the contract
/// rejects published states that cleanup would change, so a PUT of a
/// non-normalized new board would never be accepted.
#[test]
fn test_new_board_state_is_normalized() {
    let mut rng = rand::thread_rng();
    for private in [false, true] {
        let owner_sk = SigningKey::generate(&mut rng);
        let mut boards = Boards {
            map: HashMap::new(),
            current_board_key: None,
            profiles: Vec::new(),
            removed: Vec::new(),
        board_order: Vec::new(),
        archived: Vec::new(),
        client_features: ClientFeatures::default(),
            migrated_boards: vec![],
            blocked_image_hashes: Vec::new(),
            auto_renew_images: false,
            last_auto_renew_at: 0,
            owned_images: Vec::new(),
        };
        let key = boards.create_new_board_with_name(
            owner_sk.clone(),
            "Normalized?".to_string(),
            "alice".to_string(),
            private,
        );
        let params = ChatBoardParametersV1 { owner: key };
        let board = boards.map.get(&key).unwrap();
        let mut normalized = board.board_state.clone();
        normalized
            .normalize(&params)
            .expect("cleanup must succeed on a fresh board");
        assert_eq!(
            normalized,
            board.board_state,
            "a freshly created {} board must be a cleanup fixpoint",
            if private { "private" } else { "public" }
        );
    }
}

/// Two participants: the owner creates a private board, the invitee joins,
/// and both read the encrypted board name and a private post while an
/// outsider cannot. This is the data path the "Private board" checkbox
/// drives.
/// A reload drops the in-memory secrets. The owner key stored with the
/// board still opens the private board, even when the active profile is a
/// member with no recipient blob.
#[test]
fn the_owner_key_recovers_a_private_board_key_after_a_reload() {
    let mut rng = rand::thread_rng();
    let owner_sk = SigningKey::generate(&mut rng);
    let mut boards = empty_boards();
    let key = boards.create_new_board_with_name(
        owner_sk.clone(),
        "Private".to_string(),
        "Owner".to_string(),
        true,
    );
    let mut board = boards.map.get(&key).unwrap().clone();
    let secret = *board.get_secret().expect("the owner holds the key").0;

    board.secrets.clear();
    board.current_secret_version = None;
    board.self_sk = SigningKey::generate(&mut rng);
    board.owner_sk = Some(owner_sk);

    board.decrypt_board_secrets_with_extra_keys(&[]);

    assert_eq!(
        board.get_secret().map(|(secret, _)| *secret),
        Some(secret),
        "the owner key restores the board secret"
    );
}

/// A stored profile key can also recover a private board after a reload,
/// for a board whose owner key is not on this device.
#[test]
fn a_stored_profile_recovers_a_private_board_key_after_a_reload() {
    let mut rng = rand::thread_rng();
    let owner_sk = SigningKey::generate(&mut rng);
    let profile = IdentityProfile::new("Reader".to_string(), SigningKey::generate(&mut rng));
    let mut boards = empty_boards();
    let key = boards.create_new_board_with_identity(
        owner_sk,
        profile.clone(),
        BoardIdentityMode::Derived,
        "Private".to_string(),
        "Reader".to_string(),
        true,
    );
    let mut board = boards.map.get(&key).unwrap().clone();
    let secret = *board.get_secret().expect("the profile holds the key").0;

    board.secrets.clear();
    board.current_secret_version = None;
    board.self_sk = SigningKey::generate(&mut rng);
    board.owner_sk = None;

    let derived = profile.derive_for_board(&key);
    board.decrypt_board_secrets_with_extra_keys(&[profile.signing_key.clone(), derived]);

    assert_eq!(
        board.get_secret().map(|(secret, _)| *secret),
        Some(secret),
        "the stored profile restores the board secret"
    );
}

#[test]
fn merging_keeps_the_owner_profile_id() {
    let mut rng = rand::thread_rng();
    let owner_sk = SigningKey::generate(&mut rng);
    let profile = IdentityProfile::new("Owner".to_string(), SigningKey::generate(&mut rng));
    let mut local = empty_boards();
    let key = local.create_new_board_with_identity(
        owner_sk,
        profile.clone(),
        BoardIdentityMode::Same,
        "Board".to_string(),
        "Owner".to_string(),
        false,
    );
    let expected = local.map.get(&key).unwrap().owner_profile_id.clone();
    assert_eq!(expected, Some(profile.id.clone()));

    let mut incoming = empty_boards();
    let mut board = local.map.get(&key).unwrap().clone();
    board.profile_id = Some("member-profile".to_string());
    board.owner_profile_id = None;
    incoming.map.insert(key, board);

    local.merge(incoming).expect("the board merge succeeds");
    assert_eq!(
        local.map.get(&key).unwrap().owner_profile_id,
        expected,
        "a member profile save must not erase the owner profile"
    );
}

#[test]
fn board_order_archive_and_notification_mode_survive_serialization() {
    let mut rng = rand::thread_rng();
    let mut boards = empty_boards();
    let first = boards.create_new_board_with_name(
        SigningKey::generate(&mut rng),
        "First".to_string(),
        "Owner".to_string(),
        false,
    );
    let second = boards.create_new_board_with_name(
        SigningKey::generate(&mut rng),
        "Second".to_string(),
        "Owner".to_string(),
        false,
    );
    boards.move_board(second, -1);
    boards.set_archived(first, true);
    boards.map.get_mut(&first).unwrap().notification_mode =
        NotificationMode::Muted;

    let mut buffer = Vec::new();
    ciborium::ser::into_writer(&boards, &mut buffer).unwrap();
    let decoded: Boards = ciborium::from_reader(&buffer[..]).unwrap();

    assert!(decoded.ordered_keys().iter().position(|key| *key == second) <
        decoded.ordered_keys().iter().position(|key| *key == first));
    assert!(decoded.is_archived(first));
    assert_eq!(
        decoded.map.get(&first).unwrap().notification_mode,
        NotificationMode::Muted
    );
}

#[test]
fn nickname_requests_move_from_pending_to_approved() {
    let mut rng = rand::thread_rng();
    let owner_sk = SigningKey::generate(&mut rng);
    let mut boards = empty_boards();
    let key = boards.create_new_board_with_name(
        owner_sk,
        "Board".to_string(),
        "Owner".to_string(),
        false,
    );
    let member = MemberId::from_bytes([9; 32]);
    let board = boards.map.get_mut(&key).unwrap();
    board.add_nickname_request(member, "Old".to_string(), "New".to_string());

    let pending = board.pending_nickname_request(member).unwrap().clone();
    assert_eq!(pending.requested_name, "New");
    assert_eq!(pending.status, NicknameRequestStatus::Pending);

    board.decide_nickname_request(&pending.id, NicknameRequestStatus::Approved);
    assert!(board.pending_nickname_request(member).is_none());
    assert_eq!(
        board.latest_nickname_request(member).unwrap().status,
        NicknameRequestStatus::Approved
    );
}

#[test]
fn test_private_board_is_readable_by_members_only() {
    use crate::util::ecies::{
        decrypt_secret_from_member_blob, decrypt_with_symmetric_key, seal_bytes, unseal_bytes,
    };
    use plaza_core::board_state::privacy::SealedBytes;
    use plaza_core::board_state::ChatBoardStateV1Delta;

    let mut rng = rand::thread_rng();
    let owner_sk = SigningKey::generate(&mut rng);
    let mut boards = Boards {
        map: HashMap::new(),
        current_board_key: None,
        profiles: Vec::new(),
        removed: Vec::new(),
        board_order: Vec::new(),
        archived: Vec::new(),
        client_features: ClientFeatures::default(),
        migrated_boards: vec![],
        blocked_image_hashes: Vec::new(),
        auto_renew_images: false,
        last_auto_renew_at: 0,
        owned_images: Vec::new(),
    };

    let key = boards.create_new_board_with_name(
        owner_sk.clone(),
        "Secret Plans".to_string(),
        "alice".to_string(),
        true,
    );
    let board = boards.map.get(&key).expect("board created");
    assert!(board.is_private(), "board must be created private");
    let (secret, version) = board.get_secret().expect("owner holds the secret");
    let secret = *secret;
    assert!(
        board
            .board_state
            .pq_secrets
            .keys
            .iter()
            .any(|entry| entry.key.member_id == MemberId::from(&key)),
        "the owner must publish a PQ key"
    );
    assert!(
        board.board_state.pq_secrets.sets.iter().any(|entry| {
            matches!(
                entry.set.scope,
                plaza_core::board_state::pq_secrets::PqScope::Board
            ) && entry
                .set
                .secrets
                .iter()
                .any(|secret| secret.member_id == MemberId::from(&key))
        }),
        "the owner must receive a PQ-sealed board secret"
    );
    board
        .board_state
        .verify(&board.board_state, &ChatBoardParametersV1 { owner: key })
        .expect("the PQ records verify in the contract state");

    // The owner reads the sealed board name.
    match &board.board_state.configuration.configuration.display.name {
        SealedBytes::Private {
            ciphertext,
            nonce,
            secret_version,
            ..
        } => assert_eq!(
            decrypt_with_symmetric_key(&secret, ciphertext, nonce, *secret_version).unwrap(),
            b"Secret Plans"
        ),
        _ => panic!("a private board name must be sealed"),
    }

    // The invitee joins with their own key.
    let invitee_sk = SigningKey::generate(&mut rng);
    let invitee_id: MemberId = invitee_sk.verifying_key().into();
    let owner_id: MemberId = key.into();
    let board = boards.map.get_mut(&key).unwrap();
    board
        .board_state
        .members
        .members
        .push(AuthorizedMember::new(
            Member {
                owner_member_id: owner_id,
                invited_by: owner_id,
                member_vk: invitee_sk.verifying_key(),
                join_proof: None,
            },
            &owner_sk,
        ));

    // The owner distributes the secret (same call the sync path makes when
    // a member joins) and applies it to the board state.
    let state_before = board.board_state.clone();
    let secrets_delta = board
        .generate_missing_member_secrets()
        .expect("the invitee needs an encrypted secret");
    board
        .board_state
        .apply_delta(
            &state_before,
            &ChatBoardParametersV1 { owner: key },
            &Some(ChatBoardStateV1Delta {
                secrets: Some(secrets_delta),
                ..Default::default()
            }),
        )
        .expect("the secrets delta applies cleanly");

    let blob = board
        .board_state
        .secrets
        .encrypted_secrets
        .iter()
        .find(|s| s.secret.member_id == invitee_id)
        .expect("the applied state carries the invitee's secret");
    assert_eq!(blob.secret.secret_version, version);
    let ephemeral = x25519_dalek::PublicKey::from(blob.secret.sender_ephemeral_public_key);
    let invitee_secret = decrypt_secret_from_member_blob(
        &blob.secret.ciphertext,
        &blob.secret.nonce,
        &ephemeral,
        &invitee_sk,
    )
    .expect("the invitee decrypts the board secret");
    assert_eq!(invitee_secret, secret, "both clients share the secret");

    // The invitee publishes its PQ key, the owner re-seals the board
    // secret, and the invitee opens it from the PQ set.
    use plaza_core::board_state::pq_secrets::{
        AuthorizedPqMemberKey, PqMemberKey, PqSecretsDelta,
    };
    let invitee_pq_key = AuthorizedPqMemberKey::new(
        PqMemberKey {
            member_id: invitee_id,
            ek: crate::util::pq::encapsulation_key(&invitee_sk),
            version: 1,
        },
        &invitee_sk,
    );
    assert!(
        board
            .board_state
            .members
            .members
            .iter()
            .any(|member| member.member.id() == invitee_id),
        "the invitee is in the members list before the PQ key"
    );
    let state_before = board.board_state.clone();
    board
        .board_state
        .apply_delta(
            &state_before,
            &ChatBoardParametersV1 { owner: key },
            &Some(ChatBoardStateV1Delta {
                pq_secrets: Some(PqSecretsDelta {
                    keys: vec![invitee_pq_key],
                    sets: vec![],
                }),
                ..Default::default()
            }),
        )
        .expect("the invitee KEM key applies");

    assert!(
        board.generate_missing_pq_secrets(),
        "the owner seals the secret to the invitee key"
    );

    let mut invitee_view = board.clone();
    invitee_view.self_sk = invitee_sk.clone();
    invitee_view.secrets.clear();
    invitee_view.current_secret_version = None;
    invitee_view.decrypt_pq_board_secrets();
    assert_eq!(
        invitee_view.get_secret().map(|(secret, _)| *secret),
        Some(secret),
        "the invitee opens the PQ-sealed secret"
    );

    // A private post from the owner opens for the invitee, not for others.
    let post = seal_bytes(b"hello from the owner", &secret, version);
    assert_eq!(
        unseal_bytes(&post, Some(&invitee_secret)).unwrap(),
        b"hello from the owner"
    );
    assert!(
        unseal_bytes(&post, Some(&[9u8; 32])).is_err(),
        "an outsider without the secret must not read the post"
    );
}

/// A restricted category shares its key with the members of the chosen
/// roles only. Members of the roles read the real name and its posts; other
/// board members see the placeholder and cannot open them.
#[test]
fn restricted_category_reaches_only_role_members() {
    use crate::util::ecies::seal_bytes;
    use plaza_core::board_state::category_secrets::CategorySecretsDelta;
    use plaza_core::board_state::content::CategoryContentV1;
    use plaza_core::board_state::roles::{
        AuthorizedRole, AuthorizedRoleAssignment, Role, RoleAssignment, RolesDelta,
    };
    use plaza_core::board_state::sections::{AuthorizedSectionV1, SectionV1, SectionsDelta};
    use plaza_core::board_state::ChatBoardStateV1Delta;

    let mut rng = rand::thread_rng();
    let owner_sk = SigningKey::generate(&mut rng);
    let invitee_sk = SigningKey::generate(&mut rng);
    let outsider_sk = SigningKey::generate(&mut rng);

    let mut boards = Boards {
        map: HashMap::new(),
        current_board_key: None,
        profiles: Vec::new(),
        removed: Vec::new(),
        board_order: Vec::new(),
        archived: Vec::new(),
        client_features: ClientFeatures::default(),
        migrated_boards: vec![],
        blocked_image_hashes: Vec::new(),
        auto_renew_images: false,
        last_auto_renew_at: 0,
        owned_images: Vec::new(),
    };
    let key = boards.create_new_board_with_name(
        owner_sk.clone(),
        "Public Board".to_string(),
        "alice".to_string(),
        false,
    );
    let params = ChatBoardParametersV1 { owner: key };
    let owner_id: MemberId = key.into();
    let invitee_id: MemberId = invitee_sk.verifying_key().into();
    let role_id = [7u8; 16];

    let board = boards.map.get_mut(&key).unwrap();
    board
        .board_state
        .members
        .members
        .push(AuthorizedMember::new(
            Member {
                owner_member_id: owner_id,
                invited_by: owner_id,
                member_vk: invitee_sk.verifying_key(),
                join_proof: None,
            },
            &owner_sk,
        ));

    let before = board.board_state.clone();
    board
        .board_state
        .apply_delta(
            &before,
            &params,
            &Some(ChatBoardStateV1Delta {
                roles: Some(RolesDelta {
                    roles: vec![AuthorizedRole::new(
                        Role {
                            id: role_id,
                            name: "Members".to_string(),
                            generation: 0,
                            can_manage_access: false,
                            can_distribute_keys: true,
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
                            signed_at: get_current_system_time(),
                        },
                        &owner_sk,
                    )],
                    assignments: vec![AuthorizedRoleAssignment::new(
                        RoleAssignment {
                            role_id,
                            member_id: invitee_id,
                            generation: 1,
                            revoked: false,
                            signed_at: get_current_system_time(),
                        },
                        &owner_sk,
                    )],
                }),
                ..Default::default()
            }),
        )
        .expect("roles apply");

    let category_secret = [3u8; 32];
    let sealed_name = seal_bytes(b"Members only", &category_secret, 0);
    let category_id = MessageId::from_bytes([11u8; 32]);
    let category = CategoryContentV1::new(
        "Restricted category".to_string(),
        None,
        "#6366f1".to_string(),
    )
    .with_allowed_roles(vec![role_id], sealed_name.clone(), true);
    let authorized_section = AuthorizedSectionV1::new(
        SectionV1 {
            id: category_id,
            parent: None,
            name: "Restricted category".to_string(),
            description: None,
            icon: None,
            color: "#6366f1".to_string(),
            allowed_roles: vec![role_id],
            sealed_name: Some(sealed_name),
            hidden: true,
            is_group: false,
            images_allowed: true,
            auto_moderated_topics: None,
            generation: 1,
            deleted: false,
            contract: None,
            signed_at: get_current_system_time(),
        },
        &owner_sk,
        None,
    );

    let readers = board.category_readers(&category);
    assert!(readers.contains(&invitee_id));
    let secret_set = board.new_category_secret_set(&category_id, &category_secret, 0, &readers);

    let before = board.board_state.clone();
    board
        .board_state
        .apply_delta(
            &before,
            &params,
            &Some(ChatBoardStateV1Delta {
                sections: Some(SectionsDelta {
                    sections: vec![authorized_section],
                }),
                category_secrets: Some(CategorySecretsDelta {
                    sets: vec![secret_set],
                }),
                ..Default::default()
            }),
        )
        .expect("section and its secret set apply");
    board.decrypt_category_secrets();
    assert_eq!(
        board.category_secret(&category_id),
        Some((0, category_secret)),
        "the owner keeps the key"
    );

    // Publish the invitee's PQ key and seal the category key to it with
    // the hybrid set.
    use plaza_core::board_state::pq_secrets::{
        AuthorizedPqMemberKey, PqMemberKey, PqScope, PqSecretsDelta,
    };
    let invitee_pq_key = AuthorizedPqMemberKey::new(
        PqMemberKey {
            member_id: invitee_id,
            ek: crate::util::pq::encapsulation_key(&invitee_sk),
            version: 1,
        },
        &invitee_sk,
    );
    let before = board.board_state.clone();
    board
        .board_state
        .apply_delta(
            &before,
            &params,
            &Some(ChatBoardStateV1Delta {
                pq_secrets: Some(PqSecretsDelta {
                    keys: vec![invitee_pq_key],
                    sets: vec![],
                }),
                ..Default::default()
            }),
        )
        .expect("the invitee PQ key applies");
    assert!(
        board.generate_missing_pq_category_secrets(),
        "the owner seals the category key to the invitee"
    );
    assert!(board.board_state.pq_secrets.sets.iter().any(|entry| {
        entry.set.scope == PqScope::Category(category_id)
            && entry
                .set
                .secrets
                .iter()
                .any(|secret| secret.member_id == invitee_id)
    }));

    let owner_view = boards.map.get(&key).unwrap().clone();
    assert_eq!(
        owner_view.restricted_categories().len(),
        1,
        "restricted section is discovered from sections state"
    );

    // The invitee decrypts their blob and recovers the category key.
    let mut invitee_view = owner_view.clone();
    invitee_view.self_sk = invitee_sk.clone();
    invitee_view.owner_sk = None;
    invitee_view.category_secrets.clear();
    invitee_view.decrypt_pq_category_secrets();
    assert_eq!(
        invitee_view.category_secret(&category_id),
        Some((0, category_secret))
    );

    // The outsider is a board member but not in the role: no blob.
    let outsider_id: MemberId = outsider_sk.verifying_key().into();
    let mut outsider_view = owner_view.clone();
    outsider_view.self_sk = outsider_sk.clone();
    outsider_view.owner_sk = None;
    outsider_view.category_secrets.clear();
    outsider_view.decrypt_category_secrets();
    assert!(outsider_view.category_secret(&category_id).is_none());

    // A post sealed with the category key opens only for key holders.
    let category_post = seal_bytes(b"members only post", &category_secret, 0);
    let plaintext =
        crate::util::ecies::unseal_bytes(&category_post, Some(&category_secret)).unwrap();
    assert_eq!(plaintext, b"members only post");

    // Adding a member to the role later: the owner's next distribution
    // carries the key, and the new member can read the category.
    let board = boards.map.get_mut(&key).unwrap();
    board
        .board_state
        .members
        .members
        .push(AuthorizedMember::new(
            Member {
                owner_member_id: owner_id,
                invited_by: owner_id,
                member_vk: outsider_sk.verifying_key(),
                join_proof: None,
            },
            &owner_sk,
        ));
    let before = board.board_state.clone();
    board
        .board_state
        .apply_delta(
            &before,
            &params,
            &Some(ChatBoardStateV1Delta {
                roles: Some(RolesDelta {
                    roles: vec![],
                    assignments: vec![AuthorizedRoleAssignment::new(
                        RoleAssignment {
                            role_id,
                            member_id: outsider_id,
                            generation: 1,
                            revoked: false,
                            signed_at: get_current_system_time(),
                        },
                        &owner_sk,
                    )],
                }),
                ..Default::default()
            }),
        )
        .expect("the role grant applies");

    // The distribution comes from the invitee, a member of the role with
    // the key-distribution permission, not from the owner.
    let mut distributor_view = boards.map.get(&key).unwrap().clone();
    distributor_view.self_sk = invitee_sk.clone();
    distributor_view.owner_sk = None;
    distributor_view.category_secrets.clear();
    distributor_view.decrypt_category_secrets();
    assert_eq!(
        distributor_view.category_secret(&category_id),
        Some((0, category_secret)),
        "the distributor holds the category key"
    );

    let delta = distributor_view
        .generate_missing_category_secrets()
        .expect("the new role member needs the category key");
    let blob = delta.sets[0]
        .encrypted_secrets
        .iter()
        .find(|blob| blob.secret.member_id == outsider_id)
        .expect("the outsider is the missing recipient");
    assert_eq!(blob.signer, Some(invitee_id));

    let board = boards.map.get_mut(&key).unwrap();
    let before = board.board_state.clone();
    board
        .board_state
        .apply_delta(
            &before,
            &params,
            &Some(ChatBoardStateV1Delta {
                category_secrets: Some(delta),
                ..Default::default()
            }),
        )
        .expect("the distribution applies");

    let mut newcomer = boards.map.get(&key).unwrap().clone();
    newcomer.self_sk = outsider_sk;
    newcomer.owner_sk = None;
    newcomer.category_secrets.clear();
    newcomer.decrypt_category_secrets();
    assert_eq!(
        newcomer.category_secret(&category_id),
        Some((0, category_secret)),
        "the new role member can read the category"
    );
}

/// Regression test for #85: accepting an invitation for a board that already
/// exists in the boards map must update self_sk so can_send_message() passes.
#[test]
fn test_can_send_message_after_self_sk_update() {
    let mut rng = rand::thread_rng();

    // Create owner
    let owner_sk = SigningKey::generate(&mut rng);
    let owner_vk = owner_sk.verifying_key();

    // Create board state with owner config
    let config = AuthorizedConfigurationV1::new(Configuration::default(), &owner_sk);
    let mut board_state = ChatBoardStateV1 {
        configuration: config,
        ..Default::default()
    };

    // Create an invitee and add them as a member
    let invitee_sk = SigningKey::generate(&mut rng);
    let invitee_vk = invitee_sk.verifying_key();
    let member = Member {
        owner_member_id: owner_vk.into(),
        invited_by: owner_vk.into(),
        member_vk: invitee_vk,
        join_proof: None,
    };
    let authorized_member = AuthorizedMember::new(member, &owner_sk);
    board_state.members.members.push(authorized_member);

    // Create BoardData with a STALE self_sk (different from the invitee key)
    let stale_sk = SigningKey::generate(&mut rng);
    let params = ChatBoardParametersV1 { owner: owner_vk };
    let params_bytes = to_cbor_vec(&params);
    let contract_code = ContractCode::from(BOARD_CONTRACT_WASM);
    let contract_key =
        ContractKey::from_params_and_code(Parameters::from(params_bytes), &contract_code);

    let mut board_data = BoardData {
        owner_vk,
        board_state,
        self_sk: stale_sk,
        owner_sk: None,
        owner_profile_id: None,
        profile_id: None,
        contract_key,
        secrets: HashMap::new(),
        category_secrets: HashMap::new(),
        old_category_secrets: HashMap::new(),
        collapsed_groups: Vec::new(),
        last_visit: 0,
        topic_read: HashMap::new(),
        topic_drafts: HashMap::new(),
        pending_uploads: Vec::new(),
        subscribed_categories: Vec::new(),
        notification_mode: NotificationMode::All,
        mail_visibility: MailVisibility::Hidden,
        nickname_requests: Vec::new(),
        current_secret_version: None,
        last_secret_rotation: None,
        key_migrated_to_delegate: false,
        self_authorized_member: None,
        invite_chain: vec![],
        self_member_info: None,
        spectator: false,
    };

    // With stale key, user should NOT be recognized as a member
    assert_eq!(
        board_data.can_send_message(),
        Err(SendMessageError::UserNotMember)
    );

    // After updating self_sk to the invitee's key, user should be a member
    board_data.self_sk = invitee_sk;
    assert_eq!(board_data.can_send_message(), Ok(()));
}

/// Test that capture_self_membership_data captures and updates member_info.
#[test]
fn test_capture_self_membership_data_preserves_nickname() {
    use plaza_core::board_state::privacy::SealedBytes;

    let mut rng = rand::thread_rng();
    let owner_sk = SigningKey::generate(&mut rng);
    let owner_vk = owner_sk.verifying_key();
    let invitee_sk = SigningKey::generate(&mut rng);
    let invitee_vk = invitee_sk.verifying_key();
    let member_id = MemberId::from(&invitee_vk);

    let config = AuthorizedConfigurationV1::new(Configuration::default(), &owner_sk);
    let mut board_state = ChatBoardStateV1 {
        configuration: config,
        ..Default::default()
    };

    // Add invitee as member
    let member = Member {
        owner_member_id: owner_vk.into(),
        invited_by: owner_vk.into(),
        member_vk: invitee_vk,
        join_proof: None,
    };
    board_state
        .members
        .members
        .push(AuthorizedMember::new(member, &owner_sk));

    // Add member_info with a custom nickname
    let info = MemberInfo {
        member_id,
        version: 0,
        preferred_nickname: SealedBytes::public("Alice".to_string().into_bytes()),
    };
    let authorized_info = AuthorizedMemberInfo::new_with_member_key(info, &invitee_sk);
    board_state.member_info.member_info.push(authorized_info);

    let params = ChatBoardParametersV1 { owner: owner_vk };
    let params_bytes = to_cbor_vec(&params);
    let contract_code = ContractCode::from(BOARD_CONTRACT_WASM);
    let contract_key =
        ContractKey::from_params_and_code(Parameters::from(params_bytes), &contract_code);

    let mut board_data = BoardData {
        owner_vk,
        board_state,
        self_sk: invitee_sk.clone(),
        owner_sk: None,
        owner_profile_id: None,
        profile_id: None,
        contract_key,
        secrets: HashMap::new(),
        category_secrets: HashMap::new(),
        old_category_secrets: HashMap::new(),
        collapsed_groups: Vec::new(),
        last_visit: 0,
        topic_read: HashMap::new(),
        topic_drafts: HashMap::new(),
        pending_uploads: Vec::new(),
        subscribed_categories: Vec::new(),
        notification_mode: NotificationMode::All,
        mail_visibility: MailVisibility::Hidden,
        nickname_requests: Vec::new(),
        current_secret_version: None,
        last_secret_rotation: None,
        key_migrated_to_delegate: false,
        self_authorized_member: None,
        invite_chain: vec![],
        self_member_info: None,
        spectator: false,
    };

    // Before capture, self_member_info should be None
    assert!(board_data.self_member_info.is_none());

    // Capture should populate self_member_info
    board_data.capture_self_membership_data(&params);
    assert!(board_data.self_member_info.is_some());
    let stored = board_data.self_member_info.as_ref().unwrap();
    assert_eq!(stored.member_info.member_id, member_id);
    assert_eq!(stored.member_info.version, 0);

    // Simulate nickname edit: update member_info in board_state with higher version
    let updated_info = MemberInfo {
        member_id,
        version: 1,
        preferred_nickname: SealedBytes::public("Bob".to_string().into_bytes()),
    };
    let updated_authorized =
        AuthorizedMemberInfo::new_with_member_key(updated_info, &invitee_sk);
    board_data.board_state.member_info.member_info[0] = updated_authorized;

    // Re-capture should update to latest version
    board_data.capture_self_membership_data(&params);
    let stored = board_data.self_member_info.as_ref().unwrap();
    assert_eq!(stored.member_info.version, 1);
}

#[test]
fn test_is_awaiting_initial_sync() {
    let mut rng = rand::thread_rng();
    let owner_sk = SigningKey::generate(&mut rng);
    let owner_vk = owner_sk.verifying_key();
    let invitee_sk = SigningKey::generate(&mut rng);

    let params = ChatBoardParametersV1 { owner: owner_vk };
    let params_bytes = to_cbor_vec(&params);
    let contract_code = ContractCode::from(BOARD_CONTRACT_WASM);
    let contract_key =
        ContractKey::from_params_and_code(Parameters::from(params_bytes), &contract_code);

    let make_board = |sk: SigningKey, members: Vec<AuthorizedMember>| {
        let config = AuthorizedConfigurationV1::new(Configuration::default(), &owner_sk);
        let mut board_state = ChatBoardStateV1 {
            configuration: config,
            ..Default::default()
        };
        board_state.members.members = members;
        BoardData {
            owner_vk,
            board_state,
            self_sk: sk,
            owner_sk: None,
            owner_profile_id: None,
            profile_id: None,
            contract_key,
            secrets: HashMap::new(),
            category_secrets: HashMap::new(),
            old_category_secrets: HashMap::new(),

            collapsed_groups: Vec::new(),
            last_visit: 0,
            topic_read: HashMap::new(),
            topic_drafts: HashMap::new(),
            pending_uploads: Vec::new(),
            subscribed_categories: Vec::new(),
        notification_mode: NotificationMode::All,
        mail_visibility: MailVisibility::Hidden,
        nickname_requests: Vec::new(),
            current_secret_version: None,
            last_secret_rotation: None,
            key_migrated_to_delegate: false,
            self_authorized_member: None,
            invite_chain: vec![],
            self_member_info: None,
            spectator: false,
        }
    };

    // Owner with empty members: NOT awaiting sync (owner created the board)
    let owner_board = make_board(owner_sk.clone(), vec![]);
    assert!(!owner_board.is_awaiting_initial_sync());

    // Imported board with empty members: IS awaiting sync
    let imported_board = make_board(invitee_sk.clone(), vec![]);
    assert!(imported_board.is_awaiting_initial_sync());

    // Imported board after sync (members populated): NOT awaiting sync
    let member = Member {
        owner_member_id: owner_vk.into(),
        invited_by: owner_vk.into(),
        member_vk: invitee_sk.verifying_key(),
        join_proof: None,
    };
    let auth_member = AuthorizedMember::new(member, &owner_sk);
    let synced_board = make_board(invitee_sk.clone(), vec![auth_member]);
    assert!(!synced_board.is_awaiting_initial_sync());

    // Synced board with members pruned but sections present: NOT awaiting sync
    let mut pruned_board = make_board(invitee_sk, vec![]);
    use plaza_core::board_state::sections::{AuthorizedSectionV1, SectionV1};
    let dummy_section = AuthorizedSectionV1::new(
        SectionV1 {
            id: plaza_core::board_state::message::MessageId::from_bytes([1u8; 32]),
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
    pruned_board
        .board_state
        .sections
        .sections
        .push(dummy_section);
    assert!(!pruned_board.is_awaiting_initial_sync());
}

/// The board-scoped key is stable for one board, differs between boards,
/// and is not the root key.
#[test]
fn profile_derivation_is_deterministic_and_board_scoped() {
    let mut rng = rand::thread_rng();
    let profile = IdentityProfile::new("Profile".to_string(), SigningKey::generate(&mut rng));
    let board_a = SigningKey::generate(&mut rng).verifying_key();
    let board_b = SigningKey::generate(&mut rng).verifying_key();

    let first = profile.derive_for_board(&board_a);
    let again = profile.derive_for_board(&board_a);
    let other = profile.derive_for_board(&board_b);

    assert_eq!(first.to_bytes(), again.to_bytes());
    assert_ne!(first.to_bytes(), other.to_bytes());
    assert_ne!(first.verifying_key(), profile.signing_key.verifying_key());
}

/// A private board in derived mode signs as a board key; the root profile
/// stays local and is reachable through `profile_id`.
#[test]
fn a_private_board_can_use_a_derived_profile_key() {
    let mut rng = rand::thread_rng();
    let owner_sk = SigningKey::generate(&mut rng);
    let profile = IdentityProfile::new("Shared".to_string(), SigningKey::generate(&mut rng));
    let root_vk = profile.signing_key.verifying_key();
    let mut boards = empty_boards();

    let key = boards.create_new_board_with_identity(
        owner_sk,
        profile.clone(),
        BoardIdentityMode::Derived,
        "Private".to_string(),
        "Shared".to_string(),
        true,
    );
    let board = boards.map.get(&key).unwrap();
    let derived_vk = profile.derive_for_board(&key).verifying_key();

    assert_ne!(board.self_sk.verifying_key(), root_vk);
    assert_eq!(board.self_sk.verifying_key(), derived_vk);
    assert_eq!(board.profile_id.as_deref(), Some(profile.id.as_str()));
    assert!(!board.uses_same_identity_as(&profile));
    assert!(board
        .board_state
        .members
        .members
        .iter()
        .any(|member| member.member.member_vk == derived_vk));
    assert!(board
        .board_state
        .admin
        .admins
        .iter()
        .any(|admin| admin.admin.member_id == MemberId::from(&derived_vk)));
    assert!(!board
        .board_state
        .member_info
        .member_info
        .iter()
        .any(|info| info.member_info.member_id == MemberId::from(&root_vk)));
    board
        .board_state
        .verify(&board.board_state, &ChatBoardParametersV1 { owner: key })
        .expect("the derived membership verifies");
    assert_eq!(
        boards.profile_for_board(board).map(|p| p.id.clone()),
        Some(profile.id.clone())
    );
}

/// Public boards keep the root key. Private boards signed with the same
/// root key are flagged; derived boards are not.
#[test]
fn profile_linkability_flags_a_shared_root_key_across_privacy_modes() {
    let mut rng = rand::thread_rng();
    let profile = IdentityProfile::new("Shared".to_string(), SigningKey::generate(&mut rng));
    let mut boards = empty_boards();

    let public_key = boards.create_new_board_with_identity(
        SigningKey::generate(&mut rng),
        profile.clone(),
        BoardIdentityMode::Derived,
        "Public".to_string(),
        "Shared".to_string(),
        false,
    );
    let derived_key = boards.create_new_board_with_identity(
        SigningKey::generate(&mut rng),
        profile.clone(),
        BoardIdentityMode::Derived,
        "Derived private".to_string(),
        "Shared".to_string(),
        true,
    );

    assert_eq!(
        boards.map[&public_key].self_sk.verifying_key(),
        profile.signing_key.verifying_key()
    );
    let linkability = boards.profile_linkability(&profile);
    assert_eq!(linkability.public_boards, vec![public_key]);
    assert!(linkability.private_boards.is_empty());
    assert_eq!(linkability.derived_boards, vec![derived_key]);
    assert!(!linkability.linked_across);

    // Same identity on a private board: the root key now appears on both.
    let same_key = boards.create_new_board_with_identity(
        SigningKey::generate(&mut rng),
        profile.clone(),
        BoardIdentityMode::Same,
        "Same private".to_string(),
        "Shared".to_string(),
        true,
    );
    let linkability = boards.profile_linkability(&profile);
    assert_eq!(
        boards.map[&same_key].self_sk.verifying_key(),
        profile.signing_key.verifying_key()
    );
    assert_eq!(linkability.private_boards, vec![same_key]);
    assert!(linkability.linked_across);
    assert_eq!(linkability.derived_boards, vec![derived_key]);
}

/// A derived board exports its root profile; importing it restores the
/// profile id, the root key and the owner key path.
#[test]
fn an_identity_export_roundtrips_the_root_profile() {
    let mut rng = rand::thread_rng();
    let owner_sk = SigningKey::generate(&mut rng);
    let owner_vk = owner_sk.verifying_key();
    let profile = IdentityProfile::new("Root".to_string(), SigningKey::generate(&mut rng));
    let mut boards = empty_boards();

    let key = boards.create_new_board_with_identity(
        owner_sk,
        profile.clone(),
        BoardIdentityMode::Derived,
        "Private".to_string(),
        "Root".to_string(),
        true,
    );
    let board = boards.map.get(&key).unwrap();
    let root = boards
        .export_root_profile(board)
        .expect("the board names its root profile");
    let export = IdentityExport {
        board_owner: key,
        signing_key: board.self_sk.clone(),
        owner_signing_key: Some(board.owner_key().clone()),
        authorized_member: board.self_authorized_member.clone().unwrap(),
        invite_chain: board.invite_chain.clone(),
        member_info: board.self_member_info.clone(),
        board_name: Some("Private".to_string()),
        category_keys: Vec::new(),
        board_secrets: Vec::new(),
        current_board_secret: None,
        profile_id: Some(root.id.clone()),
        profile_name: Some(root.name.clone()),
        profile_signing_key: Some(root.signing_key.clone()),
    };
    let decoded =
        IdentityExport::from_armored_string(&export.to_armored_string()).expect("decodes");

    let mut imported = empty_boards();
    let profile_id = imported
        .register_imported_profile(&decoded)
        .expect("the root profile is registered");
    let mut imported_board = board.clone();
    imported_board.self_sk = decoded.signing_key.clone();
    imported_board.owner_sk = decoded.owner_signing_key.clone();
    imported_board.profile_id = Some(profile_id.clone());
    imported.map.insert(key, imported_board);

    let resolved = imported
        .profile_for_board(&imported.map[&key])
        .expect("the board resolves to its root profile");
    assert_eq!(resolved.id, profile_id);
    assert_eq!(
        resolved.signing_key.to_bytes(),
        profile.signing_key.to_bytes()
    );
    assert_eq!(
        imported.map[&key].self_sk.verifying_key(),
        root.derive_for_board(&key).verifying_key()
    );
    assert_eq!(
        imported.map[&key].owner_sk.as_ref().map(|key| key.verifying_key()),
        Some(owner_vk)
    );
}
