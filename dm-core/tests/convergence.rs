use ed25519_dalek::SigningKey;
use plaza_dm_core::*;
use rand::rngs::OsRng;
use std::collections::HashSet;

#[derive(Clone)]
struct Fixture {
    params: DmParamsV1,
    creator_identity: SigningKey,
    creator_device: SigningKey,
    state: DmStateV1,
}

fn fixture() -> Fixture {
    let creator_identity = SigningKey::generate(&mut OsRng);
    let creator_device = SigningKey::generate(&mut OsRng);
    let state = DmStateV1::new(
        [1u8; 32],
        &creator_identity,
        &creator_device,
        vec![2u8; 1184],
        1_000,
    );
    Fixture {
        params: DmParamsV1 {
            protocol_version: PROTOCOL_VERSION,
            contract_secret: [7u8; 32],
        },
        creator_identity,
        creator_device,
        state,
    }
}

fn invite(fixture: &mut Fixture, invite_id: [u8; 32], token: [u8; 32], now: i64) -> DmInvite {
    let invite = DmInvite::new(
        invite_id,
        &fixture.creator_identity,
        &token,
        now,
        now + 10_000,
        None,
    );
    fixture
        .state
        .apply_delta(
            &fixture.params,
            &DmStateDeltaV1 {
                invites: Some(vec![invite.clone()]),
                ..Default::default()
            },
        )
        .expect("invite applies");
    invite
}

fn join(
    fixture: &mut Fixture,
    invite: &DmInvite,
    invitee_identity: &SigningKey,
    invitee_device: &SigningKey,
    now: i64,
) {
    let identity = identity_id(invitee_identity);
    let device = DmDevice {
        device_id: device_id(invitee_device),
        signing_key: invitee_device.verifying_key().to_bytes(),
        kem_ek: vec![3u8; 1184],
        created_at: now,
        revoked_at: None,
    };
    let member = DmMember {
        identity,
        version: 0,
        role: DmRole::Member,
        joined_at: now,
        devices: vec![AuthorizedDmDevice::new(device, invitee_identity)],
        left_at: None,
    };
    let mut used = invite.clone();
    used.mark_used(identity, now, &fixture.creator_identity);
    fixture
        .state
        .apply_delta(
            &fixture.params,
            &DmStateDeltaV1 {
                members: Some(vec![AuthorizedDmMember::new(member, invitee_identity)]),
                invites: Some(vec![used]),
                ..Default::default()
            },
        )
        .expect("join applies");
}

fn message(
    fixture: &mut Fixture,
    author: &SigningKey,
    device: &SigningKey,
    text: &str,
    now: i64,
) -> AuthorizedDmMessage {
    let message = DmMessage {
        id: [0u8; 32],
        author: identity_id(author),
        device: device_id(device),
        key_version: 0,
        created_at: now,
        content_type: CONTENT_TYPE_TEXT,
        ciphertext: text.as_bytes().to_vec(),
        nonce: [0u8; 24],
        reply_to: None,
        declared_len: text.len() as u32,
    };
    let authorized = AuthorizedDmMessage::new(message, device);
    fixture
        .state
        .apply_delta(
            &fixture.params,
            &DmStateDeltaV1 {
                messages: Some(vec![authorized.clone()]),
                ..Default::default()
            },
        )
        .expect("message applies");
    authorized
}

#[test]
fn state_summary_and_delta_round_trip() {
    let fixture = fixture();
    let bytes = encode(&fixture.state).unwrap();
    assert!(bytes.len() <= MAX_STATE_BYTES);
    let decoded = decode_state(&bytes).unwrap();
    assert_eq!(decoded, fixture.state);

    let summary = fixture.state.summarize();
    let summary_bytes = encode(&summary).unwrap();
    let decoded_summary = decode_summary(&summary_bytes).unwrap();
    assert_eq!(
        decoded_summary.state_version,
        fixture.state.meta.state_version
    );

    let delta = fixture
        .state
        .delta(&DmStateSummaryV1::default())
        .expect("a fresh summary gets a full delta");
    let delta_bytes = encode(&delta).unwrap();
    let decoded_delta = decode_delta(&delta_bytes).unwrap();
    assert_eq!(decoded_delta.members.unwrap().len(), 1);
}

#[test]
fn the_creator_state_verifies() {
    let fixture = fixture();
    fixture.state.verify(&fixture.params).unwrap();
    assert_eq!(fixture.state.members.members.len(), 1);
    assert_eq!(fixture.state.meta.state_version, 1);
}

#[test]
fn an_invite_adds_the_second_member() {
    let mut fixture = fixture();
    let token = [9u8; 32];
    let invite = invite(&mut fixture, [4u8; 32], token, 1_100);
    let invitee_identity = SigningKey::generate(&mut OsRng);
    let invitee_device = SigningKey::generate(&mut OsRng);
    join(
        &mut fixture,
        &invite,
        &invitee_identity,
        &invitee_device,
        1_200,
    );

    assert_eq!(fixture.state.members.members.len(), 2);
    fixture.state.verify(&fixture.params).unwrap();
    let stored = fixture
        .state
        .invites
        .invites
        .iter()
        .find(|entry| entry.invite_id == invite.invite_id)
        .unwrap();
    assert!(stored.used_at.is_some());
    assert_eq!(stored.used_by, Some(identity_id(&invitee_identity)));
}

#[test]
fn messages_round_trip_and_duplicates_are_ignored() {
    let mut fixture = fixture();
    let invite = invite(&mut fixture, [4u8; 32], [9u8; 32], 1_100);
    let invitee_identity = SigningKey::generate(&mut OsRng);
    let invitee_device = SigningKey::generate(&mut OsRng);
    join(
        &mut fixture,
        &invite,
        &invitee_identity,
        &invitee_device,
        1_200,
    );

    let creator_identity = fixture.creator_identity.clone();
    let creator_device = fixture.creator_device.clone();
    let sent = message(
        &mut fixture,
        &creator_identity,
        &creator_device,
        "hello",
        1_300,
    );
    fixture
        .state
        .apply_delta(
            &fixture.params,
            &DmStateDeltaV1 {
                messages: Some(vec![sent.clone()]),
                ..Default::default()
            },
        )
        .expect("a duplicate message is ignored");
    assert_eq!(fixture.state.messages.messages.len(), 1);

    message(
        &mut fixture,
        &invitee_identity,
        &invitee_device,
        "hi back",
        1_400,
    );
    assert_eq!(fixture.state.messages.messages.len(), 2);
    fixture.state.verify(&fixture.params).unwrap();
}

#[test]
fn a_message_from_an_unknown_device_is_rejected() {
    let mut fixture = fixture();
    let rogue = SigningKey::generate(&mut OsRng);
    let message = DmMessage {
        id: [0u8; 32],
        author: identity_id(&fixture.creator_identity),
        device: device_id(&rogue),
        key_version: 0,
        created_at: 1_300,
        content_type: CONTENT_TYPE_TEXT,
        ciphertext: b"spoof".to_vec(),
        nonce: [0u8; 24],
        reply_to: None,
        declared_len: 5,
    };
    let authorized = AuthorizedDmMessage::new(message, &rogue);
    let error = fixture
        .state
        .apply_delta(
            &fixture.params,
            &DmStateDeltaV1 {
                messages: Some(vec![authorized]),
                ..Default::default()
            },
        )
        .expect_err("the device is not a member");
    assert!(error.contains("device"), "{error}");
}

#[test]
fn the_message_cap_is_enforced() {
    let mut fixture = fixture();
    let mut messages = Vec::new();
    for index in 0..=MAX_MESSAGES {
        let text = format!("message {index}");
        let message = DmMessage {
            id: [0u8; 32],
            author: identity_id(&fixture.creator_identity),
            device: device_id(&fixture.creator_device),
            key_version: 0,
            created_at: 1_000 + index as i64,
            content_type: CONTENT_TYPE_TEXT,
            ciphertext: text.as_bytes().to_vec(),
            nonce: [0u8; 24],
            reply_to: None,
            declared_len: text.len() as u32,
        };
        messages.push(AuthorizedDmMessage::new(message, &fixture.creator_device));
    }
    let error = fixture
        .state
        .apply_delta(
            &fixture.params,
            &DmStateDeltaV1 {
                messages: Some(messages),
                ..Default::default()
            },
        )
        .expect_err("the state must refuse more than the cap");
    assert!(error.contains("cap"), "{error}");
}

#[test]
fn an_oversized_message_is_rejected() {
    let mut fixture = fixture();
    let text = vec![b'x'; MAX_MESSAGE_BYTES + 1];
    let message = DmMessage {
        id: [0u8; 32],
        author: identity_id(&fixture.creator_identity),
        device: device_id(&fixture.creator_device),
        key_version: 0,
        created_at: 1_300,
        content_type: CONTENT_TYPE_TEXT,
        ciphertext: text.clone(),
        nonce: [0u8; 24],
        reply_to: None,
        declared_len: text.len() as u32,
    };
    let authorized = AuthorizedDmMessage::new(message, &fixture.creator_device);
    let error = fixture
        .state
        .apply_delta(
            &fixture.params,
            &DmStateDeltaV1 {
                messages: Some(vec![authorized]),
                ..Default::default()
            },
        )
        .expect_err("oversized messages are rejected");
    assert!(error.contains("too large"), "{error}");
}

#[test]
fn merging_two_histories_converges_on_content() {
    let mut base = fixture();
    let invite = invite(&mut base, [4u8; 32], [9u8; 32], 1_100);
    let invitee_identity = SigningKey::generate(&mut OsRng);
    let invitee_device = SigningKey::generate(&mut OsRng);
    join(
        &mut base,
        &invite,
        &invitee_identity,
        &invitee_device,
        1_200,
    );

    let mut left = base.clone();
    let mut right = base.clone();
    message(
        &mut left,
        &base.creator_identity.clone(),
        &base.creator_device.clone(),
        "from left",
        1_300,
    );
    message(
        &mut right,
        &invitee_identity,
        &invitee_device,
        "from right",
        1_400,
    );

    left.state.merge(&base.params, &right.state).unwrap();
    right.state.merge(&base.params, &left.state).unwrap();

    let ids = |state: &DmStateV1| {
        state
            .messages
            .messages
            .iter()
            .map(|message| message.message.id)
            .collect::<HashSet<_>>()
    };
    assert_eq!(ids(&left.state), ids(&right.state));
    left.state.verify(&base.params).unwrap();
    right.state.verify(&base.params).unwrap();
}

#[test]
fn a_used_invite_cannot_be_reopened() {
    let mut fixture = fixture();
    let invite = invite(&mut fixture, [4u8; 32], [9u8; 32], 1_100);
    let invitee_identity = SigningKey::generate(&mut OsRng);
    let invitee_device = SigningKey::generate(&mut OsRng);
    join(
        &mut fixture,
        &invite,
        &invitee_identity,
        &invitee_device,
        1_200,
    );

    let stale = invite.clone();
    fixture
        .state
        .apply_delta(
            &fixture.params,
            &DmStateDeltaV1 {
                invites: Some(vec![stale]),
                ..Default::default()
            },
        )
        .expect("a stale invite does not reopen the used one");
    let stored = fixture
        .state
        .invites
        .invites
        .iter()
        .find(|entry| entry.invite_id == invite.invite_id)
        .unwrap();
    assert!(stored.used_at.is_some());
}

#[test]
fn a_revoked_device_cannot_send_new_messages() {
    let mut fixture = fixture();
    let mut member = fixture.state.members.members[0].member.clone();
    member.version = 1;
    let mut device = member.devices[0].device.clone();
    device.revoked_at = Some(2_000);
    member.devices[0] = AuthorizedDmDevice::new(device, &fixture.creator_identity);
    fixture
        .state
        .apply_delta(
            &fixture.params,
            &DmStateDeltaV1 {
                members: Some(vec![AuthorizedDmMember::new(
                    member,
                    &fixture.creator_identity,
                )]),
                ..Default::default()
            },
        )
        .unwrap();

    let message = DmMessage {
        id: [0u8; 32],
        author: identity_id(&fixture.creator_identity),
        device: device_id(&fixture.creator_device),
        key_version: 0,
        created_at: 2_001,
        content_type: CONTENT_TYPE_TEXT,
        ciphertext: b"after revoke".to_vec(),
        nonce: [0u8; 24],
        reply_to: None,
        declared_len: 12,
    };
    let authorized = AuthorizedDmMessage::new(message, &fixture.creator_device);
    let error = fixture
        .state
        .apply_delta(
            &fixture.params,
            &DmStateDeltaV1 {
                messages: Some(vec![authorized]),
                ..Default::default()
            },
        )
        .expect_err("a revoked device cannot send");
    assert!(error.contains("revoked"), "{error}");
}

#[test]
fn a_generation_pointer_is_signed_and_stored() {
    let mut fixture = fixture();
    let next = [5u8; 32];
    let generation = DmGenerationV1::new(1, None, Some(next), Some(1_500), &fixture.creator_device);
    fixture
        .state
        .apply_delta(
            &fixture.params,
            &DmStateDeltaV1 {
                generation: Some(generation),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(fixture.state.generation.generation, 1);
    assert_eq!(fixture.state.generation.next_contract, Some(next));
    fixture.state.verify(&fixture.params).unwrap();
}
