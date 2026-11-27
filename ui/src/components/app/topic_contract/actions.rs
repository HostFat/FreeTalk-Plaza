//! Topic post content codecs, reactions, polls, edits, and post approvals.

use super::*;

pub(super) fn encode_content(
    board: &BoardData,
    content: &TopicPostContentV1,
) -> Result<SealedBytes, String> {
    let bytes = encode(content)?;
    seal_action_payload(board, &bytes)
}

pub(super) fn decode_content(board: &BoardData, sealed: &SealedBytes) -> Option<TopicPostContentV1> {
    let bytes = open_action_payload(board, sealed)?;
    ciborium::de::from_reader::<TopicPostContentV1, _>(bytes.as_slice()).ok()
}

/// Decode typed post content, falling back to a plain-text reply written before
/// the typed envelope existed.
pub fn read_post_content(
    board: &BoardData,
    sealed: &SealedBytes,
) -> Option<TopicPostContentV1> {
    if let Some(content) = decode_content(board, sealed) {
        return Some(content);
    }
    read_text(board, sealed).map(TopicPostContentV1::Text)
}

/// Latest reaction per member and emoji for one post or the topic header.
pub fn reactions_for(
    board: &BoardData,
    state: &TopicPartState,
    target: MessageId,
) -> BTreeMap<String, Vec<MemberId>> {
    let mut latest: BTreeMap<(MemberId, String), (u64, bool)> = BTreeMap::new();
    for entry in state.all_actions().into_iter().filter(|entry| {
        entry.action.target == target
            && matches!(
                entry.action.kind,
                TopicActionKind::React | TopicActionKind::Unreact
            )
    }) {
        let Some(bytes) = open_action_payload(board, &entry.action.payload) else {
            continue;
        };
        let Ok(emoji) = String::from_utf8(bytes) else {
            continue;
        };
        let key = (entry.action.signer, emoji);
        let value = (entry.action.generation, entry.action.kind == TopicActionKind::React);
        match latest.get(&key) {
            Some((generation, _)) if *generation >= value.0 => {}
            _ => {
                latest.insert(key, value);
            }
        }
    }
    let mut out: BTreeMap<String, Vec<MemberId>> = BTreeMap::new();
    for ((member, emoji), (_, active)) in latest {
        if active {
            out.entry(emoji).or_default().push(member);
        }
    }
    for members in out.values_mut() {
        members.sort();
    }
    out
}

pub async fn toggle_reaction(
    owner: VerifyingKey,
    topic_id: MessageId,
    part: u32,
    target: MessageId,
    emoji: String,
    add: bool,
) -> Result<(), String> {
    let board = board_for(owner)?;
    let target_part = if target == topic_id { 0 } else { part };
    let conversation = conversation_for(owner, topic_id, target_part)?;
    if emoji.is_empty() || emoji.len() > 32 {
        return Err("the reaction is not valid".to_string());
    }
    let signer = MemberId::from(&board.self_sk.verifying_key());
    let now = system_time_ms(get_current_system_time());
    let generation = conversation
        .state
        .all_actions()
        .into_iter()
        .filter(|entry| {
            entry.action.target == target
                && entry.action.signer == signer
                && matches!(
                    entry.action.kind,
                    TopicActionKind::React | TopicActionKind::Unreact
                )
        })
        .map(|entry| entry.action.generation + 1)
        .max()
        .unwrap_or(1);
    let action = plaza_topic_core::TopicActionV1 {
        kind: if add {
            TopicActionKind::React
        } else {
            TopicActionKind::Unreact
        },
        target,
        payload: seal_action_payload(&board, emoji.as_bytes())?,
        generation,
        created_at: now,
        signer,
    };
    let authorized = plaza_topic_core::AuthorizedTopicActionV1 {
        signature: plaza_core::util::sign_struct(&action, &board.self_sk),
        action,
        signer_key: Some(board.self_sk.verifying_key()),
        authority: None,
    };
    let mut participants = Vec::new();
    if signer != board.current_owner_id()
        && signer != MemberId::from(&owner)
        && !conversation
            .state
            .participants()
            .iter()
            .any(|p| p.record.member_id == signer)
    {
        if let Some(cert) = participant_for(&board, signer) {
            participants.push(cert);
        }
    }
    match &conversation.state {
        TopicPartState::Head(_) => {
            publish_topic_delta(
                *conversation.key.id(),
                TopicDeltaV1 {
                    participants,
                    actions: vec![authorized],
                    ..Default::default()
                },
            )
            .await
        }
        TopicPartState::Page(_) => {
            publish_topic_page_delta(
                *conversation.key.id(),
                TopicPageDeltaV1 {
                    participants,
                    actions: vec![authorized],
                    ..Default::default()
                },
            )
            .await
        }
    }
}

/// Counts per option, using the latest vote per member.
pub fn poll_votes(
    board: &BoardData,
    state: &TopicPartState,
    poll_id: MessageId,
) -> Vec<Vec<MemberId>> {
    let Some(content) = effective_post_content(board, state, poll_id) else {
        return Vec::new();
    };
    let Some(TopicPostContentV1::Poll(poll)) = read_post_content(board, &content) else {
        return Vec::new();
    };
    let mut latest: BTreeMap<MemberId, (u64, PollVoteV1)> = BTreeMap::new();
    for entry in state.all_actions().into_iter().filter(|entry| {
        entry.action.target == poll_id && entry.action.kind == TopicActionKind::Vote
    }) {
        let Some(bytes) = open_action_payload(board, &entry.action.payload) else {
            continue;
        };
        let Ok(vote) = ciborium::de::from_reader::<PollVoteV1, _>(bytes.as_slice()) else {
            continue;
        };
        if vote.poll != poll_id || vote.validate_for(&poll).is_err() {
            continue;
        }
        let signer = entry.action.signer;
        let generation = entry.action.generation;
        match latest.get(&signer) {
            Some((known, _)) if *known >= generation => {}
            _ => {
                latest.insert(signer, (generation, vote));
            }
        }
    }
    let mut counts = vec![Vec::new(); poll.options.len()];
    for (member, (_, vote)) in latest {
        for index in vote.options {
            if let Some(slot) = counts.get_mut(index as usize) {
                slot.push(member);
            }
        }
    }
    for slot in counts.iter_mut() {
        slot.sort();
    }
    counts
}

pub async fn vote(
    owner: VerifyingKey,
    topic_id: MessageId,
    part: u32,
    poll_id: MessageId,
    options: Vec<u16>,
) -> Result<(), String> {
    let board = board_for(owner)?;
    let conversation = conversation_for(owner, topic_id, part)?;
    let content = effective_post_content(&board, &conversation.state, poll_id)
        .ok_or("the poll is not in this topic")?;
    let Some(TopicPostContentV1::Poll(poll)) = read_post_content(&board, &content) else {
        return Err("the target is not a poll".to_string());
    };
    let now = system_time_ms(get_current_system_time());
    if poll.closes_at.is_some_and(|closes| closes <= now) {
        return Err("the poll is closed".to_string());
    }
    let signer = MemberId::from(&board.self_sk.verifying_key());
    let generation = conversation
        .state
        .all_actions()
        .into_iter()
        .filter(|entry| {
            entry.action.target == poll_id
                && entry.action.kind == TopicActionKind::Vote
                && entry.action.signer == signer
        })
        .map(|entry| entry.action.generation + 1)
        .max()
        .unwrap_or(1);
    let vote = PollVoteV1 {
        poll: poll_id,
        options,
        generation,
        created_at: now,
    };
    vote.validate_for(&poll)?;
    let payload = seal_action_payload(&board, &encode(&vote)?)?;
    let action = plaza_topic_core::TopicActionV1 {
        kind: TopicActionKind::Vote,
        target: poll_id,
        payload,
        generation,
        created_at: now,
        signer,
    };
    let authorized = plaza_topic_core::AuthorizedTopicActionV1 {
        signature: plaza_core::util::sign_struct(&action, &board.self_sk),
        action,
        signer_key: Some(board.self_sk.verifying_key()),
        authority: None,
    };
    let mut participants = Vec::new();
    if signer != board.current_owner_id()
        && signer != MemberId::from(&owner)
        && !conversation
            .state
            .participants()
            .iter()
            .any(|p| p.record.member_id == signer)
    {
        if let Some(cert) = participant_for(&board, signer) {
            participants.push(cert);
        }
    }
    match &conversation.state {
        TopicPartState::Head(_) => {
            publish_topic_delta(
                *conversation.key.id(),
                TopicDeltaV1 {
                    participants,
                    actions: vec![authorized],
                    ..Default::default()
                },
            )
            .await
        }
        TopicPartState::Page(_) => {
            publish_topic_page_delta(
                *conversation.key.id(),
                TopicPageDeltaV1 {
                    participants,
                    actions: vec![authorized],
                    ..Default::default()
                },
            )
            .await
        }
    }
}

pub(super) fn open_action_payload(board: &BoardData, payload: &SealedBytes) -> Option<Vec<u8>> {
    match payload {
        SealedBytes::Public { value } => Some(value.clone()),
        SealedBytes::Private {
            ciphertext,
            nonce,
            secret_version,
            ..
        } => {
            let secret = board.get_secret_for_version(*secret_version)?;
            decrypt_with_symmetric_key(secret, ciphertext, nonce, *secret_version).ok()
        }
    }
}

pub(super) fn seal_action_payload(board: &BoardData, bytes: &[u8]) -> Result<SealedBytes, String> {
    if board.is_private() {
        let (secret, version) = board
            .get_secret()
            .ok_or("the board secret is not available")?;
        let (ciphertext, nonce) = encrypt_with_symmetric_key(secret, bytes, version);
        Ok(SealedBytes::private(
            ciphertext,
            nonce,
            version,
            bytes.len() as u32,
        ))
    } else {
        Ok(SealedBytes::public(bytes.to_vec()))
    }
}

pub fn effective_topic_content(
    board: &BoardData,
    state: &TopicStateV1,
) -> Option<(SealedBytes, SealedBytes)> {
    let header = state.header.as_ref()?;
    let target = header.header.id();
    let fallback = (header.header.title.clone(), header.header.body.clone());
    let Some(action) = state.latest_action(target, TopicActionKind::Edit) else {
        return Some(fallback);
    };
    let Some(bytes) = open_action_payload(board, &action.action.payload) else {
        return Some(fallback);
    };
    let Ok(edit) = ciborium::de::from_reader::<TopicEditV1, _>(bytes.as_slice()) else {
        return Some(fallback);
    };
    Some((edit.title, edit.body))
}

pub fn is_topic_edited(state: &TopicStateV1) -> bool {
    state
        .header
        .as_ref()
        .is_some_and(|header| state.latest_action(header.header.id(), TopicActionKind::Edit).is_some())
}

pub fn is_post_edited(state: &TopicPartState, post_id: MessageId) -> bool {
    state.latest_action(post_id, TopicActionKind::Edit).is_some()
        || state.latest_action(post_id, TopicActionKind::EditPoll).is_some()
}

pub fn effective_post_content(
    board: &BoardData,
    state: &TopicPartState,
    post_id: MessageId,
) -> Option<SealedBytes> {
    let post = state.posts().get(&post_id)?;
    let edit_action = state.latest_action(post_id, TopicActionKind::Edit);
    let poll_action = state.latest_action(post_id, TopicActionKind::EditPoll);
    let action = match (edit_action, poll_action) {
        (Some(a), Some(b)) => {
            if (b.action.created_at, b.action.generation)
                >= (a.action.created_at, a.action.generation)
            {
                Some(b)
            } else {
                Some(a)
            }
        }
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    };
    let Some(action) = action else {
        return Some(post.post.content.clone());
    };
    let Some(bytes) = open_action_payload(board, &action.action.payload) else {
        return Some(post.post.content.clone());
    };
    match ciborium::de::from_reader::<PostEditV1, _>(bytes.as_slice()) {
        Ok(edit) => Some(edit.content),
        Err(_) => Some(post.post.content.clone()),
    }
}

/// Edit the topic title and body. Topic-level edits always target `part == 0`
/// (the topic head). Only the topic author updates the board index entry.
pub async fn edit_topic(
    owner: VerifyingKey,
    topic_id: MessageId,
    _part: u32,
    title: String,
    body: String,
) -> Result<(), String> {
    let board = board_for(owner)?;
    let conversation = conversation_for(owner, topic_id, 0)?;
    let head = conversation
        .state
        .as_head()
        .ok_or("topic head is not loaded")?;
    let header = head
        .header
        .as_ref()
        .ok_or("the topic is still loading")?;
    let self_id = MemberId::from(&board.self_sk.verifying_key());
    if header.header.author != self_id {
        return Err("only the topic author can edit its title here".to_string());
    }
    if title.trim().is_empty() {
        return Err("the topic needs a title".to_string());
    }
    let now = system_time_ms(get_current_system_time());
    let edit = TopicEditV1 {
        title: seal_text(&board, &title)?,
        body: seal_text(&board, &body)?,
    };
    let payload = seal_action_payload(&board, &encode(&edit)?)?;
    let generation = head
        .latest_action(header.header.id(), TopicActionKind::Edit)
        .map(|entry| entry.action.generation + 1)
        .unwrap_or(1);
    let action = plaza_topic_core::TopicActionV1 {
        kind: TopicActionKind::Edit,
        target: header.header.id(),
        payload,
        generation,
        created_at: now,
        signer: self_id,
    };
    let authorized = plaza_topic_core::AuthorizedTopicActionV1 {
        signature: plaza_core::util::sign_struct(&action, &board.self_sk),
        action,
        signer_key: Some(board.self_sk.verifying_key()),
        authority: None,
    };
    publish_topic_delta(
        *conversation.key.id(),
        TopicDeltaV1 {
            actions: vec![authorized],
            ..Default::default()
        },
    )
    .await?;

    let index = crate::components::app::section_contract::merged_index(
        owner,
        &board.board_state.topics,
    );
    if let Some(entry) = index.entry(&topic_id) {
        let mut next = entry.entry.clone();
        next.title = seal_text(&board, &title)?;
        let preview: String = body.chars().take(200).collect();
        next.preview = seal_text(&board, &preview)?;
        next.generation += 1;
        let authorized_entry = AuthorizedTopicEntryV1::new(next, &board.self_sk);
        let board_delta = ChatBoardStateV1Delta {
            topics: Some(TopicIndexDelta {
                entries: vec![authorized_entry],
                ..Default::default()
            }),
            ..Default::default()
        };
        apply_topic_board_delta(owner, topic_id, board_delta).await?;
    }
    Ok(())
}

/// Edit one reply. The author or the board owner may edit it.
pub async fn edit_post(
    owner: VerifyingKey,
    topic_id: MessageId,
    part: u32,
    post_id: MessageId,
    text: String,
) -> Result<(), String> {
    let board = board_for(owner)?;
    let conversation = conversation_for(owner, topic_id, part)?;
    let post = conversation
        .state
        .posts()
        .get(&post_id)
        .ok_or("the reply is not in this topic")?;
    let self_id = MemberId::from(&board.self_sk.verifying_key());
    let signer_sk = if post.post.author == self_id {
        board.self_sk.clone()
    } else if board.is_current_owner() {
        board.owner_key().clone()
    } else {
        return Err("only the author or the owner can edit this reply".to_string());
    };
    let signer = MemberId::from(&signer_sk.verifying_key());
    let now = system_time_ms(get_current_system_time());
    let edit = PostEditV1 {
        content: seal_text(&board, &text)?,
    };
    let payload = seal_action_payload(&board, &encode(&edit)?)?;
    let generation = conversation
        .state
        .latest_action(post_id, TopicActionKind::Edit)
        .map(|entry| entry.action.generation + 1)
        .unwrap_or(1);
    let action = plaza_topic_core::TopicActionV1 {
        kind: TopicActionKind::Edit,
        target: post_id,
        payload,
        generation,
        created_at: now,
        signer,
    };
    let authorized = plaza_topic_core::AuthorizedTopicActionV1 {
        signature: plaza_core::util::sign_struct(&action, &signer_sk),
        action,
        signer_key: Some(signer_sk.verifying_key()),
        authority: None,
    };
    publish_part_action(&conversation, authorized).await
}

/// Edit one poll reply using `TopicActionKind::EditPoll`. The author or the
/// board owner may edit it.
pub async fn edit_poll(
    owner: VerifyingKey,
    topic_id: MessageId,
    part: u32,
    post_id: MessageId,
    mut poll: PollContentV1,
) -> Result<(), String> {
    poll.title = poll.title.trim().to_string();
    poll.options = poll
        .options
        .into_iter()
        .map(|opt| opt.trim().to_string())
        .filter(|opt| !opt.is_empty())
        .collect();
    if poll.title.is_empty() {
        return Err("the poll needs a question".to_string());
    }
    if poll.options.len() < 2 {
        return Err("a poll needs at least two options".to_string());
    }
    let board = board_for(owner)?;
    let conversation = conversation_for(owner, topic_id, part)?;
    let post = conversation
        .state
        .posts()
        .get(&post_id)
        .ok_or("the poll is not in this topic")?;
    let self_id = MemberId::from(&board.self_sk.verifying_key());
    let signer_sk = if post.post.author == self_id {
        board.self_sk.clone()
    } else if board.is_current_owner() {
        board.owner_key().clone()
    } else {
        return Err("only the author or the owner can edit this poll".to_string());
    };
    let signer = MemberId::from(&signer_sk.verifying_key());
    let now = system_time_ms(get_current_system_time());
    let edit = PostEditV1 {
        content: encode_content(&board, &TopicPostContentV1::Poll(poll))?,
    };
    let payload = seal_action_payload(&board, &encode(&edit)?)?;
    let generation = conversation
        .state
        .latest_action(post_id, TopicActionKind::EditPoll)
        .map(|entry| entry.action.generation + 1)
        .unwrap_or(1);
    let action = plaza_topic_core::TopicActionV1 {
        kind: TopicActionKind::EditPoll,
        target: post_id,
        payload,
        generation,
        created_at: now,
        signer,
    };
    let authorized = plaza_topic_core::AuthorizedTopicActionV1 {
        signature: plaza_core::util::sign_struct(&action, &signer_sk),
        action,
        signer_key: Some(signer_sk.verifying_key()),
        authority: None,
    };
    publish_part_action(&conversation, authorized).await
}



pub(super) fn delete_authority(
    board: &BoardData,
    signer: &MemberId,
) -> Option<AuthorityProof> {
    let state = &board.board_state;
    let admin = state
        .admin
        .admins
        .iter()
        .find(|entry| {
            entry.admin.id() == *signer
                && !state.admin.revoked.iter().any(|rev| {
                    rev.id() == *signer && rev.revocation.generation >= entry.admin.generation
                })
        })
        .cloned();
    for assignment in state
        .roles
        .assignments
        .iter()
        .filter(|entry| entry.assignment.member_id == *signer && !entry.assignment.revoked)
    {
        if let Some(role) = state.roles.roles.iter().find(|entry| {
            entry.role.id == assignment.assignment.role_id
                && !entry.role.deleted
                && entry.role.can_delete_posts
        }) {
            return Some(AuthorityProof {
                admin,
                grant: Some(Box::new(RoleGrantProof {
                    role: role.clone(),
                    assignment: assignment.clone(),
                })),
            });
        }
    }
    admin.map(|admin| AuthorityProof {
        admin: Some(admin),
        grant: None,
    })
}

/// Approve or reject one pending reply. The owner/moderator signs the approval
/// and, when approving, also trusts the author so later replies are visible
/// immediately.
pub async fn approve_post(
    owner: VerifyingKey,
    topic_id: MessageId,
    part: u32,
    post_id: MessageId,
    approved: bool,
) -> Result<(), String> {
    let board = board_for(owner)?;
    let conversation = conversation_for(owner, topic_id, part)?;
    if !conversation.state.is_loaded() {
        return Err("the topic is still loading".to_string());
    }
    let chain = conversation.state.section_chain();
    let scope = conversation.state.section_id();
    let self_id = MemberId::from(&board.self_sk.verifying_key());
    let owner_id = board.current_owner_id();
    let (signer_sk, signer, authority) = if self_id != owner_id
        && board.can_moderate(&chain)
    {
        (
            board.self_sk.clone(),
            self_id,
            delete_authority(&board, &self_id),
        )
    } else if board.is_current_owner() {
        (board.owner_key().clone(), owner_id, None)
    } else {
        return Err("only a moderator can approve replies".to_string());
    };
    let post = conversation
        .state
        .posts()
        .get(&post_id)
        .ok_or("the reply is not in this topic")?;
    let now = system_time_ms(get_current_system_time());
    let generation = conversation
        .state
        .approvals()
        .iter()
        .filter(|entry| entry.approval.target == post_id)
        .map(|entry| entry.approval.generation + 1)
        .max()
        .unwrap_or(1);
    let approval = TopicApprovalV1 {
        target: post_id,
        approved,
        generation,
        scope,
        signed_by: signer,
        created_at: now,
    };
    let authorized = AuthorizedTopicApprovalV1 {
        signature: plaza_core::util::sign_struct(&approval, &signer_sk),
        approval,
        signer_key: Some(signer_sk.verifying_key()),
        authority: authority.clone().map(Box::new),
    };
    let trust_record = if approved {
        let author = post.post.author;
        let trust_generation = conversation
            .state
            .trust()
            .iter()
            .filter(|entry| entry.trust.member_id == author)
            .map(|entry| entry.trust.generation + 1)
            .max()
            .unwrap_or(1);
        let trust = TrustV1 {
            member_id: author,
            trusted: true,
            generation: trust_generation,
            signed_by: signer,
            created_at: now,
        };
        Some(AuthorizedTrustV1 {
            signature: plaza_core::util::sign_struct(&trust, &signer_sk),
            trust,
            signer_key: Some(signer_sk.verifying_key()),
            authority: authority.clone().map(Box::new),
        })
    } else {
        None
    };
    match &conversation.state {
        TopicPartState::Head(_) => {
            publish_topic_delta(
                *conversation.key.id(),
                TopicDeltaV1 {
                    approvals: vec![authorized],
                    trust: trust_record.into_iter().collect(),
                    ..Default::default()
                },
            )
            .await?;
        }
        TopicPartState::Page(_) => {
            publish_topic_page_delta(
                *conversation.key.id(),
                TopicPageDeltaV1 {
                    approvals: vec![authorized],
                    trust: trust_record.into_iter().collect(),
                    ..Default::default()
                },
            )
            .await?;
        }
    }

    let index = board.clone().with_merged_topics().board_state.topics;
    if let Some(current) = index
        .activity_for(&topic_id)
        .map(|entry| entry.activity.clone())
    {
        let activity = TopicActivityV1 {
            topic_id,
            last_activity: current.last_activity,
            last_post_id: current.last_post_id,
            reply_count: current.reply_count,
            pending_approvals: current.pending_approvals.saturating_sub(1),
            generation: current.generation + 1,
        };
        let authorized_activity = AuthorizedTopicActivityV1 {
            signature: plaza_core::util::sign_struct(&activity, &signer_sk),
            activity,
            signer: Some(signer),
            signer_key: Some(signer_sk.verifying_key()),
        };
        let section = index
            .section_of(&topic_id)
            .0
            .or_else(|| section_for_topic(owner, topic_id).map(|(s, _)| s));
        if let Err(error) = crate::components::app::activity_contract::record_activity(
            owner,
            section,
            topic_id,
            part,
            authorized_activity,
        )
        .await
        {
            dioxus::logger::tracing::warn!(
                "approval sent but the pending count was not updated: {}",
                error
            );
        }
    }
    Ok(())
}
