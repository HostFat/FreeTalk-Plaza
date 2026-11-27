//! Section management, topic move/merge/split, reporting, and authority propagation.

use super::*;

pub(super) fn section_snapshot_from_board(
    board: &BoardData,
    section_id: MessageId,
) -> Result<SectionSnapshotV1, String> {
    let section = board
        .board_state
        .sections
        .section(&section_id)
        .ok_or("the section does not exist")?;
    Ok(SectionSnapshotV1 {
        section: section_id,
        parent: section.parent,
        chain: board.board_state.sections.chain(&section_id),
        allowed_roles: section.allowed_roles.clone(),
        sealed_name: section.sealed_name.clone(),
        hidden: section.hidden,
        images_allowed: section.images_allowed,
        auto_moderated_topics: section.auto_moderated_topics,
        generation: section.generation,
        signed_at: system_time_ms(section.signed_at),
    })
}

/// Move a topic to another section. The owner signs a Move action carrying the
/// new section snapshot on `part == 0` and a board `Section` flag for the index.
pub async fn move_topic(
    owner: VerifyingKey,
    topic_id: MessageId,
    _part: u32,
    section_id: MessageId,
) -> Result<(), String> {
    let board = board_for(owner)?;
    if !board.is_current_owner() {
        return Err("only the board owner can move a topic for now".to_string());
    }
    let conversation = conversation_for(owner, topic_id, 0)?;
    let head = conversation
        .state
        .as_head()
        .ok_or("topic head is not loaded")?;
    let header = head
        .header
        .as_ref()
        .ok_or("the topic is still loading")?;
    let snapshot = section_snapshot_from_board(&board, section_id)?;
    let payload = SealedBytes::public(encode(&snapshot)?);
    let now = system_time_ms(get_current_system_time());
    let owner_key = board.owner_key();
    let signer = MemberId::from(&owner_key.verifying_key());
    let generation = head
        .latest_action(header.header.id(), TopicActionKind::Move)
        .map(|entry| entry.action.generation + 1)
        .unwrap_or(1);
    let action = plaza_topic_core::TopicActionV1 {
        kind: TopicActionKind::Move,
        target: header.header.id(),
        payload,
        generation,
        created_at: now,
        signer,
    };
    let authorized = plaza_topic_core::AuthorizedTopicActionV1 {
        signature: plaza_core::util::sign_struct(&action, owner_key),
        action,
        signer_key: Some(owner_key.verifying_key()),
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
    let base = index.entry(&topic_id).ok_or("the topic is not indexed")?;
    let current_generation = index
        .flag(&topic_id, TopicFlagKind::Section)
        .map(|flag| flag.generation)
        .unwrap_or(0);
    let flag = TopicFlagV1 {
        topic_id,
        kind: TopicFlagKind::Section,
        value: true,
        destination: None,
        section: Some(section_id),
        section_chain: snapshot.chain,
        destination_sections: board
            .board_state
            .sections
            .chain_only(&section_id)
            .sections,
        part: None,
        scope_chain: base.entry.section_chain.clone(),
        generation: current_generation + 1,
        created_at: now,
    };
    let authorized_flag = AuthorizedTopicFlagV1 {
        signature: plaza_core::util::sign_struct(&flag, owner_key),
        flag,
        signer: Some(signer),
        signer_key: Some(owner_key.verifying_key()),
        authority: None,
    };
    let board_delta = ChatBoardStateV1Delta {
        topics: Some(TopicIndexDelta {
            flags: vec![authorized_flag],
            ..Default::default()
        }),
        ..Default::default()
    };
    apply_topic_board_delta(owner, topic_id, board_delta).await
}

/// Merge a topic into another one as a link. Replies stay in the source
/// contract; the Merge action is recorded on `part == 0` and the index marks
/// the source as merged.
pub async fn merge_topic(
    owner: VerifyingKey,
    topic_id: MessageId,
    _part: u32,
    destination: MessageId,
) -> Result<(), String> {
    let board = board_for(owner)?;
    if !board.is_current_owner() {
        return Err("only the board owner can merge topics for now".to_string());
    }
    if topic_id == destination {
        return Err("a topic cannot merge into itself".to_string());
    }
    let index = crate::components::app::section_contract::merged_index(
        owner,
        &board.board_state.topics,
    );
    if index.entry(&destination).is_none() {
        return Err("the destination topic is not indexed".to_string());
    }
    let source_section = index.section_of(&topic_id).0;
    let destination_section = index.section_of(&destination).0;
    let dest_on_page0 = source_section
        .and_then(|section| {
            crate::components::app::section_contract::section_page_state(owner, section, 0)
        })
        .is_some_and(|manifest| manifest.topics.entry(&destination).is_some());
    let (flag_section, flag_section_chain) =
        if source_section != destination_section || !dest_on_page0 {
            let section = destination_section
                .ok_or("a cross-section merge needs a destination section")?;
            let chain = board.board_state.sections.chain(&section);
            (Some(section), chain)
        } else {
            (None, Vec::new())
        };
    let conversation = conversation_for(owner, topic_id, 0)?;
    let head = conversation
        .state
        .as_head()
        .ok_or("topic head is not loaded")?;
    let header = head
        .header
        .as_ref()
        .ok_or("the topic is still loading")?;
    let now = system_time_ms(get_current_system_time());
    let owner_key = board.owner_key();
    let signer = MemberId::from(&owner_key.verifying_key());
    let generation = head
        .latest_action(header.header.id(), TopicActionKind::Merge)
        .map(|entry| entry.action.generation + 1)
        .unwrap_or(1);
    let action = plaza_topic_core::TopicActionV1 {
        kind: TopicActionKind::Merge,
        target: header.header.id(),
        payload: SealedBytes::public(destination.as_bytes().to_vec()),
        generation,
        created_at: now,
        signer,
    };
    let authorized = plaza_topic_core::AuthorizedTopicActionV1 {
        signature: plaza_core::util::sign_struct(&action, owner_key),
        action,
        signer_key: Some(owner_key.verifying_key()),
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

    let base = index.entry(&topic_id).ok_or("the topic is not indexed")?;
    let current_generation = index
        .flag(&topic_id, TopicFlagKind::Merged)
        .map(|flag| flag.generation)
        .unwrap_or(0);
    let flag = TopicFlagV1 {
        topic_id,
        kind: TopicFlagKind::Merged,
        value: true,
        destination: Some(destination),
        section: flag_section,
        section_chain: flag_section_chain,
        destination_sections: flag_section
            .map(|section| {
                board
                    .board_state
                    .sections
                    .chain_only(&section)
                    .sections
            })
            .unwrap_or_default(),
        part: None,
        scope_chain: base.entry.section_chain.clone(),
        generation: current_generation + 1,
        created_at: now,
    };
    let authorized_flag = AuthorizedTopicFlagV1 {
        signature: plaza_core::util::sign_struct(&flag, owner_key),
        flag,
        signer: Some(signer),
        signer_key: Some(owner_key.verifying_key()),
        authority: None,
    };
    let board_delta = ChatBoardStateV1Delta {
        topics: Some(TopicIndexDelta {
            flags: vec![authorized_flag],
            ..Default::default()
        }),
        ..Default::default()
    };
    apply_topic_board_delta(owner, topic_id, board_delta).await
}

/// Split one text reply into a new topic and mark the original reply as moved.
pub async fn split_reply(
    owner: VerifyingKey,
    topic_id: MessageId,
    part: u32,
    reply_id: MessageId,
    title: String,
    section: Option<MessageId>,
) -> Result<MessageId, String> {
    let board = board_for(owner)?;
    if !board.is_current_owner() {
        return Err("only the board owner can split a reply for now".to_string());
    }
    let conversation = conversation_for(owner, topic_id, part)?;
    let post = conversation
        .state
        .posts()
        .get(&reply_id)
        .ok_or("the reply is not in this topic")?;
    let body = match read_post_content(&board, &post.post.content) {
        Some(TopicPostContentV1::Text(text)) => text,
        Some(TopicPostContentV1::Poll(_)) => {
            return Err("splitting a poll is not supported yet".to_string());
        }
        None => return Err("the reply content could not be read".to_string()),
    };
    let new_topic = create_topic(owner, title, body, section).await?;
    let now = system_time_ms(get_current_system_time());
    let owner_key = board.owner_key();
    let signer = MemberId::from(&owner_key.verifying_key());
    let generation = conversation
        .state
        .latest_action(reply_id, TopicActionKind::Split)
        .map(|entry| entry.action.generation + 1)
        .unwrap_or(1);
    let action = plaza_topic_core::TopicActionV1 {
        kind: TopicActionKind::Split,
        target: reply_id,
        payload: SealedBytes::public(new_topic.as_bytes().to_vec()),
        generation,
        created_at: now,
        signer,
    };
    let authorized = plaza_topic_core::AuthorizedTopicActionV1 {
        signature: plaza_core::util::sign_struct(&action, owner_key),
        action,
        signer_key: Some(owner_key.verifying_key()),
        authority: None,
    };
    publish_part_action(&conversation, authorized).await?;
    Ok(new_topic)
}


/// Report a topic or one of its posts. Reports live in the per-board
/// moderation contract, so the moderation queue sees them without rewriting
/// the section page.
pub async fn report_post(
    owner: VerifyingKey,
    topic_id: MessageId,
    post_id: Option<MessageId>,
    reason: ReportReason,
    body: String,
) -> Result<(), String> {
    let board = board_for(owner)?;
    let index = board.clone().with_merged_topics().board_state.topics;
    if index.entry(&topic_id).is_none() {
        return Err("the topic is not indexed".to_string());
    }
    let body = body.trim().to_string();
    if body.len() > 2_000 {
        return Err("the report is too long".to_string());
    }
    let reporter = MemberId::from(&board.self_sk.verifying_key());
    let now = system_time_ms(get_current_system_time());
    let mut recent_reports: Vec<i64> = index
        .reports
        .iter()
        .filter(|entry| entry.report.reporter == reporter)
        .map(|entry| entry.report.created_at)
        .collect();
    recent_reports.push(now);
    if exceeds_window(
        &recent_reports,
        REPORT_RATE_WINDOW_MS,
        MAX_REPORTS_PER_WINDOW,
    ) {
        return Err("too many reports sent in the last hour; wait before sending another".to_string());
    }
    let generation = index
        .reports
        .iter()
        .filter(|entry| {
            entry.report.topic_id == topic_id
                && entry.report.post_id == post_id
                && entry.report.reporter == reporter
        })
        .map(|entry| entry.report.generation + 1)
        .max()
        .unwrap_or(1);
    let section = index.section_of(&topic_id).0;
    let signer_vk = board.self_sk.verifying_key();
    let proof =
        crate::components::app::member_contract::build_member_proof(owner, signer_vk).map(Box::new);
    let report = TopicReportV1 {
        topic_id,
        post_id,
        reporter,
        reason,
        body: seal_text(&board, &body)?,
        created_at: now,
        generation,
    };
    let authorized = AuthorizedTopicReportV1 {
        signature: plaza_core::util::sign_struct(&report, &board.self_sk),
        report,
        signer_key: Some(signer_vk),
        proof,
    };
    crate::components::app::moderation_contract::record_report(owner, section, authorized).await
}


pub async fn resolve_report(
    owner: VerifyingKey,
    topic_id: MessageId,
    post_id: Option<MessageId>,
    reporter: MemberId,
) -> Result<(), String> {
    let board = board_for(owner)?;
    let index = board.clone().with_merged_topics().board_state.topics;
    let report = index
        .reports
        .iter()
        .find(|entry| {
            entry.report.topic_id == topic_id
                && entry.report.post_id == post_id
                && entry.report.reporter == reporter
        })
        .ok_or("the report does not exist")?;
    let _ = report;
    let self_id = MemberId::from(&board.self_sk.verifying_key());
    let owner_id = board.current_owner_id();
    let (topic_section, chain) = index.section_of(&topic_id);
    let section = topic_section;
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
        return Err("only a moderator can resolve a report".to_string());
    };
    let (ownership_transfers, transfer_admins) =
        crate::components::app::member_contract::ownership_proof_for(&board);
    let generation = index
        .report_resolutions
        .iter()
        .filter(|entry| {
            entry.resolution.topic_id == topic_id
                && entry.resolution.post_id == post_id
                && entry.resolution.reporter == reporter
        })
        .map(|entry| entry.resolution.generation + 1)
        .max()
        .unwrap_or(1);
    let resolution = TopicReportResolutionV1 {
        topic_id,
        post_id,
        reporter,
        resolved_by: signer,
        created_at: system_time_ms(get_current_system_time()),
        generation,
    };
    let authorized = AuthorizedTopicReportResolutionV1 {
        signature: plaza_core::util::sign_struct(&resolution, &signer_sk),
        resolution,
        signer_key: Some(signer_sk.verifying_key()),
        authority: authority.clone().map(Box::new),
        ownership_transfers,
        transfer_admins,
    };
    crate::components::app::moderation_contract::record_resolution(owner, section, authorized)
        .await
}

pub fn topic_reports(
    board: &BoardData,
    topic_id: MessageId,
) -> Vec<TopicReportV1> {
    let mut reports: Vec<_> = board
        .board_state
        .topics
        .reports
        .iter()
        .filter(|entry| entry.report.topic_id == topic_id)
        .map(|entry| entry.report.clone())
        .collect();
    reports.sort_by_key(|report| (report.created_at, report.generation));
    reports
}

pub fn report_body(board: &BoardData, report: &TopicReportV1) -> String {
    read_text(board, &report.body).unwrap_or_default()
}

/// Create a new board section. Only the owner can sign the section record.
pub async fn create_section(
    owner: VerifyingKey,
    name: String,
) -> Result<MessageId, String> {
    let board = board_for(owner)?;
    if !board.is_current_owner() {
        return Err("only the board owner can create a section".to_string());
    }
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("the section needs a name".to_string());
    }
    if name.chars().count() > 200 {
        return Err("the section name is too long".to_string());
    }
    let mut id_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut id_bytes);
    let id = MessageId::from_bytes(id_bytes);
    let child_key: Option<ContractKey> =
        Some(crate::components::app::section_contract::section_key(owner, id));
    let now = get_current_system_time();
    let (public_name, sealed_name) = if board.is_private() {
        let (secret, version) = board
            .get_secret()
            .ok_or("the board secret is not available")?;
        let (ciphertext, nonce) =
            encrypt_with_symmetric_key(secret, name.as_bytes(), version);
        (
            "Section".to_string(),
            Some(SealedBytes::private(
                ciphertext,
                nonce,
                version,
                name.len() as u32,
            )),
        )
    } else {
        (name, None)
    };
    let section = SectionV1 {
        id,
        parent: None,
        name: public_name,
        description: None,
        icon: None,
        color: "#6366f1".to_string(),
        allowed_roles: Vec::new(),
        sealed_name,
        hidden: false,
        is_group: false,
        images_allowed: true,
        auto_moderated_topics: None,
        generation: 1,
        deleted: false,
        contract: child_key.map(|key| *key.id()),
        signed_at: now,
    };
    let authorized = AuthorizedSectionV1::new(section, board.owner_key(), None);
    if child_key.is_some() {
        let owner_sk = board.owner_key();
        let page_size = crate::components::app::section_contract::current_topic_page_size();
        let topic_pages =
            plaza_core::board_state::pages::AuthorizedTopicPageListV1::new(
                id,
                Vec::new(),
                page_size,
                owner_sk,
                system_time_ms(now),
            );
        crate::components::app::section_contract::create_section_board(
            owner,
            &authorized,
            &board.board_state,
            Some(topic_pages),
        )
        .await?;
    }
    let delta = ChatBoardStateV1Delta {
        sections: Some(SectionsDelta {
            sections: vec![authorized],
        }),
        ..Default::default()
    };
    apply_board_delta(owner, delta)?;
    let refreshed = board_for(owner)?;
    let sections: Vec<_> = refreshed
        .board_state
        .sections
        .sections
        .iter()
        .filter_map(|entry| entry.section.contract.map(|_| entry.section.id))
        .collect();
    for section in sections {
        let _ = crate::components::app::section_contract::sync_section_authority(
            owner,
            section,
            &refreshed.board_state,
        )
        .await;
    }
    Ok(id)
}


pub(super) fn authority_from_board(
    board: &BoardData,
    is_owner: bool,
    member_ids: &HashSet<MemberId>,
) -> Result<plaza_topic_core::TopicAuthorityV1, String> {
    let now = system_time_ms(get_current_system_time());
    let policy = TopicPolicyV1 {
        read_only: board.board_state.configuration.configuration.read_only,
        approval_required: board
            .board_state
            .configuration
            .configuration
            .approval_required,
        rate_window_ms: board
            .board_state
            .configuration
            .configuration
            .rate_window_ms,
        max_posts_per_window: board
            .board_state
            .configuration
            .configuration
            .max_posts_per_window,
        images_allowed: true,
        auto_moderated_topics: board
            .board_state
            .configuration
            .configuration
            .auto_moderated_topics,
        reactions_enabled: board
            .board_state
            .configuration
            .configuration
            .reactions_enabled,
        max_post_size: board
            .board_state
            .configuration
            .configuration
            .max_message_size,
        generation: 1,
        updated_at: now,
    };
    let (policy, source_configuration) = if is_owner {
        (
            Some(AuthorizedTopicPolicyV1::new(policy, board.owner_key())),
            None,
        )
    } else {
        (None, Some(board.board_state.configuration.clone()))
    };
    let mut merged_board_state = board.board_state.clone();
    let mut merged_members = std::mem::take(&mut merged_board_state.members);
    crate::components::app::member_contract::apply_to_members(
        board.owner_vk,
        &merged_board_state,
        &mut merged_members,
    );
    merged_board_state.members = merged_members;
    let tree = plaza_topic_core::AuthorityTreeV1::from_board(&merged_board_state);
    let content_hash = tree.content_hash();
    let digest = tree.root(0).digest;
    let signed_root = board
        .board_state
        .authority_root
        .0
        .clone()
        .filter(|root| {
            root.root.digest == digest && root.root.content_hash == content_hash
        })
        .or_else(|| {
            board.is_current_owner().then(|| {
                let mut root =
                    tree.root(system_time_ms(get_current_system_time()));
                root.content_hash = content_hash;
                plaza_topic_core::AuthorizedAuthorityRootV1::new(root, board.owner_key())
            })
        });
    // A ban also needs the banner's key to verify its signature. When the
    // banner is not the owner or an admin, include that member's proof too.
    let owner_id = MemberId::from(&board.owner_vk);
    let admin_ids: HashSet<MemberId> = board
        .board_state
        .admin
        .admins
        .iter()
        .map(|admin| admin.admin.member_id)
        .collect();
    let mut ids: HashSet<MemberId> = member_ids.iter().copied().collect();
    loop {
        let mut added = false;
        for ban in &board.board_state.bans.0 {
            if ids.contains(&ban.ban.banned_user)
                && ban.banned_by != owner_id
                && !admin_ids.contains(&ban.banned_by)
                && ids.insert(ban.banned_by)
            {
                added = true;
            }
        }
        for suspension in &board.board_state.suspensions.suspensions {
            if ids.contains(&suspension.suspension.target) {
                if let Some(signer) = suspension.signer {
                    if signer != owner_id
                        && !admin_ids.contains(&signer)
                        && ids.insert(signer)
                    {
                        added = true;
                    }
                }
            }
        }
        if !added {
            break;
        }
    }
    let (root, member_proofs, roles, bans, ban_revocations, suspensions) =
        if let Some(root) = signed_root {
            let proofs = tree.proofs_for(ids.iter());
            // Compact role definitions: include only roles referenced by member
            // proofs, invite tokens of referenced members, active moderation/
            // access-management roles, or any section ACL on the board so large
            // boards with dozens of cosmetic roles do not bloat every topic.
            let mut needed_roles: HashSet<plaza_core::board_state::roles::RoleId> = HashSet::new();
            for proof in &proofs {
                for r in &proof.status.roles {
                    needed_roles.insert(r.role.id);
                }
                for a in &proof.status.assignments {
                    needed_roles.insert(a.assignment.role_id);
                }
            }
            for id in &ids {
                if let Some(member) = merged_board_state
                    .members
                    .members
                    .iter()
                    .find(|m| m.member.id() == *id)
                {
                    if let Some(join_proof) = &member.member.join_proof {
                        if let Some(token) = board
                            .board_state
                            .invites
                            .tokens
                            .iter()
                            .find(|t| t.token.id == join_proof.token_id)
                        {
                            needed_roles.insert(token.token.role_id);
                        }
                    }
                }
            }
            for section in &board.board_state.sections.sections {
                if !section.section.deleted {
                    needed_roles.extend(section.section.allowed_roles.iter().copied());
                }
            }
            let compact_roles = board
                .board_state
                .roles
                .roles
                .iter()
                .filter(|entry| {
                    needed_roles.contains(&entry.role.id)
                        || entry.role.can_delete_posts
                        || entry.role.can_manage_access
                        || entry.role.can_pin_posts
                        || entry.role.can_move_posts
                        || board
                            .board_state
                            .invites
                            .tokens
                            .iter()
                            .any(|t| !t.token.deleted && t.token.role_id == entry.role.id)
                })
                .cloned()
                .collect();
            (
                Some(root),
                proofs,
                plaza_core::board_state::roles::RolesV1 {
                    roles: compact_roles,
                    assignments: Vec::new(),
                },
                Default::default(),
                Default::default(),
                Default::default(),
            )
        } else {
            // No owner-signed root is available yet (legacy board or a member
            // that has not received it). Keep the full lists; the contract
            // still verifies every record.
            (
                None,
                Vec::new(),
                board.board_state.roles.clone(),
                board.board_state.bans.clone(),
                board.board_state.ban_revocations.clone(),
                board.board_state.suspensions.clone(),
            )
        };
    Ok(plaza_topic_core::TopicAuthorityV1 {
        ownership: board.board_state.ownership.clone(),
        admins: board.board_state.admin.clone(),
        roles,
        bans,
        ban_revocations,
        suspensions,
        policy,
        source_configuration,
        root,
        member_proofs,
    })
}

/// Hash of the board authority fields that a topic mirrors. Used to trigger a
/// propagation pass only when bans, roles, admins, ownership or the policy
/// actually changed.
pub fn authority_hash(board: &BoardData) -> i64 {
    let state = &board.board_state;
    let bytes = match encode(&(
        &state.ownership,
        &state.admin,
        &state.roles,
        &state.bans,
        &state.ban_revocations,
        &state.suspensions,
        &state.configuration,
    )) {
        Ok(bytes) => bytes,
        Err(_) => return 0,
    };
    freenet_scaffold::util::fast_hash(&bytes).0
}

pub static PROPAGATED_AUTHORITY: GlobalSignal<HashMap<VerifyingKey, i64>> =
    Global::new(HashMap::new);

/// Returns true when this client has not propagated this authority snapshot
/// yet. The marker is local, so each client does its own pass.
pub fn mark_authority_seen(owner: VerifyingKey, hash: i64) -> bool {
    let mut seen = PROPAGATED_AUTHORITY.write();
    match seen.get(&owner) {
        Some(previous) if *previous == hash => false,
        _ => {
            seen.insert(owner, hash);
            true
        }
    }
}

/// Send the current board authority to one topic when it differs from the
/// topic's merged authority.
pub async fn sync_topic_authority(
    owner: VerifyingKey,
    topic_id: MessageId,
    part: u32,
) -> Result<bool, String> {
    #[cfg(feature = "no-sync")]
    {
        let _ = (owner, topic_id, part);
        return Ok(false);
    }
    #[cfg(not(feature = "no-sync"))]
    {
    let board = board_for(owner)?;
    let conversation = conversation_for(owner, topic_id, part)?;
    if !conversation.state.is_loaded() {
        return Ok(false);
    }
    // Sealed extra pages have stripped authority and never need authority syncs.
    if let TopicPartState::Page(page) = &conversation.state {
        if page.is_sealed() {
            return Ok(false);
        }
    }
    let mut member_ids = HashSet::new();
    match &conversation.state {
        TopicPartState::Head(head) => {
            if let Some(header) = &head.header {
                member_ids.insert(header.header.author);
            }
        }
        TopicPartState::Page(page) => {
            if let Some(header) = &page.header {
                member_ids.insert(header.header.creator);
            }
        }
    }
    for participant in conversation.state.participants() {
        member_ids.insert(participant.record.member_id);
    }
    for action in conversation.state.all_actions() {
        member_ids.insert(action.action.signer);
    }
    for approval in conversation.state.approvals() {
        member_ids.insert(approval.approval.signed_by);
    }
    for trust in conversation.state.trust() {
        member_ids.insert(trust.trust.signed_by);
    }
    let generated =
        authority_from_board(&board, board.is_current_owner(), &member_ids)?;
    let current_authority = conversation.state.authority();
    if current_authority.merged_with(&generated) == *current_authority {
        return Ok(false);
    }
    match &conversation.state {
        TopicPartState::Head(_) => {
            publish_topic_delta(
                *conversation.key.id(),
                TopicDeltaV1 {
                    authority: Some(generated),
                    ..Default::default()
                },
            )
            .await?;
        }
        TopicPartState::Page(_) => {
            publish_topic_page_delta(
                *conversation.key.id(),
                TopicPageDeltaV1 {
                    authority: Some(generated),
                    ..Default::default()
                },
            )
            .await?;
        }
    }
    Ok(true)
    }
}

/// Maximum number of already-loaded cached topic contracts proactively synced
/// when board authority changes. Unloaded topics sync authority lazily when
/// opened (`TopicView`) so bans and role changes stay O(1) instead of fanning
/// out O(N) GET/UPDATEs across the entire board index.
const MAX_PROACTIVE_AUTHORITY_SYNC_TOPICS: usize = 16;

/// Push bans, suspensions, roles, admins, ownership and the policy to the
/// bounded set of unsealed topic parts already cached in memory for `owner`.
/// Topics not currently loaded in `TOPIC_CACHE` sync authority lazily when
/// opened in `TopicView`, avoiding an O(topics) network storm on every ban or
/// role change.
pub async fn propagate_authority(owner: VerifyingKey) -> Result<(), String> {
    let board = board_for(owner)?;
    if !board.board_state.mode.is_topic_index() {
        return Ok(());
    }
    let mut cached_targets: Vec<(i64, MessageId, u32)> = TOPIC_CACHE
        .read()
        .values()
        .filter(|conversation| {
            conversation.params.board_owner == owner
                && conversation.state.is_loaded()
                && !conversation.state.is_sealed()
        })
        .map(|conversation| {
            (
                conversation.last_used,
                MessageId::from_bytes(conversation.params.topic_id),
                conversation.params.part,
            )
        })
        .collect();
    cached_targets.sort_by_key(|(last_used, _, _)| std::cmp::Reverse(*last_used));
    cached_targets.truncate(MAX_PROACTIVE_AUTHORITY_SYNC_TOPICS);
    for (_, topic_id, part) in cached_targets {
        if let Err(error) = sync_topic_authority(owner, topic_id, part).await {
            dioxus::logger::tracing::warn!(
                "authority sync failed for cached topic {} part {}: {}",
                topic_id,
                part,
                error
            );
        }
    }
    Ok(())
}

/// Human-readable section name, decrypting the sealed name on private boards.
pub fn section_name(board: &BoardData, section: &MessageId) -> Option<String> {
    let value = board.board_state.sections.section(section)?;
    if let Some(sealed) = &value.sealed_name {
        read_text(board, sealed)
    } else {
        Some(value.name.clone())
    }
}
