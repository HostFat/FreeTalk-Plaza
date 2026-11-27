//! Section-scoped authority pruning and compact-page delta builders.

use super::*;

/// Members whose records a section manifest needs: topic authors, activity
/// signers, flag moderators, reporters, report resolvers, and any ownership
/// transfer targets/voters.
pub(super) fn section_member_ids(state: &ChatBoardStateV1, parent: &ChatBoardStateV1) -> HashSet<MemberId> {
    let mut ids = HashSet::new();
    for entry in &state.topics.entries {
        ids.insert(entry.entry.author);
    }
    for entry in &state.topics.activity {
        if let Some(signer) = entry.signer {
            ids.insert(signer);
        }
    }
    for entry in &state.topics.flags {
        if let Some(signer) = entry.signer {
            ids.insert(signer);
        }
    }
    for entry in &state.topics.reports {
        ids.insert(entry.report.reporter);
    }
    for entry in &state.topics.report_resolutions {
        ids.insert(entry.resolution.resolved_by);
    }
    ids.extend(ownership_referenced_members(&parent.ownership));
    ids
}

pub(super) fn delta_member_ids(delta: &ChatBoardStateV1Delta, owner_id: MemberId) -> HashSet<MemberId> {
    let mut ids = HashSet::new();
    if let Some(topics) = &delta.topics {
        for entry in &topics.entries {
            ids.insert(entry.entry.author);
        }
        for entry in &topics.activity {
            if let Some(signer) = entry.signer {
                ids.insert(signer);
            }
        }
        for entry in &topics.flags {
            if let Some(signer) = entry.signer {
                ids.insert(signer);
            }
        }
        for entry in &topics.reports {
            ids.insert(entry.report.reporter);
        }
        for entry in &topics.report_resolutions {
            ids.insert(entry.resolution.resolved_by);
        }
    }
    ids.remove(&owner_id);
    ids
}

/// Resolve the `AuthorizedMember` records for `ids` plus their invite-chain
/// ancestors from both `parent.members` and loaded `member_contract` shards,
/// skipping any member already in `known`.
pub(super) fn collect_members_with_ancestors(
    owner: VerifyingKey,
    parent: &ChatBoardStateV1,
    ids: &HashSet<MemberId>,
    known: &HashSet<MemberId>,
) -> Vec<AuthorizedMember> {
    let owner_id = MemberId::from(&owner);
    let mut merged = parent.members.clone();
    crate::components::app::member_contract::apply_to_members(owner, parent, &mut merged);
    let by_id: HashMap<MemberId, AuthorizedMember> = merged
        .members
        .into_iter()
        .map(|m| (m.member.id(), m))
        .collect();

    let mut added = Vec::new();
    let mut added_ids: HashSet<MemberId> = HashSet::new();
    let mut stack: Vec<MemberId> = ids.iter().copied().collect();

    while let Some(id) = stack.pop() {
        if id == owner_id || known.contains(&id) || !added_ids.insert(id) {
            continue;
        }
        if let Some(member) = by_id.get(&id) {
            if member.member.join_proof.is_none()
                && member.member.invited_by != owner_id
                && member.member.invited_by != id
            {
                stack.push(member.member.invited_by);
            }
            added.push(member.clone());
        }
        if let Some(entry) = crate::components::app::member_contract::find_member_entry(owner, id) {
            if !by_id.contains_key(&id) {
                added.push(entry.member);
            }
            for ancestor in entry.invite_chain {
                let anc_id = ancestor.member.id();
                if anc_id != owner_id && !known.contains(&anc_id) && added_ids.insert(anc_id) {
                    added.push(ancestor);
                }
            }
        } else if !by_id.contains_key(&id) {
            let local = crate::components::app::BOARDS
                .read()
                .map
                .get(&owner)
                .and_then(|board| {
                    board
                        .self_authorized_member
                        .as_ref()
                        .filter(|member| member.member.id() == id)
                        .map(|member| (member.clone(), board.invite_chain.clone()))
                });
            if let Some((member, chain)) = local {
                added.push(member);
                for ancestor in chain {
                    let anc_id = ancestor.member.id();
                    if anc_id != owner_id && !known.contains(&anc_id) && added_ids.insert(anc_id) {
                        added.push(ancestor);
                    }
                }
            }
        }
    }
    added
}

pub(super) fn relevant_roles(parent: &ChatBoardStateV1, ids: &HashSet<MemberId>) -> RolesDelta {
    let mut roles: Vec<AuthorizedRole> = Vec::new();
    let mut assignments: Vec<AuthorizedRoleAssignment> = Vec::new();
    let mut role_ids = HashSet::new();
    for id in ids {
        for role in parent.roles.active_roles_of(id) {
            role_ids.insert(role.id);
        }
        assignments.extend(
            parent
                .roles
                .assignments
                .iter()
                .filter(|assignment| assignment.assignment.member_id == *id)
                .cloned(),
        );
    }
    for entry in &parent.roles.roles {
        if role_ids.contains(&entry.role.id) {
            roles.push(entry.clone());
        }
    }
    RolesDelta { roles, assignments }
}

/// A token-joined member carries the join proof; the section child checks it
/// against the token record, so the token must travel with the member.
pub(super) fn relevant_invites_for_members(
    owner: VerifyingKey,
    parent: &ChatBoardStateV1,
    known_tokens: &HashSet<[u8; 16]>,
    members: &[AuthorizedMember],
) -> Vec<AuthorizedInviteToken> {
    let mut tokens = Vec::new();
    for member in members {
        let Some(proof) = member.member.join_proof.as_ref() else {
            continue;
        };
        if known_tokens.contains(&proof.token_id) {
            continue;
        }
        let token = parent
            .invites
            .tokens
            .iter()
            .find(|t| t.token.id == proof.token_id)
            .cloned()
            .or_else(|| {
                crate::components::app::member_contract::find_member_entry(owner, member.member.id())
                    .and_then(|entry| entry.invite_token)
            });
        if let Some(token) = token {
            if !tokens
                .iter()
                .any(|existing: &AuthorizedInviteToken| existing.token.id == token.token.id)
            {
                tokens.push(token);
            }
        }
    }
    tokens
}

pub(super) fn relevant_invites(
    owner: VerifyingKey,
    parent: &ChatBoardStateV1,
    child: &ChatBoardStateV1,
    ids: &HashSet<MemberId>,
    extra_members: &[AuthorizedMember],
) -> Vec<AuthorizedInviteToken> {
    let known: HashSet<[u8; 16]> = child
        .invites
        .tokens
        .iter()
        .map(|token| token.token.id)
        .collect();
    let mut candidates: Vec<AuthorizedMember> = parent
        .members
        .members
        .iter()
        .filter(|member| ids.contains(&member.member.id()))
        .cloned()
        .collect();
    candidates.extend(extra_members.iter().cloned());
    relevant_invites_for_members(owner, parent, &known, &candidates)
}

pub(super) fn add_token_roles(
    parent: &ChatBoardStateV1,
    invites: &[AuthorizedInviteToken],
    roles: &mut RolesDelta,
) {
    for token in invites {
        if let Some(role) = parent
            .roles
            .roles
            .iter()
            .find(|role| role.role.id == token.token.role_id)
        {
            if !roles
                .roles
                .iter()
                .any(|existing| existing.role.id == role.role.id)
            {
                roles.roles.push(role.clone());
            }
        }
    }
}

pub(super) fn relevant_bans(parent: &ChatBoardStateV1, ids: &HashSet<MemberId>) -> Vec<AuthorizedUserBan> {
    parent
        .bans
        .0
        .iter()
        .filter(|ban| ids.contains(&ban.ban.banned_user))
        .cloned()
        .collect()
}

pub(super) fn relevant_revocations(
    parent: &ChatBoardStateV1,
    ids: &HashSet<MemberId>,
) -> Vec<AuthorizedBanRevocation> {
    parent
        .ban_revocations
        .revocations
        .iter()
        .filter(|revocation| ids.contains(&revocation.revocation.banned_user))
        .cloned()
        .collect()
}

pub(super) fn relevant_suspensions(
    parent: &ChatBoardStateV1,
    ids: &HashSet<MemberId>,
) -> Vec<AuthorizedSuspension> {
    parent
        .suspensions
        .suspensions
        .iter()
        .filter(|suspension| ids.contains(&suspension.suspension.target))
        .cloned()
        .collect()
}

/// Add the member, role and moderation records that a manifest delta needs to
/// verify its new topic/flag records.
pub(super) fn with_section_records(
    owner: VerifyingKey,
    parent: &ChatBoardStateV1,
    child: &ChatBoardStateV1,
    mut delta: ChatBoardStateV1Delta,
) -> ChatBoardStateV1Delta {
    let owner_id = MemberId::from(&owner);
    let ids = delta_member_ids(&delta, owner_id);
    if ids.is_empty() {
        return delta;
    }
    let known: HashSet<MemberId> = child
        .members
        .members
        .iter()
        .map(|member| member.member.id())
        .collect();
    let added = collect_members_with_ancestors(owner, parent, &ids, &known);
    let invites = relevant_invites(owner, parent, child, &ids, &added);
    if !added.is_empty() {
        delta.members = Some(MembersDelta::new(added));
    }
    let mut roles = relevant_roles(parent, &ids);
    add_token_roles(parent, &invites, &mut roles);
    if !invites.is_empty() {
        delta.invites = Some(InviteTokensDelta { tokens: invites });
    }
    let new_roles: Vec<_> = roles
        .roles
        .into_iter()
        .filter(|role| {
            !child.roles.roles.iter().any(|known| {
                known.role.id == role.role.id
                    && known.role.generation == role.role.generation
                    && known.role.deleted == role.role.deleted
            })
        })
        .collect();
    let new_assignments: Vec<_> = roles
        .assignments
        .into_iter()
        .filter(|assignment| {
            !child.roles.assignments.iter().any(|known| {
                known.assignment.role_id == assignment.assignment.role_id
                    && known.assignment.member_id == assignment.assignment.member_id
                    && known.assignment.generation == assignment.assignment.generation
                    && known.assignment.revoked == assignment.assignment.revoked
            })
        })
        .collect();
    if !new_roles.is_empty() || !new_assignments.is_empty() {
        delta.roles = Some(RolesDelta {
            roles: new_roles,
            assignments: new_assignments,
        });
    }
    let bans: Vec<_> = relevant_bans(parent, &ids)
        .into_iter()
        .filter(|ban| !child.bans.0.iter().any(|known| known.id() == ban.id()))
        .collect();
    if !bans.is_empty() {
        delta.bans = Some(bans);
    }
    let revocations: Vec<_> = relevant_revocations(parent, &ids)
        .into_iter()
        .filter(|revocation| {
            !child
                .ban_revocations
                .revocations
                .iter()
                .any(|known| known.revocation.ban_id == revocation.revocation.ban_id)
        })
        .collect();
    if !revocations.is_empty() {
        delta.ban_revocations = Some(revocations);
    }
    let suspensions: Vec<_> = relevant_suspensions(parent, &ids)
        .into_iter()
        .filter(|suspension| {
            !child.suspensions.suspensions.iter().any(|known| {
                known.suspension.target == suspension.suspension.target
                    && known.suspension.generation == suspension.suspension.generation
            })
        })
        .collect();
    if !suspensions.is_empty() {
        delta.suspensions = Some(SuspensionsDelta { suspensions });
    }
    delta
}

/// Sync parent authority to page 0 (the section manifest) only. Compact extra
/// pages (`page > 0`) do not duplicate board authority and never receive
/// authority syncs.
pub async fn sync_section_authority(
    owner: VerifyingKey,
    section: SectionId,
    parent: &ChatBoardStateV1,
) -> Result<(), String> {
    let loaded = SECTION_BOARDS
        .read()
        .get(section_page_key(owner, section, 0).id())
        .map(|board| board.synced)
        .unwrap_or(false);
    if loaded {
        sync_section_page_authority(owner, section, parent).await?;
    }
    Ok(())
}

pub(super) async fn sync_section_page_authority(
    owner: VerifyingKey,
    section: SectionId,
    parent: &ChatBoardStateV1,
) -> Result<(), String> {
    let key = section_page_key(owner, section, 0);
    let contract_id = *key.id();
    let Some((child, synced, syncing)) = SECTION_BOARDS
        .read()
        .get(&contract_id)
        .and_then(|board| {
            board
                .state
                .as_manifest()
                .map(|manifest| (manifest.clone(), board.synced, board.syncing))
        })
    else {
        return Err("the section board is not loaded".to_string());
    };
    if !synced {
        return Err("the section state has not arrived yet".to_string());
    }
    if syncing {
        return Ok(());
    }
    SECTION_BOARDS.with_mut(|boards| {
        if let Some(board) = boards.get_mut(&contract_id) {
            board.syncing = true;
            board.ready = false;
        }
    });
    let board_params = ChatBoardParametersV1 { owner };
    let ids = section_member_ids(&child, parent);

    // Prepare the update payload in a closure so any error path resets
    // `board.syncing = false` instead of deadlocking future syncs.
    enum PreparedAuthority {
        NoChange,
        State(ChatBoardStateV1, Vec<u8>),
        Delta(ChatBoardStateV1, Vec<u8>),
    }
    let prepared: Result<PreparedAuthority, String> = (|| {
        // Admin and ownership changes are rare and touch the whole chain; keep the
        // full-state path for them, but prune members/roles/bans/suspensions to
        // only the records this manifest and its ownership chain actually need.
        let full_state = parent.admin != child.admin || parent.ownership != child.ownership;
        let mut state = child.clone();
        if full_state {
            state.configuration = parent.configuration.clone();
            state.admin = parent.admin.clone();
            state.ownership = parent.ownership.clone();
            state.sections = parent.sections.chain_only(&section);
            state.authority_root = Default::default();
            let members = collect_members_with_ancestors(owner, parent, &ids, &HashSet::new());
            let invites = relevant_invites_for_members(owner, parent, &HashSet::new(), &members);
            let mut roles = relevant_roles(parent, &ids);
            add_token_roles(parent, &invites, &mut roles);
            state.members = plaza_core::board_state::member::MembersV1 { members };
            state.invites = plaza_core::board_state::invites::InviteTokensV1 { tokens: invites };
            state.roles = plaza_core::board_state::roles::RolesV1 {
                roles: roles.roles,
                assignments: roles.assignments,
            };
            state.bans = plaza_core::board_state::ban::BansV1(relevant_bans(parent, &ids));
            state.ban_revocations = plaza_core::board_state::ban::BanRevocationsV1 {
                revocations: relevant_revocations(parent, &ids),
            };
            state.suspensions = plaza_core::board_state::member_moderation::SuspensionsV1 {
                suspensions: relevant_suspensions(parent, &ids),
            };
            state
                .verify_with_section(&board_params, Some(section))
                .map_err(|error| format!("section authority does not verify: {error}"))?;
            let bytes = to_cbor_vec(&state);
            Ok(PreparedAuthority::State(state, bytes))
        } else {
            let mut delta = ChatBoardStateV1Delta::default();
            if parent.configuration != child.configuration {
                delta.configuration = Some(parent.configuration.clone());
            }
            let wanted_sections = parent.sections.chain_only(&section);
            if wanted_sections != child.sections {
                delta.sections = Some(SectionsDelta {
                    sections: wanted_sections.sections,
                });
            }
            let known: HashSet<MemberId> = child
                .members
                .members
                .iter()
                .map(|member| member.member.id())
                .collect();
            let added = collect_members_with_ancestors(owner, parent, &ids, &known);
            let invites = relevant_invites(owner, parent, &child, &ids, &added);
            if !added.is_empty() {
                delta.members = Some(MembersDelta::new(added));
            }
            let mut roles = relevant_roles(parent, &ids);
            add_token_roles(parent, &invites, &mut roles);
            if !invites.is_empty() {
                delta.invites = Some(InviteTokensDelta { tokens: invites });
            }
            let new_roles: Vec<_> = roles
                .roles
                .into_iter()
                .filter(|role| {
                    !child.roles.roles.iter().any(|known| {
                        known.role.id == role.role.id
                            && known.role.generation == role.role.generation
                            && known.role.deleted == role.role.deleted
                    })
                })
                .collect();
            let new_assignments: Vec<_> = roles
                .assignments
                .into_iter()
                .filter(|assignment| {
                    !child.roles.assignments.iter().any(|known| {
                        known.assignment.role_id == assignment.assignment.role_id
                            && known.assignment.member_id == assignment.assignment.member_id
                            && known.assignment.generation == assignment.assignment.generation
                            && known.assignment.revoked == assignment.assignment.revoked
                    })
                })
                .collect();
            if !new_roles.is_empty() || !new_assignments.is_empty() {
                delta.roles = Some(RolesDelta {
                    roles: new_roles,
                    assignments: new_assignments,
                });
            }
            let bans: Vec<_> = relevant_bans(parent, &ids)
                .into_iter()
                .filter(|ban| !child.bans.0.iter().any(|known| known.id() == ban.id()))
                .collect();
            if !bans.is_empty() {
                delta.bans = Some(bans);
            }
            let revocations: Vec<_> = relevant_revocations(parent, &ids)
                .into_iter()
                .filter(|revocation| {
                    !child
                        .ban_revocations
                        .revocations
                        .iter()
                        .any(|known| known.revocation.ban_id == revocation.revocation.ban_id)
                })
                .collect();
            if !revocations.is_empty() {
                delta.ban_revocations = Some(revocations);
            }
            let suspensions: Vec<_> = relevant_suspensions(parent, &ids)
                .into_iter()
                .filter(|suspension| {
                    !child.suspensions.suspensions.iter().any(|known| {
                        known.suspension.target == suspension.suspension.target
                            && known.suspension.generation == suspension.suspension.generation
                    })
                })
                .collect();
            if !suspensions.is_empty() {
                delta.suspensions = Some(SuspensionsDelta { suspensions });
            }
            let has_changes = delta.configuration.is_some()
                || delta.sections.is_some()
                || delta.members.is_some()
                || delta.invites.is_some()
                || delta.roles.is_some()
                || delta.bans.is_some()
                || delta.ban_revocations.is_some()
                || delta.suspensions.is_some();
            if !has_changes {
                return Ok(PreparedAuthority::NoChange);
            }
            state
                .apply_delta(&child, &board_params, &Some(delta.clone()))
                .map_err(|error| format!("apply section authority: {error}"))?;
            state
                .verify_delta(&delta, &board_params)
                .map_err(|error| format!("section authority does not verify: {error}"))?;
            if state
                .topics
                .entries
                .iter()
                .any(|entry| entry.entry.section != Some(section))
            {
                return Err("section authority put a topic in another section".to_string());
            }
            Ok(PreparedAuthority::Delta(state, to_cbor_vec(&delta)))
        }
    })();

    let (state, data) = match prepared {
        Ok(PreparedAuthority::NoChange) => {
            SECTION_BOARDS.with_mut(|boards| {
                if let Some(board) = boards.get_mut(&contract_id) {
                    board.syncing = false;
                    board.ready = true;
                    board.last_used = now_ms();
                }
            });
            return Ok(());
        }
        Ok(PreparedAuthority::State(state, bytes)) => (state, UpdateData::State(bytes.into())),
        Ok(PreparedAuthority::Delta(state, bytes)) => (state, UpdateData::Delta(bytes.into())),
        Err(error) => {
            SECTION_BOARDS.with_mut(|boards| {
                if let Some(board) = boards.get_mut(&contract_id) {
                    board.syncing = false;
                }
            });
            return Err(error);
        }
    };

    SECTION_BOARDS.with_mut(|boards| {
        if let Some(board) = boards.get_mut(&contract_id) {
            board.state = SectionBoardState::Manifest(state.clone());
            board.synced = true;
            board.ready = false;
            board.dirty = true;
            board.last_used = now_ms();
        }
    });
    schedule_section_save();
    let result = send_client_request(ClientRequest::ContractOp(ContractRequest::Update {
        key,
        data,
    }))
    .await;
    SECTION_BOARDS.with_mut(|boards| {
        if let Some(board) = boards.get_mut(&contract_id) {
            board.syncing = false;
            board.ready = result.is_ok();
            // The UpdateResponse clears this; until then a Get that still has
            // the older authority must not replace the local copy.
            board.dirty = true;
        }
    });
    result.map_err(|error| format!("send section authority: {error}"))
}

/// Build a compact [`SectionPageDeltaV1`] for `page > 0` from topic entries,
/// attaching only the minimal author/invite/role records missing from `page_state`.
pub(super) fn build_compact_page_delta(
    owner: VerifyingKey,
    parent: Option<&ChatBoardStateV1>,
    page_state: &SectionPageStateV1,
    entries: Vec<plaza_core::board_state::topics::AuthorizedTopicEntryV1>,
) -> SectionPageDeltaV1 {
    if page_state.is_sealed() {
        return SectionPageDeltaV1 {
            entry_edits: entries,
            ..Default::default()
        };
    }
    let owner_id = MemberId::from(&owner);
    let mut author_ids: HashSet<MemberId> = entries
        .iter()
        .map(|entry| entry.entry.author)
        .collect();
    author_ids.remove(&owner_id);

    let mut delta = SectionPageDeltaV1 {
        entries,
        ..Default::default()
    };
    let Some(parent) = parent else {
        return delta;
    };
    if author_ids.is_empty() {
        return delta;
    }

    let known_authors: HashSet<MemberId> = page_state
        .authors
        .iter()
        .map(|m| m.member.id())
        .collect();
    let authors = collect_members_with_ancestors(owner, parent, &author_ids, &known_authors);
    let known_tokens: HashSet<[u8; 16]> = page_state.invites.iter().map(|t| t.token.id).collect();
    let invites = relevant_invites_for_members(owner, parent, &known_tokens, &authors);

    let needs_roles = page_state
        .header
        .as_ref()
        .is_some_and(|h| !h.header.allowed_roles.is_empty());
    let mut roles = if needs_roles {
        relevant_roles(parent, &author_ids)
    } else {
        RolesDelta {
            roles: Vec::new(),
            assignments: Vec::new(),
        }
    };
    add_token_roles(parent, &invites, &mut roles);

    let new_roles: Vec<_> = roles
        .roles
        .into_iter()
        .filter(|role| {
            !page_state.roles.iter().any(|known| {
                known.role.id == role.role.id
                    && known.role.generation == role.role.generation
                    && known.role.deleted == role.role.deleted
            })
        })
        .collect();
    let new_assignments: Vec<_> = roles
        .assignments
        .into_iter()
        .filter(|assignment| {
            !page_state.role_assignments.iter().any(|known| {
                known.assignment.role_id == assignment.assignment.role_id
                    && known.assignment.member_id == assignment.assignment.member_id
                    && known.assignment.generation == assignment.assignment.generation
                    && known.assignment.revoked == assignment.assignment.revoked
            })
        })
        .collect();

    // Only include admin records when an invite token or role record was
    // signed by a non-owner admin not already present on the page.
    let mut needed_admin_ids: HashSet<MemberId> = HashSet::new();
    for token in &invites {
        if let Some(signer) = token.signer {
            if signer != owner_id {
                needed_admin_ids.insert(signer);
            }
        }
    }
    for role in &new_roles {
        if let Some(signer) = role.signer {
            if signer != owner_id {
                needed_admin_ids.insert(signer);
            }
        }
    }
    for assignment in &new_assignments {
        if let Some(signer) = assignment.signer {
            if signer != owner_id {
                needed_admin_ids.insert(signer);
            }
        }
    }
    if !needed_admin_ids.is_empty() {
        let missing_admins: Vec<_> = parent
            .admin
            .admins
            .iter()
            .filter(|a| {
                needed_admin_ids.contains(&a.admin.id())
                    && !page_state
                        .admin
                        .admins
                        .iter()
                        .any(|known| known.admin.id() == a.admin.id())
            })
            .cloned()
            .collect();
        if !missing_admins.is_empty() {
            delta.admin = Some(AdminsV1 {
                admins: missing_admins,
                revoked: Vec::new(),
            });
        }
    }

    delta.authors = authors;
    delta.invites = invites;
    delta.roles = new_roles;
    delta.role_assignments = new_assignments;
    delta
}
