//! Section page creation, sealing, and on-demand page loading.

use super::*;

/// Resolve the signing key and optional admin proof for creating or sealing a
/// section page: either the current board owner or an active (non-revoked)
/// board admin.
pub(super) fn resolve_section_page_signer(
    parent_state: &ChatBoardStateV1,
    owner_sk: Option<SigningKey>,
    current_owner: VerifyingKey,
    self_sk: SigningKey,
) -> Result<(SigningKey, Option<plaza_core::board_state::roles::AuthorityProof>), String> {
    if let Some(key) = owner_sk.filter(|key| key.verifying_key() == current_owner) {
        return Ok((key, None));
    }
    if self_sk.verifying_key() == current_owner {
        return Ok((self_sk, None));
    }
    let self_id = MemberId::from(&self_sk.verifying_key());
    let active_admin = parent_state
        .admin
        .admins
        .iter()
        .find(|entry| {
            entry.admin.id() == self_id
                && !parent_state.admin.revoked.iter().any(|rev| {
                    rev.id() == self_id && rev.revocation.generation >= entry.admin.generation
                })
        })
        .cloned();
    if let Some(admin_record) = active_admin {
        return Ok((
            self_sk,
            Some(plaza_core::board_state::roles::AuthorityProof {
                admin: Some(admin_record),
                grant: None,
            }),
        ));
    }
    Err("only the board owner or an active admin can add or seal a section page".to_string())
}

/// Seal a full extra page (`page > 0`) as the board owner or an active admin,
/// compacting away all duplicated author/invite/role records.
pub(super) async fn seal_section_page(
    owner: VerifyingKey,
    section: SectionId,
    page: u32,
    signer_sk: &SigningKey,
    authority: Option<plaza_core::board_state::roles::AuthorityProof>,
    parent_admins: &AdminsV1,
) -> Result<(), String> {
    if page == 0 {
        return Ok(());
    }
    let key = section_page_key(owner, section, page);
    let contract_id = *key.id();
    let Some(page_state) = SECTION_BOARDS
        .read()
        .get(&contract_id)
        .and_then(|board| board.state.as_compact_page().cloned())
    else {
        return Ok(());
    };
    if page_state.is_sealed() || page_state.entries.is_empty() {
        return Ok(());
    }
    let params = SectionParametersV1 {
        owner,
        section,
        page,
    };
    let seal = AuthorizedSectionPageSealV1::new_with_authority(
        &params,
        &page_state.entries,
        signer_sk,
        authority.clone(),
        now_ms(),
    )?;
    let delta = SectionPageDeltaV1 {
        admin: authority.is_some().then(|| parent_admins.clone()),
        seal: Some(seal),
        ..Default::default()
    };
    let mut next = page_state;
    next.apply_delta(&params, &delta)?;
    SECTION_BOARDS.with_mut(|boards| {
        if let Some(board) = boards.get_mut(&contract_id) {
            board.state = SectionBoardState::CompactPage(next);
            board.dirty = true;
            board.last_used = now_ms();
        }
    });
    schedule_section_save();
    send_client_request(ClientRequest::ContractOp(ContractRequest::Update {
        key,
        data: UpdateData::Delta(to_cbor_vec(&delta).into()),
    }))
    .await
    .map_err(|error| format!("seal section page {page}: {error}"))
}

/// Create the next compact topic-entry page (`page > 0`) of a section, seal
/// any full unsealed previous extra pages, and add the new page to the
/// manifest's signed page list. Both the current owner and active board admins
/// can add and seal pages.
pub async fn create_section_page(owner: VerifyingKey, section: SectionId) -> Result<u32, String> {
    let parent = {
        let boards = crate::components::app::BOARDS.read();
        boards
            .map
            .get(&owner)
            .map(|board| {
                (
                    board.board_state.clone(),
                    board.owner_sk.clone(),
                    board.current_owner_key(),
                    board.self_sk.clone(),
                )
            })
            .ok_or("the board is not loaded")?
    };
    let (parent_state, owner_sk, current_owner, self_sk) = parent;
    let (signer_sk, authority) =
        resolve_section_page_signer(&parent_state, owner_sk, current_owner, self_sk)?;
    let existing_pages = pages_for(owner, section);
    let page_size = page_size_for(owner, section).unwrap_or_else(current_topic_page_size);

    // Compact any full, unsealed extra pages before spilling to the next page.
    for existing in existing_pages.iter().copied().filter(|p| *p > 0) {
        let should_seal = SECTION_BOARDS
            .read()
            .get(section_page_key(owner, section, existing).id())
            .map(|board| {
                board.synced
                    && !board.state.is_sealed()
                    && board.state.entry_count() >= page_size as usize
            })
            .unwrap_or(false);
        if should_seal {
            if let Err(error) = seal_section_page(
                owner,
                section,
                existing,
                &signer_sk,
                authority.clone(),
                &parent_state.admin,
            )
            .await
            {
                dioxus::logger::tracing::warn!("could not seal section page {existing}: {error}");
            }
        }
    }

    let page = existing_pages.iter().copied().max().unwrap_or(0) + 1;
    let key = section_page_key(owner, section, page);
    let contract_id = *key.id();

    let section_data = parent_state
        .sections
        .section(&section)
        .ok_or("the section does not exist")?;
    let section_chain = parent_state.sections.chain(&section);
    let header = AuthorizedSectionPageHeaderV1::new_with_authority(
        SectionPageHeaderV1 {
            board: owner.to_bytes(),
            section,
            section_chain,
            page,
            page_size,
            allowed_roles: section_data.allowed_roles.clone(),
            created_at: now_ms(),
        },
        &signer_sk,
        authority.clone(),
    );

    let mut compact_page = SectionPageStateV1 {
        header: Some(header),
        ..Default::default()
    };
    if authority.is_some() {
        compact_page.admin = parent_state.admin.clone();
    }
    if !parent_state.ownership.transfers.is_empty() {
        compact_page.ownership = parent_state.ownership.clone();
        compact_page.admin = parent_state.admin.clone();
        let transfer_ids = ownership_referenced_members(&parent_state.ownership);
        let authors =
            collect_members_with_ancestors(owner, &parent_state, &transfer_ids, &HashSet::new());
        let invites =
            relevant_invites_for_members(owner, &parent_state, &HashSet::new(), &authors);
        let mut roles = RolesDelta {
            roles: Vec::new(),
            assignments: Vec::new(),
        };
        add_token_roles(&parent_state, &invites, &mut roles);
        compact_page.authors = authors;
        compact_page.invites = invites;
        compact_page.roles = roles.roles;
        compact_page.sort();
    }

    let params = SectionParametersV1 {
        owner,
        section,
        page,
    };
    compact_page
        .verify(&params)
        .map_err(|error| format!("section page does not verify: {error}"))?;

    let contract = ContractContainer::from(ContractWasmAPIVersion::V1(WrappedContract::new(
        Arc::new(ContractCode::from(SECTION_CONTRACT_WASM)),
        Parameters::from(to_cbor_vec(&params)),
    )));
    let encoded_state = WrappedState::new(to_cbor_vec(&compact_page));
    SECTION_BOARDS.with_mut(|boards| {
        let mut board = SectionBoard::new(
            params.clone(),
            SectionBoardState::CompactPage(compact_page),
            true,
        );
        board.ready = true;
        boards.insert(contract_id, board);
    });
    evict_extra_section_pages(contract_id);
    schedule_section_save();
    send_client_request(ClientRequest::ContractOp(ContractRequest::Put {
        contract,
        state: encoded_state,
        related_contracts: Default::default(),
        subscribe: true,
        blocking_subscribe: false,
    }))
    .await
    .map_err(|error| format!("put section page: {error}"))?;

    // The manifest owns the page list.
    let page0_key = section_page_key(owner, section, 0);
    let page0_id = *page0_key.id();
    if !SECTION_BOARDS
        .read()
        .get(&page0_id)
        .map(|board| board.synced)
        .unwrap_or(false)
    {
        let _ = load_section_page(owner, section, 0).await;
    }
    let mut pages = pages_for(owner, section);
    pages.retain(|existing| *existing > 0);
    pages.push(page);
    let list = AuthorizedTopicPageListV1::new_with_authority(
        section,
        pages,
        page_size,
        &signer_sk,
        authority,
        now_ms(),
    );
    SECTION_BOARDS.with_mut(|boards| {
        if let Some(board) = boards.get_mut(&page0_id) {
            if let SectionBoardState::Manifest(manifest) = &mut board.state {
                manifest.topic_pages.0 = Some(list.clone());
            }
            board.dirty = true;
        }
    });
    schedule_section_save();
    send_client_request(ClientRequest::ContractOp(ContractRequest::Update {
        key: page0_key,
        data: UpdateData::Delta(
            to_cbor_vec(&ChatBoardStateV1Delta {
                topic_pages: Some(list),
                ..Default::default()
            })
            .into(),
        ),
    }))
    .await
    .map_err(|error| format!("add the section page to its manifest: {error}"))?;
    Ok(page)
}

pub async fn ensure_section_page_loaded(
    owner: VerifyingKey,
    section: SectionId,
    page: u32,
) -> Result<(), String> {
    if page == 0 {
        return Ok(());
    }
    let key = section_page_key(owner, section, page);
    let contract_id = *key.id();
    for _ in 0..12 {
        if SECTION_BOARDS
            .read()
            .get(&contract_id)
            .map(|board| board.synced)
            .unwrap_or(false)
        {
            return Ok(());
        }
        let _ = load_section_page(owner, section, page).await;
        for _ in 0..10 {
            crate::util::sleep(std::time::Duration::from_millis(200)).await;
            if SECTION_BOARDS
                .read()
                .get(&contract_id)
                .map(|board| board.synced)
                .unwrap_or(false)
            {
                return Ok(());
            }
        }
    }
    Err("the section page is not loaded yet".to_string())
}

/// Choose the active page with room for another topic without fetching older
/// sealed pages. Checks the newest page first, creating a new page when the
/// current active page is full or sealed.
pub async fn active_page(owner: VerifyingKey, section: SectionId) -> Result<u32, String> {
    ensure_section_loaded(owner, section).await?;
    let limit = page_size_for(owner, section).unwrap_or_else(current_topic_page_size) as usize;
    let pages = pages_for(owner, section);

    // Check the newest page first so a section with many sealed archive pages
    // only touches its active tail page.
    if let Some(&last_page) = pages.last() {
        ensure_section_page_loaded(owner, section, last_page).await?;
        let has_room = SECTION_BOARDS
            .read()
            .get(section_page_key(owner, section, last_page).id())
            .map(|board| !board.state.is_sealed() && board.state.entry_count() < limit)
            .unwrap_or(false);
        if has_room {
            return Ok(last_page);
        }
    }
    create_section_page(owner, section).await
}

/// Fetch and subscribe to the section manifest (page 0). Safe to call on every
/// render.
pub async fn load_section_board(
    owner: VerifyingKey,
    section: SectionId,
) -> Result<ContractInstanceId, String> {
    load_section_page(owner, section, 0).await
}

/// Fetch and subscribe to one topic-entry page of a section.
pub async fn load_section_page(
    owner: VerifyingKey,
    section: SectionId,
    page: u32,
) -> Result<ContractInstanceId, String> {
    let key = section_page_key(owner, section, page);
    let contract_id = *key.id();
    let known = SECTION_BOARDS
        .read()
        .get(&contract_id)
        .map(|board| board.synced)
        .unwrap_or(false);
    if known {
        return Ok(contract_id);
    }
    let pending = SECTION_BOARDS
        .read()
        .get(&contract_id)
        .map(|board| !board.synced && now_ms().saturating_sub(board.last_fetch) < 10_000)
        .unwrap_or(false);
    if pending {
        return Ok(contract_id);
    }
    SECTION_BOARDS.with_mut(|boards| {
        if !boards.contains_key(&contract_id) {
            let empty_state = if page == 0 {
                SectionBoardState::Manifest(ChatBoardStateV1::default())
            } else {
                SectionBoardState::CompactPage(SectionPageStateV1::default())
            };
            boards.insert(
                contract_id,
                SectionBoard::new(
                    SectionParametersV1 {
                        owner,
                        section,
                        page,
                    },
                    empty_state,
                    false,
                ),
            );
        }
        if let Some(board) = boards.get_mut(&contract_id) {
            board.last_used = now_ms();
            board.last_fetch = now_ms();
        }
    });
    if page > 0 {
        evict_extra_section_pages(contract_id);
    }
    send_client_request(ClientRequest::ContractOp(ContractRequest::Get {
        key: contract_id,
        return_contract_code: false,
        subscribe: true,
        blocking_subscribe: false,
    }))
    .await
    .map_err(|error| format!("get section board: {error}"))?;
    Ok(contract_id)
}

/// Load every page listed by the section manifest. Missing pages are fetched
/// with a GET; page 0 is the manifest itself.
pub async fn load_section_pages(owner: VerifyingKey, section: SectionId) -> Result<(), String> {
    load_section_board(owner, section).await?;
    let pages = pages_for(owner, section);
    for page in pages.into_iter().filter(|page| *page > 0) {
        let _ = load_section_page(owner, section, page).await;
    }
    Ok(())
}

/// Drop every extra page from memory and from the delegate blob. Test hook:
/// lets a reload exercise the on-demand page path instead of the persisted
/// cache. Page 0 and the boards themselves are kept.
pub async fn clear_extra_pages() {
    SECTION_BOARDS.with_mut(|boards| {
        boards.retain(|_, board| board.params.page == 0);
    });
    let _ = save_section_boards_now().await;
}

/// Load and wait for every page listed by a section manifest. Views that scan
/// the whole index (search, notifications, moderation) call this explicitly;
/// the board list loads pages on demand.
pub async fn load_all_section_pages(
    owner: VerifyingKey,
    section: SectionId,
) -> Result<(), String> {
    load_section_pages(owner, section).await?;
    for page in pages_for(owner, section)
        .into_iter()
        .filter(|page| *page > 0)
    {
        ensure_section_page_loaded(owner, section, page).await?;
    }
    Ok(())
}

/// Section ids of a loaded board that point to a child contract.
pub(super) fn board_sections(owner: VerifyingKey) -> Vec<SectionId> {
    let boards = crate::components::app::BOARDS.read();
    boards
        .map
        .get(&owner)
        .map(|board| {
            board
                .board_state
                .sections
                .sections
                .iter()
                .filter(|entry| !entry.section.deleted && entry.section.contract.is_some())
                .map(|entry| entry.section.id)
                .collect()
        })
        .unwrap_or_default()
}

/// Load and wait for every page of every section of a board.
pub async fn load_all_section_pages_for_board(owner: VerifyingKey) -> Result<(), String> {
    for section in board_sections(owner) {
        let _ = load_all_section_pages(owner, section).await;
    }
    Ok(())
}

/// True when the manifest lists a page that is not loaded yet.
pub fn has_more_pages(owner: VerifyingKey) -> bool {
    for section in board_sections(owner) {
        for page in pages_for(owner, section)
            .into_iter()
            .filter(|page| *page > 0)
        {
            let loaded = SECTION_BOARDS
                .read()
                .get(section_page_key(owner, section, page).id())
                .map(|board| board.synced)
                .unwrap_or(false);
            if !loaded {
                return true;
            }
        }
    }
    false
}

/// Send a GET for up to `limit` pages that are not loaded yet. The states
/// arrive asynchronously and the list re-renders when they do.
pub async fn load_next_pages(owner: VerifyingKey, limit: usize) -> Result<usize, String> {
    let mut started = 0;
    for section in board_sections(owner) {
        for page in pages_for(owner, section)
            .into_iter()
            .filter(|page| *page > 0)
        {
            if started >= limit {
                return Ok(started);
            }
            let loaded = SECTION_BOARDS
                .read()
                .get(section_page_key(owner, section, page).id())
                .map(|board| board.synced)
                .unwrap_or(false);
            if loaded {
                continue;
            }
            load_section_page(owner, section, page).await?;
            started += 1;
        }
    }
    Ok(started)
}

pub async fn ensure_section_loaded(owner: VerifyingKey, section: SectionId) -> Result<(), String> {
    let key = section_key(owner, section);
    let contract_id = *key.id();
    for _ in 0..12 {
        if SECTION_BOARDS
            .read()
            .get(&contract_id)
            .map(|board| board.ready)
            .unwrap_or(false)
        {
            return Ok(());
        }
        let synced = SECTION_BOARDS
            .read()
            .get(&contract_id)
            .map(|board| board.synced)
            .unwrap_or(false);
        if !synced {
            load_section_board(owner, section).await?;
            for _ in 0..10 {
                crate::util::sleep(std::time::Duration::from_millis(200)).await;
                if SECTION_BOARDS
                    .read()
                    .get(&contract_id)
                    .map(|board| board.synced)
                    .unwrap_or(false)
                {
                    break;
                }
            }
            continue;
        }
        let parent = {
            let boards = crate::components::app::BOARDS.read();
            boards
                .map
                .get(&owner)
                .map(|board| board.board_state.clone())
        };
        let Some(parent) = parent else {
            return Err("the parent board is not loaded".to_string());
        };
        let _ = sync_section_authority(owner, section, &parent).await;
        for _ in 0..10 {
            crate::util::sleep(std::time::Duration::from_millis(200)).await;
            if SECTION_BOARDS
                .read()
                .get(&contract_id)
                .map(|board| board.ready)
                .unwrap_or(false)
            {
                return Ok(());
            }
        }
    }
    Err("the section board is not ready yet".to_string())
}
