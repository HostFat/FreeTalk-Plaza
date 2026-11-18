//! Export and restore the identities and local state this device holds.
//!
//! Board content lives on Freenet, but the signing keys, private-board secrets
//! and local preferences live only in the delegate store. This backup captures
//! them; it does not include the raw image bytes or composer upload queues.

use crate::board_data::Boards;
use crate::components::app::BOARDS;
use dioxus::prelude::ReadableExt;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use wasm_bindgen::JsCast;

#[derive(Serialize, Deserialize)]
pub struct BackupV1 {
    format: u32,
    created_at: i64,
    boards: Boards,
    /// `BoardData.secrets` is skipped by serde, so it travels separately.
    secrets: HashMap<VerifyingKey, HashMap<u32, [u8; 32]>>,
    current_secret_versions: HashMap<VerifyingKey, u32>,
}

pub fn export_bytes() -> Result<Vec<u8>, String> {
    let boards = BOARDS.read();
    let mut secrets = HashMap::new();
    let mut current_secret_versions = HashMap::new();
    for (key, board) in &boards.map {
        if !board.secrets.is_empty() {
            secrets.insert(*key, board.secrets.clone());
        }
        if let Some(version) = board.current_secret_version {
            current_secret_versions.insert(*key, version);
        }
    }
    let backup = BackupV1 {
        format: 1,
        created_at: chrono::Utc::now().timestamp_millis(),
        boards: boards.clone(),
        secrets,
        current_secret_versions,
    };
    let mut buffer = Vec::new();
    ciborium::ser::into_writer(&backup, &mut buffer)
        .map_err(|error| format!("Could not build the backup: {error}"))?;
    Ok(buffer)
}

/// Merge a backup into the current store. Boards in the file win; local-only
/// preferences from this device are kept when the file has none.
pub async fn import_bytes(bytes: &[u8]) -> Result<usize, String> {
    let backup: BackupV1 = ciborium::from_reader(bytes)
        .map_err(|error| format!("This is not a FreeTalk Plaza backup: {error}"))?;
    if backup.format != 1 {
        return Err(format!("Unsupported backup format {}", backup.format));
    }
    dioxus::logger::tracing::info!(
        "Backup decoded: {} boards, boards_loaded={}",
        backup.boards.map.len(),
        *crate::components::app::BOARDS_LOADED.read()
    );

    // The initial delegate load replaces BOARDS when it finishes. Importing
    // before that point would be wiped by the load; wait briefly for it.
    let deadline = crate::util::get_current_system_time() + std::time::Duration::from_secs(3);
    while !*crate::components::app::BOARDS_LOADED.read()
        && crate::util::get_current_system_time() < deadline
    {
        crate::util::sleep(std::time::Duration::from_millis(50)).await;
    }
    let imported_keys: Vec<VerifyingKey> = backup.boards.map.keys().copied().collect();
    let mut imported = 0usize;
    BOARDS.with_mut(|boards| {
        for (key, mut board) in backup.boards.map {
            if let Some(versions) = backup.secrets.get(&key) {
                board.secrets = versions.clone();
            }
            if let Some(version) = backup.current_secret_versions.get(&key) {
                board.current_secret_version = Some(*version);
            }
            boards.map.insert(key, board);
            imported += 1;
        }
        // An imported board must not stay tombstoned from an earlier removal:
        // the next load would drop the copy the backup just restored.
        boards.removed.retain(|key| !imported_keys.contains(key));
        boards.auto_renew_images = backup.boards.auto_renew_images;
        boards.last_auto_renew_at = backup.boards.last_auto_renew_at;
        for hash in backup.boards.blocked_image_hashes {
            if !boards.blocked_image_hashes.contains(&hash) {
                boards.blocked_image_hashes.push(hash);
            }
        }
        if backup.boards.current_board_key.is_some() {
            boards.current_board_key = backup.boards.current_board_key;
        }
    });
    if imported > 0 {
        // The store is no longer empty; an empty-map guard must not block this
        // save if a concurrent load produced no boards.
        *crate::components::app::DELEGATE_HAD_BOARDS.write() = true;
    }
    dioxus::logger::tracing::info!("Backup imported {imported} boards; saving");
    let save_result = crate::components::app::chat_delegate::save_boards_direct().await;
    save_result?;
    let persisted =
        crate::components::app::chat_delegate::stored_boards_contain(&imported_keys).await?;
    if !persisted {
        return Err(
            "The backup was written but the delegate does not contain every board".to_string(),
        );
    }
    dioxus::logger::tracing::info!(
        "Backup saved; BOARDS has {} boards",
        BOARDS.read().map.len()
    );
    Ok(imported)
}

/// Download the backup through a temporary object URL.
pub fn download() -> Result<(), String> {
    let bytes = export_bytes()?;
    let parts = js_sys::Array::new();
    parts.push(&js_sys::Uint8Array::from(bytes.as_slice()));
    let blob = web_sys::Blob::new_with_u8_array_sequence(&parts)
        .map_err(|error| format!("Could not create the backup file: {error:?}"))?;
    let url = web_sys::Url::create_object_url_with_blob(&blob)
        .map_err(|error| format!("Could not create the download link: {error:?}"))?;
    let document = web_sys::window()
        .and_then(|window| window.document())
        .ok_or("No browser document")?;
    let anchor = document
        .create_element("a")
        .map_err(|error| format!("Could not create the link: {error:?}"))?;
    let date = chrono::Utc::now().format("%Y%m%d-%H%M");
    anchor.set_attribute("href", &url).ok();
    anchor
        .set_attribute("download", &format!("plaza-backup-{date}.cbor"))
        .ok();
    // Some browsers only start a download for an anchor attached to the page.
    if let Some(body) = document.body() {
        let _ = body.append_child(&anchor);
    }
    if let Ok(html) = anchor.clone().dyn_into::<web_sys::HtmlElement>() {
        html.click();
    }
    anchor.remove();
    Ok(())
}

/// File chosen in the restore input, clearing it for the next attempt.
pub fn selected_file() -> Option<web_sys::File> {
    let document = web_sys::window()?.document()?;
    let input = document
        .get_element_by_id("plaza-backup-file")?
        .dyn_into::<web_sys::HtmlInputElement>()
        .ok()?;
    let files = input.files()?;
    let file = files.get(0);
    input.set_value("");
    file
}
