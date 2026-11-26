//! Export and restore the identities and local state this device holds.
//!
//! Board content lives on Freenet, but the signing keys, private-board secrets
//! and local preferences live only in the delegate store. This backup captures
//! them; it does not include the raw image bytes or composer upload queues.

use crate::board_data::Boards;
use crate::components::app::BOARDS;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use dioxus::prelude::ReadableExt;
use ed25519_dalek::VerifyingKey;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use wasm_bindgen::JsCast;
use zeroize::Zeroize;

const BACKUP_MAGIC: &[u8] = b"PLAZABK1";
const MIN_PASSPHRASE: usize = 8;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

#[derive(Serialize, Deserialize)]
pub struct BackupV1 {
    format: u32,
    created_at: i64,
    boards: Boards,
    /// `BoardData.secrets` is skipped by serde, so it travels separately.
    secrets: HashMap<VerifyingKey, HashMap<u32, [u8; 32]>>,
    current_secret_versions: HashMap<VerifyingKey, u32>,
    /// `DmBackupV1` bytes exported by the DM delegate. Optional so format 1
    /// backups still import.
    #[serde(default)]
    dm: Option<Vec<u8>>,
}

pub async fn export_bytes() -> Result<Vec<u8>, String> {
    let dm = match crate::components::app::dm_delegate::send_request(
        plaza_dm_core::delegate::DmDelegateRequestMsg::ExportBackup,
    )
    .await?
    {
        plaza_dm_core::delegate::DmDelegateResponseMsg::Backup { bytes } => Some(bytes),
        plaza_dm_core::delegate::DmDelegateResponseMsg::Error { message } => {
            return Err(format!("Could not export the DM keys: {message}"));
        }
        other => return Err(format!("Unexpected DM backup response: {other:?}")),
    };
    if let Some(bytes) = &dm {
        if let Ok(parsed) = ciborium::from_reader::<plaza_dm_core::delegate::DmBackupV1, _>(
            bytes.as_slice(),
        ) {
            dioxus::logger::tracing::info!(
                "DM backup export: {} identities, {} conversation keys",
                parsed.identities.len(),
                parsed
                    .identities
                    .iter()
                    .map(|identity| identity.keys.len())
                    .sum::<usize>()
            );
        }
    }

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
        format: 2,
        created_at: chrono::Utc::now().timestamp_millis(),
        boards: boards.clone(),
        secrets,
        current_secret_versions,
        dm,
    };
    let mut buffer = Vec::new();
    ciborium::ser::into_writer(&backup, &mut buffer)
        .map_err(|error| format!("Could not build the backup: {error}"))?;
    Ok(buffer)
}

/// Merge a backup into the current store. Boards in the file win; local-only
/// preferences from this device are kept when the file has none.
pub async fn import_bytes(bytes: &[u8], passphrase: &str) -> Result<usize, String> {
    let mut plain = open_backup(bytes, passphrase)?;
    let decoded = ciborium::from_reader::<BackupV1, _>(plain.as_slice())
        .map_err(|error| format!("This is not a FreeTalk Plaza backup: {error}"));
    plain.zeroize();
    let backup = decoded?;
    if backup.format == 0 || backup.format > 2 {
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

    if let Some(dm_bytes) = backup.dm {
        if let Ok(parsed) = ciborium::from_reader::<plaza_dm_core::delegate::DmBackupV1, _>(
            dm_bytes.as_slice(),
        ) {
            dioxus::logger::tracing::info!(
                "DM backup import: {} identities, {} conversation keys",
                parsed.identities.len(),
                parsed
                    .identities
                    .iter()
                    .map(|identity| identity.keys.len())
                    .sum::<usize>()
            );
        }
        match crate::components::app::dm_delegate::send_request(
            plaza_dm_core::delegate::DmDelegateRequestMsg::ImportBackup { bytes: dm_bytes },
        )
        .await?
        {
            plaza_dm_core::delegate::DmDelegateResponseMsg::Ok => {}
            plaza_dm_core::delegate::DmDelegateResponseMsg::Error { message } => {
                return Err(format!(
                    "Boards restored, but the DM backup failed: {message}"
                ));
            }
            other => {
                return Err(format!(
                    "Boards restored, but the DM import returned: {other:?}"
                ));
            }
        }
        let _ = crate::components::app::dm_contract::load_conversations().await;
    }

    Ok(imported)
}

/// Wrap the cleartext CBOR backup. The file starts with `PLAZABK1`, then a
/// 16-byte salt, a 12-byte nonce, and the ChaCha20-Poly1305 ciphertext.
pub fn seal_backup(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>, String> {
    if passphrase.chars().count() < MIN_PASSPHRASE {
        return Err("Use a passphrase of at least 8 characters.".to_string());
    }
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_bytes);
    let mut key = derive_backup_key(passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new((&key).into());
    let encrypted = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|_| "Could not encrypt the backup.".to_string());
    key.zeroize();
    let ciphertext = encrypted?;
    let mut out = Vec::with_capacity(BACKUP_MAGIC.len() + SALT_LEN + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(BACKUP_MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a sealed backup. Only passphrase-encrypted `PLAZABK1` files are
/// accepted.
pub fn open_backup(bytes: &[u8], passphrase: &str) -> Result<Vec<u8>, String> {
    if !bytes.starts_with(BACKUP_MAGIC) {
        return Err("This is not an encrypted FreeTalk Plaza backup.".to_string());
    }
    if bytes.len() < BACKUP_MAGIC.len() + SALT_LEN + NONCE_LEN + 16 {
        return Err("This backup file is incomplete.".to_string());
    }
    if passphrase.chars().count() < MIN_PASSPHRASE {
        return Err("Enter the backup passphrase (at least 8 characters).".to_string());
    }
    let salt_at = BACKUP_MAGIC.len();
    let nonce_at = salt_at + SALT_LEN;
    let body_at = nonce_at + NONCE_LEN;
    let salt: [u8; SALT_LEN] = bytes[salt_at..nonce_at]
        .try_into()
        .map_err(|_| "This backup file is incomplete.".to_string())?;
    let nonce = Nonce::from_slice(&bytes[nonce_at..body_at]);
    let mut key = derive_backup_key(passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new((&key).into());
    let decrypted = cipher
        .decrypt(nonce, &bytes[body_at..])
        .map_err(|_| "Wrong passphrase, or the backup file is damaged.".to_string());
    key.zeroize();
    decrypted
}

fn derive_backup_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let params = Params::new(19_456, 2, 1, Some(32))
        .map_err(|error| format!("Could not prepare the passphrase: {error}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|error| format!("Could not derive the backup key: {error}"))?;
    Ok(key)
}

/// Download the backup through a temporary object URL.
pub async fn download(passphrase: &str) -> Result<(), String> {
    let mut plain = export_bytes().await?;
    let sealed = seal_backup(&plain, passphrase);
    plain.zeroize();
    let bytes = sealed?;
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
    // Revoke the temporary object URL after the browser has started the download
    // so exported private key material does not stay pinned in memory.
    crate::util::safe_spawn_local(async move {
        crate::util::sleep(std::time::Duration::from_secs(5)).await;
        let _ = web_sys::Url::revoke_object_url(&url);
    });
    Ok(())
}

/// File currently chosen in the restore input, without clearing it. The
/// change handler uses this; only the restore action consumes the file.
pub fn peek_selected_file() -> Option<web_sys::File> {
    let document = web_sys::window()?.document()?;
    let input = document
        .get_element_by_id("plaza-backup-file")?
        .dyn_into::<web_sys::HtmlInputElement>()
        .ok()?;
    input.files()?.get(0)
}

/// Clear the restore file input after a completed restore.
pub fn clear_selected_file() {
    let Some(document) = web_sys::window().and_then(|window| window.document()) else {
        return;
    };
    let Some(input) = document
        .get_element_by_id("plaza-backup-file")
        .and_then(|element| element.dyn_into::<web_sys::HtmlInputElement>().ok())
    else {
        return;
    };
    input.set_value("");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_passphrase_round_trips_and_a_wrong_one_fails() {
        let sealed = seal_backup(b"board-keys", "correct horse").unwrap();
        assert!(sealed.starts_with(BACKUP_MAGIC));
        assert_eq!(open_backup(&sealed, "correct horse").unwrap(), b"board-keys");
        assert!(open_backup(&sealed, "wrong passphrase").is_err());
    }

    #[test]
    fn a_short_passphrase_is_rejected() {
        assert!(seal_backup(b"x", "short").is_err());
    }

    #[test]
    fn an_unencrypted_file_is_rejected() {
        assert!(open_backup(b"legacy-cbor", "correct horse").is_err());
    }
}
