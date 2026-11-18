//! Posts waiting for their images, resumed after a reload.
//!
//! The composer queues one when the user sends during an upload. The background
//! resume finishes the queued uploads, persists the resulting image references
//! after each one, and publishes the message when every attachment is ready.

use crate::board_data::{BoardData, PendingSend};
use crate::components::app::chat_delegate::save_boards_to_delegate;
use crate::components::app::BOARDS;
use crate::util::messaging::{send_message, ReplyContext};
use dioxus::logger::tracing::warn;
use dioxus::prelude::ReadableExt;
use ed25519_dalek::VerifyingKey;
use plaza_core::board_state::privacy::PrivacyMode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use wasm_bindgen_futures::spawn_local;

/// The queue is merged into the board state shortly after load; the resume can
/// start before that. Wait for the record instead of giving up on the first
/// look.
async fn wait_for_upload(board_key: &VerifyingKey, id: &str) -> Option<crate::board_data::PendingUpload> {
    for _ in 0..30 {
        let found = BOARDS
            .read()
            .map
            .get(board_key)
            .and_then(|board| {
                board
                    .pending_uploads
                    .iter()
                    .find(|record| record.id == id)
                    .cloned()
            });
        if found.is_some() {
            return found;
        }
        crate::util::sleep(Duration::from_secs(1)).await;
    }
    None
}

static RESUME_STARTED: AtomicBool = AtomicBool::new(false);

/// Store the intent to publish and persist it. The uploads stay in the regular
/// queue and the draft points at them by id.
pub fn queue(board_key: VerifyingKey, draft: PendingSend) {
    // The uploaded records stay in the regular queue; the draft only points at
    // them, so the delegate does not store the same bytes twice.
    store(board_key, &draft);
}

/// Drop the intent, for example once the post is published.
pub fn clear(board_key: VerifyingKey) {
    BOARDS.with_mut(|boards| {
        if let Some(board) = boards.map.get_mut(&board_key) {
            board.pending_send = None;
        }
    });
    persist();
}

fn store(board_key: VerifyingKey, draft: &PendingSend) {
    BOARDS.with_mut(|boards| {
        if let Some(board) = boards.map.get_mut(&board_key) {
            board.pending_send = Some(draft.clone());
        }
    });
    persist();
}

fn persist() {
    spawn_local(async {
        if let Err(error) = save_boards_to_delegate().await {
            warn!("Could not persist the pending post: {error}");
        }
    });
}

/// Record an attachment that finished uploading while the post waited, so a
/// resume uses it instead of looking for a queue entry that is already gone.
pub fn image_uploaded(
    board_key: VerifyingKey,
    id: &str,
    image: &plaza_core::board_state::images::ImageRef,
) {
    BOARDS.with_mut(|boards| {
        let Some(board) = boards.map.get_mut(&board_key) else {
            return;
        };
        let Some(pending) = board.pending_send.as_mut() else {
            return;
        };
        pending.attachment_ids.retain(|attachment| attachment != id);
        if !pending
            .images
            .iter()
            .any(|existing| existing.instance == image.instance)
        {
            pending.images.push(image.clone());
        }
    });
    persist();
}

/// Finish and publish every queued post. Runs once per page load.
pub fn resume_all() {
    if RESUME_STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    let pending: Vec<(VerifyingKey, BoardData, PendingSend)> = BOARDS
        .read()
        .map
        .iter()
        .filter_map(|(key, board)| {
            board
                .pending_send
                .clone()
                .map(|draft| (*key, board.clone(), draft))
        })
        .collect();
    for (key, board, draft) in pending {
        crate::util::safe_spawn_local(async move {
            resume_one(key, board, draft).await;
        });
    }
}

async fn resume_one(board_key: VerifyingKey, board: BoardData, mut draft: PendingSend) {
    // The queue lives under its own key now; make sure it is in memory before
    // waiting for the ids the draft points at.
    crate::util::pending_uploads::ensure_loaded().await;
    let all_ids = draft.attachment_ids.clone();
    // Upload what is still queued, saving after each success so a second
    // interruption does not lose the images already stored.
    for id in draft.attachment_ids.clone() {
        let Some(record) = wait_for_upload(&board_key, &id).await else {
            // Never publish a post whose image is gone: keep the draft so the
            // author can see it and decide.
            warn!("Pending post: queued image {id} is missing; keeping the draft");
            crate::components::app::toasts::show_error(
                "Queued post: an attached image is missing. The draft is kept.",
            );
            return;
        };
        let image = if let Some(image) = record.image.clone() {
            image
        } else if record.bytes.is_empty() {
            warn!("Pending post: image {id} is still being prepared; keeping the draft");
            return;
        } else {
            match crate::util::uploads::upload_pending(&board, &record, None).await {
                Ok((image, copy)) => {
                    crate::util::pending_uploads::set_image_for(&board_key, &id, &image);
                    if let Some(copy) = copy {
                        crate::util::owned_images::record(&image, copy);
                    }
                    image
                }
                Err(error) => {
                    warn!("Pending post is waiting for an image: {error}");
                    crate::components::app::toasts::show_error(format!(
                        "Queued post: the image upload failed ({error}). It retries on the next reload."
                    ));
                    return;
                }
            }
        };
        draft.attachment_ids.retain(|pending| pending != &id);
        if !draft
            .images
            .iter()
            .any(|existing| existing.instance == image.instance)
        {
            draft.images.push(image);
        }
        store(board_key, &draft);
    }

    let configuration = &board.board_state.configuration.configuration;
    let is_private = configuration.privacy_mode == PrivacyMode::Private;
    let secret_opt = board
        .current_secret()
        .copied()
        .zip(board.current_secret_version);
    let category_secret = draft
        .category_id
        .and_then(|category| {
            board
                .category_secret(&category)
                .map(|(version, key)| (category, key, version))
        })
        .or_else(|| draft.reply_to.and_then(|target| board.posting_secret_for(&target)));
    let reply_ctx = draft.reply_to.map(|message_id| ReplyContext {
        message_id,
        author_name: draft.reply_author.clone().unwrap_or_default(),
        content_preview: draft.reply_preview.clone().unwrap_or_default(),
    });

    match send_message(
        board.owner_vk,
        board.board_key(),
        board.self_sk.clone(),
        board.board_state.clone(),
        is_private,
        secret_opt,
        category_secret,
        draft.category_id,
        draft.title.clone(),
        draft.text.clone(),
        reply_ctx,
        draft.images.clone(),
        None,
    )
    .await
    {
        Ok(()) => {
            for id in all_ids {
                crate::util::pending_uploads::remove_for(&board_key, &id);
            }
            clear(board_key);
            crate::components::app::toasts::show("Queued post published.");
        }
        Err(error) => {
            // Keep the draft: the text and the uploaded images are still here,
            // and the next load tries again.
            warn!("Pending post could not be published: {error}");
            crate::components::app::toasts::show_error(format!(
                "Queued post not published: {error}. The draft is kept."
            ));
        }
    }
}
