//! Shared upload of one queued image, used by the composer and by the
//! background resume of a post whose images were still uploading.

use crate::board_data::{BoardData, PendingUpload};
use crate::util::images::upload_image;
use plaza_core::board_state::images::ImageRef;

pub async fn upload_pending(
    board: &BoardData,
    record: &PendingUpload,
) -> Result<ImageRef, String> {
    let configuration = &board.board_state.configuration.configuration;
    let limit = if record.animated {
        configuration.animated_image_byte_limit()
    } else {
        configuration.image_byte_limit()
    };
    if record.bytes.len() as u32 > limit {
        return Err(format!(
            "Image is {} KB, the limit is {} KB",
            record.bytes.len() / 1024,
            limit / 1024
        ));
    }

    let (instance, sha256, bytes) = upload_image(
        record.bytes.clone(),
        record.mime.clone(),
        record.width,
        record.height,
        &board.self_sk,
        board.owner_vk,
        board.current_owner_key(),
        record.secret,
    )
    .await?;

    Ok(ImageRef {
        instance,
        sha256,
        mime: record.mime.clone(),
        width: record.width,
        height: record.height,
        bytes,
        alt: record.alt.clone(),
        display: 0,
        sealed: record.secret.is_some(),
        animated: record.animated,
        nsfw: record.nsfw,
    })
}
