//! Board-level image retirement, used by moderators.

use crate::util::message_actions::{apply_state_delta, ActionContext};
use plaza_core::board_state::image_retirements::{
    AuthorizedImageRetirement, ImageRetirementV1, ImageRetirementsDelta,
};
use plaza_core::board_state::member::MemberId;
use plaza_core::board_state::roles::{admin_authority_proof, image_retire_authority_proof};
use plaza_core::board_state::ChatBoardStateV1Delta;

/// Retire an image for the whole board. The record goes to the board state and
/// its hash becomes a denylist entry, so the same file cannot come back under
/// another contract.
pub fn retire_image(
    ctx: &ActionContext,
    instance: [u8; 32],
    sha256: [u8; 32],
    reason: String,
) -> Result<(), String> {
    // The owner signs with the owner key; a moderator signs as its profile
    // member and carries the authority proof.
    let (signing_key, signer) = if ctx.is_current_owner() {
        (ctx.owner_sk.clone(), None)
    } else {
        let id = MemberId::from(&ctx.self_sk.verifying_key());
        (ctx.self_sk.clone(), Some(id))
    };
    let proof = signer.and_then(|self_id| {
        admin_authority_proof(&ctx.board_state, &self_id)
            .or_else(|| image_retire_authority_proof(&ctx.board_state, &self_id))
    });
    let retirement = ImageRetirementV1 {
        instance,
        sha256,
        reason: reason.chars().take(280).collect(),
        created_at: chrono::Utc::now().timestamp_millis(),
    };
    let entry = AuthorizedImageRetirement::new(retirement, &signing_key)
        .with_optional_authority(proof);
    let delta = ChatBoardStateV1Delta {
        image_retirements: Some(ImageRetirementsDelta {
            retirements: vec![entry],
        }),
        ..Default::default()
    };
    apply_state_delta(ctx, delta)
}
