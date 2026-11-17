//! References to images stored in their own contracts.
//!
//! The board state only carries a pointer: the bytes live in a separate
//! contract, downloaded on demand and verified against the hash below.

use serde::{Deserialize, Serialize};

/// Mime types the client can render without plugins.
pub const ALLOWED_IMAGE_MIME_TYPES: [&str; 4] =
    ["image/jpeg", "image/png", "image/webp", "image/gif"];

/// Reference to one image, embedded in a message.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ImageRef {
    /// Instance id of the image contract.
    pub instance: [u8; 32],
    /// SHA-256 of the bytes served by the contract; verified on download.
    pub sha256: [u8; 32],
    pub mime: String,
    pub width: u32,
    pub height: u32,
    /// Size of the image state in bytes, used for the declared limits.
    pub bytes: u32,
    /// Alternative text, required for accessibility.
    pub alt: String,
    /// Width of the rendered image as a percentage of the message width.
    /// Zero means the default.
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub display: u16,
    /// Bytes are sealed with the board or section key.
    #[serde(default, skip_serializing_if = "is_false")]
    pub sealed: bool,
    /// GIF, APNG or animated WebP.
    #[serde(default, skip_serializing_if = "is_false")]
    pub animated: bool,
    /// Needs a click before the image is shown.
    #[serde(default, skip_serializing_if = "is_false")]
    pub nsfw: bool,
}

fn is_zero_u16(value: &u16) -> bool {
    *value == 0
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl ImageRef {
    pub fn validate(&self, max_bytes: u32, max_animated_bytes: u32) -> Result<(), String> {
        if !ALLOWED_IMAGE_MIME_TYPES.contains(&self.mime.as_str()) {
            return Err(format!("Image mime type not allowed: {}", self.mime));
        }
        if self.instance == [0u8; 32] {
            return Err("Image contract id is missing".to_string());
        }
        if self.sha256 == [0u8; 32] {
            return Err("Image hash is missing".to_string());
        }
        let limit = if self.animated {
            max_animated_bytes
        } else {
            max_bytes
        };
        if self.bytes == 0 || self.bytes > limit {
            return Err(format!(
                "Image size {} bytes is outside the allowed range (max {})",
                self.bytes, limit
            ));
        }
        if self.width == 0 || self.height == 0 || self.width > 20_000 || self.height > 20_000 {
            return Err(format!(
                "Image dimensions {}x{} are not valid",
                self.width, self.height
            ));
        }
        if self.alt.trim().is_empty() {
            return Err("Image alternative text is required".to_string());
        }
        if self.alt.len() > 500 {
            return Err("Image alternative text is too long".to_string());
        }
        if self.display != 0 && !(25..=100).contains(&self.display) {
            return Err(format!(
                "Image display width {} is outside 25..100",
                self.display
            ));
        }
        Ok(())
    }
}
