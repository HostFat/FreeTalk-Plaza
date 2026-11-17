//! Client-side image preparation: strip metadata, downscale, or keep as is.

use base64::Engine;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{HtmlCanvasElement, HtmlImageElement};

pub const DEFAULT_MAX_SIDE: u32 = 2048;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageMode {
    /// Keep the format and the pixels, drop EXIF/XMP/text chunks.
    StripMetadata,
    /// Re-encode to WebP, longest side 2048 px.
    Webp2048,
    /// Re-encode to WebP, longest side 1280 px.
    Webp1280,
    /// Upload the file untouched, metadata included.
    KeepOriginal,
}

impl ImageMode {
    pub fn label(&self) -> &'static str {
        match self {
            ImageMode::StripMetadata => "Original, metadata removed",
            ImageMode::Webp2048 => "Resize to 2048 px (WebP)",
            ImageMode::Webp1280 => "Resize to 1280 px (WebP)",
            ImageMode::KeepOriginal => "Keep the original (metadata included)",
        }
    }
}

#[derive(Clone, Debug)]
pub struct PreparedImage {
    pub bytes: Vec<u8>,
    pub mime: String,
    pub width: u32,
    pub height: u32,
    pub animated: bool,
}

/// Prepare one file for upload according to the chosen mode.
pub async fn prepare_image(file: &web_sys::File, mode: ImageMode) -> Result<PreparedImage, String> {
    let declared = file.type_();
    let animated_gif = declared == "image/gif";

    if animated_gif || mode == ImageMode::KeepOriginal || mode == ImageMode::StripMetadata {
        let mut bytes = read_file_bytes(file).await?;
        let (width, height) = image_dimensions(file).await?;
        let animated = animated_gif || is_apng(&bytes);
        let mime = if declared.is_empty() {
            guess_mime(&bytes).to_string()
        } else {
            declared
        };
        if mode == ImageMode::StripMetadata {
            if let Some(stripped) = crate::util::image_meta::strip_metadata(&bytes) {
                bytes = stripped;
            }
        }
        return Ok(PreparedImage {
            bytes,
            mime,
            width,
            height,
            animated,
        });
    }

    let max_side = match mode {
        ImageMode::Webp2048 => DEFAULT_MAX_SIDE,
        ImageMode::Webp1280 => 1280,
        _ => DEFAULT_MAX_SIDE,
    };
    reencode_webp(file, max_side).await
}

async fn reencode_webp(file: &web_sys::File, max_side: u32) -> Result<PreparedImage, String> {
    let url = web_sys::Url::create_object_url_with_blob(file)
        .map_err(|e| format!("blob url: {e:?}"))?;
    let result = reencode_from_url(&url, max_side).await;
    let _ = web_sys::Url::revoke_object_url(&url);
    result
}

async fn reencode_from_url(url: &str, max_side: u32) -> Result<PreparedImage, String> {
    let image = HtmlImageElement::new().map_err(|e| format!("image: {e:?}"))?;
    image.set_src(url);
    JsFuture::from(image.decode())
        .await
        .map_err(|e| format!("decode: {e:?}"))?;

    let (natural_width, natural_height) = (image.natural_width(), image.natural_height());
    if natural_width == 0 || natural_height == 0 {
        return Err("The image has no readable dimensions".to_string());
    }
    let (width, height) = if natural_width.max(natural_height) > max_side {
        let scale = max_side as f64 / natural_width.max(natural_height) as f64;
        (
            ((natural_width as f64 * scale).round() as u32).max(1),
            ((natural_height as f64 * scale).round() as u32).max(1),
        )
    } else {
        (natural_width, natural_height)
    };

    let document = web_sys::window()
        .and_then(|window| window.document())
        .ok_or_else(|| "No document available".to_string())?;
    let canvas: HtmlCanvasElement = document
        .create_element("canvas")
        .map_err(|e| format!("canvas: {e:?}"))?
        .dyn_into()
        .map_err(|_| "canvas element".to_string())?;
    canvas.set_width(width);
    canvas.set_height(height);
    let context: web_sys::CanvasRenderingContext2d = canvas
        .get_context("2d")
        .map_err(|e| format!("context: {e:?}"))?
        .ok_or_else(|| "canvas context unavailable".to_string())?
        .dyn_into()
        .map_err(|_| "2d context".to_string())?;
    context
        .draw_image_with_html_image_element_and_dw_and_dh(
            &image,
            0.0,
            0.0,
            width as f64,
            height as f64,
        )
        .map_err(|e| format!("draw: {e:?}"))?;

    let data_url: String = canvas
        .to_data_url_with_type("image/webp")
        .map_err(|e| format!("encode: {e:?}"))?;
    let encoded = data_url
        .split_once(',')
        .map(|(_, payload)| payload)
        .ok_or_else(|| "encode: unexpected data url".to_string())?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| format!("encode: {e}"))?;
    if bytes.is_empty() {
        return Err("The encoded image is empty".to_string());
    }

    Ok(PreparedImage {
        bytes,
        mime: "image/webp".to_string(),
        width,
        height,
        animated: false,
    })
}

/// Read the bytes of a file without decoding it.
pub async fn read_file_bytes(file: &web_sys::File) -> Result<Vec<u8>, String> {
    let buffer = JsFuture::from(file.array_buffer())
        .await
        .map_err(|e| format!("read: {e:?}"))?;
    let array = js_sys::Uint8Array::new(&buffer);
    let mut bytes = vec![0u8; array.length() as usize];
    array.copy_to(&mut bytes);
    Ok(bytes)
}

/// Dimensions of an image file, read by decoding it once.
pub async fn image_dimensions(file: &web_sys::File) -> Result<(u32, u32), String> {
    let url = web_sys::Url::create_object_url_with_blob(file)
        .map_err(|e| format!("blob url: {e:?}"))?;
    let result = async {
        let image = HtmlImageElement::new().map_err(|e| format!("image: {e:?}"))?;
        image.set_src(&url);
        JsFuture::from(image.decode())
            .await
            .map_err(|e| format!("decode: {e:?}"))?;
        Ok((image.natural_width(), image.natural_height()))
    }
    .await;
    let _ = web_sys::Url::revoke_object_url(&url);
    result
}

fn is_apng(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0x89, b'P', b'N', b'G']) && bytes.windows(4).any(|window| window == b"acTL")
}

fn guess_mime(bytes: &[u8]) -> &'static str {
    if bytes.starts_with(&[0xFF, 0xD8]) {
        "image/jpeg"
    } else if bytes.starts_with(&[0x89, b'P', b'N', b'G']) {
        "image/png"
    } else if bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        "image/webp"
    } else if bytes.starts_with(b"GIF") {
        "image/gif"
    } else {
        "application/octet-stream"
    }
}
