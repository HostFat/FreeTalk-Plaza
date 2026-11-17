//! Client-side image preparation: downscale and re-encode in the browser.
//!
//! The conversion to WebP also guarantees that EXIF and the other containers'
//! metadata are gone, which is why it is the default path.

use base64::Engine;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{HtmlCanvasElement, HtmlImageElement};

pub const DEFAULT_MAX_SIDE: u32 = 2048;

#[derive(Clone, Debug)]
pub struct PreparedImage {
    pub bytes: Vec<u8>,
    pub mime: String,
    pub width: u32,
    pub height: u32,
}

/// Decode the file, scale it so its longest side is at most `max_side`, and
/// re-encode as WebP.
pub async fn prepare_image(
    file: &web_sys::File,
    max_side: Option<u32>,
) -> Result<PreparedImage, String> {
    let url = web_sys::Url::create_object_url_with_blob(file).map_err(|e| format!("blob url: {e:?}"))?;
    let result = prepare_from_url(&url, max_side).await;
    let _ = web_sys::Url::revoke_object_url(&url);
    result
}

async fn prepare_from_url(url: &str, max_side: Option<u32>) -> Result<PreparedImage, String> {
    let image = HtmlImageElement::new().map_err(|e| format!("image: {e:?}"))?;
    image.set_src(url);
    JsFuture::from(image.decode())
        .await
        .map_err(|e| format!("decode: {e:?}"))?;

    let (natural_width, natural_height) = (image.natural_width(), image.natural_height());
    if natural_width == 0 || natural_height == 0 {
        return Err("The image has no readable dimensions".to_string());
    }
    let (width, height) = match max_side {
        Some(limit) if natural_width.max(natural_height) > limit => {
            let scale = limit as f64 / natural_width.max(natural_height) as f64;
            (
                ((natural_width as f64 * scale).round() as u32).max(1),
                ((natural_height as f64 * scale).round() as u32).max(1),
            )
        }
        _ => (natural_width, natural_height),
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
    })
}

/// Read the bytes of a file without decoding it, for the "keep original" path.
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
    let url = web_sys::Url::create_object_url_with_blob(file).map_err(|e| format!("blob url: {e:?}"))?;
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
