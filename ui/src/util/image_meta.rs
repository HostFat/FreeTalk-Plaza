//! Container-level metadata stripping for the formats we accept.
//!
//! Removing EXIF, XMP, IPTC and the PNG text chunks rewrites the container
//! only: the image data is copied untouched, so the quality does not change.

/// Remove metadata without touching the pixels. Returns `None` for formats we
/// do not rewrite (the caller keeps the original bytes).
pub fn strip_metadata(data: &[u8]) -> Option<Vec<u8>> {
    if data.starts_with(&[0xFF, 0xD8]) {
        Some(strip_jpeg(data))
    } else if data.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
        Some(strip_png(data))
    } else if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        Some(strip_webp(data))
    } else {
        None
    }
}

/// JPEG: drop APP1 (EXIF/XMP), APP13 (IPTC) and COM segments. Everything up to
/// the start of scan is parsed; the compressed data is copied verbatim.
fn strip_jpeg(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(&data[0..2]);
    let mut i = 2;
    while i + 1 < data.len() {
        if data[i] != 0xFF {
            // Malformed marker: keep the rest as it is.
            out.extend_from_slice(&data[i..]);
            return out;
        }
        let marker = data[i + 1];
        if marker == 0xD9 {
            out.extend_from_slice(&data[i..]);
            return out;
        }
        if marker == 0xDA {
            // Start of scan: the rest is entropy-coded data.
            out.extend_from_slice(&data[i..]);
            return out;
        }
        if marker == 0x01 || (0xD0..=0xD7).contains(&marker) {
            out.extend_from_slice(&data[i..i + 2]);
            i += 2;
            continue;
        }
        if i + 4 > data.len() {
            out.extend_from_slice(&data[i..]);
            return out;
        }
        let length = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
        let end = (i + 2 + length).min(data.len());
        if !matches!(marker, 0xE1 | 0xED | 0xFE) {
            out.extend_from_slice(&data[i..end]);
        }
        i = end;
    }
    out
}

/// PNG: drop textual and EXIF chunks, keep the image, the palette, the colour
/// profile and the APNG animation chunks.
fn strip_png(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(&data[0..8]);
    let mut i = 8;
    while i + 8 <= data.len() {
        let length = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]) as usize;
        let kind = &data[i + 4..i + 8];
        let end = (i + 12 + length).min(data.len());
        let drop = matches!(kind, b"eXIf" | b"tEXt" | b"zTXt" | b"iTXt" | b"tIME");
        if !drop {
            out.extend_from_slice(&data[i..end]);
        }
        if kind == b"IEND" {
            out.extend_from_slice(&data[end..]);
            return out;
        }
        i = end;
    }
    out.extend_from_slice(&data[i.min(data.len())..]);
    out
}

/// WebP: drop the EXIF and XMP chunks, keep the image, the animation and the
/// colour profile chunks, and fix the RIFF size.
fn strip_webp(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(&data[0..12]);
    let mut i = 12;
    while i + 8 <= data.len() {
        let kind = &data[i..i + 4];
        let size =
            u32::from_le_bytes([data[i + 4], data[i + 5], data[i + 6], data[i + 7]]) as usize;
        let end = (i + 8 + size + (size & 1)).min(data.len());
        if kind != b"EXIF" && kind != b"XMP " {
            out.extend_from_slice(&data[i..end]);
        }
        i = end;
    }
    out.extend_from_slice(&data[i.min(data.len())..]);
    let riff_size = (out.len().saturating_sub(8)) as u32;
    out[4..8].copy_from_slice(&riff_size.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jpeg_with_exif() -> Vec<u8> {
        let mut data = vec![0xFF, 0xD8]; // SOI
        data.extend_from_slice(&[0xFF, 0xE0, 0x00, 0x04, 0x00, 0x00]); // APP0
        data.extend_from_slice(&[0xFF, 0xE1, 0x00, 0x06, 1, 2, 3, 4]); // APP1 EXIF
        data.extend_from_slice(&[0xFF, 0xFE, 0x00, 0x04, 9, 9]); // COM
        data.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x04, 7, 7]); // SOS + header
        data.extend_from_slice(&[1, 2, 3, 4]); // scan data
        data.extend_from_slice(&[0xFF, 0xD9]); // EOI
        data
    }

    #[test]
    fn jpeg_drops_exif_and_comment_but_keeps_the_scan() {
        let stripped = strip_metadata(&jpeg_with_exif()).expect("jpeg");
        assert_eq!(&stripped[0..2], &[0xFF, 0xD8]);
        assert!(!stripped.windows(2).any(|w| w == [0xFF, 0xE1]));
        assert!(!stripped.windows(2).any(|w| w == [0xFF, 0xFE]));
        // APP0, SOS, scan and EOI survive.
        assert!(stripped.windows(2).any(|w| w == [0xFF, 0xE0]));
        assert!(stripped.ends_with(&[
            0xFF, 0xDA, 0x00, 0x04, 7, 7, 1, 2, 3, 4, 0xFF, 0xD9
        ]));
    }

    fn png_chunk(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(kind);
        out.extend_from_slice(payload);
        out.extend_from_slice(&[0, 0, 0, 0]); // CRC placeholder
        out
    }

    #[test]
    fn png_drops_text_chunks_and_keeps_the_animation() {
        let mut data = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        data.extend_from_slice(&png_chunk(b"IHDR", &[1, 2, 3]));
        data.extend_from_slice(&png_chunk(b"tEXt", b"hello"));
        data.extend_from_slice(&png_chunk(b"eXIf", b"exifdata"));
        data.extend_from_slice(&png_chunk(b"acTL", &[1, 0, 0, 0, 2, 0, 0, 0]));
        data.extend_from_slice(&png_chunk(b"IDAT", b"pixels"));
        data.extend_from_slice(&png_chunk(b"IEND", &[]));

        let stripped = strip_metadata(&data).expect("png");
        assert!(!stripped.windows(4).any(|w| w == b"tEXt"));
        assert!(!stripped.windows(4).any(|w| w == b"eXIf"));
        assert!(stripped.windows(4).any(|w| w == b"acTL"));
        assert!(stripped.windows(4).any(|w| w == b"IDAT"));
        assert!(stripped.windows(4).any(|w| w == b"IEND"));
    }

    fn webp_chunk(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(kind);
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload);
        if payload.len() % 2 == 1 {
            out.push(0);
        }
        out
    }

    #[test]
    fn webp_drops_exif_and_xmp() {
        let mut body = Vec::new();
        body.extend_from_slice(&webp_chunk(b"VP8 ", &[1, 2, 3, 4]));
        body.extend_from_slice(&webp_chunk(b"EXIF", b"metadata"));
        body.extend_from_slice(&webp_chunk(b"XMP ", b"xmp"));
        let mut data = Vec::new();
        data.extend_from_slice(b"RIFF");
        data.extend_from_slice(&((body.len() + 4) as u32).to_le_bytes());
        data.extend_from_slice(b"WEBP");
        data.extend_from_slice(&body);

        let stripped = strip_metadata(&data).expect("webp");
        assert!(!stripped.windows(4).any(|w| w == b"EXIF"));
        assert!(!stripped.windows(4).any(|w| w == b"XMP "));
        assert!(stripped.windows(4).any(|w| w == b"VP8 "));
        let declared = u32::from_le_bytes([
            stripped[4],
            stripped[5],
            stripped[6],
            stripped[7],
        ]) as usize;
        assert_eq!(declared, stripped.len() - 8);
    }
}
