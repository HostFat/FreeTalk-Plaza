//! Write the CBOR files needed to publish and retire a blob with `fdev`.
//!
//! Usage: cargo run -p plaza-blob --example make_blob -- <out-dir>
//!
//! The keys are fixed seeds: this is a development helper, not a client.

use ed25519_dalek::SigningKey;
use plaza_blob_core::{sha256, BlobParametersV1, BlobStateV1};
use std::fs;
use std::path::Path;

/// A 1x1 transparent PNG.
const IMAGE: [u8; 67] = [
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
    0x89, 0x00, 0x00, 0x00, 0x0a, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae,
    0x42, 0x60, 0x82,
];

fn write_cbor<T: serde::Serialize>(path: &Path, value: &T) {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes).expect("serializes");
    fs::write(path, bytes).expect("write");
}

fn main() {
    let out = std::env::args().nth(1).expect("out directory");
    let out = Path::new(&out);
    fs::create_dir_all(out).expect("create dir");

    let uploader = SigningKey::from_bytes(&[11u8; 32]);
    let founding = SigningKey::from_bytes(&[12u8; 32]);
    let current = SigningKey::from_bytes(&[13u8; 32]);

    let parameters = BlobParametersV1::new(
        sha256(&IMAGE),
        uploader.verifying_key(),
        founding.verifying_key(),
        current.verifying_key(),
    );
    let state = BlobStateV1::live(
        &parameters,
        "image/png".to_string(),
        1,
        1,
        IMAGE.to_vec(),
    );
    let retired = state
        .retire(&parameters, &uploader)
        .expect("uploader can retire");

    write_cbor(&out.join("params.cbor"), &parameters);
    write_cbor(&out.join("state.cbor"), &state);
    write_cbor(&out.join("retired.cbor"), &retired);
    println!("wrote params.cbor, state.cbor, retired.cbor in {}", out.display());
}
