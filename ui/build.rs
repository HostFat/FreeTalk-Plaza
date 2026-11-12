use chrono::Utc;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // Get the current UTC date and time
    let now = Utc::now();
    // Use ISO 8601 format (UTC) e.g., "2023-10-27T10:30:00Z"
    // This is easily parseable by JavaScript's Date object.
    let build_timestamp_iso = now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    // Set the BUILD_TIMESTAMP_ISO environment variable for the main crate compilation
    println!(
        "cargo:rustc-env=BUILD_TIMESTAMP_ISO={}",
        build_timestamp_iso
    );

    // Get git commit hash (short)
    let git_hash = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=GIT_COMMIT_HASH={}", git_hash);

    generate_legacy_delegates();

    // Note: We intentionally do NOT use cargo:rerun-if-changed here.
    // Without it, Cargo will re-run this build script on every compilation,
    // ensuring the timestamp is always fresh. This is important for development
    // to verify which version of the code is deployed. The registry file is
    // re-read on every run for the same reason.
}

/// Turn `legacy_delegates.toml` into the `LEGACY_DELEGATES` const the UI uses.
///
/// Keeping the registry in one text file means a new delegate generation is a
/// one-line change that both CI (`scripts/check-migration.sh`) and the Wasm
/// build see, instead of hand-copied byte arrays that drift apart.
fn generate_legacy_delegates() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let registry = manifest_dir
        .parent()
        .expect("ui/ must live under the repository root")
        .join("legacy_delegates.toml");

    let text = fs::read_to_string(&registry).unwrap_or_else(|e| {
        panic!(
            "cannot read {}: {e}. The delegate registry is required to avoid \
             orphaning boards written by a previous delegate generation.",
            registry.display()
        )
    });

    let mut entries: Vec<([u8; 32], [u8; 32])> = Vec::new();
    let mut version = String::new();
    let mut delegate_key: Option<[u8; 32]> = None;
    let mut code_hash: Option<[u8; 32]> = None;
    let mut line_no = 0usize;

    for line in text.lines() {
        line_no += 1;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[[entry]]" {
            flush_entry(
                &mut entries,
                &mut version,
                &mut delegate_key,
                &mut code_hash,
            );
            continue;
        }
        if let Some(value) = line.strip_prefix("version = ") {
            version = value.trim().trim_matches('"').to_string();
        } else if let Some(value) = line.strip_prefix("delegate_key = ") {
            delegate_key = Some(parse_hex32(value.trim(), "delegate_key", line_no));
        } else if let Some(value) = line.strip_prefix("code_hash = ") {
            code_hash = Some(parse_hex32(value.trim(), "code_hash", line_no));
        }
    }
    flush_entry(
        &mut entries,
        &mut version,
        &mut delegate_key,
        &mut code_hash,
    );

    let mut out = String::from(
        "// Generated from legacy_delegates.toml by ui/build.rs. Do not edit.\n\
         pub const LEGACY_DELEGATES: &[([u8; 32], [u8; 32])] = &[\n",
    );
    for (key, hash) in &entries {
        out.push_str("    (");
        out.push_str(&format_bytes(key));
        out.push_str(", ");
        out.push_str(&format_bytes(hash));
        out.push_str("),\n");
    }
    out.push_str("];\n");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    fs::write(out_dir.join("legacy_delegates.rs"), out).expect("write legacy_delegates.rs");
}

fn flush_entry(
    entries: &mut Vec<([u8; 32], [u8; 32])>,
    version: &mut String,
    delegate_key: &mut Option<[u8; 32]>,
    code_hash: &mut Option<[u8; 32]>,
) {
    let key = delegate_key.take();
    let hash = code_hash.take();
    match (key, hash) {
        (None, None) => {}
        (Some(key), Some(hash)) => entries.push((key, hash)),
        _ => panic!(
            "legacy_delegates.toml entry {} is missing delegate_key or code_hash",
            version
        ),
    }
    version.clear();
}

fn parse_hex32(value: &str, field: &str, line_no: usize) -> [u8; 32] {    let hex = value.trim_matches('"');
    assert!(
        hex.len() == 64,
        "legacy_delegates.toml line {line_no}: {field} must be 64 hex chars, got {hex:?}"
    );
    let mut bytes = [0u8; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or_else(|_| {
            panic!("legacy_delegates.toml line {line_no}: {field} is not valid hex")
        });
    }
    bytes
}

fn format_bytes(bytes: &[u8; 32]) -> String {
    let mut s = String::from("[");
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            s.push_str(", ");
        }
        s.push_str(&format!("{b}"));
    }
    s.push(']');
    s
}
