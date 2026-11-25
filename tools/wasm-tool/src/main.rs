//! Host-only helper for the delegate registry.
//!
//! The delegate key is `BLAKE3(BLAKE3(wasm) || params)`. `params` is empty for
//! FreeTalk, so the key is `BLAKE3(code_hash_bytes)`. Changing the delegate WASM
//! therefore changes the address the node uses for the user's boards.
//!
//! Subcommands:
//!   hash <file>                 print code_hash and delegate_key
//!   add <version> <description> append the committed WASM to legacy_delegates.toml
//!   check [--ci <base> <head>]  fail when the committed WASM changed without a registry entry
//!
//! Exits non-zero on any error so `cargo make` tasks and CI stop.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const COMMITTED_WASM: &str = "ui/public/contracts/plaza_delegate.wasm";
const REGISTRY: &str = "legacy_delegates.toml";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("hash") => cmd_hash(args.get(1)),
        Some("add") => cmd_add(args.get(1), args.get(2)),
        Some("check") => cmd_check(&args[1..]),
        Some("sync") => cmd_sync(&args[1..]),
        _ => usage(),
    };
    if let Err(e) = code {
        eprintln!("ERROR: {e}");
        std::process::exit(1);
    }
}

fn usage() -> Result<(), String> {
    eprintln!(
        "usage:\n  wasm-tool hash <file>\n  wasm-tool add <version> <description>\n  wasm-tool check [--ci <base> <head>]\n  wasm-tool sync [--changed] [--only <package>...]"
    );
    Err("no subcommand".into())
}

fn repo_root() -> PathBuf {
    // Resolve at runtime from the working directory, so moving or cloning the
    // checkout does not leave a compiled-in path behind.
    if let Ok(cwd) = std::env::current_dir() {
        for dir in cwd.ancestors() {
            if dir.join(REGISTRY).exists() && dir.join("Cargo.toml").exists() {
                return dir.to_path_buf();
            }
        }
    }
    // Fallback: tools/wasm-tool/ -> repo root
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("repo root")
        .to_path_buf()
}

fn hashes(bytes: &[u8]) -> (String, String) {
    let code_hash = blake3::hash(bytes);
    let delegate_key = blake3::hash(code_hash.as_bytes());
    (code_hash.to_hex().to_string(), delegate_key.to_hex().to_string())
}

fn cmd_hash(path: Option<&String>) -> Result<(), String> {
    let path = path.ok_or("hash needs a file path")?;
    let bytes = fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let (code_hash, delegate_key) = hashes(&bytes);
    println!("code_hash:    {code_hash}");
    println!("delegate_key: {delegate_key}");
    Ok(())
}

fn cmd_add(version: Option<&String>, description: Option<&String>) -> Result<(), String> {
    let version = version.ok_or("add needs a version, e.g. V3")?;
    let description = description.ok_or("add needs a description")?;
    let root = repo_root();
    let wasm = root.join(COMMITTED_WASM);
    let bytes = fs::read(&wasm).map_err(|e| {
        format!(
            "cannot read {}: {e}. Run `cargo make sync-wasm` first.",
            wasm.display()
        )
    })?;
    let (code_hash, delegate_key) = hashes(&bytes);
    let registry = root.join(REGISTRY);
    let mut text = fs::read_to_string(&registry).map_err(|e| format!("cannot read {}: {e}", registry.display()))?;

    if text.contains(&code_hash) {
        println!("code_hash {code_hash} is already in {REGISTRY} - nothing to do");
        return Ok(());
    }

    let date = today();
    text.push_str(&format!(
        "\n[[entry]]\nversion = \"{version}\"\ndescription = \"{description}\"\ndate = \"{date}\"\ndelegate_key = \"{delegate_key}\"\ncode_hash = \"{code_hash}\"\n"
    ));
    fs::write(&registry, text).map_err(|e| format!("cannot write {}: {e}", registry.display()))?;
    println!("Added {version} to {REGISTRY}");
    println!("  code_hash:    {code_hash}");
    println!("  delegate_key: {delegate_key}");
    println!("\nNext: rebuild the WASMs, then commit legacy_delegates.toml with them.");
    Ok(())
}

struct WasmTarget {
    package: &'static str,
    wasm_file: &'static str,
    destinations: &'static [&'static str],
    watch_paths: &'static [&'static str],
}

const WASM_TARGETS: &[WasmTarget] = &[
    WasmTarget {
        package: "plaza-contract",
        wasm_file: "plaza_contract.wasm",
        destinations: &[
            "ui/public/contracts/plaza_contract.wasm",
            "cli/contracts/plaza_contract.wasm",
        ],
        watch_paths: &["plaza-contract", "common"],
    },
    WasmTarget {
        package: "plaza-delegate",
        wasm_file: "plaza_delegate.wasm",
        destinations: &["ui/public/contracts/plaza_delegate.wasm"],
        watch_paths: &["plaza-delegate", "common/src/chat_delegate.rs"],
    },
    WasmTarget {
        package: "plaza-dm-delegate",
        wasm_file: "plaza_dm_delegate.wasm",
        destinations: &["ui/public/contracts/plaza_dm_delegate.wasm"],
        watch_paths: &["dm-delegate", "dm-core"],
    },
    WasmTarget {
        package: "plaza-dm-contract",
        wasm_file: "plaza_dm_contract.wasm",
        destinations: &["ui/public/contracts/plaza_dm_contract.wasm"],
        watch_paths: &["dm-contract", "dm-core"],
    },
    WasmTarget {
        package: "plaza-topic-contract",
        wasm_file: "plaza_topic_contract.wasm",
        destinations: &["ui/public/contracts/plaza_topic_contract.wasm"],
        watch_paths: &["topic-contract", "topic-core", "common"],
    },
    WasmTarget {
        package: "plaza-section-contract",
        wasm_file: "plaza_section_contract.wasm",
        destinations: &["ui/public/contracts/plaza_section_contract.wasm"],
        watch_paths: &["section-contract", "common"],
    },
    WasmTarget {
        package: "plaza-activity-contract",
        wasm_file: "plaza_activity_contract.wasm",
        destinations: &["ui/public/contracts/plaza_activity_contract.wasm"],
        watch_paths: &["activity-contract", "common"],
    },
    WasmTarget {
        package: "plaza-moderation-contract",
        wasm_file: "plaza_moderation_contract.wasm",
        destinations: &["ui/public/contracts/plaza_moderation_contract.wasm"],
        watch_paths: &["moderation-contract", "common"],
    },
    WasmTarget {
        package: "plaza-profile-contract",
        wasm_file: "plaza_profile_contract.wasm",
        destinations: &["ui/public/contracts/plaza_profile_contract.wasm"],
        watch_paths: &["profile-contract", "common"],
    },
    WasmTarget {
        package: "plaza-member-contract",
        wasm_file: "plaza_member_contract.wasm",
        destinations: &["ui/public/contracts/plaza_member_contract.wasm"],
        watch_paths: &["member-contract", "common"],
    },
];

fn newest_mtime(path: &Path) -> Option<std::time::SystemTime> {
    let meta = fs::metadata(path).ok()?;
    if meta.is_file() {
        return meta.modified().ok();
    }
    if !meta.is_dir() {
        return None;
    }
    let mut newest: Option<std::time::SystemTime> = None;
    let Ok(entries) = fs::read_dir(path) else {
        return None;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
            if name == "target" {
                continue;
            }
        }
        let mtime = newest_mtime(&p);
        if let Some(t) = mtime {
            if newest.map_or(true, |cur| t > cur) {
                newest = Some(t);
            }
        }
    }
    newest
}

fn target_needs_rebuild(root: &Path, target: &WasmTarget) -> bool {
    let mut oldest_dst: Option<std::time::SystemTime> = None;
    for dst in target.destinations {
        let path = root.join(dst);
        let Ok(meta) = fs::metadata(&path) else {
            return true;
        };
        let Ok(mtime) = meta.modified() else {
            return true;
        };
        if oldest_dst.map_or(true, |cur| mtime < cur) {
            oldest_dst = Some(mtime);
        }
    }
    let Some(oldest_dst) = oldest_dst else {
        return true;
    };
    for extra in ["Cargo.toml", "Cargo.lock"] {
        if let Some(t) = newest_mtime(&root.join(extra)) {
            if t > oldest_dst {
                return true;
            }
        }
    }
    for rel in target.watch_paths {
        if let Some(t) = newest_mtime(&root.join(rel)) {
            if t > oldest_dst {
                return true;
            }
        }
    }
    false
}

fn matches_only_filter(target: &WasmTarget, filter: &str) -> bool {
    let normalized = filter.trim().to_ascii_lowercase();
    let pkg = target.package.to_ascii_lowercase();
    let short = pkg.strip_prefix("plaza-").unwrap_or(&pkg);
    normalized == pkg || normalized == short
}

fn cmd_sync(args: &[String]) -> Result<(), String> {
    let root = repo_root();
    let mut changed_only = false;
    let mut only_filters: Vec<String> = Vec::new();
    let mut idx = 0;
    while idx < args.len() {
        match args[idx].as_str() {
            "--changed" => {
                changed_only = true;
                idx += 1;
            }
            "--only" => {
                idx += 1;
                while idx < args.len() && !args[idx].starts_with("--") {
                    for part in args[idx].split(',') {
                        if !part.trim().is_empty() {
                            only_filters.push(part.trim().to_string());
                        }
                    }
                    idx += 1;
                }
            }
            other => {
                return Err(format!("unknown sync option: {other}"));
            }
        }
    }

    let mut selected: Vec<&WasmTarget> = if only_filters.is_empty() {
        WASM_TARGETS.iter().collect()
    } else {
        for filter in &only_filters {
            if !WASM_TARGETS.iter().any(|t| matches_only_filter(t, filter)) {
                let valid: Vec<&str> = WASM_TARGETS.iter().map(|t| t.package).collect();
                return Err(format!(
                    "unknown package '{filter}' for --only. Valid packages: {}",
                    valid.join(", ")
                ));
            }
        }
        WASM_TARGETS
            .iter()
            .filter(|t| only_filters.iter().any(|f| matches_only_filter(t, f)))
            .collect()
    };

    if changed_only {
        selected.retain(|target| {
            let dirty = target_needs_rebuild(&root, target);
            if !dirty {
                println!("up to date: {} (skipped)", target.package);
            }
            dirty
        });
    }

    if selected.is_empty() {
        println!("All selected contract/delegate WASMs are up to date.");
        return Ok(());
    }

    let mut cargo_args: Vec<&str> = vec![
        "build",
        "--locked",
        "--profile",
        "release",
        "--target",
        "wasm32-unknown-unknown",
    ];
    for target in &selected {
        cargo_args.push("-p");
        cargo_args.push(target.package);
    }

    let status = Command::new("cargo")
        .args(&cargo_args)
        .current_dir(&root)
        .status()
        .map_err(|e| format!("cannot run cargo: {e}"))?;
    if !status.success() {
        return Err("cargo build failed".into());
    }

    let out = root.join("target/wasm32-unknown-unknown/release");
    for target in &selected {
        let src = out.join(target.wasm_file);
        for dst in target.destinations {
            let dst = root.join(dst);
            if let Some(parent) = dst.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
            }
            fs::copy(&src, &dst)
                .map_err(|e| format!("cannot copy {} to {}: {e}", src.display(), dst.display()))?;
            println!("copied {} -> {}", src.display(), dst.display());
        }
    }
    println!("\nVerify with: cargo make check-migration");
    Ok(())
}

fn cmd_check(args: &[String]) -> Result<(), String> {
    let root = repo_root();
    let wasm_path = root.join(COMMITTED_WASM);
    let registry_path = root.join(REGISTRY);
    let registry = fs::read_to_string(&registry_path)
        .map_err(|e| format!("cannot read {}: {e}", registry_path.display()))?;

    if args.first().map(String::as_str) == Some("--ci") {
        let base = args.get(1).ok_or("check --ci needs BASE_SHA")?;
        let head = args.get(2).ok_or("check --ci needs HEAD_SHA")?;
        let base_hash = hash_at_ref(&root, base)?;
        let head_hash = hash_at_ref(&root, head)?;
        let Some(base_hash) = base_hash else {
            println!("committed WASM did not exist at base {base} - no migration needed");
            return Ok(());
        };
        let head_hash =
            head_hash.ok_or_else(|| format!("{COMMITTED_WASM} was deleted at head {head}"))?;
        if base_hash == head_hash {
            println!("committed WASM unchanged - no migration needed");
            return Ok(());
        }
        let head_registry = registry_at_ref(&root, head)?;
        if head_registry.contains(&base_hash) {
            println!("committed WASM changed and the old hash is registered - OK");
            return Ok(());
        }
        return Err(format!(
            "committed WASM changed ({base_hash} -> {head_hash}) but {base_hash} is not in \
             {REGISTRY} on HEAD. Run `cargo make add-migration` and commit the entry."
        ));
    }

    // Local mode: compare the working-tree WASM against HEAD's.
    let working = fs::read(&wasm_path)
        .map_err(|e| format!("cannot read {}: {e}", wasm_path.display()))?;
    let (working_hash, _) = hashes(&working);
    let Some(head_hash) = hash_at_ref(&root, "HEAD")? else {
        println!("committed WASM is not tracked at HEAD - treating as a new baseline");
        return Ok(());
    };
    if working_hash == head_hash {
        println!("committed WASM matches HEAD - no migration needed");
        return Ok(());
    }
    if registry.contains(&head_hash) {
        println!("committed WASM changed and the old hash is registered - OK");
        return Ok(());
    }
    Err(format!(
        "committed WASM changed in the working tree ({head_hash} -> {working_hash}) and \
         {head_hash} is not in {REGISTRY}. Run `cargo make add-migration`."
    ))
}

fn hash_at_ref(root: &Path, git_ref: &str) -> Result<Option<String>, String> {
    let exists = Command::new("git")
        .args(["cat-file", "-e", &format!("{git_ref}:{COMMITTED_WASM}")])
        .current_dir(root)
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| format!("cannot run git: {e}"))?;
    if !exists.success() {
        return Ok(None);
    }
    let out = Command::new("git")
        .args(["show", &format!("{git_ref}:{COMMITTED_WASM}")])
        .current_dir(root)
        .output()
        .map_err(|e| format!("cannot run git show: {e}"))?;
    if !out.status.success() {
        return Err(format!("git show failed for {git_ref}:{COMMITTED_WASM}"));
    }
    Ok(Some(hashes(&out.stdout).0))
}

fn registry_at_ref(root: &Path, git_ref: &str) -> Result<String, String> {
    let out = Command::new("git")
        .args(["show", &format!("{git_ref}:{REGISTRY}")])
        .current_dir(root)
        .output()
        .map_err(|e| format!("cannot run git show: {e}"))?;
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Local date as YYYY-MM-DD, without pulling in chrono.
fn today() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}
