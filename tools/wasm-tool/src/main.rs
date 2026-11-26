//! Host-only helper for the delegate registry.
//!
//! The delegate key is `BLAKE3(BLAKE3(wasm) || params)`. `params` is empty for
//! FreeTalk, so the key is `BLAKE3(code_hash_bytes)`. Changing the delegate WASM
//! therefore changes the address the node uses for the user's boards.
//!
//! Subcommands:
//!   hash <file>                        print code_hash and delegate_key
//!   add [--dm] <version> <description> append the committed delegate WASM to its registry
//!   check [--ci <base> <head>]         fail when a committed delegate WASM changed without a registry entry
//!   sync [--changed] [--only <pkg>...] build WASMs reproducibly and copy to committed paths
//!
//! Exits non-zero on any error so `cargo make` tasks and CI stop.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const COMMITTED_WASM: &str = "ui/public/contracts/plaza_delegate.wasm";
const REGISTRY: &str = "legacy_delegates.toml";
const COMMITTED_DM_WASM: &str = "ui/public/contracts/plaza_dm_delegate.wasm";
const DM_REGISTRY: &str = "legacy_dm_delegates.toml";

/// Binaryen `wasm-opt` major version pinned to match `flake.lock`.
/// A different binaryen version changes output bytes and re-keys every WASM.
const EXPECTED_WASM_OPT_VERSION: &str = "125";

/// Each delegate whose key must survive a rebuild has its own registry.
/// The board delegate and the DM delegate are checked the same way.
const TRACKED_DELEGATES: &[(&str, &str)] = &[
    (COMMITTED_WASM, REGISTRY),
    (COMMITTED_DM_WASM, DM_REGISTRY),
];

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("hash") => cmd_hash(args.get(1)),
        Some("add") => cmd_add(&args[1..]),
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
        "usage:\n  wasm-tool hash <file>\n  wasm-tool add [--dm] <version> <description>\n  wasm-tool check [--ci <base> <head>]\n  wasm-tool sync [--changed] [--only <package>...]"
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

fn escape_toml_string(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

fn registry_contains_code_hash(registry: &str, hash: &str) -> bool {
    let expected = format!("\"{hash}\"");
    registry.lines().any(|line| {
        let trimmed = line.trim();
        trimmed
            .strip_prefix("code_hash")
            .and_then(|rest| rest.trim_start().strip_prefix('='))
            .map(|val| val.trim() == expected)
            .unwrap_or(false)
    })
}

fn parse_add_args<'a>(args: &'a [String]) -> Result<(bool, &'a str, &'a str), String> {
    let (is_dm, rest) = match args.first().map(String::as_str) {
        Some("--dm") => (true, &args[1..]),
        _ => (false, args),
    };
    let version = rest.first().map(String::as_str).ok_or("add needs a version, e.g. V2")?;
    let description = rest.get(1).map(String::as_str).ok_or("add needs a description")?;
    Ok((is_dm, version, description))
}

fn cmd_add(args: &[String]) -> Result<(), String> {
    let (is_dm, version, description) = parse_add_args(args)?;
    let (wasm_rel, registry_rel) = if is_dm {
        (COMMITTED_DM_WASM, DM_REGISTRY)
    } else {
        (COMMITTED_WASM, REGISTRY)
    };
    let root = repo_root();
    let wasm = root.join(wasm_rel);
    let bytes = fs::read(&wasm).map_err(|e| {
        format!(
            "cannot read {}: {e}. Run `cargo make sync-wasm` first.",
            wasm.display()
        )
    })?;
    let (code_hash, delegate_key) = hashes(&bytes);
    let registry = root.join(registry_rel);
    let mut text = fs::read_to_string(&registry).map_err(|e| format!("cannot read {}: {e}", registry.display()))?;

    if registry_contains_code_hash(&text, &code_hash) {
        println!("code_hash {code_hash} is already in {registry_rel} - nothing to do");
        return Ok(());
    }

    let date = today();
    let escaped_version = escape_toml_string(version);
    let escaped_description = escape_toml_string(description);
    text.push_str(&format!(
        "\n[[entry]]\nversion = \"{escaped_version}\"\ndescription = \"{escaped_description}\"\ndate = \"{date}\"\ndelegate_key = \"{delegate_key}\"\ncode_hash = \"{code_hash}\"\n"
    ));
    fs::write(&registry, text).map_err(|e| format!("cannot write {}: {e}", registry.display()))?;
    println!("Added {version} to {registry_rel}");
    println!("  code_hash:    {code_hash}");
    println!("  delegate_key: {delegate_key}");
    println!("\nNext: rebuild the WASMs, then commit {registry_rel} with them.");
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
        destinations: &["ui/public/contracts/plaza_contract.wasm"],
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
    WasmTarget {
        package: "plaza-blob",
        wasm_file: "plaza_blob.wasm",
        destinations: &["ui/public/contracts/blob_contract.wasm"],
        watch_paths: &["plaza-blob", "plaza-blob-core"],
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

    verify_wasm_opt_version()?;

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

    // One lockfile is shared with the UI on purpose for now. Builds stay
    // `--locked`. Path remapping via CARGO_ENCODED_RUSTFLAGS (which handles
    // paths with spaces cleanly) keeps two machines on the same bytes.
    let encoded_rustflags = encoded_remap_rustflags(&root);
    println!(
        "CARGO_ENCODED_RUSTFLAGS: {}",
        encoded_rustflags.replace('\x1f', " ")
    );

    let status = Command::new("cargo")
        .args(&cargo_args)
        .current_dir(&root)
        .env_remove("RUSTFLAGS")
        .env("CARGO_ENCODED_RUSTFLAGS", &encoded_rustflags)
        .status()
        .map_err(|e| format!("cannot run cargo: {e}"))?;
    if !status.success() {
        return Err("cargo build failed".into());
    }

    let out = root.join("target/wasm32-unknown-unknown/release");
    let probes = path_probes(&root);
    for target in &selected {
        let src = out.join(target.wasm_file);
        optimize_wasm(&src)?;
        refuse_machine_paths(&src, &probes)?;
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
    for (wasm, registry) in TRACKED_DELEGATES {
        check_one(&root, wasm, registry, args)?;
    }
    Ok(())
}

fn check_one(root: &Path, wasm: &str, registry_rel: &str, args: &[String]) -> Result<(), String> {
    let wasm_path = root.join(wasm);
    let registry_path = root.join(registry_rel);
    let registry = fs::read_to_string(&registry_path)
        .map_err(|e| format!("cannot read {}: {e}", registry_path.display()))?;

    if args.first().map(String::as_str) == Some("--ci") {
        let base = args.get(1).ok_or("check --ci needs BASE_SHA")?;
        let head = args.get(2).ok_or("check --ci needs HEAD_SHA")?;
        let base_hash = hash_at_ref(root, base, wasm)?;
        let head_hash = hash_at_ref(root, head, wasm)?;
        let Some(base_hash) = base_hash else {
            println!("{wasm} did not exist at base {base} - no migration needed");
            return Ok(());
        };
        let head_hash = head_hash.ok_or_else(|| format!("{wasm} was deleted at head {head}"))?;
        if base_hash == head_hash {
            println!("{wasm} unchanged - no migration needed");
            return Ok(());
        }
        let head_registry = file_at_ref(root, head, registry_rel)?;
        if registry_contains_code_hash(&head_registry, &base_hash) {
            println!("{wasm} changed and the old hash is registered - OK");
            return Ok(());
        }
        return Err(format!(
            "{wasm} changed ({base_hash} -> {head_hash}) but {base_hash} is not in \
             {registry_rel} on HEAD. Record the outgoing code_hash before replacing the WASM."
        ));
    }

    let working = fs::read(&wasm_path)
        .map_err(|e| format!("cannot read {}: {e}", wasm_path.display()))?;
    let (working_hash, _) = hashes(&working);
    let Some(head_hash) = hash_at_ref(root, "HEAD", wasm)? else {
        println!("{wasm} is not tracked at HEAD - treating as a new baseline");
        return Ok(());
    };
    if working_hash == head_hash {
        println!("{wasm} matches HEAD - no migration needed");
        return Ok(());
    }
    if registry_contains_code_hash(&registry, &head_hash) {
        println!("{wasm} changed and the old hash is registered - OK");
        return Ok(());
    }
    Err(format!(
        "{wasm} changed in the working tree ({head_hash} -> {working_hash}) and \
         {head_hash} is not in {registry_rel}. Record the outgoing code_hash first."
    ))
}

fn hash_at_ref(root: &Path, git_ref: &str, wasm: &str) -> Result<Option<String>, String> {
    let exists = Command::new("git")
        .args(["cat-file", "-e", &format!("{git_ref}:{wasm}")])
        .current_dir(root)
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| format!("cannot run git: {e}"))?;
    if !exists.success() {
        return Ok(None);
    }
    let out = Command::new("git")
        .args(["show", &format!("{git_ref}:{wasm}")])
        .current_dir(root)
        .output()
        .map_err(|e| format!("cannot run git show: {e}"))?;
    if !out.status.success() {
        return Err(format!("git show failed for {git_ref}:{wasm}"));
    }
    Ok(Some(hashes(&out.stdout).0))
}

fn file_at_ref(root: &Path, git_ref: &str, path: &str) -> Result<String, String> {
    let out = Command::new("git")
        .args(["show", &format!("{git_ref}:{path}")])
        .current_dir(root)
        .output()
        .map_err(|e| format!("cannot run git show: {e}"))?;
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// `--remap-path-prefix` for the roots that otherwise land in panic locations
/// and make the WASM depend on the machine that built it. Uses Cargo's
/// `\x1f`-delimited `CARGO_ENCODED_RUSTFLAGS` so paths with spaces work.
fn encoded_remap_rustflags(root: &Path) -> String {
    let mut flags: Vec<String> = if let Ok(existing) = std::env::var("CARGO_ENCODED_RUSTFLAGS") {
        existing
            .split('\x1f')
            .filter(|part| !part.is_empty())
            .map(ToOwned::to_owned)
            .collect()
    } else if let Ok(existing) = std::env::var("RUSTFLAGS") {
        existing
            .split_whitespace()
            .map(ToOwned::to_owned)
            .collect()
    } else {
        Vec::new()
    };

    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_default();
    let cargo = std::env::var("CARGO_HOME").unwrap_or_else(|_| format!("{home}/.cargo"));
    let rustup = std::env::var("RUSTUP_HOME").unwrap_or_else(|_| format!("{home}/.rustup"));
    let sysroot = rustc_sysroot().unwrap_or_default();
    let repo = root.display().to_string();

    for (prefix, name) in [
        (cargo, "/cargo"),
        (rustup, "/rustup"),
        (sysroot, "/rustup"),
        (repo, "/build"),
    ] {
        push_remap(&mut flags, &prefix, name);
    }
    flags.join("\x1f")
}

fn rustc_sysroot() -> Option<String> {
    let out = Command::new("rustc").args(["--print", "sysroot"]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!s.is_empty()).then_some(s)
}

fn push_remap(flags: &mut Vec<String>, prefix: &str, name: &str) {
    if prefix.is_empty() {
        return;
    }
    let flag = format!("--remap-path-prefix={prefix}={name}");
    if !flags.contains(&flag) {
        flags.push(flag);
    }
    let forward = prefix.replace('\\', "/");
    if forward != prefix {
        let forward_flag = format!("--remap-path-prefix={forward}={name}");
        if !flags.contains(&forward_flag) {
            flags.push(forward_flag);
        }
    }
    let back = prefix.replace('/', "\\");
    if back != prefix && back != forward {
        let back_flag = format!("--remap-path-prefix={back}={name}");
        if !flags.contains(&back_flag) {
            flags.push(back_flag);
        }
    }
}

fn path_probes(root: &Path) -> Vec<String> {
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_default();
    let cargo = std::env::var("CARGO_HOME").unwrap_or_else(|_| format!("{home}/.cargo"));
    let rustup = std::env::var("RUSTUP_HOME").unwrap_or_else(|_| format!("{home}/.rustup"));
    let mut probes = vec![cargo, rustup, root.display().to_string(), home];
    let forward: Vec<String> = probes.iter().map(|probe| probe.replace('\\', "/")).collect();
    let back: Vec<String> = probes.iter().map(|probe| probe.replace('/', "\\")).collect();
    probes.extend(forward);
    probes.extend(back);
    probes.retain(|probe| probe.len() >= 4);
    probes.sort();
    probes.dedup();
    probes
}

fn refuse_machine_paths(path: &Path, probes: &[String]) -> Result<(), String> {
    let bytes = fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    for probe in probes {
        if contains_bytes(&bytes, probe.as_bytes()) {
            return Err(format!(
                "REFUSING: {} contains the build-machine path '{probe}'",
                path.display()
            ));
        }
    }
    for pattern in [b"/home/" as &[u8], b"/Users/", b"C:\\Users\\", b"C:/Users/"] {
        if contains_bytes(&bytes, pattern) {
            return Err(format!(
                "REFUSING: {} contains a home-directory path ({})",
                path.display(),
                String::from_utf8_lossy(pattern)
            ));
        }
    }
    Ok(())
}

fn verify_wasm_opt_version() -> Result<(), String> {
    let out = Command::new("wasm-opt")
        .arg("--version")
        .output()
        .map_err(|e| {
            format!(
                "cannot run `wasm-opt --version`: {e}. Install binaryen version \
                 {EXPECTED_WASM_OPT_VERSION} (matching flake.lock) so WASM bytes stay reproducible."
            )
        })?;
    if !out.status.success() {
        return Err("`wasm-opt --version` failed".into());
    }
    let version = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let expected = format!("wasm-opt version {EXPECTED_WASM_OPT_VERSION}");
    if !version.starts_with(&expected) {
        return Err(format!(
            "REFUSING: expected `{expected}` (matching flake.lock), found `{version}`. \
             A different binaryen version re-keys every WASM."
        ));
    }
    println!("{version}");
    Ok(())
}

fn optimize_wasm(path: &Path) -> Result<(), String> {
    let tmp = path.with_extension("wasm.opt");
    let status = Command::new("wasm-opt")
        .args([
            "-Oz",
            "--strip-debug",
            "--strip-producers",
            "--enable-bulk-memory",
            "--enable-sign-ext",
            "--enable-mutable-globals",
            "--enable-nontrapping-float-to-int",
            "--enable-multivalue",
            "--enable-reference-types",
        ])
        .arg(path)
        .arg("-o")
        .arg(&tmp)
        .status()
        .map_err(|e| format!("cannot run wasm-opt on {}: {e}", path.display()))?;
    if !status.success() {
        let _ = fs::remove_file(&tmp);
        return Err(format!("wasm-opt failed on {}", path.display()));
    }
    fs::rename(&tmp, path)
        .map_err(|e| format!("cannot replace {} with optimized wasm: {e}", path.display()))
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|window| window == needle)
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
