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
        Some("sync") => cmd_sync(),
        _ => usage(),
    };
    if let Err(e) = code {
        eprintln!("ERROR: {e}");
        std::process::exit(1);
    }
}

fn usage() -> Result<(), String> {
    eprintln!(
        "usage:\n  wasm-tool hash <file>\n  wasm-tool add <version> <description>\n  wasm-tool check [--ci <base> <head>]\n  wasm-tool sync"
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

fn cmd_sync() -> Result<(), String> {
    let root = repo_root();
    let status = Command::new("cargo")
        .args([
            "build",
            "--locked",
            "--profile",
            "release",
            "--target",
            "wasm32-unknown-unknown",
            "-p",
            "plaza-contract",
            "-p",
            "plaza-delegate",
        ])
        .current_dir(&root)
        .status()
        .map_err(|e| format!("cannot run cargo: {e}"))?;
    if !status.success() {
        return Err("cargo build failed".into());
    }

    let out = root.join("target/wasm32-unknown-unknown/release");
    let copies = [
        ("plaza_contract.wasm", "ui/public/contracts/plaza_contract.wasm"),
        ("plaza_delegate.wasm", "ui/public/contracts/plaza_delegate.wasm"),
        ("plaza_contract.wasm", "cli/contracts/plaza_contract.wasm"),
    ];
    for (src, dst) in copies {
        let src = out.join(src);
        let dst = root.join(dst);
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
        fs::copy(&src, &dst)
            .map_err(|e| format!("cannot copy {} to {}: {e}", src.display(), dst.display()))?;
        println!("copied {} -> {}", src.display(), dst.display());
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
