use std::env;
use std::fs;
use std::path::Path;
use std::process;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // Get the output directory
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("plaza_contract.wasm");

    // Try to find the WASM file in several locations
    let possible_paths = [
        // When building from workspace
        "../ui/public/contracts/plaza_contract.wasm",
        // When building from workspace root
        "ui/public/contracts/plaza_contract.wasm",
        // Pre-built WASM included in the package (required for crates.io)
        // This file MUST be committed to the repo for publishing
        "contracts/plaza_contract.wasm",
    ];

    let mut wasm_found = false;

    for path in &possible_paths {
        if Path::new(path).exists() {
            println!("cargo:rerun-if-changed={}", path);
            fs::copy(path, &dest_path).expect("Failed to copy WASM file");
            println!("cargo:warning=Copied plaza_contract.wasm from {}", path);
            wasm_found = true;

            verify_matches_built_artifact(&dest_path);
            break;
        }
    }

    if !wasm_found {
        // For crates.io publishing, we need the WASM file to be included
        // Create a dummy file or panic based on whether this is a docs build
        if env::var("DOCS_RS").is_ok() {
            // During docs.rs build, create a dummy file
            fs::write(&dest_path, b"dummy").expect("Failed to create dummy WASM file");
        } else {
            panic!(
                "plaza_contract.wasm not found! Please ensure it exists in one of these locations: {:?}",
                possible_paths
            );
        }
    }
}

fn verify_matches_built_artifact(dest_path: &Path) {
    if std::env::var("RIVER_SKIP_CONTRACT_CHECK").is_ok() {
        return;
    }

    let candidates = built_wasm_candidates();
    if candidates.is_empty() {
        // Nothing to compare against (contract probably not rebuilt yet)
        return;
    }

    let dest_bytes = match fs::read(dest_path) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!(
                "Failed to read copied plaza_contract.wasm at {}: {err}",
                dest_path.display()
            );
            process::exit(1);
        }
    };

    let mut checked = Vec::new();
    for candidate in &candidates {
        let built_bytes = match fs::read(candidate) {
            Ok(bytes) => bytes,
            Err(err) => {
                eprintln!(
                    "Failed to read built plaza_contract.wasm at {}: {err}",
                    candidate.display()
                );
                process::exit(1);
            }
        };
        if built_bytes == dest_bytes {
            return;
        }
        checked.push(candidate.display().to_string());
    }

    panic!(
        "plaza_contract.wasm is out of date.\n\
         The CLI is bundling {}, which differs from every built artifact:\n  {}\n\
         Rebuild the contract and copy it to ui/public/contracts/ (deploy-fast.ps1 does that).",
        dest_path.display(),
        checked.join("\n  ")
    );
}

/// Built contract artifacts to compare the bundled WASM with. `deploy-fast`
/// builds with `--target-dir target/dx-fast` and the `release-fast` profile,
/// so the default `target/wasm32-unknown-unknown/release` path alone is not
/// enough.
fn built_wasm_candidates() -> Vec<std::path::PathBuf> {
    let mut roots = vec![
        std::path::PathBuf::from("..").join("target"),
        std::path::PathBuf::from("..").join("target").join("dx-fast"),
    ];
    if let Ok(dir) = env::var("CARGO_TARGET_DIR") {
        let path = std::path::PathBuf::from(dir);
        roots.push(if path.is_absolute() {
            path
        } else {
            std::path::PathBuf::from("..").join(path)
        });
    }

    let mut candidates = Vec::new();
    for root in roots {
        for profile in ["release", "release-fast"] {
            let candidate = root
                .join("wasm32-unknown-unknown")
                .join(profile)
                .join("plaza_contract.wasm");
            if candidate.exists() && !candidates.contains(&candidate) {
                candidates.push(candidate);
            }
        }
    }
    candidates
}
