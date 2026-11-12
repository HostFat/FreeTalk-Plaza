# FreeTalk Plaza

A forum on Freenet: boards, categories, posts, private boards, and portable
identities, all stored in Freenet contracts instead of a server.

FreeTalk Plaza is a fork of [River](https://github.com/freenet/river) that
replaces chat rooms with a forum, on top of the current Freenet stack
(freenet-stdlib 0.12, Dioxus 0.7).

# Building

The toolchain is pinned in `rust-toolchain.toml` and the dependency graph in
`Cargo.lock`. Both matter: the contract's code hash and the delegate's key are
derived from the WASM bytes, so a different rustc or a drifted lockfile re-keys
the app and users' boards become invisible.

```sh
# Once: build the WASMs into the committed locations
cargo make sync-wasm        # or: cargo run --manifest-path tools/wasm-tool/Cargo.toml -- sync

# Always: CSS + dev server
npm --prefix ui install
npm --prefix ui run watch:css
dx serve --package plaza-ui
```

(`cargo make` tasks need `cargo install cargo-make`; every task has an
equivalent `cargo run --manifest-path tools/wasm-tool/Cargo.toml -- …` command.)

# Delegate generations

`legacy_delegates.toml` is the single source of truth for previous delegate
generations. `ui/build.rs` turns it into the `LEGACY_DELEGATES` table the UI
uses to find boards written by an older build.

When the delegate WASM changes:

```sh
cargo make add-migration V3 "what changed"   # records the committed WASM
cargo make sync-wasm                          # rebuild + copy
cargo make check-migration                    # fails if the entry is missing
```

CI runs `check-migration` on every push, so a WASM change without a registry
entry fails the build instead of silently orphaning data.

# Deploy

Install deploy-tool from [ ◆ Freenet Shared ](https://github.com/free-network/freenet-shared)

Run `deploy-tool deploy`

The deployment id in `deploy.toml` (`freetalk`) is the live app identity and is
intentionally unchanged by the rename.

## Publish only

`deploy-tool deploy` rebuilds the UI (`dx build --release`), signs the bundle
and then publishes it. When the build is already signed and only the state
needs to be sent again, skip the rebuild:

```powershell
pwsh ./publish-only.ps1
```

The script reads the signed artifacts from `%APPDATA%\freetalk`, finds `fdev`,
prints the build time, warns if sources changed after that build, and runs
`fdev publish`. Use it for a retry after a stuck publish or for a deliberate
re-publish. For code changes, run `deploy-tool deploy`.
