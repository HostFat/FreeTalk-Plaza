# FreeTalk

A Forum for freenet

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
dx serve --package freetalk-ui
```

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
