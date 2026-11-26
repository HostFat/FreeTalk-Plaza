# WASM File Safety — CRITICAL

## Never use `git add -A`, `git add .`, or `git add -u` in this repo

These commands can pick up unintentionally rebuilt WASM binaries from `ui/public/contracts/`.
Any byte change to a contract or delegate WASM changes its Freenet key (`BLAKE3(BLAKE3(wasm) || params)`), which re-keys contracts and orphans user secrets stored under previous delegate keys.

**Always add files by name:**
```bash
# RIGHT
git add ui/src/components/conversation.rs ui/src/util.rs

# WRONG — may pick up rebuilt WASMs in the working tree
git add -A
git add .
git add -u
```

## Canonical WASM builds

Always rebuild contract and delegate WASMs through the canonical tool:
```bash
cargo make sync-wasm
```
`wasm-tool sync` builds `--locked` with `CARGO_ENCODED_RUSTFLAGS` path remapping (`CARGO_HOME`, `RUSTUP_HOME`, `rustc --print sysroot`, repo root), runs pinned `wasm-opt` (`binaryen` **125**, `-Oz --strip-debug --strip-producers`), and refuses any artifact that embeds a local machine path. Both `rust-toolchain.toml` and `flake.nix` must stay pinned to the exact same Rust version (`1.94.0`) and `binaryen` version (`125`).

## Never commit delegate WASM changes without registering the outgoing hash

Both delegates are tracked by dedicated registries (read by `ui/build.rs` and enforced in CI):
- Board delegate (`ui/public/contracts/plaza_delegate.wasm`) → `legacy_delegates.toml`
  - Record outgoing hash: `cargo make add-migration <version> "<description>"`
- DM delegate (`ui/public/contracts/plaza_dm_delegate.wasm`) → `legacy_dm_delegates.toml`
  - Record outgoing hash: `cargo make add-dm-migration <version> "<description>"`

Never hand-edit generated arrays in `chat_delegate.rs` or `dm_delegate.rs`; update the TOML registries via `wasm-tool add` / `wasm-tool add --dm`, and verify before committing:
```bash
cargo make check-migration
```

If `git status` shows modified `.wasm` files that you did **not** intentionally rebuild, restore them:
```bash
git checkout HEAD -- ui/public/contracts/
```
