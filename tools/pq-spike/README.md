# Post-quantum cost spike

A standalone measurement of what post-quantum cryptography would cost
FreeTalk Plaza. It is not part of the workspace and not used by the app.

## Run

```sh
cargo run --release --manifest-path tools/pq-spike/Cargo.toml
```

The binary builds signed messages with Ed25519 and ML-DSA-65, encodes the
same state with CBOR, and verifies every signature. It also compares ML-KEM-768
with the current X25519 sealed-secret layout.

## Wasm size

```sh
# Ed25519 only (baseline)
cargo build --release --target wasm32-unknown-unknown \
  --manifest-path tools/pq-spike/Cargo.toml --lib --no-default-features

# Ed25519 + ML-DSA-65 + ML-KEM-768
cargo build --release --target wasm32-unknown-unknown \
  --manifest-path tools/pq-spike/Cargo.toml --lib
```

The `.wasm` is under `tools/pq-spike/target/wasm32-unknown-unknown/release/`.
The spike uses the fast profile (`opt-level = "s"`, no LTO). The real
contract uses `opt-level = "z"` and LTO, so its absolute size is smaller; the
delta is the relevant number.

## Results (x86_64, release)

Message payload 500 bytes, 10 members, CBOR state including the member
verifying keys:

| Records | Ed25519 state | ML-DSA-65 state | Ed sign | ML-DSA sign | Ed verify | ML-DSA verify |
|---:|---:|---:|---:|---:|---:|---:|
| 100 | 116,791 B | 770,399 B | 2.2 ms | 337 ms | 3.1 ms | 99 ms |
| 1,000 | 1,160,342 B | 7,366,410 B | 23.7 ms | 3,283 ms | 34.5 ms | 949 ms |
| 10,000 | 11,595,842 B | 73,326,510 B | 227 ms | 32,789 ms | 344 ms | 9,492 ms |

Key and signature sizes:

| Item | Ed25519 | ML-DSA-65 |
|---|---:|---:|
| Verifying key | 32 B | 1,952 B |
| Signature | 64 B | 3,309 B |

ML-KEM-768 vs the current X25519 ECIES:

| Item | X25519 + AES-GCM | ML-KEM-768 |
|---|---:|---:|
| Sealed secret blob | 92 B | 1,160 B |
| Encapsulation / decapsulation | ~0.05 ms (X25519) | 0.27 / 0.38 ms |

Wasm size for the probe crate:

| Build | Wasm |
|---|---:|
| Ed25519 only | 122,737 B |
| Ed25519 + ML-DSA-65 + ML-KEM-768 | 227,652 B |


## Wasm runtime

The contract runs in wasm, so the native numbers are a lower bound. Build the
benchmark for WASI and run it in wasmtime:

```sh
rustup target add wasm32-wasip1 --toolchain 1.94.1

cargo build --release --target wasm32-wasip1 \
  --manifest-path tools/pq-spike/Cargo.toml --bin pq-spike

wasmtime run tools/pq-spike/target/wasm32-wasip1/release/pq-spike.wasm
```

`wasmtime` can be downloaded from
[bytecodealliance/wasmtime releases](https://github.com/bytecodealliance/wasmtime/releases)
(the x86_64 Windows zip contains `wasmtime.exe`).

Wasmtime results (same input as the native table):

| Records | Ed25519 verify | ML-DSA-65 verify | Ed25519 sign | ML-DSA-65 sign |
|---:|---:|---:|---:|---:|
| 100 | 34 ms | 279 ms | 12.6 ms | 998 ms |
| 1,000 | 264 ms | 2.84 s | 119 ms | 8.65 s |
| 10,000 | 2.69 s | 28.6 s | 1.13 s | 87.9 s |

ML-KEM-768 in wasmtime: 0.59 ms encapsulation, 0.79 ms decapsulation.

The wasm binary is 328.6 KB (it includes the benchmark and std). The probe
library alone is 122.7 KB with Ed25519 and 227.7 KB with both PQ primitives
(+105 KB) in the fast profile.

In wasm ML-DSA verification is about 3× slower than native, and Ed25519 is
about 8× slower. A full 10,000-message state takes ~29 s to verify in wasm,
before the rest of the contract's work. That rules out ML-DSA on every
message for large boards.
## Reading the numbers

- A board with 10,000 messages grows from about 11.6 MB to 73.3 MB, and every
  full-state verification spends about 9.5 s in ML-DSA on x86_64. In the
  contract wasm it will be slower. This is the case against ML-DSA on every
  message.
- KEM-only adds ~1.1 KB per sealed secret and ~1.2 KB per member key; the
  contract stores those blobs without verifying them. It does not change
  signature or identity sizes.
- ML-DSA signing is also expensive (~3.3 ms per message natively); the UI
  would pay it on each post, which is acceptable, but the state growth is not.
- The wasm code for both PQ primitives is about +105 KB in the fast profile,
  which is small compared with the 1.2 MB contract.

## Recommendation

1. Ship ML-KEM (hybrid with X25519) for secret distribution first, keeping
   Ed25519 signatures and the current IDs.
2. Add hybrid Ed25519 + ML-DSA only to the control plane (member joins,
   admin/roles, invites, category key records, bans).
3. Do not put ML-DSA on every message without a new contract generation, a
   message cap and a wasm benchmark.
