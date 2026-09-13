# Solana Winternitz

[![CI](https://github.com/blueshift-gg/solana-winternitz/actions/workflows/ci.yml/badge.svg)](https://github.com/blueshift-gg/solana-winternitz/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/solana-winternitz.svg)](https://crates.io/crates/solana-winternitz)
[![Docs.rs](https://docs.rs/solana-winternitz/badge.svg)](https://docs.rs/solana-winternitz)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Generalized XMSS with target-sum Winternitz encoding, instantiated with
Keccak-256 from [DKKW25](https://eprint.iacr.org/2025/055).
Verification is `no_std` and uses Solana's `sol_keccak256` syscall.

Signing is stateful: each leaf permits one signing attempt, including failed
salt sampling. This is an experimental instantiation with no independent
audit. [SPEC.md](SPEC.md) defines its bytes and paper correspondence;
[SECURITY.md](SECURITY.md) states its assumptions and signing-state rules.

| Instance | Leaves per key | Signature | Public key | Verify CU |
|---|---:|---:|---:|---:|
| `winternitz` | 1 | 849 B | 41 B | 34,371 |
| `xmss` | 256 | 1,037 B | 41 B | 36,012 |

## Usage

```toml
[dependencies]
solana-winternitz = { git = "https://github.com/blueshift-gg/solana-winternitz" }
```

```rust
use solana_winternitz::{Error, VerifyingKey, xmss};

fn verify(key: &[u8], digest: &[u8; 32], signature: &[u8]) -> Result<(), Error> {
    let key = VerifyingKey::from_slice(key)?;
    key.verify(digest, &xmss::Signature::from_slice(signature)?)
}
```

Pass a `winternitz::Signature` for a one-leaf key. Verification takes a
32-byte digest; the application defines its message framing and hashing.
Constructors check encoded size; verification checks the signature.

### Signing

Enable the host-only `sign` feature for a file-backed signer:

```rust,no_run
# #[cfg(feature = "sign")]
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use solana_winternitz::xmss;

let mut signer = xmss::SigningKey::create("tree.key")?;
let digest = [0u8; 32]; // The application's message digest.
let signature = signer.sign(&digest)?;
signer.verifying_key().verify(&digest, &signature)?;
# Ok(())
# }
# #[cfg(not(feature = "sign"))]
# fn main() {}
```

`create` uses OS randomness and refuses an existing file. Resume with `open`.
The signer persists the leaf before releasing a signature. It can replay the
recorded signature for an identical message, including after reopening.
A new attempt replaces that retry record, even if salt sampling fails.

Keep one authoritative key file on a trusted local filesystem, accessed by
the same path. Never restore an older state or remove the permanent `.lock`
sidecar. A signature spends its leaf even if its transaction never lands.

`hazmat` exposes key generation and `sign_at` for callers managing their own
state. Reserve and persist a leaf before every attempt. `sign_at_with_salt`
reproduces a signature from its recorded accepted salt. These methods provide
no automatic protection against leaf reuse.

## TypeScript

The [TypeScript package](packages/winternitz) supplies the same custom
construction; Noble's SLH-DSA is a different signature scheme. The root export
is pure verification. The `./signer` subpath provides file-backed signing on
Bun/macOS and Bun/Linux with glibc, using the same file format and Unix locks
as Rust.

```ts
import { xmss } from '@blueshift-gg/solana-winternitz/signer';

using signer = xmss.SigningKey.create('tree.key');
const signature = signer.sign(digest);
signer.verifyingKey().verify(digest, signature);
```

## Tests

CI runs fmt, strict Clippy, doctests, Rust and TypeScript tests, and SBPF
verification. Tests cover independent reference signatures, parameter bounds,
tampering, signing-state recovery and failure behavior.

```sh
cargo test --lib --features sign
cargo test --doc --features sign
cargo test --test sbpf -- --nocapture --test-threads=1
bun install --frozen-lockfile
bun run test
```

The CU figures above are fixture measurements under Mollusk, SBPF v3,
platform-tools v1.56. SBPF tests require `cargo-build-sbf 4.2.0`.

## License

[MIT](LICENSE).
