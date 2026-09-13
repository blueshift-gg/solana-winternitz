# Solana Winternitz

[![CI](https://github.com/blueshift-gg/solana-winternitz/actions/workflows/ci.yml/badge.svg)](https://github.com/blueshift-gg/solana-winternitz/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/solana-winternitz.svg)](https://crates.io/crates/solana-winternitz)
[![Docs.rs](https://docs.rs/solana-winternitz/badge.svg)](https://docs.rs/solana-winternitz)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Hash-based signatures for Solana programs: target-sum Winternitz and a
256-leaf XMSS tree, using Keccak-256. Verification is `no_std` and uses
Solana's `sol_keccak256` syscall.

| Module | Max. signatures per key | Signature | Public key | Verify CU |
|---|---:|---:|---:|---:|
| `winternitz` | 1 | 849 bytes | 41 bytes | 34,450 |
| `xmss` | 256 | 1,037 bytes | 41 bytes | 36,116 |

This is a custom instantiation of [DKKW25](https://eprint.iacr.org/2025/055),
not RFC 8391 XMSS. It has not been independently audited.

## Usage

```toml
[dependencies]
solana-winternitz = { git = "https://github.com/blueshift-gg/solana-winternitz" }
```

```rust
use solana_winternitz::{Error, VerifyingKey, xmss};

fn verify(key: &[u8], digest: &[u8; 32], signature: &[u8]) -> Result<(), Error> {
    let key = VerifyingKey::ref_from_bytes(key)?;
    key.verify(digest, xmss::Signature::ref_from_bytes(signature)?)
}
```

For a one-time key, use `winternitz::Signature`. Both verify a 32-byte digest;
your application chooses how to hash its message.

### Signing

Enable the `sign` feature for the host signer:

```rust,no_run
# #[cfg(feature = "sign")]
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use solana_winternitz::xmss;

let mut signer = xmss::SigningKey::create("tree.key")?;
let digest = [0u8; 32]; // Replace with your message digest.
let signature = signer.sign(&digest)?;
signer.verifying_key().verify(&digest, &signature)?;
# Ok(())
# }
# #[cfg(not(feature = "sign"))]
# fn main() {}
```

Resume with `SigningKey::open("tree.key")`. The signer persists each leaf before
signing. Never restore an older key file or delete its `.lock` file: reusing a
leaf can allow forgery. Failed signing attempts also spend a leaf; a failed transaction does not restore it.

See [SECURITY.md](SECURITY.md) for state management and [SPEC.md](SPEC.md) for
the construction and encoding.

## Example program

The [program](program/src/lib.rs) verifies instruction data with no accounts:
`[tag: 1][public key: 41][digest: 32][signature]`. Tag `0` selects Winternitz;
tag `1` selects XMSS. Invalid signatures return `Custom(1)`.

It checks the supplied signature only. A consuming application must bind the
key to its authority and reject replayed messages or leaves.
The [SBPF test](tests/sbpf.rs) constructs both instructions and measures their CU.

## TypeScript

The [TypeScript package](packages/winternitz) includes browser-compatible
verification and a `./signer` export for file-backed signing under Bun.

## Tests

```sh
cargo test --lib --features sign
cargo test --doc --features sign
cargo build-sbf --arch v3 --manifest-path program/Cargo.toml
cargo test --test sbpf -- --nocapture
bun install --frozen-lockfile
bun run test
```

CU figures use SBPF v3. SBPF tests need `cargo-build-sbf 4.2.0`.

## License

[MIT](LICENSE).
