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
| `winternitz` | 1 | 849 bytes | 41 bytes | ~34,800 |
| `xmss` | 256 | 1,037 bytes | 41 bytes | ~36,500 |

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

Resume with `SigningKey::open("tree.key")`. Use one key file on a trusted local
filesystem, always through the same path. Never restore an older copy or
replace its `.lock` file. Signing attempts spend a leaf even on failure;
a failed transaction does not restore it. Exact retries return the saved signature.

## Example program

The [program](program/src/lib.rs) creates a public-key account and verifies
signatures against it. The [test](program/tests/registration.rs) generates keys,
signs on the host, creates the account with the System Program, and submits
signatures for both instances.

| Tag | Instruction data after tag | Operation |
|---|---|---|
| `0` | Public key, 41 bytes | Create a Winternitz key account |
| `1` | Public key, 41 bytes | Create an XMSS key account |
| `2` | Digest, 32 bytes, then signature | Verify and mark the leaf used |

The key account signs creation and is writable for both operations. It holds
an instance byte, the public key and a 32-byte used-leaf bitmap (74 bytes total).
Reused leaves are rejected; unused XMSS leaves may arrive out of order.

## TypeScript

The [TypeScript package](packages/winternitz) includes browser-compatible
verification and a `./signer` export for file-backed signing under Bun.

## Tests

```sh
cargo test --lib --features sign
cargo test --doc --features sign
cargo build-sbf --arch v3 --manifest-path program/Cargo.toml
cargo test -p solana-winternitz-example --test registration -- --nocapture
bun install --frozen-lockfile
bun run test
```

CU figures use SBPF v3. SBPF tests need `cargo-build-sbf 4.2.0`.

## License

[MIT](LICENSE).

Based on [DKKW25](https://eprint.iacr.org/2025/055) and
[hash-sig](https://github.com/b-wagn/hash-sig/tree/e66a48565d73c4d83d54e1b28fe249ab8c0d8542),
using Keccak-256, sampled chain starts and at most 256 leaves. Not compatible
with RFC 8391 XMSS. Unaudited.
