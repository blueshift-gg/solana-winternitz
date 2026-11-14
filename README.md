# Solana Winternitz

[![CI](https://github.com/blueshift-gg/solana-winternitz/actions/workflows/ci.yml/badge.svg)](https://github.com/blueshift-gg/solana-winternitz/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/solana-winternitz.svg)](https://crates.io/crates/solana-winternitz)
[![Docs.rs](https://docs.rs/solana-winternitz/badge.svg)](https://docs.rs/solana-winternitz)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

One-time hash-based signatures for Solana programs: DKKW25 target-sum
Winternitz over Keccak-256. Verification is `no_std` and uses Solana's
`sol_keccak256` syscall.

| Crate | Max. signatures per key | Signature | Public key | Verify CU |
|---|---:|---:|---:|---:|
| `solana-winternitz` | 1 | 849 bytes | 41 bytes | ~34,800 |
| [`solana-xmss`](https://github.com/blueshift-gg/solana-xmss) | 256 | 1,037 bytes | 41 bytes | ~36,500 |

A one-time key must sign exactly one message: two signatures from the same
key let anyone forge. If a signed message can fail and need signing again,
use [`solana-xmss`](https://github.com/blueshift-gg/solana-xmss), whose 256 leaves are one-time keys under a single
public key.

## Usage

```toml
[dependencies]
solana-winternitz = "0.3.0"
```

```rust
use solana_winternitz::{Error, Signature, VerifyingKey};

fn verify(key: &[u8], digest: &[u8; 32], signature: &[u8]) -> Result<(), Error> {
    let key = VerifyingKey::ref_from_bytes(key)?;
    key.verify(digest, Signature::ref_from_bytes(signature)?)
}
```

Verification takes a 32-byte digest; your application chooses how to hash
its message.

### Signing

Enable the `sign` feature for the host signer:

```rust,no_run
# #[cfg(feature = "sign")]
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use solana_winternitz::SigningKey;

let mut signer = SigningKey::create("once.key")?;
let digest = [0u8; 32]; // Replace with your message digest.
let signature = signer.sign(&digest)?;
signer.verifying_key().verify(&digest, &signature)?;
# Ok(())
# }
# #[cfg(not(feature = "sign"))]
# fn main() {}
```

Resume with `SigningKey::open("once.key")`. Use one key file on a trusted local
filesystem, always through the same path. Never restore an older copy or
replace its `.lock` file. A signing attempt spends the key even on failure;
a failed transaction does not restore it. Exact retries return the saved
signature; any other message is refused.

`hazmat` has raw keys with caller-managed usage, and the generic key file
`solana-xmss` signs through. `primitives` has the hash building blocks
`solana-xmss` builds its tree from; every tweak is defined there, so leaf,
node, chain and message hashes cannot collide.

## Example program

The [program](program/src/lib.rs) registers a one-time public key in an
account, verifies one signature against it and marks the key spent. The
[test](program/tests/registration.rs) generates a key, signs on the host,
creates the account with the System Program and submits the signature.

| Tag | Instruction data after tag | Operation |
|---|---|---|
| `0` | Public key, 41 bytes | Register the key |
| `1` | Digest, 32 bytes, then signature, 849 bytes | Verify and spend the key |

The key account signs registration and is writable for both operations. It
holds a state byte and the public key (42 bytes). A spent key refuses every
further signature.

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
using Keccak-256 and sampled chain starts. Unaudited.

Version 0.3 moves XMSS to [`solana-xmss`](https://github.com/blueshift-gg/solana-xmss); keys, signatures and key
files are unchanged from 0.2. Versions 0.2 and later are a new scheme and are
not compatible with the 0.1.x releases (224-bit Keccak Winternitz without a
checksum, which must not be used).
