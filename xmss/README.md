# Solana XMSS

[![Crates.io](https://img.shields.io/crates/v/solana-xmss.svg)](https://crates.io/crates/solana-xmss)
[![Docs.rs](https://docs.rs/solana-xmss/badge.svg)](https://docs.rs/solana-xmss)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Many-time hash-based signatures for Solana programs: a DKKW25 generalized
XMSS tree of 256 leaves, each a [`solana-winternitz`](https://crates.io/crates/solana-winternitz)
one-time key, over Keccak-256. Verification is `no_std` and uses Solana's
`sol_keccak256` syscall.

| Max. signatures per key | Signature | Public key | Verify CU |
|---:|---:|---:|---:|
| 256 | 1,037 bytes | 41 bytes | ~36,500 |

## Usage

```toml
[dependencies]
solana-xmss = "0.1.0"
```

```rust
use solana_xmss::{Error, Signature, VerifyingKey};

fn verify(key: &[u8], digest: &[u8; 32], signature: &[u8]) -> Result<(), Error> {
    let key = VerifyingKey::ref_from_bytes(key)?;
    key.verify(digest, Signature::ref_from_bytes(signature)?)
}
```

Verification is stateless. Each leaf signs once, so your program must refuse
a leaf it has already accepted, for example by recording a used-leaf bitmap
or by requiring `Signature::leaf()` to exceed the last accepted leaf.

### Signing

Enable the `sign` feature for the host signer:

```rust,no_run
# #[cfg(feature = "sign")]
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use solana_xmss::SigningKey;

let mut signer = SigningKey::create("tree.key")?;
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
a failed transaction does not restore it. Exact retries return the saved
signature. Key files from `solana-winternitz` 0.2's `xmss` module open unchanged.

## License

[MIT](LICENSE).

Based on [DKKW25](https://eprint.iacr.org/2025/055) and
[hash-sig](https://github.com/b-wagn/hash-sig/tree/e66a48565d73c4d83d54e1b28fe249ab8c0d8542),
using Keccak-256, sampled chain starts and 256 leaves. Not compatible with
RFC 8391 XMSS. Unaudited.
