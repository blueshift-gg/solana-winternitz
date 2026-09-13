# Solana Winternitz

[![CI](https://github.com/blueshift-gg/solana-winternitz/actions/workflows/ci.yml/badge.svg)](https://github.com/blueshift-gg/solana-winternitz/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/blueshift-gg/solana-winternitz/blob/main/LICENSE)

Generalized XMSS with target-sum Winternitz encoding, instantiated with
Keccak-256: Constructions 3 and 6 of
[Drake, Khovratovich, Kudinov and Wagner (DKKW25)](https://eprint.iacr.org/2025/055).
Verification uses Solana's `sol_keccak256` syscall. Signing is stateful:
each leaf permits one signing attempt, including failed salt sampling.

Experimental; no independent security audit. The target is 128-bit
classical and 64-bit quantum security under the assumptions in
[SECURITY.md](https://github.com/blueshift-gg/solana-winternitz/blob/main/SECURITY.md).
This is a Keccak-256 instantiation of the construction, with locally
chosen lifetimes and persistent signer state. The byte formats and
relationship to the paper are specified in
[SPEC.md](https://github.com/blueshift-gg/solana-winternitz/blob/main/SPEC.md).

| Instance | Leaves per key | Signature | Public key | Verify CU |
|---|---:|---:|---:|---:|
| `winternitz` | 1 | 849 B | 41 B | 34,371 |
| `xmss` | 256 | 1,037 B | 41 B | 36,012 |

Accepted signatures require one message hash, 243 chain steps, one leaf
hash and, for `xmss`, eight node hashes. CU figures are fixture
measurements under Mollusk with platform-tools v1.56; reproduce them
with the SBPF test below.

## Verify

```toml
[dependencies]
solana-winternitz = "0.1"
```

Given a stored public key, a 32-byte message digest and signature bytes:

```rust
# fn verify(public_key: [u8; 41], message: [u8; 32], signature: [u8; 1037]) -> Result<(), solana_winternitz::Error> {
use solana_winternitz::{VerifyingKey, xmss};

let public_key = VerifyingKey::from_bytes(&public_key);
let signature = xmss::Signature::from_bytes(&signature);
public_key.verify(&message, &signature)?;
# Ok(())
# }
```

Pass a `winternitz::Signature` to the same key method for the one-leaf
instance. The digest argument is `&[u8; MESSAGE_LEN]`, and
verification returns `Error::InvalidSignature` on failure. These are inherent
methods with no trait imports. The crate is `no_std` and has no dependencies
on Solana.

The application hashes everything it authorizes into the message and
enforces replay protection atomically with execution. For `winternitz`,
retire the key after acceptance. For `xmss`, `signature.leaf()` gives the
leaf index for the application's replay policy. It is a counter,
unrelated to Solana slots or epochs.

## Sign

```sh
bun add @blueshift-gg/solana-winternitz @noble/hashes
```

```ts
import { keccak_256 } from '@noble/hashes/sha3.js';
import { xmss } from '@blueshift-gg/solana-winternitz/signer';

using signer = xmss.SigningKey.create('tree.key');
const message = keccak_256(new TextEncoder().encode('example'));
const publicKey = signer.verifyingKey();
const signature = signer.sign(message);
publicKey.verify(message, signature);
```

`create` samples the key from the OS random source and refuses an
existing file. Resume with `xmss.SigningKey.open('tree.key')`.
The recorded message can be retried with the same signature bytes,
including after reopening. A new attempt replaces that retry record;
sampling failure also spends its leaf.

Rust provides `xmss::SigningKey::create("tree.key")` and
`winternitz::SigningKey::create("once.key")` with the `sign` feature.
Both implementations share a key-file format and Unix kernel locks.
The TypeScript signer requires Bun on macOS or Linux with glibc;
the pure package root also runs in browsers, workers and Node. See the
[package README](https://github.com/blueshift-gg/solana-winternitz/blob/main/packages/winternitz/README.md)
for API details.

The key file contains secrets and usage state. Keep one authoritative
copy, on a trusted local filesystem, accessed through the same path.
Never restore an older signing state or remove its permanent `.lock`
sidecar. A signature spends its leaf even if its transaction never lands.
The `hazmat` module (`./hazmat` in TypeScript) provides caller-managed key
generation and leaf signing. It does not manage usage state.

```rust
# #[cfg(feature = "sign")]
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use solana_winternitz::{hazmat::winternitz::SecretKey, SigningError};

let fill = |out: &mut [u8]| getrandom::fill(out).map_err(SigningError::Random);
let secret = SecretKey::generate(fill)?;
let digest = [0u8; 32]; // Replace with the application's message digest.
// This fresh one-leaf key is used once and discarded, including on failure.
let signature = secret.sign_at(0, &digest, fill)?;
secret.verifying_key().verify(&digest, &signature)?;
# Ok(())
# }
# #[cfg(not(feature = "sign"))]
# fn main() {}
```

If the key survives a call, reserve and persist the leaf before calling `sign_at`,
including attempts that fail. `sign_at_with_salt` on `hazmat::OneTime` reproduces a
signature from a recorded accepted salt without sampling or allocating a leaf.

## Validation

The tests check parameter bounds, sampled-input signing agreement
between Rust and TypeScript, independent reference signatures, tampered
fixtures, and signer failure and recovery behavior.

```sh
cargo test --lib
cargo test --doc --features sign
cargo +nightly fmt --all -- --check
cargo +nightly clippy --all-targets --features sign -- -D warnings
bun install --frozen-lockfile
bun run test
```

SBPF correctness and CU measurements require `cargo build-sbf` and run
separately from CI:

```sh
cargo test --test sbpf -- --nocapture --test-threads=1
```

## License

[MIT](https://github.com/blueshift-gg/solana-winternitz/blob/main/LICENSE).
