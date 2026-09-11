# Solana Winternitz

[![CI](https://github.com/blueshift-gg/solana-winternitz/actions/workflows/ci.yml/badge.svg)](https://github.com/blueshift-gg/solana-winternitz/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/blueshift-gg/solana-winternitz/blob/main/LICENSE)

Post-quantum hash-based signatures for Solana programs, verified with the
`sol_keccak256` syscall alone: generalized XMSS over target-sum
Winternitz, Constructions 3 and 6 of
[Drake, Khovratovich, Kudinov and Wagner, IACR CiC 2025](https://eprint.iacr.org/2025/055),
in the paper's SHA-3 instantiation (§7.2) at its §8 operating point, with
the parameters and 32-byte messages of the authors' implementation
[hash-sig](https://github.com/b-wagn/hash-sig), and with chain starts,
parameter and salts sampled as the paper writes them. Keccak-256 stands
in for SHA3-256, the one substitution the platform forces; with that
substitution, hash-sig's signatures verify here. The security level is
the paper's 128 bits classical and 64 bits quantum (Corollary 2,
Parameter Requirements 2 and 3). Research code, not audited.

| Instance | Signatures per key | Signature | Public key | Verify CU |
|---|---:|---:|---:|---:|
| `winternitz` | 1 | 849 B | 41 B | 34,331 |
| `xmss` | 256, one per leaf | 1,037 B | 41 B | 35,971 |

`winternitz` is the tree of height 0, `xmss` the tree of height 8; one
code path serves both. Verification is constant work: one message hash,
243 chain steps, one leaf hash, one node hash per tree level.

- [SPEC.md](https://github.com/blueshift-gg/solana-winternitz/blob/main/SPEC.md):
  every byte from seed to signature, the key file and its lock, the
  vectors, and what differs from the paper and from hash-sig.
- [SECURITY.md](https://github.com/blueshift-gg/solana-winternitz/blob/main/SECURITY.md):
  the claim, the model, the bound at these parameters, the assumptions
  behind it, and what is not proven.

## Verify on-chain

```toml
[dependencies]
solana-winternitz = "0.1"
```

```rust,ignore
use solana_winternitz::{PublicKey, winternitz, xmss};

let message: [u8; 32] = keccak256(payload); // the program hashes what it acts on

winternitz::Signature(signature_bytes).verify(&PublicKey(stored), &message)?;

let sig = xmss::Signature(signature_bytes);
if sig.leaf() <= last_leaf { return Err(...) } // the program's leaf policy, see SECURITY.md
sig.verify(&PublicKey(stored), &message)?;
last_leaf = sig.leaf(); // in the same instruction
```

A message is a 32-byte digest, the paper's fixed message length and
hash-sig's: the program hashes whatever it acts on, with `sol_keccak256`
or any collision-resistant hash, and passes the digest. The crate is
`no_std` with no on-chain dependencies. `verify` returns
`Err(Error::InvalidSignature)` for any failure, with no distinction
between a wrong message, a wrong key and corrupted bytes.

## Sign off-chain

```sh
bun add @blueshift-gg/solana-winternitz
```

```ts
import { keccak_256 } from '@noble/hashes/sha3.js';
import { Signer, winternitz, xmss } from '@blueshift-gg/solana-winternitz';

const signer = Signer.create(xmss.SecretKey, 'tree.key'); // samples the key, ~1 s: builds 256 leaves
const treeKey = signer.publicKey; // 41 bytes, register on-chain
const message = keccak_256(payload); // the digest the program will compute
const signature = signer.sign(message); // spends leaf 0, recorded in the file first
signer.sign(message); // the same message again: same bytes, no leaf spent
signer.close();

const again = Signer.open(xmss.SecretKey, 'tree.key').floor(lastAcceptedOnChain + 1);
const once = Signer.create(winternitz.SecretKey, 'once.key'); // one leaf
```

The same `Signer` exists in Rust behind the `sign` feature, with
`create`, `open`, `floor`, `sign`, `public_key`, `next_leaf` and
`remaining`. The two read each other's key files and honour each other's
locks. `create` samples every chain start and the parameter from the
operating system's random source, as the paper's key generation does,
and refuses an existing file; `open` takes only a file. The key file is
the key and its only copy: the chain starts, the parameter, the next
leaf, and the last message with its salt, 906 bytes for `winternitz` and
212,046 for `xmss`. Back up the file. One process holds a file at a
time, through a kernel lock on a permanent `.lock` sidecar that the OS
releases if the holder dies. The TypeScript signer needs Bun on a unix
host for that call; verification and key generation run anywhere.
`signAt` and `sign_at` sign under an explicit leaf with a given salt and
record nothing; they exist for tests and vectors.

## Rules

- Put everything the program will act on in the payload it hashes into
  the message. The scheme binds that digest, not the transaction around
  it.
- `winternitz`: one message per seed, and the program retires the key in
  the instruction that verifies.
- `xmss`: never two messages under one leaf. `Signer` enforces it on the
  device; the program enforces a leaf policy on the index. A signature
  that reached any RPC has spent its leaf, landed or not.
- A leaf index is a counter, the paper's epoch. Never derive it from a
  slot or the Solana epoch.

## Parameters

| Parameter | Value | Source |
|---|---:|---|
| Chains `v` | 36 | hash-sig's 18-byte message hash: 144 bits ≥ 138, eq. (13) |
| Chain positions `2^w` | 16 | one nibble per chain |
| Target sum `T` | 297 | `δ = 1.1`, §8: 243 verifier steps, ~111 salts per signature |
| Salt trials `K` | 4096 | §8; all miss once in e^36.8 |
| Chain element `n` | 23 B | ≥ 183 bits at lifetime 2^8, eq. (15) |
| Public parameter `P` | 18 B | ≥ 142 bits, eq. (16) |
| Salt `ρ` | 21 B | ≥ 168 bits at lifetime 2^8 with 4096 trials, eq. (14) |
| Message | 32 B | hash-sig's `MESSAGE_LENGTH`, the paper's fixed `l_msg` |
| Tree height | 0 or 8 | 1 or 256 leaves |

The lengths are what the authors'
[parameter script](https://github.com/b-wagn/hashsig-parameters) prints
for these inputs, rounded up to bytes as hash-sig does; the tests pin
the bounds. At lifetime 2^18 hash-sig's own SHA-3 instantiation has the
same `v`, `w`, `P` and `δ`, with longer chain elements and salts for the
longer lifetime.

## Tests

`cargo test --lib` pins the four parameter bounds, Keccak-256 against its
known answers, the syscall id, hash-sig's signatures in
[`tests/hash-sig.json`](https://github.com/blueshift-gg/solana-winternitz/blob/main/tests/hash-sig.json)
verifying, signing from explicit chain starts and salts against
[`tests/sampled.json`](https://github.com/blueshift-gg/solana-winternitz/blob/main/tests/sampled.json)
and the key file
[`tests/winternitz.key`](https://github.com/blueshift-gg/solana-winternitz/blob/main/tests/winternitz.key),
rejection of every single-byte tamper, the signer's rules, and its lock
dying with its holder. The TypeScript package is a second implementation
written from `SPEC.md`, sharing no code, that must reproduce the same
fixtures and additionally checks that a failed random source, salt
exhaustion and a failed write release no signature. `tests/sbpf.rs`
measures the verifiers as SBPF programs under Mollusk and needs
`cargo build-sbf`.

```sh
cargo test --lib
cargo +nightly fmt --all -- --check
cargo +nightly clippy --all-targets --features sign -- -D warnings
cargo test --test sbpf -- --nocapture --test-threads=1
bun install --frozen-lockfile
bun run test
```

## License

MIT. Provided as-is; review it against your own threat model before using
it to secure value.
