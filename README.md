# Solana Winternitz

[![CI](https://github.com/blueshift-gg/solana-winternitz/actions/workflows/ci.yml/badge.svg)](https://github.com/blueshift-gg/solana-winternitz/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Post-quantum hash-based signatures for Solana programs, verified with
`sol_sha256` syscalls only. The construction is generalized XMSS with
target-sum Winternitz from
[Drake, Khovratovich, Kudinov and Wagner (IACR CiC 2025)](https://eprint.iacr.org/2025/055)
over a tweakable hash built from SHA-256, at 128-bit classical and 64-bit
quantum security. Two instances share one implementation and one 56-byte public key format:

| Instance | Signatures per key | Signature | Verify CU |
|---|---:|---:|---:|
| `winternitz` | 1 | 864 B | 29,328 |
| `xmss` | 256, one per epoch | 1,124 B | 31,022 |

## What is a hash-based signature?

A hash chain is a secret start value hashed repeatedly. Publishing the end of
a chain commits to the start without revealing it, and revealing any
intermediate value proves you knew everything before it.

A Winternitz key is 35 such chains of 16 positions. To sign, the message is
hashed into 35 nibbles, and for each chain the signer reveals the value at
the position that nibble names. The verifier hashes each revealed value
forward to the end of its chain and checks that the 35 ends hash to the
public key. Nothing but a hash function is involved, which is why the scheme
survives quantum computers: there is no algebraic structure to attack.

The price is that each such key signs **one** message. Revealing a value at
position 7 also proves positions 8 through 15, so a second signature on a
different message leaks enough to forge a third. XMSS puts 256 one-time keys
under a Merkle tree so one public key signs 256 times, each signature naming
the leaf it spends.

## How it works

```text
seed (32 bytes)
  │
  ├─ P              = SHA-256(0x03 ‖ 0 ‖ seed)[..24]                  public parameter
  ├─ sk[e][i]       = SHA-256(0x03 ‖ 1 ‖ e ‖ i ‖ seed)[..24]          chain starts, epoch e, chain i
  │
  │  step(e, i, k, x) = SHA-256(0x00 ‖ e ‖ i ‖ k ‖ P ‖ x)[..24]      k = position stepped into
  │
  ├─ pk[e][i]       = step(e, i, 15, … step(e, i, 1, sk[e][i]))      chain ends
  ├─ leaf[e]        = SHA-256(0x01 ‖ 0 ‖ e ‖ P ‖ pk[e][0] ‖ … ‖ pk[e][34])
  ├─ node[l][j]     = SHA-256(0x01 ‖ l ‖ j ‖ P ‖ node[l−1][2j] ‖ node[l−1][2j+1])
  └─ public key     = node ‖ P        node = leaf[0] (winternitz) or the root (xmss)

sign(e, m): find salt ρ with  x = SHA-256(0x02 ‖ e ‖ ρ ‖ P ‖ m)[..18] as 35 nibbles
            (low nibble of each byte first), Σ x_i = 325;
            σ_i = chain i of epoch e walked to position x_i
verify:     recompute x, reject unless Σ x_i = 325;  walk each σ_i from x_i to 15;
            hash the ends into leaf[e], climb the authentication path, compare to the root
```

Every hash input starts with a role byte, 0 for chain steps, 1 for leaves
and tree nodes, 2 for the message, 3 for key derivation, the way RFC 8391
§5.1 prefixes its four functions. Within a role every field but the message
has a fixed width and comes first, so the inputs of different roles and of
different positions are distinct byte strings. `winternitz` is the
single-leaf case: epoch 0 and no path. `xmss` signatures carry the epoch
and the 8 sibling nodes.

Classical Winternitz appends checksum chains so that no message can be
reached from another by only walking chains forward. The target sum does the
same job with no extra chains: two distinct nibble vectors with the same sum
always differ in both directions somewhere. The signer pays for it by
grinding the salt, about 940 attempts on average at two host SHA-256 calls
each. The verifier gains a constant workload: exactly 200 chain steps for
every accepted signature. A message that misses the target is rejected
after one hash; a wrong key is detected only after all of them.

## This implementation

The Rust crate is `no_std` and has no on-chain dependencies. On
`target_os = "solana"` every hash is the `sol_sha256` syscall; the host
build uses the `sha2` crate. Key generation and signing are behind the
`sign` feature and are never compiled for the Solana target.

| Parameter | Value | Source |
|---|---:|---|
| Chains `v` | 35 | 35 × 4 bits = 140 ≥ 138, DKKW25 eq. (13) |
| Chain length `w` | 16 | one nibble per chain, no big-integer decoding |
| Target sum | 325 | 200 verifier steps; one uniform digest in ~940 lands on the layer of `[16]^35` with this sum |
| Chain element `n` | 24 bytes | ≥ 23 bytes at lifetime 256, DKKW25 eq. (15) |
| Public parameter `P` | 24 bytes | ≥ 18 bytes, DKKW25 eq. (16) |
| Salt `ρ` | 24 bytes | ≥ 22 bytes at lifetime 256 with 2^16 signing trials, DKKW25 eq. (14) |
| Tree height | 8 | 256 leaves; nodes are full 32-byte SHA-256 outputs |

The tweak layout, domain bytes, input orders, nibble order and chain-step
convention are those of the authors' reference implementation
[hash-sig](https://github.com/b-wagn/hash-sig), and the length bounds are
what their [parameter script](https://github.com/b-wagn/hashsig-parameters)
prints for lifetime 2^8, 35 chains, 4-bit chunks and 2^16 signing trials:
hash ≥ 183 bits, parameter ≥ 142, salt ≥ 176, message hash ≥ 138. The
tests pin those numbers. The paper instantiates the tweakable hash with
SHA-3; this crate uses SHA-256 because it is the cheapest hash syscall on
Solana (85 CU per call plus 1 CU per 2 bytes, from agave's
`execution_budget.rs`), the same substitution FIPS 205 makes for its
SHA-2 parameter sets.

| Verification step | Syscalls | Cost |
|---|---:|---:|
| Message hash and target-sum check | 1 | ~140 CU |
| Chain steps, 55-byte input each | 200 | ~22,400 CU |
| Leaf hash over `P`, tweak and 35 chain ends, 870 bytes | 1 | ~520 CU |
| Tree nodes, `xmss` only | 8 | ~1,000 CU |

The remainder of the measured total is BPF loop overhead: a tight loop of
bare chain-step syscalls measures within 2.5k CU of `verify`. Variants
measured and declined: three-slice hashing without copies costs more (the
runtime charges at least 10 CU per slice), and shrinking every length to the
paper's exact bound saves 9% at one to two bits of margin.

## Tests and verification

`cargo test --lib` checks that:

- the parameters satisfy DKKW25 requirements (13)–(16) at lifetime 256, and
  the target sum gives the documented grinding cost, the layer size computed
  exactly with `num-bigint`;
- syscall ids match published values;
- both instances round-trip, `xmss` on every one of its 256 leaves, and the
  fixed [`tests/vectors.json`](tests/vectors.json) corpus is reproduced byte
  for byte;
- accepted encodings are pairwise incomparable, the property that replaces
  the checksum;
- flipping any byte of a signature, public key or message is rejected, and
  so is relabelling a signature with another epoch.

The [TypeScript package](packages/winternitz/src/index.ts) is a second
implementation written from the specification above, sharing no code with
the crate. It must reproduce every vector. A bug that is symmetric between
the Rust signer and verifier passes the round-trip tests and fails there.

`tests/sbpf.rs` compiles both verifiers to SBPF programs and runs them under
Mollusk through [`svm-unit-test`](https://github.com/blueshift-gg/svm-unit-test).
It needs `cargo build-sbf`.

```sh
cargo test --lib
cargo +nightly fmt --all -- --check
cargo +nightly clippy --all-targets --features sign -- -D warnings
cargo test --test sbpf -- --nocapture --test-threads=1
bun install --frozen-lockfile
bun run test
```

Local measurements with platform-tools v1.53:

| Operation | Compute units |
|---|---:|
| `winternitz::Signature::verify`, accepted | 29,328 |
| `xmss::Signature::verify`, accepted | 31,022 |
| either, message off target | 863 |

For comparison, the previous `solana-winternitz` crate (32 byte-wide chains,
no checksum) needs about 4,080 hashes on average and 8,160 in the worst
case, roughly 412k and 824k CU by the same cost model, with a 1,024-byte
signature. Its missing checksum also makes signatures forgeable in about
2^45 work for a typical key, and far less for an unlucky one.

## Assumptions

The paper's theorem gives 128-bit classical and 64-bit quantum security
under properties of its tweakable hash. Three things here are not in the
paper's text and are assumed on top of it:

- **SHA-256 in place of SHA-3.** The concrete bounds model the hash as a
  random oracle; we apply the same heuristic to SHA-256, as FIPS 205 and
  RFC 8391 do for their SHA-2 instantiations.
- **Key derivation is a PRF.** The parameter, chain starts and salts are
  `SHA-256(0x03 ‖ …‖ seed)`, assumed pseudorandom to anyone without the
  seed. This is the PRF term the paper's Remark 7 adds and the construction
  RFC 8391 §5.1 uses. The deterministic salt relies on it: the encoding
  needs salts an adversary cannot predict, not salts that are fresh.
- **Security is the digest width, not the layer.** Hitting a signed
  encoding costs 2^140 hashes however the target sum is set, DKKW25 eq.
  (13). The accepted layer's size only sets the signer's grinding cost, so
  the target sum is a verifier-cost knob with no security effect.

Length-extension does not apply: every input has a role byte first and
fixed-width fields before the message, and outputs are truncated.

## Choosing an instance

**`winternitz`** when the verifying program controls the key's whole life:
a vault whose withdrawal message names the next key, a recovery key that is
used once. The program must retire the key in the same instruction that
verifies.

**`xmss`** when the same key must sign again after a failure, which is any
flow where a failed transaction leaves state unchanged and the client
retries. The program stores the last accepted epoch and rejects any
signature at or below it. The client keeps the highest epoch it has ever
signed with, landed or not, and never signs below it: a signature broadcast
in a failed transaction has still revealed its leaf. With 256 leaves and the
last leaf signing the next root, lifetime is unbounded.

## TypeScript: sign off-chain

```sh
bun add @blueshift-gg/solana-winternitz
```

```ts
import { randomBytes } from 'node:crypto';
import { winternitz, xmss } from '@blueshift-gg/solana-winternitz';

const once = winternitz.SecretKey.fromSeed(randomBytes(32));
const publicKey = once.publicKey; // 56 bytes, register on-chain
const signature = once.sign(message); // 864 bytes, one call per key
signature.verify(publicKey, message); // throws on failure

const tree = xmss.SecretKey.fromSeed(randomBytes(32)); // ~1 s: builds 256 leaves
const treeKey = tree.publicKey; // 56 bytes, register on-chain
const sig = tree.sign(epoch, message); // 1,124 bytes; epoch strictly increasing
sig.verify(treeKey, message);
```

Seeds are 32 bytes; store the seed, not the key. `winternitz.SecretKey.sign`
throws on a second call. `xmss.SecretKey.sign` takes the epoch, because the
rule that an epoch is used once belongs to whoever tracks what was
broadcast. Byte getters return copies. The
[package README](packages/winternitz/README.md) has the API; run
`bun examples/sign.ts` from this checkout to try it.

## Rust: verify on-chain

```toml
[dependencies]
solana-winternitz = "0.1"
```

```rust
use solana_winternitz::{PublicKey, winternitz, xmss};

winternitz::Signature(signature_bytes).verify(&PublicKey(stored), message)?;

let sig = xmss::Signature(signature_bytes);
if sig.epoch() <= last_epoch { return Err(...) }
sig.verify(&PublicKey(stored), message)?;
last_epoch = sig.epoch(); // in the same instruction
```

`verify` returns `Err(Error::InvalidSignature)` for any failure and makes no
distinction between a wrong message, a wrong key, and corrupted bytes.

Host-side Rust, with the `sign` feature:

```rust
use solana_winternitz::{winternitz, xmss};

let once = winternitz::SecretKey(seed);
let public_key = once.public_key();
let signature = once.sign(message).expect("2^16 salts all missed"); // consumes the key

let tree = xmss::SecretKey::from_seed(seed);
let public_key = tree.public_key();
let sig = tree.sign(epoch, message).expect("epoch in range, salts found");
```

Signing is deterministic in seed, epoch and message. It fails only if
65,536 salts all miss the target sum, which under a uniform model happens
for one seed-and-message pair in e^70; for a given pair the outcome is
fixed.

## Using it safely

- Include everything the program will act on in the message. The scheme
  binds the message, not the transaction around it.
- `winternitz`: one message per seed, and the program swaps the key in the
  instruction that verifies.
- `xmss`: the program enforces strictly increasing epochs; the client never
  reuses one, including epochs spent in transactions that failed.
- Signatures are 864 and 1,124 bytes. A verifying instruction fits a
  transaction on its own; a larger authorized action goes in a separate
  transaction the way multisig programs propose and then approve.

## License

MIT. This software is provided as-is; review it for your own threat model
before using it to secure value.
