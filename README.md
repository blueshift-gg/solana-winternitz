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
| `winternitz` | 1 | 864 B | 29,524 |
| `xmss` | 256, one per leaf | 1,124 B | 31,224 |

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
the leaf it spends by index. The paper calls that index the epoch; it is not
a time, and never the Solana epoch.

## How it works

```text
seed (32 bytes),  h = tree height: 0 for winternitz, 8 for xmss
  │
  ├─ P              = SHA-256(0x03 ‖ 0 ‖ h ‖ seed)[..24]              public parameter
  ├─ sk[ℓ][i]       = SHA-256(0x03 ‖ 1 ‖ h ‖ ℓ ‖ i ‖ seed)[..24]      chain starts, leaf ℓ, chain i
  │
  │  step(ℓ, i, k, x) = SHA-256(0x00 ‖ ℓ ‖ i ‖ k ‖ P ‖ x)[..24]      k = position stepped into
  │
  ├─ pk[ℓ][i]       = step(ℓ, i, 15, … step(ℓ, i, 1, sk[ℓ][i]))      chain ends
  ├─ leaf[ℓ]        = SHA-256(0x01 ‖ 0 ‖ ℓ ‖ P ‖ pk[ℓ][0] ‖ … ‖ pk[ℓ][34])
  ├─ node[l][j]     = SHA-256(0x01 ‖ l ‖ j ‖ P ‖ node[l−1][2j] ‖ node[l−1][2j+1])
  └─ public key     = node ‖ P        node = leaf[0] (winternitz) or the root (xmss)

sign(ℓ, m): find salt ρ = SHA-256(0x03 ‖ 2 ‖ h ‖ ℓ ‖ ctr ‖ SHA-256(m) ‖ seed)[..24], ctr = 0, 1, …
            with  x = HMAC-SHA-256(0x02 ‖ ℓ ‖ ρ ‖ P, m)[..18] as 35 nibbles
            (low nibble of each byte first), Σ x_i = 325;
            σ_i = chain i of leaf ℓ walked to position x_i
verify:     recompute x, reject unless Σ x_i = 325;  walk each σ_i from x_i to 15;
            hash the ends into leaf[ℓ], climb the authentication path, compare to the root

HMAC-SHA-256(K, m) = SHA-256((K ‖ 0¹¹) ⊕ 0x5c⁶⁴ ‖ SHA-256((K ‖ 0¹¹) ⊕ 0x36⁶⁴ ‖ m)),  K = 53 bytes
```

Every structured hash input starts with a role byte, 0 for chain steps, 1
for leaves and tree nodes, 2 for the message, 3 for key derivation, the way
RFC 8391 §5.1 prefixes its four functions. Within a role every field but
the message has a fixed width and comes first, so the inputs of different
roles and of different positions are distinct byte strings. The message
hash is HMAC-SHA-256 keyed by its 53-byte prefix, so its two SHA-256 calls
begin with `0x02 ⊕ 0x36` and `0x02 ⊕ 0x5c`, still disjoint from the other
roles. The one plain hash is `SHA-256(m)` inside salt derivation; it is
public and gives an attacker nothing they cannot compute. Disjoint inputs
are what the role bytes buy; they do not make SHA-256 an independent
random oracle per role, see the assumptions below. `winternitz` is the
single-leaf case: leaf 0 and no path. `xmss` signatures carry the leaf
index and the 8 sibling nodes.

Classical Winternitz appends checksum chains so that no message can be
reached from another by only walking chains forward. The target sum does the
same job with no extra chains: two distinct nibble vectors with the same sum
always differ in both directions somewhere. The signer pays for it by
grinding the salt, about 940 attempts on average at three host SHA-256 calls
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

The chain and tree tweak layouts, the domain bytes, the nibble order and
the chain-step convention are those of the authors' reference
implementation [hash-sig](https://github.com/b-wagn/hash-sig). The input
order is not: the paper's §7.2 and hash-sig hash `P ‖ tweak ‖ message` and
`ρ ‖ P ‖ tweak ‖ message`, this crate hashes `tweak ‖ P ‖ message` for
chains and trees so that the role byte is at offset 0, and computes the
message hash as HMAC-SHA-256 keyed by `tweak ‖ ρ ‖ P`, with the leaf index
big-endian where hash-sig uses little-endian. Vectors are therefore not
interchangeable with hash-sig. Under the random-oracle heuristic the
paper's bounds do not depend on the order; the HMAC is what lets SHA-256
stand in for SHA-3 in the message hash, see the assumptions below. The length bounds are what the authors'
[parameter script](https://github.com/b-wagn/hashsig-parameters) prints
for lifetime 2^8, 35 chains, 4-bit chunks and 2^16 signing trials:
hash ≥ 183 bits, parameter ≥ 142, salt ≥ 176, message hash ≥ 138. The
tests pin those numbers. The paper instantiates the tweakable hash with
SHA-3; this crate uses SHA-256 because it is the cheapest hash syscall on
Solana (85 CU per call plus 1 CU per 2 bytes, from agave's
`execution_budget.rs`). FIPS 205 is precedent for SHA-2 in this role at
the 128-bit level only, which is the level here: its SHA-2 parameter sets
pad the seed to a full block and use SHA-512 above security category 1.

| Verification step | Syscalls | Cost |
|---|---:|---:|
| Message hash, HMAC-SHA-256, and target-sum check | 2 | ~270 CU |
| Chain steps, 55-byte input each | 200 | ~22,400 CU |
| Leaf hash over tweak, `P` and the 35 chain ends, three slices | 1 | ~530 CU |
| Tree nodes, `xmss` only | 8 | ~1,000 CU |

The remainder of the measured total is BPF loop overhead: a tight loop of
bare chain-step syscalls measures within 2.5k CU of `verify`. Variants
measured and declined: three-slice chain steps, where the runtime's 10 CU
minimum per slice exceeds the one copy; copying the chain ends into one
leaf buffer, 200 to 500 CU more than passing them as a third slice; and
shrinking every length to the paper's exact bound, which saves 9% at one
to two bits of margin.

## Tests and verification

`cargo test --lib` checks that:

- the parameters satisfy DKKW25 requirements (13)–(16) at lifetime 256, and
  the target sum gives the documented grinding cost, the layer size computed
  exactly with `num-bigint`;
- the message hash's HMAC matches RFC 4231, and syscall ids match their
  published values;
- both instances round-trip, `xmss` on every one of its 256 leaves, the
  fixed [`tests/vectors.json`](tests/vectors.json) corpus is reproduced byte
  for byte, and the key file [`tests/winternitz.key`](tests/winternitz.key)
  opens and repeats its vector's signature;
- flipping any byte of a signature, public key or message is rejected, and
  so is relabelling a signature with another leaf;
- the same seed gives unrelated `winternitz` and `xmss` keys;
- the signer holds one file per instance, opens only from a file, records
  before it signs, repeats the last message for free, and refuses foreign,
  truncated, behind-the-chain and exhausted files.

Incomparability of accepted encodings, the property that replaces the
checksum, is DKKW25 Lemma 7 and is not tested: two distinct vectors with
equal sums cannot be ordered coordinate-wise.

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

Local measurements with platform-tools v1.56:

| Operation | Compute units |
|---|---:|
| `winternitz::Signature::verify`, accepted | 29,524 |
| `xmss::Signature::verify`, accepted | 31,224 |
| either, message off target | 1,076 |

The HMAC message hash costs about 210 CU of these figures over a plain
hash: two syscalls of 138 and 133 CU in place of one of 140, plus the pad
construction, done eight bytes at a time because a byte loop measured
1,000 CU on SBPF. Measured before and after on the same machine and
toolchain: 29,329 and 31,025 before, 29,524 and 31,224 after, the last
15 CU recovered by passing the chain ends to the leaf hash uncopied.

For comparison, the previous `solana-winternitz` crate (32 byte-wide chains,
no checksum) needs about 4,080 hashes on average and 8,160 in the worst
case, roughly 412k and 824k CU by the same cost model, with a 1,024-byte
signature. Its missing checksum also makes signatures forgeable in about
2^45 work for a typical key, and far less for an unlucky one.

## Assumptions

The paper's Corollary 2, Theorem 1 applied to Constructions 3 and 6,
gives 128-bit classical and 64-bit quantum security under properties of
its tweakable hash, with the lengths set by Parameter Requirements 2 and
3. Four things here are not in the paper's text and are assumed on top of
it:

- **SHA-256 in place of SHA-3.** The concrete bounds model the hash as a
  random oracle; we apply the same heuristic to SHA-256, as FIPS 205 and
  RFC 8391 do for their SHA-2 instantiations.
- **Key derivation is a PRF.** The parameter, chain starts and salts are
  `SHA-256(0x03 ‖ purpose ‖ h ‖ … ‖ seed)`, assumed pseudorandom to anyone
  without the seed. This is the additive PRF term the paper's Remark 7
  allows. The form follows RFC 8391 §5.1's `PRF`, plain SHA-256 over a
  domain tag, the key and the input, but it is not that function: the
  RFC's is `SHA-256(toByte(3, 32) ‖ KEY ‖ M)`, here the tag is one byte and
  the key comes last so the role byte stays at offset 0. The assumption is
  this crate's own, not one the RFC establishes. Remark 7 covers only the
  chain starts; the paper's signer samples each salt candidate uniformly
  and independently, so the deterministic salts need one more step: with
  the whole seed-derived function replaced by a random function, the
  distinct labels, purpose byte, height, leaf index and counter, make the
  parameter, every chain start and every salt candidate independent and
  uniform, and the one-message-per-leaf rule keeps the labels distinct.
  Unpredictability alone would not do: one unknown salt repeated for every
  counter is unpredictable and gives a single grinding attempt. The tree height `h` is in every derivation so that one seed gives
  unrelated `winternitz` and `xmss` keys; without it the single leaf would
  be leaf 0 of the tree, and a signature under one instance would spend
  the other's one-time key. The paper has no such case, its keys are
  sampled independently per instance.
- **Two output lengths under one theorem.** The paper's `Th` has a single
  output space `H`. Here chain steps output 24 bytes while leaf and node
  hashes output 32. Read both as one function `G(P, t, x) = SHA-256(t ‖ P
  ‖ x)` over the chain and tree tweaks, with the chain hash its truncation
  to 24 bytes. Theorem 1's terms then split by function. The tree term
  (`B1`, multi-target collision resistance with `2·L·v·2^w` targets, eq.
  (6)) runs against `G`: the reduction has to build every chain before it
  learns `P`, which it can, by querying `G` with chain tweaks and
  truncating, while keeping the full 32 bytes for leaves and nodes; a
  forged tree then yields a full-width collision in `G`. The chain terms
  (`B3` to `B6`: collision resistance, undetectability, preimage
  resistance, eqs. (7) to (9)) run against the truncated function, which
  is where eq. (15) is checked. The 24-byte outputs and the 32-byte nodes
  are inputs of the tree hash, as `H^v ⊆ M` and `H^2 ⊆ M` require. The
  wider nodes only add margin on the tree term.
- **Security is the digest width, not the layer.** In the paper's
  random-oracle model, hitting a signed encoding costs 2^140 hashes
  however the target sum is set, DKKW25 eq. (13): the accepted layer's
  size sets the signer's grinding cost and, at a fixed retry cap, nothing
  else. A plain SHA-256 message hash would not honour that number. It is
  Merkle–Damgård with a 256-bit state and its whole input is public once
  a leaf is signed, so an attacker holding `t` signed leaves could herd
  the `t` first-block states of `0x02 ‖ leaf ‖ ρ ‖ P ‖ m` into one
  internal state at about `t · 2^128` compression calls, then test every
  one of the `t` signed encodings with each suffix trial, about
  `2^140 / t` more: roughly 2^134 at `t = 64`, above the 128-bit target
  but below the claim. That is the mechanism of Perlner, Kelsey and
  Cooper's category-5 SPHINCS+ attack (ePrint 2022/1061) transposed to
  the encoding; its structure was reproduced on a small-state model with
  the crate's exact block layout, and the plain hash was declined. The
  message hash is HMAC-SHA-256 keyed by the public prefix instead: the
  outer call binds the prefix again, so a merged inner state still tests
  one target per compression, and HMAC with a fixed-length key under 511
  bits, this one is 424, is indifferentiable from a keyed random oracle
  (Dodis, Ristenpart, Steinberger, Tessaro, CRYPTO 2012, Theorem 4.4) at
  a classical loss of `σ² / 2^256`. It costs one extra syscall. The chain
  and tree hashes never needed it: their inputs have one admissible
  length each and their targets are 256 bits wide.

Length extension does not apply. The message hash is HMAC, whose outer
call closes it. Chain and tree inputs have one admissible length each,
fixed by their role and level bytes, so an extension is never an input
the scheme hashes. Key derivation is the one place a secret is involved,
and its outputs are truncated.

## Choosing an instance

**`winternitz`** when the verifying program controls the key's whole life:
a vault whose withdrawal message names the next key, a recovery key that is
used once. The program must retire the key in the same instruction that
verifies.

**`xmss`** when the same key must sign again after a failure, which is any
flow where a failed transaction leaves state unchanged and the client
retries. The program enforces a leaf policy, see below, and the client
signs through `Signer`, which consumes leaves in order and records each
before releasing the bytes: a signature that reached any RPC has revealed
its leaf, landed or not. With 256 leaves and a leaf signing the next root,
lifetime is unbounded.

## TypeScript: sign off-chain

```sh
bun add @blueshift-gg/solana-winternitz
```

```ts
import { randomBytes } from 'node:crypto';
import { Signer, winternitz, xmss } from '@blueshift-gg/solana-winternitz';

const signer = Signer.create(xmss.SecretKey, 'tree.key', randomBytes(32)); // ~1 s: builds 256 leaves; refuses an existing file
const treeKey = signer.publicKey; // 56 bytes, register on-chain
const signature = signer.sign(message); // spends leaf 0, recorded in the file before it is computed
signature.verify(treeKey, message); // throws on failure
signer.sign(message); // the same message again: same bytes, no leaf spent
signer.close(); // releases the file for the next instance

const again = Signer.open(xmss.SecretKey, 'tree.key').floor(lastAcceptedOnChain + 1); // continues at leaf 1
again.remaining; // 255
const once = Signer.create(winternitz.SecretKey, 'once.key', randomBytes(32)); // the one-leaf case
```

The key file is the key: 71 bytes holding the seed, the next leaf and the
digest of the last message, mode 0600, replaced atomically on every spent
leaf. Back up the file, not the seed. `create` takes any fresh 32-byte
seed, from the OS or a derivation, and refuses a path that already holds
a file; `open` takes only the file, so no key is ever opened at leaf 0 by
accident; a stale copy is caught by `floor` when the chain's last accepted
leaf is at hand. One instance holds a file at a time, through a `.lock`
sidecar with the holder's pid; a sidecar left by a dead process is
cleared, a live or reused pid makes `open` fail with the pid named. The
last message signed again returns the same bytes and spends nothing, so a
retry never touches a counter. Underneath, `signAt(leaf, message)` on
either key is the primitive: it takes the leaf explicitly and records
nothing, for tests and vectors. Byte getters return copies. The
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
if sig.leaf() <= last_leaf { return Err(...) } // or the leaf policy of your choice, see below
sig.verify(&PublicKey(stored), message)?;
last_leaf = sig.leaf(); // in the same instruction
```

`verify` returns `Err(Error::InvalidSignature)` for any failure and makes no
distinction between a wrong message, a wrong key, and corrupted bytes.

Host-side Rust, with the `sign` feature:

```rust
use solana_winternitz::{Signer, winternitz, xmss};

let mut signer = Signer::<xmss::SecretKey>::create("tree.key", seed)?; // a fresh seed; refuses an existing file
let public_key = signer.public_key();
let signature = signer.sign(message)?; // spends leaf 0, recorded in the file before it is computed
signer.sign(message)?; // the same message again: same bytes, no leaf spent
drop(signer); // releases the file

let mut again = Signer::<xmss::SecretKey>::open("tree.key")?.floor(last_accepted_on_chain + 1)?;
let once = Signer::<winternitz::SecretKey>::create("once.key", seed)?; // the one-leaf case
```

The key file and its rules are the same as in the TypeScript package
above; the two packages read each other's files. `Signer` drives either
key through the `OneTime` trait, whose `sign_at(leaf, message)` is the
primitive underneath: it takes the leaf explicitly and records nothing.

Signing is deterministic in seed, leaf and message. It fails only if
65,536 salts all miss the target sum, which under a uniform model happens
for one seed-and-message pair in e^70; for a given pair the outcome is
fixed.

## Using it safely

- Include everything the program will act on in the message. The scheme
  binds the message, not the transaction around it.
- `winternitz`: one message per seed, and the program swaps the key in the
  instruction that verifies.
- `xmss`: the program enforces a leaf policy, see below; the client never
  reuses a leaf, including leaves spent in transactions that failed. Reuse
  is a break, not a weakening. Each signature under a leaf reveals a chain
  position, and a forger needs only a salt whose encoding lies at or above
  the lowest revealed position in every chain, built from public signatures
  alone. Measured on this crate: one signature leaves one reachable
  encoding, the full 2^140 search; a second signature under the same leaf
  cuts it to about 2^46 to 2^51 salt trials depending on the pair, a
  fourth to about 2^23, and with eight the forgery lands in roughly ten
  thousand trials.
- Signatures are 864 and 1,124 bytes. A verifying instruction fits a
  transaction on its own; a larger authorized action goes in a separate
  transaction the way multisig programs propose and then approve.

## Leaf policy

The program decides which leaves it accepts. `Signer` consumes leaves in
order and returns the last message's signature again without spending
one, which serves either policy. Three facts hold under both:

- **A leaf index is not a time.** The paper calls it the epoch; never
  derive it from a slot or from the Solana epoch: `slot % 256` reuses
  leaves, and two signatures in one slot collide.
- **Exposure is permanent.** A signature that reached any RPC, for
  simulation or broadcast, is public whether or not its transaction landed
  or expired, and anyone can resubmit it inside a new transaction until the
  program retires it. Only the program's sequence check, or a deadline the
  signed message itself carries, retires an authorization; the blockhash
  does not. A changed message therefore always takes an unused leaf, and
  waiting for expiry buys nothing.
- **The key file is the key.** The next leaf and the digest of the last
  message live in the file with the seed, and every device that signs
  must hold the current file. Neither the seed nor the chain can rebuild
  it: failed transactions leave no on-chain trace of the leaves they
  exposed, which is why `open` takes a file and never a seed. A margin
  above the on-chain value is a guess, not a bound: if leaves 11 to 30
  were exposed and the account shows 10, resuming at 20 reuses a leaf.
  `floor` catches a restored old copy of the file, not that gap. If the
  file is truly lost, the least bad move is one signature at the highest
  leaf that rotates to a fresh key, landed at once, with the funds treated
  as at risk until it lands.

**Strictly increasing.** The account stores the last accepted leaf and
takes any greater one. Gaps are allowed, so a leaf whose transaction was
lost is closed by landing anything higher, which also retires any second
signature a bug produced under it. Two signatures at one leaf cost a
forger about 2^46 hashes, hours of GPU time, and the leaf closes in
seconds, so the window is the mitigation. The cost is ordering: a leaf-8
signature landing first invalidates an outstanding leaf-7 one, which is
an application policy, not a requirement of the scheme. A program that
needs several signatures in flight can store a 256-bit used-leaf bitmap
instead; that loses closing by landing higher, so it leans entirely on the
sequence number to retire abandoned signatures.

**Strict nonce.** The account requires exactly the next leaf, or, as
winterwallet does, stores the one root allowed to sign next. Nothing is
skipped, and a restore of the position, though not of the digest, is one
read of the account. Its problems, stated here so they are not
rediscovered:

- **There is no burn path.** A lost transaction whose intent has changed
  cannot be skipped. The only safe retry is the identical message, which
  is what `sign` returns for it. A different message at that leaf is
  the reuse, and an advance-only no-op is a different message too. If the
  original intent can no longer execute, the key is stuck: only a path
  that does not need the one-time key moves it.
- **The client guard is the whole defence.** The program cannot tell a
  legitimate retry from a reuse, since both carry the pinned leaf. The
  key file must be current on every device that signs, and a device
  without it must not sign.
- **Recovery by scanning is the symptom.** winterwallet's recover command
  derives positions until one matches the on-chain root, then sets the
  client back to it, which is the position whose signature was lost. A
  recover tool under this policy restores the key file, not only its
  position.

Choose strict nonce only if the program needs leaves without gaps.

## License

MIT. This software is provided as-is; review it for your own threat model
before using it to secure value.
