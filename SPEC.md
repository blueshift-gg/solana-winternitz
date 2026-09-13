# Specification

This document defines the two Keccak-256 instances implemented by the
Rust crate and TypeScript package. References to constructions, lemmas
and equations refer to [DKKW25], revision 2025-09-12. Security assumptions
are in [SECURITY.md](SECURITY.md).

## Parameters and notation

| Symbol | Value | Meaning |
|---|---:|---|
| `v` | 36 | number of chains |
| `w` | 4 | bits per digit; chain positions are 0 through 15 |
| `T` | 297 | accepted digit sum, `⌈1.1 · v · (2^w − 1) / 2⌉` (§8) |
| `K` | 4096 | maximum salt candidates per signing attempt (§8) |
| `n` | 184 bits | chain element, leaf hash and node hash: 23 bytes |
| `P` | 18 bytes | public parameter |
| `ρ` | 21 bytes | salt |
| `m` | 32 bytes | application-supplied message digest (Remark 1) |
| `h` | 0 or 8 | tree height: `winternitz` or `xmss` |
| `L` | `2^h` | number of leaves |
| `ℓ` (paper: `ep`) | `0 .. L−1` | leaf index, called an epoch in DKKW25; unrelated to a Solana epoch |

Indices are zero-based: `ℓ` is a leaf, `i` a chain, `k` a chain
position, `l` a tree level and `j` a node index within that level.
`‖` denotes concatenation. Parenthesized lengths below are in bytes.
All integers are unsigned and big-endian except the leaf index in the
message hash, which is little-endian as in [hash-sig].

## Hash inputs

Let `H` be Keccak-256. The functions follow §7.2's layouts `P ‖ t ‖ x`
and `ρ ‖ P ‖ t ‖ m`, where `t` is a tweak with the domain byte and
position fields of §7.1, equations (17)–(19).

| Role | Input to `H` | Input bytes | Output |
|---|---|---:|---|
| chain step | `P(18) ‖ 0x00 ‖ ℓ(4) ‖ i(1) ‖ k(1) ‖ x(23)` | 48 | first 23 bytes |
| leaf | `P(18) ‖ 0x01 ‖ 0x00 ‖ ℓ(4) ‖ pk_0 ‖ … ‖ pk_35` | 852 | first 23 bytes |
| node | `P(18) ‖ 0x01 ‖ l(1) ‖ j(4) ‖ left(23) ‖ right(23)` | 70 | first 23 bytes |
| message | `ρ(21) ‖ P(18) ‖ 0x02 ‖ ℓ(4, LE) ‖ m(32)` | 76 | first 18 bytes |

The encoding reads each message-hash byte's low nibble, then its high
nibble, yielding `x ∈ {0, …, 15}^36`. It accepts exactly when `Σ x_i = T`
(Construction 6). Distinct accepted vectors are incomparable under
coordinatewise ordering (Lemma 7).

## Key generation

Sample `P` and each chain start `sk[ℓ][i]` independently and uniformly
(Construction 3, Gen). The persistent signers use `getrandom::fill` in Rust and
`randomFillSync` in TypeScript; `hazmat` key generation takes an explicit
CSPRNG fill callback with requests of at most 828 bytes. Store the starts in leaf-major, then
chain-major order: 828 bytes per leaf. There is no seed or PRF derivation.

For each leaf and chain, define:

```text
F[ℓ,i,0] = sk[ℓ][i]
F[ℓ,i,k] = step(P, ℓ, i, k, F[ℓ,i,k−1])    for k = 1 … 15
pk[ℓ][i] = F[ℓ,i,15]
```

The step entering position `k` uses tweak `k` (Construction 2).
Hash the 36 chain ends into `node[0][ℓ]`. Build higher levels by hashing
`node[l−1][2j] ‖ node[l−1][2j+1]` at level `l`, index `j`, for
`l = 1 … h` (Construction 1). The root is `node[h][0]`; at height zero
it is the sole leaf hash. The public key is `root ‖ P`.

## Signing and verification

For a fixed salt, signing takes a leaf `ℓ`, message `m` and salt `ρ`.
The caller-managed `hazmat::SecretKey::sign_at` / `signAt` operation samples
salts through an explicit CSPRNG callback; `sign_at_with_salt` /
`signAtWithSalt` reproduces a signature using an already accepted salt.
Reject an out-of-range leaf or a salt whose encoding fails. Otherwise,
return chain values `σ_i = F[ℓ,i,x_i]` and the authentication path
`node[l][(ℓ >> l) xor 1]` for `l = 0 … h−1`, leaf level first
(Construction 3, Sig). An empty path is used at height zero.

To verify (Construction 3, Ver):

1. Reject `ℓ ≥ L`; `winternitz` has implicit leaf zero.
2. Encode the signature's salt and supplied message under `P` and `ℓ`;
   reject if the sum is not `T`.
3. Walk each `σ_i` from position `x_i` to 15, using tweaks `x_i+1 … 15`.
   Lemma 2 gives the same chain ends as key generation.
4. Hash the chain ends into the leaf, then climb the authentication path.
   At level `l = 1 … h`, use index `j = ℓ >> l` and put the current node
   on the left iff bit `l−1` of `ℓ` is zero (Construction 1, VerPath;
   correctness is Lemma 1).
5. Accept iff the computed root equals the public key's root.

An accepted signature requires `36 · 15 − 297 = 243` chain hash steps.
Verification neither records leaf use nor prevents replay.

## Wire formats

| Object | Layout | Bytes |
|---|---|---:|
| public key | `root(23) ‖ P(18)` | 41 |
| `winternitz` signature | `ρ(21) ‖ σ_0 ‖ … ‖ σ_35` | 849 |
| `xmss` signature | `ℓ(4) ‖ ρ(21) ‖ σ_0 ‖ … ‖ σ_35 ‖ path_0 ‖ … ‖ path_7` | 1,037 |

All chain values and path entries are 23 bytes. Rust represents keys
and signatures as fixed-size byte arrays; TypeScript constructors
reject incorrect lengths.

## Persistent signer

`SigningKey` supplies Construction 3's salt sampling and enforces one
completed signing attempt per leaf (Definition 8). For a new attempt:

1. Sample independent 21-byte salt candidates, at most `K`, stopping at
   the first accepted encoding.
2. Advance `next_leaf`. On success, record the message and accepted salt.
   On salt exhaustion or randomness failure, clear both fields.
3. Persist the record before returning a signature or sampling error.

A retry of the recorded message uses its recorded salt at `next_leaf−1`,
returning the same bytes without sampling or advancing. Each new attempt
replaces that record; failure clears it. An exhausted key can still
retry its recorded message. Raw `sign_at` / `signAt` does no allocation
or persistence.

The version 2 key file has a 78-byte header followed by all chain starts:

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 1 | version, `2` |
| 1 | 1 | height, `0` or `8` |
| 2 | 18 | `P` |
| 20 | 4 | `next_leaf`, big-endian |
| 24 | 1 | message flag, `0` or `1` |
| 25 | 32 | recorded message |
| 57 | 21 | recorded salt |
| 78 | `828 · L` | chain starts |

Total length is 906 bytes for `winternitz`, 212,046 for `xmss`.
Readers reject an incorrect length, version or instance height, a flag
outside `{0,1}`, or `next_leaf > L`. Flag zero requires zero message and
salt fields. Flag one requires `next_leaf > 0` and a salt that encodes
the recorded message at `next_leaf−1` to the target sum. Version 1 seed
files are rejected; using sampled keys requires application key rotation.

Creation uses exclusive file creation with mode 0600. Updates write
`<file>.tmp`, fsync it, rename it over the key file and fsync the parent
directory. A write failure releases no signature; drop/close and reopen
the signer before continuing. Temporary files are ignored on open.
`require_next_leaf_at_least(minimum)` / `requireNextLeafAtLeast(minimum)` rejects a record with `next_leaf < minimum`; it does not advance it.

An open signer holds an exclusive, nonblocking kernel lock on the
permanent `<file>.lock` sidecar. On Unix, Rust's `File::try_lock` and
TypeScript's Bun FFI use `flock(LOCK_EX | LOCK_NB)`. Closing the descriptor
releases the lock; process death releases it once no holder remains.
Never delete or replace the sidecar: a different inode creates a second
lock. [SECURITY.md](SECURITY.md#signer-state) specifies the filesystem
and recovery assumptions.

## Relationship to the sources

The generic construction is instantiated with Keccak-256 in place of
§7.2's SHA3-256. Hash layouts, truncation and digit order follow
[hash-sig]; widths are recomputed for `L ≤ 256`. Construction 3 samples
starts and salts, whereas hash-sig derives them using a PRF. This signer
uses the paper's sampling and `K = 4096` from §8. Its key file, lock and
embedded leaf index are local conventions. These instances implement
individual signatures; they do not implement the paper's aggregation
construction.

[Sampled vectors](tests/sampled.json) specify deliberately non-random
inputs for Rust/TypeScript signing agreement. Leaves 127 and 128 exercise
both path orientations at every level.
[winternitz.key](tests/winternitz.key) is a public test key with one
recorded signature; its secrets must never secure an application.
Regenerate both with
`cargo test --lib regenerate_sampled_vectors -- --ignored`.

[Reference vector](tests/hash-sig.json) contains a signature from
hash-sig with SHA3-256 replaced by Keccak-256. Its `source` field records
the commit, type parameters and generation seed. It tests verification
against an independent implementation; no reference key derivation is
retained. [SBPF tests](tests/sbpf.rs) embed host-generated signatures for
runtime verification and CU measurements.

[DKKW25]: https://eprint.iacr.org/2025/055
[hash-sig]: https://github.com/b-wagn/hash-sig/tree/e66a48565d73c4d83d54e1b28fe249ab8c0d8542
