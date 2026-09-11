# Specification

Every byte of the scheme as implemented, for a second implementer. The
TypeScript package was written from this document and must reproduce
[`tests/sampled.json`](tests/sampled.json) and
[`tests/winternitz.key`](tests/winternitz.key) and verify
[`tests/hash-sig.json`](tests/hash-sig.json) and
[`tests/vectors.json`](tests/vectors.json). References are to
[DKKW25](https://eprint.iacr.org/2025/055) and to its reference
implementation [hash-sig](https://github.com/b-wagn/hash-sig) at commit
`e66a485`.

## Parameters

| Symbol | Value | Meaning |
|---|---:|---|
| `v` | 36 | chains, one per nibble of hash-sig's 18-byte message hash |
| `2^w` | 16 | chain positions, `w = 4` |
| `T` | 297 | required nibble sum, `⌈1.1 · 36 · 15 / 2⌉`, Construction 6 at §8's `δ = 1.1` |
| `K` | 4096 | salt trials before signing fails, §8 |
| `n` | 23 B | chain element, leaf and node |
| `P` | 18 B | public parameter |
| `ρ` | 21 B | salt |
| `l_msg` | 32 B | message, hash-sig's `MESSAGE_LENGTH`: the caller's digest of what it acts on (Remark 1) |
| `h` | 0 or 8 | tree height: `winternitz`, `xmss` |

The hash is Keccak-256, the `sol_keccak256` syscall, standing in for the
paper's SHA3-256 (§7.2): the same permutation, rate and capacity, padding
byte `0x01` for `0x06`. Every integer in a hash input or a wire format is
big-endian except the leaf index inside the message tweak, little-endian
as in hash-sig's `ShaMessageHash`.

## Hash inputs

Chain, leaf and node inputs are `P ‖ T ‖ M` and the message input
`ρ ‖ P ‖ T ‖ m`, §7.2.2 and §7.2.1, with the tweaks `T` of §7.1: a domain
byte, eqs. (17) to (19), then the position. Outputs are truncated to `n`
bytes, or to `v · w = 144` bits for the message. These are hash-sig's
`ShaTweakHash<18, 23>` and `ShaMessageHash<18, 21, 36, 4>` with the hash
swapped.

| Role | Input | Output |
|---|---|---|
| chain step | `P(18) ‖ 0x00 ‖ ℓ(4) ‖ i(1) ‖ k(1) ‖ x(23)`, 48 bytes | first 23 bytes |
| leaf | `P(18) ‖ 0x01 ‖ 0x00 ‖ ℓ(4) ‖ pk_0 ‖ … ‖ pk_35`, 852 bytes | first 23 bytes |
| node | `P(18) ‖ 0x01 ‖ l(1) ‖ j(4) ‖ left(23) ‖ right(23)`, 70 bytes | first 23 bytes |
| message | `ρ(21) ‖ P(18) ‖ 0x02 ‖ ℓ(4, LE) ‖ m(32)`, 76 bytes | first 144 bits |

`ℓ` is the leaf index, the paper's epoch; `i` the chain, `k` the chain
position, `l` the tree level, `j` the node index within the level. Every
role has its own input length, so inputs of different roles are distinct
strings whatever their content.

## Keys

Construction 3 Gen: every chain start `sk[ℓ][i]`, 23 bytes, and the
18-byte parameter `P` are sampled from the operating system's random
source, `getrandom` in Rust and `randomFillSync` in TypeScript. The chain
starts are kept leaf-major, chain-major: 828 bytes per leaf, 828 bytes
for `winternitz`, 211 968 for `xmss`. There is no seed.

```text
pk[ℓ][i]   = step(ℓ, i, 15, … step(ℓ, i, 1, sk[ℓ][i]))   chain ends, 15 steps
leaf[ℓ]    = leaf hash of pk[ℓ][0..36]
node[l][j] = node hash of node[l−1][2j], node[l−1][2j+1], l = 1 … h
public key = root ‖ P,  root = leaf[0] when h = 0, node[h][0] when h = 8
```

`step(ℓ, i, k, x)` is the chain-step hash with position `k`: the step
into position `k` carries tweak `k`, as hash-sig's `chain` and
Construction 2.

## Signing

Construction 3 Sig:

1. Sample a 21-byte salt `ρ` from the random source, at most `K` times.
2. `x = encode(ρ, P, ℓ, m)`: the 18 bytes of the message hash as 36
   nibbles, low nibble of each byte first (hash-sig's `bytes_to_chunks`).
   Accept iff `Σ x_i = T`; otherwise sample again. Under a uniform model
   one salt in ~111 is accepted and all `K` miss once in e^36.8, in which
   case nothing is recorded and no leaf is spent.
3. Record `ρ`, `m` and the next leaf in the key file (below), then
   `σ_i = step(ℓ, i, x_i, … step(ℓ, i, 1, sk[ℓ][i]))`, the chain walked to
   position `x_i`; `σ_i = sk[ℓ][i]` when `x_i = 0`.
4. `xmss` only: the authentication path, `node[l][(ℓ >> l) ^ 1]` for
   `l = 0 … 7`, leaf level first.

Signing the recorded message again uses the recorded `ρ` and returns the
same bytes. The raw operation, `sign_at` and `signAt`, takes an accepted
`ρ`, refuses `ℓ ≥ 2^h` or a `ρ` that misses the target sum, and records
nothing.

## Verification

Construction 3 Ver, constant work for an accepted signature:

1. `xmss`: reject if `ℓ ≥ 256`.
2. `x = encode(ρ, P, ℓ, m)`; reject if `Σ x_i ≠ T`.
3. `pk_i = step(ℓ, i, 15, … step(ℓ, i, x_i + 1, σ_i))`: walk each
   element from `x_i` to 15, 243 steps in total.
4. Leaf hash of the 36 ends. `xmss`: climb, at level `l = 1 … 8` with
   index `j = ℓ >> l`, hashing `(current, sibling)` when bit `l − 1` of
   `ℓ` is 0 and `(sibling, current)` when it is 1.
5. Accept iff the result equals the public key's first 23 bytes.

## Wire formats

| Object | Layout | Bytes |
|---|---|---:|
| public key | `root(23) ‖ P(18)` | 41 |
| `winternitz` signature | `ρ(21) ‖ σ_0 ‖ … ‖ σ_35` | 849 |
| `xmss` signature | `ℓ(4) ‖ ρ(21) ‖ σ_0 ‖ … ‖ σ_35 ‖ path_0 ‖ … ‖ path_7` | 1,037 |
| key file | `version(1) = 2 ‖ h(1) ‖ P(18) ‖ next leaf(4) ‖ message flag(1) ‖ last message(32) ‖ its salt(21) ‖ chain starts` | 906 or 212,046 |

## Key file and lock

The key file is the key: it holds every chain start and is the only copy.
It is created with mode 0600 and replaced atomically on every spent leaf:
temp file `<file>.tmp`, fsync, rename, directory fsync. The message flag
is 0 before the first signature, with the message and salt fields zero,
and 1 after, with the last message and its accepted salt stored whole.
A reader refuses a file whose length, version or `h` is wrong, whose
flag disagrees with the next leaf, or whose salt does not encode the
recorded message under leaf `next leaf − 1` to the target sum. `h` tags
the instance so a file opens only under its own.

The open signer holds a kernel lock on `<file>.lock`, the same in both
packages: open or create the sidecar without truncating it, take
`flock(LOCK_EX | LOCK_NB)` on that descriptor, Rust's `File::try_lock`
and libc's `flock` through Bun's FFI, and keep the descriptor for the
signer's lifetime; a contended lock refuses before the record is read.
Release closes the descriptor. The sidecar is permanent and is never
deleted, renamed or replaced, since a new file at the path would be a
second lock; its existence and content mean nothing. When a holder dies
the kernel releases the lock and the next signer resumes from the
record's next leaf. `flock` is advisory and per host: signers of one
file share a host and a local filesystem. The TypeScript signer needs
Bun on a unix host for the call; verification and key generation run
anywhere.

## Vectors

`tests/sampled.json` pins signing in both packages from explicit,
deliberately non-random test inputs stated in its `test_inputs` field:
an `xmss` key whose chain-start byte `i` is `(i mod 251) xor 7` with `P`
eighteen bytes of `0x57`, five leaves signed over the message `leaf` as
a little-endian `u32` padded to 32 bytes, each with the first salt, a
little-endian counter padded to 21 bytes, that encodes to the target
sum; and the signature that `tests/winternitz.key`, a key file sampled
at creation and then signed once, returns for its recorded message.
`cargo test --lib regenerate_sampled_vectors -- --ignored` rewrites both.

`tests/hash-sig.json` holds the public key and five signatures of a key
generated by hash-sig at commit `e66a485` with `sha3::Sha3_256` replaced
by `sha3::Keccak256` in its three `sha.rs` files, at the type
`GeneralizedXMSSSignatureScheme<ShaPRF<23, 21>, TargetSumEncoding<ShaMessageHash<18, 21, 36, 4>, 297>, ShaTweakHash<18, 23>, 8>`
from `StdRng` seed 2025; the `source` field records this, and its
`prf_key` is hash-sig's own key derivation, not used here. Both packages
verify the signatures: the message hash, chunking, chains, leaf, tree and
public key are the reference implementation's byte for byte.
`tests/vectors.json` holds twenty further signatures from an earlier
seed-derived key generation, kept as verification fixtures; `tests/sbpf.rs`
embeds its case 1 of each instance and its case 0 message as the one to
reject.

## Differences from the paper and from hash-sig

| Where | Paper / hash-sig | Here | Why |
|---|---|---|---|
| hash function | SHA3-256 (§7.2), `sha3::Sha3_256` | Keccak-256 | the sponge Solana provides; software SHA3-256 exhausts the transaction budget; SECURITY.md §4.1 |
| chain starts and salts | sampled (Construction 3); hash-sig derives both from a PRF key (Remark 7) | sampled, as the paper | SECURITY.md §4.2 |
| lifetime | 2^18 and up in hash-sig's instantiations | 2^0 and 2^8 | lengths from the same script at these lifetimes |
| salt trials | `K ≤ 4096` (§8); 100 000 in hash-sig | 4096 | the paper's |
| wire format | epoch supplied beside the signature | epoch inside the `xmss` signature, absent at height 0 | one buffer per instruction |
| key file, lock | none | above | local additions |

Everything else is hash-sig's, and its signatures verify here.

## Cost

agave charges every hash syscall, `sol_keccak256` included, 85 CU plus
`max(10, len / 2)` per slice.

| Verification step | Syscalls | CU |
|---|---:|---:|
| message hash, four slices | 1 | ~130 |
| chain steps, one 48-byte slice each | 243 | ~26,500 |
| leaf hash, three slices | 1 | ~520 |
| tree nodes, `xmss` only, four slices each | 8 | ~1,000 |

Measured under Mollusk with platform-tools v1.56: 34,331 CU for
`winternitz`, 35,971 for `xmss`, 879 for a message off target. The
remainder over the syscalls is SBPF instruction count. Measured and
declined: three-slice chain steps, where the 10 CU minimum per slice
exceeds the one copy; copying the chain ends into one leaf buffer, 200 to
500 CU more than a third slice; SHA3-256 in software on the SBPF target,
about 11,600 CU per call, which exhausts the 1,400,000 CU transaction
maximum inside one verification. The earlier SHA-256 instantiation with
35 chains and `T = 325` measured 29,524 and 31,224 CU; the difference is
43 more chain steps at the paper's operating point.
