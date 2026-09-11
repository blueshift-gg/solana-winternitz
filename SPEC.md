# Specification

Every byte of the scheme as implemented, for a second implementer. The
TypeScript package was written from this document and must reproduce
[`tests/vectors.json`](tests/vectors.json) and
[`tests/winternitz.key`](tests/winternitz.key). References are to
[DKKW25](https://eprint.iacr.org/2025/055) and to its reference
implementation [hash-sig](https://github.com/b-wagn/hash-sig).

## Parameters

| Symbol | Value | Meaning |
|---|---:|---|
| `v` | 36 | chains, one per nibble of hash-sig's 18-byte message hash |
| `2^w` | 16 | chain positions, `w = 4` |
| `T` | 297 | required nibble sum, `⌈1.1 · 36 · 15 / 2⌉`, Construction 6 at §8's `δ = 1.1` |
| `n` | 23 B | chain element, leaf and node |
| `P` | 18 B | public parameter |
| `ρ` | 21 B | salt |
| `l_msg` | 32 B | message, hash-sig's `MESSAGE_LENGTH`: the caller's digest of what it acts on (Remark 1) |
| `h` | 0 or 8 | tree height: `winternitz`, `xmss` |
| `K` | 4096 | salt trials before signing fails, §8 |

The hash is Keccak-256, the `sol_keccak256` syscall, standing in for the
paper's SHA3-256 (§7.2): the same permutation, rate and capacity, padding
byte `0x01` for `0x06`. Every integer in a hash input or a wire format is
big-endian except the leaf index inside the message tweak, little-endian
as in hash-sig's `ShaMessageHash`.

## Hash inputs

Chain, leaf and node inputs are `P ‖ T ‖ M` and the message input
`ρ ‖ P ‖ T ‖ m`, §7.2.2 and §7.2.1, with the tweaks `T` of §7.1: a domain
byte, eqs. (17) to (19), then the position. Outputs are truncated to `n`
bytes, or to `v · w = 144` bits for the message. Chain starts and salts
are Remark 7's PRF over the seed with hash-sig's `ShaPRF` layout: its
16-byte domain separator `00 01 12 ff 00 01 fa ff 00 af 12 ff 01 fa ff 00`,
a purpose byte, the key, the epoch, then the chain index as a `u64` or the
message and a `u64` counter. These are hash-sig's `ShaTweakHash<18, 23>`,
`ShaMessageHash<18, 21, 36, 4>` and `ShaPRF<23, 21>` with the hash
swapped; `tests/hash-sig.json` holds its key and signatures.

| Role | Input | Output |
|---|---|---|
| chain step | `P(18) ‖ 0x00 ‖ ℓ(4) ‖ i(1) ‖ k(1) ‖ x(23)`, 48 bytes | first 23 bytes |
| leaf | `P(18) ‖ 0x01 ‖ 0x00 ‖ ℓ(4) ‖ pk_0 ‖ … ‖ pk_35`, 852 bytes | first 23 bytes |
| node | `P(18) ‖ 0x01 ‖ l(1) ‖ j(4) ‖ left(23) ‖ right(23)`, 70 bytes | first 23 bytes |
| message | `ρ(21) ‖ P(18) ‖ 0x02 ‖ ℓ(4, LE) ‖ m(32)`, 76 bytes | first 144 bits |
| chain start | `sep(16) ‖ 0x00 ‖ seed(32) ‖ ℓ(4) ‖ i(8)`, 61 bytes | first 23 bytes |
| salt | `sep(16) ‖ 0x01 ‖ seed(32) ‖ ℓ(4) ‖ m(32) ‖ ctr(8)`, 93 bytes | first 21 bytes |

`ℓ` is the leaf index, the paper's epoch; `i` the chain, `k` the chain
position, `l` the tree level, `j` the node index within the level. Every
role has its own input length, so inputs of different roles are distinct
strings whatever their content.

## Keys

From a 32-byte seed and an 18-byte parameter `P`, both sampled by the
caller:

```text
sk[ℓ][i]   = start(seed, ℓ, i)                           chain starts
pk[ℓ][i]   = step(ℓ, i, 15, … step(ℓ, i, 1, sk[ℓ][i]))   chain ends, 15 steps
leaf[ℓ]    = leaf hash of pk[ℓ][0..36]
node[l][j] = node hash of node[l−1][2j], node[l−1][2j+1], l = 1 … h
public key = root ‖ P,  root = leaf[0] when h = 0, node[h][0] when h = 8
```

`step(ℓ, i, k, x)` is the chain-step hash with position `k`: the step
into position `k` carries tweak `k`, as hash-sig's `chain` and
Construction 2.

## Signing

Construction 3 Sig, deterministic in seed, parameter, leaf and message,
as hash-sig's:

1. For `ctr = 0, 1, …, K − 1`: `ρ = salt(seed, ℓ, m, ctr)`.
2. `x = encode(ρ, P, ℓ, m)`: the 18 bytes of the message hash as 36
   nibbles, low nibble of each byte first (hash-sig's `bytes_to_chunks`).
   Accept iff `Σ x_i = T`; otherwise next `ctr`. Under a uniform model
   one salt in ~111 is accepted and all `K` miss once in e^36.8.
3. `σ_i = step(ℓ, i, x_i, … step(ℓ, i, 1, sk[ℓ][i]))`, the chain walked to
   position `x_i`; `σ_i = sk[ℓ][i]` when `x_i = 0`.
4. `xmss` only: the authentication path, `node[l][(ℓ >> l) ^ 1]` for
   `l = 0 … 7`, leaf level first.

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
| key file | `version(1) = 1 ‖ h(1) ‖ seed(32) ‖ P(18) ‖ next leaf(4) ‖ message flag(1) ‖ last message(32)` | 89 |

The key file is written with mode 0600 and replaced atomically: temp
file, fsync, rename, directory fsync. A `.lock` sidecar next to it is held
by the open signer, through the OS file lock in Rust and an exclusively
created file holding the pid in Node. The last message signed is stored
whole, flag 0 before the first signature. `h` tags the instance so a file
opens only under its own; it enters no derivation.

## Vectors

`tests/vectors.json` holds ten cases per instance with `seed`,
`parameter`, `message`, `public_key`, `signature` and, for `xmss`, `leaf`
as a number: three named cases, then seven under one `xmss` key at leaves
2 to 8. `tests/winternitz.key` is the key file of `winternitz` case 1
after signing its message. `cargo test --lib regenerate_vectors --
--ignored` rewrites both; `tests/sbpf.rs` embeds case 1 of each corpus as
byte arrays, and case 0's message as the one it must reject, all
regenerated with them.

`tests/hash-sig.json` holds the PRF key, parameter, public key and five
signatures of a key generated by hash-sig at commit `e66a485` with
`sha3::Sha3_256` replaced by `sha3::Keccak256` in its three `sha.rs`
files, at the type
`GeneralizedXMSSSignatureScheme<ShaPRF<23, 21>, TargetSumEncoding<ShaMessageHash<18, 21, 36, 4>, 297>, ShaTweakHash<18, 23>, 8>`
from `StdRng` seed 2025; the `source` field records this. Both packages
build the key from the PRF key and parameter and reproduce the public key
and every signature byte for byte.

## Departures from the paper and hash-sig

| Where | Paper / hash-sig | Here | Why |
|---|---|---|---|
| hash function | SHA3-256 (§7.2), `sha3::Sha3_256` | Keccak-256 | the sponge Solana provides; software SHA3-256 exhausts the transaction budget; see SECURITY.md |
| chain starts and salts | sampled (Construction 3), any PRF for starts (Remark 7); hash-sig's `ShaPRF` | hash-sig's `ShaPRF` | one seed per key; see SECURITY.md |
| lifetime | 2^18 and up in hash-sig's instantiations | 2^0 and 2^8 | lengths from the same script at these lifetimes |
| salt trials | `K ≤ 4096` (§8); 100 000 in hash-sig | 4096 | the paper's; the same salts up to there |

Everything else is hash-sig's, and its keys and signatures are
reproduced here.

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
