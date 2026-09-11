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
| `v` | 35 | chains, one per digest nibble |
| `2^w` | 16 | chain positions, `w = 4` |
| `T` | 325 | required nibble sum, Construction 6 |
| `n` | 24 B | chain element |
| `P` | 24 B | public parameter |
| `ρ` | 24 B | salt |
| `h` | 0 or 8 | tree height: `winternitz`, `xmss` |
| `K` | 2^16 | salt trials before signing fails |

Integers in hash inputs are big-endian; the leaf index in an `xmss`
signature is little-endian.

## Hash inputs

Every structured input to SHA-256 begins with a role byte and has
fixed-width fields before any variable one, so inputs of different roles
and positions are distinct byte strings. The role bytes are §7.1's domain
bytes, eqs. (17) to (19), plus RFC 8391's PRF tag; they sit at offset 0
where §7.2.2 puts them after `P`.

| Role | Input | Output |
|---|---|---|
| chain step | `0x00 ‖ ℓ(4) ‖ i(1) ‖ k(1) ‖ P(24) ‖ x(24)`, 55 bytes | first 24 bytes |
| leaf | `0x01 ‖ 0x00 ‖ ℓ(4) ‖ P(24) ‖ pk_0 ‖ … ‖ pk_34`, 870 bytes | 32 bytes |
| node | `0x01 ‖ l(1) ‖ j(4) ‖ P(24) ‖ left(32) ‖ right(32)`, 94 bytes | 32 bytes |
| message | `HMAC-SHA-256(key = 0x02 ‖ ℓ(4) ‖ ρ(24) ‖ P(24), m)` | first 140 bits |
| parameter | `0x03 ‖ 0x00 ‖ h(1) ‖ seed(32)` | first 24 bytes |
| chain start | `0x03 ‖ 0x01 ‖ h(1) ‖ ℓ(4) ‖ i(1) ‖ seed(32)` | first 24 bytes |
| salt | `0x03 ‖ 0x02 ‖ h(1) ‖ ℓ(4) ‖ ctr(4) ‖ SHA-256(m) ‖ seed(32)` | first 24 bytes |

`HMAC-SHA-256(K, m) = SHA-256((K ‖ 0¹¹) ⊕ 0x5c⁶⁴ ‖ SHA-256((K ‖ 0¹¹) ⊕ 0x36⁶⁴ ‖ m))`,
RFC 2104 with the 53-byte key zero-padded to one block. Its two SHA-256
calls begin with `0x02 ⊕ 0x36` and `0x02 ⊕ 0x5c`, disjoint from the other
roles. The one unstructured hash is the `SHA-256(m)` inside the salt
input; it is public.

## Keys

From a 32-byte seed and the instance height `h`:

```text
P          = parameter(seed, h)
sk[ℓ][i]   = start(seed, h, ℓ, i)                        chain starts
pk[ℓ][i]   = step(ℓ, i, 15, … step(ℓ, i, 1, sk[ℓ][i]))   chain ends, 15 steps
leaf[ℓ]    = leaf hash of pk[ℓ][0..35]
node[l][j] = node hash of node[l−1][2j], node[l−1][2j+1], l = 1 … h
public key = root ‖ P,  root = leaf[0] when h = 0, node[h][0] when h = 8
```

`step(ℓ, i, k, x)` is the chain-step hash with position `k`: the step
into position `k` carries tweak `k`, as hash-sig's `chain` and
Construction 2. Key derivation is Remark 7's PRF, extended to salts; `h`
is in every derivation so one seed gives unrelated keys under the two
instances.

## Signing

Construction 3 Sig, deterministic in seed, leaf and message:

1. For `ctr = 0, 1, …, K − 1`: `ρ = salt(seed, h, ℓ, ctr, SHA-256(m))`.
2. `x = encode(ρ, P, ℓ, m)`: the first 140 bits of the message hash as 35
   nibbles, low nibble of each byte first (hash-sig's `bytes_to_chunks`).
   Accept iff `Σ x_i = T`; otherwise next `ctr`. Under a uniform model
   one salt in ~940 is accepted and all `K` miss once in e^70.
3. `σ_i = step(ℓ, i, x_i, … step(ℓ, i, 1, sk[ℓ][i]))`, the chain walked to
   position `x_i`; `σ_i = sk[ℓ][i]` when `x_i = 0`.
4. `xmss` only: the authentication path, `node[l][(ℓ >> l) ^ 1]` for
   `l = 0 … 7`, leaf level first.

## Verification

Construction 3 Ver, constant work for an accepted signature:

1. `xmss`: reject if `ℓ ≥ 256`.
2. `x = encode(ρ, P, ℓ, m)`; reject if `Σ x_i ≠ T`.
3. `pk_i = step(ℓ, i, 15, … step(ℓ, i, x_i + 1, σ_i))`: walk each
   element from `x_i` to 15, 200 steps in total.
4. Leaf hash of the 35 ends. `xmss`: climb, at level `l = 1 … 8` with
   index `j = ℓ >> l`, hashing `(current, sibling)` when bit `l − 1` of
   `ℓ` is 0 and `(sibling, current)` when it is 1.
5. Accept iff the result equals the public key's first 32 bytes.

## Wire formats

| Object | Layout | Bytes |
|---|---|---:|
| public key | `root(32) ‖ P(24)` | 56 |
| `winternitz` signature | `ρ(24) ‖ σ_0 ‖ … ‖ σ_34` | 864 |
| `xmss` signature | `ℓ(4, LE) ‖ ρ(24) ‖ σ_0 ‖ … ‖ σ_34 ‖ path_0 ‖ … ‖ path_7` | 1,124 |
| key file | `version(1) = 1 ‖ h(1) ‖ seed(32) ‖ next leaf(4, LE) ‖ digest flag(1) ‖ digest(32)` | 71 |

The key file is written with mode 0600 and replaced atomically: temp
file, fsync, rename, directory fsync. A `.lock` sidecar next to it is held
by the open signer, through the OS file lock in Rust and an exclusively
created file holding the pid in Node. The digest is `SHA-256` of the last
message signed, flag 0 before the first signature.

## Vectors

`tests/vectors.json` holds three `winternitz` and three `xmss` cases with
`seed`, `message`, `public_key`, `signature` and, for `xmss`, `leaf` as a
number. `tests/winternitz.key` is the key file of `winternitz` case 1
after signing its message. `cargo test --lib regenerate_vectors --
--ignored` rewrites both; `tests/sbpf.rs` embeds case 1 of each corpus as
byte arrays that must be regenerated with them.

## Departures from the paper and hash-sig

| Where | Paper / hash-sig | Here | Why |
|---|---|---|---|
| hash function | SHA-3 (§7.2) | SHA-256 | cheapest Solana syscall; see SECURITY.md |
| input order | `P ‖ tweak ‖ m`, `ρ ‖ P ‖ tweak ‖ m` | `tweak ‖ P ‖ m`; message hash keyed by `tweak ‖ ρ ‖ P` | role byte at offset 0 |
| message hash | plain hash (§7.2.1) | HMAC-SHA-256 | closes Merkle–Damgård herding; see SECURITY.md |
| leaf index encoding | little-endian in hash-sig's message tweak | big-endian in every hash input | one convention |
| output widths | one `n` | 24-byte chains, 32-byte nodes | full digest for the tree; see SECURITY.md |
| key material | sampled (Construction 3), PRF allowed (Remark 7) | seed-derived, salts included, height bound | one seed per key; see SECURITY.md |
| target sum | `⌈δ · v(2^w − 1)/2⌉`, δ ≤ 1.1 | 325, δ = 1.24 | 200 verifier steps |

Chain and tree tweak layouts, nibble order and the chain-step convention
match hash-sig. Vectors are not interchangeable with it.

## Cost

agave charges a `sol_sha256` call 85 CU plus `max(10, len / 2)` per slice.

| Verification step | Syscalls | CU |
|---|---:|---:|
| message hash, HMAC | 2 | ~270 |
| chain steps, one 55-byte slice each | 200 | ~22,400 |
| leaf hash, three slices | 1 | ~530 |
| tree nodes, `xmss` only | 8 | ~1,000 |

Measured under Mollusk with platform-tools v1.56: 29,524 CU for
`winternitz`, 31,224 for `xmss`, 1,076 for a message off target. The
remainder over the syscalls is SBPF instruction count; a bare loop of
chain-step syscalls measures within 2.5k CU of `verify`. Measured and
declined: three-slice chain steps, where the 10 CU minimum per slice
exceeds the one copy; copying the chain ends into one leaf buffer, 200 to
500 CU more than a third slice; a byte loop for the HMAC pads, 1,000 CU
more than eight 64-bit XORs; and shrinking every length to the paper's
exact bound, 9% for one to two bits of margin.
