# Security analysis

This document states the security claim of the crate, the model in which
it holds, the bound it rests on evaluated at the implemented parameters,
the arguments for each point at which the implementation differs from
[DKKW25] and its reference implementation [hash-sig], the attacks that
were considered with their costs, the operational assumptions the model
requires, and what remains unproven. The code has not been audited.
Byte-level definitions are in [SPEC.md](SPEC.md).

## 1. Scheme

The crate implements the generalized XMSS signature of [DKKW25,
Construction 3] with the target-sum encoding of [DKKW25, Construction 6]
and lifetime `L ∈ {1, 2^8}`, in the SHA-3 instantiation of [DKKW25, §7.2]
with Keccak-256 in place of SHA3-256 (§4.1). Tweaks are the byte strings
of §7.1; `ℓ` is the leaf index, the paper's epoch. Messages are 32-byte
digests, `l_msg = 256` as in [hash-sig], the compression of longer
inputs being the caller's as Remark 1 prescribes. The lengths and the
key derivation are those of [hash-sig]'s SHA-3 target-sum instantiation
for `w = 4`, the lengths recomputed for these lifetimes.

| Function | Definition | Role in [DKKW25] |
|---|---|---|
| `Th(P, t, x) = Keccak-256(P ‖ t ‖ x)[0..184]` | chain step, leaf and node; `t` a chain or tree tweak | `Th` of §7.2.2, Constructions 1 and 2 |
| `Th_msg(P, ℓ, ρ, m) = Keccak-256(ρ ‖ P ‖ 0x02 ‖ ℓ ‖ m)[0..144]` | encoding input, read as 36 nibbles | `Th_msg` of §7.2.1, Construction 6 |
| `Φ_seed(label) = Keccak-256(sep ‖ purpose ‖ seed ‖ label)[0..]` | chain starts, salt candidates; [hash-sig]'s `ShaPRF` | Remark 7 |

| Parameter | Value | Requirement | Margin |
|---|---:|---|---:|
| `v · w`, digest bits | 144 | ≥ 137.64, eq. (13) | 6.4 bits |
| `log₂ |R|`, salt bits | 168 | ≥ 167.81, eq. (14), `L = 2^8`, `K = 2^12` | 0.2 bits |
| `n`, chain element bits | 184 | ≥ 182.15, eq. (15), `L = 2^8` | 1.9 bits |
| `log₂ |P|`, parameter bits | 144 | ≥ 141.64, eq. (16) | 2.4 bits |
| `T`, target sum | 297 | Construction 6 at `δ = 1.1`, [DKKW25, §8] | see below |

Requirements are Parameter Requirements 2 and 3 of [DKKW25] at
`k_C = 128`, `k_Q = 64`, evaluated by `src/tests.rs` and equal to the
output of [hashsig-parameters] for these inputs, rounded up to bytes as
[hash-sig] rounds. `v = 36` is [hash-sig]'s 18-byte message hash; the
bound alone allows 35, which no whole-byte truncation of the hash gives.
Parameter Requirement 3 is stated for `L, v ≥ 2`; the `winternitz`
instance at `L = 1` uses the `L = 2^8` widths, which meet every
requirement at `L = 1` since each bound is non-decreasing in `log L`.

`T = 297` exceeds the mean nibble sum `270` by the factor `δ = 1.1` of
[DKKW25, §8] and [hash-sig]'s `Off10` instantiations. By Lemma 7 the set
of accepted vectors is incomparable, which replaces the Winternitz
checksum, and its size is the coefficient `η_T` of `x^297` in
`(1 + x + … + x^15)^36`, `2^137.20`, so a uniform digest is accepted with
probability `2^-6.80`, once in 111 trials. By Lemma 3 the signer fails
with probability `(1 − 2^-6.80)^K = e^-36.8` at `K = 2^12`. By Lemma 8
the encoding's target collision resistance reduces to `T₂` below
regardless of `T`, so `T` sets signer and verifier work only: 243 chain
steps per verification.

## 2. Model

Security is synchronized strong unforgeability, [DKKW25, Definition 8].
The adversary receives `pk = (root, P)`, may query `Sig(ℓ, m)` at most
once per leaf `ℓ`, and wins with `(ℓ*, m*, σ*)` such that `Ver` accepts
and `(m*, σ*)` is not the pair returned for `ℓ*`. Queries to the hash are
counted as `q`, classical or quantum; signing queries are classical and
number `q_s ≤ L`. Theorem 5 charges the reduction `q' = q + pK` hash
queries, `K` per signing query whether or not the signer's grinding stops
early; the figures of §3 divide by this charged `t ≥ q + q_s K`, an
accounting convention, not measured work.

Outside the model, and treated in §6: replay of a valid signature, which
the definition does not count as a forgery; more than one signature per
leaf; keys that are not independently generated; loss or rollback of the
signer's record.

## 3. The bound

[DKKW25, Theorem 1] with Corollary 2, plus the pseudorandomness term of
Remark 7, gives for every adversary `A`

```
Adv(A) ≤ Δ_PRF + T₁ + T₂ + 2·T₃ + L·v·2^w · (2^w · T₅ + T₆)
```

where the terms are advantages of reductions `B₁ … B₆` against the
following properties, each with the number of targets shown.

| Term | Property, [DKKW25] definition | Function | Targets |
|---|---|---|---:|
| `T₁` | multi-target collision resistance, Def. 3 | `Th`, tree tweaks | `2·L·v·2^w` |
| `T₂` | target collision resistance with random sampling, Def. 6, `K` trials | `Th_msg` | `q_s` |
| `T₃` | multi-target collision resistance, Def. 3 | `Th`, chain tweaks | `L·v·2^w` |
| `T₅` | undetectability, Def. 5 | `Th`, chain tweaks | 1 |
| `T₆` | preimage resistance, Def. 4 | `Th`, chain tweaks | 1 |

Substituting the random-oracle bounds of [DKKW25, Table 1] with
`|H_msg| = 2^144`, `|H| = 2^184`, `|R| = 2^168`, `|P| = 2^144`,
`a_L = L·v·2^w = 147 456`, `p = q_s = 2^8`, `pK = 2^20`, and bounding every
query count by `t`:

```
classical:  (Adv − Δ_PRF)/t ≤ 1/2^144 + 6/2^144 + pK/2^168 + (6 + a_L·(2^w + 2))/2^184
                            ≤ 2^-144 + 2^-141.4 + 2^-148 + 2^-162.7  ≈ 2^-141.2

quantum:    Adv − Δ_PRF ≤ α·t² + β·t + γ·√t,
            α = 8/2^144 + 96/2^144 + (96 + 8·a_L)/2^184 ≈ 2^-137.3,
            β = 12·a_L·(2^w + 1)/2^92 ≈ 2^-67.2,
            γ = (3/2)·pK/2^84 ≈ 2^-63.4,
            so (Adv − Δ_PRF)/t ≤ 2^-67.1 for 2^20 ≤ t ≤ 2^64 and ≤ 1/t beyond.
```

The `6/2^144` and `96/2^144` terms are the `2q/|P|` and `32q²/|P|` parts
of the collision bounds, one for `T₁` and two for `T₃`: the classical
level, 141 bits, is set by the parameter and digest widths together,
both 144 bits as eqs. (13) and (16) require. The quantum level is the
64-bit target, with 67 bits in the regime where the bound is not
trivial; the `γ` term is why `t` is taken at or above `pK`, the charged
cost of the signing queries. `Δ_PRF` is not quantified and stays on the
left of both inequalities; §4.2 states what it assumes.

Two things are outside the bound. The application's hash of its payload
into the 32-byte message: a chosen-message collision on it costs `2^128`
classically and about `2^85` quantumly, at and above the targets, and is
A4's concern. And the model itself: these are heuristic figures in the
sense of the paper, the properties in the table being standard-model
assumptions on Keccak-256 under these input layouts, estimated by Table 1
with the hash modelled as a random oracle.

## 4. Differences from the paper and from hash-sig

What is not the paper's or hash-sig's, each treated below or in §6: the
hash function (§4.1); salts from the PRF where the paper samples them, as
hash-sig does (§4.2); lifetimes `2^0` and `2^8` with lengths recomputed
from the authors' script, where hash-sig ships `2^18` and up; `K = 4096`,
§8's parameter-setting assumption, where hash-sig allows 100 000 and
produces the same salts up to there; the wire formats, which carry the
epoch inside the signature, and the signer's key file and lock (§6).

### 4.1 Keccak-256 for SHA3-256

**Claim.** This is a Keccak-256 instantiation of the paper's generic
construction. The reduction of Theorem 1 applies under the properties of
§3 assumed for these Keccak-256 functions and for `Φ_seed`. Matching
sponge parameters and related padding support analogous security
estimates; they do not prove equal concrete classical or quantum security
to SHA3-256, and the paper proves nothing about the concrete SHA3-256
functions either.

**What is the same.** SHA3-256 [FIPS202] is `Keccak[c = 512](M ‖ 01)`;
Keccak-256, Ethereum's and Solana's `sol_keccak256`, is
`Keccak[c = 512](M)`, both under `pad10*1`. The permutation
`Keccak-p[1600, 24]`, the 1088-bit rate, the 512-bit capacity and the
256-bit output are identical; the suffix separates SHA3-256 from SHAKE,
which is not used here. In the classical ideal-permutation model both
are sponges with an admissible padding, and [BDPV08, Theorem 2] gives
each the same indifferentiability loss `O(N²/2^512)` in permutation
calls `N`. That model replaces the fixed permutation by a random one and
says nothing about concrete security, and its bound does not carry to
quantum queries: the quantum ideal-permutation result of [ACMT25,
Theorem 7.22] is vacuous at this rate and capacity for `q = 2^64`, so the
quantum figures of §3 rest on the QROM heuristic of Table 1 applied to
Keccak-256, as the paper applies it to SHA3-256. The cryptanalytic record
of §7.2.3 concerns the permutation and capacity and reads the same for
both; the designers' argument that the suffix restricts Keccak's domain
supports the suffixed function from the plain one, not the converse.

**Why not SHA3-256 itself.** Solana has no SHA3-256 syscall. SHA3-256 in
software on the SBPF target measures about 11,600 CU per call, and one
verification makes 245 or 253 calls; both verifiers exhausted the
1,400,000 CU transaction maximum (§8). The suffix cannot be produced
through the Keccak-256 syscall, which appends its own padding.

### 4.2 Seed-derived chain starts and salts

**Claim.** Replacing the independently sampled chain starts and salt
candidates of Construction 3 by `Φ_seed` costs the additive term
`Δ_PRF`, the advantage of distinguishing `Φ_seed` from a random function
on the labels the scheme uses. `P` is sampled by the caller as
Construction 3 samples it.

**Argument.** `Φ_seed` is [hash-sig]'s `ShaPRF` with its hash swapped:
its 16-byte domain separator, a purpose byte, the key, then `(ℓ, i)` for
chain starts and `(ℓ, m, ctr)` for salt candidates; a key evaluates at
most `L·v + q_s·K` labels. In the hybrid where `Φ_seed` is a random
function, every chain start and every salt candidate is independent and
uniform, which is the distribution Construction 3 samples, provided the
labels are distinct. Distinct purposes and chain indices separate the
starts; for salts, one signing query per leaf makes `(ℓ, ctr)` distinct
across the whole game, so the message in the label is not needed for
distinctness. Remark 7 of [DKKW25] covers the chain starts; [hash-sig]
derives its salts the same way, and the extension of the argument to
salts is the paragraph above. Unpredictability of salts would not
suffice: a single unknown salt repeated for every counter is
unpredictable and yields one grinding attempt.

The PRF is keyed by the seed alone, as [hash-sig]'s is, so the
`winternitz` key and the `xmss` key built from one seed and one `P` share
leaf 0, exactly as two [hash-sig] keys of different lifetimes built from
one PRF key would. A5 therefore requires one seed per key. The
pseudorandomness of `Φ_seed`, classical and quantum, is an assumption of
this crate, as the pseudorandomness of `ShaPRF` is one of [hash-sig]; a
quantum distinguisher also evaluates the public hash, so the assumption
must be made in that setting.

### 4.3 Domain separation

Inputs are laid out as [DKKW25, §7.2] specifies: `P ‖ t ‖ x` with the
domain byte of §7.1 first in every tweak, and `ρ ‖ P ‖ t ‖ m` for the
message. Every role has its own fixed input length, 48, 852 and 70 bytes
for chain steps, leaves and nodes, 76 for the message hash, 61 and 93 for
the two PRF purposes, so inputs of different roles are distinct strings
whatever their content, and within a role the fixed-width tweak
separates positions. The message input begins with the salt, which a
forger chooses, exactly as in §7.2.1; the paper's own note applies, that
no domain separation between the spaces of the two functions is added,
and none of the reductions in §3 requires it. The argument is specific
to these lengths; another parameter set needs its own.

## 5. Attacks considered

| Attack | Requires | Classical | Quantum | Status |
|---|---|---:|---:|---|
| second preimage of one signed encoding | one signature | `2^144` | `2^72` | generic, §3 |
| collision on `P`-dependent targets, the `2q/|P|` terms | one signature | `2^143` | `2^70` | §3, eq. (16) |
| herding across `t` signed leaves | `t` signatures | none: sponge, [BDPV08]; `2^134.3` had the hash been SHA-256, §9 | | not applicable |
| chain preimage or undetectability | one signature | `2^184` per target, `2^163` after the proof's `L·v·2^(2w)` loss; eq. (15) requires `2^151.5` | `2^67` in the `β` term of §3 | covered |
| seed recovery from `pk` | public key | `2^184` constrained preimages, wrong root with overwhelming probability | | covered |
| leaf reuse, `k` signatures under one leaf | violation of A1 | table below | | outside the model |
| multi-user forgery against `U` keys | `U` public keys | single-key cost `/ U` at most | | §7 |
| rollback of the signer's record | violation of A2 | equals leaf reuse | | §6 |

**Leaf reuse.** Let `x^(1), …, x^(k)` be the encodings signed under one
leaf and `m_i = min_j x^(j)_i`. The revealed chain values reach every
`x` with `x_i ≥ m_i` for all `i`, so a forger needs a salt whose encoding
lies in `R(m) = { x ∈ [16]^36 : x ≥ m, Σ x_i = 297 }`, at
`2^144 / |R(m)|` hash evaluations, using public signatures only.
Measured on this crate at leaf 7 of one key:

| `k` | `Σ m_i` | `log₂ |R(m)|` | cost | run |
|---:|---:|---:|---:|---|
| 1 | 297 | 0 | `2^144` | |
| 2 | 219 | 91.3 | `2^52.7` | |
| 3 | 153 | 115.6 | `2^28.4` | |
| 4 | 120 | 122.7 | `2^21.3` | |
| 8 | 58 | 132.3 | `2^11.7` | forged in 7 503 trials, accepted |
| 16 | 31 | 134.8 | `2^9.2` | forged in 755 trials, accepted |

The cost for `k = 2` depends on the pair; the earlier 35-chain
instantiation measured `2^46.1` and `2^50.9` on two transcripts.

## 6. Operational assumptions

The model of §2 applies only if the following hold. Each names where the
crate enforces it and what §5 says about its violation.

- **A1, one message per leaf.** Enforced by `Signer`: a leaf is recorded
  as spent before its signature is released, the last message is
  repeated rather than re-signed, a different message on a spent leaf is
  refused, and one process holds a key file at a time through a `.lock`
  sidecar carrying its pid, the same protocol in both packages, so a file
  held by one implementation is refused by the other. Pid files assume
  one pid namespace: signers of one file share a host. `sign_at` bypasses
  all of this and is for tests. Violation: leaf reuse, §5.
- **A2, integrity of the signer's record.** The record holds the seed,
  `P`, the next leaf and the last message; a copy older than the latest
  signature reintroduces A1's violation. Not detectable locally; a lower
  bound from the verifier's last accepted leaf is checked by `floor`.
  Backups are of the record, never of the seed alone. Cf. [SP800-208,
  §8] on state management.
- **A3, verifier leaf policy.** The verifier retires leaves whose
  signatures are public, since a signature stays valid until it does. A
  strictly increasing leaf index retires every lower leaf on acceptance,
  including any reused one; a used-leaf bitmap admits out-of-order
  landing but retires only leaves that landed; requiring exactly the next
  leaf leaves no way to skip a leaf whose message can no longer be
  executed, so a changed message on that leaf is a reuse. The leaf index
  is a counter and must not be derived from a slot or the Solana epoch.
- **A4, message binding.** Everything the verifier acts upon is hashed
  into the 32-byte `m` by the application, with a collision-resistant
  hash as Remark 1 requires; `Keccak-256` of the payload is the natural
  choice. Replay protection, for example a sequence number in the
  payload, is the application's, as the model does not count replay as
  forgery.
- **A5, key independence.** One seed per key, and a fresh `P` per key,
  from the caller's randomness. The two instances share leaf 0 under one
  seed (§4.2); keys of different seeds are independent under `Δ_PRF`.

## 7. Open problems and limitations

- The properties of Keccak-256 in §3 under these input layouts, at
  184-bit truncation, are assumed, not proven; the paper's SHA3-256
  instantiation carries the same caveat.
- `Δ_PRF` for `Φ_seed`, classically and against quantum queries, is not
  quantified.
- Multi-user security is bounded only by the generic `log₂ U` loss.
- Signing time varies with the message and seed through the number of
  salt candidates tried; it reveals that number and nothing else. Seeds
  are overwritten when keys and signers are dropped; transient stack
  copies are not.
- Correctness with these constants is argued for `T = 297`; other targets
  change `η_T` and the required `K`.
- Mutual exclusion between the two signer implementations is checked
  outside CI (§8).

## 8. Verification record

Mechanically checked in the repository: eqs. (13) to (16) and `η_T`
(`src/tests.rs`); Keccak-256 against the known answers for the empty
string and `"abc"`, which SHA3-256 does not share; the SBPF syscall
number; a key generated by [hash-sig] at commit `e66a485` with its hash
swapped to Keccak-256, at these exact type parameters, whose public key
and five signatures both packages reproduce byte for byte from its PRF
key and parameter (`tests/hash-sig.json`); the vector corpus reproduced
by two implementations sharing no code; the SBPF verifier under Mollusk
against host-generated signatures, 34 331 and 35 971 CU; the lock
protocol against a live pid, an empty file, garbage and a dead pid in
both packages.

Checked outside CI through the public APIs: each package refuses a key
file the other holds, in both acquisition orders, and opens it once
released. Reproduced in this analysis: the leaf-reuse forgeries of §5 at
full parameters, accepted by the verifier; software SHA3-256 on the SBPF
target exhausting 1 400 000 CU in one verification, 12 454 CU for the
single message hash of a rejected signature.

## 9. Alternatives considered

SHA-256, with its cheaper appearance on Solana: rejected. Every hash
syscall costs the same 85 CU plus `max(10, len/2)` per slice, and the
plain Merkle–Damgård message hash admits herding across signed leaves at
about `2^134.3` [PKC22, KK06], reproduced at reduced parameters before
this instantiation was chosen; HMAC closes it at the price of leaving
§7.2. SHA3-256 in software on-chain: rejected by measurement, §4.1.
35 chains, the minimum of eq. (13): rejected, 4 bits of digest that the
reference implementation cannot express and 7 fewer chain steps. Fresh
random salts per signature: rejected, [hash-sig] derives them from its
PRF and the record-before-sign design needs signing to be a function of
the record. Messages of any length hashed inside `Th_msg`, with a height
label in the PRF separating the two instances: rejected in favour of
[hash-sig]'s layout, which the tests now reproduce; the salted `2^144`
bound on the message becomes the application's `2^128` collision bound
on its payload hash, the paper's own arrangement. An OS advisory lock on
the sidecar: rejected, Node has none, and two protocols on one file let
each implementation open a file the other held. Classical Winternitz
with checksum chains, Construction 5: more chains and variable verifier
work. Resuming a restored seed at a margin above the verifier's last
accepted leaf: rejected, a guess (A2).

## References

- [DKKW25] J. Drake, D. Khovratovich, M. Kudinov, B. Wagner. Hash-Based
  Multi-Signatures for Post-Quantum Ethereum. IACR CiC 2025.
  https://eprint.iacr.org/2025/055
- [hash-sig] https://github.com/b-wagn/hash-sig, the reference
  implementation of [DKKW25]; commit `e66a485`.
- [hashsig-parameters] https://github.com/b-wagn/hashsig-parameters,
  the parameter script of [DKKW25].
- [FIPS202] SHA-3 Standard: Permutation-Based Hash and Extendable-Output
  Functions. NIST, 2015.
- [BDPV08] G. Bertoni, J. Daemen, M. Peeters, G. Van Assche. On the
  Indifferentiability of the Sponge Construction. EUROCRYPT 2008.
- [ACMT25] G. Alagic, J. Carolan, C. Majenz, S. Tokat. The Sponge is
  Quantum Indifferentiable. arXiv:2504.16887, 2025.
- [PKC22] R. Perlner, J. Kelsey, D. Cooper. Breaking Category Five
  SPHINCS+ with SHA-256. PQCrypto 2022. https://eprint.iacr.org/2022/1061
- [KK06] J. Kelsey, T. Kohno. Herding Hash Functions and the Nostradamus
  Attack. EUROCRYPT 2006.
- [RFC8391] XMSS: eXtended Merkle Signature Scheme.
- [SP800-208] Recommendation for Stateful Hash-Based Signature Schemes.
  NIST, 2020.
