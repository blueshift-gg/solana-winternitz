# Security analysis

This document states the security claim of the crate, the model in which
it holds, the bound it rests on evaluated at the implemented parameters,
the arguments for each point at which the implementation departs from
[DKKW25], the attacks that were considered with their costs, the
operational assumptions the model requires, and what remains unproven.
The code has not been audited. Byte-level definitions are in
[SPEC.md](SPEC.md).

## 1. Scheme

The crate implements the generalized XMSS signature of [DKKW25,
Construction 3] with the target-sum encoding of [DKKW25, Construction 6]
and lifetime `L ∈ {1, 2^8}`, instantiated as follows. Tweaks are the
byte strings of §7.1 with the role byte first; `ℓ` is the leaf index, the
paper's epoch.

| Function | Definition | Role in [DKKW25] |
|---|---|---|
| `F(P, t, x) = SHA-256(t ‖ P ‖ x)[0..192]` | chain step, `t` a chain tweak | `Th` on `H`, Construction 2 |
| `G(P, t, x) = SHA-256(t ‖ P ‖ x)` | leaf and node, `t` a tree tweak | `Th` on `H^v` and `H^2`, Construction 1 |
| `H_msg(P, ℓ, ρ, m) = HMAC-SHA-256(0x02 ‖ ℓ ‖ ρ ‖ P, m)[0..140]` | encoding input, read as 35 nibbles | `Th_msg`, Construction 6 |
| `Φ_seed(label) = SHA-256(0x03 ‖ label ‖ seed)[0..192]` | parameter, chain starts, salt candidates | Remark 7 |

| Parameter | Value | Requirement | Margin |
|---|---:|---|---:|
| `v · w`, digest bits | 140 | ≥ 137.64, eq. (13) | 2.4 bits |
| `log₂ |R|`, salt bits | 192 | ≥ 175.81, eq. (14), `L = 2^8`, `K = 2^16` | 16.2 bits |
| `n`, chain element bits | 192 | ≥ 182.07, eq. (15), `L = 2^8` | 9.9 bits |
| `log₂ |P|`, parameter bits | 192 | ≥ 141.64, eq. (16) | 50.4 bits |
| `T`, target sum | 325 | Construction 6 | see §4.5 |
| leaf and node width | 256 | none in the paper | see §4.1 |

Requirements are Parameter Requirements 2 and 3 of [DKKW25] at
`k_C = 128`, `k_Q = 64`, evaluated by `tests/tests.rs` and equal to the
output of [hashsig-parameters] for these inputs.

## 2. Model

Security is synchronized strong unforgeability, [DKKW25, Definition 8].
The adversary receives `pk = (root, P)`, may query `Sig(ℓ, m)` at most
once per leaf `ℓ`, and wins with `(ℓ*, m*, σ*)` such that `Ver` accepts
and `(m*, σ*)` is not the pair returned for `ℓ*`. Queries to the hash are
counted as `q`, classical or quantum; signing queries are classical and
number `q_s ≤ L`. The paper's convention charges the signing oracle's own
hashing to the adversary's time `t`, so `t ≥ q + q_s K`.

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
| `T₁` | multi-target collision resistance, Def. 3 | `G` | `2·L·v·2^w` |
| `T₂` | target collision resistance with random sampling, Def. 6, `K` trials | `H_msg` | `q_s` |
| `T₃` | multi-target collision resistance, Def. 3 | `F` | `L·v·2^w` |
| `T₅` | undetectability, Def. 5 | `F` | 1 |
| `T₆` | preimage resistance, Def. 4 | `F` | 1 |

The reduction for `T₁` is the one of §4.1; the others are the paper's.
Substituting the random-oracle bounds of [DKKW25, Table 1] with
`|H_msg| = 2^140`, `|F| = |R| = |P| = 2^192`, `|G| = 2^256`,
`a_L = L·v·2^w = 143 360`, `p = q_s = 2^8`, `pK = 2^24`, and bounding every
query count by `t`:

```
classical:  Adv/t ≤ 1/2^140 + (10 + a_L·(2^w + 2) + pK)/2^192 + 2/2^256
                  ≤ 2^-140 + 2^-167.8 + 2^-255  ≈ 2^-140.0

quantum:    Adv   ≤ α·t² + β·t + γ·√t,
            α = 8/2^140 + (160 + 8·a_L)/2^192 + 32/2^256 ≈ 2^-137.0,
            β = 12·a_L·(2^w + 1)/2^96 ≈ 2^-71.2,
            γ = (3/2)·pK/2^96 ≈ 2^-71.4,
            so Adv/t ≤ 2^-70.8 for t ≤ 2^64 and ≤ 1/t ≤ 2^-64 beyond.
```

The classical level is 140 bits, set by the encoding width; the quantum
level is the 64-bit target, with 70.8 bits in the regime where the bound
is not trivial. `Δ_PRF` is not quantified; §4.3 states what it assumes.
These are heuristic figures in the sense of the paper: the properties in
the table are standard-model assumptions on SHA-256 under these input
layouts, and Table 1 estimates them by modelling the hash as a random
oracle.

## 4. Departures from the paper

### 4.1 Two output widths

**Claim.** Theorem 1 holds with `F` of 192 bits and `G` of 256 bits,
with `T₁` taken against `G` and `T₃, T₅, T₆` against `F`.

**Argument.** Define `Ĝ(P, t, x) = SHA-256(t ‖ P ‖ x)` over chain and
tree tweaks together, so that `F = Ĝ[0..192]` on chain tweaks and
`G = Ĝ` on tree tweaks. The reduction `B₁` in the first game hop must
construct every chain before it learns `P`. Given the multi-target
collision oracle for `Ĝ`, it queries chain tweaks and truncates the
answers to obtain chain ends, queries tree tweaks for leaves and nodes,
and a forged authentication path that differs from the honest one yields
a full-width collision in `Ĝ` at a tree node. The remaining hops concern
chain values only and use the 192-bit function; the tree can be built
after `P` is known. The containments `H^v ⊆ M` and `H^2 ⊆ M` of
Construction 3 hold, since `G` accepts 35 chain ends and two nodes as
input. The wider tree function only enlarges the denominator of `T₁`.

### 4.2 The message hash

**Claim.** With `H_msg` as HMAC-SHA-256 keyed by the public prefix, the
random-oracle estimate of `T₂` applies up to the indifferentiability
loss of HMAC; with a plain `SHA-256(0x02 ‖ ℓ ‖ ρ ‖ P ‖ m)` it does not.

**Attack on the plain hash.** After `t` leaves are signed, every input to
the message hash is public. Let `s_j` be the SHA-256 chaining state after
the first 64-byte block of leaf `j`'s input, the 53-byte prefix plus 11
message bytes. A diamond structure [KK06] merges `2^k` such states into
one at about `2^((256+k)/2 + 2)` compression calls, each merge being a
collision on the 256-bit state. Every suffix `z` appended after the
diamond then produces one digest that is compared with all `2^k` signed
encodings, so a suffix that re-creates leaf `j`'s encoding is found in
about `2^(140−k)` trials, and leaf `j`'s original signature verifies the
forged message `0^11 ‖ path_j ‖ z`. The total is minimized near `k = 7`
at about `2^134.3`, and equals `2^134.6` at `k = 6` with a 427-byte
message. This is the mechanism of [PKC22] applied to the encoding rather
than to WOTS⁺ keys. It is above `k_C = 128` and below the `2^140` of the
random-oracle model; it does not exist against SHA-3, whose sponge
capacity is 512 bits. The structure was reproduced on a Merkle–Damgård
hash with the crate's block geometry and a 32-bit state: 63 merges over
six levels, suffix searches of `2^18` expected trials against `2^24` for
one target, and the forged 427-byte message verified under its leaf's
prefix.

**Closure.** HMAC computes `SHA-256((K ⊕ opad) ‖ SHA-256((K ⊕ ipad) ‖ m))`
with `K` the 53-byte prefix. A merged inner state gives all `2^k` paths
the same inner digest, but the outer call hashes it under each leaf's own
`K ⊕ opad`, so every outer evaluation tests one target. [DRST12, Theorem
4.4] proves HMAC with a fixed-length key shorter than 511 bits
indifferentiable from a keyed random oracle when the compression function
is ideal, with loss `O(σ²/2^256)` in the number of compression calls `σ`;
the key here is 424 bits. Under that result the Table 1 estimate for `T₂`
applies to `H_msg`. No quantum indifferentiability result for HMAC with a
public key is invoked; the quantum figure in §3 rests on the random-oracle
model directly. The chain and tree functions are not subject to the
attack: each admits one input length, and its targets are 192 and 256
bits wide.

### 4.3 Seed-derived keys and salts

**Claim.** Replacing the independently sampled `P`, chain starts and salt
candidates of Construction 3 by `Φ_seed` costs the additive term
`Δ_PRF`, the advantage of distinguishing `Φ_seed` from a random function
on the labels the scheme uses.

**Argument.** The labels are `(purpose, h)`, `(purpose, h, ℓ, i)` and
`(purpose, h, ℓ, ctr, SHA-256(m))` with distinct purpose bytes; a key
evaluates at most `1 + L·v + q_s·K` of them. In the hybrid where `Φ_seed`
is a random function, the parameter, every chain start and every salt
candidate are independent and uniform, which is the distribution
Construction 3 samples, provided the labels are distinct. Distinct
purposes and chain indices separate the parameter and starts; for salts,
one signing query per leaf makes `(ℓ, ctr)` distinct across the whole
game, so the message digest in the label is not needed for distinctness
and no collision-resistance assumption on the prehash is used. Remark 7
of [DKKW25] covers the chain starts only; the extension to the parameter
and salts is this argument. Unpredictability of salts would not suffice:
a single unknown salt repeated for every counter is unpredictable and
yields one grinding attempt. The height `h` in every label makes the
`winternitz` key and the `xmss` key of one seed independent in the
hybrid; without it the single leaf equals leaf 0 of the tree.

`Φ_seed` is SHA-256 over a one-byte tag, the label and the seed last. It
has the form of the PRF of [RFC8391, §5.1] but is not that function,
which is `SHA-256(toByte(3, 32) ‖ KEY ‖ M)`; the pseudorandomness of
`Φ_seed`, classical and quantum, is an assumption of this crate.

### 4.4 Input order and domain separation

Chain and tree inputs are `t ‖ P ‖ x` where [DKKW25, §7.2.2] and
[hash-sig] use `P ‖ t ‖ x`; the message hash is keyed by `t ‖ ρ ‖ P`
where §7.2.1 hashes `ρ ‖ P ‖ t ‖ m`. Within one role every field before
the message has fixed width, and the role byte is at offset 0, so the
inputs of chain steps, leaves, nodes, key derivation and the two HMAC
calls, whose first bytes are `0x02 ⊕ 0x36` and `0x02 ⊕ 0x5c`, are
pairwise distinct byte strings. The prehash `SHA-256(m)` inside the salt
label is the one unstructured input; it is public. Disjointness of inputs
is what the random-oracle heuristic requires of a single hash used in
several roles; it does not turn SHA-256 into independent oracles per
role, and none of the arguments above assume that.

### 4.5 Target sum

`T = 325` exceeds the mean nibble sum `262.5` by the factor `δ = 1.24`,
where [DKKW25, §8] uses `δ ≤ 1.1`; Remark 8 permits any `T`. By Lemma 7
the set of accepted vectors is incomparable, which replaces the
Winternitz checksum, and its size is the coefficient `η_T` of
`x^325` in `(1 + x + … + x^15)^35`, `2^130.12`, so a uniform digest is
accepted with probability `2^-9.88`, once in 943 trials. By Lemma 3 the
signer fails with probability `(1 − 2^-9.88)^K = e^-69.5` at `K = 2^16`.
By Lemma 8 the encoding's target collision resistance reduces to `T₂`
regardless of `T`, so `T` sets signer and verifier work only: 200 chain
steps per verification.

## 5. Attacks considered

| Attack | Requires | Classical | Quantum | Status |
|---|---|---:|---:|---|
| second preimage of one signed encoding | one signature | `2^140` HMAC | `2^70` | generic, §3 |
| herding across `t` signed leaves, plain SHA-256 | `t` signatures | `2^134.3` | ≥ `2^85` per merge | closed, §4.2 |
| chain preimage or undetectability | one signature | ≥ `2^151`, eq. (15) with the `L·v·2^w` loss | ≥ `2^64`, eq. (15) | covered |
| tree collision | one signature | ≥ `2^191`, eq. (6) at `|P| = 2^192` | ≥ `2^93` | covered |
| seed recovery from `P` | public key | `2^192` constrained preimages, wrong root with overwhelming probability | | covered |
| leaf reuse, `k` signatures under one leaf | violation of A1 | table below | | outside the model |
| multi-user forgery against `U` keys | `U` public keys | single-key cost `/ U` at most | | §7 |
| rollback of the signer's record | violation of A2 | equals leaf reuse | | §6 |

**Leaf reuse.** Let `x^(1), …, x^(k)` be the encodings signed under one
leaf and `m_i = min_j x^(j)_i`. The revealed chain values reach every
`x` with `x_i ≥ m_i` for all `i`, so a forger needs a salt whose encoding
lies in `R(m) = { x ∈ [16]^35 : x ≥ m, Σ x_i = 325 }`, at
`2^140 / |R(m)|` HMAC evaluations, using public signatures only.
Measured on this crate at leaf 7 of one key:

| `k` | `Σ m_i` | `log₂ |R(m)|` | cost | run |
|---:|---:|---:|---:|---|
| 1 | 325 | 0 | `2^140` | |
| 2 | 235 | 93.9 | `2^46.1` | |
| 3 | 177 | 108.9 | `2^31.1` | |
| 4 | 137 | 117.1 | `2^22.9` | |
| 8 | 72 | 125.7 | `2^14.3` | forged in 12 372 trials, accepted |
| 16 | 34 | 128.3 | `2^11.7` | forged in 9 276 trials, accepted |

The cost for `k = 2` depends on the pair; another transcript measured
`2^50.9`.

## 6. Operational assumptions

The model of §2 applies only if the following hold. Each names where the
crate enforces it and what §5 says about its violation.

- **A1, one message per leaf.** Enforced by `Signer`: a leaf is recorded
  as spent before its signature is released, the last message is
  repeated rather than re-signed, a different message on a spent leaf is
  refused. `sign_at` bypasses this and is for tests. Violation: leaf
  reuse, §5.
- **A2, integrity of the signer's record.** The record holds the seed,
  the next leaf and the digest of the last message; a copy older than the
  latest signature reintroduces A1's violation. Not detectable locally; a
  lower bound from the verifier's last accepted leaf is checked by
  `floor`. Backups are of the record, never of the seed alone. Cf.
  [SP800-208, §8] on state management.
- **A3, verifier leaf policy.** The verifier retires leaves whose
  signatures are public, since a signature stays valid until it does. A
  strictly increasing leaf index retires every lower leaf on acceptance,
  including any reused one; a used-leaf bitmap admits out-of-order
  landing but retires only leaves that landed; requiring exactly the next
  leaf leaves no way to skip a leaf whose message can no longer be
  executed, so a changed message on that leaf is a reuse. The leaf index
  is a counter and must not be derived from a slot or the Solana epoch.
- **A4, message binding.** Everything the verifier acts upon is part of
  `m`; replay protection, for example a sequence number in `m`, is the
  application's, as the model does not count replay as forgery.
- **A5, key independence.** One seed per key. The two instances of one
  seed are separated by `h` (§4.3); keys of different seeds are
  independent under `Δ_PRF`.

## 7. Open problems and limitations

- The properties of SHA-256 in §3 under these input layouts, at 192-bit
  truncation for chains and 256 bits for the tree, are assumed, not
  proven; the paper's own SHA-3 instantiation carries the same caveat.
- `Δ_PRF` for `Φ_seed`, classically and against quantum queries, is not
  quantified.
- The indifferentiability result used for HMAC is classical.
- Multi-user security is bounded only by the generic `log₂ U` loss.
- Signing time varies with the message and seed through the number of
  salt candidates tried; it reveals that number and nothing else. Seeds
  are overwritten when keys and signers are dropped; transient stack
  copies are not.
- Correctness with these constants is argued for `T = 325`; other targets
  change `η_T` and the required `K`.

## 8. Verification record

Mechanically checked in the repository: eqs. (13) to (16) and `η_T`
(`tests/tests.rs`); HMAC against [RFC4231]; the vector corpus reproduced
by two implementations sharing no code; the SBPF verifier under Mollusk
against host-generated signatures, 29 524 and 31 224 CU. Reproduced in
this analysis: the herding structure of §4.2 at reduced parameters and
the leaf-reuse forgeries of §5 at full parameters, both accepted by the
verifier.

## 9. Alternatives considered

Plain SHA-256 as the message hash: rejected, §4.2. A fixed-length message
with an unsalted prehash: rejected, a `2^128` chosen-message collision
on the prehash. Keccak-256 for the message hash: closes §4.2 but adds a
primitive. Classical Winternitz with checksum chains, Construction 5:
more chains and variable verifier work. Resuming a restored seed at a
margin above the verifier's last accepted leaf: rejected, a guess (A2).

## References

- [DKKW25] J. Drake, D. Khovratovich, M. Kudinov, B. Wagner. Hash-Based
  Multi-Signatures for Post-Quantum Ethereum. IACR CiC 2025.
  https://eprint.iacr.org/2025/055
- [PKC22] R. Perlner, J. Kelsey, D. Cooper. Breaking Category Five
  SPHINCS+ with SHA-256. PQCrypto 2022. https://eprint.iacr.org/2022/1061
- [KK06] J. Kelsey, T. Kohno. Herding Hash Functions and the Nostradamus
  Attack. EUROCRYPT 2006.
- [DRST12] Y. Dodis, T. Ristenpart, J. Steinberger, S. Tessaro. To Hash or
  Not to Hash Again? (In)differentiability Results for H² and HMAC.
  CRYPTO 2012.
- [RFC2104] HMAC: Keyed-Hashing for Message Authentication.
- [RFC4231] Identifiers and Test Vectors for HMAC-SHA-224, -256, -384, -512.
- [RFC8391] XMSS: eXtended Merkle Signature Scheme.
- [FIPS205] Stateless Hash-Based Digital Signature Standard. NIST, 2024.
- [SP800-208] Recommendation for Stateful Hash-Based Signature Schemes.
  NIST, 2020.
- [hash-sig] https://github.com/b-wagn/hash-sig, the reference
  implementation of [DKKW25].
- [hashsig-parameters] https://github.com/b-wagn/hashsig-parameters,
  the parameter script of [DKKW25].
