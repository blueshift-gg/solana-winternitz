# Security

The claim, what it rests on, what was measured, and what is not proven.
Research code, not audited. Report findings to the maintainers before
disclosing them.

## The claim

[DKKW25](https://eprint.iacr.org/2025/055) Corollary 2, Theorem 1 applied
to Constructions 3 and 6, gives 128-bit classical and 64-bit quantum
security for one key with at most one signature per leaf, under
multi-target collision resistance, undetectability and preimage
resistance of the tweakable hash and target collision resistance with
random sampling of the message hash. The lengths satisfy Parameter
Requirements 2 and 3, eqs. (13) to (16), at lifetime 2^8 with 2^16 salt
trials; the tests pin them to the authors' script. The theorem is
single-key: a deployment with `U` keys loses at most `log2 U` bits under
the generic guessing reduction, and shared seeds are not independent keys.

The paper proves the theorem in the standard model and sets parameters by
random-oracle heuristics (Table 1). Nothing here proves SHA-256 has the
required properties; the assumptions below are what is added to the
paper's own.

## Assumptions beyond the paper

- **SHA-256 in place of SHA-3.** The concrete bounds model the hash as a
  random oracle; the same heuristic is applied to SHA-256, as FIPS 205
  and RFC 8391 do for their SHA-2 instantiations, with one structural
  exception handled below. FIPS 205 is precedent at the 128-bit level
  only: its SHA-2 sets pad the seed to a block and use SHA-512 above
  category 1.

- **Key derivation is a PRF.** Parameter, chain starts and salts are
  `SHA-256(0x03 ‖ purpose ‖ h ‖ … ‖ seed)`, assumed pseudorandom without
  the seed. This is the additive term Remark 7 allows, but Remark 7 covers
  the chain starts, and the paper's signer samples each salt candidate
  uniformly and independently. The deterministic salts need one more
  step: with the whole seed-derived function replaced by a random one, the
  distinct labels, purpose, height, leaf and counter, make the parameter,
  every chain start and every salt candidate independent and uniform, and
  one message per leaf keeps the labels distinct. Unpredictability alone
  would not do; one unknown salt repeated per counter is unpredictable
  and gives a single grinding attempt. The form follows RFC 8391 §5.1's
  `PRF`, plain SHA-256 over a tag, key and input, but is not that
  function: the RFC's is `SHA-256(toByte(3, 32) ‖ KEY ‖ M)`, here the tag
  is one byte and the key comes last so the role byte stays at offset 0.
  The assumption is this crate's own. The height is in every derivation
  so one seed gives unrelated keys under the two instances; without it
  the `winternitz` leaf is `xmss` leaf 0 of the same seed and a signature
  under one spends the other's one-time key.

- **Two output lengths under one theorem.** The paper's `Th` has one
  output space. Here chain steps output 24 bytes and leaf and node hashes
  32. Read both as one function `G(P, t, x) = SHA-256(t ‖ P ‖ x)` over
  chain and tree tweaks, with the chain hash its 24-byte truncation.
  Theorem 1's terms then split by function. The tree term (`B1`,
  multi-target collision resistance with `2·L·v·2^w` targets, eq. (6))
  runs against `G`: the reduction must build every chain before it learns
  `P`, which it can by querying `G` with chain tweaks and truncating while
  keeping the full 32 bytes for leaves and nodes; a forged tree is then a
  full-width collision in `G`. The chain terms (`B3` to `B6`, eqs. (7) to
  (9)) run against the truncated function, where eq. (15) is checked. The
  24-byte outputs and 32-byte nodes are inputs of the tree hash as
  `H^v ⊆ M` and `H^2 ⊆ M` require. The wider nodes add margin on the tree
  term only.

- **The message hash is HMAC, and why.** In the paper's model, hitting a
  signed encoding costs 2^140 hashes however the target sum is set (Lemma
  8 reduces to SM-rTCR, eq. (13)); the accepted layer's size sets the
  signer's grinding cost and, at a fixed retry cap, nothing else. A plain
  SHA-256 message hash would not honour that number. It is
  Merkle–Damgård with a 256-bit state and its whole input is public once
  a leaf is signed, so an attacker holding `t` signed leaves could herd
  the `t` first-block states of `0x02 ‖ leaf ‖ ρ ‖ P ‖ m` into one
  internal state at about `t · 2^128` compression calls, then test every
  one of the `t` signed encodings with each suffix trial, about
  `2^140 / t` more: roughly 2^134 at `t = 64`, above the 128-bit target
  but below the claim, with a forged message of 427 attacker-chosen
  bytes. That is Perlner, Kelsey and Cooper's category-5 SPHINCS+ attack
  ([ePrint 2022/1061](https://eprint.iacr.org/2022/1061)) transposed to
  the encoding. Its structure was reproduced on a small-state model with
  the crate's exact block layout: 63 merges over six levels, the suffix
  search landing in `2^d / t` trials, the forged message verifying under
  its leaf's prefix. The plain hash was declined. HMAC-SHA-256 keyed by
  the public prefix re-binds the prefix in the outer call, so a merged
  inner state still tests one target per compression, and HMAC with a
  fixed-length key under 511 bits, this one is 424, is indifferentiable
  from a keyed random oracle (Dodis, Ristenpart, Steinberger, Tessaro,
  CRYPTO 2012, Theorem 4.4) at a classical loss of `σ² / 2^256`. It costs
  one syscall, about 210 CU measured. Quantum cost never moved: one
  internal collision is about 2^85 queries against 2^70 for the direct
  search. The chain and tree hashes are not exposed: one admissible input
  length each and 256-bit targets.

Length extension does not apply. The message hash is HMAC, whose outer
call closes it; chain and tree inputs have one admissible length each,
fixed by their role and level bytes; key derivation is the one place a
secret is involved, and its outputs are truncated. Role bytes buy
disjoint inputs, not an independent random oracle per role.

## Leaf reuse

Two signatures under one leaf are a break, not a weakening. Each
signature reveals a chain position; a forger needs a salt whose encoding
lies at or above the lowest revealed position in every chain, built from
public signatures alone. Measured on this crate, 256 leaves, target 325:

| Signatures under one leaf | Reachable encodings | Forgery cost |
|---:|---:|---:|
| 1 | 1 | 2^140 salt trials |
| 2 | 2^94 | about 2^46, transcript-dependent up to 2^51 |
| 4 | 2^117 | about 2^23 |
| 8 | 2^126 | about 12,000 trials, verified accepted |

This is why the signer records a leaf before releasing its signature,
repeats the last message rather than re-signing it, and refuses a
different message on a spent leaf.

## Leaf policy

The program decides which leaves it accepts. `Signer` consumes leaves in
order and returns the last message's signature again without spending
one, which serves either policy. Three facts hold under both:

- **A leaf index is not a time.** The paper calls it the epoch; never
  derive it from a slot or the Solana epoch: `slot % 256` reuses leaves,
  and two signatures in one slot collide.
- **Exposure is permanent.** A signature that reached any RPC, for
  simulation or broadcast, is public whether or not its transaction
  landed or expired, and anyone can resubmit it in a new transaction until
  the program retires it. Only the program's sequence check, or a deadline
  the signed message carries, retires an authorization; the blockhash
  does not. A changed message always takes an unused leaf; waiting for
  expiry buys nothing.
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
signature landing first invalidates an outstanding leaf-7 one, an
application policy rather than a requirement of the scheme. A program
that needs several signatures in flight can store a 256-bit used-leaf
bitmap instead; that loses closing by landing higher, so it leans
entirely on the sequence number to retire abandoned signatures.

**Strict nonce.** The account requires exactly the next leaf, or stores
the one root allowed to sign next. Nothing is skipped and a restore of
the position, though not of the digest, is one read of the account. Its
problems:

- **There is no burn path.** A lost transaction whose intent has changed
  cannot be skipped. The only safe retry is the identical message, which
  is what `sign` returns for it; a different message at that leaf is the
  reuse, and an advance-only no-op is a different message too. If the
  original intent can no longer execute, the key is stuck: only a path
  that does not need the one-time key moves it.
- **The client guard is the whole defence.** The program cannot tell a
  legitimate retry from a reuse, since both carry the pinned leaf. The key
  file must be current on every device that signs, and a device without
  it must not sign.
- **Recovery by scanning is the symptom.** A tool that derives positions
  until one matches the on-chain root sets the client back to the
  position whose signature was lost. A recover tool under this policy
  restores the key file, not only its position.

Choose strict nonce only if the program needs leaves without gaps.

## Not proven, and what to attack

- SHA-256's multi-target collision resistance, undetectability and
  preimage resistance at the truncated 192-bit chain function and the
  256-bit tree function under these exact input layouts.
- The crate's own PRF: `SHA-256(0x03 ‖ purpose ‖ h ‖ … ‖ seed)` with the
  key last, classically and quantumly, across the `1 + L·v + p·K` labels
  a key uses.
- The HMAC indifferentiability bound is classical; no quantum bound for
  HMAC with a public key is cited.
- Multi-key composition is not analysed beyond the generic `log2 U` loss.
- A restored valid old copy of a key file is undetectable locally; `floor`
  needs the chain's last accepted leaf.
- Target sums other than 325 are not covered by the correctness argument
  with the same constants.

## Design record

Evaluated and declined, with the reason: a plain SHA-256 message hash
(herdable, above); resuming a restored seed a margin above the chain's
last accepted leaf (a guess, above); a fixed-length message interface
with an unsalted prehash (a 2^128 chosen-message collision, worse than
the herding it replaces); Keccak-256 for the message hash alone (also
closes herding, but a second primitive); a persisted-state callback with
signatures released before the write (regressable, replaced by the
file-owning signer); classical Winternitz with checksum chains
(Construction 5, more chains and variable verifier work).
