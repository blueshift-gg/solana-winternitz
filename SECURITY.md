# Security

This is experimental cryptographic software. It has not received an
independent security audit or formal verification. The security target
is 128 bits classical and 64 bits quantum, conditional on the hash and
state assumptions below. The construction and formats are defined in
[SPEC.md](SPEC.md).

## Construction and assumptions

The scheme is generalized XMSS with target-sum encoding: [DKKW25],
Constructions 3 and 6. Its security model is synchronized strong
unforgeability (Definition 8): an adversary may request one signature
per leaf and must produce an accepted message/signature pair that was
not returned for that leaf. A failed signing query also consumes its
leaf. Replaying the identical pair is outside this forgery definition.

Theorem 1 and Corollary 2 reduce security to the following properties
of the instantiated tweakable hash functions:

- Multi-target collision resistance for the tree and chain hashes
  (Definition 3).
- Target collision resistance with random sampling for the message hash
  (Definition 6, via Lemma 8).
- Undetectability and preimage resistance for the chain hash
  (Definitions 5 and 4).

These are assumptions on Keccak-256 with the exact input layouts and
truncations in SPEC.md. The paper estimates these properties in the
classical and quantum random-oracle models (Table 1). Applying those
estimates to a concrete hash is a heuristic; the theorem does not prove
this implementation's security.

Chain starts, the public parameter and salt candidates are sampled
through the OS random source. Its output must be suitable for independent
uniform sampling. The implementation adds no PRF derivation; Remark 7's
additional PRF assumption is therefore unnecessary. The random source,
host and secret storage remain trusted.

### Parameters

Parameter Requirements 2 and 3, equations (13)–(16), give the following
minimum integer widths at `k_C = 128`, `k_Q = 64`, `w = 4`, `v = 36`,
`L = q_s = 256` and `K = 4096`. Here `q_s` counts signing queries,
including failed attempts.

| Quantity | Required bits | Implemented bits | Equation |
|---|---:|---:|---|
| Message-hash output | 138 | 144 | (13) |
| Salt | 168 | 168 | (14) |
| Chain element / tree hash | 183 | 184 | (15) |
| Public parameter | 142 | 144 | (16) |

The values are rounded up to whole bytes. The equations and agreement
with the authors' pinned [parameter script] are checked in
[src/tests.rs](src/tests.rs). These are the paper's security targets,
not a separate concrete attack-cost estimate.

Parameter Requirement 3 is stated for `L, v ≥ 2`. For `winternitz` at
`L = 1`, the tree reduces to its leaf and the authentication path is
empty. The implementation retains the `L = 256` widths and uses the
same chain and leaf arguments with fewer targets. This is a
specialization argument, not a direct application of that parameter
requirement outside its stated range.

### Target-sum encoding

Accepted vectors have 36 coordinates in `{0, …, 15}` with sum 297.
Lemma 7 establishes their incomparability: if distinct `x` and `y`
had `x_i ≤ y_i` for every coordinate, their sums could not be equal.
This replaces the checksum in ordinary Winternitz encoding. Lemma 8
reduces encoding collision resistance to the message-hash property.

For uniformly distributed message-hash outputs, acceptance probability
is `p = η_297 / 2^144`, where `η_297` is the coefficient of `z^297` in
`(1 + z + … + z^15)^36`. This gives about 111 salt candidates per
success and exhaustion probability `(1−p)^4096 ≈ 9.0 × 10^−17`.
More generally, Lemma 7 includes the hash's uniformity error, and
Lemma 3 bounds signing failure by the encoding error raised to `K`.
The coefficient is evaluated in the parameter test.

One-use state is essential to the incomparability argument. After
multiple signatures under one leaf, an observer can choose the earliest
revealed position on each chain and walk forward from those positions.
The combined values can reach encodings unavailable from any single
signature. Never sign again under a spent leaf with another message or
salt.

### Keccak-256

Keccak-256 and SHA3-256 use the same 24-round, 1600-bit permutation,
1088-bit rate, 512-bit capacity and 256-bit output. Their suffixes
differ: the delimited suffix is `0x01` for Keccak-256 and `0x06` for
SHA3-256. See [FIPS 202] and the [Keccak specification]. They produce
different digests and are distinct protocol instantiations.

The shared permutation and sponge parameters motivate analogous
security estimates. They do not establish equal concrete security or
transfer a quantum random-oracle assumption between the functions.
This implementation assumes the properties above for Keccak-256
because verification uses Solana's Keccak syscall.

With the fixed formats in SPEC.md, chain, leaf, node and message inputs
have distinct lengths: 48, 852, 70 and 76 bytes. Within each role,
fixed-width tweaks distinguish positions. This argument must be
revisited if the formats or parameters change.

## Signer state

`SigningKey` persists each completed attempt before releasing a signature
or sampling error. Exact retries use the recorded message and salt;
a new attempt replaces the retry record, and sampling failure clears
it. Persistence errors release no signature and require reopening the
file. The record and lock protocol are specified in
[SPEC.md](SPEC.md#persistent-signer).

The operational requirements are:

- **One authoritative record.** Signers must share a host, trusted local
  filesystem and the same key-file path, without aliases or independent
  signing copies. The interoperability contract is Unix `flock`; the
  TypeScript implementation uses Bun on macOS or Linux with glibc.
- **A permanent lock inode.** Never unlink, rename or replace `.lock`.
  Locking the key file itself would lose mutual exclusion when an update
  replaces that file. The kernel releases the sidecar lock when its last
  holder closes or dies; no stale-file deletion is needed for recovery.
- **No rollback.** Preserve the complete current record. An old backup
  can reuse a leaf, even if that leaf's transaction never landed.
  `requireNextLeafAtLeast(lastAcceptedLeaf + 1)` checks a lower bound; it cannot detect
  signatures exposed off-chain or make an old backup safe.
- **Trusted storage.** Durability relies on the filesystem honoring
  fsync and atomic rename. Format validation detects malformed records,
  but does not authenticate them against malicious edits.

Raw key constructors and `sign_at` / `signAt` bypass these protections.
Their callers must provide independently sampled starts and `P` and
manage one-use state themselves. The secret bytes alone are insufficient
to recover signing state.

## Application responsibilities

Hash a canonical encoding of everything the application authorizes
into the 32-byte message, including its domain and replay context.
The prehash must be collision-resistant (Remark 1).

Verification is stateless. Retire a one-time key, or record accepted
XMSS leaves, atomically with executing the authorized action. A strictly
increasing leaf policy permits skipped leaves; a used-leaf set permits
out-of-order acceptance. Requiring exactly the next leaf can block
progress after a failed or abandoned signing attempt. The leaf index
is a counter, unrelated to Solana slots or epochs.

## Implementation limits and evidence

Signing time depends on salt sampling. A fixed number of chain hashes
for accepted signatures is not a constant-time guarantee. No complete
side-channel assessment has been performed. Rust overwrites retained
chain starts on drop; complete erasure of transient copies, including
JavaScript heap copies, is not guaranteed. No tighter multi-user
security bound is claimed here.

The tests check parameter equations, Keccak known answers, independent
reference signatures, Rust/TypeScript signing agreement, mutations of
fixtures, malformed records, failed randomness and persistence, retries,
and process-death lock recovery. SBPF tests exercise syscall verification
and measure compute units separately from CI. These checks support
correctness for their inputs; they are not a security proof or an audit.

[DKKW25]: https://eprint.iacr.org/2025/055
[parameter script]: https://github.com/b-wagn/hashsig-parameters/blob/95a80bcd3ac73f67d9a322a83b2b6819d36a5c66/lower_bounds.py
[FIPS 202]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
[Keccak specification]: https://keccak.team/keccak_specs_summary.html
