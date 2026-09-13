# `@blueshift-gg/solana-winternitz`

TypeScript signing and verification for the
[Solana Winternitz](https://github.com/blueshift-gg/solana-winternitz)
crate: generalized XMSS with target-sum encoding and Keccak-256.
`winternitz` has one leaf per key; `xmss` has 256. Each leaf permits one
signing attempt, including failed salt sampling.

Experimental; no independent security audit. Read the
[security assumptions](https://github.com/blueshift-gg/solana-winternitz/blob/main/SECURITY.md)
before integrating.

```sh
bun add @blueshift-gg/solana-winternitz @noble/hashes
```

```ts
import { keccak_256 } from '@noble/hashes/sha3.js';
import { xmss } from '@blueshift-gg/solana-winternitz/signer';

using signer = xmss.SigningKey.create('tree.key');
const message = keccak_256(new TextEncoder().encode('example'));
const publicKey = signer.verifyingKey();
const signature = signer.sign(message);
publicKey.verify(message, signature);
```

`create` samples the chain starts and public parameter from the OS random
source and refuses an existing file. Use
`xmss.SigningKey.open('tree.key')` to resume, or substitute
`winternitz.SigningKey` from the same subpath for the one-leaf instance. Messages must be
32-byte digests of the application's authorized payload.

`sign` persists the attempt before returning. Retrying the recorded
message returns identical signature bytes, including after reopening.
A new attempt replaces that record; salt exhaustion or randomness failure
spends the leaf and clears it. A write failure closes the signer.
`nextLeaf()` and `remaining()` report allocation state; `requireNextLeafAtLeast(minimum)` rejects
a record below a caller-supplied lower bound without advancing it.

Keep one authoritative key file on a trusted local filesystem, using
the same path. Never restore an older state or remove the permanent
`.lock` sidecar. Rust and TypeScript share the record and lock formats.
`SigningKey` requires Bun on macOS or Linux with glibc; the pure package root also
runs in browsers, workers and Node.

Import `VerifyingKey`, `xmss` and `winternitz` from the package root to verify
without a file or platform dependencies. Use `VerifyingKey.fromBytes(bytes)` and `xmss.Signature.fromBytes(bytes)`
(or `winternitz.Signature.fromBytes`) to decode exact-size encodings.
`toBytes()` returns a copy. Each encoded type exposes `BYTE_LEN`.
`key.verify(message, signature)` throws `CryptoError` with code
`InvalidLength` or `InvalidSignature`. Signing and persistence failures throw
`SigningError` with a stable code and preserve underlying I/O errors as `cause`.
`ErrorCode` and `SigningErrorCode` are exported unions; match `code`, not
message text. `using` closes the signer on normal and exceptional scope exit;
`close()` is also available. `signWithRng(message, fill)` accepts an explicit
synchronous CSPRNG fill callback, with the same persistence rules as `sign`.
It is never called on an exact retry; RNG failure still spends the leaf.
Raw `SecretKey` operations live exclusively in `./hazmat`; their caller owns
leaf allocation and persistence. The [specification](https://github.com/blueshift-gg/solana-winternitz/blob/main/SPEC.md)
defines the formats, raw inputs and reference vectors.

For caller-managed signing, `SecretKey.generate(fill)` samples a fresh key and
`signAt(leaf, digest, fill)` samples an accepted salt before signing. The callback
must fill every byte with CSPRNG output; requests are at most 828 bytes.

```ts
import { winternitz } from '@blueshift-gg/solana-winternitz/hazmat';

const fill = (out: Uint8Array) => { crypto.getRandomValues(out); };
const secret = winternitz.SecretKey.generate(fill);
const digest = new Uint8Array(32); // Replace with the application's message digest.
// This fresh one-leaf key is used once and discarded, including on failure.
const signature = secret.signAt(0, digest, fill);
secret.verifyingKey().verify(digest, signature);
```

If the key survives a call, reserve and persist the leaf before calling `signAt`,
including attempts that fail. `signAtWithSalt` reproduces a signature from a
recorded accepted salt; it does not allocate a leaf or sample randomness.
