# `@blueshift-gg/solana-winternitz`

TypeScript signing and verification for the
[Solana Winternitz](https://github.com/blueshift-gg/solana-winternitz)
crate: DKKW25 one-time Winternitz with target-sum encoding and Keccak-256.
A key permits one signing attempt, including failed salt sampling. For 256
signatures under one key, use
[`@blueshift-gg/solana-xmss`](https://www.npmjs.com/package/@blueshift-gg/solana-xmss).

```sh
bun add @blueshift-gg/solana-winternitz @noble/hashes
```

```ts
import { keccak_256 } from '@noble/hashes/sha3.js';
import { SigningKey } from '@blueshift-gg/solana-winternitz/signer';

using signer = SigningKey.create('once.key');
const message = keccak_256(new TextEncoder().encode('example'));
const publicKey = signer.verifyingKey();
const signature = signer.sign(message);
publicKey.verify(message, signature);
```

`create` samples the chain starts and public parameter from the OS random
source and refuses an existing file. Use `SigningKey.open('once.key')` to
resume. Messages must be 32-byte digests of the application's authorized payload.

`sign` persists the attempt before returning. Retrying the recorded
message returns identical signature bytes, including after reopening; any
other message is refused with `Exhausted`. Salt exhaustion or randomness
failure spends the key. A write failure closes the signer.

Keep one authoritative key file on a trusted local filesystem, using
the same path. Never restore an older state or remove the permanent
`.lock` sidecar. Rust and TypeScript share the record and lock formats.
`SigningKey` requires Bun on macOS or Linux with glibc; the pure package root also
runs in browsers, workers and Node.

Import `VerifyingKey` and `Signature` from the package root to verify
without a file or platform dependencies. `fromBytes(bytes)` decodes an
exact-size encoding and `toBytes()` returns a copy; each type exposes `BYTE_LEN`.
`key.verify(message, signature)` throws `CryptoError` with code
`InvalidLength` or `InvalidSignature`. Signing and persistence failures throw
`SigningError` with a stable code and preserve underlying I/O errors as `cause`.
`ErrorCode` and `SigningErrorCode` are exported unions; match `code`, not
message text. `using` closes the signer on normal and exceptional scope exit;
`close()` is also available. `signWithRng(message, fill)` accepts an explicit
synchronous CSPRNG fill callback, with the same persistence rules as `sign`.
It is never called on an exact retry; RNG failure still spends the key.

For caller-managed signing, `./hazmat`'s `SecretKey.generate(fill)` samples a
fresh key and `signAt(0, digest, fill)` samples an accepted salt before signing.
The callback must fill every byte with CSPRNG output; requests are at most 828 bytes.

```ts
import { SecretKey } from '@blueshift-gg/solana-winternitz/hazmat';

const fill = (out: Uint8Array) => { crypto.getRandomValues(out); };
const secret = SecretKey.generate(fill);
const digest = new Uint8Array(32); // Replace with the application's message digest.
// This fresh key is used once and discarded, including on failure.
const signature = secret.signAt(0, digest, fill);
secret.verifyingKey().verify(digest, signature);
```

If the key survives a call, persist that it is spent before calling `signAt`,
including attempts that fail. `signAtWithSalt` reproduces a signature from a
recorded accepted salt; it does not sample randomness.

`./primitives` and `./signer`'s `KeyFile` are the pieces
`@blueshift-gg/solana-xmss` builds on. Unaudited.
