# `@blueshift-gg/solana-xmss`

TypeScript signing and verification for the
[Solana XMSS](https://github.com/blueshift-gg/solana-winternitz/tree/main/xmss)
crate: a 256-leaf DKKW25 generalized XMSS tree, each leaf an
[`@blueshift-gg/solana-winternitz`](https://www.npmjs.com/package/@blueshift-gg/solana-winternitz)
one-time key, over Keccak-256. Each leaf permits one signing attempt,
including failed salt sampling.

```sh
bun add @blueshift-gg/solana-xmss @noble/hashes
```

```ts
import { keccak_256 } from '@noble/hashes/sha3.js';
import { SigningKey } from '@blueshift-gg/solana-xmss/signer';

using signer = SigningKey.create('tree.key');
const message = keccak_256(new TextEncoder().encode('example'));
const publicKey = signer.verifyingKey();
const signature = signer.sign(message);
publicKey.verify(message, signature);
```

`create` samples the chain starts and public parameter from the OS random
source and refuses an existing file. Use `SigningKey.open('tree.key')` to
resume. Messages must be 32-byte digests of the application's authorized payload.

`sign` persists the attempt before returning. Retrying the recorded
message returns identical signature bytes, including after reopening.
A new attempt replaces that record; salt exhaustion or randomness failure
spends the leaf and clears it. A write failure closes the signer.
`nextLeaf()` and `remaining()` report allocation state; `requireNextLeafAtLeast(minimum)` rejects
a record below a caller-supplied lower bound without advancing it.

Keep one authoritative key file on a trusted local filesystem, using
the same path. Never restore an older state or remove the permanent
`.lock` sidecar. Rust and TypeScript share the record and lock formats, and
key files from `@blueshift-gg/solana-winternitz` 0.2's `xmss` signer open unchanged.
`SigningKey` requires Bun on macOS or Linux with glibc; the pure package root also
runs in browsers, workers and Node.

Import `VerifyingKey` and `Signature` from the package root to verify
without a file or platform dependencies. Verification is stateless: refuse
a leaf (`signature.leaf()`) you have already accepted. Errors are the
`CryptoError` and `SigningError` classes of `@blueshift-gg/solana-winternitz`.

For caller-managed signing, `./hazmat`'s `SecretKey.generate(fill)` samples a
fresh key and `signAt(leaf, digest, fill)` signs at a leaf you have reserved and
persisted, including attempts that fail.

This is the Rust crate's custom Keccak-256 instantiation of DKKW25, not RFC 8391 XMSS. Unaudited.
