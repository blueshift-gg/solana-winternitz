# `@blueshift-gg/solana-winternitz`

Create post-quantum hash-based signatures that the `solana-winternitz` crate
verifies on-chain: `winternitz` for one signature per key, `xmss` for 256.

```sh
bun add @blueshift-gg/solana-winternitz
```

```ts
import { randomBytes } from 'node:crypto';
import { winternitz, xmss } from '@blueshift-gg/solana-winternitz';

const once = winternitz.SecretKey.fromSeed(randomBytes(32));
const publicKey = once.publicKey; // 56 bytes, store this on-chain
const signature = once.sign(message); // 864 bytes, one call per key
signature.verify(publicKey, message); // throws on failure

const tree = xmss.SecretKey.fromSeed(randomBytes(32)); // builds 256 leaves
const treeKey = tree.publicKey; // 56 bytes
const sig = tree.sign(epoch, message); // 1,124 bytes; never reuse an epoch
sig.verify(treeKey, message);
```

A one-time key signs once: `sign` throws on a second call. An `xmss` epoch
is spent the moment its signature leaves the machine, whether or not the
transaction lands. Byte getters return copies.

See the [repository README](https://github.com/blueshift-gg/solana-winternitz)
for the scheme, the on-chain verifier, the security model, and the
verification evidence.
