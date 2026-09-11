# `@blueshift-gg/solana-winternitz`

Create post-quantum hash-based signatures that the `solana-winternitz` crate
verifies on-chain: `winternitz` for one signature per key, `xmss` for 256.

```sh
bun add @blueshift-gg/solana-winternitz
```

```ts
import { randomBytes } from 'node:crypto';
import { Signer, winternitz, xmss } from '@blueshift-gg/solana-winternitz';

const signer = Signer.create(xmss.SecretKey, 'tree.key', randomBytes(32)); // builds 256 leaves; refuses an existing file
const treeKey = signer.publicKey; // 56 bytes, store this on-chain
const signature = signer.sign(message); // spends leaf 0, recorded in the file before it is computed
signature.verify(treeKey, message); // throws on failure
signer.sign(message); // the same message again: same bytes, no leaf spent
signer.close(); // releases the file

const again = Signer.open(xmss.SecretKey, 'tree.key').floor(lastAcceptedOnChain + 1); // continues at leaf 1
const once = Signer.create(winternitz.SecretKey, 'once.key', randomBytes(32)); // the one-leaf case
```

The key file is the key: seed, next leaf and last message digest in 71
bytes, mode 0600, replaced atomically on every spent leaf. Back up the
file, not the seed. `create` takes any fresh seed and refuses an existing
file; `open` takes only the file, so no key starts at leaf 0 by accident;
one instance holds a file at a time. A leaf is spent the moment its
signature leaves the machine, whether or not the transaction lands, so the
record is written before the signature is computed, and the last message
signed again returns the same bytes without spending one. `signAt(leaf,
message)` on either key is the primitive underneath and records nothing.
Byte getters return copies.

See the [repository README](https://github.com/blueshift-gg/solana-winternitz)
for the scheme, the on-chain verifier, the security model, and the
verification evidence.
