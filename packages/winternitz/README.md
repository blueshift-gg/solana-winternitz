# `@blueshift-gg/solana-winternitz`

Create post-quantum hash-based signatures that the `solana-winternitz`
crate verifies on-chain: `winternitz` for one signature per key, `xmss`
for 256. DKKW25's generalized XMSS at hash-sig's parameters, Keccak-256
for SHA3-256, keys sampled as the paper writes them; hash-sig's
signatures verify here.

```sh
bun add @blueshift-gg/solana-winternitz
```

```ts
import { keccak_256 } from '@noble/hashes/sha3.js';
import { Signer, winternitz, xmss } from '@blueshift-gg/solana-winternitz';

const signer = Signer.create(xmss.SecretKey, 'tree.key'); // samples the key and builds 256 leaves; refuses an existing file
const treeKey = signer.publicKey; // 41 bytes, store this on-chain
const message = keccak_256(payload); // 32 bytes: the digest the program computes over what it acts on
const signature = signer.sign(message); // spends leaf 0, recorded in the file before it is computed
signature.verify(treeKey, message); // throws on failure
signer.sign(message); // the same message again: same bytes, no leaf spent
signer.close(); // releases the file

const again = Signer.open(xmss.SecretKey, 'tree.key').floor(lastAcceptedOnChain + 1); // continues at leaf 1
const once = Signer.create(winternitz.SecretKey, 'once.key'); // the one-leaf case
```

A message is a 32-byte digest; the program hashes whatever it acts on
and passes the digest, so sign the same digest. `create` samples every
chain start and the parameter from the operating system's random
source and refuses an existing file; `open` takes only the file, so no
key starts at leaf 0 by accident. The key file is the key and its only
copy: chain starts, parameter, next leaf and the last message with its
salt, 906 bytes for `winternitz` and 212,046 for `xmss`, mode 0600,
replaced atomically on every spent leaf. Back up the file. One process holds a file at a time through
a kernel lock, `flock`, on a permanent `.lock` sidecar, the same call
the Rust signer makes, so the two honour each other's locks and the OS
releases a dead holder's. `Signer` reaches `flock` through Bun's FFI, so
it needs Bun on a unix host; verification and key generation run
anywhere. A leaf is spent the moment
its signature leaves the machine, whether or not the transaction lands,
so the record is written before the signature is computed, and the last
message signed again returns the same bytes without spending one.
`signAt(leaf, message, salt)` on either key is the primitive underneath:
it takes an accepted salt, records nothing and refuses a leaf out of
range. Byte getters return copies.

The repository's [SPEC.md](https://github.com/blueshift-gg/solana-winternitz/blob/main/SPEC.md)
defines every byte and [SECURITY.md](https://github.com/blueshift-gg/solana-winternitz/blob/main/SECURITY.md)
the claim and its assumptions.
