// Sign a payload with a one-time key: `bun examples/sign.ts <key file> <payload hex>`.
// The scheme signs a 32-byte digest, so the payload is hashed first, as a program hashes
// what it acts on. The first run creates the key file from a fresh seed and parameter; later
// runs open it. The one leaf is spent on the first payload: the same payload prints the same
// signature again, any other payload is refused.

import { keccak_256 } from '@noble/hashes/sha3.js';
import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { PARAMETER_LENGTH, Signer, winternitz } from '@blueshift-gg/solana-winternitz';

const [path = 'once.key', payloadHex = ''] = process.argv.slice(2);
const fromHex = (text: string) => Uint8Array.from(text.match(/../g) ?? [], (b) => parseInt(b, 16));
const toHex = (data: Uint8Array) => Buffer.from(data).toString('hex');

const signer = existsSync(path)
  ? Signer.open(winternitz.SecretKey, path)
  : Signer.create(winternitz.SecretKey, path, new Uint8Array(randomBytes(32)), new Uint8Array(randomBytes(PARAMETER_LENGTH)));
try {
  const message = keccak_256(fromHex(payloadHex));
  const signature = signer.sign(message); // recorded in the key file before it is computed
  signature.verify(signer.publicKey, message);
  console.log(`key file   ${path}`);
  console.log(`public key ${toHex(signer.publicKey.bytes)}`);
  console.log(`signature  ${toHex(signature.bytes)}`);
  console.log(`remaining  ${signer.remaining}`);
} finally {
  signer.close();
}
