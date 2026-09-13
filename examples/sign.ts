// bun examples/sign.ts <key file> <payload hex>
// Creates or resumes a one-time key. Only the recorded payload can be retried.

import { keccak_256 } from '@noble/hashes/sha3.js';
import { existsSync } from 'node:fs';
import { winternitz } from '@blueshift-gg/solana-winternitz/signer';

const [path = 'once.key', payloadHex = ''] = process.argv.slice(2);
const fromHex = (text: string) => Uint8Array.from(text.match(/../g) ?? [], (b) => parseInt(b, 16));
const toHex = (data: Uint8Array) => Buffer.from(data).toString('hex');

using signer = existsSync(path)
  ? winternitz.SigningKey.open(path)
  : winternitz.SigningKey.create(path);
const message = keccak_256(fromHex(payloadHex));
const signature = signer.sign(message);
signer.verifyingKey().verify(message, signature);
console.log(`key file   ${path}`);
console.log(`public key ${toHex(signer.verifyingKey().toBytes())}`);
console.log(`signature  ${toHex(signature.toBytes())}`);
console.log(`remaining  ${signer.remaining()}`);
