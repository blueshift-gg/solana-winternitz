// Sign a message with a fresh one-time key: `bun examples/sign.ts <seed hex> <message hex>`.

import { randomBytes } from 'node:crypto';
import { winternitz } from '@blueshift-gg/solana-winternitz';

const [seedHex, messageHex = ''] = process.argv.slice(2);
const fromHex = (text: string) => Uint8Array.from(text.match(/../g) ?? [], (b) => parseInt(b, 16));
const seed = seedHex ? fromHex(seedHex) : new Uint8Array(randomBytes(32));

const key = winternitz.SecretKey.fromSeed(seed);
const publicKey = key.publicKey;
const signature = key.sign(fromHex(messageHex));
signature.verify(publicKey, fromHex(messageHex));
console.log(`seed       ${Buffer.from(seed).toString('hex')}`);
console.log(`public key ${Buffer.from(publicKey.bytes).toString('hex')}`);
console.log(`signature  ${Buffer.from(signature.bytes).toString('hex')}`);
