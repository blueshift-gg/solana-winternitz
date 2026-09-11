// Sign a message with a one-time key: `bun examples/sign.ts <key file> <message hex>`.
// The first run creates the key file from a fresh random seed; later runs open it. The
// one leaf is spent on the first message: the same message prints the same signature
// again, any other message is refused.

import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { Signer, winternitz } from '@blueshift-gg/solana-winternitz';

const [path = 'once.key', messageHex = ''] = process.argv.slice(2);
const fromHex = (text: string) => Uint8Array.from(text.match(/../g) ?? [], (b) => parseInt(b, 16));
const toHex = (data: Uint8Array) => Buffer.from(data).toString('hex');

const signer = existsSync(path)
  ? Signer.open(winternitz.SecretKey, path)
  : Signer.create(winternitz.SecretKey, path, new Uint8Array(randomBytes(32)));
try {
  const message = fromHex(messageHex);
  const signature = signer.sign(message); // recorded in the key file before it is computed
  signature.verify(signer.publicKey, message);
  console.log(`key file   ${path}`);
  console.log(`public key ${toHex(signer.publicKey.bytes)}`);
  console.log(`signature  ${toHex(signature.bytes)}`);
  console.log(`remaining  ${signer.remaining}`);
} finally {
  signer.close();
}
