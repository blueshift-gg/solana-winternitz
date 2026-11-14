import { VerifyingKey, Signature } from '@blueshift-gg/solana-xmss';
import reference from '../../../xmss/tests/hash-sig.json' with { type: 'json' };

const fromHex = (hex: string) => Uint8Array.from(hex.match(/../g) ?? [], (byte) => parseInt(byte, 16));
const vector = reference.signatures[0]!;
const bytes = new Uint8Array(Signature.BYTE_LEN);
new DataView(bytes.buffer).setUint32(0, vector.leaf, false);
bytes.set(fromHex(vector.salt + vector.elements + vector.path), 4);
VerifyingKey.fromBytes(fromHex(reference.public_key)).verify(fromHex(vector.message), Signature.fromBytes(bytes));
