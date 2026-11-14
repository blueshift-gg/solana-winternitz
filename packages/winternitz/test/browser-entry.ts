import { VerifyingKey, Signature } from '@blueshift-gg/solana-winternitz';
import vectors from '../../../tests/vectors.json' with { type: 'json' };

const fromHex = (hex: string) => Uint8Array.from(hex.match(/../g) ?? [], (byte) => parseInt(byte, 16));
const valid = vectors.cases[0]!;
VerifyingKey.fromBytes(fromHex(vectors.public_key)).verify(fromHex(valid.message), Signature.fromBytes(fromHex(valid.signature)));
