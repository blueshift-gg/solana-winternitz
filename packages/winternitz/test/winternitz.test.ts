import { expect, test } from 'bun:test';
import vectors from '../../../tests/vectors.json' with { type: 'json' };
import { PUBLIC_KEY_LENGTH, PublicKey, winternitz, xmss } from '../src/index.js';

const hex = (data: Uint8Array) => Array.from(data, (b) => b.toString(16).padStart(2, '0')).join('');
const fromHex = (text: string) => Uint8Array.from(text.match(/../g) ?? [], (b) => parseInt(b, 16));

test.each(vectors.winternitz)('winternitz matches the Rust crate for a $message.length/2-byte message', ({ seed, message, public_key, signature }) => {
  const key = winternitz.SecretKey.fromSeed(fromHex(seed));
  expect(hex(key.publicKey.bytes)).toBe(public_key);
  expect(hex(key.sign(fromHex(message)).bytes)).toBe(signature);
  winternitz.Signature.from(fromHex(signature)).verify(PublicKey.from(fromHex(public_key)), fromHex(message));
});

test.each(vectors.xmss)('xmss matches the Rust crate at epoch $epoch', ({ seed, epoch, message, public_key, signature }) => {
  const key = xmss.SecretKey.fromSeed(fromHex(seed));
  expect(hex(key.publicKey.bytes)).toBe(public_key);
  const sig = key.sign(epoch, fromHex(message));
  expect(sig.epoch).toBe(epoch);
  expect(hex(sig.bytes)).toBe(signature);
  xmss.Signature.from(fromHex(signature)).verify(PublicKey.from(fromHex(public_key)), fromHex(message));
});

test('every single-byte change to a signature, key or message is rejected', () => {
  const w = vectors.winternitz[1]!;
  const input = fromHex(w.message);
  const pk = PublicKey.from(fromHex(w.public_key));
  for (let i = 0; i < winternitz.SIGNATURE_LENGTH; i++) {
    const bad = fromHex(w.signature);
    bad[i]! ^= 1;
    expect(() => winternitz.Signature.from(bad).verify(pk, input)).toThrow('invalid signature');
  }
  for (let i = 0; i < PUBLIC_KEY_LENGTH; i++) {
    const bad = fromHex(w.public_key);
    bad[i]! ^= 1;
    expect(() => winternitz.Signature.from(fromHex(w.signature)).verify(PublicKey.from(bad), input)).toThrow('invalid signature');
  }
  expect(() => winternitz.Signature.from(fromHex(w.signature)).verify(pk, Uint8Array.of(1))).toThrow('invalid signature');

  const x = vectors.xmss[1]!;
  const xpk = PublicKey.from(fromHex(x.public_key));
  for (let i = 0; i < xmss.SIGNATURE_LENGTH; i++) {
    const bad = fromHex(x.signature);
    bad[i]! ^= 1;
    expect(() => xmss.Signature.from(bad).verify(xpk, fromHex(x.message))).toThrow('invalid signature');
  }
});

test('a one-time key signs once and xmss epochs are range-checked', () => {
  const key = winternitz.SecretKey.fromSeed(new Uint8Array(32));
  key.sign(new Uint8Array());
  expect(() => key.sign(new Uint8Array())).toThrow('already used');
  const tree = xmss.SecretKey.fromSeed(new Uint8Array(32));
  expect(() => tree.sign(xmss.LEAVES, new Uint8Array())).toThrow('epoch');
  tree.sign(xmss.LEAVES - 1, new Uint8Array()).verify(tree.publicKey, new Uint8Array());
});

test('lengths are checked', () => {
  expect(() => winternitz.SecretKey.fromSeed(new Uint8Array(31))).toThrow('expected 32 bytes');
  expect(() => winternitz.Signature.from(new Uint8Array(863))).toThrow('expected 864 bytes');
  expect(() => xmss.Signature.from(new Uint8Array(1123))).toThrow('expected 1124 bytes');
  expect(() => PublicKey.from(new Uint8Array(55))).toThrow('expected 56 bytes');
});
