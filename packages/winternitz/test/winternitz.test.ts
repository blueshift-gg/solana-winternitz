import { expect, test } from 'bun:test';
import vectors from '../../../tests/vectors.json' with { type: 'json' };
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PUBLIC_KEY_LENGTH, PublicKey, Signer, winternitz, xmss } from '../src/index.js';

const hex = (data: Uint8Array) => Array.from(data, (b) => b.toString(16).padStart(2, '0')).join('');
const fromHex = (text: string) => Uint8Array.from(text.match(/../g) ?? [], (b) => parseInt(b, 16));

test.each(vectors.winternitz)('winternitz matches the Rust crate for a $message.length/2-byte message', ({ seed, message, public_key, signature }) => {
  const key = winternitz.SecretKey.fromSeed(fromHex(seed));
  expect(hex(key.publicKey.bytes)).toBe(public_key);
  expect(hex(key.signAt(0, fromHex(message)).bytes)).toBe(signature);
  winternitz.Signature.from(fromHex(signature)).verify(PublicKey.from(fromHex(public_key)), fromHex(message));
});

const trees = new Map<string, xmss.SecretKey>();
test.each(vectors.xmss)('xmss matches the Rust crate at leaf $leaf', ({ seed, leaf, message, public_key, signature }) => {
  const key = trees.get(seed) ?? xmss.SecretKey.fromSeed(fromHex(seed));
  trees.set(seed, key);
  expect(hex(key.publicKey.bytes)).toBe(public_key);
  const sig = key.signAt(leaf, fromHex(message));
  expect(sig.leaf).toBe(leaf);
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

test('the signer owns leaf allocation', () => {
  const dir = mkdtempSync(join(tmpdir(), 'solana-winternitz-'));
  const path = join(dir, 'tree.key');
  const seed = new Uint8Array(32);
  const m = (n: number) => Uint8Array.of(n);

  const signer = Signer.create(xmss.SecretKey, path, seed);
  expect(signer.remaining).toBe(xmss.LEAVES);
  expect(() => Signer.create(xmss.SecretKey, path, seed)).toThrow('locked');
  expect(() => Signer.open(xmss.SecretKey, path)).toThrow('locked');

  const a = signer.sign(m(1));
  expect(a.leaf).toBe(0);
  a.verify(signer.publicKey, m(1));
  expect(signer.sign(m(1)).bytes).toEqual(a.bytes);
  expect(signer.remaining).toBe(xmss.LEAVES - 1);
  expect(signer.sign(m(2)).leaf).toBe(1);
  signer.close();
  expect(() => signer.sign(m(3))).toThrow('closed');

  expect(() => Signer.create(xmss.SecretKey, path, seed)).toThrow('already exists');
  expect(() => Signer.open(winternitz.SecretKey, path)).toThrow('not a record of this instance');
  expect(() => Signer.open(xmss.SecretKey, join(dir, 'none.key'))).toThrow('no key file');

  // Restart: continue at the record; an older message is a new leaf.
  const again = Signer.open(xmss.SecretKey, path);
  expect(again.nextLeaf).toBe(2);
  expect(again.sign(m(2)).leaf).toBe(1);
  expect(again.sign(m(1)).leaf).toBe(2);
  again.close();
  expect(() => Signer.open(xmss.SecretKey, path).floor(4)).toThrow('behind the chain');
  Signer.open(xmss.SecretKey, path).floor(3).close();

  // Interrupted write: stale temp ignored, truncated record refused, dead pid's lock cleared.
  writeFileSync(`${path}.tmp`, 'garbage');
  writeFileSync(`${path}.lock`, '999999999');
  const after = Signer.open(xmss.SecretKey, path);
  expect(after.nextLeaf).toBe(3);
  after.close();
  const record = readFileSync(path);
  writeFileSync(path, record.subarray(0, record.length - 1));
  expect(() => Signer.open(xmss.SecretKey, path)).toThrow('not a record of this instance');

  // Last leaf: one more message, then only that one.
  const last = Buffer.from(record);
  last.writeUInt32LE(xmss.LEAVES - 1, 34);
  writeFileSync(path, last);
  const s = Signer.open(xmss.SecretKey, path);
  expect(s.remaining).toBe(1);
  const z = s.sign(m(9));
  expect(z.leaf).toBe(xmss.LEAVES - 1);
  expect(s.remaining).toBe(0);
  expect(() => s.sign(m(8))).toThrow('exhausted');
  expect(s.sign(m(9)).bytes).toEqual(z.bytes);
  s.close();

  // The one-leaf instance.
  const once = Signer.create(winternitz.SecretKey, join(dir, 'once.key'), seed);
  const sig = once.sign(m(5));
  sig.verify(once.publicKey, m(5));
  expect(once.sign(m(5)).bytes).toEqual(sig.bytes);
  expect(() => once.sign(m(6))).toThrow('exhausted');
  once.close();
  rmSync(dir, { recursive: true });
});

test('the key file written by the Rust crate opens here', () => {
  const dir = mkdtempSync(join(tmpdir(), 'solana-winternitz-'));
  const path = join(dir, 'once.key');
  writeFileSync(path, readFileSync(new URL('../../../tests/winternitz.key', import.meta.url)));
  const w = vectors.winternitz[1]!;
  const once = Signer.open(winternitz.SecretKey, path);
  expect(hex(once.publicKey.bytes)).toBe(w.public_key);
  expect(once.remaining).toBe(0);
  expect(hex(once.sign(fromHex(w.message)).bytes)).toBe(w.signature);
  once.close();
  rmSync(dir, { recursive: true });
});

test('inputs are range-checked', () => {
  expect(() => xmss.SecretKey.fromSeed(new Uint8Array(32)).signAt(xmss.LEAVES, new Uint8Array())).toThrow('leaf');
  expect(() => winternitz.SecretKey.fromSeed(new Uint8Array(31))).toThrow('expected 32 bytes');
  expect(() => winternitz.Signature.from(new Uint8Array(863))).toThrow('expected 864 bytes');
  expect(() => xmss.Signature.from(new Uint8Array(1123))).toThrow('expected 1124 bytes');
  expect(() => PublicKey.from(new Uint8Array(55))).toThrow('expected 56 bytes');
});
