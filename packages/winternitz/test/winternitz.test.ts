import { expect, test } from 'bun:test';
import vectors from '../../../tests/vectors.json' with { type: 'json' };
import reference from '../../../tests/hash-sig.json' with { type: 'json' };
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MESSAGE_LENGTH, PARAMETER_LENGTH, PUBLIC_KEY_LENGTH, PublicKey, Signer, winternitz, xmss } from '../src/index.js';
import { keccak_256 } from '@noble/hashes/sha3.js';

const hex = (data: Uint8Array) => Array.from(data, (b) => b.toString(16).padStart(2, '0')).join('');
const fromHex = (text: string) => Uint8Array.from(text.match(/../g) ?? [], (b) => parseInt(b, 16));

test('the hash is Keccak-256, not SHA3-256', () => {
  expect(hex(keccak_256(new Uint8Array()))).toBe('c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
});

test.each(vectors.winternitz)('winternitz matches the Rust crate', ({ seed, parameter, message, public_key, signature }) => {
  const key = winternitz.SecretKey.new(fromHex(seed), fromHex(parameter));
  expect(hex(key.publicKey.bytes)).toBe(public_key);
  expect(hex(key.signAt(0, fromHex(message)).bytes)).toBe(signature);
  winternitz.Signature.from(fromHex(signature)).verify(PublicKey.from(fromHex(public_key)), fromHex(message));
});

// hash-sig's key at these type parameters, hash swapped to Keccak-256: its public key and signatures byte for byte.
const referenceKey = xmss.SecretKey.new(fromHex(reference.prf_key), fromHex(reference.parameter));
test('the hash-sig public key is reproduced', () => {
  expect(hex(referenceKey.publicKey.bytes)).toBe(reference.public_key);
});
test.each(reference.signatures)('the hash-sig signature at leaf $leaf is reproduced', ({ leaf, message, salt, elements, path }) => {
  const bytes = new Uint8Array(4 + (salt.length + elements.length + path.length) / 2);
  new DataView(bytes.buffer).setUint32(0, leaf, false);
  bytes.set(fromHex(salt + elements + path), 4);
  expect(hex(referenceKey.signAt(leaf, fromHex(message)).bytes)).toBe(hex(bytes));
  const signature = xmss.Signature.from(bytes);
  const key = PublicKey.from(fromHex(reference.public_key));
  expect(signature.leaf).toBe(leaf);
  expect(() => signature.verify(key, fromHex(message))).not.toThrow();
  const other = fromHex(message);
  other[0]! ^= 1;
  expect(() => signature.verify(key, other)).toThrow();
});

const trees = new Map<string, xmss.SecretKey>();

test.each(vectors.xmss)('xmss matches the Rust crate at leaf $leaf', ({ seed, parameter, leaf, message, public_key, signature }) => {
  const key = trees.get(seed) ?? xmss.SecretKey.new(fromHex(seed), fromHex(parameter));
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
  for (let i = 0; i < MESSAGE_LENGTH; i++) {
    const bad = fromHex(w.message);
    bad[i]! ^= 1;
    expect(() => winternitz.Signature.from(fromHex(w.signature)).verify(pk, bad)).toThrow('invalid signature');
  }

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
  const parameter = new Uint8Array(PARAMETER_LENGTH).fill(0x50);
  const m = (n: number) => new Uint8Array(MESSAGE_LENGTH).fill(n);

  const signer = Signer.create(xmss.SecretKey, path, seed, parameter);
  expect(signer.remaining).toBe(xmss.LEAVES);
  expect(() => Signer.create(xmss.SecretKey, path, seed, parameter)).toThrow('held by another signer');
  expect(() => Signer.open(xmss.SecretKey, path)).toThrow('held by another signer');

  const a = signer.sign(m(1));
  expect(a.leaf).toBe(0);
  a.verify(signer.publicKey, m(1));
  expect(signer.sign(m(1)).bytes).toEqual(a.bytes);
  expect(signer.remaining).toBe(xmss.LEAVES - 1);
  expect(signer.sign(m(2)).leaf).toBe(1);
  signer.close();
  expect(() => signer.sign(m(3))).toThrow('closed');

  expect(() => Signer.create(xmss.SecretKey, path, seed, parameter)).toThrow('already exists');
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

  // Interrupted write: stale temp ignored, truncated record refused.
  writeFileSync(`${path}.tmp`, 'garbage');
  // The lock is the kernel's, not the sidecar's existence or content.
  writeFileSync(`${path}.lock`, 'anything');
  const after = Signer.open(xmss.SecretKey, path);
  expect(after.nextLeaf).toBe(3);
  after.close();
  expect(existsSync(`${path}.lock`)).toBe(true);
  const record = readFileSync(path);
  writeFileSync(path, record.subarray(0, record.length - 1));
  expect(() => Signer.open(xmss.SecretKey, path)).toThrow('not a record of this instance');

  // Last leaf: one more message, then only that one.
  const last = Buffer.from(record);
  last.writeUInt32BE(xmss.LEAVES - 1, 2 + 32 + PARAMETER_LENGTH);
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
  const once = Signer.create(winternitz.SecretKey, join(dir, 'once.key'), seed, parameter);
  const sig = once.sign(m(5));
  sig.verify(once.publicKey, m(5));
  expect(once.sign(m(5)).bytes).toEqual(sig.bytes);
  expect(() => once.sign(m(6))).toThrow('exhausted');
  once.close();
  rmSync(dir, { recursive: true });
}, 60_000); // builds the 256-leaf key on every open

test('the lock dies with its holder', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'solana-winternitz-'));
  const path = join(dir, 'once.key');
  Signer.create(winternitz.SecretKey, path, new Uint8Array(32), new Uint8Array(PARAMETER_LENGTH)).close();
  const source = new URL('../src/index.ts', import.meta.url).pathname;
  const holder = spawn(process.execPath, [
    '-e',
    `const { Signer, winternitz } = await import(${JSON.stringify(source)}); Signer.open(winternitz.SecretKey, ${JSON.stringify(path)}); console.log('HOLDING'); await new Promise(() => {});`,
  ]);
  await new Promise<void>((resolve, reject) => {
    holder.stdout.on('data', (chunk: Buffer) => chunk.toString().includes('HOLDING') && resolve());
    holder.on('exit', (code) => reject(new Error(`holder exited with ${code}`)));
  });
  expect(() => Signer.open(winternitz.SecretKey, path)).toThrow('held by another signer');
  holder.kill('SIGKILL');
  await once(holder, 'exit');
  Signer.open(winternitz.SecretKey, path).close();
  rmSync(dir, { recursive: true });
}, 30_000);

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
  const p = new Uint8Array(PARAMETER_LENGTH);
  const m = new Uint8Array(MESSAGE_LENGTH);
  expect(() => xmss.SecretKey.new(new Uint8Array(32), p).signAt(xmss.LEAVES, m)).toThrow('leaf');
  expect(() => winternitz.SecretKey.new(new Uint8Array(32), p).signAt(0, new Uint8Array(31))).toThrow('expected 32 bytes');
  expect(() => winternitz.SecretKey.new(new Uint8Array(32), p).signAt(1, m)).toThrow('leaf');
  expect(() => winternitz.Signature.from(new Uint8Array(849)).verify(PublicKey.from(new Uint8Array(41)), new Uint8Array(33))).toThrow('expected 32 bytes');
  expect(() => winternitz.SecretKey.new(new Uint8Array(31), p)).toThrow('expected 32 bytes');
  expect(() => winternitz.SecretKey.new(new Uint8Array(32), new Uint8Array(17))).toThrow('expected 18 bytes');
  expect(() => winternitz.Signature.from(new Uint8Array(848))).toThrow('expected 849 bytes');
  expect(() => xmss.Signature.from(new Uint8Array(1036))).toThrow('expected 1037 bytes');
  expect(() => PublicKey.from(new Uint8Array(40))).toThrow('expected 41 bytes');
});
