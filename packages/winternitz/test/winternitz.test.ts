import { expect, test, spyOn } from 'bun:test';
import vectors from '../../../tests/vectors.json' with { type: 'json' };
import sampled from '../../../tests/sampled.json' with { type: 'json' };
import * as crypto from 'node:crypto';
import reference from '../../../tests/hash-sig.json' with { type: 'json' };
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MESSAGE_LENGTH, PARAMETER_LENGTH, PUBLIC_KEY_LENGTH, PublicKey, Signer, winternitz, xmss } from '../src/index.js';
import { keccak_256 } from '@noble/hashes/sha3.js';

const hex = (data: Uint8Array) => Array.from(data, (b) => b.toString(16).padStart(2, '0')).join('');
const fromHex = (text: string) => Uint8Array.from(text.match(/../g) ?? [], (b) => parseInt(b, 16));

test('the hash is Keccak-256, not SHA3-256', () => {
  expect(hex(keccak_256(new Uint8Array()))).toBe('c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
});

test.each(vectors.winternitz)('historical winternitz signatures verify', ({ message, public_key, signature }) => {
  winternitz.Signature.from(fromHex(signature)).verify(PublicKey.from(fromHex(public_key)), fromHex(message));
});

// Independently generated reference signatures check verification; no PRF is retained.
test.each(reference.signatures)('the hash-sig signature at leaf $leaf verifies', ({ leaf, message, salt, elements, path }) => {
  const bytes = new Uint8Array(4 + (salt.length + elements.length + path.length) / 2);
  new DataView(bytes.buffer).setUint32(0, leaf, false);
  bytes.set(fromHex(salt + elements + path), 4);
  const signature = xmss.Signature.from(bytes);
  const key = PublicKey.from(fromHex(reference.public_key));
  expect(signature.leaf).toBe(leaf);
  expect(() => signature.verify(key, fromHex(message))).not.toThrow();
  const other = fromHex(message);
  other[0]! ^= 1;
  expect(() => signature.verify(key, other)).toThrow();
});

test.each(vectors.xmss)('historical xmss signatures verify at leaf $leaf', ({ message, public_key, signature }) => {
  xmss.Signature.from(fromHex(signature)).verify(PublicKey.from(fromHex(public_key)), fromHex(message));
});

// Deliberately non-random public inputs, matching the Rust fixture generator.
function acceptedSalt(parameter: Uint8Array, leaf: number, message: Uint8Array): Uint8Array {
  const input = new Uint8Array(76);
  input.set(parameter, 21);
  input[39] = 2;
  new DataView(input.buffer).setUint32(40, leaf, true);
  input.set(message, 44);
  for (let counter = 0; ; counter++) {
    new DataView(input.buffer).setUint32(0, counter, true);
    const hash = keccak_256(input);
    let sum = 0;
    for (const b of hash.subarray(0, 18)) sum += (b & 15) + (b >> 4);
    if (sum === 297) return input.slice(0, 21);
  }
}

const sampledTree = xmss.SecretKey.new(Uint8Array.from({ length: 256 * 828 }, (_, i) => (i % 251) ^ 7), new Uint8Array(18).fill(0x57));
test.each(sampled.signatures)('explicit chain starts reproduce Rust signing at leaf $leaf', ({ leaf, signature }) => {
  const message = new Uint8Array(32);
  new DataView(message.buffer).setUint32(0, leaf, true);
  const sig = sampledTree.signAt(leaf, message, acceptedSalt(sampledTree.publicKey.parameter, leaf, message));
  expect(hex(sampledTree.publicKey.bytes)).toBe(sampled.public_key);
  expect(hex(sig.bytes)).toBe(signature);
  sig.verify(sampledTree.publicKey, message);
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
  const m = (n: number) => new Uint8Array(MESSAGE_LENGTH).fill(n);

  const signer = Signer.create(xmss.SecretKey, path);
  expect(signer.remaining).toBe(xmss.LEAVES);
  expect(() => Signer.create(xmss.SecretKey, path)).toThrow('held by another signer');
  expect(() => Signer.open(xmss.SecretKey, path)).toThrow('held by another signer');

  const a = signer.sign(m(1));
  expect(a.leaf).toBe(0);
  a.verify(signer.publicKey, m(1));
  expect(signer.sign(m(1)).bytes).toEqual(a.bytes);
  expect(signer.remaining).toBe(xmss.LEAVES - 1);
  const b = signer.sign(m(2));
  expect(b.leaf).toBe(1);
  signer.close();
  expect(() => signer.sign(m(3))).toThrow('closed');

  expect(() => Signer.create(xmss.SecretKey, path)).toThrow('already exists');
  expect(() => Signer.open(winternitz.SecretKey, path)).toThrow('not a record of this instance');
  expect(() => Signer.open(xmss.SecretKey, join(dir, 'none.key'))).toThrow('no key file');

  // Restart: continue at the record; an older message is a new leaf.
  const again = Signer.open(xmss.SecretKey, path);
  expect(again.nextLeaf).toBe(2);
  expect(again.sign(m(2)).bytes).toEqual(b.bytes);
  expect(again.sign(m(1)).leaf).toBe(2);
  again.close();
  expect(() => Signer.open(xmss.SecretKey, path).floor(4)).toThrow('behind the chain');
  Signer.open(xmss.SecretKey, path).floor(3).close();

  // A stale temp file is ignored, and the sidecar's content is not the lock.
  writeFileSync(`${path}.tmp`, 'garbage');
  writeFileSync(`${path}.lock`, 'anything');
  const after = Signer.open(xmss.SecretKey, path);
  expect(after.nextLeaf).toBe(3);
  after.close();
  expect(existsSync(`${path}.lock`)).toBe(true);
  // A truncated record and a self-contradicting one are refused.
  const record = readFileSync(path);
  writeFileSync(path, record.subarray(0, record.length - 1));
  expect(() => Signer.open(xmss.SecretKey, path)).toThrow('not a record of this instance');
  const contradiction = Buffer.from(record);
  contradiction.writeUInt32BE(0, 2 + PARAMETER_LENGTH);
  writeFileSync(path, contradiction);
  expect(() => Signer.open(xmss.SecretKey, path)).toThrow('not a record of this instance');

  // Last leaf: one more message, then only that one.
  const last = Buffer.from(record);
  last.writeUInt32BE(xmss.LEAVES - 1, 2 + PARAMETER_LENGTH);
  last.set(acceptedSalt(last.subarray(2, 20), xmss.LEAVES - 2, last.subarray(25, 57)), 57);
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
  const once = Signer.create(winternitz.SecretKey, join(dir, 'once.key'));
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
  Signer.create(winternitz.SecretKey, path).close();
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
  const record = readFileSync(path);
  const once = Signer.open(winternitz.SecretKey, path);
  expect(once.remaining).toBe(0);
  expect(hex(once.sign(record.subarray(25, 57)).bytes)).toBe(sampled.one_time_signature);
  expect(readFileSync(path)).toEqual(record);
  once.close();
  rmSync(dir, { recursive: true });
});

test('inputs are range-checked', () => {
  const p = new Uint8Array(PARAMETER_LENGTH);
  const m = new Uint8Array(MESSAGE_LENGTH);
  const salt = new Uint8Array(21);
  const key = winternitz.SecretKey.new(new Uint8Array(828), p);
  expect(() => sampledTree.signAt(xmss.LEAVES, m, salt)).toThrow('leaf');
  expect(() => key.signAt(0, new Uint8Array(31), salt)).toThrow('expected 32 bytes');
  expect(() => key.signAt(1, m, salt)).toThrow('leaf');
  expect(() => key.signAt(0, m, new Uint8Array(20))).toThrow('expected 21 bytes');
  expect(() => winternitz.Signature.from(new Uint8Array(849)).verify(PublicKey.from(new Uint8Array(41)), new Uint8Array(33))).toThrow('expected 32 bytes');
  expect(() => winternitz.SecretKey.new(new Uint8Array(32), p)).toThrow('expected 828 bytes');
  expect(() => xmss.SecretKey.new(new Uint8Array(828), p)).toThrow('expected 211968 bytes');
  expect(() => winternitz.SecretKey.new(new Uint8Array(828), new Uint8Array(17))).toThrow('expected 18 bytes');
  expect(() => winternitz.Signature.from(new Uint8Array(848))).toThrow('expected 849 bytes');
  expect(() => xmss.Signature.from(new Uint8Array(1036))).toThrow('expected 1037 bytes');
  expect(() => PublicKey.from(new Uint8Array(40))).toThrow('expected 41 bytes');
});

test('entropy failure, salt exhaustion, and write failure release no signature', () => {
  const dir = mkdtempSync(join(tmpdir(), 'solana-winternitz-'));
  const path = join(dir, 'once.key');
  const signer = Signer.create(winternitz.SecretKey, path);
  const before = readFileSync(path);
  const m = new Uint8Array(32);
  const randomFill = crypto.randomFillSync;
  const fill = spyOn(crypto, 'randomFillSync');
  try {
    fill.mockImplementation(() => { throw new Error('entropy unavailable'); });
    expect(() => signer.sign(m)).toThrow('entropy unavailable');
    expect(signer.nextLeaf).toBe(0);
    expect(readFileSync(path)).toEqual(before);
    // One known rejected candidate repeated K times deterministically forces exhaustion.
    const bad = new Uint8Array(21);
    const input = new Uint8Array(76);
    input.set(signer.publicKey.parameter, 21);
    input[39] = 2;
    input.set(m, 44);
    for (let counter = 0; ; counter++) {
      new DataView(bad.buffer).setUint32(0, counter, true);
      input.set(bad, 0);
      const sum = keccak_256(input).subarray(0, 18).reduce((n, b) => n + (b & 15) + (b >> 4), 0);
      if (sum !== 297) break;
    }
    fill.mockImplementation((buffer) => { new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength).set(bad); return buffer; });
    expect(() => signer.sign(m)).toThrow('4096 salts missed');
    expect(signer.nextLeaf).toBe(0);
    expect(readFileSync(path)).toEqual(before);
    fill.mockImplementation(randomFill);
    mkdirSync(`${path}.tmp`);
    expect(() => signer.sign(m)).toThrow();
    expect(() => signer.sign(m)).toThrow('closed');
    expect(readFileSync(path)).toEqual(before);
    rmSync(`${path}.tmp`, { recursive: true });
    const again = Signer.open(winternitz.SecretKey, path);
    const signature = again.sign(m);
    fill.mockImplementation(() => { throw new Error('retry drew entropy'); });
    expect(again.sign(m).bytes).toEqual(signature.bytes);
    again.close();
    const reopened = Signer.open(winternitz.SecretKey, path);
    expect(reopened.sign(m).bytes).toEqual(signature.bytes);
    reopened.close();
  } finally { fill.mockRestore(); signer.close(); rmSync(dir, { recursive: true, force: true }); }
});
