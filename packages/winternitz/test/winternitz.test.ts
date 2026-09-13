import { expect, test, spyOn } from 'bun:test';
import sampled from '../../../tests/sampled.json' with { type: 'json' };
import * as crypto from 'node:crypto';
import reference from '../../../tests/hash-sig.json' with { type: 'json' };
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runInNewContext } from 'node:vm';
import { type ErrorCode, CryptoError, MESSAGE_LEN, PARAMETER_LEN, PUBLIC_KEY_LEN, VerifyingKey, winternitz, xmss } from '../src/index.js';
import { type SigningErrorCode, SigningError, xmss as xmssSigner, winternitz as winternitzSigner } from '../src/signer.js';
import * as hazmat from '../src/hazmat.js';
import { keccak_256 } from '@noble/hashes/sha3.js';

function expectCode(action: () => unknown, code: ErrorCode | SigningErrorCode): void {
  let caught: unknown;
  try { action(); } catch (error) { caught = error; }
  const error = caught;
  expect(error instanceof CryptoError || error instanceof SigningError).toBe(true);
  expect((error as { code: ErrorCode | SigningErrorCode }).code).toBe(code);
}

const hex = (data: Uint8Array) => Array.from(data, (b) => b.toString(16).padStart(2, '0')).join('');
const fromHex = (text: string) => Uint8Array.from(text.match(/../g) ?? [], (b) => parseInt(b, 16));

test('the public root bundles and verifies without Node or Bun globals', async () => {
  const result = await Bun.build({
    entrypoints: [new URL('./browser-entry.ts', import.meta.url).pathname],
    target: 'browser',
  });
  expect(result.success).toBe(true);
  runInNewContext(await result.outputs[0]!.text(), { TextEncoder }, { timeout: 1000 });
});

test('using releases the lock on normal and exceptional exit', () => {
  const dir = mkdtempSync(join(tmpdir(), 'solana-winternitz-dispose-'));
  const path = join(dir, 'once.key');
  try {
    {
      using signer = winternitzSigner.SigningKey.create(path);
      expect(signer.remaining()).toBe(1);
      expectCode(() => winternitzSigner.SigningKey.open(path), 'Locked');
    }
    const failure = new Error('leave the scope');
    try {
      using signer = winternitzSigner.SigningKey.open(path);
      expect(signer.remaining()).toBe(1);
      throw failure;
    } catch (error) { expect(error).toBe(failure); }
    using signer = winternitzSigner.SigningKey.open(path);
    expect(signer.remaining()).toBe(1);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('explicit randomness cannot mutate retries, reenter signing, or release the lock', () => {
  const dir = mkdtempSync(join(tmpdir(), 'solana-winternitz-rng-'));
  const path = join(dir, 'once.key');
  const message = new Uint8Array(MESSAGE_LEN).fill(7);
  const original = message.slice();
  try {
    using signer = winternitzSigner.SigningKey.create(path);
    const salt = acceptedSalt(signer.verifyingKey().toBytes().subarray(23), 0, message);
    let retained: Uint8Array | undefined;
    const signature = signer.signWithRng(message, (out) => {
      expectCode(() => signer.sign(new Uint8Array(MESSAGE_LEN)), 'Unusable');
      expectCode(() => signer.close(), 'Unusable');
      expectCode(() => winternitzSigner.SigningKey.open(path), 'Locked');
      message.fill(0);
      out.set(salt);
      retained = out;
    });
    retained!.fill(0);
    const retryRng = () => { throw new Error('retry must not request entropy'); };
    expect(signer.signWithRng(original, retryRng).toBytes()).toEqual(signature.toBytes());
    signer.verifyingKey().verify(original, signature);
    signer.close();
    using reopened = winternitzSigner.SigningKey.open(path);
    expect(reopened.signWithRng(original, retryRng).toBytes()).toEqual(signature.toBytes());
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// Independent reference verification checks the hash layouts and authentication path.
test.each(reference.signatures)('the hash-sig signature at leaf $leaf verifies', ({ leaf, message, salt, elements, path }) => {
  const bytes = new Uint8Array(4 + (salt.length + elements.length + path.length) / 2);
  new DataView(bytes.buffer).setUint32(0, leaf, false);
  bytes.set(fromHex(salt + elements + path), 4);
  const signature = xmss.Signature.fromBytes(bytes);
  const key = VerifyingKey.fromBytes(fromHex(reference.public_key));
  expect(signature.leaf()).toBe(leaf);
  expect(() => (key).verify(fromHex(message), signature)).not.toThrow();
  const other = fromHex(message);
  other[0]! ^= 1;
  expectCode(() => (key).verify(other, signature), 'InvalidSignature');
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

const sampledTree = hazmat.xmss.SecretKey.fromSecrets(Uint8Array.from({ length: 256 * 828 }, (_, i) => (i % 251) ^ 7), new Uint8Array(18).fill(0x57));
test.each(sampled.signatures)('explicit chain starts reproduce Rust signing at leaf $leaf', ({ leaf, signature }) => {
  const message = new Uint8Array(32);
  new DataView(message.buffer).setUint32(0, leaf, true);
  const sig = sampledTree.signAtWithSalt(leaf, message, acceptedSalt(sampledTree.verifyingKey().toBytes().subarray(23), leaf, message));
  expect(hex(sampledTree.verifyingKey().toBytes())).toBe(sampled.public_key);
  expect(hex(sig.toBytes())).toBe(signature);
  (sampledTree.verifyingKey()).verify(message, sig);
});

test('one-bit mutations at each fixture byte are rejected', () => {
  const record = readFileSync(new URL('../../../tests/winternitz.key', import.meta.url));
  const input = record.subarray(25, 57);
  const pk = hazmat.winternitz.SecretKey.fromSecrets(record.subarray(78), record.subarray(2, 20)).verifyingKey();
  const w = { signature: sampled.one_time_signature, message: hex(input), public_key: hex(pk.toBytes()) };
  for (let i = 0; i < winternitz.SIGNATURE_LEN; i++) {
    const bad = fromHex(w.signature);
    bad[i]! ^= 1;
    expectCode(() => (pk).verify(input, winternitz.Signature.fromBytes(bad)), 'InvalidSignature');
  }
  for (let i = 0; i < PUBLIC_KEY_LEN; i++) {
    const bad = fromHex(w.public_key);
    bad[i]! ^= 1;
    expectCode(() => (VerifyingKey.fromBytes(bad)).verify(input, winternitz.Signature.fromBytes(fromHex(w.signature))), 'InvalidSignature');
  }
  for (let i = 0; i < MESSAGE_LEN; i++) {
    const bad = fromHex(w.message);
    bad[i]! ^= 1;
    expectCode(() => (pk).verify(bad, winternitz.Signature.fromBytes(fromHex(w.signature))), 'InvalidSignature');
  }

  const vector = sampled.signatures[1]!;
  const message = new Uint8Array(32);
  new DataView(message.buffer).setUint32(0, vector.leaf, true);
  const x = { signature: vector.signature, message: hex(message) };
  const xpk = VerifyingKey.fromBytes(fromHex(sampled.public_key));
  for (let i = 0; i < xmss.SIGNATURE_LEN; i++) {
    const bad = fromHex(x.signature);
    bad[i]! ^= 1;
    expectCode(() => (xpk).verify(fromHex(x.message), xmss.Signature.fromBytes(bad)), 'InvalidSignature');
  }
});

test('the signer owns leaf allocation', () => {
  const dir = mkdtempSync(join(tmpdir(), 'solana-winternitz-'));
  const path = join(dir, 'tree.key');
  const m = (n: number) => new Uint8Array(MESSAGE_LEN).fill(n);

  const signer = xmssSigner.SigningKey.create(path);
  expect(signer.remaining()).toBe(xmss.LEAVES);
  expectCode(() => xmssSigner.SigningKey.create(path), 'Locked');
  expectCode(() => xmssSigner.SigningKey.open(path), 'Locked');

  const a = signer.sign(m(1));
  expect(a.leaf()).toBe(0);
  (signer.verifyingKey()).verify(m(1), a);
  expect(signer.sign(m(1)).toBytes()).toEqual(a.toBytes());
  expect(signer.remaining()).toBe(xmss.LEAVES - 1);
  const b = signer.sign(m(2));
  expect(b.leaf()).toBe(1);
  signer.close();
  expectCode(() => signer.sign(m(3)), 'Unusable');

  expectCode(() => xmssSigner.SigningKey.create(path), 'Exists');
  expectCode(() => winternitzSigner.SigningKey.open(path), 'Corrupt');
  expectCode(() => xmssSigner.SigningKey.open(join(dir, 'none.key')), 'Missing');

  // Restart: continue at the record; an older message is a new leaf.
  const again = xmssSigner.SigningKey.open(path);
  expect(again.nextLeaf()).toBe(2);
  expect(again.sign(m(2)).toBytes()).toEqual(b.toBytes());
  expect(again.sign(m(1)).leaf()).toBe(2);
  again.close();
  expectCode(() => xmssSigner.SigningKey.open(path).requireNextLeafAtLeast(4), 'LeafBelowMinimum');
  expectCode(() => xmssSigner.SigningKey.open(path).requireNextLeafAtLeast(-1), 'InvalidEncoding');
  xmssSigner.SigningKey.open(path).requireNextLeafAtLeast(3).close();

  // A stale temp file is ignored, and the sidecar's content is not the lock.
  writeFileSync(`${path}.tmp`, 'garbage');
  writeFileSync(`${path}.lock`, 'anything');
  const after = xmssSigner.SigningKey.open(path);
  expect(after.nextLeaf()).toBe(3);
  after.close();
  expect(existsSync(`${path}.lock`)).toBe(true);
  // A truncated record and a self-contradicting one are refused.
  const record = readFileSync(path);
  writeFileSync(path, record.subarray(0, record.length - 1));
  expectCode(() => xmssSigner.SigningKey.open(path), 'Corrupt');
  const contradiction = Buffer.from(record);
  contradiction.writeUInt32BE(0, 2 + PARAMETER_LEN);
  writeFileSync(path, contradiction);
  expectCode(() => xmssSigner.SigningKey.open(path), 'Corrupt');

  // Last leaf: one more message, then only that one.
  const last = Buffer.from(record);
  last.writeUInt32BE(xmss.LEAVES - 1, 2 + PARAMETER_LEN);
  last.set(acceptedSalt(last.subarray(2, 20), xmss.LEAVES - 2, last.subarray(25, 57)), 57);
  writeFileSync(path, last);
  const s = xmssSigner.SigningKey.open(path);
  expect(s.remaining()).toBe(1);
  const z = s.sign(m(9));
  expect(z.leaf()).toBe(xmss.LEAVES - 1);
  expect(s.remaining()).toBe(0);
  expectCode(() => s.sign(m(8)), 'Exhausted');
  expect(s.sign(m(9)).toBytes()).toEqual(z.toBytes());
  s.close();

  // The one-leaf instance.
  const once = winternitzSigner.SigningKey.create(join(dir, 'once.key'));
  const sig = once.sign(m(5));
  (once.verifyingKey()).verify(m(5), sig);
  expect(once.sign(m(5)).toBytes()).toEqual(sig.toBytes());
  expectCode(() => once.sign(m(6)), 'Exhausted');
  once.close();
  rmSync(dir, { recursive: true });
}, 60_000); // builds the 256-leaf key on every open

test('the lock dies with its holder', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'solana-winternitz-'));
  const path = join(dir, 'once.key');
  winternitzSigner.SigningKey.create(path).close();
  const source = new URL('../src/signer.ts', import.meta.url).pathname;
  const holder = spawn(process.execPath, [
    '-e',
    `const { winternitz } = await import(${JSON.stringify(source)}); winternitz.SigningKey.open(${JSON.stringify(path)}); console.log('HOLDING'); await new Promise(() => {});`,
  ]);
  await new Promise<void>((resolve, reject) => {
    holder.stdout.on('data', (chunk: Buffer) => chunk.toString().includes('HOLDING') && resolve());
    holder.on('exit', (code) => reject(new Error(`holder exited with ${code}`)));
  });
  expectCode(() => winternitzSigner.SigningKey.open(path), 'Locked');
  holder.kill('SIGKILL');
  await once(holder, 'exit');
  winternitzSigner.SigningKey.open(path).close();
  rmSync(dir, { recursive: true });
}, 30_000);

test('the key file written by the Rust crate opens here', () => {
  const dir = mkdtempSync(join(tmpdir(), 'solana-winternitz-'));
  const path = join(dir, 'once.key');
  writeFileSync(path, readFileSync(new URL('../../../tests/winternitz.key', import.meta.url)));
  const record = readFileSync(path);
  const once = winternitzSigner.SigningKey.open(path);
  expect(once.remaining()).toBe(0);
  expect(hex(once.sign(record.subarray(25, 57)).toBytes())).toBe(sampled.one_time_signature);
  expect(readFileSync(path)).toEqual(record);
  once.close();
  rmSync(dir, { recursive: true });
});

test('inputs are range-checked', () => {
  const p = new Uint8Array(PARAMETER_LEN);
  const m = new Uint8Array(MESSAGE_LEN);
  const salt = new Uint8Array(21);
  const key = hazmat.winternitz.SecretKey.fromSecrets(new Uint8Array(828), p);
  expectCode(() => sampledTree.signAtWithSalt(xmss.LEAVES, m, salt), 'InvalidEncoding');
  expectCode(() => key.signAtWithSalt(0, new Uint8Array(31), salt), 'InvalidLength');
  expectCode(() => key.signAtWithSalt(1, m, salt), 'InvalidEncoding');
  expectCode(() => key.signAtWithSalt(0, m, new Uint8Array(20)), 'InvalidLength');
  expectCode(() => (VerifyingKey.fromBytes(new Uint8Array(41))).verify(new Uint8Array(33), winternitz.Signature.fromBytes(new Uint8Array(849))), 'InvalidLength');
  expectCode(() => hazmat.winternitz.SecretKey.fromSecrets(new Uint8Array(32), p), 'InvalidLength');
  expectCode(() => hazmat.xmss.SecretKey.fromSecrets(new Uint8Array(828), p), 'InvalidLength');
  expectCode(() => hazmat.winternitz.SecretKey.fromSecrets(new Uint8Array(828), new Uint8Array(17)), 'InvalidLength');
  expectCode(() => winternitz.Signature.fromBytes(new Uint8Array(848)), 'InvalidLength');
  expectCode(() => xmss.Signature.fromBytes(new Uint8Array(1036)), 'InvalidLength');
  expectCode(() => VerifyingKey.fromBytes(new Uint8Array(40)), 'InvalidLength');
});

test('entropy failure, salt exhaustion, and write failure release no signature', () => {
  const dir = mkdtempSync(join(tmpdir(), 'solana-winternitz-'));
  const path = join(dir, 'once.key');
  const signer = xmssSigner.SigningKey.create(path);
  const m = new Uint8Array(32);
  const randomFill = crypto.randomFillSync;
  const fill = spyOn(crypto, 'randomFillSync');
  try {
    fill.mockImplementation(() => { throw new Error('entropy unavailable'); });
    expectCode(() => signer.sign(m), 'Random');
    expect(signer.nextLeaf()).toBe(1);
    // One known rejected candidate repeated K times deterministically forces exhaustion.
    const bad = new Uint8Array(21);
    const input = new Uint8Array(76);
    input.set(signer.verifyingKey().toBytes().subarray(23), 21);
    input[39] = 2;
    new DataView(input.buffer).setUint32(40, 1, true);
    input.set(m, 44);
    for (let counter = 0; ; counter++) {
      new DataView(bad.buffer).setUint32(0, counter, true);
      input.set(bad, 0);
      const sum = keccak_256(input).subarray(0, 18).reduce((n, b) => n + (b & 15) + (b >> 4), 0);
      if (sum !== 297) break;
    }
    fill.mockImplementation((buffer) => { new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength).set(bad); return buffer; });
    expectCode(() => signer.sign(m), 'SaltsExhausted');
    expect(signer.nextLeaf()).toBe(2);
    const before = readFileSync(path);
    expect(before[24]).toBe(0);
    fill.mockImplementation(randomFill);
    mkdirSync(`${path}.tmp`);
    expectCode(() => signer.sign(m), 'Io');
    expectCode(() => signer.sign(m), 'Unusable');
    expect(readFileSync(path)).toEqual(before);
    rmSync(`${path}.tmp`, { recursive: true });
    const again = xmssSigner.SigningKey.open(path);
    expect(again.nextLeaf()).toBe(2);
    const signature = again.sign(m);
    fill.mockImplementation(() => { throw new Error('retry drew entropy'); });
    expect(again.sign(m).toBytes()).toEqual(signature.toBytes());
    again.close();
    const reopened = xmssSigner.SigningKey.open(path);
    expect(reopened.sign(m).toBytes()).toEqual(signature.toBytes());
    reopened.close();
  } finally { fill.mockRestore(); signer.close(); rmSync(dir, { recursive: true, force: true }); }
});


test('encoded values own their bytes and failures have stable codes', () => {
  const bytes = new Uint8Array(VerifyingKey.BYTE_LEN).fill(7);
  const key = VerifyingKey.fromBytes(bytes);
  bytes.fill(0); key.toBytes().fill(0);
  expect(key.toBytes()).toEqual(new Uint8Array(41).fill(7));
  for (const type of [winternitz.Signature, xmss.Signature]) {
    const encoded = new Uint8Array(type.BYTE_LEN).fill(9);
    const signature = type.fromBytes(encoded);
    encoded.fill(0); signature.toBytes().fill(0);
    expect(signature.toBytes()).toEqual(new Uint8Array(type.BYTE_LEN).fill(9));
    try { key.verify(new Uint8Array(31), signature); throw new Error('accepted'); }
    catch (error) { expect(error).toBeInstanceOf(CryptoError); expect((error as CryptoError).code).toBe('InvalidLength'); }
    try { key.verify(new Uint8Array(32), signature); throw new Error('accepted'); }
    catch (error) { expect(error).toBeInstanceOf(CryptoError); expect((error as CryptoError).code).toBe('InvalidSignature'); }
  }
  const dir = mkdtempSync(join(tmpdir(), 'solana-winternitz-'));
  try {
    try { winternitzSigner.SigningKey.open(join(dir, 'missing')); throw new Error('accepted'); }
    catch (error) { expect(error).toBeInstanceOf(SigningError); expect((error as SigningError).code).toBe('Missing'); }
  } finally { rmSync(dir, { recursive: true }); }
});
