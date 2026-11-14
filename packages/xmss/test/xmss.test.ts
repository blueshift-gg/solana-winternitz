import { expect, test, spyOn } from 'bun:test';
import sampled from '../../../xmss/tests/sampled.json' with { type: 'json' };
import * as crypto from 'node:crypto';
import reference from '../../../xmss/tests/hash-sig.json' with { type: 'json' };
import vectors from '../../../xmss/tests/vectors.json' with { type: 'json' };
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runInNewContext } from 'node:vm';
import { type ErrorCode, CryptoError, MESSAGE_LEN, PARAMETER_LEN, PUBLIC_KEY_LEN, LEAVES, SIGNATURE_LEN, Signature, VerifyingKey } from '../src/index.js';
import { type SigningErrorCode, SigningError, SigningKey } from '../src/signer.js';
import { SecretKey } from '../src/hazmat.js';
import * as winternitz from '@blueshift-gg/solana-winternitz';
import { SigningKey as OneTimeSigningKey } from '@blueshift-gg/solana-winternitz/signer';
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

// Independent reference verification checks the hash layouts and authentication path.
test.each(reference.signatures)('the hash-sig signature at leaf $leaf verifies', ({ leaf, message, salt, elements, path }) => {
  const bytes = new Uint8Array(4 + (salt.length + elements.length + path.length) / 2);
  new DataView(bytes.buffer).setUint32(0, leaf, false);
  bytes.set(fromHex(salt + elements + path), 4);
  const signature = Signature.fromBytes(bytes);
  const key = VerifyingKey.fromBytes(fromHex(reference.public_key));
  expect(signature.leaf()).toBe(leaf);
  expect(() => (key).verify(fromHex(message), signature)).not.toThrow();
  const other = fromHex(message);
  other[0]! ^= 1;
  expectCode(() => (key).verify(other, signature), 'InvalidSignature');
});

// The same verify-only known answers the Rust `verify_vectors` test checks.
test('the shared vector file has every case', () => {
  expect(vectors.cases.length).toBe(11);
});
test.each(vectors.cases)('vector: $name', ({ message, signature, valid }) => {
  const key = VerifyingKey.fromBytes(fromHex(vectors.public_key));
  const sig = Signature.fromBytes(fromHex(signature));
  if (valid) expect(() => key.verify(fromHex(message), sig)).not.toThrow();
  else expectCode(() => key.verify(fromHex(message), sig), 'InvalidSignature');
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

const sampledTree = SecretKey.fromSecrets(Uint8Array.from({ length: 256 * 828 }, (_, i) => (i % 251) ^ 7), new Uint8Array(18).fill(0x57));
test.each(sampled.signatures)('explicit chain starts reproduce Rust signing at leaf $leaf', ({ leaf, signature }) => {
  const message = new Uint8Array(32);
  new DataView(message.buffer).setUint32(0, leaf, true);
  const sig = sampledTree.signAtWithSalt(leaf, message, acceptedSalt(sampledTree.verifyingKey().toBytes().subarray(23), leaf, message));
  expect(hex(sampledTree.verifyingKey().toBytes())).toBe(sampled.public_key);
  expect(hex(sig.toBytes())).toBe(signature);
  (sampledTree.verifyingKey()).verify(message, sig);
});

test('one-bit mutations at each fixture byte are rejected', () => {
  const vector = sampled.signatures[1]!;
  const message = new Uint8Array(32);
  new DataView(message.buffer).setUint32(0, vector.leaf, true);
  const x = { signature: vector.signature, message: hex(message) };
  const xpk = VerifyingKey.fromBytes(fromHex(sampled.public_key));
  for (let i = 0; i < SIGNATURE_LEN; i++) {
    const bad = fromHex(x.signature);
    bad[i]! ^= 1;
    expectCode(() => (xpk).verify(fromHex(x.message), Signature.fromBytes(bad)), 'InvalidSignature');
  }
});

test('the signer owns leaf allocation', () => {
  const dir = mkdtempSync(join(tmpdir(), 'solana-winternitz-'));
  const path = join(dir, 'tree.key');
  const m = (n: number) => new Uint8Array(MESSAGE_LEN).fill(n);

  const signer = SigningKey.create(path);
  expect(signer.remaining()).toBe(LEAVES);
  expectCode(() => SigningKey.create(path), 'Locked');
  expectCode(() => SigningKey.open(path), 'Locked');

  const a = signer.sign(m(1));
  expect(a.leaf()).toBe(0);
  (signer.verifyingKey()).verify(m(1), a);
  expect(signer.sign(m(1)).toBytes()).toEqual(a.toBytes());
  expect(signer.remaining()).toBe(LEAVES - 1);
  const b = signer.sign(m(2));
  expect(b.leaf()).toBe(1);
  signer.close();
  expectCode(() => signer.sign(m(3)), 'Unusable');

  expectCode(() => SigningKey.create(path), 'Exists');
  expectCode(() => OneTimeSigningKey.open(path), 'Corrupt');
  expectCode(() => SigningKey.open(join(dir, 'none.key')), 'Missing');

  // Restart: continue at the record; an older message is a new leaf.
  const again = SigningKey.open(path);
  expect(again.nextLeaf()).toBe(2);
  expect(again.sign(m(2)).toBytes()).toEqual(b.toBytes());
  expect(again.sign(m(1)).leaf()).toBe(2);
  again.close();
  expectCode(() => SigningKey.open(path).requireNextLeafAtLeast(4), 'LeafBelowMinimum');
  expectCode(() => SigningKey.open(path).requireNextLeafAtLeast(-1), 'InvalidEncoding');
  SigningKey.open(path).requireNextLeafAtLeast(3).close();

  // A stale temp file is ignored, and the sidecar's content is not the lock.
  writeFileSync(`${path}.tmp`, 'garbage');
  writeFileSync(`${path}.lock`, 'anything');
  const after = SigningKey.open(path);
  expect(after.nextLeaf()).toBe(3);
  after.close();
  expect(existsSync(`${path}.lock`)).toBe(true);
  // A truncated record and a self-contradicting one are refused.
  const record = readFileSync(path);
  writeFileSync(path, record.subarray(0, record.length - 1));
  expectCode(() => SigningKey.open(path), 'Corrupt');
  const contradiction = Buffer.from(record);
  contradiction.writeUInt32BE(0, 2 + PARAMETER_LEN);
  writeFileSync(path, contradiction);
  expectCode(() => SigningKey.open(path), 'Corrupt');

  // Last leaf: one more message, then only that one.
  const last = Buffer.from(record);
  last.writeUInt32BE(LEAVES - 1, 2 + PARAMETER_LEN);
  last.set(acceptedSalt(last.subarray(2, 20), LEAVES - 2, last.subarray(25, 57)), 57);
  writeFileSync(path, last);
  const s = SigningKey.open(path);
  expect(s.remaining()).toBe(1);
  const z = s.sign(m(9));
  expect(z.leaf()).toBe(LEAVES - 1);
  expect(s.remaining()).toBe(0);
  expectCode(() => s.sign(m(8)), 'Exhausted');
  expect(s.sign(m(9)).toBytes()).toEqual(z.toBytes());
  s.close();

  rmSync(dir, { recursive: true });
}, 60_000); // builds the 256-leaf key on every open

test('inputs are range-checked', () => {
  const p = new Uint8Array(PARAMETER_LEN);
  const m = new Uint8Array(MESSAGE_LEN);
  expectCode(() => sampledTree.signAtWithSalt(LEAVES, m, new Uint8Array(21)), 'InvalidEncoding');
  expectCode(() => SecretKey.fromSecrets(new Uint8Array(828), p), 'InvalidLength');
  expectCode(() => Signature.fromBytes(new Uint8Array(1036)), 'InvalidLength');
  expectCode(() => VerifyingKey.fromBytes(new Uint8Array(40)), 'InvalidLength');
  expect(PUBLIC_KEY_LEN).toBe(41);
  expect(SIGNATURE_LEN).toBe(1037);
});

test('one-time and tree signatures are not interchangeable', () => {
  const m = new Uint8Array(MESSAGE_LEN).fill(3);
  const once = winternitz.Signature.fromBytes(sampledTree.signAtWithSalt(0, m, acceptedSalt(sampledTree.parameter, 0, m)).toBytes().subarray(4, 4 + winternitz.SIGNATURE_LEN));
  expectCode(() => winternitz.VerifyingKey.fromBytes(sampledTree.verifyingKey().toBytes()).verify(m, once), 'InvalidSignature');
  expectCode(() => sampledTree.verifyingKey().verify(m, once as unknown as Signature), 'InvalidSignature');
});

test('entropy failure, salt exhaustion, and write failure release no signature', () => {
  const dir = mkdtempSync(join(tmpdir(), 'solana-winternitz-'));
  const path = join(dir, 'once.key');
  const signer = SigningKey.create(path);
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
    fill.mockImplementation(((buffer: Uint8Array) => { buffer.set(bad); return buffer; }) as typeof crypto.randomFillSync);
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
    const again = SigningKey.open(path);
    expect(again.nextLeaf()).toBe(2);
    const signature = again.sign(m);
    fill.mockImplementation(() => { throw new Error('retry drew entropy'); });
    expect(again.sign(m).toBytes()).toEqual(signature.toBytes());
    again.close();
    const reopened = SigningKey.open(path);
    expect(reopened.sign(m).toBytes()).toEqual(signature.toBytes());
    reopened.close();
  } finally { fill.mockRestore(); signer.close(); rmSync(dir, { recursive: true, force: true }); }
});


test('encoded values own their bytes', () => {
  const encoded = new Uint8Array(Signature.BYTE_LEN).fill(9);
  const signature = Signature.fromBytes(encoded);
  encoded.fill(0); signature.toBytes().fill(0);
  expect(signature.toBytes()).toEqual(new Uint8Array(Signature.BYTE_LEN).fill(9));
  const key = VerifyingKey.fromBytes(new Uint8Array(41).fill(7));
  expectCode(() => key.verify(new Uint8Array(31), signature), 'InvalidLength');
  expectCode(() => key.verify(new Uint8Array(32), signature), 'InvalidSignature');
});
