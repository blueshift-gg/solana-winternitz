import { expect, test } from 'bun:test';
import sampled from '../../../tests/sampled.json' with { type: 'json' };
import vectors from '../../../tests/vectors.json' with { type: 'json' };
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runInNewContext } from 'node:vm';
import { type ErrorCode, CryptoError, MESSAGE_LEN, PARAMETER_LEN, PUBLIC_KEY_LEN, SIGNATURE_LEN, Signature, VerifyingKey } from '../src/index.js';
import { type SigningErrorCode, SigningError, SigningKey } from '../src/signer.js';
import { SecretKey } from '../src/hazmat.js';
import { node } from '../src/primitives.js';
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
      using signer = SigningKey.create(path);
      expect(signer.remaining()).toBe(1);
      expectCode(() => SigningKey.open(path), 'Locked');
    }
    const failure = new Error('leave the scope');
    try {
      using signer = SigningKey.open(path);
      expect(signer.remaining()).toBe(1);
      throw failure;
    } catch (error) { expect(error).toBe(failure); }
    using signer = SigningKey.open(path);
    expect(signer.remaining()).toBe(1);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('explicit randomness cannot mutate retries, reenter signing, or release the lock', () => {
  const dir = mkdtempSync(join(tmpdir(), 'solana-winternitz-rng-'));
  const path = join(dir, 'once.key');
  const message = new Uint8Array(MESSAGE_LEN).fill(7);
  const original = message.slice();
  try {
    using signer = SigningKey.create(path);
    const salt = acceptedSalt(signer.verifyingKey().toBytes().subarray(23), 0, message);
    let retained: Uint8Array | undefined;
    const signature = signer.signWithRng(message, (out) => {
      expectCode(() => signer.sign(new Uint8Array(MESSAGE_LEN)), 'Unusable');
      expectCode(() => signer.close(), 'Unusable');
      expectCode(() => SigningKey.open(path), 'Locked');
      message.fill(0);
      out.set(salt);
      retained = out;
    });
    retained!.fill(0);
    const retryRng = () => { throw new Error('retry must not request entropy'); };
    expect(signer.signWithRng(original, retryRng).toBytes()).toEqual(signature.toBytes());
    signer.verifyingKey().verify(original, signature);
    signer.close();
    using reopened = SigningKey.open(path);
    expect(reopened.signWithRng(original, retryRng).toBytes()).toEqual(signature.toBytes());
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// The same verify-only known answers the Rust `verify_vectors` test checks.
test('the shared vector file has every case', () => {
  expect(vectors.cases.length).toBe(4);
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

test('one-bit mutations at each fixture byte are rejected', () => {
  const record = readFileSync(new URL('../../../tests/winternitz.key', import.meta.url));
  const input = record.subarray(25, 57);
  const pk = SecretKey.fromSecrets(record.subarray(78), record.subarray(2, 20)).verifyingKey();
  const w = { signature: sampled.one_time_signature, message: hex(input), public_key: hex(pk.toBytes()) };
  for (let i = 0; i < SIGNATURE_LEN; i++) {
    const bad = fromHex(w.signature);
    bad[i]! ^= 1;
    expectCode(() => (pk).verify(input, Signature.fromBytes(bad)), 'InvalidSignature');
  }
  for (let i = 0; i < PUBLIC_KEY_LEN; i++) {
    const bad = fromHex(w.public_key);
    bad[i]! ^= 1;
    expectCode(() => (VerifyingKey.fromBytes(bad)).verify(input, Signature.fromBytes(fromHex(w.signature))), 'InvalidSignature');
  }
  for (let i = 0; i < MESSAGE_LEN; i++) {
    const bad = fromHex(w.message);
    bad[i]! ^= 1;
    expectCode(() => (pk).verify(bad, Signature.fromBytes(fromHex(w.signature))), 'InvalidSignature');
  }

});

test('the one-time signer signs one message', () => {
  const dir = mkdtempSync(join(tmpdir(), 'solana-winternitz-'));
  const path = join(dir, 'once.key');
  const m = (n: number) => new Uint8Array(MESSAGE_LEN).fill(n);
  try {
    const signer = SigningKey.create(path);
    expect(signer.remaining()).toBe(1);
    expectCode(() => SigningKey.create(path), 'Locked');
    const sig = signer.sign(m(5));
    signer.verifyingKey().verify(m(5), sig);
    expect(signer.sign(m(5)).toBytes()).toEqual(sig.toBytes());
    expectCode(() => signer.sign(m(6)), 'Exhausted');
    expect(signer.remaining()).toBe(0);
    signer.close();
    expectCode(() => signer.sign(m(5)), 'Unusable');
    expectCode(() => SigningKey.create(path), 'Exists');
    expectCode(() => SigningKey.open(join(dir, 'none.key')), 'Missing');
    const again = SigningKey.open(path);
    expect(again.sign(m(5)).toBytes()).toEqual(sig.toBytes());
    expectCode(() => again.sign(m(6)), 'Exhausted');
    again.close();
    // A truncated record and a self-contradicting one are refused.
    const record = readFileSync(path);
    writeFileSync(path, record.subarray(0, record.length - 1));
    expectCode(() => SigningKey.open(path), 'Corrupt');
    const contradiction = Buffer.from(record);
    contradiction.writeUInt32BE(0, 2 + PARAMETER_LEN);
    writeFileSync(path, contradiction);
    expectCode(() => SigningKey.open(path), 'Corrupt');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('leaves and Merkle nodes cannot share a hash domain', () => {
  const p = new Uint8Array(PARAMETER_LEN);
  const child = new Uint8Array(23);
  expect(() => node(p, 0, 0, child, child)).toThrow(RangeError);
  const input = new Uint8Array([...p, 1, 3, 0, 0, 0, 5, ...child.fill(1), ...new Uint8Array(23).fill(2)]);
  expect(node(p, 3, 5, new Uint8Array(23).fill(1), new Uint8Array(23).fill(2))).toEqual(keccak_256(input).subarray(0, 23));
});

test('the lock dies with its holder', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'solana-winternitz-'));
  const path = join(dir, 'once.key');
  SigningKey.create(path).close();
  const source = new URL('../src/signer.ts', import.meta.url).pathname;
  const holder = spawn(process.execPath, [
    '-e',
    `const { SigningKey } = await import(${JSON.stringify(source)}); SigningKey.open(${JSON.stringify(path)}); console.log('HOLDING'); await new Promise(() => {});`,
  ]);
  await new Promise<void>((resolve, reject) => {
    holder.stdout.on('data', (chunk: Buffer) => chunk.toString().includes('HOLDING') && resolve());
    holder.on('exit', (code) => reject(new Error(`holder exited with ${code}`)));
  });
  expectCode(() => SigningKey.open(path), 'Locked');
  holder.kill('SIGKILL');
  await once(holder, 'exit');
  SigningKey.open(path).close();
  rmSync(dir, { recursive: true });
}, 30_000);

test('the key file written by the Rust crate opens here', () => {
  const dir = mkdtempSync(join(tmpdir(), 'solana-winternitz-'));
  const path = join(dir, 'once.key');
  writeFileSync(path, readFileSync(new URL('../../../tests/winternitz.key', import.meta.url)));
  const record = readFileSync(path);
  const once = SigningKey.open(path);
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
  const key = SecretKey.fromSecrets(new Uint8Array(828), p);
  expectCode(() => key.signAtWithSalt(0, new Uint8Array(31), salt), 'InvalidLength');
  expectCode(() => key.signAtWithSalt(1, m, salt), 'InvalidEncoding');
  expectCode(() => key.signAtWithSalt(0, m, new Uint8Array(20)), 'InvalidLength');
  expectCode(() => (VerifyingKey.fromBytes(new Uint8Array(41))).verify(new Uint8Array(33), Signature.fromBytes(new Uint8Array(849))), 'InvalidLength');
  expectCode(() => SecretKey.fromSecrets(new Uint8Array(32), p), 'InvalidLength');
  expectCode(() => SecretKey.fromSecrets(new Uint8Array(2 * 828), p), 'InvalidLength');
  expectCode(() => SecretKey.fromSecrets(new Uint8Array(828), new Uint8Array(17)), 'InvalidLength');
  expectCode(() => Signature.fromBytes(new Uint8Array(848)), 'InvalidLength');
  expectCode(() => VerifyingKey.fromBytes(new Uint8Array(40)), 'InvalidLength');
});

test('encoded values own their bytes and failures have stable codes', () => {
  const bytes = new Uint8Array(VerifyingKey.BYTE_LEN).fill(7);
  const key = VerifyingKey.fromBytes(bytes);
  bytes.fill(0); key.toBytes().fill(0);
  expect(key.toBytes()).toEqual(new Uint8Array(41).fill(7));
  for (const type of [Signature]) {
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
    try { SigningKey.open(join(dir, 'missing')); throw new Error('accepted'); }
    catch (error) { expect(error).toBeInstanceOf(SigningError); expect((error as SigningError).code).toBe('Missing'); }
  } finally { rmSync(dir, { recursive: true }); }
});
