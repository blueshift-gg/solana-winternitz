import { keccak_256 } from '@noble/hashes/sha3.js';
import { CryptoError, SigningError, signingError, type FillRandom } from './error.js';

/** 36 four-bit digits from an 18-byte hash; ≥ 138 bits, eq. (13). */
export const CHAINS = 36;
export const POSITIONS = 16;
/** `n`, chain elements, leaves and nodes alike: eq. (15) at L = 2^8. */
export const ELEMENT_LENGTH = 23;
/** `ρ`: eq. (14) at L = 2^8, K = 2^12. */
export const SALT_LENGTH = 21;
/** `P`: eq. (16). */
export const PARAMETER_LEN = 18;
export const ELEMENTS_LENGTH = CHAINS * ELEMENT_LENGTH;
/** §8 target: 243 verifier chain steps; equal-sum vectors are incomparable (Lemma 7). */
export const TARGET_SUM = 297;
/** `K` of Construction 3. Lemma 3 bounds failure by encoding error raised to `K`. */
export const MAX_TRIALS = 4096;
export const ROLE_CHAIN = 0;
export const ROLE_TREE = 1;
export const ROLE_MESSAGE = 2;
/** Application-supplied digest length in bytes (Remark 1). */
export const MESSAGE_LEN = 32;

/** `node || P`: the leaf for `winternitz`, the Merkle root for `xmss`. */
export const PUBLIC_KEY_LEN = ELEMENT_LENGTH + PARAMETER_LEN;

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export function bytes(value: Uint8Array, length: number, what: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== length) throw new CryptoError('InvalidLength', `${what}: expected ${length} bytes`);
  return Uint8Array.from(value);
}

export function u32be(n: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, false);
  return out;
}

export function u32le(n: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, true);
  return out;
}

export function equal(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

/** Construction 6: low-first nibbles and a little-endian message tweak, as in hash-sig. */
export function encode(salt: Uint8Array, parameter: Uint8Array, leaf: number, message: Uint8Array): Uint8Array | undefined {
  const digest = keccak_256(concat(salt, parameter, Uint8Array.of(ROLE_MESSAGE), u32le(leaf), message));
  const x = Uint8Array.from({ length: CHAINS }, (_, i) => (digest[i >> 1]! >> (4 * (i & 1))) & 0x0f);
  return x.reduce((a, b) => a + b, 0) === TARGET_SUM ? x : undefined;
}

/** The step entering `k` uses tweak `k`; Lemma 2 permits splitting at the signed position. */
export function walk(parameter: Uint8Array, leaf: number, i: number, from: number, to: number, x: Uint8Array): Uint8Array {
  for (let k = from; k < to; k++) {
    x = keccak_256(concat(parameter, Uint8Array.of(ROLE_CHAIN), u32be(leaf), Uint8Array.of(i, k + 1), x)).subarray(0, ELEMENT_LENGTH);
  }
  return x;
}

export function treeTweak(level: number, index: number): Uint8Array {
  return concat(Uint8Array.of(ROLE_TREE, level), u32be(index));
}

/** Construction 1 leaf over the 36 chain ends. */
export function leafHash(parameter: Uint8Array, leaf: number, ends: Uint8Array[]): Uint8Array {
  return keccak_256(concat(parameter, treeTweak(0, leaf), ...ends)).subarray(0, ELEMENT_LENGTH);
}

/** Construction 1 node. */
export function node(parameter: Uint8Array, level: number, index: number, left: Uint8Array, right: Uint8Array): Uint8Array {
  return keccak_256(concat(parameter, treeTweak(level, index), left, right)).subarray(0, ELEMENT_LENGTH);
}

/** Explicit chain starts, in leaf-major, chain-major order. */
export function start(secrets: Uint8Array, leaf: number, i: number): Uint8Array {
  const offset = leaf * ELEMENTS_LENGTH + i * ELEMENT_LENGTH;
  return secrets.subarray(offset, offset + ELEMENT_LENGTH);
}

export function endsOf(secrets: Uint8Array, parameter: Uint8Array, leaf: number): Uint8Array[] {
  return Array.from({ length: CHAINS }, (_, i) => walk(parameter, leaf, i, 0, POSITIONS - 1, start(secrets, leaf, i)));
}

export function endsFromSignature(parameter: Uint8Array, leaf: number, x: Uint8Array, elements: Uint8Array): Uint8Array[] {
  return Array.from({ length: CHAINS }, (_, i) =>
    walk(parameter, leaf, i, x[i]!, POSITIONS - 1, elements.subarray(i * ELEMENT_LENGTH, (i + 1) * ELEMENT_LENGTH)),
  );
}

/** Construction 3 Sig with an already accepted salt. */
export function signLeaf(secrets: Uint8Array, parameter: Uint8Array, leaf: number, message: Uint8Array, salt: Uint8Array): Uint8Array {
  const x = encode(salt, parameter, leaf, message);
  if (!x) throw new CryptoError('InvalidEncoding', 'salt misses the target sum');
  const elements = Array.from({ length: CHAINS }, (_, i) => walk(parameter, leaf, i, 0, x[i]!, start(secrets, leaf, i)));
  return concat(salt, ...elements);
}
export function sampleSalt(parameter: Uint8Array, leaf: number, message: Uint8Array, fill: FillRandom): Uint8Array {
  const salt = new Uint8Array(SALT_LENGTH);
  for (let trial = 0; trial < MAX_TRIALS; trial++) {
    try { fill(salt); } catch (error) { throw signingError(error, 'Random'); }
    if (encode(salt, parameter, leaf, message)) return salt.slice();
  }
  throw new SigningError('SaltsExhausted', '4096 salts missed the target sum; the leaf is spent');
}

/** Sample a raw key through bounded CSPRNG requests; wipe temporary secrets on every exit. */
export function generateKey<K>(leaves: number, fromSecrets: (secrets: Uint8Array, parameter: Uint8Array) => K, fill: FillRandom): K {
  const secrets = new Uint8Array(leaves * ELEMENTS_LENGTH);
  try {
    for (let offset = 0; offset < secrets.length; offset += ELEMENTS_LENGTH) fill(secrets.subarray(offset, offset + ELEMENTS_LENGTH));
    const parameter = new Uint8Array(PARAMETER_LEN);
    fill(parameter);
    return fromSecrets(secrets, parameter);
  } catch (error) { throw signingError(error, 'Random'); }
  finally { secrets.fill(0); }
}
