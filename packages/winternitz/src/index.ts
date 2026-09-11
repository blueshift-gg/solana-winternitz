// Generalized XMSS with target-sum Winternitz over SHA-256 (DKKW25). The signer side of the
// `solana-winternitz` crate: the on-chain program verifies what `sign` emits, and every byte here is
// pinned to the Rust crate by `tests/vectors.json`.
//
// `winternitz`: lifetime 1, one signature per key. `xmss`: lifetime 256, one signature per epoch under
// a Merkle tree. Both use the 56-byte public key `node || P`. Every hash input starts with a role byte.

import { sha256 } from '@noble/hashes/sha2.js';

const CHAINS = 35;
const POSITIONS = 16;
const ELEMENT_LENGTH = 24;
const SALT_LENGTH = 24;
const PARAMETER_LENGTH = 24;
const NODE_LENGTH = 32;
const ELEMENTS_LENGTH = CHAINS * ELEMENT_LENGTH;
/** Verifier steps `35 × 15 − 325 = 200`; one uniform digest in ~940 lands on the target. */
const TARGET_SUM = 325;
const MAX_TRIALS = 1 << 16;
const ROLE_CHAIN = 0;
const ROLE_TREE = 1;
const ROLE_MESSAGE = 2;
const ROLE_SEED = 3;

/** `node || P`: the leaf for `winternitz`, the Merkle root for `xmss`. */
export const PUBLIC_KEY_LENGTH = NODE_LENGTH + PARAMETER_LENGTH;

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

function bytes(value: Uint8Array | ArrayLike<number>, length: number, what: string): Uint8Array {
  const out = Uint8Array.from(value);
  if (out.length !== length) throw new TypeError(`${what}: expected ${length} bytes, got ${out.length}`);
  return out;
}

function u32be(n: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, false);
  return out;
}

function u32le(n: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, true);
  return out;
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

/** The first 140 bits of `SHA-256(0x02 || epoch || salt || P || m)` as nibbles, low nibble first, if they sum to the target. */
function encode(salt: Uint8Array, parameter: Uint8Array, epoch: number, message: Uint8Array): Uint8Array | undefined {
  const digest = sha256(concat(Uint8Array.of(ROLE_MESSAGE), u32be(epoch), salt, parameter, message));
  const x = Uint8Array.from({ length: CHAINS }, (_, i) => (digest[i >> 1]! >> (4 * (i & 1))) & 0x0f);
  return x.reduce((a, b) => a + b, 0) === TARGET_SUM ? x : undefined;
}

/** Walk chain `i` of `epoch` from position `from` to `to`; the step into `k` is `SHA-256(0x00 || epoch || i || k || P || x)[..24]`. */
function walk(parameter: Uint8Array, epoch: number, i: number, from: number, to: number, x: Uint8Array): Uint8Array {
  for (let k = from; k < to; k++) {
    x = sha256(concat(Uint8Array.of(ROLE_CHAIN), u32be(epoch), Uint8Array.of(i, k + 1), parameter, x)).subarray(0, ELEMENT_LENGTH);
  }
  return x;
}

function treeTweak(level: number, index: number): Uint8Array {
  return concat(Uint8Array.of(ROLE_TREE, level), u32be(index));
}

/** `SHA-256(0x01 || 0 || epoch || P || pk_0 || … || pk_34)`. */
function leaf(parameter: Uint8Array, epoch: number, ends: Uint8Array[]): Uint8Array {
  return sha256(concat(treeTweak(0, epoch), parameter, ...ends));
}

/** `SHA-256(0x01 || level || index || P || left || right)`. */
function node(parameter: Uint8Array, level: number, index: number, left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(concat(treeTweak(level, index), parameter, left, right));
}

/** Key derivation `SHA-256(0x03 || purpose || fields || seed)`. */
function parameterOf(seed: Uint8Array): Uint8Array {
  return sha256(concat(Uint8Array.of(ROLE_SEED, 0), seed)).subarray(0, PARAMETER_LENGTH);
}

function start(seed: Uint8Array, epoch: number, i: number): Uint8Array {
  return sha256(concat(Uint8Array.of(ROLE_SEED, 1), u32be(epoch), Uint8Array.of(i), seed)).subarray(0, ELEMENT_LENGTH);
}

function endsOf(seed: Uint8Array, parameter: Uint8Array, epoch: number): Uint8Array[] {
  return Array.from({ length: CHAINS }, (_, i) => walk(parameter, epoch, i, 0, POSITIONS - 1, start(seed, epoch, i)));
}

function endsFromSignature(parameter: Uint8Array, epoch: number, x: Uint8Array, elements: Uint8Array): Uint8Array[] {
  return Array.from({ length: CHAINS }, (_, i) =>
    walk(parameter, epoch, i, x[i]!, POSITIONS - 1, elements.subarray(i * ELEMENT_LENGTH, (i + 1) * ELEMENT_LENGTH)),
  );
}

/** Salt and chain elements for one leaf: salts are `SHA-256(0x03 || 2 || epoch || ctr || SHA-256(m) || seed)`. */
function signLeaf(seed: Uint8Array, parameter: Uint8Array, epoch: number, message: Uint8Array): Uint8Array {
  const digest = sha256(message);
  for (let ctr = 0; ctr < MAX_TRIALS; ctr++) {
    const salt = sha256(concat(Uint8Array.of(ROLE_SEED, 2), u32be(epoch), u32be(ctr), digest, seed)).subarray(0, SALT_LENGTH);
    const x = encode(salt, parameter, epoch, message);
    if (!x) continue;
    const elements = Array.from({ length: CHAINS }, (_, i) => walk(parameter, epoch, i, 0, x[i]!, start(seed, epoch, i)));
    return concat(salt, ...elements);
  }
  throw new Error('no salt reached the target sum in 65536 attempts');
}

/** `node || P`, 56 bytes: what a program stores. */
export class PublicKey {
  readonly #bytes: Uint8Array;

  private constructor(data: Uint8Array) {
    this.#bytes = data;
  }

  static from(value: Uint8Array | ArrayLike<number>): PublicKey {
    return new PublicKey(bytes(value, PUBLIC_KEY_LENGTH, 'public key'));
  }

  get bytes(): Uint8Array {
    return this.#bytes.slice();
  }

  /** @internal */
  get node(): Uint8Array {
    return this.#bytes.subarray(0, NODE_LENGTH);
  }

  /** @internal */
  get parameter(): Uint8Array {
    return this.#bytes.subarray(NODE_LENGTH);
  }
}

export namespace winternitz {
  /** `salt || 35 chain elements`. */
  export const SIGNATURE_LENGTH = SALT_LENGTH + ELEMENTS_LENGTH;

  export class Signature {
    readonly #bytes: Uint8Array;

    private constructor(data: Uint8Array) {
      this.#bytes = data;
    }

    static from(value: Uint8Array | ArrayLike<number>): Signature {
      return new Signature(bytes(value, SIGNATURE_LENGTH, 'signature'));
    }

    get bytes(): Uint8Array {
      return this.#bytes.slice();
    }

    /** What the on-chain verifier computes: throws `invalid signature` unless the chains close on the key. */
    verify(publicKey: PublicKey, message: Uint8Array): void {
      const x = encode(this.#bytes.subarray(0, SALT_LENGTH), publicKey.parameter, 0, message);
      if (!x) throw new Error('invalid signature');
      const ends = endsFromSignature(publicKey.parameter, 0, x, this.#bytes.subarray(SALT_LENGTH));
      if (!equal(leaf(publicKey.parameter, 0, ends), publicKey.node)) throw new Error('invalid signature');
    }
  }

  /** A one-time key derived from a 32-byte seed. `sign` may be called once. */
  export class SecretKey {
    readonly #seed: Uint8Array;
    #used = false;

    private constructor(seed: Uint8Array) {
      this.#seed = seed;
    }

    static fromSeed(seed: Uint8Array | ArrayLike<number>): SecretKey {
      return new SecretKey(bytes(seed, 32, 'seed'));
    }

    get publicKey(): PublicKey {
      const parameter = parameterOf(this.#seed);
      return PublicKey.from(concat(leaf(parameter, 0, endsOf(this.#seed, parameter, 0)), parameter));
    }

    /** Deterministic in seed and message. Throws on a second call: signing twice with one key leaks it. */
    sign(message: Uint8Array): Signature {
      if (this.#used) throw new Error('one-time key already used');
      this.#used = true;
      return Signature.from(signLeaf(this.#seed, parameterOf(this.#seed), 0, message));
    }
  }
}

export namespace xmss {
  export const HEIGHT = 8;
  export const LEAVES = 1 << HEIGHT;
  /** `epoch LE || salt || 35 chain elements || authentication path`. */
  export const SIGNATURE_LENGTH = 4 + SALT_LENGTH + ELEMENTS_LENGTH + HEIGHT * NODE_LENGTH;

  const ELEMENTS = 4 + SALT_LENGTH;
  const PATH = ELEMENTS + ELEMENTS_LENGTH;
  const levelOffset = (l: number) => 2 * LEAVES - (2 << (HEIGHT - l));

  export class Signature {
    readonly #bytes: Uint8Array;

    private constructor(data: Uint8Array) {
      this.#bytes = data;
    }

    static from(value: Uint8Array | ArrayLike<number>): Signature {
      return new Signature(bytes(value, SIGNATURE_LENGTH, 'signature'));
    }

    get bytes(): Uint8Array {
      return this.#bytes.slice();
    }

    /** The leaf this signature spends. A verifier must reject any epoch at or below the last accepted one. */
    get epoch(): number {
      return new DataView(this.#bytes.buffer, this.#bytes.byteOffset).getUint32(0, true);
    }

    /** What the on-chain verifier computes: throws `invalid signature` unless the path closes on the root. */
    verify(publicKey: PublicKey, message: Uint8Array): void {
      const epoch = this.epoch;
      if (epoch >= LEAVES) throw new Error('invalid signature');
      const parameter = publicKey.parameter;
      const x = encode(this.#bytes.subarray(4, ELEMENTS), parameter, epoch, message);
      if (!x) throw new Error('invalid signature');
      let current = leaf(parameter, epoch, endsFromSignature(parameter, epoch, x, this.#bytes.subarray(ELEMENTS, PATH)));
      for (let level = 1; level <= HEIGHT; level++) {
        const sibling = this.#bytes.subarray(PATH + (level - 1) * NODE_LENGTH, PATH + level * NODE_LENGTH);
        const index = epoch >> level;
        current = (epoch >> (level - 1)) & 1 ? node(parameter, level, index, sibling, current) : node(parameter, level, index, current, sibling);
      }
      if (!equal(current, publicKey.node)) throw new Error('invalid signature');
    }
  }

  /** A 256-leaf key. Construction walks every chain of every leaf, ~135k SHA-256 calls. */
  export class SecretKey {
    readonly #seed: Uint8Array;
    readonly #parameter: Uint8Array;
    /** Level-major: leaves first, root last. */
    readonly #nodes: Uint8Array[];

    private constructor(seed: Uint8Array) {
      this.#seed = seed;
      this.#parameter = parameterOf(seed);
      this.#nodes = new Array(2 * LEAVES - 1);
      for (let epoch = 0; epoch < LEAVES; epoch++) this.#nodes[epoch] = leaf(this.#parameter, epoch, endsOf(seed, this.#parameter, epoch));
      for (let l = 1; l <= HEIGHT; l++) {
        for (let i = 0; i < LEAVES >> l; i++) {
          const child = levelOffset(l - 1) + 2 * i;
          this.#nodes[levelOffset(l) + i] = node(this.#parameter, l, i, this.#nodes[child]!, this.#nodes[child + 1]!);
        }
      }
    }

    static fromSeed(seed: Uint8Array | ArrayLike<number>): SecretKey {
      return new SecretKey(bytes(seed, 32, 'seed'));
    }

    get publicKey(): PublicKey {
      return PublicKey.from(concat(this.#nodes[levelOffset(HEIGHT)]!, this.#parameter));
    }

    /**
     * Sign with leaf `epoch`. The caller owns the rule that an epoch is used once: keep the highest
     * epoch ever signed, including in transactions that failed. Deterministic in seed, epoch, message.
     */
    sign(epoch: number, message: Uint8Array): Signature {
      if (!Number.isInteger(epoch) || epoch < 0 || epoch >= LEAVES) throw new RangeError(`epoch: expected 0..${LEAVES}`);
      const path = Array.from({ length: HEIGHT }, (_, l) => this.#nodes[levelOffset(l) + ((epoch >> l) ^ 1)]!);
      return Signature.from(concat(u32le(epoch), signLeaf(this.#seed, this.#parameter, epoch, message), ...path));
    }
  }
}
