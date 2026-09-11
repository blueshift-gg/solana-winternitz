// The signer side of the `solana-winternitz` crate: DKKW25's generalized XMSS (Construction 3) over
// target-sum Winternitz (Construction 6) with SHA-256. Written from the crate's README, sharing no code
// with it; `tests/vectors.json` and `tests/winternitz.key` pin the two together byte for byte.

import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { closeSync, fsyncSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from 'node:fs';
import { dirname } from 'node:path';

const CHAINS = 35;
const POSITIONS = 16;
const ELEMENT_LENGTH = 24;
const SALT_LENGTH = 24;
const PARAMETER_LENGTH = 24;
const NODE_LENGTH = 32;
const ELEMENTS_LENGTH = CHAINS * ELEMENT_LENGTH;
/** `T` of Construction 6: 200 verifier steps, ~940 salts per signature. */
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

/**
 * Construction 6: the message hash as 35 nibbles, low nibble first, accepted iff they sum to `T`. HMAC
 * rather than a plain hash because a plain SHA-256 here is herdable across signed leaves (see the crate).
 */
function encode(salt: Uint8Array, parameter: Uint8Array, leaf: number, message: Uint8Array): Uint8Array | undefined {
  const digest = hmac(sha256, concat(Uint8Array.of(ROLE_MESSAGE), u32be(leaf), salt, parameter), message);
  const x = Uint8Array.from({ length: CHAINS }, (_, i) => (digest[i >> 1]! >> (4 * (i & 1))) & 0x0f);
  return x.reduce((a, b) => a + b, 0) === TARGET_SUM ? x : undefined;
}

/** Construction 2's chain: the step into position `k` carries tweak `k`. */
function walk(parameter: Uint8Array, leaf: number, i: number, from: number, to: number, x: Uint8Array): Uint8Array {
  for (let k = from; k < to; k++) {
    x = sha256(concat(Uint8Array.of(ROLE_CHAIN), u32be(leaf), Uint8Array.of(i, k + 1), parameter, x)).subarray(0, ELEMENT_LENGTH);
  }
  return x;
}

function treeTweak(level: number, index: number): Uint8Array {
  return concat(Uint8Array.of(ROLE_TREE, level), u32be(index));
}

/** Construction 1 leaf over the 35 chain ends. */
function leafHash(parameter: Uint8Array, leaf: number, ends: Uint8Array[]): Uint8Array {
  return sha256(concat(treeTweak(0, leaf), parameter, ...ends));
}

/** Construction 1 node. */
function node(parameter: Uint8Array, level: number, index: number, left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(concat(treeTweak(level, index), parameter, left, right));
}

/**
 * Remark 7's PRF, `SHA-256(0x03 || purpose || height || fields || seed)`. `height` is here because without
 * it the `winternitz` key is `xmss` leaf 0 of the same seed.
 */
function parameterOf(seed: Uint8Array, height: number): Uint8Array {
  return sha256(concat(Uint8Array.of(ROLE_SEED, 0, height), seed)).subarray(0, PARAMETER_LENGTH);
}

function start(seed: Uint8Array, height: number, leaf: number, i: number): Uint8Array {
  return sha256(concat(Uint8Array.of(ROLE_SEED, 1, height), u32be(leaf), Uint8Array.of(i), seed)).subarray(0, ELEMENT_LENGTH);
}

function endsOf(seed: Uint8Array, parameter: Uint8Array, height: number, leaf: number): Uint8Array[] {
  return Array.from({ length: CHAINS }, (_, i) => walk(parameter, leaf, i, 0, POSITIONS - 1, start(seed, height, leaf, i)));
}

function endsFromSignature(parameter: Uint8Array, leaf: number, x: Uint8Array, elements: Uint8Array): Uint8Array[] {
  return Array.from({ length: CHAINS }, (_, i) =>
    walk(parameter, leaf, i, x[i]!, POSITIONS - 1, elements.subarray(i * ELEMENT_LENGTH, (i + 1) * ELEMENT_LENGTH)),
  );
}

/** Construction 3 Sig steps 3–5, salts from the PRF over `(leaf, ctr, SHA-256(m))`. */
function signLeaf(seed: Uint8Array, parameter: Uint8Array, height: number, leaf: number, message: Uint8Array): Uint8Array {
  const digest = sha256(message);
  for (let ctr = 0; ctr < MAX_TRIALS; ctr++) {
    const salt = sha256(concat(Uint8Array.of(ROLE_SEED, 2, height), u32be(leaf), u32be(ctr), digest, seed)).subarray(0, SALT_LENGTH);
    const x = encode(salt, parameter, leaf, message);
    if (!x) continue;
    const elements = Array.from({ length: CHAINS }, (_, i) => walk(parameter, leaf, i, 0, x[i]!, start(seed, height, leaf, i)));
    return concat(salt, ...elements);
  }
  throw new Error('no salt reached the target sum in 65536 attempts');
}

/** `(root, P)` of Construction 3, 56 bytes. */
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
    return this.#bytes.slice(0, NODE_LENGTH);
  }

  /** @internal */
  get parameter(): Uint8Array {
    return this.#bytes.slice(NODE_LENGTH);
  }
}

export namespace winternitz {
  /** In every derivation, so this key is not `xmss` leaf 0. */
  const HEIGHT = 0;
  /** `(ρ, σ_OTS)` of Construction 3. */
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

    /** Construction 3 Ver at L = 1; throws `invalid signature`. */
    verify(publicKey: PublicKey, message: Uint8Array): void {
      const x = encode(this.#bytes.subarray(0, SALT_LENGTH), publicKey.parameter, 0, message);
      if (!x) throw new Error('invalid signature');
      const ends = endsFromSignature(publicKey.parameter, 0, x, this.#bytes.subarray(SALT_LENGTH));
      if (!equal(leafHash(publicKey.parameter, 0, ends), publicKey.node)) throw new Error('invalid signature');
    }
  }

  /** One seed, one signature; sign through `Signer`. */
  export class SecretKey {
    readonly #seed: Uint8Array;

    private constructor(seed: Uint8Array) {
      this.#seed = seed;
    }

    static fromSeed(seed: Uint8Array | ArrayLike<number>): SecretKey {
      return new SecretKey(bytes(seed, 32, 'seed'));
    }

    get publicKey(): PublicKey {
      const parameter = parameterOf(this.#seed, HEIGHT);
      return PublicKey.from(concat(leafHash(parameter, 0, endsOf(this.#seed, parameter, HEIGHT, 0)), parameter));
    }

    readonly leaves = 1;
    readonly height = HEIGHT;

    /** Construction 3 Sig at the one leaf. Records nothing. */
    signAt(_leaf: number, message: Uint8Array): Signature {
      return Signature.from(signLeaf(this.#seed, parameterOf(this.#seed, HEIGHT), HEIGHT, 0, message));
    }
  }
}

export namespace xmss {
  export const HEIGHT = 8;
  export const LEAVES = 1 << HEIGHT;
  /** `(ep, ρ, σ_OTS, path_ep)` of Construction 3, `ep` as u32 LE. */
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

    /** The paper's epoch: a counter, never a slot or the Solana epoch. */
    get leaf(): number {
      return new DataView(this.#bytes.buffer, this.#bytes.byteOffset).getUint32(0, true);
    }

    /** Construction 3 Ver, then Construction 1 VerPath; throws `invalid signature`. */
    verify(publicKey: PublicKey, message: Uint8Array): void {
      const leaf = this.leaf;
      if (leaf >= LEAVES) throw new Error('invalid signature');
      const parameter = publicKey.parameter;
      const x = encode(this.#bytes.subarray(4, ELEMENTS), parameter, leaf, message);
      if (!x) throw new Error('invalid signature');
      let current = leafHash(parameter, leaf, endsFromSignature(parameter, leaf, x, this.#bytes.subarray(ELEMENTS, PATH)));
      for (let level = 1; level <= HEIGHT; level++) {
        const sibling = this.#bytes.subarray(PATH + (level - 1) * NODE_LENGTH, PATH + level * NODE_LENGTH);
        const index = leaf >> level;
        current = (leaf >> (level - 1)) & 1 ? node(parameter, level, index, sibling, current) : node(parameter, level, index, current, sibling);
      }
      if (!equal(current, publicKey.node)) throw new Error('invalid signature');
    }
  }

  /** Construction 3 Gen with Remark 7's PRF, every node kept: ~135k hashes to build. */
  export class SecretKey {
    readonly #seed: Uint8Array;
    readonly #parameter: Uint8Array;
    /** Level-major: leaves first, root last. */
    readonly #nodes: Uint8Array[];

    private constructor(seed: Uint8Array) {
      this.#seed = seed;
      this.#parameter = parameterOf(seed, HEIGHT);
      this.#nodes = new Array(2 * LEAVES - 1);
      for (let leaf = 0; leaf < LEAVES; leaf++) this.#nodes[leaf] = leafHash(this.#parameter, leaf, endsOf(seed, this.#parameter, HEIGHT, leaf));
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

    readonly leaves = LEAVES;
    readonly height = HEIGHT;

    /** Construction 3 Sig plus Construction 1 Path. Records nothing; sign through `Signer`. */
    signAt(leaf: number, message: Uint8Array): Signature {
      if (!Number.isInteger(leaf) || leaf < 0 || leaf >= LEAVES) throw new RangeError(`leaf: expected 0..${LEAVES}`);
      const path = Array.from({ length: HEIGHT }, (_, l) => this.#nodes[levelOffset(l) + ((leaf >> l) ^ 1)]!);
      return Signature.from(concat(u32le(leaf), signLeaf(this.#seed, this.#parameter, HEIGHT, leaf, message), ...path));
    }
  }
}

/** The two instances as the signer sees them: `signAt` is Sig with no one-use rule; `Signer` supplies it. */
export interface OneTime<S> {
  readonly leaves: number;
  /** In the key file, so a file opens only under its own instance. */
  readonly height: number;
  readonly publicKey: PublicKey;
  signAt(leaf: number, message: Uint8Array): S;
}

/** `winternitz.SecretKey` or `xmss.SecretKey`. */
export interface KeyType<S> {
  fromSeed(seed: Uint8Array): OneTime<S>;
}

// Key file: version || height || seed || next leaf LE || digest flag || digest, 71 bytes, byte-identical to the crate's.
const VERSION = 1;
const SEED = 2;
const NEXT_LEAF = SEED + 32;
const HAS_DIGEST = NEXT_LEAF + 4;
const DIGEST = HAS_DIGEST + 1;
const RECORD = DIGEST + 32;

/**
 * Owns leaf allocation, after winterwallet's client. Here because Theorem 1 admits one signature per leaf
 * and neither the seed nor the chain records which leaves are spent: `create` from a fresh seed, `open`
 * from the file only, `sign` records before it signs and repeats the last message for free, `close`
 * releases the file.
 */
export class Signer<S> {
  readonly #key: OneTime<S>;
  readonly #seed: Uint8Array;
  readonly #path: string;
  readonly #lock: string;
  #nextLeaf: number;
  #lastDigest: Uint8Array | undefined;
  #closed = false;

  private constructor(key: OneTime<S>, seed: Uint8Array, path: string, lock: string, nextLeaf: number, lastDigest?: Uint8Array) {
    this.#key = key;
    this.#seed = seed;
    this.#path = path;
    this.#lock = lock;
    this.#nextLeaf = nextLeaf;
    this.#lastDigest = lastDigest;
  }

  /** The seed must never have signed; the file is what to back up. */
  static create<S>(type: KeyType<S>, path: string, seed: Uint8Array | ArrayLike<number>): Signer<S> {
    const bytesOfSeed = bytes(seed, 32, 'seed');
    const lock = acquire(path);
    try {
      let fd: number;
      try {
        fd = openSync(path, 'wx', 0o600);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'EEXIST') throw new Error('a key file already exists at this path: open it instead');
        throw error;
      }
      const signer = new Signer(type.fromSeed(bytesOfSeed), bytesOfSeed, path, lock, 0);
      writeSync(fd, signer.#record());
      fsyncSync(fd);
      closeSync(fd);
      syncDir(path);
      return signer;
    } catch (error) {
      release(lock);
      throw error;
    }
  }

  static open<S>(type: KeyType<S>, path: string): Signer<S> {
    const lock = acquire(path);
    try {
      let record: Buffer;
      try {
        record = readFileSync(path);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') throw new Error('no key file at this path: a seed alone cannot say which leaves are spent');
        throw error;
      }
      const corrupt = new Error('the key file is not a record of this instance');
      if (record.length !== RECORD || record[0] !== VERSION || record[HAS_DIGEST]! > 1) throw corrupt;
      const seed = Uint8Array.from(record.subarray(SEED, NEXT_LEAF));
      const key = type.fromSeed(seed);
      const nextLeaf = record.readUInt32LE(NEXT_LEAF);
      if (record[1] !== key.height || nextLeaf > key.leaves) throw corrupt;
      const lastDigest = record[HAS_DIGEST] === 1 ? Uint8Array.from(record.subarray(DIGEST, RECORD)) : undefined;
      return new Signer(key, seed, path, lock, nextLeaf, lastDigest);
    } catch (error) {
      release(lock);
      throw error;
    }
  }

  /** `floor` is the chain's last accepted leaf plus one: catches a restored old copy, not unlanded exposure. */
  floor(floor: number): this {
    if (this.#nextLeaf < floor) {
      this.close();
      throw new Error(`the key file is behind the chain: next leaf ${this.#nextLeaf}, floor ${floor}`);
    }
    return this;
  }

  get publicKey(): PublicKey {
    return this.#key.publicKey;
  }

  get nextLeaf(): number {
    return this.#nextLeaf;
  }

  get remaining(): number {
    return this.#key.leaves - this.#nextLeaf;
  }

  /** Record first, sign second (RFC 8391 §4.1.9); the last message is repeated, never re-spent. */
  sign(message: Uint8Array): S {
    if (this.#closed) throw new Error('the signer is closed');
    const digest = sha256(message);
    if (this.#lastDigest && equal(digest, this.#lastDigest)) return this.#key.signAt(this.#nextLeaf - 1, message);
    if (this.#nextLeaf >= this.#key.leaves) throw new Error('leaves exhausted');
    const leaf = this.#nextLeaf;
    this.#nextLeaf = leaf + 1;
    this.#lastDigest = digest;
    try {
      this.#write();
    } catch (error) {
      // On disk or not, the leaf stays spent; the digest goes so the unrecorded signature is never handed out.
      this.#lastDigest = undefined;
      throw error;
    }
    return this.#key.signAt(leaf, message);
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    release(this.#lock);
  }

  #record(): Buffer {
    const record = Buffer.alloc(RECORD);
    record[0] = VERSION;
    record[1] = this.#key.height;
    record.set(this.#seed, SEED);
    record.writeUInt32LE(this.#nextLeaf, NEXT_LEAF);
    if (this.#lastDigest) {
      record[HAS_DIGEST] = 1;
      record.set(this.#lastDigest, DIGEST);
    }
    return record;
  }

  #write(): void {
    const tmp = `${this.#path}.tmp`;
    const fd = openSync(tmp, 'w', 0o600);
    writeSync(fd, this.#record());
    fsyncSync(fd);
    closeSync(fd);
    renameSync(tmp, this.#path);
    syncDir(this.#path);
  }
}

/**
 * Node has no file locking, so the lock is an exclusively created `.lock` sidecar holding the pid; a sidecar
 * because rename would orphan a lock on the record. Cleared when its pid is gone, fatal when alive or reused.
 */
function acquire(path: string): string {
  const lock = `${path}.lock`;
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const fd = openSync(lock, 'wx', 0o600);
      writeSync(fd, String(process.pid));
      closeSync(fd);
      return lock;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
    }
    const pid = Number(readFileSync(lock, 'utf8'));
    if (alive(pid)) throw new Error(`the key file is locked by process ${pid} (${lock})`);
    unlinkSync(lock);
  }
  throw new Error(`could not lock ${lock}`);
}

function alive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === 'EPERM';
  }
}

function release(lock: string): void {
  try {
    unlinkSync(lock);
  } catch {
    // Already gone: nothing to release.
  }
}

/** A rename is durable only once its directory is synced. */
function syncDir(path: string): void {
  if (process.platform === 'win32') return;
  const fd = openSync(dirname(path) || '.', 'r');
  fsyncSync(fd);
  closeSync(fd);
}
