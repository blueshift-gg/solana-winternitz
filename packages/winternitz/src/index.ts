// The signer side of the `solana-winternitz` crate: DKKW25's generalized XMSS (Construction 3) over
// target-sum Winternitz (Construction 6) at hash-sig's parameters, Keccak-256 for the paper's SHA3-256.
// Written from the crate's SPEC.md, sharing no code with it; `tests/vectors.json`, `tests/hash-sig.json`
// and `tests/winternitz.key` pin the two together.

import { keccak_256 } from '@noble/hashes/sha3.js';
import { closeSync, fsyncSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from 'node:fs';
import { dirname } from 'node:path';

/** `v`: hash-sig's 18-byte message hash at w = 4, 144 bits ≥ 138, eq. (13). */
const CHAINS = 36;
const POSITIONS = 16;
/** `n`, chain elements, leaves and nodes alike: eq. (15) at L = 2^8. */
const ELEMENT_LENGTH = 23;
/** `ρ`: eq. (14) at L = 2^8, K = 2^12. */
const SALT_LENGTH = 21;
/** `P`: eq. (16). */
export const PARAMETER_LENGTH = 18;
const ELEMENTS_LENGTH = CHAINS * ELEMENT_LENGTH;
/** `T = ⌈1.1 · 36 · 15 / 2⌉`, the paper's §8 operating point and hash-sig's `Off10`: 243 verifier steps, ~111 salts per signature. */
const TARGET_SUM = 297;
/** `K` of Construction 3, the paper's §8 assumption. */
const MAX_TRIALS = 4096;
const ROLE_CHAIN = 0;
const ROLE_TREE = 1;
const ROLE_MESSAGE = 2;
/** hash-sig `symmetric/prf/sha.rs`: `PRF_DOMAIN_SEP`, then a purpose byte for a domain element or randomness. */
const PRF_DOMAIN_SEP = Uint8Array.of(0x00, 0x01, 0x12, 0xff, 0x00, 0x01, 0xfa, 0xff, 0x00, 0xaf, 0x12, 0xff, 0x01, 0xfa, 0xff, 0x00);
const PRF_DOMAIN_ELEMENT = 0;
const PRF_RANDOMNESS = 1;
/** `l_msg`, hash-sig's `MESSAGE_LENGTH`: a message is a 32-byte digest, the caller's hash of whatever it acts on. */
export const MESSAGE_LENGTH = 32;

/** `node || P`: the leaf for `winternitz`, the Merkle root for `xmss`. */
export const PUBLIC_KEY_LENGTH = ELEMENT_LENGTH + PARAMETER_LENGTH;

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

function u64be(n: number): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(n), false);
  return out;
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

/**
 * Construction 6 over §7.2.1's `H(R || P || T || M)`, byte for byte hash-sig's `ShaMessageHash`: the epoch
 * little-endian in this one tweak, 36 nibbles low nibble first, accepted iff they sum to `T`.
 */
function encode(salt: Uint8Array, parameter: Uint8Array, leaf: number, message: Uint8Array): Uint8Array | undefined {
  const digest = keccak_256(concat(salt, parameter, Uint8Array.of(ROLE_MESSAGE), u32le(leaf), message));
  const x = Uint8Array.from({ length: CHAINS }, (_, i) => (digest[i >> 1]! >> (4 * (i & 1))) & 0x0f);
  return x.reduce((a, b) => a + b, 0) === TARGET_SUM ? x : undefined;
}

/** Construction 2's chain over §7.2.2's `H(P || T || M)`: the step into position `k` carries tweak `k`. */
function walk(parameter: Uint8Array, leaf: number, i: number, from: number, to: number, x: Uint8Array): Uint8Array {
  for (let k = from; k < to; k++) {
    x = keccak_256(concat(parameter, Uint8Array.of(ROLE_CHAIN), u32be(leaf), Uint8Array.of(i, k + 1), x)).subarray(0, ELEMENT_LENGTH);
  }
  return x;
}

function treeTweak(level: number, index: number): Uint8Array {
  return concat(Uint8Array.of(ROLE_TREE, level), u32be(index));
}

/** Construction 1 leaf over the 36 chain ends. */
function leafHash(parameter: Uint8Array, leaf: number, ends: Uint8Array[]): Uint8Array {
  return keccak_256(concat(parameter, treeTweak(0, leaf), ...ends)).subarray(0, ELEMENT_LENGTH);
}

/** Construction 1 node. */
function node(parameter: Uint8Array, level: number, index: number, left: Uint8Array, right: Uint8Array): Uint8Array {
  return keccak_256(concat(parameter, treeTweak(level, index), left, right)).subarray(0, ELEMENT_LENGTH);
}

/**
 * Remark 7's PRF, byte for byte hash-sig's `ShaPRF`: `H(sep || purpose || key || epoch || index)` for chain
 * starts. Keyed by the seed alone, so one seed per key. `P` is sampled, not derived.
 */
function start(seed: Uint8Array, leaf: number, i: number): Uint8Array {
  return keccak_256(concat(PRF_DOMAIN_SEP, Uint8Array.of(PRF_DOMAIN_ELEMENT), seed, u32be(leaf), u64be(i))).subarray(0, ELEMENT_LENGTH);
}

function endsOf(seed: Uint8Array, parameter: Uint8Array, leaf: number): Uint8Array[] {
  return Array.from({ length: CHAINS }, (_, i) => walk(parameter, leaf, i, 0, POSITIONS - 1, start(seed, leaf, i)));
}

function endsFromSignature(parameter: Uint8Array, leaf: number, x: Uint8Array, elements: Uint8Array): Uint8Array[] {
  return Array.from({ length: CHAINS }, (_, i) =>
    walk(parameter, leaf, i, x[i]!, POSITIONS - 1, elements.subarray(i * ELEMENT_LENGTH, (i + 1) * ELEMENT_LENGTH)),
  );
}

/** Construction 3 Sig steps 3–5, salts from hash-sig's PRF over `(leaf, m, ctr)`. */
function signLeaf(seed: Uint8Array, parameter: Uint8Array, leaf: number, message: Uint8Array): Uint8Array {
  for (let ctr = 0; ctr < MAX_TRIALS; ctr++) {
    const salt = keccak_256(concat(PRF_DOMAIN_SEP, Uint8Array.of(PRF_RANDOMNESS), seed, u32be(leaf), message, u64be(ctr))).subarray(0, SALT_LENGTH);
    const x = encode(salt, parameter, leaf, message);
    if (!x) continue;
    const elements = Array.from({ length: CHAINS }, (_, i) => walk(parameter, leaf, i, 0, x[i]!, start(seed, leaf, i)));
    return concat(salt, ...elements);
  }
  throw new Error('no salt reached the target sum in 4096 attempts');
}

/** `(root, P)` of Construction 3, 41 bytes. */
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
    return this.#bytes.slice(0, ELEMENT_LENGTH);
  }

  /** @internal */
  get parameter(): Uint8Array {
    return this.#bytes.slice(ELEMENT_LENGTH);
  }
}

export namespace winternitz {
  /** The key-file tag of this instance. */
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
      const x = encode(this.#bytes.subarray(0, SALT_LENGTH), publicKey.parameter, 0, bytes(message, MESSAGE_LENGTH, 'message'));
      if (!x) throw new Error('invalid signature');
      const ends = endsFromSignature(publicKey.parameter, 0, x, this.#bytes.subarray(SALT_LENGTH));
      if (!equal(leafHash(publicKey.parameter, 0, ends), publicKey.node)) throw new Error('invalid signature');
    }
  }

  /** One seed, one signature; sign through `Signer`. */
  export class SecretKey {
    readonly #seed: Uint8Array;
    readonly #parameter: Uint8Array;

    private constructor(seed: Uint8Array, parameter: Uint8Array) {
      this.#seed = seed;
      this.#parameter = parameter;
    }

    /** Construction 3 Gen from the caller's sampled `seed` and `P`. */
    static new(seed: Uint8Array | ArrayLike<number>, parameter: Uint8Array | ArrayLike<number>): SecretKey {
      return new SecretKey(bytes(seed, 32, 'seed'), bytes(parameter, PARAMETER_LENGTH, 'parameter'));
    }

    get publicKey(): PublicKey {
      return PublicKey.from(concat(leafHash(this.#parameter, 0, endsOf(this.#seed, this.#parameter, 0)), this.#parameter));
    }

    readonly leaves = 1;
    readonly height = HEIGHT;

    /** Construction 3 Sig at the one leaf; throws at any other. Records nothing. */
    signAt(leaf: number, message: Uint8Array): Signature {
      if (leaf !== 0) throw new RangeError('leaf: expected 0');
      return Signature.from(signLeaf(this.#seed, this.#parameter, 0, bytes(message, MESSAGE_LENGTH, 'message')));
    }
  }
}

export namespace xmss {
  export const HEIGHT = 8;
  export const LEAVES = 1 << HEIGHT;
  /** `(ep, ρ, σ_OTS, path_ep)` of Construction 3, `ep` as u32 big-endian. */
  export const SIGNATURE_LENGTH = 4 + SALT_LENGTH + ELEMENTS_LENGTH + HEIGHT * ELEMENT_LENGTH;

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
      return new DataView(this.#bytes.buffer, this.#bytes.byteOffset).getUint32(0, false);
    }

    /** Construction 3 Ver, then Construction 1 VerPath; throws `invalid signature`. */
    verify(publicKey: PublicKey, message: Uint8Array): void {
      const leaf = this.leaf;
      if (leaf >= LEAVES) throw new Error('invalid signature');
      const parameter = publicKey.parameter;
      const x = encode(this.#bytes.subarray(4, ELEMENTS), parameter, leaf, bytes(message, MESSAGE_LENGTH, 'message'));
      if (!x) throw new Error('invalid signature');
      let current = leafHash(parameter, leaf, endsFromSignature(parameter, leaf, x, this.#bytes.subarray(ELEMENTS, PATH)));
      for (let level = 1; level <= HEIGHT; level++) {
        const sibling = this.#bytes.subarray(PATH + (level - 1) * ELEMENT_LENGTH, PATH + level * ELEMENT_LENGTH);
        const index = leaf >> level;
        current = (leaf >> (level - 1)) & 1 ? node(parameter, level, index, sibling, current) : node(parameter, level, index, current, sibling);
      }
      if (!equal(current, publicKey.node)) throw new Error('invalid signature');
    }
  }

  /** Construction 3 Gen with hash-sig's PRF, every node kept: ~140k hashes to build. */
  export class SecretKey {
    readonly #seed: Uint8Array;
    readonly #parameter: Uint8Array;
    /** Level-major: leaves first, root last. */
    readonly #nodes: Uint8Array[];

    private constructor(seed: Uint8Array, parameter: Uint8Array) {
      this.#seed = seed;
      this.#parameter = parameter;
      this.#nodes = new Array(2 * LEAVES - 1);
      for (let leaf = 0; leaf < LEAVES; leaf++) this.#nodes[leaf] = leafHash(this.#parameter, leaf, endsOf(seed, this.#parameter, leaf));
      for (let l = 1; l <= HEIGHT; l++) {
        for (let i = 0; i < LEAVES >> l; i++) {
          const child = levelOffset(l - 1) + 2 * i;
          this.#nodes[levelOffset(l) + i] = node(this.#parameter, l, i, this.#nodes[child]!, this.#nodes[child + 1]!);
        }
      }
    }

    /** Construction 3 Gen from the caller's sampled `seed` and `P`: every chain of every leaf, then the tree. */
    static new(seed: Uint8Array | ArrayLike<number>, parameter: Uint8Array | ArrayLike<number>): SecretKey {
      return new SecretKey(bytes(seed, 32, 'seed'), bytes(parameter, PARAMETER_LENGTH, 'parameter'));
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
      return Signature.from(concat(u32be(leaf), signLeaf(this.#seed, this.#parameter, leaf, bytes(message, MESSAGE_LENGTH, 'message')), ...path));
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
  'new'(seed: Uint8Array, parameter: Uint8Array): OneTime<S>;
}

// Key file: version || height || seed || P || next leaf BE || message flag || last message, 89 bytes, byte-identical to the crate's.
const VERSION = 1;
const SEED = 2;
const PARAMETER = SEED + 32;
const NEXT_LEAF = PARAMETER + PARAMETER_LENGTH;
const HAS_MESSAGE = NEXT_LEAF + 4;
const MESSAGE = HAS_MESSAGE + 1;
const RECORD = MESSAGE + MESSAGE_LENGTH;

/**
 * Owns leaf allocation, after winterwallet's client. Here because Theorem 1 admits one signature per leaf
 * and neither the seed nor the chain records which leaves are spent: `create` from a fresh seed, `open`
 * from the file only, `sign` records before it signs and repeats the last message for free, `close`
 * releases the file.
 */
export class Signer<S> {
  readonly #key: OneTime<S>;
  readonly #seed: Uint8Array;
  readonly #parameter: Uint8Array;
  readonly #path: string;
  readonly #lock: string;
  #nextLeaf: number;
  #lastMessage: Uint8Array | undefined;
  #closed = false;

  private constructor(key: OneTime<S>, seed: Uint8Array, parameter: Uint8Array, path: string, lock: string, nextLeaf: number, lastMessage?: Uint8Array) {
    this.#key = key;
    this.#seed = seed;
    this.#parameter = parameter;
    this.#path = path;
    this.#lock = lock;
    this.#nextLeaf = nextLeaf;
    this.#lastMessage = lastMessage;
  }

  /** `seed` and `parameter` are the caller's fresh randomness, Construction 3's `sk` and `P`; the seed must never have signed. The file is what to back up. */
  static create<S>(type: KeyType<S>, path: string, seed: Uint8Array | ArrayLike<number>, parameter: Uint8Array | ArrayLike<number>): Signer<S> {
    const bytesOfSeed = bytes(seed, 32, 'seed');
    const bytesOfParameter = bytes(parameter, PARAMETER_LENGTH, 'parameter');
    const lock = acquire(path);
    try {
      let fd: number;
      try {
        fd = openSync(path, 'wx', 0o600);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'EEXIST') throw new Error('a key file already exists at this path: open it instead');
        throw error;
      }
      const signer = new Signer(type.new(bytesOfSeed, bytesOfParameter), bytesOfSeed, bytesOfParameter, path, lock, 0);
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
      if (record.length !== RECORD || record[0] !== VERSION || record[HAS_MESSAGE]! > 1) throw corrupt;
      const seed = Uint8Array.from(record.subarray(SEED, PARAMETER));
      const parameter = Uint8Array.from(record.subarray(PARAMETER, NEXT_LEAF));
      const key = type.new(seed, parameter);
      const nextLeaf = record.readUInt32BE(NEXT_LEAF);
      if (record[1] !== key.height || nextLeaf > key.leaves) throw corrupt;
      const lastMessage = record[HAS_MESSAGE] === 1 ? Uint8Array.from(record.subarray(MESSAGE, RECORD)) : undefined;
      return new Signer(key, seed, parameter, path, lock, nextLeaf, lastMessage);
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
    const bytesOfMessage = bytes(message, MESSAGE_LENGTH, 'message');
    if (this.#lastMessage && equal(bytesOfMessage, this.#lastMessage)) return this.#key.signAt(this.#nextLeaf - 1, bytesOfMessage);
    if (this.#nextLeaf >= this.#key.leaves) throw new Error('leaves exhausted');
    const leaf = this.#nextLeaf;
    this.#nextLeaf = leaf + 1;
    this.#lastMessage = bytesOfMessage;
    try {
      this.#write();
    } catch (error) {
      // On disk or not, the leaf stays spent; the message goes so the unrecorded signature is never handed out.
      this.#lastMessage = undefined;
      throw error;
    }
    return this.#key.signAt(leaf, bytesOfMessage);
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
    record.set(this.#parameter, PARAMETER);
    record.writeUInt32BE(this.#nextLeaf, NEXT_LEAF);
    if (this.#lastMessage) {
      record[HAS_MESSAGE] = 1;
      record.set(this.#lastMessage, MESSAGE);
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
 * The `.lock` sidecar, created exclusively and holding the owner's pid: the Rust crate's protocol byte for
 * byte, so each refuses a file the other holds. A sidecar because rename would orphan a lock on the record.
 * An empty or unreadable lock is held, its owner between creating it and writing its pid. A dead owner's
 * lock is renamed away before removal, so of two openers clearing it at once only one can go on to create.
 */
function acquire(path: string): string {
  const lock = `${path}.lock`;
  const locked = new Error(`the key file is locked (${lock})`);
  for (let attempt = 0; attempt < 2; attempt++) {
    let fd: number;
    try {
      fd = openSync(lock, 'wx', 0o600);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
      let owner: string;
      try {
        owner = readFileSync(lock, 'utf8');
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue;
        throw error;
      }
      const pid = Number(owner.trim());
      if (!Number.isInteger(pid) || pid <= 0 || alive(pid)) throw locked;
      try {
        renameSync(lock, `${lock}.stale`);
        unlinkSync(`${lock}.stale`);
      } catch {
        // Another opener cleared it first.
      }
      continue;
    }
    try {
      writeSync(fd, String(process.pid));
      closeSync(fd);
    } catch (error) {
      release(lock);
      throw error;
    }
    return lock;
  }
  throw locked;
}

/** `kill(pid, 0)` delivers nothing and reports whether the process exists; `EPERM` means it exists under another user. */
function alive(pid: number): boolean {
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
