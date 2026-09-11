// The signer side of the `solana-winternitz` crate: DKKW25's generalized XMSS (Construction 3) over
// target-sum Winternitz (Construction 6) at hash-sig's parameters, Keccak-256 for the paper's SHA3-256.
// Written from the crate's SPEC.md, sharing no code with it; `tests/vectors.json`, `tests/hash-sig.json`
// and `tests/winternitz.key` pin the two together.

import { keccak_256 } from '@noble/hashes/sha3.js';
import { closeSync, fsyncSync, openSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { randomFillSync } from 'node:crypto';
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

/** Explicit chain starts, in leaf-major, chain-major order. */
function start(secrets: Uint8Array, leaf: number, i: number): Uint8Array {
  const offset = leaf * ELEMENTS_LENGTH + i * ELEMENT_LENGTH;
  return secrets.subarray(offset, offset + ELEMENT_LENGTH);
}

function endsOf(secrets: Uint8Array, parameter: Uint8Array, leaf: number): Uint8Array[] {
  return Array.from({ length: CHAINS }, (_, i) => walk(parameter, leaf, i, 0, POSITIONS - 1, start(secrets, leaf, i)));
}

function endsFromSignature(parameter: Uint8Array, leaf: number, x: Uint8Array, elements: Uint8Array): Uint8Array[] {
  return Array.from({ length: CHAINS }, (_, i) =>
    walk(parameter, leaf, i, x[i]!, POSITIONS - 1, elements.subarray(i * ELEMENT_LENGTH, (i + 1) * ELEMENT_LENGTH)),
  );
}

/** Construction 3 Sig with an already accepted salt. */
function signLeaf(secrets: Uint8Array, parameter: Uint8Array, leaf: number, message: Uint8Array, salt: Uint8Array): Uint8Array {
  const x = encode(salt, parameter, leaf, message);
  if (!x) throw new Error('salt misses the target sum');
  const elements = Array.from({ length: CHAINS }, (_, i) => walk(parameter, leaf, i, 0, x[i]!, start(secrets, leaf, i)));
  return concat(salt, ...elements);
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

  /** Sampled chain starts, one signature; sign through `Signer`. */
  export class SecretKey {
    static readonly LEAVES = 1;
    static readonly HEIGHT = HEIGHT;
    readonly #secrets: Uint8Array;
    readonly #parameter: Uint8Array;

    private constructor(secrets: Uint8Array, parameter: Uint8Array) {
      this.#secrets = secrets;
      this.#parameter = parameter;
    }

    /** Construction 3 Gen from independently sampled chain starts and `P`. */
    static new(secrets: Uint8Array | ArrayLike<number>, parameter: Uint8Array | ArrayLike<number>): SecretKey {
      return new SecretKey(bytes(secrets, SecretKey.LEAVES * ELEMENTS_LENGTH, 'chain starts'), bytes(parameter, PARAMETER_LENGTH, 'parameter'));
    }

    /** Raw chain starts; never restore usage state from these alone. */
    get secrets(): Uint8Array { return this.#secrets.slice(); }

    get publicKey(): PublicKey {
      return PublicKey.from(concat(leafHash(this.#parameter, 0, endsOf(this.#secrets, this.#parameter, 0)), this.#parameter));
    }

    readonly leaves = 1;
    readonly height = HEIGHT;

    /** Construction 3 Sig at the one leaf; throws at any other. Records nothing. */
    signAt(leaf: number, message: Uint8Array, salt: Uint8Array): Signature {
      if (leaf !== 0) throw new RangeError('leaf: expected 0');
      return Signature.from(signLeaf(this.#secrets, this.#parameter, 0, bytes(message, MESSAGE_LENGTH, 'message'), bytes(salt, SALT_LENGTH, 'salt')));
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

  /** Construction 3 Gen from sampled chain starts, every node kept: ~148k hashes to build. */
  export class SecretKey {
    static readonly LEAVES = LEAVES;
    static readonly HEIGHT = HEIGHT;
    readonly #secrets: Uint8Array;
    readonly #parameter: Uint8Array;
    /** Level-major: leaves first, root last. */
    readonly #nodes: Uint8Array[];

    private constructor(secrets: Uint8Array, parameter: Uint8Array) {
      this.#secrets = secrets;
      this.#parameter = parameter;
      this.#nodes = new Array(2 * LEAVES - 1);
      for (let leaf = 0; leaf < LEAVES; leaf++) this.#nodes[leaf] = leafHash(this.#parameter, leaf, endsOf(secrets, this.#parameter, leaf));
      for (let l = 1; l <= HEIGHT; l++) {
        for (let i = 0; i < LEAVES >> l; i++) {
          const child = levelOffset(l - 1) + 2 * i;
          this.#nodes[levelOffset(l) + i] = node(this.#parameter, l, i, this.#nodes[child]!, this.#nodes[child + 1]!);
        }
      }
    }

    /** Construction 3 Gen from independently sampled chain starts and `P`: every chain of every leaf, then the tree. */
    static new(secrets: Uint8Array | ArrayLike<number>, parameter: Uint8Array | ArrayLike<number>): SecretKey {
      return new SecretKey(bytes(secrets, SecretKey.LEAVES * ELEMENTS_LENGTH, 'chain starts'), bytes(parameter, PARAMETER_LENGTH, 'parameter'));
    }

    /** Raw chain starts; never restore usage state from these alone. */
    get secrets(): Uint8Array { return this.#secrets.slice(); }

    get publicKey(): PublicKey {
      return PublicKey.from(concat(this.#nodes[levelOffset(HEIGHT)]!, this.#parameter));
    }

    readonly leaves = LEAVES;
    readonly height = HEIGHT;

    /** Construction 3 Sig plus Construction 1 Path. Records nothing; sign through `Signer`. */
    signAt(leaf: number, message: Uint8Array, salt: Uint8Array): Signature {
      if (!Number.isInteger(leaf) || leaf < 0 || leaf >= LEAVES) throw new RangeError(`leaf: expected 0..${LEAVES}`);
      const path = Array.from({ length: HEIGHT }, (_, l) => this.#nodes[levelOffset(l) + ((leaf >> l) ^ 1)]!);
      return Signature.from(concat(u32be(leaf), signLeaf(this.#secrets, this.#parameter, leaf, bytes(message, MESSAGE_LENGTH, 'message'), bytes(salt, SALT_LENGTH, 'salt')), ...path));
    }
  }
}

/** Raw operations without a one-use rule. Use `Signer`; never reuse starts across keys. */
export interface OneTime<S> {
  readonly leaves: number;
  readonly height: number;
  readonly publicKey: PublicKey;
  readonly secrets: Uint8Array;
  /** Never use a spent leaf with a different message or salt. */
  signAt(leaf: number, message: Uint8Array, salt: Uint8Array): S;
}

/** `winternitz.SecretKey` or `xmss.SecretKey`. */
export interface KeyType<S> {
  readonly LEAVES: number;
  readonly HEIGHT: number;
  'new'(secrets: Uint8Array, parameter: Uint8Array): OneTime<S>;
}

// v2: version || height || P || next leaf BE || message flag || message || accepted salt || chain starts.
const VERSION = 2;
const PARAMETER = 2;
const NEXT_LEAF = PARAMETER + PARAMETER_LENGTH;
const HAS_MESSAGE = NEXT_LEAF + 4;
const MESSAGE = HAS_MESSAGE + 1;
const SALT = MESSAGE + MESSAGE_LENGTH;
const SECRETS = SALT + SALT_LENGTH;

/** Owns leaf allocation and exact retries. Needs Bun on a unix host for the permanent kernel lock. */
export class Signer<S> {
  readonly #key: OneTime<S>;
  readonly #path: string;
  readonly #lock: number;
  #nextLeaf: number;
  #lastMessage: Uint8Array | undefined;
  #lastSalt: Uint8Array;
  #closed = false;

  private constructor(key: OneTime<S>, path: string, lock: number, nextLeaf: number, lastSalt: Uint8Array, lastMessage?: Uint8Array) {
    this.#key = key;
    this.#path = path;
    this.#lock = lock;
    this.#nextLeaf = nextLeaf;
    this.#lastMessage = lastMessage;
    this.#lastSalt = lastSalt;
  }

  /** Sample every chain start and `P` from the OS random source. Refuses an existing file; back up the whole file. */
  static create<S>(type: KeyType<S>, path: string): Signer<S> {
    const lock = acquire(path);
    try {
      let fd: number;
      try { fd = openSync(path, 'wx', 0o600); }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'EEXIST') throw new Error('a key file already exists at this path: open it instead');
        throw error;
      }
      let signer: Signer<S>;
      const secrets = new Uint8Array(type.LEAVES * ELEMENTS_LENGTH);
      try {
        randomFillSync(secrets);
        const parameter = randomFillSync(new Uint8Array(PARAMETER_LENGTH));
        signer = new Signer(type.new(secrets, parameter), path, lock, 0, new Uint8Array(SALT_LENGTH));
        signer.#writeRecord(fd);
        fsyncSync(fd);
      } finally { secrets.fill(0); closeSync(fd); }
      syncDir(path);
      return signer;
    } catch (error) { release(lock); throw error; }
  }

  /** Continue from a v2 file. Seed-based v1 records are rejected. */
  static open<S>(type: KeyType<S>, path: string): Signer<S> {
    const lock = acquire(path);
    try {
      let record: Buffer;
      try { record = readFileSync(path); }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') throw new Error('no key file at this path: usage state is required');
        throw error;
      }
      try {
        const corrupt = new Error('the key file is not a record of this instance');
        if (record.length !== SECRETS + type.LEAVES * ELEMENTS_LENGTH || record[0] !== VERSION
            || record[1] !== type.HEIGHT || record[HAS_MESSAGE]! > 1) throw corrupt;
        const parameter = record.subarray(PARAMETER, NEXT_LEAF);
        const nextLeaf = record.readUInt32BE(NEXT_LEAF);
        const lastMessage = record[HAS_MESSAGE] === 1 ? Uint8Array.from(record.subarray(MESSAGE, SALT)) : undefined;
        const lastSalt = Uint8Array.from(record.subarray(SALT, SECRETS));
        if (nextLeaf > type.LEAVES || Boolean(lastMessage) !== (nextLeaf > 0)
            || (lastMessage ? !encode(lastSalt, parameter, nextLeaf - 1, lastMessage) : record.subarray(MESSAGE, SECRETS).some((b) => b !== 0))) throw corrupt;
        return new Signer(type.new(record.subarray(SECRETS), parameter), path, lock, nextLeaf, lastSalt, lastMessage);
      } finally { record.fill(0); }
    } catch (error) { release(lock); throw error; }
  }

  /** `floor` is the chain's last accepted leaf plus one: catches a restored old copy, not unlanded exposure. */
  floor(floor: number): this {
    if (!Number.isInteger(floor) || floor < 0 || floor > this.#key.leaves) { this.close(); throw new RangeError('invalid leaf floor'); }
    if (this.#nextLeaf < floor) {
      this.close();
      throw new Error(`the key file is behind the chain: next leaf ${this.#nextLeaf}, floor ${floor}`);
    }
    return this;
  }

  get publicKey(): PublicKey { return this.#key.publicKey; }
  get nextLeaf(): number { return this.#nextLeaf; }
  get remaining(): number { return this.#key.leaves - this.#nextLeaf; }

  /** Sample salts, persist the accepted salt and allocation, then sign. Retry with the persisted salt. */
  sign(message: Uint8Array): S {
    if (this.#closed) throw new Error('the signer is closed');
    const bytesOfMessage = bytes(message, MESSAGE_LENGTH, 'message');
    if (this.#lastMessage && equal(bytesOfMessage, this.#lastMessage)) return this.#key.signAt(this.#nextLeaf - 1, bytesOfMessage, this.#lastSalt);
    if (this.#nextLeaf >= this.#key.leaves) throw new Error('leaves exhausted');
    const leaf = this.#nextLeaf;
    const parameter = this.publicKey.parameter;
    const salt = new Uint8Array(SALT_LENGTH);
    for (let trial = 0; trial < MAX_TRIALS; trial++) {
      randomFillSync(salt);
      if (!encode(salt, parameter, leaf, bytesOfMessage)) continue;
      this.#nextLeaf = leaf + 1;
      this.#lastMessage = bytesOfMessage;
      this.#lastSalt = salt;
      try { this.#write(); }
      catch (error) { this.close(); throw error; }
      return this.#key.signAt(leaf, bytesOfMessage, salt);
    }
    throw new Error('4096 salts missed the target sum; no leaf was spent');
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    release(this.#lock);
  }

  #writeRecord(fd: number): void {
    const header = Buffer.alloc(SECRETS);
    header[0] = VERSION;
    header[1] = this.#key.height;
    header.set(this.publicKey.parameter, PARAMETER);
    header.writeUInt32BE(this.#nextLeaf, NEXT_LEAF);
    if (this.#lastMessage) {
      header[HAS_MESSAGE] = 1;
      header.set(this.#lastMessage, MESSAGE);
      header.set(this.#lastSalt, SALT);
    }
    const secrets = this.#key.secrets;
    try { writeFileSync(fd, header); writeFileSync(fd, secrets); }
    finally { secrets.fill(0); }
  }

  #write(): void {
    const tmp = `${this.#path}.tmp`;
    const fd = openSync(tmp, 'w', 0o600);
    try { this.#writeRecord(fd); fsyncSync(fd); }
    finally { closeSync(fd); }
    renameSync(tmp, this.#path);
    syncDir(this.#path);
  }
}

/**
 * The `.lock` sidecar, permanent, held through `flock(LOCK_EX | LOCK_NB)` for the signer's lifetime: the same
 * call the Rust crate makes through `File::try_lock`, so each refuses a file the other holds, and the kernel
 * releases a dead holder's lock, so there is no stale-owner decision to race on. A sidecar because rename
 * would orphan a lock on the record; never deleted, since a new file at the path would be a second lock.
 * `flock` is reached through Bun's FFI: `Signer` needs Bun on a unix host; everything else runs anywhere.
 */
function acquire(path: string): number {
  const fd = openSync(`${path}.lock`, 'a', 0o600);
  try {
    if (!flock(fd)) throw new Error(`the key file is held by another signer (${path}.lock)`);
    return fd;
  } catch (error) { closeSync(fd); throw error; }
}

function release(fd: number): void {
  closeSync(fd);
}

const LOCK_EX = 2;
const LOCK_NB = 4;
let libc: { symbols: { flock: (fd: number, operation: number) => number } } | undefined;

function flock(fd: number): boolean {
  if (typeof Bun === 'undefined' || process.platform === 'win32') {
    throw new Error('Signer needs Bun on a unix host: the key-file lock is flock(2) through bun:ffi');
  }
  if (!libc) {
    const { dlopen, FFIType } = require('bun:ffi') as typeof import('bun:ffi');
    libc = dlopen(process.platform === 'darwin' ? '/usr/lib/libSystem.B.dylib' : 'libc.so.6', {
      flock: { args: [FFIType.i32, FFIType.i32], returns: FFIType.i32 },
    });
  }
  return libc.symbols.flock(fd, LOCK_EX | LOCK_NB) === 0;
}

/** A rename is durable only once its directory is synced. */
function syncDir(path: string): void {
  if (process.platform === 'win32') return;
  const fd = openSync(dirname(path) || '.', 'r');
  try { fsyncSync(fd); } finally { closeSync(fd); }
}
