import { closeSync, fsyncSync, openSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { randomFillSync } from 'node:crypto';
import { dirname } from 'node:path';
import { bytes, equal, encode, ELEMENTS_LENGTH, ELEMENT_LENGTH, PARAMETER_LEN, MESSAGE_LEN, SALT_LENGTH, sampleSalt } from './core.js';
import { VerifyingKey } from './verifying-key.js';
import { CryptoError, SigningError, signingError, type FillRandom } from './error.js';
import * as winternitz from './hazmat/winternitz.js';
import * as xmss from './hazmat/xmss.js';

function fillRandom(bytes: Uint8Array): Uint8Array {
  try { return randomFillSync(bytes); }
  catch (error) { throw signingError(error, 'Random'); }
}

/** Raw operations without a one-use rule. Use `SigningKey`; never reuse starts across keys. */
interface OneTime<S> {
  readonly leaves: number;
  readonly height: number;
  verifyingKey(): VerifyingKey;
  readonly secrets: Uint8Array;
  /** Never use a spent leaf with a different message or salt. */
  signAtWithSalt(leaf: number, message: Uint8Array, salt: Uint8Array): S;
}

/** `winternitz.SecretKey` or `xmss.SecretKey`. */
interface KeyType<S> {
  readonly LEAVES: number;
  readonly HEIGHT: number;
  fromSecrets(secrets: Uint8Array, parameter: Uint8Array): OneTime<S>;
}

function checkKeyType(type: unknown): void {
  if (type !== winternitz.SecretKey && type !== xmss.SecretKey) throw new SigningError('Corrupt', 'unsupported signing instance');
}

// v2: version || height || P || next leaf BE || message flag || message || accepted salt || chain starts.
const VERSION = 2;
const PARAMETER = 2;
const NEXT_LEAF = PARAMETER + PARAMETER_LEN;
const HAS_MESSAGE = NEXT_LEAF + 4;
const MESSAGE = HAS_MESSAGE + 1;
const SALT = MESSAGE + MESSAGE_LEN;
const SECRETS = SALT + SALT_LENGTH;

/** Makes Definition 8 signing state durable in an exclusively locked key file.
 * Requires Bun on macOS or Linux with glibc. */
export class SigningKey<S> {
  readonly #key: OneTime<S>;
  readonly #path: string;
  readonly #lock: number;
  #nextLeaf: number;
  #lastMessage: Uint8Array | undefined;
  #lastSalt: Uint8Array;
  #closed = false;
  #sampling = false;

  private constructor(key: OneTime<S>, path: string, lock: number, nextLeaf: number, lastSalt: Uint8Array, lastMessage?: Uint8Array) {
    this.#key = key;
    this.#path = path;
    this.#lock = lock;
    this.#nextLeaf = nextLeaf;
    this.#lastMessage = lastMessage;
    this.#lastSalt = lastSalt;
  }

  /** Sample every chain start and `P` from the OS random source. Refuses an existing file. */
  static create<S>(type: KeyType<S>, path: string): SigningKey<S> {
    // Only the built-in instances may choose a key-file tag.
    checkKeyType(type);
    const lock = acquire(path);
    try {
      let fd: number;
      try { fd = openSync(path, 'wx', 0o600); }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'EEXIST') throw new SigningError('Exists', 'a key file already exists at this path: open it instead');
        throw error;
      }
      let signer: SigningKey<S>;
      const secrets = new Uint8Array(type.LEAVES * ELEMENTS_LENGTH);
      try {
        fillRandom(secrets);
        const parameter = fillRandom(new Uint8Array(PARAMETER_LEN));
        signer = new SigningKey(type.fromSecrets(secrets, parameter), path, lock, 0, new Uint8Array(SALT_LENGTH));
        signer.#writeRecord(fd);
        fsyncSync(fd);
      } finally { secrets.fill(0); closeSync(fd); }
      syncDir(path);
      return signer;
    } catch (error) { release(lock); throw signingError(error); }
  }

  /** Open a v2 key file and hold its permanent sidecar lock. */
  static open<S>(type: KeyType<S>, path: string): SigningKey<S> {
    // Only the built-in instances may choose a key-file tag.
    checkKeyType(type);
    const lock = acquire(path);
    try {
      let record: Buffer;
      try { record = readFileSync(path); }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') throw new SigningError('Missing', 'no key file at this path: usage state is required');
        throw error;
      }
      try {
        const corrupt = new SigningError('Corrupt', 'the key file is not a record of this instance');
        if (record.length !== SECRETS + type.LEAVES * ELEMENTS_LENGTH || record[0] !== VERSION
            || record[1] !== type.HEIGHT || record[HAS_MESSAGE]! > 1) throw corrupt;
        const parameter = record.subarray(PARAMETER, NEXT_LEAF);
        const nextLeaf = record.readUInt32BE(NEXT_LEAF);
        const lastMessage = record[HAS_MESSAGE] === 1 ? Uint8Array.from(record.subarray(MESSAGE, SALT)) : undefined;
        const lastSalt = Uint8Array.from(record.subarray(SALT, SECRETS));
        if (nextLeaf > type.LEAVES || (lastMessage && nextLeaf === 0)
            || (lastMessage ? !encode(lastSalt, parameter, nextLeaf - 1, lastMessage) : record.subarray(MESSAGE, SECRETS).some((b) => b !== 0))) throw corrupt;
        return new SigningKey(type.fromSecrets(record.subarray(SECRETS), parameter), path, lock, nextLeaf, lastSalt, lastMessage);
      } finally { record.fill(0); }
    } catch (error) { release(lock); throw signingError(error); }
  }

  /** Require the next unused leaf to be at least `minimum`, without advancing it.
   * Closes and throws `LeafBelowMinimum` if state is behind. A chain's last
   * accepted leaf plus one cannot account for signatures exposed but not landed. */
  requireNextLeafAtLeast(minimum: number): this {
    if (!Number.isInteger(minimum) || minimum < 0 || minimum > this.#key.leaves) { this.close(); throw new CryptoError('InvalidEncoding', 'invalid leaf minimum'); }
    if (this.#nextLeaf < minimum) {
      this.close();
      throw new SigningError('LeafBelowMinimum', `the key file is behind the chain: next leaf ${this.#nextLeaf}, minimum ${minimum}`);
    }
    return this;
  }

  verifyingKey(): VerifyingKey { return this.#key.verifyingKey(); }
  nextLeaf(): number { return this.#nextLeaf; }
  remaining(): number { return this.#key.leaves - this.#nextLeaf; }

  /** Persist each attempt. Retry the recorded message exactly; sampling failure spends a leaf and clears the record. */
  sign(message: Uint8Array): S {
    return this.signWithRng(message, fillRandom);
  }

  /** The source must synchronously fill every byte with fresh CSPRNG output or throw. Failed attempts
   * still spend a leaf; retries never call the source. No caller buffer is retained. */
  signWithRng(message: Uint8Array, fill: FillRandom): S {
    if (this.#closed) throw new SigningError('Unusable', 'the signer is closed');
    if (this.#sampling) throw new SigningError('Unusable', 'a signing attempt is already in progress');
    const bytesOfMessage = bytes(message, MESSAGE_LEN, 'message');
    if (this.#lastMessage && equal(bytesOfMessage, this.#lastMessage)) return this.#key.signAtWithSalt(this.#nextLeaf - 1, bytesOfMessage, this.#lastSalt);
    if (this.#nextLeaf >= this.#key.leaves) throw new SigningError('Exhausted', 'leaves exhausted');
    const leaf = this.#nextLeaf;
    let salt: Uint8Array | undefined;
    let failure: unknown;
    this.#sampling = true;
    try { salt = sampleSalt(this.verifyingKey().toBytes().subarray(ELEMENT_LENGTH), leaf, bytesOfMessage, fill); }
    catch (error) { failure = signingError(error, 'Random'); }
    finally { this.#sampling = false; }
    // Definition 8 permits one attempt per leaf, including failure.
    this.#nextLeaf = leaf + 1;
    this.#lastMessage = salt ? bytesOfMessage : undefined;
    this.#lastSalt = salt ?? new Uint8Array(SALT_LENGTH);
    try { this.#write(); }
    catch (error) { this.close(); throw signingError(error); }
    if (!salt) throw failure;
    return this.#key.signAtWithSalt(leaf, bytesOfMessage, salt);
  }

  /** Release the exclusive key-file lock at the end of a `using` scope. */
  [Symbol.dispose](): void { this.close(); }

  close(): void {
    if (this.#sampling) throw new SigningError('Unusable', 'cannot release the lock during a signing attempt');
    if (this.#closed) return;
    this.#closed = true;
    release(this.#lock);
  }

  #writeRecord(fd: number): void {
    const header = Buffer.alloc(SECRETS);
    header[0] = VERSION;
    header[1] = this.#key.height;
    header.set(this.verifyingKey().toBytes().subarray(ELEMENT_LENGTH), PARAMETER);
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
 * Lock a permanent sidecar so replacing the record preserves mutual exclusion.
 * Never unlink it: a new inode would permit a second holder. Uses the same Unix flock as Rust.
 */
function acquire(path: string): number {
  let fd: number;
  try { fd = openSync(`${path}.lock`, 'a', 0o600); }
  catch (error) { throw signingError(error); }
  try {
    if (!flock(fd)) throw new SigningError('Locked', `the key file is held by another signer (${path}.lock)`);
    return fd;
  } catch (error) { closeSync(fd); throw signingError(error); }
}

function release(fd: number): void {
  closeSync(fd);
}

const LOCK_EX = 2;
const LOCK_NB = 4;
let libc: { symbols: { flock: (fd: number, operation: number) => number } } | undefined;

function flock(fd: number): boolean {
  if (typeof Bun === 'undefined' || process.platform === 'win32') {
    throw new Error('SigningKey needs Bun on a unix host: the key-file lock is flock(2) through bun:ffi');
  }
  if (!libc) {
    const { dlopen, FFIType } = require('bun:ffi') as typeof import('bun:ffi');
    libc = dlopen(process.platform === 'darwin' ? '/usr/lib/libSystem.B.dylib' : 'libc.so.6', {
      flock: { args: [FFIType.i32, FFIType.i32], returns: FFIType.i32 },
    });
  }
  return libc.symbols.flock(fd, LOCK_EX | LOCK_NB) === 0;
}

/** Sync the directory entry after creating or replacing the record. */
function syncDir(path: string): void {
  if (process.platform === 'win32') return;
  const fd = openSync(dirname(path) || '.', 'r');
  try { fsyncSync(fd); } finally { closeSync(fd); }
}
