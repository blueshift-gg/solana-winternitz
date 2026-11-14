import { bytes, PUBLIC_KEY_LEN, MESSAGE_LEN, SALT_LENGTH, ELEMENT_LENGTH, leaf, equal } from './core.js';
import { CryptoError } from './error.js';
import { Signature } from './signature.js';

/** `leaf || P`, 41 bytes. */
export class VerifyingKey {
  static readonly BYTE_LEN = PUBLIC_KEY_LEN;

  /** Verify a one-time signature over an application-supplied 32-byte digest. Records no usage state. */
  verify(message: Uint8Array, signature: Signature): void {
    const digest = bytes(message, MESSAGE_LEN, 'message');
    if (!(signature instanceof Signature)) throw new CryptoError('InvalidSignature');
    const encoded = signature.toBytes();
    const committed = leaf(this.#bytes.subarray(ELEMENT_LENGTH), 0, encoded.subarray(0, SALT_LENGTH), encoded.subarray(SALT_LENGTH), digest);
    if (!committed || !equal(committed, this.#bytes.subarray(0, ELEMENT_LENGTH))) throw new CryptoError('InvalidSignature');
  }

  readonly #bytes: Uint8Array;

  private constructor(data: Uint8Array) {
    this.#bytes = bytes(data, VerifyingKey.BYTE_LEN, 'verifying key');
  }

  /** Copy the exact-size encoding. Authentication is checked only by verification. */
  static fromBytes(value: Uint8Array): VerifyingKey {
    return new VerifyingKey(value);
  }

  /** Return an independent copy of the encoding. */
  toBytes(): Uint8Array {
    return this.#bytes.slice();
  }
}
