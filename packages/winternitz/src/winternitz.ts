import { bytes, SALT_LENGTH, ELEMENTS_LENGTH } from './core.js';

/** `(ρ, σ_OTS)` of Construction 3. */
export const SIGNATURE_LEN = SALT_LENGTH + ELEMENTS_LENGTH;

export class Signature {
  static readonly BYTE_LEN = SIGNATURE_LEN;
  readonly #bytes: Uint8Array;

  private constructor(data: Uint8Array) {
    this.#bytes = bytes(data, Signature.BYTE_LEN, 'signature');
  }

  /** Copy the exact-size encoding. Authentication is checked only by verification. */
  static fromBytes(value: Uint8Array): Signature {
    return new Signature(value);
  }

  /** Return an independent copy of the encoding. */
  toBytes(): Uint8Array {
    return this.#bytes.slice();
  }
}
