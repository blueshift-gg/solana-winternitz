import { bytes, SALT_LENGTH, ELEMENTS_LENGTH, ELEMENT_LENGTH } from './core.js';

export const HEIGHT = 8;
export const LEAVES = 1 << HEIGHT;
/** `(ep, ρ, σ_OTS, path_ep)` of Construction 3, `ep` as u32 big-endian. */
export const SIGNATURE_LEN = 4 + SALT_LENGTH + ELEMENTS_LENGTH + HEIGHT * ELEMENT_LENGTH;

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

  /** The unverified leaf index, unrelated to Solana epochs. */
  leaf(): number {
    return new DataView(this.#bytes.buffer, this.#bytes.byteOffset).getUint32(0, false);
  }
}
