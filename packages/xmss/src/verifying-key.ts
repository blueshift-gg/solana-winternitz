import { CryptoError, bytes, equal, leaf, node, MESSAGE_LEN, SALT_LENGTH, ELEMENTS_LENGTH, ELEMENT_LENGTH } from '@blueshift-gg/solana-winternitz/primitives';
import { HEIGHT, LEAVES, Signature } from './signature.js';

/** `root || P`, 41 bytes. */
export const PUBLIC_KEY_LEN = 41;

const SALT = 4;
const ELEMENTS = SALT + SALT_LENGTH;
const PATH = ELEMENTS + ELEMENTS_LENGTH;

export class VerifyingKey {
  static readonly BYTE_LEN = PUBLIC_KEY_LEN;

  /** Verify the chains and authentication path over an application-supplied
   * 32-byte digest. Stateless: the application must refuse leaves it has accepted. */
  verify(message: Uint8Array, signature: Signature): void {
    const digest = bytes(message, MESSAGE_LEN, 'message');
    if (!(signature instanceof Signature)) throw new CryptoError('InvalidSignature');
    const encoded = signature.toBytes();
    const index = signature.leaf();
    if (index >= LEAVES) throw new CryptoError('InvalidSignature');
    const parameter = this.#bytes.subarray(ELEMENT_LENGTH);
    let current = leaf(parameter, index, encoded.subarray(SALT, ELEMENTS), encoded.subarray(ELEMENTS, PATH), digest);
    if (!current) throw new CryptoError('InvalidSignature');
    for (let level = 1; level <= HEIGHT; level++) {
      const sibling = encoded.subarray(PATH + (level - 1) * ELEMENT_LENGTH, PATH + level * ELEMENT_LENGTH);
      const at = index >> level;
      current = (index >> (level - 1)) & 1 ? node(parameter, level, at, sibling, current) : node(parameter, level, at, current, sibling);
    }
    if (!equal(current, this.#bytes.subarray(0, ELEMENT_LENGTH))) throw new CryptoError('InvalidSignature');
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
