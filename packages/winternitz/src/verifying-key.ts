import { bytes, PUBLIC_KEY_LEN, MESSAGE_LEN, SALT_LENGTH, ELEMENTS_LENGTH, ELEMENT_LENGTH, encode, leafHash, endsFromSignature, node, equal } from './core.js';
import { CryptoError } from './error.js';
import * as winternitz from './winternitz.js';
import * as xmss from './xmss.js';

export class VerifyingKey {
  static readonly BYTE_LEN = PUBLIC_KEY_LEN;

  /** Verify a signature over an application-supplied 32-byte digest. Records no usage state. */
  verify(message: Uint8Array, signature: winternitz.Signature | xmss.Signature): void {
    const digest = bytes(message, MESSAGE_LEN, 'message');
    const isXmss = signature instanceof xmss.Signature;
    if (!isXmss && !(signature instanceof winternitz.Signature)) throw new CryptoError('InvalidSignature');
    const encoded = signature.toBytes();
    const leaf = isXmss ? (signature as xmss.Signature).leaf() : 0;
    if (leaf >= xmss.LEAVES) throw new CryptoError('InvalidSignature');
    const salt = isXmss ? 4 : 0;
    const elements = salt + SALT_LENGTH;
    const path = elements + ELEMENTS_LENGTH;
    const parameter = this.#bytes.subarray(ELEMENT_LENGTH);
    const x = encode(encoded.subarray(salt, elements), parameter, leaf, digest);
    if (!x) throw new CryptoError('InvalidSignature');
    let current = leafHash(parameter, leaf, endsFromSignature(parameter, leaf, x, encoded.subarray(elements, path)));
    if (isXmss) for (let level = 1; level <= xmss.HEIGHT; level++) {
      const sibling = encoded.subarray(path + (level - 1) * ELEMENT_LENGTH, path + level * ELEMENT_LENGTH);
      const index = leaf >> level;
      current = (leaf >> (level - 1)) & 1 ? node(parameter, level, index, sibling, current) : node(parameter, level, index, current, sibling);
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
