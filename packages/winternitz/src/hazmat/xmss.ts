import { generateKey, sampleSalt, bytes, ELEMENTS_LENGTH, PARAMETER_LEN, MESSAGE_LEN, SALT_LENGTH, concat, leafHash, endsOf, signLeaf, node, u32be } from '../core.js';
import { CryptoError, SigningError, type FillRandom } from '../error.js';
import { VerifyingKey } from '../verifying-key.js';
import { Signature, HEIGHT, LEAVES } from '../xmss.js';

const levelOffset = (l: number) => 2 * LEAVES - (2 << (HEIGHT - l));

/** Construction 3 key generation and signing with caller-managed leaf allocation;
 * use `SigningKey` from `./signer` for durable usage state. */
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

  /** Generate chain starts and a public parameter without a file. The synchronous
   * CSPRNG callback fills every byte or throws; requests are at most 828 bytes.
   * The caller owns leaf allocation and persistence. */
  static generate(fill: FillRandom): SecretKey {
    return generateKey(SecretKey.LEAVES, SecretKey.fromSecrets, fill);
  }

  /** Sample salts and sign at a caller-reserved leaf. Records no usage state.
   * Reserve and persist the leaf before calling; sampling failure still spends
   * the attempt. The synchronous callback must fill every byte with CSPRNG output. */
  signAt(leaf: number, message: Uint8Array, fill: FillRandom): Signature {
    if (!Number.isInteger(leaf) || leaf < 0 || leaf >= SecretKey.LEAVES) throw new SigningError('InvalidLeaf', 'leaf index is outside this instance');
    const digest = bytes(message, MESSAGE_LEN, 'message');
    const salt = sampleSalt(this.#parameter, leaf, digest, fill);
    return this.signAtWithSalt(leaf, digest, salt);
  }

  /** Check exact lengths and copy sampled chain starts and `P`, then build the tree. Does not check entropy. */
  static fromSecrets(secrets: Uint8Array, parameter: Uint8Array): SecretKey {
    return new SecretKey(bytes(secrets, SecretKey.LEAVES * ELEMENTS_LENGTH, 'chain starts'), bytes(parameter, PARAMETER_LEN, 'parameter'));
  }

  /** Raw chain starts; never restore usage state from these alone. */
  get secrets(): Uint8Array { return this.#secrets.slice(); }

  verifyingKey(): VerifyingKey {
    return VerifyingKey.fromBytes(concat(this.#nodes[levelOffset(HEIGHT)]!, this.#parameter));
  }

  readonly leaves = LEAVES;
  readonly height = HEIGHT;

  /** Reproduce a recorded signature using its accepted salt. Records no usage state. */
  signAtWithSalt(leaf: number, message: Uint8Array, salt: Uint8Array): Signature {
    if (!Number.isInteger(leaf) || leaf < 0 || leaf >= LEAVES) throw new CryptoError('InvalidEncoding', `leaf: expected 0..${LEAVES}`);
    const path = Array.from({ length: HEIGHT }, (_, l) => this.#nodes[levelOffset(l) + ((leaf >> l) ^ 1)]!);
    return Signature.fromBytes(concat(u32be(leaf), signLeaf(this.#secrets, this.#parameter, leaf, bytes(message, MESSAGE_LEN, 'message'), bytes(salt, SALT_LENGTH, 'salt')), ...path));
  }
}
