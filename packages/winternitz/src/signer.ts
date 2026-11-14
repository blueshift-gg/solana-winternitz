/** Persistent signers. `create` samples a new key; `open` restores its usage
 * state. Requires Bun on macOS or Linux with glibc. Use `using` to release locks. */
import { KeyFile } from './signing-key.js';
import { SecretKey } from './hazmat.js';
import type { Signature } from './signature.js';
import type { VerifyingKey } from './verifying-key.js';

export { SigningError, type SigningErrorCode, type FillRandom } from './error.js';
export { KeyFile, type OneTime, type KeyType } from './signing-key.js';

/** Definition 8 signing state made durable in an exclusively locked key file. */
export type SigningKey = KeyFile<Signature, VerifyingKey>;

/** Open or create a persistent one-time signer. */
export const SigningKey = {
  /** Sample a new key from OS randomness; refuse an existing key file. */
  create(path: string): SigningKey { return KeyFile.create(SecretKey, path); },
  /** Restore a key and its complete usage state under an exclusive file lock. */
  open(path: string): SigningKey { return KeyFile.open(SecretKey, path); },
};
