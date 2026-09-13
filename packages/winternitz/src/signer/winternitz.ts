import { SigningKey as PersistentSigningKey } from '../signing-key.js';
import { SecretKey } from '../hazmat/winternitz.js';
import type { Signature } from '../winternitz.js';

/** Definition 8 signing state made durable in an exclusively locked winternitz key file. */
export type SigningKey = PersistentSigningKey<Signature>;

/** Open or create a persistent winternitz signer. */
export const SigningKey = {
  /** Sample a new key from OS randomness; refuse an existing key file. */
  create(path: string): SigningKey { return PersistentSigningKey.create(SecretKey, path); },
  /** Restore a key and its complete usage state under an exclusive file lock. */
  open(path: string): SigningKey { return PersistentSigningKey.open(SecretKey, path); },
};
