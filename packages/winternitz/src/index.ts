/** Target-sum Winternitz one-time signatures. The root is runtime-independent.
 * Persistent signing is available from `@blueshift-gg/solana-winternitz/signer`. */
export { CryptoError, type ErrorCode } from './error.js';
export { VerifyingKey } from './verifying-key.js';
export { Signature } from './signature.js';
export { MESSAGE_LEN, PARAMETER_LEN, PUBLIC_KEY_LEN, SIGNATURE_LEN } from './core.js';
