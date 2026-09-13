/** Target-sum Winternitz and XMSS primitives. The root is runtime-independent.
 * Persistent signing is available from `@blueshift-gg/solana-winternitz/signer`. */
export { CryptoError, type ErrorCode } from './error.js';
export { VerifyingKey } from './verifying-key.js';
export { MESSAGE_LEN, PARAMETER_LEN, PUBLIC_KEY_LEN } from './core.js';
export * as winternitz from './winternitz.js';
export * as xmss from './xmss.js';
