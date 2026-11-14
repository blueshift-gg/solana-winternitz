/** A 256-leaf DKKW25 XMSS tree over `@blueshift-gg/solana-winternitz` one-time keys.
 * The root is runtime-independent. Persistent signing is available from
 * `@blueshift-gg/solana-xmss/signer`. */
export { CryptoError, type ErrorCode } from '@blueshift-gg/solana-winternitz';
export { MESSAGE_LEN, PARAMETER_LEN } from '@blueshift-gg/solana-winternitz';
export { VerifyingKey, PUBLIC_KEY_LEN } from './verifying-key.js';
export { Signature, HEIGHT, LEAVES, SIGNATURE_LEN } from './signature.js';
