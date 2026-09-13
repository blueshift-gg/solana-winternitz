/** Persistent signers. `create` samples a new key; `open` restores its usage
 * state. Requires Bun on macOS or Linux with glibc. Use `using` to release locks. */
export { SigningError, type SigningErrorCode, type FillRandom } from './error.js';
export * as winternitz from './signer/winternitz.js';
export * as xmss from './signer/xmss.js';
