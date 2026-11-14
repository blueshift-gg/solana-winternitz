/** DKKW25 building blocks shared with `@blueshift-gg/solana-xmss`: the leaf a
 * one-time signature commits to, the Merkle nodes above it, and leaf signing.
 * Every tweak is defined here, so the hash domains cannot overlap: chain steps
 * use role 0, leaves and nodes role 1 (leaves alone at level 0), and message
 * encoding role 2. `node` refuses level 0. */
export {
  ELEMENT_LENGTH, ELEMENTS_LENGTH, SALT_LENGTH, PARAMETER_LEN, MESSAGE_LEN,
  bytes, concat, equal, u32be, leaf, node, signLeaf, sampleSalt, generateKey,
} from './core.js';
export { CryptoError } from './error.js';
import { endsOf, leafHash } from './core.js';

/** The public leaf of `leaf`, from its chain starts in leaf-major order. */
export function publicLeaf(secrets: Uint8Array, parameter: Uint8Array, leaf: number): Uint8Array {
  return leafHash(parameter, leaf, endsOf(secrets, parameter, leaf));
}
