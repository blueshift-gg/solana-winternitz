//! Post-quantum hash-based signatures for Solana programs: DKKW25's
//! generalized XMSS (Construction 3) over target-sum Winternitz
//! (Construction 6), with SHA-256 in place of the paper's SHA-3 (§7.2).
//! [`winternitz`] is the tree of height 0, [`xmss`] the tree of height 8;
//! one code path serves both. On `target_os = "solana"` every hash is the
//! `sol_sha256` syscall.
//!
//! Each departure from the paper is marked where it is made: input order
//! (§7.1–7.2), HMAC for the message hash (§7.2.1), 24-byte chains under
//! 32-byte nodes (Theorem 1), seed-derived keys and salts (Remark 7).
//!
//! [DKKW25]: https://eprint.iacr.org/2025/055
#![no_std]

mod sha256;
mod syscalls;
pub mod winternitz;
pub mod xmss;

#[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
extern crate std;
#[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
mod signer;
#[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
pub use signer::{OneTime, Signer, SignerError};

#[cfg(test)]
mod tests;

/// `v`: 35 × 4 bits = 140 ≥ 138, eq. (13).
const CHAINS: usize = 35;
/// `2^w`, w = 4: one nibble per chain, no big-integer decoding.
const POSITIONS: u8 = 16;
/// `T` of Construction 6, above the mean 262.5 as Remark 8 allows (δ =
/// 1.24 against the paper's 1.1): 35·15 − 325 = 200 verifier steps, ~940
/// salts per signature by Lemma 7's `η_T`. The digest width carries the
/// security, not `T`: Lemma 8 reduces to SM-rTCR, eq. (13).
const TARGET_SUM: u16 = 325;
/// `ρ`: eq. (14) at L = 2^8, K = 2^16 needs ≥ 176 bits.
const SALT_LENGTH: usize = 24;
/// `P`: eq. (16) needs ≥ 142 bits.
const PARAMETER_LENGTH: usize = 24;
/// `n`: eq. (15) at L = 2^8 needs ≥ 183 bits.
const ELEMENT_LENGTH: usize = 24;
/// Leaf and node: full SHA-256. Wider than the paper's single `H`; Theorem
/// 1's tree term then runs against the untruncated hash, see README.
const NODE_LENGTH: usize = 32;
const ELEMENTS_LENGTH: usize = CHAINS * ELEMENT_LENGTH;

/// §7.1 domain bytes, eqs. (17)–(19), plus RFC 8391's PRF tag. Placed at
/// offset 0 rather than after `P` (§7.2.2) so an input's role is its first
/// byte; every field before the message has a fixed width.
const ROLE_CHAIN: u8 = 0;
const ROLE_TREE: u8 = 1;
const ROLE_MESSAGE: u8 = 2;
const ROLE_SEED: u8 = 3;
/// `tweak(ep, i, k)` of eq. (17): `role ‖ leaf ‖ chain ‖ position`.
const CHAIN_TWEAK_LENGTH: usize = 7;
/// `tweakmt(l, i)` of eq. (18): `role ‖ level ‖ index`.
const TREE_TWEAK_LENGTH: usize = 6;

/// `pk = (root, P)` of Construction 3; the root is the leaf at height 0.
pub const PUBLIC_KEY_LENGTH: usize = NODE_LENGTH + PARAMETER_LENGTH;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The salted digest misses the target sum, the leaf is out of range,
    /// or the chains do not close on the public key.
    InvalidSignature,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey(pub [u8; PUBLIC_KEY_LENGTH]);

impl PublicKey {
    fn new(node: &[u8; NODE_LENGTH], parameter: &[u8]) -> Self {
        let mut pk = [0; PUBLIC_KEY_LENGTH];
        pk[..NODE_LENGTH].copy_from_slice(node);
        pk[NODE_LENGTH..].copy_from_slice(parameter);
        Self(pk)
    }

    #[inline(always)]
    fn node(&self) -> &[u8] {
        &self.0[..NODE_LENGTH]
    }

    #[inline(always)]
    fn parameter(&self) -> &[u8] {
        &self.0[NODE_LENGTH..]
    }
}

/// HMAC-SHA-256 (RFC 2104), keyed by the public message-hash prefix.
///
/// Here because §7.2.1's message hash is SHA-3 and a plain SHA-256 in its
/// place is herdable: once `t` leaves are signed their hash inputs are
/// public, the `t` first-block states merge at `t · 2^128`, and every
/// suffix trial then tests `t` encodings, ~2^134 at `t = 64` against the
/// model's 2^140 (Perlner, Kelsey, Cooper, ePrint 2022/1061). The outer
/// call re-binds the prefix, so one compression tests one target again.
/// Keyed hash, not MAC: the key is public.
fn hmac(key: &[u8], message: &[u8]) -> [u8; sha256::HASH_LENGTH] {
    // Eight-byte XORs: a byte loop measured ~1,000 CU on SBPF.
    let mut padded = [0u8; 64];
    padded[..key.len()].copy_from_slice(key);
    let mut ipad = [0u8; 64];
    let mut opad = [0u8; 64];
    for ((k, i), o) in padded
        .chunks_exact(8)
        .zip(ipad.chunks_exact_mut(8))
        .zip(opad.chunks_exact_mut(8))
    {
        let k = u64::from_ne_bytes(k.try_into().unwrap());
        i.copy_from_slice(&(k ^ 0x3636_3636_3636_3636).to_ne_bytes());
        o.copy_from_slice(&(k ^ 0x5c5c_5c5c_5c5c_5c5c).to_ne_bytes());
    }
    let inner = sha256::hashv(&[&ipad, message]);
    sha256::hashv(&[&opad, &inner])
}

/// Construction 6: `Th_msg` as `v` chunks of `w` bits, accepted iff they
/// sum to `T`. Chunks are low nibble first, hash-sig's `bytes_to_chunks`.
/// The raw message goes in: Remark 1's compression step is the HMAC itself.
fn encode(salt: &[u8], parameter: &[u8], leaf: u32, message: &[u8]) -> Option<[u8; CHAINS]> {
    let mut key = [0u8; 5 + SALT_LENGTH + PARAMETER_LENGTH];
    key[0] = ROLE_MESSAGE;
    key[1..5].copy_from_slice(&leaf.to_be_bytes());
    key[5..5 + SALT_LENGTH].copy_from_slice(salt);
    key[5 + SALT_LENGTH..].copy_from_slice(parameter);
    let digest = hmac(&key, message);
    let mut x = [0u8; CHAINS];
    for (i, xi) in x.iter_mut().enumerate() {
        *xi = digest[i / 2] >> (4 * (i % 2)) & 0x0f;
    }
    (x.iter().map(|&v| u16::from(v)).sum::<u16>() == TARGET_SUM).then_some(x)
}

/// Construction 2's chain, `Th(P, tweak(ep, i, k), x)` laid out as one
/// 55-byte buffer: each step is one syscall over one SHA-256 block.
struct Chain([u8; Chain::VALUE + ELEMENT_LENGTH]);

impl Chain {
    const INDEX: usize = 5;
    const POSITION: usize = 6;
    const VALUE: usize = CHAIN_TWEAK_LENGTH + PARAMETER_LENGTH;

    fn new(parameter: &[u8], leaf: u32) -> Self {
        let mut buf = [0u8; Self::VALUE + ELEMENT_LENGTH];
        buf[0] = ROLE_CHAIN;
        buf[1..Self::INDEX].copy_from_slice(&leaf.to_be_bytes());
        buf[CHAIN_TWEAK_LENGTH..Self::VALUE].copy_from_slice(parameter);
        Self(buf)
    }

    /// Construction 2: the step into position `k` carries tweak `k`, as
    /// hash-sig's `chain`. Lemma 2 is why signer and verifier may split
    /// the walk at `x_i`.
    fn walk(&mut self, i: u8, from: u8, to: u8, x: &[u8; ELEMENT_LENGTH]) -> [u8; ELEMENT_LENGTH] {
        self.0[Self::INDEX] = i;
        self.0[Self::VALUE..].copy_from_slice(x);
        for k in from..to {
            self.0[Self::POSITION] = k + 1;
            let h = sha256::hashv(&[&self.0]);
            self.0[Self::VALUE..].copy_from_slice(&h[..ELEMENT_LENGTH]);
        }
        self.0[Self::VALUE..].try_into().unwrap()
    }

    /// Construction 3 Ver step 6: each `σ_i` walked from `x_i` to `2^w − 1`.
    fn ends(&mut self, x: &[u8; CHAINS], elements: &[u8]) -> [[u8; ELEMENT_LENGTH]; CHAINS] {
        let mut ends = [[0u8; ELEMENT_LENGTH]; CHAINS];
        for (i, (end, element)) in ends
            .iter_mut()
            .zip(elements.chunks_exact(ELEMENT_LENGTH))
            .enumerate()
        {
            *end = self.walk(i as u8, x[i], POSITIONS - 1, element.try_into().unwrap());
        }
        ends
    }
}

/// `tweakmt(l, i)`, eq. (18).
fn tree_tweak(level: u8, index: u32) -> [u8; TREE_TWEAK_LENGTH] {
    let mut tweak = [ROLE_TREE, level, 0, 0, 0, 0];
    tweak[2..].copy_from_slice(&index.to_be_bytes());
    tweak
}

/// Construction 1 leaf, `Th(P, tweakmt(0, i), pk_i)`, `pk_i` the 35 chain
/// ends of Construction 3.
fn leaf_hash(
    parameter: &[u8],
    leaf: u32,
    ends: &[[u8; ELEMENT_LENGTH]; CHAINS],
) -> [u8; NODE_LENGTH] {
    const ENDS: usize = TREE_TWEAK_LENGTH + PARAMETER_LENGTH;
    let mut buf = [0u8; ENDS + ELEMENTS_LENGTH];
    buf[..TREE_TWEAK_LENGTH].copy_from_slice(&tree_tweak(0, leaf));
    buf[TREE_TWEAK_LENGTH..ENDS].copy_from_slice(parameter);
    for (slot, end) in buf[ENDS..].chunks_exact_mut(ELEMENT_LENGTH).zip(ends) {
        slot.copy_from_slice(end);
    }
    sha256::hashv(&[&buf])
}

/// Construction 1 node, `Th(P, tweakmt(l, i), (left, right))`.
fn node(parameter: &[u8], level: u8, index: u32, left: &[u8], right: &[u8]) -> [u8; NODE_LENGTH] {
    sha256::hashv(&[&tree_tweak(level, index), parameter, left, right])
}

/// Key material from one 32-byte seed, Remark 7's PRF, as
/// `SHA-256(0x03 ‖ purpose ‖ height ‖ fields ‖ seed)[..]`. Salts come from
/// it too, which the paper samples fresh: distinct (purpose, height, leaf,
/// counter) labels make them independent under the PRF, and one message
/// per leaf keeps the labels distinct. `height` is here because without it
/// the `winternitz` leaf is `xmss` leaf 0 of the same seed.
#[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
mod seed {
    use super::*;

    /// `K` of Construction 3, error `δ^K` by Lemma 3: ~940 expected, all
    /// miss once in e^70. Eq. (14) prices the salt for this `K`.
    pub const MAX_TRIALS: u32 = 1 << 16;

    const PARAMETER: u8 = 0;
    const START: u8 = 1;
    const SALT: u8 = 2;

    pub fn parameter(seed: &[u8; 32], height: u8) -> [u8; PARAMETER_LENGTH] {
        sha256::hashv(&[&[ROLE_SEED, PARAMETER, height], seed])[..PARAMETER_LENGTH]
            .try_into()
            .unwrap()
    }

    fn start(seed: &[u8; 32], height: u8, leaf: u32, i: u8) -> [u8; ELEMENT_LENGTH] {
        sha256::hashv(&[&[ROLE_SEED, START, height], &leaf.to_be_bytes(), &[i], seed])
            [..ELEMENT_LENGTH]
            .try_into()
            .unwrap()
    }

    /// Construction 3 Gen step 2: the chain ends `pk_ep`.
    pub fn ends(
        seed: &[u8; 32],
        parameter: &[u8],
        height: u8,
        leaf: u32,
    ) -> [[u8; ELEMENT_LENGTH]; CHAINS] {
        let mut chain = Chain::new(parameter, leaf);
        let mut ends = [[0u8; ELEMENT_LENGTH]; CHAINS];
        for (i, end) in ends.iter_mut().enumerate() {
            *end = chain.walk(
                i as u8,
                0,
                POSITIONS - 1,
                &start(seed, height, leaf, i as u8),
            );
        }
        ends
    }

    /// Construction 3 Sig steps 3–5 with salt candidates from the PRF over
    /// `(leaf, ctr, SHA-256(m))`; `None` iff all `MAX_TRIALS` miss.
    pub fn sign(
        seed: &[u8; 32],
        parameter: &[u8],
        height: u8,
        leaf: u32,
        message: &[u8],
    ) -> Option<([u8; SALT_LENGTH], [u8; ELEMENTS_LENGTH])> {
        let digest = sha256::hashv(&[message]);
        let mut chain = Chain::new(parameter, leaf);
        (0..MAX_TRIALS).find_map(|ctr| {
            let salt: [u8; SALT_LENGTH] = sha256::hashv(&[
                &[ROLE_SEED, SALT, height],
                &leaf.to_be_bytes(),
                &ctr.to_be_bytes(),
                &digest,
                seed,
            ])[..SALT_LENGTH]
                .try_into()
                .unwrap();
            let x = encode(&salt, parameter, leaf, message)?;
            let mut elements = [0u8; ELEMENTS_LENGTH];
            for (i, (slot, &xi)) in elements
                .chunks_exact_mut(ELEMENT_LENGTH)
                .zip(&x)
                .enumerate()
            {
                slot.copy_from_slice(&chain.walk(
                    i as u8,
                    0,
                    xi,
                    &start(seed, height, leaf, i as u8),
                ));
            }
            Some((salt, elements))
        })
    }
}
