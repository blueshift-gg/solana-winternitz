//! Post-quantum hash-based signatures for Solana programs.
//!
//! Generalized XMSS with target-sum Winternitz over a SHA-256 tweakable
//! hash: Constructions 1, 3 and 6 and §7.2 of Drake, Khovratovich, Kudinov,
//! Wagner, *Hash-Based Multi-Signatures for Post-Quantum Ethereum* (IACR CiC
//! 2025, [DKKW25]). Two instances:
//!
//! - [`winternitz`]: lifetime 1. One key, one signature.
//! - [`xmss`]: lifetime 256. One key, 256 signatures indexed by epoch; the
//!   verifier enforces that no epoch is reused.
//!
//! Both use the 56-byte public key `node ‖ P` the paper defines, where `P`
//! is the per-key public parameter and `node` is the leaf (lifetime 1) or
//! the Merkle root. Both share the leaf: the salted message digest gives 35
//! nibbles that must sum to 325, the signer grinds the salt until they do,
//! and no two such digests are coordinate-wise comparable, which is what a
//! checksum would otherwise guarantee. Verification is a fixed 200 chain
//! hashes plus a leaf hash, plus one node hash per tree level.
//!
//! Every hash input starts with a role byte, as RFC 8391 §5.1 does, so the
//! chain, tree, message and key-derivation inputs are disjoint byte strings.
//!
//! On `target_os = "solana"` every hash is the `sol_sha256` syscall.
//!
//! [DKKW25]: https://eprint.iacr.org/2025/055
#![no_std]

mod sha256;
mod syscalls;
pub mod winternitz;
pub mod xmss;

#[cfg(test)]
mod tests;

/// Chains `v`, one digest nibble each.
const CHAINS: usize = 35;
/// Chain positions `w`.
const POSITIONS: u8 = 16;
/// Required nibble sum. Security comes from the 140-bit digest, DKKW25
/// eq. (13): hitting a signed encoding costs 2^140 hashes however the
/// target is set. The target only fixes the verifier's work,
/// `35 × 15 − 325 = 200` chain steps, and the signer's grinding: the layer
/// of `[16]^35` with this sum holds 2^130.1 vectors, so a uniform digest
/// lands in it once in ~940 tries.
const TARGET_SUM: u16 = 325;
/// Salt `ρ`. DKKW25 eq. (14) at lifetime 256 with 2^16 signing trials: ≥ 22 bytes.
const SALT_LENGTH: usize = 24;
/// Public parameter `P`. DKKW25 eq. (16): ≥ 18 bytes.
const PARAMETER_LENGTH: usize = 24;
/// Chain element `n`. DKKW25 eq. (15) at lifetime 256: ≥ 23 bytes.
const ELEMENT_LENGTH: usize = 24;
/// Leaf and tree node: the full SHA-256 output.
const NODE_LENGTH: usize = 32;
const ELEMENTS_LENGTH: usize = CHAINS * ELEMENT_LENGTH;

/// Role byte at offset 0 of every hash input. Within a role every field
/// but the message has a fixed width and precedes it.
const ROLE_CHAIN: u8 = 0;
const ROLE_TREE: u8 = 1;
const ROLE_MESSAGE: u8 = 2;
const ROLE_SEED: u8 = 3;
/// `role ‖ epoch ‖ chain ‖ position`.
const CHAIN_TWEAK_LENGTH: usize = 7;
/// `role ‖ level ‖ index`.
const TREE_TWEAK_LENGTH: usize = 6;

/// `node ‖ P`: the leaf for [`winternitz`], the Merkle root for [`xmss`].
pub const PUBLIC_KEY_LENGTH: usize = NODE_LENGTH + PARAMETER_LENGTH;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The salted digest misses the target sum, the epoch is out of range,
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

/// First 140 bits of `SHA-256(0x02 ‖ epoch ‖ ρ ‖ P ‖ m)` as nibbles, low
/// nibble first as in hash-sig's `bytes_to_chunks`, accepted only if they
/// sum to `TARGET_SUM`.
fn encode(salt: &[u8], parameter: &[u8], epoch: u32, message: &[u8]) -> Option<[u8; CHAINS]> {
    let mut tweak = [ROLE_MESSAGE, 0, 0, 0, 0];
    tweak[1..].copy_from_slice(&epoch.to_be_bytes());
    let digest = sha256::hashv(&[&tweak, salt, parameter, message]);
    let mut x = [0u8; CHAINS];
    for (i, xi) in x.iter_mut().enumerate() {
        *xi = digest[i / 2] >> (4 * (i % 2)) & 0x0f;
    }
    (x.iter().map(|&v| u16::from(v)).sum::<u16>() == TARGET_SUM).then_some(x)
}

/// Chain-step input `0x00 ‖ epoch ‖ i ‖ k ‖ P ‖ x`: one 55-byte slice per
/// syscall, reused across every step of every chain of one epoch.
struct Chain([u8; Chain::VALUE + ELEMENT_LENGTH]);

impl Chain {
    const INDEX: usize = 5;
    const POSITION: usize = 6;
    const VALUE: usize = CHAIN_TWEAK_LENGTH + PARAMETER_LENGTH;

    fn new(parameter: &[u8], epoch: u32) -> Self {
        let mut buf = [0u8; Self::VALUE + ELEMENT_LENGTH];
        buf[0] = ROLE_CHAIN;
        buf[1..Self::INDEX].copy_from_slice(&epoch.to_be_bytes());
        buf[CHAIN_TWEAK_LENGTH..Self::VALUE].copy_from_slice(parameter);
        Self(buf)
    }

    /// Walk chain `i` from position `from` to `to`, starting at `x`. The step
    /// into position `k` is tweaked with `k`, as in hash-sig's `chain`.
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

    /// Walk every chain of `elements` from the encoded positions to the end.
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

fn tree_tweak(level: u8, index: u32) -> [u8; TREE_TWEAK_LENGTH] {
    let mut tweak = [ROLE_TREE, level, 0, 0, 0, 0];
    tweak[2..].copy_from_slice(&index.to_be_bytes());
    tweak
}

/// `SHA-256(0x01 ‖ 0 ‖ epoch ‖ P ‖ pk_0 ‖ … ‖ pk_34)`: the leaf of DKKW25
/// Construction 3, and the whole tree at lifetime 1.
fn leaf(parameter: &[u8], epoch: u32, ends: &[[u8; ELEMENT_LENGTH]; CHAINS]) -> [u8; NODE_LENGTH] {
    const ENDS: usize = TREE_TWEAK_LENGTH + PARAMETER_LENGTH;
    let mut buf = [0u8; ENDS + ELEMENTS_LENGTH];
    buf[..TREE_TWEAK_LENGTH].copy_from_slice(&tree_tweak(0, epoch));
    buf[TREE_TWEAK_LENGTH..ENDS].copy_from_slice(parameter);
    for (slot, end) in buf[ENDS..].chunks_exact_mut(ELEMENT_LENGTH).zip(ends) {
        slot.copy_from_slice(end);
    }
    sha256::hashv(&[&buf])
}

/// `SHA-256(0x01 ‖ level ‖ index ‖ P ‖ left ‖ right)`: DKKW25 Construction 1.
fn node(parameter: &[u8], level: u8, index: u32, left: &[u8], right: &[u8]) -> [u8; NODE_LENGTH] {
    sha256::hashv(&[&tree_tweak(level, index), parameter, left, right])
}

/// Host-only key material, everything derived from a 32-byte seed by
/// `SHA-256(0x03 ‖ purpose ‖ fields ‖ seed)`, assumed to be a PRF keyed by
/// the seed (DKKW25 Remark 7; RFC 8391 §5.1 uses the same construction).
#[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
mod seed {
    use super::*;

    /// Salts tried before giving up: expected ~940, so under a uniform model
    /// all miss with probability e^-70. Two hashes per try. DKKW25 eq. (14)
    /// sizes the salt for this.
    pub const MAX_TRIALS: u32 = 1 << 16;

    const PARAMETER: u8 = 0;
    const START: u8 = 1;
    const SALT: u8 = 2;

    pub fn parameter(seed: &[u8; 32]) -> [u8; PARAMETER_LENGTH] {
        sha256::hashv(&[&[ROLE_SEED, PARAMETER], seed])[..PARAMETER_LENGTH]
            .try_into()
            .unwrap()
    }

    fn start(seed: &[u8; 32], epoch: u32, i: u8) -> [u8; ELEMENT_LENGTH] {
        sha256::hashv(&[&[ROLE_SEED, START], &epoch.to_be_bytes(), &[i], seed])[..ELEMENT_LENGTH]
            .try_into()
            .unwrap()
    }

    /// Chain ends of one epoch: its leaf content.
    pub fn ends(seed: &[u8; 32], parameter: &[u8], epoch: u32) -> [[u8; ELEMENT_LENGTH]; CHAINS] {
        let mut chain = Chain::new(parameter, epoch);
        let mut ends = [[0u8; ELEMENT_LENGTH]; CHAINS];
        for (i, end) in ends.iter_mut().enumerate() {
            *end = chain.walk(i as u8, 0, POSITIONS - 1, &start(seed, epoch, i as u8));
        }
        ends
    }

    /// Deterministic one-time signature of `message` under `epoch`: the salt
    /// and the 35 chain elements. Salt candidates are
    /// `SHA-256(0x03 ‖ 2 ‖ epoch ‖ ctr ‖ SHA-256(m) ‖ seed)`; `None` only if
    /// all `MAX_TRIALS` miss the target sum.
    pub fn sign(
        seed: &[u8; 32],
        parameter: &[u8],
        epoch: u32,
        message: &[u8],
    ) -> Option<([u8; SALT_LENGTH], [u8; ELEMENTS_LENGTH])> {
        let digest = sha256::hashv(&[message]);
        let mut chain = Chain::new(parameter, epoch);
        (0..MAX_TRIALS).find_map(|ctr| {
            let salt: [u8; SALT_LENGTH] = sha256::hashv(&[
                &[ROLE_SEED, SALT],
                &epoch.to_be_bytes(),
                &ctr.to_be_bytes(),
                &digest,
                seed,
            ])[..SALT_LENGTH]
                .try_into()
                .unwrap();
            let x = encode(&salt, parameter, epoch, message)?;
            let mut elements = [0u8; ELEMENTS_LENGTH];
            for (i, (slot, &xi)) in elements
                .chunks_exact_mut(ELEMENT_LENGTH)
                .zip(&x)
                .enumerate()
            {
                slot.copy_from_slice(&chain.walk(i as u8, 0, xi, &start(seed, epoch, i as u8)));
            }
            Some((salt, elements))
        })
    }
}
