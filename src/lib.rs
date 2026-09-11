#![doc = include_str!("../README.md")]
//!
//! # Reading the source
//!
//! The construction is [DKKW25] Construction 3 over Construction 6 with the
//! §7.2 instantiation and the parameters of the authors' implementation,
//! hash-sig, Keccak-256 standing in for SHA3-256 (`hash.rs`). Chain
//! starts, the parameter and salts are sampled as Construction 3 writes
//! them (`signing`, `signer`). On `target_os = "solana"` every hash is the
//! `sol_keccak256` syscall.
#![no_std]
#![deny(missing_docs, clippy::undocumented_unsafe_blocks)]

mod hash;
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

/// `v`: hash-sig's 18-byte message hash at w = 4, 36 × 4 = 144 bits ≥ 138,
/// eq. (13). The bound alone allows 35, which no whole-byte truncation
/// gives.
const CHAINS: usize = 36;
/// `2^w`, w = 4.
const POSITIONS: u8 = 16;
/// `T = ⌈δ·v(2^w − 1)/2⌉` at δ = 1.1, the paper's §8 operating point and
/// hash-sig's `Off10`: 36·15 − 297 = 243 verifier steps, one salt in ~111
/// accepted (Lemma 7's `η_T`). Security is the digest width, not `T`:
/// Lemma 8, eq. (13).
const TARGET_SUM: u16 = 297;
/// `ρ`: eq. (14) at L = 2^8, K = 2^12 needs ≥ 168 bits.
const SALT_LENGTH: usize = 21;
/// `P`: eq. (16) needs ≥ 142 bits.
const PARAMETER_LENGTH: usize = 18;
/// `n`, chain elements, leaves and nodes alike: eq. (15) at L = 2^8 needs
/// ≥ 183 bits.
const ELEMENT_LENGTH: usize = 23;
const ELEMENTS_LENGTH: usize = CHAINS * ELEMENT_LENGTH;

/// §7.1 domain bytes, eqs. (17)–(19), first in each tweak.
const ROLE_CHAIN: u8 = 0;
const ROLE_TREE: u8 = 1;
const ROLE_MESSAGE: u8 = 2;
/// `tweak(ep, i, k)` of eq. (17): `role ‖ leaf ‖ chain ‖ position`.
const CHAIN_TWEAK_LENGTH: usize = 7;
/// `tweakmt(l, i)` of eq. (18): `role ‖ level ‖ index`.
const TREE_TWEAK_LENGTH: usize = 6;

/// `pk = (root, P)` of Construction 3; the root is the leaf at height 0.
pub const PUBLIC_KEY_LENGTH: usize = ELEMENT_LENGTH + PARAMETER_LENGTH;
/// `l_msg`, as hash-sig's `MESSAGE_LENGTH`: a message is a 32-byte digest,
/// the caller's hash of whatever it acts on (Remark 1).
pub const MESSAGE_LENGTH: usize = 32;

/// The one verification error: the verifier does not say why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The salted digest misses the target sum, the leaf is out of range,
    /// or the chains do not close on the public key.
    InvalidSignature,
}

/// `root ‖ P`, 41 bytes: what a program stores.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey(pub [u8; PUBLIC_KEY_LENGTH]);

impl PublicKey {
    #[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
    fn new(node: &[u8; ELEMENT_LENGTH], parameter: &[u8]) -> Self {
        let mut pk = [0; PUBLIC_KEY_LENGTH];
        pk[..ELEMENT_LENGTH].copy_from_slice(node);
        pk[ELEMENT_LENGTH..].copy_from_slice(parameter);
        Self(pk)
    }

    #[inline(always)]
    fn node(&self) -> &[u8] {
        &self.0[..ELEMENT_LENGTH]
    }

    #[inline(always)]
    fn parameter(&self) -> &[u8] {
        &self.0[ELEMENT_LENGTH..]
    }
}

/// Overwrite secret bytes on drop. Volatile writes and a fence so the
/// compiler cannot elide the store into a value it considers dead.
#[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
fn wipe(bytes: &mut [u8]) {
    for byte in bytes {
        // SAFETY: `byte` is a valid, aligned, exclusively borrowed `u8`.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Construction 6 over §7.2.1's `Th_msg(P, T, M, R) = Trunc(H(R ‖ P ‖ T ‖ M))`:
/// the first `v·w` bits as `v` chunks of `w` bits, accepted iff they sum to
/// `T`. Byte for byte hash-sig's `ShaMessageHash`: the epoch little-endian
/// in this one tweak, chunks low nibble first.
fn encode(
    salt: &[u8],
    parameter: &[u8],
    leaf: u32,
    message: &[u8; MESSAGE_LENGTH],
) -> Option<[u8; CHAINS]> {
    let mut tweak = [ROLE_MESSAGE, 0, 0, 0, 0];
    tweak[1..].copy_from_slice(&leaf.to_le_bytes());
    let digest = hash::hashv(&[salt, parameter, &tweak, message]);
    let mut x = [0u8; CHAINS];
    for (i, xi) in x.iter_mut().enumerate() {
        *xi = digest[i / 2] >> (4 * (i % 2)) & 0x0f;
    }
    (x.iter().map(|&v| u16::from(v)).sum::<u16>() == TARGET_SUM).then_some(x)
}

/// Construction 2's chain over §7.2.2's `Th(P, T, M) = Trunc_n(H(P ‖ T ‖ M))`,
/// laid out as one 48-byte buffer: each step is one syscall.
struct Chain([u8; Chain::VALUE + ELEMENT_LENGTH]);

impl Chain {
    const TWEAK: usize = PARAMETER_LENGTH;
    const INDEX: usize = Self::TWEAK + 5;
    const POSITION: usize = Self::TWEAK + 6;
    const VALUE: usize = Self::TWEAK + CHAIN_TWEAK_LENGTH;

    fn new(parameter: &[u8], leaf: u32) -> Self {
        let mut buf = [0u8; Self::VALUE + ELEMENT_LENGTH];
        buf[..Self::TWEAK].copy_from_slice(parameter);
        buf[Self::TWEAK] = ROLE_CHAIN;
        buf[Self::TWEAK + 1..Self::INDEX].copy_from_slice(&leaf.to_be_bytes());
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
            let h = hash::hashv(&[&self.0]);
            self.0[Self::VALUE..].copy_from_slice(&h[..ELEMENT_LENGTH]);
        }
        self.0[Self::VALUE..].try_into().unwrap()
    }

    /// Construction 3 Ver step 6: each `σ_i` walked from `x_i` to `2^w − 1`.
    fn ends(&mut self, x: &[u8; CHAINS], elements: &[u8]) -> [[u8; ELEMENT_LENGTH]; CHAINS] {
        let mut ends = [[0u8; ELEMENT_LENGTH]; CHAINS];
        for (i, (end, element)) in ends
            .iter_mut()
            .zip(elements.as_chunks::<ELEMENT_LENGTH>().0)
            .enumerate()
        {
            *end = self.walk(i as u8, x[i], POSITIONS - 1, element);
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

/// Construction 1 leaf, `Th(P, tweakmt(0, i), pk_i)`, `pk_i` the 36 chain
/// ends of Construction 3. The ends are contiguous and go to the syscall
/// uncopied.
fn leaf_hash(
    parameter: &[u8],
    leaf: u32,
    ends: &[[u8; ELEMENT_LENGTH]; CHAINS],
) -> [u8; ELEMENT_LENGTH] {
    hash::hashv(&[parameter, &tree_tweak(0, leaf), ends.as_flattened()])[..ELEMENT_LENGTH]
        .try_into()
        .unwrap()
}

/// Construction 1 node, `Th(P, tweakmt(l, i), (left, right))`.
fn node(
    parameter: &[u8],
    level: u8,
    index: u32,
    left: &[u8],
    right: &[u8],
) -> [u8; ELEMENT_LENGTH] {
    hash::hashv(&[parameter, &tree_tweak(level, index), left, right])[..ELEMENT_LENGTH]
        .try_into()
        .unwrap()
}

/// Host-side Construction 3 over explicitly sampled chain starts.
#[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
mod signing {
    use super::*;

    /// `K` of Construction 3; salt candidates are sampled independently.
    pub const MAX_TRIALS: u32 = 4096;

    pub fn ends(secrets: &[u8], parameter: &[u8], leaf: u32) -> [[u8; ELEMENT_LENGTH]; CHAINS] {
        let mut chain = Chain::new(parameter, leaf);
        core::array::from_fn(|i| {
            let offset = leaf as usize * ELEMENTS_LENGTH + i * ELEMENT_LENGTH;
            chain.walk(
                i as u8,
                0,
                POSITIONS - 1,
                secrets[offset..offset + ELEMENT_LENGTH].try_into().unwrap(),
            )
        })
    }

    /// Sign with an already accepted salt, allowing a persisted signature to
    /// be reproduced without drawing fresh randomness under a spent leaf.
    pub fn sign(
        secrets: &[u8],
        parameter: &[u8],
        leaf: u32,
        message: &[u8; MESSAGE_LENGTH],
        salt: &[u8; SALT_LENGTH],
    ) -> Option<[u8; ELEMENTS_LENGTH]> {
        let x = encode(salt, parameter, leaf, message)?;
        let mut chain = Chain::new(parameter, leaf);
        let mut elements = [0; ELEMENTS_LENGTH];
        for (i, slot) in elements
            .as_chunks_mut::<ELEMENT_LENGTH>()
            .0
            .iter_mut()
            .enumerate()
        {
            let offset = leaf as usize * ELEMENTS_LENGTH + i * ELEMENT_LENGTH;
            *slot = chain.walk(
                i as u8,
                0,
                x[i],
                secrets[offset..offset + ELEMENT_LENGTH].try_into().unwrap(),
            );
        }
        Some(elements)
    }
}
