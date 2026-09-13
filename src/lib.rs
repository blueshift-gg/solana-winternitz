#![doc = include_str!("../README.md")]
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
pub use signer::{SigningError, SigningKey};

#[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
pub mod hazmat;

#[cfg(test)]
mod tests;

/// `v`: 36 four-bit digits from an 18-byte hash; ≥ 138 bits, DKKW25 eq. (13).
const CHAINS: usize = 36;
/// `2^w`, w = 4.
const POSITIONS: u8 = 16;
/// `T = ⌈1.1·v(2^w − 1)/2⌉` (§8): 243 verifier chain steps.
/// Equal-sum vectors are incomparable (Lemma 7), replacing the checksum.
const TARGET_SUM: u16 = 297;
/// `ρ`: eq. (14) at L = 2^8, K = 2^12 needs ≥ 168 bits.
const SALT_LENGTH: usize = 21;
/// `P`: eq. (16) needs ≥ 142 bits.
pub const PARAMETER_LEN: usize = 18;
/// Chain elements, leaves and nodes: eq. (15) at L = 2^8 needs ≥ 183 bits.
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
pub const PUBLIC_KEY_LEN: usize = ELEMENT_LENGTH + PARAMETER_LEN;
/// Application-supplied digest length in bytes (Remark 1).
pub const MESSAGE_LEN: usize = 32;

/// Signature verification failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The salted digest misses the target sum, the leaf is out of range,
    /// or the chains do not close on the public key.
    InvalidSignature,
    /// An encoded value has the wrong length.
    InvalidLength,
}

/// `root ‖ P`, 41 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct VerifyingKey(pub(crate) [u8; PUBLIC_KEY_LEN]);

impl VerifyingKey {
    /// Verify a Winternitz or XMSS signature over an application-supplied 32-byte digest.
    /// The signature type selects the instance. Records no replay or usage state.
    pub fn verify(
        &self,
        digest: &[u8; MESSAGE_LEN],
        signature: &impl sealed::Signature,
    ) -> Result<(), Error> {
        signature.verify_digest(self, digest)
    }

    /// Length of the fixed encoding, in bytes.
    pub const BYTE_LEN: usize = PUBLIC_KEY_LEN;

    /// Decode a fixed-size encoding. Signature validity is checked by verification.
    #[inline(always)]
    pub const fn from_bytes(bytes: &[u8; PUBLIC_KEY_LEN]) -> Self {
        Self(*bytes)
    }

    /// Copy an encoding after checking its exact length.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_bytes(
            bytes.try_into().map_err(|_| Error::InvalidLength)?,
        ))
    }

    /// Borrow an encoding without copying after checking its exact length.
    pub fn ref_from_bytes(bytes: &[u8]) -> Result<&Self, Error> {
        let bytes: &[u8; PUBLIC_KEY_LEN] = bytes.try_into().map_err(|_| Error::InvalidLength)?;
        // SAFETY: transparent wrapper around this byte array; alignment is one.
        Ok(unsafe { &*(bytes as *const [u8; PUBLIC_KEY_LEN] as *const Self) })
    }

    /// Borrow the encoded bytes.
    pub const fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.0
    }
    /// Copy the encoded bytes.
    pub const fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.0
    }
    /// Consume this value and return its encoding.
    pub const fn into_bytes(self) -> [u8; PUBLIC_KEY_LEN] {
        self.0
    }
}

impl TryFrom<&[u8]> for VerifyingKey {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(bytes)
    }
}

impl AsRef<[u8]> for VerifyingKey {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl VerifyingKey {
    #[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
    fn new(node: &[u8; ELEMENT_LENGTH], parameter: &[u8]) -> Self {
        let mut pk = [0; PUBLIC_KEY_LEN];
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

/// Overwrite this buffer without dead-store elimination; other copies may remain.
#[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
fn wipe(bytes: &mut [u8]) {
    for byte in bytes {
        // SAFETY: `byte` is a valid, aligned, exclusively borrowed `u8`.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Construction 6: accept the 36 low-first nibbles iff their sum is `T`.
/// The message tweak alone uses a little-endian leaf index, as in hash-sig.
fn encode(
    salt: &[u8],
    parameter: &[u8],
    leaf: u32,
    message: &[u8; MESSAGE_LEN],
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

/// Construction 2 over `Trunc_n(H(P ‖ t ‖ x))` (§7.2.2).
/// One 48-byte buffer keeps each chain syscall to a single slice.
struct Chain([u8; Chain::VALUE + ELEMENT_LENGTH]);

impl Chain {
    const TWEAK: usize = PARAMETER_LEN;
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

    /// The step entering position `k` uses tweak `k` (Construction 2).
    /// Lemma 2 permits splitting the walk at the signed position `x_i`.
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

/// Construction 1 leaf: hash the 36 chain ends without copying them.
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

    /// `K` of Construction 3. Lemma 3 bounds failure by encoding error raised to `K`.
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
        message: &[u8; MESSAGE_LEN],
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

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::InvalidLength => "invalid encoded value or digest length",
            Self::InvalidSignature => "invalid signature",
        })
    }
}
impl core::error::Error for Error {}

// Closed dispatch for the two supported signature encodings and key-file tags.
mod sealed {
    pub trait Signature {
        fn verify_digest(
            &self,
            key: &super::VerifyingKey,
            digest: &[u8; super::MESSAGE_LEN],
        ) -> Result<(), super::Error>;
    }
    #[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
    pub trait OneTime {}
}
