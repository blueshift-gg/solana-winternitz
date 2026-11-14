//! Raw signing operations with caller-managed leaf usage, and the pieces
//! `solana-xmss` builds its tree signer from.
//!
//! Prefer [`crate::SigningKey`]. These raw keys permit signing the same leaf
//! repeatedly. The caller must enforce one attempt per leaf and persist its
//! allocation before releasing a signature; importing secrets does not
//! restore that usage state.
//!
//! `SecretKey::generate(fill)` is Construction 3 Gen; `sign_at(leaf, digest,
//! fill)` performs salt sampling and Sig. `sign_at_with_salt` only reproduces
//! a signature from an already accepted salt, as stored in a retry record.

use std::vec::Vec;

pub use crate::signer::SigningKey;
use crate::{
    Error, MESSAGE_LEN, PARAMETER_LEN, SIGNATURE_LEN, Signature, SigningError, VerifyingKey,
    primitives::{
        CHAINS, Chain, ELEMENT_LEN, ELEMENTS_LEN, Node, POSITIONS, SALT_LEN, encode, leaf_hash,
    },
};

/// `K` of Construction 3. Lemma 3 bounds failure by encoding error raised to `K`.
pub const MAX_TRIALS: u32 = 4096;

/// Raw Construction 3 operations behind a key file. These do not enforce one
/// use per leaf; sign through [`SigningKey`]. Never reuse chain starts across keys.
///
/// Implemented by this crate's one-time key and `solana-xmss`'s tree. The key
/// file stores `HEIGHT` as its instance tag, so `LEAVES` must be `2^HEIGHT`.
pub trait OneTime: Sized {
    /// The instance's signature type.
    type Signature;
    /// The instance's public key type.
    type VerifyingKey: Copy + Eq + core::fmt::Debug + AsRef<[u8]>;
    /// Leaves per key.
    const LEAVES: u32;
    /// Tree height; also the key-file instance tag.
    const HEIGHT: u8;
    /// Copy independently sampled chain starts in leaf-major, chain-major
    /// order (828 bytes per leaf), and the independently sampled `P`.
    /// Returns `Error::InvalidLength` for the wrong secret length. Records no usage state.
    fn from_secrets(secrets: &[u8], parameter: [u8; PARAMETER_LEN]) -> Result<Self, Error>;
    /// Raw secret bytes for persistence. These alone cannot restore usage state.
    fn secrets(&self) -> &[u8];
    /// The public parameter `P`.
    fn parameter(&self) -> &[u8; PARAMETER_LEN];
    /// The public key.
    fn verifying_key(&self) -> Self::VerifyingKey;
    /// Sign with an accepted salt. `None` for an invalid leaf or encoding.
    /// Never use a spent leaf with a different message or salt.
    fn sign_at_with_salt(
        &self,
        leaf: u32,
        message: &[u8; MESSAGE_LEN],
        salt: &[u8; SALT_LEN],
    ) -> Option<Self::Signature>;
}

/// Chain starts for one or more leaves and the public parameter `P`, wiped
/// on drop. Signs one leaf's chains; the caller owns leaf allocation.
pub struct Secrets {
    secrets: Vec<u8>,
    parameter: [u8; PARAMETER_LEN],
}

impl Drop for Secrets {
    fn drop(&mut self) {
        crate::wipe(&mut self.secrets);
    }
}

impl Secrets {
    /// Copy `leaves` leaves of chain starts (828 bytes each) and `P`.
    /// Returns `Error::InvalidLength` unless `secrets` holds exactly that many.
    pub fn from_bytes(
        leaves: u32,
        secrets: &[u8],
        parameter: [u8; PARAMETER_LEN],
    ) -> Result<Self, Error> {
        if leaves == 0 || secrets.len() != leaves as usize * ELEMENTS_LEN {
            return Err(Error::InvalidLength);
        }
        Ok(Self {
            secrets: secrets.to_vec(),
            parameter,
        })
    }

    /// The chain starts, for persistence.
    pub fn as_bytes(&self) -> &[u8] {
        &self.secrets
    }

    /// The public parameter `P`.
    pub fn parameter(&self) -> &[u8; PARAMETER_LEN] {
        &self.parameter
    }

    /// The number of leaves.
    pub fn leaves(&self) -> u32 {
        (self.secrets.len() / ELEMENTS_LEN) as u32
    }

    fn start(&self, leaf: u32, i: usize) -> &[u8; ELEMENT_LEN] {
        let offset = leaf as usize * ELEMENTS_LEN + i * ELEMENT_LEN;
        self.secrets[offset..offset + ELEMENT_LEN]
            .try_into()
            .unwrap()
    }

    /// The public leaf of `leaf`, from its chain ends.
    ///
    /// # Panics
    ///
    /// If `leaf` is out of range.
    pub fn leaf(&self, leaf: u32) -> Node {
        assert!(leaf < self.leaves(), "leaf out of range");
        let mut chain = Chain::new(&self.parameter, leaf);
        let ends: [Node; CHAINS] =
            core::array::from_fn(|i| chain.walk(i as u8, 0, POSITIONS - 1, self.start(leaf, i)));
        leaf_hash(&self.parameter, leaf, &ends)
    }

    /// The chain elements of a one-time signature at `leaf` with an accepted
    /// salt. `None` for an out-of-range leaf or a salt that misses the target sum.
    /// Never use a spent leaf with a different message or salt.
    pub fn sign(
        &self,
        leaf: u32,
        message: &[u8; MESSAGE_LEN],
        salt: &[u8; SALT_LEN],
    ) -> Option<[u8; ELEMENTS_LEN]> {
        if leaf >= self.leaves() {
            return None;
        }
        let x = encode(salt, &self.parameter, leaf, message)?;
        let mut chain = Chain::new(&self.parameter, leaf);
        let mut elements = [0; ELEMENTS_LEN];
        for (i, slot) in elements
            .as_chunks_mut::<ELEMENT_LEN>()
            .0
            .iter_mut()
            .enumerate()
        {
            *slot = chain.walk(i as u8, 0, x[i], self.start(leaf, i));
        }
        Some(elements)
    }
}

/// Construction 3 key generation and signing with caller-managed leaf allocation.
/// Use [`crate::SigningKey`] for durable usage state.
pub struct SecretKey(Secrets);

impl SecretKey {
    /// Generate independently sampled chain starts and a public parameter without a file.
    /// The callback must fill every byte with CSPRNG output or return an error;
    /// requests are at most 828 bytes. The caller owns leaf allocation and persistence.
    pub fn generate(
        fill: impl FnMut(&mut [u8]) -> Result<(), SigningError>,
    ) -> Result<Self, SigningError> {
        generate(fill)
    }

    /// Sample salts and sign at the caller-reserved leaf. Records no usage state.
    /// Reserve and persist this leaf before calling; a sampling failure still spends
    /// the attempt. The callback must fill every byte with fresh CSPRNG output or fail.
    pub fn sign_at(
        &self,
        leaf: u32,
        message: &[u8; MESSAGE_LEN],
        fill: impl FnMut(&mut [u8]) -> Result<(), SigningError>,
    ) -> Result<Signature, SigningError> {
        sign_at(self, leaf, message, fill)
    }

    /// `leaf ‖ P`.
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey::new(&self.0.leaf(0), self.0.parameter())
    }
}

impl OneTime for SecretKey {
    type Signature = Signature;
    type VerifyingKey = VerifyingKey;
    const LEAVES: u32 = 1;
    const HEIGHT: u8 = 0;

    fn from_secrets(secrets: &[u8], parameter: [u8; PARAMETER_LEN]) -> Result<Self, Error> {
        Secrets::from_bytes(Self::LEAVES, secrets, parameter).map(Self)
    }

    fn secrets(&self) -> &[u8] {
        self.0.as_bytes()
    }

    fn parameter(&self) -> &[u8; PARAMETER_LEN] {
        self.0.parameter()
    }

    fn verifying_key(&self) -> VerifyingKey {
        SecretKey::verifying_key(self)
    }

    fn sign_at_with_salt(
        &self,
        leaf: u32,
        message: &[u8; MESSAGE_LEN],
        salt: &[u8; SALT_LEN],
    ) -> Option<Signature> {
        let elements = self.0.sign(leaf, message, salt)?;
        let mut sig = Signature([0; SIGNATURE_LEN]);
        sig.0[..SALT_LEN].copy_from_slice(salt);
        sig.0[SALT_LEN..].copy_from_slice(&elements);
        Some(sig)
    }
}

/// Construction 3 Gen through bounded CSPRNG requests, one leaf of chain
/// starts at a time, then `P`. Wipes the temporary secrets on every exit.
pub fn generate<K: OneTime>(
    mut fill: impl FnMut(&mut [u8]) -> Result<(), SigningError>,
) -> Result<K, SigningError> {
    let mut secrets = std::vec![0; K::LEAVES as usize * ELEMENTS_LEN];
    let result = (|| {
        // Bounded requests also fit browser CSPRNG limits in the matching TS API.
        for leaf in secrets.chunks_mut(ELEMENTS_LEN) {
            fill(leaf)?;
        }
        let mut parameter = [0; PARAMETER_LEN];
        fill(&mut parameter)?;
        K::from_secrets(&secrets, parameter).map_err(|_: Error| SigningError::Corrupt)
    })();
    crate::wipe(&mut secrets);
    result
}

/// Draw salts until one meets the target sum, at most [`MAX_TRIALS`] times.
pub fn sample_salt(
    parameter: &[u8; PARAMETER_LEN],
    leaf: u32,
    message: &[u8; MESSAGE_LEN],
    mut fill: impl FnMut(&mut [u8]) -> Result<(), SigningError>,
) -> Result<[u8; SALT_LEN], SigningError> {
    let mut salt = [0; SALT_LEN];
    for _ in 0..MAX_TRIALS {
        fill(&mut salt)?;
        if encode(&salt, parameter, leaf, message).is_some() {
            return Ok(salt);
        }
    }
    Err(SigningError::SaltsExhausted)
}

/// Sample a salt and sign at a caller-reserved leaf. Records no usage state.
pub fn sign_at<K: OneTime>(
    key: &K,
    leaf: u32,
    message: &[u8; MESSAGE_LEN],
    fill: impl FnMut(&mut [u8]) -> Result<(), SigningError>,
) -> Result<K::Signature, SigningError> {
    if leaf >= K::LEAVES {
        return Err(SigningError::InvalidLeaf);
    }
    let salt = sample_salt(key.parameter(), leaf, message, fill)?;
    key.sign_at_with_salt(leaf, message, &salt)
        .ok_or(SigningError::Corrupt)
}
