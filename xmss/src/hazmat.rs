//! Raw signing with caller-managed leaf usage.
//!
//! Prefer [`crate::SigningKey`]. A raw key permits signing the same leaf
//! repeatedly. The caller must enforce one attempt per leaf and persist its
//! allocation before releasing a signature; importing secrets does not
//! restore that usage state.
//!
//! `SecretKey::generate(fill)` is Construction 3 Gen; `sign_at(leaf, digest,
//! fill)` performs salt sampling and Sig. `sign_at_with_salt` only reproduces
//! a signature from an already accepted salt, as stored in a retry record.

pub use solana_winternitz::hazmat::OneTime;
use solana_winternitz::{
    hazmat::{self, Secrets},
    primitives::{self, ELEMENT_LEN, Node, SALT_LEN},
};

use crate::{
    ELEMENTS, Error, HEIGHT, LEAVES, MESSAGE_LEN, PARAMETER_LEN, PATH, SALT, SIGNATURE_LEN,
    Signature, SigningError, VerifyingKey,
};

/// Construction 3 key generation and signing with caller-managed leaf allocation.
/// Caches the Merkle tree; use [`crate::SigningKey`] for durable usage state.
pub struct SecretKey {
    secrets: Secrets,
    /// Level-major: leaves first, root last.
    nodes: [Node; 2 * LEAVES as usize - 1],
}

impl SecretKey {
    /// Generate independently sampled chain starts and a public parameter without a file.
    /// The callback must fill every byte with CSPRNG output or return an error;
    /// requests are at most 828 bytes. The caller owns leaf allocation and persistence.
    pub fn generate(
        fill: impl FnMut(&mut [u8]) -> Result<(), SigningError>,
    ) -> Result<Self, SigningError> {
        hazmat::generate(fill)
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
        hazmat::sign_at(self, leaf, message, fill)
    }

    /// Where level `l` starts in `nodes`.
    const fn level(l: usize) -> usize {
        2 * LEAVES as usize - (2 << (HEIGHT - l))
    }

    /// `root ‖ P`.
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey::new(&self.nodes[Self::level(HEIGHT)], self.secrets.parameter())
    }
}

impl OneTime for SecretKey {
    type Signature = Signature;
    type VerifyingKey = VerifyingKey;
    const LEAVES: u32 = LEAVES;
    const HEIGHT: u8 = HEIGHT as u8;

    fn from_secrets(secrets: &[u8], parameter: [u8; PARAMETER_LEN]) -> Result<Self, Error> {
        let secrets = Secrets::from_bytes(LEAVES, secrets, parameter)?;
        let mut nodes = [[0u8; ELEMENT_LEN]; 2 * LEAVES as usize - 1];
        for leaf in 0..LEAVES {
            nodes[leaf as usize] = secrets.leaf(leaf);
        }
        for l in 1..=HEIGHT {
            for i in 0..(LEAVES as usize >> l) {
                let child = Self::level(l - 1) + 2 * i;
                nodes[Self::level(l) + i] = primitives::node(
                    &parameter,
                    l as u8,
                    i as u32,
                    &nodes[child],
                    &nodes[child + 1],
                );
            }
        }
        Ok(Self { secrets, nodes })
    }

    fn secrets(&self) -> &[u8] {
        self.secrets.as_bytes()
    }

    fn parameter(&self) -> &[u8; PARAMETER_LEN] {
        self.secrets.parameter()
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
        let elements = self.secrets.sign(leaf, message, salt)?;
        let mut sig = Signature([0; SIGNATURE_LEN]);
        sig.0[..SALT].copy_from_slice(&leaf.to_be_bytes());
        sig.0[SALT..ELEMENTS].copy_from_slice(salt);
        sig.0[ELEMENTS..PATH].copy_from_slice(&elements);
        for (l, slot) in sig.0[PATH..]
            .as_chunks_mut::<ELEMENT_LEN>()
            .0
            .iter_mut()
            .enumerate()
        {
            let sibling = ((leaf as usize) >> l) ^ 1;
            *slot = self.nodes[Self::level(l) + sibling];
        }
        Some(sig)
    }
}
