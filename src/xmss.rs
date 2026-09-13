//! Construction 3 with 256 leaves. Verification is stateless; the application
//! must enforce replay protection on accepted leaf indices.

use crate::{
    Chain, ELEMENT_LENGTH, ELEMENTS_LENGTH, Error, MESSAGE_LEN, SALT_LENGTH, VerifyingKey, encode,
    leaf_hash, node,
};

/// Tree height `h`.
pub const HEIGHT: usize = 8;
/// Maximum signing attempts per key.
pub const LEAVES: u32 = 1 << HEIGHT;
/// `(ep, ρ, σ_OTS, path_ep)` of Construction 3, `ep` as u32 big-endian.
pub const SIGNATURE_LEN: usize = 4 + SALT_LENGTH + ELEMENTS_LENGTH + HEIGHT * ELEMENT_LENGTH;

const SALT: usize = 4;
const ELEMENTS: usize = SALT + SALT_LENGTH;
const PATH: usize = ELEMENTS + ELEMENTS_LENGTH;

/// A signature under one leaf, 1,037 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Signature(pub(crate) [u8; SIGNATURE_LEN]);

impl Signature {
    /// Length of the fixed encoding, in bytes.
    pub const BYTE_LEN: usize = SIGNATURE_LEN;

    /// Decode a fixed-size encoding. Signature validity is checked by verification.
    #[inline(always)]
    pub const fn from_bytes(bytes: &[u8; SIGNATURE_LEN]) -> Self {
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
        let bytes: &[u8; SIGNATURE_LEN] = bytes.try_into().map_err(|_| Error::InvalidLength)?;
        // SAFETY: transparent wrapper around this byte array; alignment is one.
        Ok(unsafe { &*(bytes as *const [u8; SIGNATURE_LEN] as *const Self) })
    }

    /// Borrow the encoded bytes.
    pub const fn as_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        &self.0
    }
    /// Copy the encoded bytes.
    pub const fn to_bytes(&self) -> [u8; SIGNATURE_LEN] {
        self.0
    }
    /// Consume this value and return its encoding.
    pub const fn into_bytes(self) -> [u8; SIGNATURE_LEN] {
        self.0
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(bytes)
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Signature {
    /// The unverified leaf index (the paper's epoch), unrelated to Solana epochs.
    #[inline(always)]
    pub fn leaf(&self) -> u32 {
        u32::from_be_bytes(self.0[..SALT].try_into().unwrap())
    }

    /// Verify the chains and authentication path (Construction 3, Ver).
    /// Records no usage state.
    #[inline]
    pub(crate) fn verify(
        &self,
        verifying_key: &VerifyingKey,
        message: &[u8; MESSAGE_LEN],
    ) -> Result<(), Error> {
        let leaf = self.leaf();
        if leaf >= LEAVES {
            return Err(Error::InvalidSignature);
        }
        let parameter = verifying_key.parameter();
        let x = encode(&self.0[SALT..ELEMENTS], parameter, leaf, message)
            .ok_or(Error::InvalidSignature)?;
        let ends = Chain::new(parameter, leaf).ends(&x, &self.0[ELEMENTS..PATH]);
        let mut current = leaf_hash(parameter, leaf, &ends);
        for (level, sibling) in
            (1..=HEIGHT as u8).zip(self.0[PATH..].as_chunks::<ELEMENT_LENGTH>().0)
        {
            let index = leaf >> level;
            current = if (leaf >> (level - 1)) & 1 == 0 {
                node(parameter, level, index, &current, sibling)
            } else {
                node(parameter, level, index, sibling, &current)
            };
        }
        if current == verifying_key.node() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

impl From<Signature> for [u8; SIGNATURE_LEN] {
    fn from(signature: Signature) -> Self {
        signature.into_bytes()
    }
}

impl crate::sealed::Signature for Signature {
    #[inline]
    fn verify_digest(&self, key: &VerifyingKey, digest: &[u8; MESSAGE_LEN]) -> Result<(), Error> {
        self.verify(key, digest)
    }
}

/// Definition 8 signing state made durable in an exclusively locked key file.
#[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
pub type SigningKey = crate::SigningKey<crate::hazmat::xmss::SecretKey>;

#[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
pub(crate) mod raw {
    use super::*;

    /// Construction 3 key generation and signing with caller-managed leaf allocation.
    /// Caches the Merkle tree; use [`crate::xmss::SigningKey`] for durable usage state.
    pub struct SecretKey {
        secrets: std::vec::Vec<u8>,
        parameter: [u8; crate::PARAMETER_LEN],
        /// Level-major: leaves first, root last.
        nodes: [[u8; ELEMENT_LENGTH]; 2 * LEAVES as usize - 1],
    }

    impl Drop for SecretKey {
        fn drop(&mut self) {
            crate::wipe(&mut self.secrets);
        }
    }

    impl SecretKey {
        /// Generate independently sampled chain starts and a public parameter without a file.
        /// The callback must fill every byte with CSPRNG output or return an error;
        /// requests are at most 828 bytes. The caller owns leaf allocation and persistence.
        pub fn generate(
            fill: impl FnMut(&mut [u8]) -> Result<(), crate::SigningError>,
        ) -> Result<Self, crate::SigningError> {
            crate::hazmat::generate(fill)
        }

        /// Sample salts and sign at the caller-reserved leaf. Records no usage state.
        /// Reserve and persist this leaf before calling; a sampling failure still spends
        /// the attempt. The callback must fill every byte with fresh CSPRNG output or fail.
        pub fn sign_at(
            &self,
            leaf: u32,
            message: &[u8; MESSAGE_LEN],
            fill: impl FnMut(&mut [u8]) -> Result<(), crate::SigningError>,
        ) -> Result<Signature, crate::SigningError> {
            crate::hazmat::sign_at(self, leaf, message, fill)
        }

        /// Where level `l` starts in `nodes`.
        const fn level(l: usize) -> usize {
            2 * LEAVES as usize - (2 << (HEIGHT - l))
        }

        /// `root ‖ P`.
        pub fn verifying_key(&self) -> VerifyingKey {
            VerifyingKey::new(&self.nodes[Self::level(HEIGHT)], &self.parameter)
        }
    }

    impl crate::hazmat::OneTime for SecretKey {
        type Signature = Signature;
        const LEAVES: u32 = 1 << HEIGHT;
        const HEIGHT: u8 = HEIGHT as u8;

        fn from_secrets(
            secrets: &[u8],
            parameter: [u8; crate::PARAMETER_LEN],
        ) -> Result<Self, Error> {
            if secrets.len() != Self::LEAVES as usize * ELEMENTS_LENGTH {
                return Err(Error::InvalidLength);
            }
            let mut nodes = [[0u8; ELEMENT_LENGTH]; 2 * LEAVES as usize - 1];
            for leaf in 0..LEAVES {
                nodes[leaf as usize] = leaf_hash(
                    &parameter,
                    leaf,
                    &crate::signing::ends(secrets, &parameter, leaf),
                );
            }
            for l in 1..=HEIGHT {
                for i in 0..(LEAVES as usize >> l) {
                    let child = Self::level(l - 1) + 2 * i;
                    nodes[Self::level(l) + i] = node(
                        &parameter,
                        l as u8,
                        i as u32,
                        &nodes[child],
                        &nodes[child + 1],
                    );
                }
            }
            Ok(Self {
                secrets: secrets.to_vec(),
                parameter,
                nodes,
            })
        }

        fn secrets(&self) -> &[u8] {
            &self.secrets
        }

        fn verifying_key(&self) -> VerifyingKey {
            SecretKey::verifying_key(self)
        }

        fn sign_at_with_salt(
            &self,
            leaf: u32,
            message: &[u8; MESSAGE_LEN],
            salt: &[u8; SALT_LENGTH],
        ) -> Option<Signature> {
            if leaf >= LEAVES {
                return None;
            }
            let elements =
                crate::signing::sign(&self.secrets, &self.parameter, leaf, message, salt)?;
            let mut sig = Signature([0; SIGNATURE_LEN]);
            sig.0[..SALT].copy_from_slice(&leaf.to_be_bytes());
            sig.0[SALT..ELEMENTS].copy_from_slice(salt);
            sig.0[ELEMENTS..PATH].copy_from_slice(&elements);
            for (l, slot) in sig.0[PATH..]
                .as_chunks_mut::<ELEMENT_LENGTH>()
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

    impl crate::sealed::OneTime for SecretKey {}
}
