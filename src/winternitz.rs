//! Construction 3 specialized to one leaf and an empty authentication path.

use crate::{
    Chain, ELEMENTS_LENGTH, Error, MESSAGE_LEN, SALT_LENGTH, VerifyingKey, encode, leaf_hash,
};

/// `(ρ, σ_OTS)` of Construction 3.
pub const SIGNATURE_LEN: usize = SALT_LENGTH + ELEMENTS_LENGTH;

/// A one-time signature, 849 bytes.
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
    /// Verify at leaf zero (Construction 3, Ver). Records no usage state.
    #[inline]
    pub(crate) fn verify(
        &self,
        verifying_key: &VerifyingKey,
        message: &[u8; MESSAGE_LEN],
    ) -> Result<(), Error> {
        let parameter = verifying_key.parameter();
        let x =
            encode(&self.0[..SALT_LENGTH], parameter, 0, message).ok_or(Error::InvalidSignature)?;
        let ends = Chain::new(parameter, 0).ends(&x, &self.0[SALT_LENGTH..]);
        if leaf_hash(parameter, 0, &ends) == verifying_key.node() {
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
pub type SigningKey = crate::SigningKey<crate::hazmat::winternitz::SecretKey>;

#[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
pub(crate) mod raw {
    use super::*;

    /// Construction 3 key generation and signing with caller-managed leaf allocation.
    /// Use [`crate::winternitz::SigningKey`] for durable usage state.
    pub struct SecretKey {
        secrets: std::vec::Vec<u8>,
        parameter: [u8; crate::PARAMETER_LEN],
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

        /// `leaf ‖ P`.
        pub fn verifying_key(&self) -> VerifyingKey {
            VerifyingKey::new(
                &leaf_hash(
                    &self.parameter,
                    0,
                    &crate::signing::ends(&self.secrets, &self.parameter, 0),
                ),
                &self.parameter,
            )
        }
    }

    impl crate::hazmat::OneTime for SecretKey {
        type Signature = Signature;
        const LEAVES: u32 = 1;
        const HEIGHT: u8 = 0;

        fn from_secrets(
            secrets: &[u8],
            parameter: [u8; crate::PARAMETER_LEN],
        ) -> Result<Self, Error> {
            if secrets.len() != Self::LEAVES as usize * ELEMENTS_LENGTH {
                return Err(Error::InvalidLength);
            }
            Ok(Self {
                secrets: secrets.to_vec(),
                parameter,
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
            if leaf != 0 {
                return None;
            }
            let elements = crate::signing::sign(&self.secrets, &self.parameter, 0, message, salt)?;
            let mut sig = Signature([0; SIGNATURE_LEN]);
            sig.0[..SALT_LENGTH].copy_from_slice(salt);
            sig.0[SALT_LENGTH..].copy_from_slice(&elements);
            Some(sig)
        }
    }

    impl crate::sealed::OneTime for SecretKey {}
}
