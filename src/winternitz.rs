//! Construction 3 at L = 1: the tree is its leaf, the public key
//! `(leaf, P)`, no path.

use crate::{
    Chain, ELEMENTS_LENGTH, Error, MESSAGE_LENGTH, PublicKey, SALT_LENGTH, encode, leaf_hash,
};

/// `(ρ, σ_OTS)` of Construction 3.
pub const SIGNATURE_LENGTH: usize = SALT_LENGTH + ELEMENTS_LENGTH;

/// A one-time signature, 849 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature(pub [u8; SIGNATURE_LENGTH]);

impl Signature {
    /// Construction 3 Ver at L = 1. Constant work for an accepted
    /// signature: the message hash, 243 chain steps, the leaf.
    #[inline]
    pub fn verify(
        &self,
        public_key: &PublicKey,
        message: &[u8; MESSAGE_LENGTH],
    ) -> Result<(), Error> {
        let parameter = public_key.parameter();
        let x =
            encode(&self.0[..SALT_LENGTH], parameter, 0, message).ok_or(Error::InvalidSignature)?;
        let ends = Chain::new(parameter, 0).ends(&x, &self.0[SALT_LENGTH..]);
        if leaf_hash(parameter, 0, &ends) == public_key.node() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

/// One seed, one signature; sign through [`crate::Signer`]. Not `Clone`,
/// not `Debug`.
#[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
pub struct SecretKey {
    seed: [u8; 32],
    parameter: [u8; crate::PARAMETER_LENGTH],
}

#[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
impl Drop for SecretKey {
    fn drop(&mut self) {
        crate::wipe(&mut self.seed);
    }
}

#[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
impl SecretKey {
    /// `leaf ‖ P`.
    pub fn public_key(&self) -> PublicKey {
        PublicKey::new(
            &leaf_hash(
                &self.parameter,
                0,
                &crate::seed::ends(&self.seed, &self.parameter, 0),
            ),
            &self.parameter,
        )
    }
}

#[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
impl crate::OneTime for SecretKey {
    type Signature = Signature;
    const LEAVES: u32 = 1;
    const HEIGHT: u8 = 0;

    fn new(seed: [u8; 32], parameter: [u8; crate::PARAMETER_LENGTH]) -> Self {
        Self { seed, parameter }
    }

    fn public_key(&self) -> PublicKey {
        SecretKey::public_key(self)
    }

    /// Construction 3 Sig at the one leaf; `None` at any other. Records
    /// nothing.
    fn sign_at(&self, leaf: u32, message: &[u8; MESSAGE_LENGTH]) -> Option<Signature> {
        if leaf != 0 {
            return None;
        }
        let (salt, elements) = crate::seed::sign(&self.seed, &self.parameter, 0, message)?;
        let mut sig = Signature([0; SIGNATURE_LENGTH]);
        sig.0[..SALT_LENGTH].copy_from_slice(&salt);
        sig.0[SALT_LENGTH..].copy_from_slice(&elements);
        Some(sig)
    }
}
