//! Construction 3 at L = 1: the tree is its leaf, the public key
//! `(leaf, P)`, no path.

use crate::{Chain, ELEMENTS_LENGTH, Error, PublicKey, SALT_LENGTH, encode, leaf_hash};

/// `(ρ, σ_OTS)` of Construction 3.
pub const SIGNATURE_LENGTH: usize = SALT_LENGTH + ELEMENTS_LENGTH;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature(pub [u8; SIGNATURE_LENGTH]);

impl Signature {
    /// Construction 3 Ver at L = 1. Constant work for an accepted
    /// signature: HMAC, 200 chain steps, leaf, ~29k CU.
    #[inline]
    pub fn verify(&self, public_key: &PublicKey, message: &[u8]) -> Result<(), Error> {
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

/// In every derivation, so this key is not [`crate::xmss`] leaf 0.
#[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
const HEIGHT: u8 = 0;

/// One seed, one signature; sign through [`crate::Signer`]. Not `Clone`,
/// not `Debug`.
#[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
pub struct SecretKey(pub [u8; 32]);

#[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
impl SecretKey {
    pub fn public_key(&self) -> PublicKey {
        let parameter = crate::seed::parameter(&self.0, HEIGHT);
        PublicKey::new(
            &leaf_hash(
                &parameter,
                0,
                &crate::seed::ends(&self.0, &parameter, HEIGHT, 0),
            ),
            &parameter,
        )
    }
}

#[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
impl crate::OneTime for SecretKey {
    type Signature = Signature;
    const LEAVES: u32 = 1;
    const HEIGHT: u8 = HEIGHT;

    fn from_seed(seed: [u8; 32]) -> Self {
        Self(seed)
    }

    fn public_key(&self) -> PublicKey {
        SecretKey::public_key(self)
    }

    /// Construction 3 Sig at the one leaf. Records nothing.
    fn sign_at(&self, _leaf: u32, message: &[u8]) -> Option<Signature> {
        let parameter = crate::seed::parameter(&self.0, HEIGHT);
        let (salt, elements) = crate::seed::sign(&self.0, &parameter, HEIGHT, 0, message)?;
        let mut sig = Signature([0; SIGNATURE_LENGTH]);
        sig.0[..SALT_LENGTH].copy_from_slice(&salt);
        sig.0[SALT_LENGTH..].copy_from_slice(&elements);
        Some(sig)
    }
}
