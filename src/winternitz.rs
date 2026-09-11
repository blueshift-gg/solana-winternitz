//! Lifetime 1: one key, one signature. The public key is `leaf ‖ P`.
//! Signing reveals chain intermediates: the program that verifies must
//! retire the key in the same transaction.

use crate::{Chain, ELEMENTS_LENGTH, Error, PublicKey, SALT_LENGTH, encode, leaf};

/// `ρ ‖ σ_0 ‖ … ‖ σ_34`.
pub const SIGNATURE_LENGTH: usize = SALT_LENGTH + ELEMENTS_LENGTH;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature(pub [u8; SIGNATURE_LENGTH]);

impl Signature {
    /// One message hash, 200 chain hashes of 55 bytes, one leaf hash of
    /// 870 bytes: ~29k CU, the same for every accepted signature. A wrong
    /// message rejects after the first hash; a wrong key after all of them.
    #[inline]
    pub fn verify(&self, public_key: &PublicKey, message: &[u8]) -> Result<(), Error> {
        let parameter = public_key.parameter();
        let x =
            encode(&self.0[..SALT_LENGTH], parameter, 0, message).ok_or(Error::InvalidSignature)?;
        let ends = Chain::new(parameter, 0).ends(&x, &self.0[SALT_LENGTH..]);
        if leaf(parameter, 0, &ends) == public_key.node() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

/// Signs exactly one message: `sign` consumes it. Not `Clone`, not `Debug`.
#[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
pub struct SecretKey(pub [u8; 32]);

#[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
impl SecretKey {
    pub fn public_key(&self) -> PublicKey {
        let parameter = crate::seed::parameter(&self.0);
        PublicKey::new(
            &leaf(&parameter, 0, &crate::seed::ends(&self.0, &parameter, 0)),
            &parameter,
        )
    }

    /// Deterministic in seed and message. `None` only if 2^16 salts all miss
    /// the target sum.
    pub fn sign(self, message: &[u8]) -> Option<Signature> {
        let parameter = crate::seed::parameter(&self.0);
        let (salt, elements) = crate::seed::sign(&self.0, &parameter, 0, message)?;
        let mut sig = Signature([0; SIGNATURE_LENGTH]);
        sig.0[..SALT_LENGTH].copy_from_slice(&salt);
        sig.0[SALT_LENGTH..].copy_from_slice(&elements);
        Some(sig)
    }
}
