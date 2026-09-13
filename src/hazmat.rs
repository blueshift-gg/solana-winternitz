//! Raw signing operations with caller-managed leaf usage.
//!
//! Prefer [`crate::xmss::SigningKey`] or [`crate::winternitz::SigningKey`].
//! These raw keys permit signing the same leaf repeatedly. The caller must
//! enforce one attempt per leaf and persist its allocation before releasing
//! a signature; importing secrets does not restore that usage state.
//!
//! `SecretKey::generate(fill)` is Construction 3 Gen; `sign_at(leaf, digest,
//! fill)` performs salt sampling and Sig. `sign_at_with_salt` only reproduces
//! a signature from an already accepted salt, as stored in a retry record.

pub use crate::signer::OneTime;

/// Raw one-leaf Winternitz secret material and manual signing.
pub mod winternitz {
    pub use crate::winternitz::raw::SecretKey;
}

/// Raw XMSS secret material and manual leaf signing.
pub mod xmss {
    pub use crate::xmss::raw::SecretKey;
}

use crate::{ELEMENTS_LENGTH, Error, MESSAGE_LEN, PARAMETER_LEN, SALT_LENGTH, SigningError};

pub(crate) fn generate<K: OneTime>(
    mut fill: impl FnMut(&mut [u8]) -> Result<(), SigningError>,
) -> Result<K, SigningError> {
    let mut secrets = std::vec![0; K::LEAVES as usize * ELEMENTS_LENGTH];
    let result = (|| {
        // Bounded requests also fit browser CSPRNG limits in the matching TS API.
        for leaf in secrets.chunks_mut(ELEMENTS_LENGTH) {
            fill(leaf)?;
        }
        let mut parameter = [0; PARAMETER_LEN];
        fill(&mut parameter)?;
        K::from_secrets(&secrets, parameter).map_err(|_: Error| SigningError::Corrupt)
    })();
    crate::wipe(&mut secrets);
    result
}

pub(crate) fn sample_salt(
    parameter: &[u8],
    leaf: u32,
    message: &[u8; MESSAGE_LEN],
    mut fill: impl FnMut(&mut [u8]) -> Result<(), SigningError>,
) -> Result<[u8; SALT_LENGTH], SigningError> {
    let mut salt = [0; SALT_LENGTH];
    for _ in 0..crate::signing::MAX_TRIALS {
        fill(&mut salt)?;
        if crate::encode(&salt, parameter, leaf, message).is_some() {
            return Ok(salt);
        }
    }
    Err(SigningError::SaltsExhausted)
}

pub(crate) fn sign_at<K: OneTime>(
    key: &K,
    leaf: u32,
    message: &[u8; MESSAGE_LEN],
    fill: impl FnMut(&mut [u8]) -> Result<(), SigningError>,
) -> Result<K::Signature, SigningError> {
    if leaf >= K::LEAVES {
        return Err(SigningError::InvalidLeaf);
    }
    let salt = sample_salt(key.verifying_key().parameter(), leaf, message, fill)?;
    key.sign_at_with_salt(leaf, message, &salt)
        .ok_or(SigningError::Corrupt)
}
