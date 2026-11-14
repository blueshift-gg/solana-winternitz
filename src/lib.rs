#![doc = include_str!("../README.md")]
#![no_std]
#![deny(missing_docs, clippy::undocumented_unsafe_blocks)]

mod hash;
pub mod primitives;
mod syscalls;

#[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
extern crate std;
#[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
pub mod hazmat;
#[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
mod signer;
#[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
pub use signer::SigningError;

#[cfg(test)]
mod tests;

use primitives::{ELEMENT_LEN, ELEMENTS_LEN, SALT_LEN};

/// `P`: eq. (16) needs ≥ 142 bits.
pub const PARAMETER_LEN: usize = 18;
/// `pk = (leaf, P)` of Construction 3 with one leaf.
pub const PUBLIC_KEY_LEN: usize = ELEMENT_LEN + PARAMETER_LEN;
/// Application-supplied digest length in bytes (Remark 1).
pub const MESSAGE_LEN: usize = 32;
/// `(ρ, σ_OTS)` of Construction 3.
pub const SIGNATURE_LEN: usize = SALT_LEN + ELEMENTS_LEN;

/// Definition 8 signing state made durable in an exclusively locked key file.
#[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
pub type SigningKey = hazmat::SigningKey<hazmat::SecretKey>;

/// Signature verification failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The salted digest misses the target sum, the leaf is out of range,
    /// or the chains do not close on the public key.
    InvalidSignature,
    /// An encoded value has the wrong length.
    InvalidLength,
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

/// Fixed-size byte encodings: `from_bytes`, `from_slice`, `ref_from_bytes`,
/// `as_bytes`, `to_bytes`, `into_bytes`, `TryFrom<&[u8]>` and `AsRef<[u8]>`.
/// Exported for `solana-xmss`; not part of the stable API.
#[doc(hidden)]
#[macro_export]
macro_rules! fixed_bytes {
    ($name:ident, $len:expr, $error:path) => {
        impl $name {
            /// Length of the fixed encoding, in bytes.
            pub const BYTE_LEN: usize = $len;

            /// Decode a fixed-size encoding. Signature validity is checked by verification.
            #[inline(always)]
            pub const fn from_bytes(bytes: &[u8; $len]) -> Self {
                Self(*bytes)
            }

            /// Copy an encoding after checking its exact length.
            pub fn from_slice(bytes: &[u8]) -> Result<Self, $error> {
                Ok(Self::from_bytes(
                    bytes.try_into().map_err(|_| <$error>::InvalidLength)?,
                ))
            }

            /// Borrow an encoding without copying after checking its exact length.
            pub fn ref_from_bytes(bytes: &[u8]) -> Result<&Self, $error> {
                let bytes: &[u8; $len] = bytes.try_into().map_err(|_| <$error>::InvalidLength)?;
                // SAFETY: transparent wrapper around this byte array; alignment is one.
                Ok(unsafe { &*(bytes as *const [u8; $len] as *const Self) })
            }

            /// Borrow the encoded bytes.
            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
            /// Copy the encoded bytes.
            pub const fn to_bytes(&self) -> [u8; $len] {
                self.0
            }
            /// Consume this value and return its encoding.
            pub const fn into_bytes(self) -> [u8; $len] {
                self.0
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = $error;
            fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
                Self::from_slice(bytes)
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                self.as_bytes()
            }
        }

        impl From<$name> for [u8; $len] {
            fn from(value: $name) -> Self {
                value.into_bytes()
            }
        }
    };
}

/// `leaf ‖ P`, 41 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct VerifyingKey(pub(crate) [u8; PUBLIC_KEY_LEN]);

fixed_bytes!(VerifyingKey, PUBLIC_KEY_LEN, Error);

impl VerifyingKey {
    /// Verify a one-time signature over an application-supplied 32-byte digest
    /// (Construction 3, Ver, at leaf zero). Records no usage state.
    #[inline]
    pub fn verify(&self, digest: &[u8; MESSAGE_LEN], signature: &Signature) -> Result<(), Error> {
        let (salt, elements) = signature.0.split_first_chunk::<SALT_LEN>().unwrap();
        let leaf = primitives::leaf(
            self.parameter(),
            0,
            salt,
            elements.try_into().unwrap(),
            digest,
        )
        .ok_or(Error::InvalidSignature)?;
        if leaf == self.0[..ELEMENT_LEN] {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }

    #[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
    fn new(leaf: &primitives::Node, parameter: &[u8; PARAMETER_LEN]) -> Self {
        let mut pk = [0; PUBLIC_KEY_LEN];
        pk[..ELEMENT_LEN].copy_from_slice(leaf);
        pk[ELEMENT_LEN..].copy_from_slice(parameter);
        Self(pk)
    }

    /// The public parameter `P`.
    #[inline(always)]
    pub fn parameter(&self) -> &[u8; PARAMETER_LEN] {
        self.0[ELEMENT_LEN..].try_into().unwrap()
    }
}

/// A one-time signature, 849 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Signature(pub(crate) [u8; SIGNATURE_LEN]);

fixed_bytes!(Signature, SIGNATURE_LEN, Error);

/// Overwrite this buffer without dead-store elimination; other copies may remain.
#[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
fn wipe(bytes: &mut [u8]) {
    for byte in bytes {
        // SAFETY: `byte` is a valid, aligned, exclusively borrowed `u8`.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}
