#![doc = include_str!("../README.md")]
#![no_std]
#![deny(missing_docs, clippy::undocumented_unsafe_blocks)]

use solana_winternitz::primitives::{self, ELEMENT_LEN, ELEMENTS_LEN, SALT_LEN};

pub use solana_winternitz::{Error, MESSAGE_LEN, PARAMETER_LEN};

#[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
extern crate std;
#[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
pub mod hazmat;
#[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
pub use solana_winternitz::SigningError;

#[cfg(test)]
mod tests;

/// Tree height `h`.
pub const HEIGHT: usize = 8;
/// Maximum signing attempts per key.
pub const LEAVES: u32 = 1 << HEIGHT;
/// `pk = (root, P)` of Construction 3.
pub const PUBLIC_KEY_LEN: usize = ELEMENT_LEN + PARAMETER_LEN;
/// `(ep, ρ, σ_OTS, path_ep)` of Construction 3, `ep` as u32 big-endian.
pub const SIGNATURE_LEN: usize = 4 + SALT_LEN + ELEMENTS_LEN + HEIGHT * ELEMENT_LEN;

const SALT: usize = 4;
const ELEMENTS: usize = SALT + SALT_LEN;
const PATH: usize = ELEMENTS + ELEMENTS_LEN;

/// Definition 8 signing state made durable in an exclusively locked key file.
#[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
pub type SigningKey = solana_winternitz::hazmat::SigningKey<hazmat::SecretKey>;

/// `root ‖ P`, 41 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct VerifyingKey(pub(crate) [u8; PUBLIC_KEY_LEN]);

solana_winternitz::fixed_bytes!(VerifyingKey, PUBLIC_KEY_LEN, Error);

impl VerifyingKey {
    /// Verify the chains and authentication path over an application-supplied
    /// 32-byte digest (Construction 3, Ver). Stateless: the application must
    /// refuse leaves it has already accepted.
    #[inline]
    pub fn verify(&self, digest: &[u8; MESSAGE_LEN], signature: &Signature) -> Result<(), Error> {
        let leaf = signature.leaf();
        if leaf >= LEAVES {
            return Err(Error::InvalidSignature);
        }
        let parameter = self.parameter();
        let mut current = primitives::leaf(
            parameter,
            leaf,
            signature.0[SALT..ELEMENTS].try_into().unwrap(),
            signature.0[ELEMENTS..PATH].try_into().unwrap(),
            digest,
        )
        .ok_or(Error::InvalidSignature)?;
        for (level, sibling) in
            (1..=HEIGHT as u8).zip(signature.0[PATH..].as_chunks::<ELEMENT_LEN>().0)
        {
            let index = leaf >> level;
            current = if (leaf >> (level - 1)) & 1 == 0 {
                primitives::node(parameter, level, index, &current, sibling)
            } else {
                primitives::node(parameter, level, index, sibling, &current)
            };
        }
        if current == self.0[..ELEMENT_LEN] {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }

    #[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
    fn new(root: &primitives::Node, parameter: &[u8; PARAMETER_LEN]) -> Self {
        let mut pk = [0; PUBLIC_KEY_LEN];
        pk[..ELEMENT_LEN].copy_from_slice(root);
        pk[ELEMENT_LEN..].copy_from_slice(parameter);
        Self(pk)
    }

    /// The public parameter `P`.
    #[inline(always)]
    pub fn parameter(&self) -> &[u8; PARAMETER_LEN] {
        self.0[ELEMENT_LEN..].try_into().unwrap()
    }
}

/// A signature under one leaf, 1,037 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Signature(pub(crate) [u8; SIGNATURE_LEN]);

solana_winternitz::fixed_bytes!(Signature, SIGNATURE_LEN, Error);

impl Signature {
    /// The unverified leaf index (the paper's epoch), unrelated to Solana epochs.
    #[inline(always)]
    pub fn leaf(&self) -> u32 {
        u32::from_be_bytes(self.0[..SALT].try_into().unwrap())
    }
}
