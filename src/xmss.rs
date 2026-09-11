//! Construction 3 at L = 2^8, public key `(root, P)`. The verifier cannot
//! see history: the program enforces a leaf policy on the index
//! (SECURITY.md) and [`crate::Signer`] enforces one message per leaf.

use crate::{
    Chain, ELEMENT_LENGTH, ELEMENTS_LENGTH, Error, MESSAGE_LENGTH, PublicKey, SALT_LENGTH, encode,
    leaf_hash, node,
};

/// Tree height `h`.
pub const HEIGHT: usize = 8;
/// Leaves, and so signatures, per key.
pub const LEAVES: u32 = 1 << HEIGHT;
/// `(ep, ρ, σ_OTS, path_ep)` of Construction 3, `ep` as u32 big-endian.
pub const SIGNATURE_LENGTH: usize = 4 + SALT_LENGTH + ELEMENTS_LENGTH + HEIGHT * ELEMENT_LENGTH;

const SALT: usize = 4;
const ELEMENTS: usize = SALT + SALT_LENGTH;
const PATH: usize = ELEMENTS + ELEMENTS_LENGTH;

/// A signature under one leaf, 1,037 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature(pub [u8; SIGNATURE_LENGTH]);

impl Signature {
    /// The paper's epoch: a counter, never a slot or the Solana epoch.
    #[inline(always)]
    pub fn leaf(&self) -> u32 {
        u32::from_be_bytes(self.0[..SALT].try_into().unwrap())
    }

    /// Construction 3 Ver, then Construction 1 VerPath. Constant work for
    /// an accepted signature: the message hash, 243 chain steps, the leaf,
    /// 8 nodes.
    #[inline]
    pub fn verify(
        &self,
        public_key: &PublicKey,
        message: &[u8; MESSAGE_LENGTH],
    ) -> Result<(), Error> {
        let leaf = self.leaf();
        if leaf >= LEAVES {
            return Err(Error::InvalidSignature);
        }
        let parameter = public_key.parameter();
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
        if current == public_key.node() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

/// Construction 3 Gen with Remark 7's PRF, every node kept (Remark 3):
/// ~135k hashes to build. Not `Clone`, not `Debug`.
#[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
pub struct SecretKey {
    seed: [u8; 32],
    parameter: [u8; crate::PARAMETER_LENGTH],
    /// Level-major: leaves first, root last.
    nodes: [[u8; ELEMENT_LENGTH]; 2 * LEAVES as usize - 1],
}

#[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
impl Drop for SecretKey {
    fn drop(&mut self) {
        crate::wipe(&mut self.seed);
    }
}

#[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
impl SecretKey {
    /// Where level `l` starts in `nodes`.
    const fn level(l: usize) -> usize {
        2 * LEAVES as usize - (2 << (HEIGHT - l))
    }

    /// `root ‖ P`.
    pub fn public_key(&self) -> PublicKey {
        PublicKey::new(&self.nodes[Self::level(HEIGHT)], &self.parameter)
    }
}

#[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
impl crate::OneTime for SecretKey {
    type Signature = Signature;
    const LEAVES: u32 = 1 << HEIGHT;
    const HEIGHT: u8 = HEIGHT as u8;

    /// Construction 3 Gen: every chain of every leaf, then the tree.
    fn new(seed: [u8; 32], parameter: [u8; crate::PARAMETER_LENGTH]) -> Self {
        let mut nodes = [[0u8; ELEMENT_LENGTH]; 2 * LEAVES as usize - 1];
        for leaf in 0..LEAVES {
            nodes[leaf as usize] = leaf_hash(
                &parameter,
                leaf,
                &crate::seed::ends(&seed, &parameter, leaf),
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
        Self {
            seed,
            parameter,
            nodes,
        }
    }

    fn public_key(&self) -> PublicKey {
        SecretKey::public_key(self)
    }

    /// Construction 3 Sig plus Construction 1 Path. Records nothing;
    /// `None` if `leaf >= LEAVES` or every salt misses.
    fn sign_at(&self, leaf: u32, message: &[u8; MESSAGE_LENGTH]) -> Option<Signature> {
        if leaf >= LEAVES {
            return None;
        }
        let (salt, elements) = crate::seed::sign(&self.seed, &self.parameter, leaf, message)?;
        let mut sig = Signature([0; SIGNATURE_LENGTH]);
        sig.0[..SALT].copy_from_slice(&leaf.to_be_bytes());
        sig.0[SALT..ELEMENTS].copy_from_slice(&salt);
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
