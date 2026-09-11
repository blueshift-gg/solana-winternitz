//! Lifetime 256: one key, 256 one-time leaves under a Merkle tree. The
//! public key is `root ‖ P`.
//!
//! Each signature names its leaf by epoch. A leaf signs once; the verifier
//! cannot see history, so the program that verifies stores the last epoch
//! used and accepts only strictly greater ones. A signature broadcast in a
//! transaction that failed has still revealed its leaf: the signer must
//! never reuse an epoch it has signed with, landed or not.

use crate::{
    Chain, ELEMENTS_LENGTH, Error, NODE_LENGTH, PARAMETER_LENGTH, PublicKey, SALT_LENGTH, encode,
    leaf, node,
};

pub const HEIGHT: usize = 8;
pub const LEAVES: u32 = 1 << HEIGHT;
/// `epoch (u32 LE) ‖ ρ ‖ σ_0 ‖ … ‖ σ_34 ‖ authentication path`.
pub const SIGNATURE_LENGTH: usize = 4 + SALT_LENGTH + ELEMENTS_LENGTH + HEIGHT * NODE_LENGTH;

const SALT: usize = 4;
const ELEMENTS: usize = SALT + SALT_LENGTH;
const PATH: usize = ELEMENTS + ELEMENTS_LENGTH;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature(pub [u8; SIGNATURE_LENGTH]);

impl Signature {
    /// The leaf this signature spends. The verifier must reject any epoch
    /// at or below the last one accepted for the same key.
    #[inline(always)]
    pub fn epoch(&self) -> u32 {
        u32::from_le_bytes(self.0[..SALT].try_into().unwrap())
    }

    /// One message hash, 200 chain hashes, one leaf hash, 8 node hashes:
    /// ~31k CU, the same for every accepted signature. A wrong message or
    /// epoch rejects after the first hash; a wrong key after all of them.
    #[inline]
    pub fn verify(&self, public_key: &PublicKey, message: &[u8]) -> Result<(), Error> {
        let epoch = self.epoch();
        if epoch >= LEAVES {
            return Err(Error::InvalidSignature);
        }
        let parameter = public_key.parameter();
        let x = encode(&self.0[SALT..ELEMENTS], parameter, epoch, message)
            .ok_or(Error::InvalidSignature)?;
        let ends = Chain::new(parameter, epoch).ends(&x, &self.0[ELEMENTS..PATH]);
        let mut current = leaf(parameter, epoch, &ends);
        for (level, sibling) in (1..=HEIGHT as u8).zip(self.0[PATH..].chunks_exact(NODE_LENGTH)) {
            let index = epoch >> level;
            current = if (epoch >> (level - 1)) & 1 == 0 {
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

/// A 256-leaf key. Building it walks every chain of every leaf, ~135k
/// SHA-256 calls. Not `Clone`, not `Debug`.
#[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
pub struct SecretKey {
    seed: [u8; 32],
    parameter: [u8; PARAMETER_LENGTH],
    /// Level-major: leaves first, root last.
    nodes: [[u8; NODE_LENGTH]; 2 * LEAVES as usize - 1],
}

#[cfg(all(any(feature = "sign", test), not(target_os = "solana")))]
impl SecretKey {
    /// Where level `l` starts in `nodes`.
    const fn level(l: usize) -> usize {
        2 * LEAVES as usize - (2 << (HEIGHT - l))
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        let parameter = crate::seed::parameter(&seed);
        let mut nodes = [[0u8; NODE_LENGTH]; 2 * LEAVES as usize - 1];
        for epoch in 0..LEAVES {
            nodes[epoch as usize] = leaf(
                &parameter,
                epoch,
                &crate::seed::ends(&seed, &parameter, epoch),
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

    pub fn public_key(&self) -> PublicKey {
        PublicKey::new(&self.nodes[Self::level(HEIGHT)], &self.parameter)
    }

    /// Sign `message` with leaf `epoch`. The caller owns the rule that an
    /// epoch is used once; keep the highest epoch ever signed, including in
    /// transactions that failed. Deterministic in seed, epoch and message.
    /// `None` if `epoch >= LEAVES` or 2^16 salts all miss the target sum.
    pub fn sign(&self, epoch: u32, message: &[u8]) -> Option<Signature> {
        if epoch >= LEAVES {
            return None;
        }
        let (salt, elements) = crate::seed::sign(&self.seed, &self.parameter, epoch, message)?;
        let mut sig = Signature([0; SIGNATURE_LENGTH]);
        sig.0[..SALT].copy_from_slice(&epoch.to_le_bytes());
        sig.0[SALT..ELEMENTS].copy_from_slice(&salt);
        sig.0[ELEMENTS..PATH].copy_from_slice(&elements);
        for (l, slot) in sig.0[PATH..].chunks_exact_mut(NODE_LENGTH).enumerate() {
            let sibling = ((epoch as usize) >> l) ^ 1;
            slot.copy_from_slice(&self.nodes[Self::level(l) + sibling]);
        }
        Some(sig)
    }
}
