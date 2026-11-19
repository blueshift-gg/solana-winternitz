//! DKKW25 building blocks shared with `solana-xmss`: the leaf a one-time
//! signature commits to, and the Merkle nodes above it.
//!
//! Every tweak is defined here, so the hash domains cannot overlap: chain
//! steps use role 0, leaves and Merkle nodes role 1 (leaves at level 0,
//! nodes at levels 1 and up), and message encoding role 2. [`node`] refuses
//! level 0, so no node can be confused with a leaf.

use crate::{MESSAGE_LEN, PARAMETER_LEN, hash};

/// `v`: 36 four-bit digits from an 18-byte hash; ≥ 138 bits, DKKW25 eq. (13).
pub(crate) const CHAINS: usize = 36;
/// `2^w`, w = 4.
pub(crate) const POSITIONS: u8 = 16;
/// `T = ⌈1.1·v(2^w − 1)/2⌉` (§8): 243 verifier chain steps.
/// Equal-sum vectors are incomparable (Lemma 7), replacing the checksum.
pub(crate) const TARGET_SUM: u16 = 297;
/// `ρ`: eq. (14) at L = 2^8, K = 2^12 needs ≥ 168 bits.
pub const SALT_LEN: usize = 21;
/// Chain elements, leaves and nodes: eq. (15) at L = 2^8 needs ≥ 183 bits.
pub const ELEMENT_LEN: usize = 23;
/// The 36 chain elements of a one-time signature.
pub const ELEMENTS_LEN: usize = CHAINS * ELEMENT_LEN;

/// A leaf or Merkle node.
pub type Node = [u8; ELEMENT_LEN];

/// §7.1 domain bytes, eqs. (17)–(19), first in each tweak.
pub(crate) const ROLE_CHAIN: u8 = 0;
pub(crate) const ROLE_TREE: u8 = 1;
pub(crate) const ROLE_MESSAGE: u8 = 2;
/// `tweak(ep, i, k)` of eq. (17): `role ‖ leaf ‖ chain ‖ position`.
const CHAIN_TWEAK_LENGTH: usize = 7;
/// `tweakmt(l, i)` of eq. (18): `role ‖ level ‖ index`.
const TREE_TWEAK_LENGTH: usize = 6;

/// The leaf that a one-time signature `(salt, elements)` at `leaf` commits to
/// for `message`, or `None` if the salted digest misses the target sum
/// (Construction 3, Ver, steps 1–6). A valid signature's leaf equals the
/// signer's; anything else gives an unrelated value.
#[inline]
pub fn leaf(
    parameter: &[u8; PARAMETER_LEN],
    leaf: u32,
    salt: &[u8; SALT_LEN],
    elements: &[u8; ELEMENTS_LEN],
    message: &[u8; MESSAGE_LEN],
) -> Option<Node> {
    let x = encode(salt, parameter, leaf, message)?;
    let ends = Chain::new(parameter, leaf).ends(&x, elements);
    Some(leaf_hash(parameter, leaf, &ends))
}

/// Construction 1 node at `level` ≥ 1, `Th(P, tweakmt(level, index), (left, right))`.
///
/// # Panics
///
/// At level 0, which belongs to leaves.
#[inline]
pub fn node(
    parameter: &[u8; PARAMETER_LEN],
    level: u8,
    index: u32,
    left: &Node,
    right: &Node,
) -> Node {
    assert!(level != 0, "level 0 holds leaves");
    hash::hashv(&[parameter, &tree_tweak(level, index), left, right])[..ELEMENT_LEN]
        .try_into()
        .unwrap()
}

/// Construction 6: accept the 36 low-first nibbles iff their sum is `T`.
/// The message tweak alone uses a little-endian leaf index, as in hash-sig.
pub(crate) fn encode(
    salt: &[u8],
    parameter: &[u8],
    leaf: u32,
    message: &[u8; MESSAGE_LEN],
) -> Option<[u8; CHAINS]> {
    let mut tweak = [ROLE_MESSAGE, 0, 0, 0, 0];
    tweak[1..].copy_from_slice(&leaf.to_le_bytes());
    let digest = hash::hashv(&[salt, parameter, &tweak, message]);
    let mut x = [0u8; CHAINS];
    for (i, xi) in x.iter_mut().enumerate() {
        *xi = digest[i / 2] >> (4 * (i % 2)) & 0x0f;
    }
    (x.iter().map(|&v| u16::from(v)).sum::<u16>() == TARGET_SUM).then_some(x)
}

/// Construction 2 over `Trunc_n(H(P ‖ t ‖ x))` (§7.2.2).
/// Two buffers under one tweak prefix: a step hashes one into the digest slot
/// of the other, so each chain syscall reads a single slice and the value is
/// never copied.
pub(crate) struct Chain([Buffer; 2]);

/// A chain input and the digest it receives: `P ‖ tweak ‖ value ‖ 9 bytes`.
type Buffer = [u8; Chain::VALUE + hash::HASH_LENGTH];

impl Chain {
    const TWEAK: usize = PARAMETER_LEN;
    const INDEX: usize = Self::TWEAK + 5;
    const POSITION: usize = Self::TWEAK + 6;
    const VALUE: usize = Self::TWEAK + CHAIN_TWEAK_LENGTH;
    const INPUT: usize = Self::VALUE + ELEMENT_LEN;

    pub(crate) fn new(parameter: &[u8], leaf: u32) -> Self {
        let mut buf: Buffer = [0; _];
        buf[..Self::TWEAK].copy_from_slice(parameter);
        buf[Self::TWEAK] = ROLE_CHAIN;
        buf[Self::TWEAK + 1..Self::INDEX].copy_from_slice(&leaf.to_be_bytes());
        Self([buf; 2])
    }

    /// The step entering position `k` uses tweak `k` (Construction 2).
    /// Lemma 2 permits splitting the walk at the signed position `x_i`.
    /// Two steps per iteration keep each buffer's role, so nothing is swapped.
    pub(crate) fn walk(&mut self, i: u8, from: u8, to: u8, x: &[u8; ELEMENT_LEN]) -> Node {
        let [a, b] = self.0.each_mut();
        a[Self::INDEX] = i;
        b[Self::INDEX] = i;
        a[Self::VALUE..Self::INPUT].copy_from_slice(x);
        let mut k = from;
        while k + 1 < to {
            Self::step(a, b, k + 1);
            Self::step(b, a, k + 2);
            k += 2;
        }
        if k < to {
            Self::step(a, b, k + 1);
            return b[Self::VALUE..Self::INPUT].try_into().unwrap();
        }
        a[Self::VALUE..Self::INPUT].try_into().unwrap()
    }

    /// `dst.value = Trunc_n(H(src))` with `src` at `position`.
    #[inline(always)]
    fn step(src: &mut Buffer, dst: &mut Buffer, position: u8) {
        src[Self::POSITION] = position;
        hash::hashv_into(&[&src[..Self::INPUT]], dst.last_chunk_mut().unwrap());
    }

    /// Construction 3 Ver step 6: each `σ_i` walked from `x_i` to `2^w − 1`.
    fn ends(&mut self, x: &[u8; CHAINS], elements: &[u8]) -> [Node; CHAINS] {
        let mut ends = [[0u8; ELEMENT_LEN]; CHAINS];
        for (i, (end, element)) in ends
            .iter_mut()
            .zip(elements.as_chunks::<ELEMENT_LEN>().0)
            .enumerate()
        {
            *end = self.walk(i as u8, x[i], POSITIONS - 1, element);
        }
        ends
    }
}

/// `tweakmt(l, i)`, eq. (18).
fn tree_tweak(level: u8, index: u32) -> [u8; TREE_TWEAK_LENGTH] {
    let mut tweak = [ROLE_TREE, level, 0, 0, 0, 0];
    tweak[2..].copy_from_slice(&index.to_be_bytes());
    tweak
}

/// Construction 1 leaf: hash the 36 chain ends without copying them.
pub(crate) fn leaf_hash(parameter: &[u8], leaf: u32, ends: &[Node; CHAINS]) -> Node {
    hash::hashv(&[parameter, &tree_tweak(0, leaf), ends.as_flattened()])[..ELEMENT_LEN]
        .try_into()
        .unwrap()
}
