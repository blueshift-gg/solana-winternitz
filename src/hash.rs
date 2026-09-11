//! Keccak-256: the `sol_keccak256` syscall on-chain, the `sha3` crate on the
//! host. The paper instantiates with SHA-3 (§7.2); Keccak-256 is the same
//! permutation, rate and capacity with a different padding byte, and the
//! sponge instantiation Solana provides. On-chain cost (agave
//! `execution_budget.rs`, `syscalls/src/lib.rs`): 85 CU per call plus, per
//! slice, `max(10, len / 2)` CU, the same for every hash syscall.

pub const HASH_LENGTH: usize = 32;

/// Keccak-256 of the concatenation of `data`, without concatenating.
#[cfg(target_os = "solana")]
#[inline(always)]
pub fn hashv(data: &[&[u8]]) -> [u8; HASH_LENGTH] {
    let mut out = core::mem::MaybeUninit::<[u8; HASH_LENGTH]>::uninit();
    // SAFETY: the syscall reads `data.len()` (pointer, length) pairs from
    // `data`, which is how `&[&[u8]]` is laid out on this target and what
    // `solana_program::keccak::hashv` passes, and writes exactly
    // `HASH_LENGTH` bytes to `out` before returning, so `out` is initialized.
    unsafe {
        crate::syscalls::sol_keccak256(
            data as *const _ as *const u8,
            data.len() as u64,
            out.as_mut_ptr() as *mut u8,
        );
        out.assume_init()
    }
}

#[cfg(not(target_os = "solana"))]
pub fn hashv(data: &[&[u8]]) -> [u8; HASH_LENGTH] {
    use sha3::Digest;
    let mut h = sha3::Keccak256::new();
    for d in data {
        h.update(d);
    }
    h.finalize().into()
}
