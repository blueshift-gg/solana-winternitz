//! Keccak-256 via the Solana syscall or RustCrypto on the host.
//! SHA3-256 uses a different suffix and produces different digests.

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
