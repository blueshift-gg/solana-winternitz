//! SHA-256: the `sol_sha256` syscall on-chain, the `sha2` crate on the host.
//! On-chain cost (agave `execution_budget.rs`, `syscalls/src/lib.rs`): 85 CU
//! per call plus, per slice, `max(10, len / 2)` CU.

pub const HASH_LENGTH: usize = 32;

/// SHA-256 of the concatenation of `data`, without concatenating.
#[cfg(target_os = "solana")]
#[inline(always)]
pub fn hashv(data: &[&[u8]]) -> [u8; HASH_LENGTH] {
    let mut out = core::mem::MaybeUninit::<[u8; HASH_LENGTH]>::uninit();
    unsafe {
        crate::syscalls::sol_sha256(
            data as *const _ as *const u8,
            data.len() as u64,
            out.as_mut_ptr() as *mut u8,
        );
        out.assume_init()
    }
}

#[cfg(not(target_os = "solana"))]
pub fn hashv(data: &[&[u8]]) -> [u8; HASH_LENGTH] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    for d in data {
        h.update(d);
    }
    h.finalize().into()
}
