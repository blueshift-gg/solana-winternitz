//! Raw binding for `sol_keccak256`. Only compiled for `target_os = "solana"`.
//!
//! SBPF v3 toolchains set `target_feature = "static-syscalls"` and dispatch
//! syscalls by the murmur3 hash of their name; older toolchains link the
//! symbol dynamically. The hash is computed at compile time with the same
//! function `solana-define-syscall` uses (`sys_hash`), and the tests check
//! it against the published value.

#[cfg(all(
    target_os = "solana",
    not(any(target_feature = "static-syscalls", feature = "static-syscalls"))
))]
unsafe extern "C" {
    pub fn sol_keccak256(vals: *const u8, val_len: u64, hash_result: *mut u8) -> u64;
}

#[cfg(all(
    target_os = "solana",
    any(target_feature = "static-syscalls", feature = "static-syscalls")
))]
#[inline(always)]
pub unsafe fn sol_keccak256(vals: *const u8, val_len: u64, hash_result: *mut u8) -> u64 {
    const ID: usize = sys_hash("sol_keccak256");
    // SAFETY: on static-syscall targets the runtime binds each syscall to the
    // address equal to the murmur3 of its name, the convention
    // `solana-define-syscall` implements, and this signature is the runtime's
    // `sol_keccak256` ABI.
    let f: extern "C" fn(*const u8, u64, *mut u8) -> u64 = unsafe { core::mem::transmute(ID) };
    f(vals, val_len, hash_result)
}

/// murmur3_32(name, 0): the static-syscall id. Same algorithm as
/// `solana_define_syscall::sys_hash` (anza-xyz/agave, `define-syscall/src/lib.rs`).
/// Only reached on static-syscall builds and in the tests.
#[allow(dead_code)]
pub const fn sys_hash(name: &str) -> usize {
    murmur3_32(name.as_bytes(), 0) as usize
}

#[allow(dead_code)]
const fn murmur3_32(buf: &[u8], seed: u32) -> u32 {
    const fn pre_mix(buf: [u8; 4]) -> u32 {
        u32::from_le_bytes(buf)
            .wrapping_mul(0xcc9e2d51)
            .rotate_left(15)
            .wrapping_mul(0x1b873593)
    }
    let mut hash = seed;
    let mut i = 0;
    while i < buf.len() / 4 {
        let b = [buf[i * 4], buf[i * 4 + 1], buf[i * 4 + 2], buf[i * 4 + 3]];
        hash ^= pre_mix(b);
        hash = hash.rotate_left(13);
        hash = hash.wrapping_mul(5).wrapping_add(0xe6546b64);
        i += 1;
    }
    let rem = buf.len() % 4;
    if rem > 0 {
        let mut b = [0u8; 4];
        let mut j = 0;
        while j < rem {
            b[j] = buf[buf.len() - rem + j];
            j += 1;
        }
        hash ^= pre_mix(b);
    }
    hash ^= buf.len() as u32;
    hash ^= hash >> 16;
    hash = hash.wrapping_mul(0x85ebca6b);
    hash ^= hash >> 13;
    hash = hash.wrapping_mul(0xc2b2ae35);
    hash ^= hash >> 16;
    hash
}
