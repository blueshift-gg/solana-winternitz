//! `cargo test --lib`: parameters meet DKKW25 (13)–(16) at lifetime 256 and
//! the target sum gives the documented grinding cost; syscall ids match; both instances round-trip
//! and reproduce `tests/vectors.json`; encodings are pairwise incomparable;
//! every single-byte tamper, and every out-of-range epoch, is rejected.
extern crate std;

use num_bigint::BigUint;
use serde_json::Value;
use std::vec::Vec;

use crate::{
    CHAINS, ELEMENT_LENGTH, Error, PARAMETER_LENGTH, POSITIONS, PUBLIC_KEY_LENGTH, PublicKey,
    SALT_LENGTH, TARGET_SUM, encode, seed, syscalls, winternitz, xmss,
};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn to_hex(b: &[u8]) -> std::string::String {
    b.iter().map(|x| std::format!("{x:02x}")).collect()
}

fn seed(i: u8) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[0] = i;
    seed
}

/// Vertices of `[w]^v` whose coordinates sum to `v(w−1) − d` (KKW25 §5).
fn layer_size(v: usize, w: usize, d: usize) -> BigUint {
    let binom = |n: usize, k: usize| -> BigUint {
        (0..k).fold(BigUint::from(1u8), |acc, i| {
            acc * BigUint::from(n - i) / BigUint::from(i + 1)
        })
    };
    let (mut plus, mut minus) = (BigUint::from(0u8), BigUint::from(0u8));
    for s in 0..=d / w {
        let term = binom(v, s) * binom(d - s * w + v - 1, v - 1);
        if s % 2 == 0 {
            plus += term
        } else {
            minus += term
        }
    }
    plus - minus
}

#[test]
fn parameters_satisfy_dkkw25_requirements() {
    let (kc, kq) = (128.0f64, 64.0f64);
    let (log5, log3, log12) = (5f64.log2(), 3f64.log2(), 12f64.log2());
    let (w, v, log_l, log_k) = (
        f64::from(POSITIONS).log2(),
        CHAINS as f64,
        xmss::HEIGHT as f64,
        f64::from(seed::MAX_TRIALS).log2(),
    );
    // (13) code size; (14) salt; (15) element; (16) parameter. qs = L = 2^HEIGHT.
    assert!(v * w >= (kc + log5 + 1.0).max(2.0 * (kq + log5 + 1.0) + 3.0));
    assert!(
        (8 * SALT_LENGTH) as f64
            >= (kc + log5 + log_l + log_k + 1.0).max(2.0 * (kq + log5 + log3 + log_k) + log_l)
    );
    assert!(
        (8 * ELEMENT_LENGTH) as f64
            >= (kc + log5 + 2.0 * w + log_l + v.log2())
                .max(2.0 * (kq + log5 + 2.0 * w + log_l + v.log2() + log12))
    );
    assert!((8 * PARAMETER_LENGTH) as f64 >= (kc + log5 + 3.0).max(2.0 * (kq + log5 + 2.0) + 5.0));
    // The same bounds as the authors' script prints for
    // (log_lifetime 8, 35 chains, 4-bit chunks, log_K 16):
    // b-wagn/hashsig-parameters@95a80bc lower_bounds.py.
    const { assert!(8 * ELEMENT_LENGTH >= 183 && 8 * PARAMETER_LENGTH >= 142 && 8 * SALT_LENGTH >= 176) };
    assert!(CHAINS * usize::from(w as u8) >= 138);

    // The target sum sets verifier work and signer grinding, not security:
    // 200 steps, and one accepted digest per ~940 uniform tries.
    let steps = CHAINS * usize::from(POSITIONS - 1) - usize::from(TARGET_SUM);
    assert_eq!(steps, 200);
    let size = layer_size(CHAINS, POSITIONS.into(), steps);
    let trials = BigUint::from(POSITIONS).pow(CHAINS as u32) / size;
    assert!(trials >= BigUint::from(512u32) && trials <= BigUint::from(1024u32));
    assert_eq!(PUBLIC_KEY_LENGTH, 56);
    assert_eq!(winternitz::SIGNATURE_LENGTH, 864);
    assert_eq!(xmss::SIGNATURE_LENGTH, 1124);
}

#[test]
fn syscall_ids_match_published_values() {
    // sol_sha512's is the value solana-ecvrf ships; both come from the same murmur3.
    assert_eq!(syscalls::sys_hash("sol_sha256"), 0x11f49d86);
    assert_eq!(syscalls::sys_hash("sol_sha512"), 0x9229cdcc);
}

#[test]
fn winternitz_roundtrip() {
    let messages: [&[u8]; 4] = [b"", b"hello", &[0u8; 1000], &[0xff; 33]];
    for (i, m) in messages.iter().enumerate() {
        let sk = winternitz::SecretKey(seed(i as u8));
        let pk = sk.public_key();
        let sig = sk.sign(m).unwrap();
        assert_eq!(sig.verify(&pk, m), Ok(()));
        let other = winternitz::SecretKey(seed(9)).public_key();
        assert_eq!(sig.verify(&other, m), Err(Error::InvalidSignature));
        assert_eq!(sig.verify(&pk, b"other"), Err(Error::InvalidSignature));
    }
}

#[test]
fn xmss_roundtrip_every_leaf() {
    let sk = xmss::SecretKey::from_seed(seed(3));
    let pk = sk.public_key();
    let other = xmss::SecretKey::from_seed(seed(4)).public_key();
    for epoch in 0..xmss::LEAVES {
        let m = epoch.to_le_bytes();
        let sig = sk.sign(epoch, &m).unwrap();
        assert_eq!(sig.epoch(), epoch);
        assert_eq!(sig.verify(&pk, &m), Ok(()));
        assert_eq!(sig.verify(&other, &m), Err(Error::InvalidSignature));
        assert_eq!(sig.verify(&pk, b"other"), Err(Error::InvalidSignature));
    }
    assert!(sk.sign(xmss::LEAVES, b"").is_none());
    // A signature re-labelled with another epoch fails at the tree.
    let mut sig = sk.sign(5, b"m").unwrap();
    sig.0[..4].copy_from_slice(&6u32.to_le_bytes());
    assert_eq!(sig.verify(&pk, b"m"), Err(Error::InvalidSignature));
    sig.0[..4].copy_from_slice(&xmss::LEAVES.to_le_bytes());
    assert_eq!(sig.verify(&pk, b"m"), Err(Error::InvalidSignature));
}

/// DKKW25 Def. 13, the property that replaces the checksum: no accepted
/// encoding is coordinate-wise ≤ another, so no signature can be walked
/// forward into a signature on a different message.
#[test]
fn encodings_are_incomparable() {
    let m = b"incomparable";
    let parameter = seed::parameter(&seed(0));
    let encodings: Vec<[u8; CHAINS]> = (0..48)
        .map(|epoch| {
            let (salt, _) = seed::sign(&seed(0), &parameter, epoch, m).unwrap();
            encode(&salt, &parameter, epoch, m).unwrap()
        })
        .collect();
    for a in &encodings {
        assert_eq!(a.iter().map(|&v| u16::from(v)).sum::<u16>(), TARGET_SUM);
        for b in &encodings {
            assert!(a == b || a.iter().zip(b).any(|(x, y)| x < y));
        }
    }
    let (salt, _) = seed::sign(&seed(0), &parameter, 0, m).unwrap();
    assert!(encode(&salt, &parameter, 0, b"incomparable!").is_none());
}

#[test]
fn tampering_is_rejected() {
    let m = b"tamper";
    let sk = winternitz::SecretKey(seed(2));
    let pk = sk.public_key();
    let sig = sk.sign(m).unwrap();
    for i in 0..winternitz::SIGNATURE_LENGTH {
        let mut t = sig;
        t.0[i] ^= 1;
        assert_eq!(t.verify(&pk, m), Err(Error::InvalidSignature), "byte {i}");
    }
    for i in 0..PUBLIC_KEY_LENGTH {
        let mut p = pk;
        p.0[i] ^= 1;
        assert_eq!(sig.verify(&p, m), Err(Error::InvalidSignature));
    }
    assert_eq!(sig.verify(&pk, b"tampes"), Err(Error::InvalidSignature));

    let sk = xmss::SecretKey::from_seed(seed(2));
    let pk = sk.public_key();
    let sig = sk.sign(77, m).unwrap();
    for i in 0..xmss::SIGNATURE_LENGTH {
        let mut t = sig;
        t.0[i] ^= 1;
        assert_eq!(t.verify(&pk, m), Err(Error::InvalidSignature), "byte {i}");
    }
    for i in 0..PUBLIC_KEY_LENGTH {
        let mut p = pk;
        p.0[i] ^= 1;
        assert_eq!(sig.verify(&p, m), Err(Error::InvalidSignature));
    }
}

const VECTORS: &str = include_str!("../tests/vectors.json");

#[test]
fn vectors_are_reproduced() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let field = |v: &Value, k: &str| hex(v[k].as_str().unwrap());
    let ots = vectors["winternitz"].as_array().unwrap();
    let tree = vectors["xmss"].as_array().unwrap();
    assert!(!ots.is_empty() && !tree.is_empty());
    for v in ots {
        let sk = winternitz::SecretKey(field(v, "seed").try_into().unwrap());
        let pk = PublicKey(field(v, "public_key").try_into().unwrap());
        let signature = winternitz::Signature(field(v, "signature").try_into().unwrap());
        assert_eq!(sk.public_key(), pk);
        assert_eq!(sk.sign(&field(v, "message")).unwrap(), signature);
        assert_eq!(signature.verify(&pk, &field(v, "message")), Ok(()));
    }
    for v in tree {
        let sk = xmss::SecretKey::from_seed(field(v, "seed").try_into().unwrap());
        let epoch = v["epoch"].as_u64().unwrap() as u32;
        let pk = PublicKey(field(v, "public_key").try_into().unwrap());
        let signature = xmss::Signature(field(v, "signature").try_into().unwrap());
        assert_eq!(sk.public_key(), pk);
        assert_eq!(sk.sign(epoch, &field(v, "message")).unwrap(), signature);
        assert_eq!(signature.verify(&pk, &field(v, "message")), Ok(()));
    }
}

/// `cargo test --lib regenerate_vectors -- --ignored` rewrites the corpus.
#[test]
#[ignore]
fn regenerate_vectors() {
    let cases: [(&[u8], &[u8]); 3] = [
        (b"", b""),
        (b"blueshift", b"rotate to 11111111111111111111111111111111"),
        (&[0x42; 32], &[0u8; 100]),
    ];
    let seeds: Vec<[u8; 32]> = cases
        .iter()
        .enumerate()
        .map(|(i, (prefix, _))| {
            let mut seed = [0u8; 32];
            seed[..prefix.len()].copy_from_slice(prefix);
            seed[31] = i as u8;
            seed
        })
        .collect();
    let ots: Vec<Value> = seeds
        .iter()
        .zip(&cases)
        .map(|(seed, (_, message))| {
            let sk = winternitz::SecretKey(*seed);
            let public_key = sk.public_key();
            serde_json::json!({
                "seed": to_hex(seed),
                "message": to_hex(message),
                "public_key": to_hex(&public_key.0),
                "signature": to_hex(&sk.sign(message).unwrap().0),
            })
        })
        .collect();
    let tree: Vec<Value> = seeds
        .iter()
        .zip(&cases)
        .zip([0u32, 1, xmss::LEAVES - 1])
        .map(|((seed, (_, message)), epoch)| {
            let sk = xmss::SecretKey::from_seed(*seed);
            serde_json::json!({
                "seed": to_hex(seed),
                "epoch": epoch,
                "message": to_hex(message),
                "public_key": to_hex(&sk.public_key().0),
                "signature": to_hex(&sk.sign(epoch, message).unwrap().0),
            })
        })
        .collect();
    std::fs::write(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors.json"),
        serde_json::to_string_pretty(&serde_json::json!({ "winternitz": ots, "xmss": tree }))
            .unwrap()
            + "\n",
    )
    .unwrap();
}
