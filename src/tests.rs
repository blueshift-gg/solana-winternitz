//! What is pinned: eqs. (13)–(16) and the grinding cost behind the
//! constants, the HMAC and syscall-id constants against their sources, both
//! instances against `tests/vectors.json` and the key-file fixture, every
//! single-byte tamper rejected, and the signer's allocation rules.
use num_bigint::BigUint;
use serde_json::Value;
use std::vec::Vec;

use crate::{
    CHAINS, ELEMENT_LENGTH, Error, OneTime, PARAMETER_LENGTH, POSITIONS, PUBLIC_KEY_LENGTH,
    PublicKey, SALT_LENGTH, TARGET_SUM, seed, syscalls, winternitz, xmss,
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

/// Lemma 7's `η_T`, the points of `[w]^v` with coordinate sum `v(w−1) − d`,
/// by inclusion–exclusion.
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

/// Parameter Requirements 2 and 3, eqs. (13)–(16), at L = 2^8, K = 2^16,
/// and the numbers the authors' script prints for them; the target sum's
/// verifier and signer cost.
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
    // (13) digest, (14) salt, (15) element, (16) parameter, with qs = L.
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
    // b-wagn/hashsig-parameters@95a80bc lower_bounds.py, same inputs.
    const { assert!(8 * ELEMENT_LENGTH >= 183 && 8 * PARAMETER_LENGTH >= 142 && 8 * SALT_LENGTH >= 176) };
    assert!(CHAINS * usize::from(w as u8) >= 138);

    // T = 325: 200 verifier steps, one accepted digest in 512–1024 tries.
    let steps = CHAINS * usize::from(POSITIONS - 1) - usize::from(TARGET_SUM);
    assert_eq!(steps, 200);
    let size = layer_size(CHAINS, POSITIONS.into(), steps);
    let trials = BigUint::from(POSITIONS).pow(CHAINS as u32) / size;
    assert!(trials >= BigUint::from(512u32) && trials <= BigUint::from(1024u32));
    assert_eq!(PUBLIC_KEY_LENGTH, 56);
    assert_eq!(winternitz::SIGNATURE_LENGTH, 864);
    assert_eq!(xmss::SIGNATURE_LENGTH, 1124);
}

/// RFC 4231 §4.2–4.3.
#[test]
fn hmac_matches_rfc_4231() {
    assert_eq!(
        to_hex(&crate::hmac(&[0x0b; 20], b"Hi There")),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
    assert_eq!(
        to_hex(&crate::hmac(b"Jefe", b"what do ya want for nothing?")),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
}

/// `sol_sha256` per agave's define-syscall; `sol_sha512` per solana-ecvrf,
/// the same murmur3.
#[test]
fn syscall_ids_match_published_values() {
    assert_eq!(syscalls::sys_hash("sol_sha256"), 0x11f49d86);
    assert_eq!(syscalls::sys_hash("sol_sha512"), 0x9229cdcc);
}

#[test]
fn winternitz_roundtrip() {
    let messages: [&[u8]; 4] = [b"", b"hello", &[0u8; 1000], &[0xff; 33]];
    for (i, m) in messages.iter().enumerate() {
        let sk = winternitz::SecretKey(seed(i as u8));
        let pk = sk.public_key();
        let sig = sk.sign_at(0, m).unwrap();
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
    for leaf in 0..xmss::LEAVES {
        let m = leaf.to_le_bytes();
        let sig = sk.sign_at(leaf, &m).unwrap();
        assert_eq!(sig.leaf(), leaf);
        assert_eq!(sig.verify(&pk, &m), Ok(()));
        assert_eq!(sig.verify(&other, &m), Err(Error::InvalidSignature));
        assert_eq!(sig.verify(&pk, b"other"), Err(Error::InvalidSignature));
    }
    assert!(sk.sign_at(xmss::LEAVES, b"").is_none());
    // Relabelled to another leaf: the path no longer closes.
    let mut sig = sk.sign_at(5, b"m").unwrap();
    sig.0[..4].copy_from_slice(&6u32.to_le_bytes());
    assert_eq!(sig.verify(&pk, b"m"), Err(Error::InvalidSignature));
    sig.0[..4].copy_from_slice(&xmss::LEAVES.to_le_bytes());
    assert_eq!(sig.verify(&pk, b"m"), Err(Error::InvalidSignature));
}

/// Why `height` is in key derivation: the same seed's `winternitz` key is
/// not `xmss` leaf 0, so a signature under one cannot spend the other.
#[test]
fn instances_do_not_share_keys() {
    let m = b"shared seed";
    let once = winternitz::SecretKey(seed(5)).public_key();
    let tree = xmss::SecretKey::from_seed(seed(5));
    let parameter: [u8; PARAMETER_LENGTH] = tree.public_key().parameter().try_into().unwrap();
    assert_ne!(once.parameter(), &parameter);
    let leaf0 = crate::leaf_hash(
        &parameter,
        0,
        &seed::ends(&seed(5), &parameter, xmss::HEIGHT as u8, 0),
    );
    assert_ne!(once.node(), &leaf0);
    let sig = winternitz::SecretKey(seed(5)).sign_at(0, m).unwrap();
    let mut relabelled = tree.sign_at(0, m).unwrap();
    relabelled.0[4..4 + winternitz::SIGNATURE_LENGTH].copy_from_slice(&sig.0);
    assert_eq!(
        relabelled.verify(&tree.public_key(), m),
        Err(Error::InvalidSignature)
    );
}

#[test]
fn tampering_is_rejected() {
    let m = b"tamper";
    let sk = winternitz::SecretKey(seed(2));
    let pk = sk.public_key();
    let sig = sk.sign_at(0, m).unwrap();
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
    let sig = sk.sign_at(77, m).unwrap();
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

/// Random bytes as signatures, keys and messages, and every out-of-range
/// leaf: rejected, never a panic.
#[test]
fn garbage_is_rejected_without_panic() {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut fill = |bytes: &mut [u8]| {
        for b in bytes {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *b = state as u8;
        }
    };
    let mut pk = PublicKey([0; PUBLIC_KEY_LENGTH]);
    let mut once = winternitz::Signature([0; winternitz::SIGNATURE_LENGTH]);
    let mut tree = xmss::Signature([0; xmss::SIGNATURE_LENGTH]);
    let mut message = [0u8; 64];
    for i in 0..2000u32 {
        fill(&mut pk.0);
        fill(&mut once.0);
        fill(&mut tree.0);
        fill(&mut message);
        if i % 4 == 0 {
            tree.0[..4].copy_from_slice(&(i % 3 * 128).to_le_bytes());
        }
        assert_eq!(once.verify(&pk, &message), Err(Error::InvalidSignature));
        assert_eq!(tree.verify(&pk, &message), Err(Error::InvalidSignature));
    }
    for leaf in [xmss::LEAVES, xmss::LEAVES + 1, u32::MAX] {
        tree.0[..4].copy_from_slice(&leaf.to_le_bytes());
        assert_eq!(tree.verify(&pk, &message), Err(Error::InvalidSignature));
    }
}

fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(std::format!(
        "solana-winternitz-{name}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The signer's rules: one instance per file, no open without a file, the
/// last message repeated for free, and foreign, truncated, behind-the-chain
/// and exhausted files all refused.
#[test]
fn signer_owns_leaf_allocation() {
    use crate::{Signer, SignerError};
    type Tree = Signer<xmss::SecretKey>;
    let dir = temp_dir("signer");
    let path = dir.join("tree.key");

    let mut signer = Tree::create(&path, seed(8)).unwrap();
    let pk = signer.public_key();
    assert_eq!(signer.remaining(), xmss::LEAVES);
    assert!(matches!(
        Tree::create(&path, seed(8)),
        Err(SignerError::Locked)
    ));
    assert!(matches!(Tree::open(&path), Err(SignerError::Locked)));

    let a = signer.sign(b"a").unwrap();
    assert_eq!(a.leaf(), 0);
    assert_eq!(a.verify(&pk, b"a"), Ok(()));
    assert_eq!(signer.sign(b"a").unwrap(), a);
    assert_eq!(signer.remaining(), xmss::LEAVES - 1);
    assert_eq!(signer.sign(b"b").unwrap().leaf(), 1);
    drop(signer);

    assert!(matches!(
        Tree::create(&path, seed(8)),
        Err(SignerError::Exists)
    ));
    assert!(matches!(
        Signer::<winternitz::SecretKey>::open(&path),
        Err(SignerError::Corrupt)
    ));
    assert!(matches!(
        Tree::open(dir.join("none.key")),
        Err(SignerError::Missing)
    ));

    // Restart: continue at the record; an older message is a new leaf.
    let mut signer = Tree::open(&path).unwrap();
    assert_eq!(signer.next_leaf(), 2);
    assert_eq!(signer.sign(b"b").unwrap().leaf(), 1);
    assert_eq!(signer.sign(b"a").unwrap().leaf(), 2);
    drop(signer);
    assert!(matches!(
        Tree::open(&path).unwrap().floor(4),
        Err(SignerError::BelowFloor {
            next_leaf: 3,
            floor: 4
        })
    ));
    Tree::open(&path).unwrap().floor(3).unwrap();

    // Interrupted write: stale temp ignored, truncated record refused.
    std::fs::write(dir.join("tree.key.tmp"), b"garbage").unwrap();
    assert_eq!(Tree::open(&path).unwrap().next_leaf(), 3);
    let record = std::fs::read(&path).unwrap();
    std::fs::write(&path, &record[..record.len() - 1]).unwrap();
    assert!(matches!(Tree::open(&path), Err(SignerError::Corrupt)));

    // Last leaf: one more message, then only that one.
    let mut last = record.clone();
    last[34..38].copy_from_slice(&(xmss::LEAVES - 1).to_le_bytes());
    std::fs::write(&path, &last).unwrap();
    let mut signer = Tree::open(&path).unwrap();
    assert_eq!(signer.remaining(), 1);
    let z = signer.sign(b"z").unwrap();
    assert_eq!(z.leaf(), xmss::LEAVES - 1);
    assert_eq!(signer.remaining(), 0);
    assert!(matches!(signer.sign(b"y"), Err(SignerError::Exhausted)));
    assert_eq!(signer.sign(b"z").unwrap(), z);
    drop(signer);

    // The one-leaf instance.
    let path = dir.join("once.key");
    let mut once = Signer::<winternitz::SecretKey>::create(&path, seed(8)).unwrap();
    let s = once.sign(b"m").unwrap();
    assert_eq!(s.verify(&once.public_key(), b"m"), Ok(()));
    assert_eq!(once.sign(b"m").unwrap(), s);
    assert!(matches!(once.sign(b"n"), Err(SignerError::Exhausted)));
    drop(once);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Vector 1's key file after its one signature; the TypeScript tests open
/// the same bytes.
const KEY_FILE: &[u8] = include_bytes!("../tests/winternitz.key");

const VECTORS: &str = include_str!("../tests/vectors.json");

/// Both packages must reproduce this corpus byte for byte.
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
        assert_eq!(sk.sign_at(0, &field(v, "message")).unwrap(), signature);
        assert_eq!(signature.verify(&pk, &field(v, "message")), Ok(()));
    }
    let dir = temp_dir("fixture");
    std::fs::write(dir.join("once.key"), KEY_FILE).unwrap();
    let mut once = crate::Signer::<winternitz::SecretKey>::open(dir.join("once.key")).unwrap();
    let v = &ots[1];
    assert_eq!(
        once.public_key(),
        PublicKey(field(v, "public_key").try_into().unwrap())
    );
    assert_eq!(once.remaining(), 0);
    assert_eq!(
        once.sign(&field(v, "message")).unwrap().0.to_vec(),
        field(v, "signature")
    );
    drop(once);
    std::fs::remove_dir_all(&dir).unwrap();
    let mut keys: Vec<(Vec<u8>, xmss::SecretKey)> = Vec::new();
    for v in tree {
        let seed = field(v, "seed");
        if keys.iter().all(|(s, _)| *s != seed) {
            keys.push((
                seed.clone(),
                xmss::SecretKey::from_seed(seed.as_slice().try_into().unwrap()),
            ));
        }
        let sk = &keys.iter().find(|(s, _)| *s == seed).unwrap().1;
        let leaf = v["leaf"].as_u64().unwrap() as u32;
        let pk = PublicKey(field(v, "public_key").try_into().unwrap());
        let signature = xmss::Signature(field(v, "signature").try_into().unwrap());
        assert_eq!(sk.public_key(), pk);
        assert_eq!(sk.sign_at(leaf, &field(v, "message")).unwrap(), signature);
        assert_eq!(signature.verify(&pk, &field(v, "message")), Ok(()));
    }
}

/// `cargo test --lib regenerate_vectors -- --ignored` rewrites the corpus
/// and the key-file fixture.
#[test]
#[ignore]
fn regenerate_vectors() {
    // Three named cases, then messages at the message hash's block edges:
    // 11 and 12 bytes finish or overflow the first block after the 53-byte
    // prefix, 55 and 56 sit on the padding edge, 63 to 65 on the block.
    let named_seed = |prefix: &[u8], i: u8| {
        let mut s = [0u8; 32];
        s[..prefix.len()].copy_from_slice(prefix);
        s[31] = i;
        s
    };
    let mut cases: Vec<([u8; 32], u32, Vec<u8>)> = std::vec![
        (named_seed(b"", 0), 0, Vec::new()),
        (
            named_seed(b"blueshift", 1),
            1,
            b"rotate to 11111111111111111111111111111111".to_vec(),
        ),
        (
            named_seed(&[0x42; 32], 2),
            xmss::LEAVES - 1,
            std::vec![0u8; 100]
        ),
    ];
    for (j, n) in [11usize, 12, 55, 56, 63, 64, 65].into_iter().enumerate() {
        cases.push((
            [n as u8; 32],
            2 + j as u32,
            (0..n).map(|i| i as u8).collect(),
        ));
    }
    let ots: Vec<Value> = cases
        .iter()
        .map(|(seed, _, message)| {
            let sk = winternitz::SecretKey(*seed);
            serde_json::json!({
                "seed": to_hex(seed),
                "message": to_hex(message),
                "public_key": to_hex(&sk.public_key().0),
                "signature": to_hex(&sk.sign_at(0, message).unwrap().0),
            })
        })
        .collect();
    // One xmss key for every boundary case: the corpus pins leaves, not keys.
    let boundary = xmss::SecretKey::from_seed(seed(3));
    let tree: Vec<Value> = cases
        .iter()
        .enumerate()
        .map(|(i, (seed, leaf, message))| {
            let named;
            let sk = if i < 3 {
                named = xmss::SecretKey::from_seed(*seed);
                &named
            } else {
                &boundary
            };
            let seed = if i < 3 { *seed } else { self::seed(3) };
            serde_json::json!({
                "seed": to_hex(&seed),
                "leaf": leaf,
                "message": to_hex(message),
                "public_key": to_hex(&sk.public_key().0),
                "signature": to_hex(&sk.sign_at(*leaf, message).unwrap().0),
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
    let dir = temp_dir("regenerate");
    let path = dir.join("once.key");
    let mut once = crate::Signer::<winternitz::SecretKey>::create(&path, cases[1].0).unwrap();
    once.sign(&cases[1].2).unwrap();
    drop(once);
    std::fs::copy(
        &path,
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/winternitz.key"),
    )
    .unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}
