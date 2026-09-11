//! What is pinned: eqs. (13)–(16) and the grinding cost behind the
//! constants, the hash and syscall-id constants against their sources, the
//! signatures of the authors' implementation verified, both instances against `tests/vectors.json` and the
//! key-file fixture, every single-byte tamper rejected, garbage rejected
//! without panics, the signer's allocation rules, and its kernel lock
//! dying with its holder.
use num_bigint::BigUint;
use serde_json::Value;
use std::vec::Vec;

use crate::{
    CHAINS, ELEMENT_LENGTH, Error, MESSAGE_LENGTH, OneTime, PARAMETER_LENGTH, POSITIONS,
    PUBLIC_KEY_LENGTH, PublicKey, SALT_LENGTH, TARGET_SUM, hash, signing, syscalls, winternitz,
    xmss,
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

// Deliberately non-random public test data, never a production derivation.
fn key<K: OneTime>(tag: u8) -> K {
    let secrets: Vec<u8> = (0..K::LEAVES as usize * crate::ELEMENTS_LENGTH)
        .map(|i| (i % 251) as u8 ^ tag)
        .collect();
    K::new(&secrets, parameter(tag)).unwrap()
}

fn salt(parameter: &[u8], leaf: u32, message: &[u8; MESSAGE_LENGTH]) -> [u8; SALT_LENGTH] {
    let mut salt = [0; SALT_LENGTH];
    for counter in 0u32.. {
        salt[..4].copy_from_slice(&counter.to_le_bytes());
        if crate::encode(&salt, parameter, leaf, message).is_some() {
            return salt;
        }
    }
    unreachable!()
}

fn sign<K: OneTime>(key: &K, leaf: u32, message: &[u8; MESSAGE_LENGTH]) -> K::Signature {
    key.sign_at(
        leaf,
        message,
        &salt(key.public_key().parameter(), leaf, message),
    )
    .unwrap()
}

fn parameter(i: u8) -> [u8; PARAMETER_LENGTH] {
    [0x50 ^ i; PARAMETER_LENGTH]
}

/// A message from a short tag; what a program passes is a 32-byte digest.
fn message(tag: &[u8]) -> [u8; MESSAGE_LENGTH] {
    let mut m = [0u8; MESSAGE_LENGTH];
    m[..tag.len()].copy_from_slice(tag);
    m
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

/// Parameter Requirements 2 and 3, eqs. (13)–(16), at L = 2^8, K = 2^12,
/// and the numbers the authors' script prints for them; the target sum at
/// δ = 1.1 and its verifier and signer cost.
#[test]
fn parameters_satisfy_dkkw25_requirements() {
    let (kc, kq) = (128.0f64, 64.0f64);
    let (log5, log3, log12) = (5f64.log2(), 3f64.log2(), 12f64.log2());
    let (w, v, log_l, log_k) = (
        f64::from(POSITIONS).log2(),
        CHAINS as f64,
        xmss::HEIGHT as f64,
        f64::from(signing::MAX_TRIALS).log2(),
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
    // b-wagn/hashsig-parameters@95a80bc lower_bounds.py, same inputs, rounded
    // up to bytes as hash-sig's instantiations do.
    const { assert!(8 * ELEMENT_LENGTH >= 183 && 8 * PARAMETER_LENGTH >= 142 && 8 * SALT_LENGTH >= 168) };
    const { assert!(ELEMENT_LENGTH == 23 && PARAMETER_LENGTH == 18 && SALT_LENGTH == 21) };
    assert!(CHAINS * usize::from(w as u8) >= 138);

    // T = ⌈1.1 · 36 · 15 / 2⌉ = 297, hash-sig's `Off10`: 243 verifier steps,
    // one accepted digest in 96–128 uniform tries, all 4096 miss once in e^36.
    assert_eq!(
        usize::from(TARGET_SUM),
        (1.1f64 * 36.0 * 15.0 / 2.0).ceil() as usize
    );
    let steps = CHAINS * usize::from(POSITIONS - 1) - usize::from(TARGET_SUM);
    assert_eq!(steps, 243);
    let size = layer_size(CHAINS, POSITIONS.into(), steps);
    let trials = BigUint::from(POSITIONS).pow(CHAINS as u32) / size;
    assert!(trials >= BigUint::from(96u32) && trials <= BigUint::from(128u32));
    assert_eq!(PUBLIC_KEY_LENGTH, 41);
    assert_eq!(winternitz::SIGNATURE_LENGTH, 849);
    assert_eq!(xmss::SIGNATURE_LENGTH, 1037);
}

/// The host hash is Keccak-256, padding byte 0x01, not FIPS SHA3-256: the
/// Ethereum values of the empty string and "abc".
#[test]
fn hash_is_keccak_256() {
    assert_eq!(
        to_hex(&hash::hashv(&[b""])),
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    );
    assert_eq!(
        to_hex(&hash::hashv(&[b"a", b"bc"])),
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    );
}

/// `sys_hash` is agave's murmur3: `sol_sha256` per solana-define-syscall,
/// `sol_sha512` per solana-ecvrf. `sol_keccak256`'s id is what the SBPF
/// test exercises.
#[test]
fn syscall_ids_match_published_values() {
    assert_eq!(syscalls::sys_hash("sol_sha256"), 0x11f49d86);
    assert_eq!(syscalls::sys_hash("sol_sha512"), 0x9229cdcc);
}

/// Independently generated hash-sig signatures remain valid. Key sampling
/// changes neither the wire format nor verification.
#[test]
fn reference_signatures_verify() {
    let vectors: Value = serde_json::from_str(include_str!("../tests/hash-sig.json")).unwrap();
    let field = |v: &Value, k: &str| hex(v[k].as_str().unwrap());
    let pk = PublicKey(field(&vectors, "public_key").try_into().unwrap());
    let cases = vectors["signatures"].as_array().unwrap();
    assert!(!cases.is_empty());
    for v in cases {
        let leaf = v["leaf"].as_u64().unwrap() as u32;
        let message: [u8; MESSAGE_LENGTH] = field(v, "message").try_into().unwrap();
        let mut bytes = leaf.to_be_bytes().to_vec();
        bytes.extend(field(v, "salt"));
        bytes.extend(field(v, "elements"));
        bytes.extend(field(v, "path"));
        let sig = xmss::Signature(bytes.try_into().unwrap());
        assert_eq!(sig.verify(&pk, &message), Ok(()));
        let mut other = message;
        other[0] ^= 1;
        assert_eq!(sig.verify(&pk, &other), Err(Error::InvalidSignature));
    }
}

#[test]
fn winternitz_roundtrip() {
    let messages = [message(b""), message(b"hello"), [0x55; 32], [0xff; 32]];
    for (i, m) in messages.iter().enumerate() {
        let sk = key::<winternitz::SecretKey>(i as u8);
        let pk = sk.public_key();
        let sig = sign(&sk, 0, m);
        assert_eq!(sig.verify(&pk, m), Ok(()));
        let other = key::<winternitz::SecretKey>(9).public_key();
        assert_eq!(sig.verify(&other, m), Err(Error::InvalidSignature));
        assert!(sk.sign_at(1, m, &[0; SALT_LENGTH]).is_none());
        assert_eq!(
            sig.verify(&pk, &message(b"other")),
            Err(Error::InvalidSignature)
        );
    }
}

#[test]
fn xmss_roundtrip_every_leaf() {
    let sk = key::<xmss::SecretKey>(3);
    let pk = sk.public_key();
    let other = key::<xmss::SecretKey>(4).public_key();
    for leaf in 0..xmss::LEAVES {
        let m = message(&leaf.to_le_bytes());
        let sig = sign(&sk, leaf, &m);
        assert_eq!(sig.leaf(), leaf);
        assert_eq!(sig.verify(&pk, &m), Ok(()));
        assert_eq!(sig.verify(&other, &m), Err(Error::InvalidSignature));
        assert_eq!(
            sig.verify(&pk, &message(b"other")),
            Err(Error::InvalidSignature)
        );
    }
    assert!(
        sk.sign_at(xmss::LEAVES, &message(b""), &[0; SALT_LENGTH])
            .is_none()
    );
    // Relabelled to another leaf: the path no longer closes.
    let m = message(b"m");
    let mut sig = sign(&sk, 5, &m);
    sig.0[..4].copy_from_slice(&6u32.to_be_bytes());
    assert_eq!(sig.verify(&pk, &m), Err(Error::InvalidSignature));
    sig.0[..4].copy_from_slice(&xmss::LEAVES.to_be_bytes());
    assert_eq!(sig.verify(&pk, &m), Err(Error::InvalidSignature));
}

#[test]
fn tampering_is_rejected() {
    let m = message(b"tamper");
    let sk = key::<winternitz::SecretKey>(2);
    let pk = sk.public_key();
    let sig = sign(&sk, 0, &m);
    for i in 0..winternitz::SIGNATURE_LENGTH {
        let mut t = sig;
        t.0[i] ^= 1;
        assert_eq!(t.verify(&pk, &m), Err(Error::InvalidSignature), "byte {i}");
    }
    for i in 0..PUBLIC_KEY_LENGTH {
        let mut p = pk;
        p.0[i] ^= 1;
        assert_eq!(sig.verify(&p, &m), Err(Error::InvalidSignature));
    }
    for i in 0..MESSAGE_LENGTH {
        let mut t = m;
        t[i] ^= 1;
        assert_eq!(sig.verify(&pk, &t), Err(Error::InvalidSignature));
    }

    let sk = key::<xmss::SecretKey>(2);
    let pk = sk.public_key();
    let sig = sign(&sk, 77, &m);
    for i in 0..xmss::SIGNATURE_LENGTH {
        let mut t = sig;
        t.0[i] ^= 1;
        assert_eq!(t.verify(&pk, &m), Err(Error::InvalidSignature), "byte {i}");
    }
    for i in 0..PUBLIC_KEY_LENGTH {
        let mut p = pk;
        p.0[i] ^= 1;
        assert_eq!(sig.verify(&p, &m), Err(Error::InvalidSignature));
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
    let mut message = [0u8; MESSAGE_LENGTH];
    for i in 0..2000u32 {
        fill(&mut pk.0);
        fill(&mut once.0);
        fill(&mut tree.0);
        fill(&mut message);
        if i % 4 == 0 {
            tree.0[..4].copy_from_slice(&(i % 3 * 128).to_be_bytes());
        }
        assert_eq!(once.verify(&pk, &message), Err(Error::InvalidSignature));
        assert_eq!(tree.verify(&pk, &message), Err(Error::InvalidSignature));
    }
    for leaf in [xmss::LEAVES, xmss::LEAVES + 1, u32::MAX] {
        tree.0[..4].copy_from_slice(&leaf.to_be_bytes());
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

/// Key-file offset of the next leaf: version, height, parameter.
const NEXT_LEAF: usize = 2 + PARAMETER_LENGTH;

/// The signer's rules: one instance per file, no open without a file, the
/// last message repeated for free, and foreign, truncated, behind-the-chain
/// and exhausted files all refused.
#[test]
fn signer_owns_leaf_allocation() {
    use crate::{Signer, SignerError};
    type Tree = Signer<xmss::SecretKey>;
    let dir = temp_dir("signer");
    let path = dir.join("tree.key");
    let (a, b, y, z) = (message(b"a"), message(b"b"), message(b"y"), message(b"z"));

    let mut signer = Tree::create(&path).unwrap();
    let pk = signer.public_key();
    assert_eq!(signer.remaining(), xmss::LEAVES);
    assert!(matches!(Tree::create(&path), Err(SignerError::Locked)));
    assert!(matches!(Tree::open(&path), Err(SignerError::Locked)));

    let sig_a = signer.sign(&a).unwrap();
    assert_eq!(sig_a.leaf(), 0);
    assert_eq!(sig_a.verify(&pk, &a), Ok(()));
    assert_eq!(signer.sign(&a).unwrap(), sig_a);
    assert_eq!(signer.remaining(), xmss::LEAVES - 1);
    let sig_b = signer.sign(&b).unwrap();
    assert_eq!(sig_b.leaf(), 1);
    drop(signer);

    assert!(matches!(Tree::create(&path), Err(SignerError::Exists)));
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
    assert_eq!(signer.sign(&b).unwrap(), sig_b);
    assert_eq!(signer.sign(&a).unwrap().leaf(), 2);
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

    // The lock is the kernel's, not the sidecar's existence or content.
    let lock = dir.join("tree.key.lock");
    std::fs::write(&lock, "anything").unwrap();
    drop(Tree::open(&path).unwrap());
    assert!(lock.exists());
    let record = std::fs::read(&path).unwrap();
    std::fs::write(&path, &record[..record.len() - 1]).unwrap();
    assert!(matches!(Tree::open(&path), Err(SignerError::Corrupt)));
    // A message flag with no spent leaf contradicts itself.
    let mut contradiction = record.clone();
    contradiction[NEXT_LEAF..NEXT_LEAF + 4].copy_from_slice(&0u32.to_be_bytes());
    std::fs::write(&path, &contradiction).unwrap();
    assert!(matches!(Tree::open(&path), Err(SignerError::Corrupt)));

    // Last leaf: one more message, then only that one.
    let mut last = record.clone();
    last[NEXT_LEAF..NEXT_LEAF + 4].copy_from_slice(&(xmss::LEAVES - 1).to_be_bytes());
    let accepted = salt(
        &last[2..20],
        xmss::LEAVES - 2,
        &last[25..57].try_into().unwrap(),
    );
    last[57..78].copy_from_slice(&accepted);
    std::fs::write(&path, &last).unwrap();
    let mut signer = Tree::open(&path).unwrap();
    assert_eq!(signer.remaining(), 1);
    let sig_z = signer.sign(&z).unwrap();
    assert_eq!(sig_z.leaf(), xmss::LEAVES - 1);
    assert_eq!(signer.remaining(), 0);
    assert!(matches!(signer.sign(&y), Err(SignerError::Exhausted)));
    assert_eq!(signer.sign(&z).unwrap(), sig_z);
    drop(signer);

    // The one-leaf instance.
    let path = dir.join("once.key");
    let mut once = Signer::<winternitz::SecretKey>::create(&path).unwrap();
    let s = once.sign(&a).unwrap();
    assert_eq!(s.verify(&once.public_key(), &a), Ok(()));
    assert_eq!(once.sign(&a).unwrap(), s);
    assert!(matches!(once.sign(&b), Err(SignerError::Exhausted)));
    drop(once);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The child of `lock_dies_with_its_holder`: hold the key file named by
/// the environment until killed.
#[test]
fn hold_key_file() {
    let Ok(path) = std::env::var("SOLANA_WINTERNITZ_HOLD") else {
        return;
    };
    let _held = crate::Signer::<winternitz::SecretKey>::open(&path).unwrap();
    std::println!("HOLDING");
    loop {
        std::thread::sleep(core::time::Duration::from_secs(1));
    }
}

/// The kernel holds the lock for the process that took it and releases it
/// when that process dies: a file held by another process is refused, and
/// opens after the process is killed.
#[test]
fn lock_dies_with_its_holder() {
    use crate::{Signer, SignerError};
    use std::io::BufRead;
    type Once = Signer<winternitz::SecretKey>;
    let dir = temp_dir("holder");
    let path = dir.join("once.key");
    drop(Once::create(&path).unwrap());
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "tests::hold_key_file", "--nocapture"])
        .env("SOLANA_WINTERNITZ_HOLD", &path)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = std::io::BufReader::new(child.stdout.take().unwrap()).lines();
    assert!(lines.any(|line| line.unwrap() == "HOLDING"));
    assert!(matches!(Once::open(&path), Err(SignerError::Locked)));
    child.kill().unwrap();
    child.wait().unwrap();
    drop(Once::open(&path).unwrap());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Historical Rust/TypeScript wire fixtures; no legacy key derivation is retained.
#[test]
fn historical_vectors_verify() {
    let vectors: Value = serde_json::from_str(include_str!("../tests/vectors.json")).unwrap();
    let field = |v: &Value, k: &str| hex(v[k].as_str().unwrap());
    for v in vectors["winternitz"].as_array().unwrap() {
        let pk = PublicKey(field(v, "public_key").try_into().unwrap());
        let message = field(v, "message").try_into().unwrap();
        let sig = winternitz::Signature(field(v, "signature").try_into().unwrap());
        assert_eq!(sig.verify(&pk, &message), Ok(()));
    }
    for v in vectors["xmss"].as_array().unwrap() {
        let pk = PublicKey(field(v, "public_key").try_into().unwrap());
        let message = field(v, "message").try_into().unwrap();
        let sig = xmss::Signature(field(v, "signature").try_into().unwrap());
        assert_eq!(sig.verify(&pk, &message), Ok(()));
    }
}

/// Explicit test chain starts and accepted salts pin signing in both languages.
#[test]
fn sampled_vectors_are_reproduced() {
    let vectors: Value = serde_json::from_str(include_str!("../tests/sampled.json")).unwrap();
    let sk = key::<xmss::SecretKey>(7);
    let pk = PublicKey(
        hex(vectors["public_key"].as_str().unwrap())
            .try_into()
            .unwrap(),
    );
    assert_eq!(sk.public_key(), pk);
    for v in vectors["signatures"].as_array().unwrap() {
        let leaf = v["leaf"].as_u64().unwrap() as u32;
        let m = message(&leaf.to_le_bytes());
        let sig = xmss::Signature(hex(v["signature"].as_str().unwrap()).try_into().unwrap());
        assert_eq!(sign(&sk, leaf, &m), sig);
        assert_eq!(sig.verify(&pk, &m), Ok(()));
    }
    let dir = temp_dir("fixture");
    let path = dir.join("once.key");
    std::fs::write(&path, include_bytes!("../tests/winternitz.key")).unwrap();
    let before = std::fs::read(&path).unwrap();
    let mut once = crate::Signer::<winternitz::SecretKey>::open(&path).unwrap();
    let m = before[25..57].try_into().unwrap();
    let expected = hex(vectors["one_time_signature"].as_str().unwrap());
    assert_eq!(once.sign(&m).unwrap().0.as_slice(), expected);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    drop(once);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn raw_keys_require_all_chain_starts() {
    assert!(winternitz::SecretKey::new(&[0; 32], parameter(0)).is_none());
    assert!(xmss::SecretKey::new(&[0; 828], parameter(0)).is_none());
    let key = key::<winternitz::SecretKey>(1);
    let m = message(b"bad salt");
    let bad = (0u32..)
        .find_map(|counter| {
            let mut salt = [0; SALT_LENGTH];
            salt[..4].copy_from_slice(&counter.to_le_bytes());
            crate::encode(&salt, key.public_key().parameter(), 0, &m)
                .is_none()
                .then_some(salt)
        })
        .unwrap();
    assert!(key.sign_at(0, &m, &bad).is_none());
}

/// Regenerate explicit-input vectors and the small shared state fixture.
#[test]
#[ignore]
fn regenerate_sampled_vectors() {
    let sk = key::<xmss::SecretKey>(7);
    let signatures: Vec<Value> = [0, 1, 127, 128, 255u32].into_iter().map(|leaf| {
        serde_json::json!({ "leaf": leaf, "signature": to_hex(&sign(&sk, leaf, &message(&leaf.to_le_bytes())).0) })
    }).collect();
    let dir = temp_dir("regenerate");
    let path = dir.join("once.key");
    let mut once = crate::Signer::<winternitz::SecretKey>::create(&path).unwrap();
    let sig = once.sign(&message(b"sampled fixture")).unwrap();
    drop(once);
    std::fs::copy(&path, "tests/winternitz.key").unwrap();
    std::fs::write("tests/sampled.json", serde_json::to_string_pretty(&serde_json::json!({
        "test_inputs": "Public test data only: chain-start byte i = (i mod 251) xor 7; P = 18 bytes of 0x57; message = leaf LE32 padded to 32 bytes; salt = first accepted counter LE32 padded to 21 bytes.",
        "public_key": to_hex(&sk.public_key().0), "signatures": signatures,
        "one_time_signature": to_hex(&sig.0),
    })).unwrap() + "\n").unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}
