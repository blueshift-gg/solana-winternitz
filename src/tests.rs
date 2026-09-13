use crate::hazmat::{self, OneTime};

use num_bigint::BigUint;
use serde_json::Value;
use std::vec::Vec;

use crate::{
    CHAINS, ELEMENT_LENGTH, Error, MESSAGE_LEN, PARAMETER_LEN, POSITIONS, PUBLIC_KEY_LEN,
    SALT_LENGTH, TARGET_SUM, VerifyingKey, hash, signing, syscalls, winternitz, xmss,
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
    K::from_secrets(&secrets, parameter(tag)).unwrap()
}

fn salt(parameter: &[u8], leaf: u32, message: &[u8; MESSAGE_LEN]) -> [u8; SALT_LENGTH] {
    let mut salt = [0; SALT_LENGTH];
    for counter in 0u32.. {
        salt[..4].copy_from_slice(&counter.to_le_bytes());
        if crate::encode(&salt, parameter, leaf, message).is_some() {
            return salt;
        }
    }
    unreachable!()
}

fn sign<K: OneTime>(key: &K, leaf: u32, message: &[u8; MESSAGE_LEN]) -> K::Signature {
    key.sign_at_with_salt(
        leaf,
        message,
        &salt(key.verifying_key().parameter(), leaf, message),
    )
    .unwrap()
}

fn parameter(i: u8) -> [u8; PARAMETER_LEN] {
    [0x50 ^ i; PARAMETER_LEN]
}

/// Pad a test tag to the fixed message length.
fn message(tag: &[u8]) -> [u8; MESSAGE_LEN] {
    let mut m = [0u8; MESSAGE_LEN];
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

/// Parameter Requirements 2 and 3, eqs. (13)–(16), with L = 256 and K = 4096.
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
    assert!((8 * PARAMETER_LEN) as f64 >= (kc + log5 + 3.0).max(2.0 * (kq + log5 + 2.0) + 5.0));
    // b-wagn/hashsig-parameters@95a80bc lower_bounds.py, same inputs, rounded
    // up to bytes as hash-sig's instantiations do.
    const { assert!(8 * ELEMENT_LENGTH >= 183 && 8 * PARAMETER_LEN >= 142 && 8 * SALT_LENGTH >= 168) };
    const { assert!(ELEMENT_LENGTH == 23 && PARAMETER_LEN == 18 && SALT_LENGTH == 21) };
    assert!(CHAINS * usize::from(w as u8) >= 138);

    // §8 target and Lemma 7's coefficient give verifier work and acceptance rate.
    assert_eq!(
        usize::from(TARGET_SUM),
        (1.1f64 * 36.0 * 15.0 / 2.0).ceil() as usize
    );
    let steps = CHAINS * usize::from(POSITIONS - 1) - usize::from(TARGET_SUM);
    assert_eq!(steps, 243);
    let size = layer_size(CHAINS, POSITIONS.into(), steps);
    let trials = BigUint::from(POSITIONS).pow(CHAINS as u32) / size;
    assert!(trials >= BigUint::from(96u32) && trials <= BigUint::from(128u32));
    assert_eq!(PUBLIC_KEY_LEN, 41);
    assert_eq!(winternitz::SIGNATURE_LEN, 849);
    assert_eq!(xmss::SIGNATURE_LEN, 1037);
}

/// Keccak known answers also check concatenation of hash-input slices.
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

/// An independent implementation checks the hash layouts and verification path.
#[test]
fn reference_signatures_verify() {
    let vectors: Value = serde_json::from_str(include_str!("../tests/hash-sig.json")).unwrap();
    let field = |v: &Value, k: &str| hex(v[k].as_str().unwrap());
    let pk = VerifyingKey::from_bytes(&(field(&vectors, "public_key").try_into().unwrap()));
    let cases = vectors["signatures"].as_array().unwrap();
    assert!(!cases.is_empty());
    for v in cases {
        let leaf = v["leaf"].as_u64().unwrap() as u32;
        let message: [u8; MESSAGE_LEN] = field(v, "message").try_into().unwrap();
        let mut bytes = leaf.to_be_bytes().to_vec();
        bytes.extend(field(v, "salt"));
        bytes.extend(field(v, "elements"));
        bytes.extend(field(v, "path"));
        let sig = xmss::Signature::from_bytes(&(bytes.try_into().unwrap()));
        assert_eq!(pk.verify(&message, &sig), Ok(()));
        let mut other = message;
        other[0] ^= 1;
        assert_eq!(pk.verify(&other, &sig), Err(Error::InvalidSignature));
    }
}

#[test]
fn xmss_roundtrip_every_leaf() {
    let sk = key::<hazmat::xmss::SecretKey>(3);
    let pk = sk.verifying_key();
    for leaf in 0..xmss::LEAVES {
        let m = message(&leaf.to_le_bytes());
        let sig = sign(&sk, leaf, &m);
        assert_eq!(sig.leaf(), leaf);
        assert_eq!(pk.verify(&m, &sig), Ok(()));
    }
    for leaf in [xmss::LEAVES, xmss::LEAVES + 1, u32::MAX] {
        let m = message(b"bounds");
        assert!(sk.sign_at_with_salt(leaf, &m, &[0; SALT_LENGTH]).is_none());
        let mut sig = xmss::Signature::from_bytes(&([0; xmss::SIGNATURE_LEN]));
        sig.0[..4].copy_from_slice(&leaf.to_be_bytes());
        assert_eq!(pk.verify(&m, &sig), Err(Error::InvalidSignature));
    }
}

#[test]
fn tampering_is_rejected() {
    let m = message(b"tamper");
    let sk = key::<hazmat::winternitz::SecretKey>(2);
    let pk = sk.verifying_key();
    let sig = sign(&sk, 0, &m);
    for i in 0..winternitz::SIGNATURE_LEN {
        let mut t = sig;
        t.0[i] ^= 1;
        assert_eq!(pk.verify(&m, &t), Err(Error::InvalidSignature), "byte {i}");
    }
    for i in 0..PUBLIC_KEY_LEN {
        let mut p = pk;
        p.0[i] ^= 1;
        assert_eq!(p.verify(&m, &sig), Err(Error::InvalidSignature));
    }
    for i in 0..MESSAGE_LEN {
        let mut t = m;
        t[i] ^= 1;
        assert_eq!(pk.verify(&t, &sig), Err(Error::InvalidSignature));
    }

    let sk = key::<hazmat::xmss::SecretKey>(2);
    let pk = sk.verifying_key();
    let sig = sign(&sk, 77, &m);
    for i in 0..xmss::SIGNATURE_LEN {
        let mut t = sig;
        t.0[i] ^= 1;
        assert_eq!(pk.verify(&m, &t), Err(Error::InvalidSignature), "byte {i}");
    }
    for i in 0..PUBLIC_KEY_LEN {
        let mut p = pk;
        p.0[i] ^= 1;
        assert_eq!(p.verify(&m, &sig), Err(Error::InvalidSignature));
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
const NEXT_LEAF: usize = 2 + PARAMETER_LEN;

#[test]
fn signer_owns_leaf_allocation() {
    use crate::SigningError;
    type Tree = xmss::SigningKey;
    let dir = temp_dir("signer");
    let path = dir.join("tree.key");
    let (a, b, y, z) = (message(b"a"), message(b"b"), message(b"y"), message(b"z"));

    let mut signer = Tree::create(&path).unwrap();
    let pk = signer.verifying_key();
    assert_eq!(signer.remaining(), xmss::LEAVES);
    assert!(matches!(Tree::create(&path), Err(SigningError::Locked)));
    assert!(matches!(Tree::open(&path), Err(SigningError::Locked)));

    let sig_a = signer.sign(&a).unwrap();
    assert_eq!(sig_a.leaf(), 0);
    assert_eq!(pk.verify(&a, &sig_a), Ok(()));
    assert_eq!(signer.sign(&a).unwrap(), sig_a);
    assert_eq!(signer.next_leaf(), 1);

    assert_eq!(signer.remaining(), xmss::LEAVES - 1);
    let sig_b = signer.sign(&b).unwrap();
    assert_eq!(sig_b.leaf(), 1);
    drop(signer);

    assert!(matches!(Tree::create(&path), Err(SigningError::Exists)));
    assert!(matches!(
        winternitz::SigningKey::open(&path),
        Err(SigningError::Corrupt)
    ));
    assert!(matches!(
        Tree::open(dir.join("none.key")),
        Err(SigningError::Missing)
    ));

    // Restart: continue at the record; an older message is a new leaf.
    let mut signer = Tree::open(&path).unwrap();
    assert_eq!(signer.next_leaf(), 2);
    assert_eq!(signer.sign(&b).unwrap(), sig_b);
    assert_eq!(signer.sign(&a).unwrap().leaf(), 2);
    drop(signer);
    assert!(matches!(
        Tree::open(&path).unwrap().require_next_leaf_at_least(4),
        Err(SigningError::LeafBelowMinimum {
            next_leaf: 3,
            minimum: 4
        })
    ));
    Tree::open(&path)
        .unwrap()
        .require_next_leaf_at_least(3)
        .unwrap();

    // An uncommitted temporary file must not advance state.
    std::fs::write(dir.join("tree.key.tmp"), b"garbage").unwrap();
    assert_eq!(Tree::open(&path).unwrap().next_leaf(), 3);

    // A released sidecar remains reusable regardless of its contents.
    let lock = dir.join("tree.key.lock");
    std::fs::write(&lock, "anything").unwrap();
    drop(Tree::open(&path).unwrap());
    assert!(lock.exists());
    let record = std::fs::read(&path).unwrap();
    std::fs::write(&path, &record[..record.len() - 1]).unwrap();
    assert!(matches!(Tree::open(&path), Err(SigningError::Corrupt)));

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
    assert!(matches!(signer.sign(&y), Err(SigningError::Exhausted)));
    assert_eq!(signer.sign(&z).unwrap(), sig_z);
    drop(signer);

    // The one-leaf instance.
    let path = dir.join("once.key");
    let mut once = winternitz::SigningKey::create(&path).unwrap();
    let s = once.sign(&a).unwrap();
    assert_eq!(once.verifying_key().verify(&a, &s), Ok(()));
    assert_eq!(once.sign(&a).unwrap(), s);
    assert!(matches!(once.sign(&b), Err(SigningError::Exhausted)));
    drop(once);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Subprocess entry point for the lock-recovery test.
#[test]
fn hold_key_file() {
    let Ok(path) = std::env::var("SOLANA_WINTERNITZ_HOLD") else {
        return;
    };
    let _held = crate::winternitz::SigningKey::open(&path).unwrap();
    std::println!("HOLDING");
    loop {
        std::thread::sleep(core::time::Duration::from_secs(1));
    }
}

#[test]
fn lock_dies_with_its_holder() {
    use crate::SigningError;
    use std::io::BufRead;
    type Once = winternitz::SigningKey;
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
    assert!(matches!(Once::open(&path), Err(SigningError::Locked)));
    child.kill().unwrap();
    child.wait().unwrap();
    drop(Once::open(&path).unwrap());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Explicit test chain starts and accepted salts pin signing in both languages.
#[test]
fn sampled_vectors_are_reproduced() {
    let vectors: Value = serde_json::from_str(include_str!("../tests/sampled.json")).unwrap();
    let sk = key::<hazmat::xmss::SecretKey>(7);
    let pk = VerifyingKey::from_bytes(
        &(hex(vectors["public_key"].as_str().unwrap())
            .try_into()
            .unwrap()),
    );
    assert_eq!(sk.verifying_key(), pk);
    for v in vectors["signatures"].as_array().unwrap() {
        let leaf = v["leaf"].as_u64().unwrap() as u32;
        let m = message(&leaf.to_le_bytes());
        let sig = xmss::Signature::from_bytes(
            &(hex(v["signature"].as_str().unwrap()).try_into().unwrap()),
        );
        assert_eq!(sign(&sk, leaf, &m), sig);
        assert_eq!(pk.verify(&m, &sig), Ok(()));
    }
    let dir = temp_dir("fixture");
    let path = dir.join("once.key");
    std::fs::write(&path, include_bytes!("../tests/winternitz.key")).unwrap();
    let before = std::fs::read(&path).unwrap();
    let mut once = crate::winternitz::SigningKey::open(&path).unwrap();
    let m = before[25..57].try_into().unwrap();
    let expected = hex(vectors["one_time_signature"].as_str().unwrap());
    assert_eq!(once.sign(&m).unwrap().0.as_slice(), expected);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    drop(once);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn raw_keys_require_all_chain_starts() {
    assert!(hazmat::winternitz::SecretKey::from_secrets(&[0; 32], parameter(0)).is_err());
    assert!(hazmat::xmss::SecretKey::from_secrets(&[0; 828], parameter(0)).is_err());
    let key = key::<hazmat::winternitz::SecretKey>(1);
    let m = message(b"bad salt");
    assert!(key.sign_at_with_salt(1, &m, &[0; SALT_LENGTH]).is_none());
    let bad = (0u32..)
        .find_map(|counter| {
            let mut salt = [0; SALT_LENGTH];
            salt[..4].copy_from_slice(&counter.to_le_bytes());
            crate::encode(&salt, key.verifying_key().parameter(), 0, &m)
                .is_none()
                .then_some(salt)
        })
        .unwrap();
    assert!(key.sign_at_with_salt(0, &m, &bad).is_none());
}

/// Regenerate explicit-input vectors and the small shared state fixture.
#[test]
#[ignore]
fn regenerate_sampled_vectors() {
    let sk = key::<hazmat::xmss::SecretKey>(7);
    // Complementary leaf bits exercise both path orientations at every level.
    let signatures: Vec<Value> = [127, 128u32].into_iter().map(|leaf| {
        serde_json::json!({ "leaf": leaf, "signature": to_hex(&sign(&sk, leaf, &message(&leaf.to_le_bytes())).0) })
    }).collect();
    let dir = temp_dir("regenerate");
    let path = dir.join("once.key");
    let mut once = crate::winternitz::SigningKey::create(&path).unwrap();
    let sig = once.sign(&message(b"sampled fixture")).unwrap();
    drop(once);
    std::fs::copy(&path, "tests/winternitz.key").unwrap();
    std::fs::write("tests/sampled.json", serde_json::to_string_pretty(&serde_json::json!({
        "test_inputs": "Public test data only: chain-start byte i = (i mod 251) xor 7; P = 18 bytes of 0x57; message = leaf LE32 padded to 32 bytes; salt = first accepted counter LE32 padded to 21 bytes.",
        "public_key": to_hex(&sk.verifying_key().0), "signatures": signatures,
        "one_time_signature": to_hex(&sig.0),
    })).unwrap() + "\n").unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn sdk_encoding_contract() {
    let key = VerifyingKey::from_bytes(&[7; VerifyingKey::BYTE_LEN]);
    assert_eq!(
        VerifyingKey::try_from(key.as_bytes().as_slice()).unwrap(),
        key
    );
    assert_eq!(VerifyingKey::ref_from_bytes(key.as_bytes()).unwrap(), &key);
    assert_eq!(
        VerifyingKey::from_slice(&[0; 40]),
        Err(Error::InvalidLength)
    );
    let signature = winternitz::Signature::from_bytes(&[0; winternitz::Signature::BYTE_LEN]);
    assert_eq!(
        winternitz::Signature::from_slice(signature.as_bytes()).unwrap(),
        signature
    );
    assert_eq!(
        key.verify(&[0; MESSAGE_LEN], &signature),
        Err(Error::InvalidSignature)
    );
    assert_eq!(
        xmss::Signature::from_slice(&[0; 1036]),
        Err(Error::InvalidLength)
    );
}
