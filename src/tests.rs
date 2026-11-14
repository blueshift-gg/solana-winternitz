use crate::hazmat::{self, OneTime, Secrets};

use num_bigint::BigUint;
use serde_json::Value;
use std::vec::Vec;

use crate::{
    Error, MESSAGE_LEN, PARAMETER_LEN, PUBLIC_KEY_LEN, SIGNATURE_LEN, Signature, SigningKey,
    VerifyingKey, hash,
    primitives::{
        self, CHAINS, ELEMENT_LEN, ELEMENTS_LEN, Node, POSITIONS, ROLE_CHAIN, ROLE_MESSAGE,
        ROLE_TREE, SALT_LEN, TARGET_SUM,
    },
    syscalls,
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
    let secrets: Vec<u8> = (0..K::LEAVES as usize * ELEMENTS_LEN)
        .map(|i| (i % 251) as u8 ^ tag)
        .collect();
    K::from_secrets(&secrets, parameter(tag)).unwrap()
}

fn salt(parameter: &[u8], leaf: u32, message: &[u8; MESSAGE_LEN]) -> [u8; SALT_LEN] {
    let mut salt = [0; SALT_LEN];
    for counter in 0u32.. {
        salt[..4].copy_from_slice(&counter.to_le_bytes());
        if primitives::encode(&salt, parameter, leaf, message).is_some() {
            return salt;
        }
    }
    unreachable!()
}

fn sign<K: OneTime>(key: &K, leaf: u32, message: &[u8; MESSAGE_LEN]) -> K::Signature {
    key.sign_at_with_salt(leaf, message, &salt(key.parameter(), leaf, message))
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

/// A 256-leaf instance for the key-file tests, without a Merkle tree: its
/// public key lists every leaf. `solana-xmss` is the real one.
pub(crate) struct Tree(Secrets);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TreeKey {
    pub(crate) parameter: [u8; PARAMETER_LEN],
    leaves: [Node; 256],
}

impl AsRef<[u8]> for TreeKey {
    fn as_ref(&self) -> &[u8] {
        &self.parameter
    }
}

impl TreeKey {
    pub(crate) fn verify(
        &self,
        message: &[u8; MESSAGE_LEN],
        signature: &TreeSignature,
    ) -> Result<(), Error> {
        let leaf = primitives::leaf(
            &self.parameter,
            signature.leaf,
            &signature.salt,
            &signature.elements,
            message,
        );
        match leaf == self.leaves.get(signature.leaf as usize).copied() {
            true => Ok(()),
            false => Err(Error::InvalidSignature),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TreeSignature {
    leaf: u32,
    salt: [u8; SALT_LEN],
    elements: [u8; ELEMENTS_LEN],
}

impl TreeSignature {
    fn leaf(&self) -> u32 {
        self.leaf
    }
}

impl OneTime for Tree {
    type Signature = TreeSignature;
    type VerifyingKey = TreeKey;
    const LEAVES: u32 = 256;
    const HEIGHT: u8 = 8;

    fn from_secrets(secrets: &[u8], parameter: [u8; PARAMETER_LEN]) -> Result<Self, Error> {
        Secrets::from_bytes(Self::LEAVES, secrets, parameter).map(Self)
    }
    fn secrets(&self) -> &[u8] {
        self.0.as_bytes()
    }
    fn parameter(&self) -> &[u8; PARAMETER_LEN] {
        self.0.parameter()
    }
    fn verifying_key(&self) -> TreeKey {
        TreeKey {
            parameter: *self.0.parameter(),
            leaves: core::array::from_fn(|leaf| self.0.leaf(leaf as u32)),
        }
    }
    fn sign_at_with_salt(
        &self,
        leaf: u32,
        message: &[u8; MESSAGE_LEN],
        salt: &[u8; SALT_LEN],
    ) -> Option<TreeSignature> {
        Some(TreeSignature {
            leaf,
            salt: *salt,
            elements: self.0.sign(leaf, message, salt)?,
        })
    }
}

pub(crate) type TreeSigningKey = hazmat::SigningKey<Tree>;

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
/// The parameters are sized for `solana-xmss`'s 256 leaves; one leaf needs less.
#[test]
fn parameters_satisfy_dkkw25_requirements() {
    let (kc, kq) = (128.0f64, 64.0f64);
    let (log5, log3, log12) = (5f64.log2(), 3f64.log2(), 12f64.log2());
    let (w, v, log_l, log_k) = (
        f64::from(POSITIONS).log2(),
        CHAINS as f64,
        8.0,
        f64::from(hazmat::MAX_TRIALS).log2(),
    );
    // (13) digest, (14) salt, (15) element, (16) parameter, with qs = L.
    assert!(v * w >= (kc + log5 + 1.0).max(2.0 * (kq + log5 + 1.0) + 3.0));
    assert!(
        (8 * SALT_LEN) as f64
            >= (kc + log5 + log_l + log_k + 1.0).max(2.0 * (kq + log5 + log3 + log_k) + log_l)
    );
    assert!(
        (8 * ELEMENT_LEN) as f64
            >= (kc + log5 + 2.0 * w + log_l + v.log2())
                .max(2.0 * (kq + log5 + 2.0 * w + log_l + v.log2() + log12))
    );
    assert!((8 * PARAMETER_LEN) as f64 >= (kc + log5 + 3.0).max(2.0 * (kq + log5 + 2.0) + 5.0));
    // b-wagn/hashsig-parameters@95a80bc lower_bounds.py, same inputs, rounded
    // up to bytes as hash-sig's instantiations do.
    const { assert!(8 * ELEMENT_LEN >= 183 && 8 * PARAMETER_LEN >= 142 && 8 * SALT_LEN >= 168) };
    const { assert!(ELEMENT_LEN == 23 && PARAMETER_LEN == 18 && SALT_LEN == 21) };
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
    assert_eq!(SIGNATURE_LEN, 849);
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

/// `solana-xmss` relies on these: leaves and nodes share the tree role, with
/// leaves alone at level 0, and the chain and message roles differ from it.
/// The layouts are pinned against hash-sig in `solana-xmss`'s reference test.
#[test]
fn hash_domains_are_disjoint() {
    assert_eq!(
        [ROLE_CHAIN, ROLE_TREE, ROLE_MESSAGE],
        [0, 1, 2],
        "eqs. (17)–(19)"
    );
    let p = parameter(1);
    let (left, right) = ([1; ELEMENT_LEN], [2; ELEMENT_LEN]);
    let mut input = p.to_vec();
    input.extend([ROLE_TREE, 3, 0, 0, 0, 5]);
    input.extend(left);
    input.extend(right);
    assert_eq!(
        primitives::node(&p, 3, 5, &left, &right)[..],
        hash::hashv(&[&input])[..ELEMENT_LEN]
    );
    let refused =
        std::panic::catch_unwind(|| primitives::node(&parameter(1), 0, 0, &[0; 23], &[0; 23]));
    assert!(refused.is_err(), "a node at level 0 would be a leaf");

    // A signature's leaf is the tree-role hash at level 0 of its chain ends.
    let secrets = Secrets::from_bytes(2, &[9; 2 * ELEMENTS_LEN], p).unwrap();
    let m = message(b"domains");
    let accepted = salt(&p, 1, &m);
    let elements = secrets.sign(1, &m, &accepted).unwrap();
    assert_eq!(
        primitives::leaf(&p, 1, &accepted, &elements, &m),
        Some(secrets.leaf(1))
    );
    assert_ne!(secrets.leaf(0), secrets.leaf(1));
    assert_ne!(
        primitives::leaf(&p, 0, &accepted, &elements, &m),
        Some(secrets.leaf(1)),
        "the leaf index is bound"
    );
}

#[test]
fn tampering_is_rejected() {
    let m = message(b"tamper");
    let sk = key::<hazmat::SecretKey>(2);
    let pk = sk.verifying_key();
    let sig = sign(&sk, 0, &m);
    assert_eq!(pk.verify(&m, &sig), Ok(()));
    for i in 0..SIGNATURE_LEN {
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
    type Tree = TreeSigningKey;
    const LEAVES: u32 = 256;
    let dir = temp_dir("signer");
    let path = dir.join("tree.key");
    let (a, b, y, z) = (message(b"a"), message(b"b"), message(b"y"), message(b"z"));

    let mut signer = Tree::create(&path).unwrap();
    let pk = signer.verifying_key();
    assert_eq!(signer.remaining(), LEAVES);
    assert!(matches!(Tree::create(&path), Err(SigningError::Locked)));
    assert!(matches!(Tree::open(&path), Err(SigningError::Locked)));

    let sig_a = signer.sign(&a).unwrap();
    assert_eq!(sig_a.leaf(), 0);
    assert_eq!(pk.verify(&a, &sig_a), Ok(()));
    assert_eq!(signer.sign(&a).unwrap(), sig_a);
    assert_eq!(signer.next_leaf(), 1);

    assert_eq!(signer.remaining(), LEAVES - 1);
    let sig_b = signer.sign(&b).unwrap();
    assert_eq!(sig_b.leaf(), 1);
    drop(signer);

    assert!(matches!(Tree::create(&path), Err(SigningError::Exists)));
    assert!(matches!(
        SigningKey::open(&path),
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
    last[NEXT_LEAF..NEXT_LEAF + 4].copy_from_slice(&(LEAVES - 1).to_be_bytes());
    let accepted = salt(&last[2..20], LEAVES - 2, &last[25..57].try_into().unwrap());
    last[57..78].copy_from_slice(&accepted);
    std::fs::write(&path, &last).unwrap();
    let mut signer = Tree::open(&path).unwrap();
    assert_eq!(signer.remaining(), 1);
    let sig_z = signer.sign(&z).unwrap();
    assert_eq!(sig_z.leaf(), LEAVES - 1);
    assert_eq!(signer.remaining(), 0);
    assert!(matches!(signer.sign(&y), Err(SigningError::Exhausted)));
    assert_eq!(signer.sign(&z).unwrap(), sig_z);
    drop(signer);

    // The one-leaf instance.
    let path = dir.join("once.key");
    let mut once = SigningKey::create(&path).unwrap();
    let s = once.sign(&a).unwrap();
    assert_eq!(once.verifying_key().verify(&a, &s), Ok(()));
    assert_eq!(once.sign(&a).unwrap(), s);
    assert!(matches!(once.sign(&b), Err(SigningError::Exhausted)));
    drop(once);
    assert!(matches!(Tree::open(&path), Err(SigningError::Corrupt)));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Subprocess entry point for the lock-recovery test.
#[test]
fn hold_key_file() {
    let Ok(path) = std::env::var("SOLANA_WINTERNITZ_HOLD") else {
        return;
    };
    let _held = SigningKey::open(&path).unwrap();
    std::println!("HOLDING");
    loop {
        std::thread::sleep(core::time::Duration::from_secs(1));
    }
}

#[test]
fn lock_dies_with_its_holder() {
    use crate::SigningError;
    use std::io::BufRead;
    let dir = temp_dir("holder");
    let path = dir.join("once.key");
    drop(SigningKey::create(&path).unwrap());
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "tests::hold_key_file", "--nocapture"])
        .env("SOLANA_WINTERNITZ_HOLD", &path)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = std::io::BufReader::new(child.stdout.take().unwrap()).lines();
    assert!(lines.any(|line| line.unwrap() == "HOLDING"));
    assert!(matches!(SigningKey::open(&path), Err(SigningError::Locked)));
    child.kill().unwrap();
    child.wait().unwrap();
    drop(SigningKey::open(&path).unwrap());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A key file and its recorded signature pin signing in both languages.
#[test]
fn sampled_vectors_are_reproduced() {
    let vectors: Value = serde_json::from_str(include_str!("../tests/sampled.json")).unwrap();
    let dir = temp_dir("fixture");
    let path = dir.join("once.key");
    std::fs::write(&path, include_bytes!("../tests/winternitz.key")).unwrap();
    let before = std::fs::read(&path).unwrap();
    let mut once = SigningKey::open(&path).unwrap();
    let m = before[25..57].try_into().unwrap();
    let expected = hex(vectors["one_time_signature"].as_str().unwrap());
    let sig = once.sign(&m).unwrap();
    assert_eq!(sig.0.as_slice(), expected);
    assert_eq!(once.verifying_key().verify(&m, &sig), Ok(()));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    drop(once);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn raw_keys_require_all_chain_starts() {
    assert!(hazmat::SecretKey::from_secrets(&[0; 32], parameter(0)).is_err());
    assert!(hazmat::SecretKey::from_secrets(&[0; 2 * ELEMENTS_LEN], parameter(0)).is_err());
    assert!(Secrets::from_bytes(0, &[], parameter(0)).is_err());
    assert!(Secrets::from_bytes(2, &[0; ELEMENTS_LEN], parameter(0)).is_err());
    let key = key::<hazmat::SecretKey>(1);
    let m = message(b"bad salt");
    assert!(key.sign_at_with_salt(1, &m, &[0; SALT_LEN]).is_none());
    let bad = (0u32..)
        .find_map(|counter| {
            let mut salt = [0; SALT_LEN];
            salt[..4].copy_from_slice(&counter.to_le_bytes());
            primitives::encode(&salt, key.parameter(), 0, &m)
                .is_none()
                .then_some(salt)
        })
        .unwrap();
    assert!(key.sign_at_with_salt(0, &m, &bad).is_none());
}

/// Regenerate the key-file fixture and its signature.
#[test]
#[ignore]
fn regenerate_sampled_vectors() {
    let dir = temp_dir("regenerate");
    let path = dir.join("once.key");
    let mut once = SigningKey::create(&path).unwrap();
    let sig = once.sign(&message(b"sampled fixture")).unwrap();
    drop(once);
    std::fs::copy(&path, "tests/winternitz.key").unwrap();
    std::fs::write("tests/sampled.json", serde_json::to_string_pretty(&serde_json::json!({
        "test_inputs": "Public test data only: tests/winternitz.key is a key file with a recorded attempt; one_time_signature is the signature that attempt reproduces.",
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
    let signature = Signature::from_bytes(&[0; Signature::BYTE_LEN]);
    assert_eq!(
        Signature::from_slice(signature.as_bytes()).unwrap(),
        signature
    );
    assert_eq!(
        key.verify(&[0; MESSAGE_LEN], &signature),
        Err(Error::InvalidSignature)
    );
    assert_eq!(Signature::from_slice(&[0; 848]), Err(Error::InvalidLength));
}

/// Verify-only known answers, checked byte for byte by the Rust and
/// TypeScript verifiers: a valid signature and mutations each verifier must refuse.
#[test]
fn verify_vectors() {
    let vectors: Value = serde_json::from_str(include_str!("../tests/vectors.json")).unwrap();
    let pk = VerifyingKey::from_slice(&hex(vectors["public_key"].as_str().unwrap())).unwrap();
    let cases = vectors["cases"].as_array().unwrap();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let m: [u8; MESSAGE_LEN] = hex(case["message"].as_str().unwrap()).try_into().unwrap();
        let sig = Signature::from_slice(&hex(case["signature"].as_str().unwrap())).unwrap();
        let expected = if case["valid"].as_bool().unwrap() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        };
        assert_eq!(pk.verify(&m, &sig), expected, "{name}");
    }
    assert_eq!(cases.len(), 4);
}

/// Regenerate `tests/vectors.json`.
#[test]
#[ignore]
fn regenerate_verify_vectors() {
    fn case(name: &str, m: &[u8; MESSAGE_LEN], sig: &[u8], valid: bool) -> Value {
        serde_json::json!({ "name": name, "message": to_hex(m), "signature": to_hex(sig), "valid": valid })
    }
    /// A salt whose digest misses the target sum, so encoding refuses it.
    fn bad_salt(parameter: &[u8], leaf: u32, m: &[u8; MESSAGE_LEN]) -> [u8; SALT_LEN] {
        (0u32..)
            .find_map(|counter| {
                let mut salt = [0xa5; SALT_LEN];
                salt[..4].copy_from_slice(&counter.to_le_bytes());
                primitives::encode(&salt, parameter, leaf, m)
                    .is_none()
                    .then_some(salt)
            })
            .unwrap()
    }

    let once = key::<hazmat::SecretKey>(7);
    let once_pk = once.verifying_key();
    let m = message(b"one-time");
    let sig = sign(&once, 0, &m).0;
    let mut other = m;
    other[31] ^= 1;
    let mut bad_sum = sig;
    bad_sum[..SALT_LEN].copy_from_slice(&bad_salt(once_pk.parameter(), 0, &m));
    let mut element = sig;
    element[SALT_LEN + 5 * ELEMENT_LEN] ^= 0x80;
    let cases = std::vec![
        case("valid", &m, &sig, true),
        case("other message", &other, &sig, false),
        case("salt misses the target sum", &m, &bad_sum, false),
        case("chain element flipped", &m, &element, false),
    ];

    std::fs::write(
        "tests/vectors.json",
        serde_json::to_string_pretty(&serde_json::json!({
            "test_inputs": "Public test data only: chain-start byte i = (i mod 251) xor 7; P = 18 bytes of 0x57; salt = first accepted counter LE32 padded to 21 bytes. Every invalid case must fail verification.",
            "public_key": to_hex(&once_pk.0),
            "cases": cases,
        }))
        .unwrap()
            + "\n",
    )
    .unwrap();
}
