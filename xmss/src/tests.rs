use serde_json::Value;
use std::vec::Vec;

use solana_winternitz::{
    hazmat::sample_salt,
    primitives::{self, ELEMENT_LEN, ELEMENTS_LEN, SALT_LEN},
};

use crate::hazmat::{OneTime, SecretKey};
use crate::{
    Error, LEAVES, MESSAGE_LEN, PARAMETER_LEN, PUBLIC_KEY_LEN, SIGNATURE_LEN, Signature,
    SigningError, SigningKey, VerifyingKey,
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
fn key(tag: u8) -> SecretKey {
    let secrets: Vec<u8> = (0..LEAVES as usize * ELEMENTS_LEN)
        .map(|i| (i % 251) as u8 ^ tag)
        .collect();
    SecretKey::from_secrets(&secrets, [0x50 ^ tag; PARAMETER_LEN]).unwrap()
}

/// The first accepted counter, LE32 padded to 21 bytes.
fn salt(parameter: &[u8; PARAMETER_LEN], leaf: u32, message: &[u8; MESSAGE_LEN]) -> [u8; SALT_LEN] {
    let mut counter = 0u32;
    sample_salt(parameter, leaf, message, |salt| {
        salt.fill(0);
        salt[..4].copy_from_slice(&counter.to_le_bytes());
        counter += 1;
        Ok(())
    })
    .unwrap()
}

/// A salt whose digest misses the target sum, so encoding refuses it.
fn bad_salt(parameter: &[u8; PARAMETER_LEN], leaf: u32, m: &[u8; MESSAGE_LEN]) -> [u8; SALT_LEN] {
    (0u32..)
        .find_map(|counter| {
            let mut salt = [0xa5; SALT_LEN];
            salt[..4].copy_from_slice(&counter.to_le_bytes());
            primitives::leaf(parameter, leaf, &salt, &[0; ELEMENTS_LEN], m)
                .is_none()
                .then_some(salt)
        })
        .unwrap()
}

fn sign(key: &SecretKey, leaf: u32, message: &[u8; MESSAGE_LEN]) -> Signature {
    key.sign_at_with_salt(leaf, message, &salt(key.parameter(), leaf, message))
        .unwrap()
}

/// Pad a test tag to the fixed message length.
fn message(tag: &[u8]) -> [u8; MESSAGE_LEN] {
    let mut m = [0u8; MESSAGE_LEN];
    m[..tag.len()].copy_from_slice(tag);
    m
}

fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(std::format!("solana-xmss-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn encodings_have_their_documented_sizes() {
    assert_eq!(PUBLIC_KEY_LEN, 41);
    assert_eq!(SIGNATURE_LEN, 1037);
    assert_eq!(SIGNATURE_LEN, 4 + SALT_LEN + ELEMENTS_LEN + 8 * ELEMENT_LEN);
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
        let sig = Signature::from_bytes(&(bytes.try_into().unwrap()));
        assert_eq!(pk.verify(&message, &sig), Ok(()));
        let mut other = message;
        other[0] ^= 1;
        assert_eq!(pk.verify(&other, &sig), Err(Error::InvalidSignature));
    }
}

#[test]
fn roundtrip_every_leaf() {
    let sk = key(3);
    let pk = sk.verifying_key();
    for leaf in 0..LEAVES {
        let m = message(&leaf.to_le_bytes());
        let sig = sign(&sk, leaf, &m);
        assert_eq!(sig.leaf(), leaf);
        assert_eq!(pk.verify(&m, &sig), Ok(()));
    }
    for leaf in [LEAVES, LEAVES + 1, u32::MAX] {
        let m = message(b"bounds");
        assert!(sk.sign_at_with_salt(leaf, &m, &[0; SALT_LEN]).is_none());
        let mut sig = Signature::from_bytes(&([0; SIGNATURE_LEN]));
        sig.0[..4].copy_from_slice(&leaf.to_be_bytes());
        assert_eq!(pk.verify(&m, &sig), Err(Error::InvalidSignature));
    }
}

/// A one-time key over a leaf's chain starts verifies its own signature, but
/// that signature does not verify against the tree, and the tree's does not
/// verify against the one-time key.
#[test]
fn one_time_and_tree_signatures_are_not_interchangeable() {
    let tree = key(4);
    let m = message(b"cross");
    let once = solana_winternitz::hazmat::SecretKey::from_secrets(
        &tree.secrets()[..ELEMENTS_LEN],
        *tree.parameter(),
    )
    .unwrap();
    let once_sig = once
        .sign_at_with_salt(0, &m, &salt(tree.parameter(), 0, &m))
        .unwrap();
    let tree_sig = sign(&tree, 0, &m);
    assert_eq!(once.verifying_key().verify(&m, &once_sig), Ok(()));
    assert_ne!(
        once.verifying_key().as_bytes(),
        tree.verifying_key().as_bytes()
    );

    // Same chains, salt and elements; only the tree's path differs.
    let mut relabelled = [0; SIGNATURE_LEN];
    relabelled[4..4 + once_sig.as_bytes().len()].copy_from_slice(once_sig.as_bytes());
    assert_eq!(
        &relabelled[..PATH_START],
        &tree_sig.as_bytes()[..PATH_START]
    );
    assert_eq!(
        tree.verifying_key()
            .verify(&m, &Signature::from_bytes(&relabelled)),
        Err(Error::InvalidSignature)
    );
    let truncated =
        solana_winternitz::Signature::from_slice(&tree_sig.as_bytes()[4..PATH_START]).unwrap();
    assert_eq!(
        solana_winternitz::VerifyingKey::from_bytes(tree.verifying_key().as_bytes())
            .verify(&m, &truncated),
        Err(Error::InvalidSignature)
    );
}

const PATH_START: usize = 4 + SALT_LEN + ELEMENTS_LEN;

#[test]
fn tampering_is_rejected() {
    let m = message(b"tamper");
    let sk = key(2);
    let pk = sk.verifying_key();
    let sig = sign(&sk, 77, &m);
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
}

#[test]
fn signer_allocates_leaves() {
    let dir = temp_dir("signer");
    let path = dir.join("tree.key");
    let (a, b) = (message(b"a"), message(b"b"));
    let mut signer = SigningKey::create(&path).unwrap();
    let pk = signer.verifying_key();
    let sig_a = signer.sign(&a).unwrap();
    assert_eq!((sig_a.leaf(), pk.verify(&a, &sig_a)), (0, Ok(())));
    assert_eq!(signer.sign(&a).unwrap(), sig_a);
    let sig_b = signer.sign(&b).unwrap();
    assert_eq!((sig_b.leaf(), pk.verify(&b, &sig_b)), (1, Ok(())));
    assert_eq!(signer.remaining(), LEAVES - 2);
    drop(signer);

    let mut signer = SigningKey::open(&path).unwrap();
    assert_eq!(signer.verifying_key(), pk);
    assert_eq!(signer.sign(&b).unwrap(), sig_b);
    drop(signer);
    assert!(matches!(
        solana_winternitz::SigningKey::open(&path),
        Err(SigningError::Corrupt)
    ));

    // A one-time key file is not a tree's.
    let once = dir.join("once.key");
    drop(solana_winternitz::SigningKey::create(&once).unwrap());
    assert!(matches!(
        SigningKey::open(&once),
        Err(SigningError::Corrupt)
    ));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Explicit test chain starts and accepted salts pin signing in both languages.
#[test]
fn sampled_vectors_are_reproduced() {
    let vectors: Value = serde_json::from_str(include_str!("../tests/sampled.json")).unwrap();
    let sk = key(7);
    let pk = VerifyingKey::from_slice(&hex(vectors["public_key"].as_str().unwrap())).unwrap();
    assert_eq!(sk.verifying_key(), pk);
    for v in vectors["signatures"].as_array().unwrap() {
        let leaf = v["leaf"].as_u64().unwrap() as u32;
        let m = message(&leaf.to_le_bytes());
        let sig = Signature::from_slice(&hex(v["signature"].as_str().unwrap())).unwrap();
        assert_eq!(sign(&sk, leaf, &m), sig);
        assert_eq!(pk.verify(&m, &sig), Ok(()));
    }
}

#[test]
fn raw_keys_require_all_chain_starts() {
    let p = [0; PARAMETER_LEN];
    assert!(SecretKey::from_secrets(&[0; ELEMENTS_LEN], p).is_err());
    assert!(
        SecretKey::from_secrets(&std::vec![0; (LEAVES as usize + 1) * ELEMENTS_LEN], p).is_err()
    );
}

/// Regenerate `tests/sampled.json`.
#[test]
#[ignore]
fn regenerate_sampled_vectors() {
    let sk = key(7);
    // Complementary leaf bits exercise both path orientations at every level.
    let signatures: Vec<Value> = [127, 128u32].into_iter().map(|leaf| {
        serde_json::json!({ "leaf": leaf, "signature": to_hex(&sign(&sk, leaf, &message(&leaf.to_le_bytes())).0) })
    }).collect();
    std::fs::write("tests/sampled.json", serde_json::to_string_pretty(&serde_json::json!({
        "test_inputs": "Public test data only: chain-start byte i = (i mod 251) xor 7; P = 18 bytes of 0x57; message = leaf LE32 padded to 32 bytes; salt = first accepted counter LE32 padded to 21 bytes.",
        "public_key": to_hex(&sk.verifying_key().0), "signatures": signatures,
    })).unwrap() + "\n").unwrap();
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
    assert_eq!(Signature::from_slice(&[0; 1036]), Err(Error::InvalidLength));
}

/// Verify-only known answers, checked byte for byte by the Rust and
/// TypeScript verifiers: valid signatures at both ends of the tree and
/// mutations each verifier must refuse.
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
    assert_eq!(cases.len(), 11);
}

/// Regenerate `tests/vectors.json`.
#[test]
#[ignore]
fn regenerate_verify_vectors() {
    fn case(name: &str, m: &[u8; MESSAGE_LEN], sig: &[u8], valid: bool) -> Value {
        serde_json::json!({ "name": name, "message": to_hex(m), "signature": to_hex(sig), "valid": valid })
    }
    let tree = key(7);
    let tree_pk = tree.verifying_key();
    let mut cases: Vec<Value> = [0u32, 1, 127, 128, 254, 255]
        .into_iter()
        .map(|leaf| {
            let m = message(&leaf.to_le_bytes());
            case(
                &std::format!("valid at leaf {leaf}"),
                &m,
                &sign(&tree, leaf, &m).0,
                true,
            )
        })
        .collect();
    let m = message(&0u32.to_le_bytes());
    let leaf0 = sign(&tree, 0, &m).0;
    let mut wrong_leaf = leaf0;
    wrong_leaf[..4].copy_from_slice(&1u32.to_be_bytes());
    let mut out_of_range = leaf0;
    out_of_range[..4].copy_from_slice(&LEAVES.to_be_bytes());
    let mut bad_sum = leaf0;
    bad_sum[4..4 + SALT_LEN].copy_from_slice(&bad_salt(tree_pk.parameter(), 0, &m));
    let m255 = message(&255u32.to_le_bytes());
    let mut path = sign(&tree, 255, &m255).0;
    *path.last_mut().unwrap() ^= 1;
    let mut other = m;
    other[0] ^= 1;
    cases.extend([
        case(
            "leaf 0 signature relabelled as leaf 1",
            &m,
            &wrong_leaf,
            false,
        ),
        case("leaf 256 is out of range", &m, &out_of_range, false),
        case("salt misses the target sum", &m, &bad_sum, false),
        case("top authentication path byte flipped", &m255, &path, false),
        case("other message", &other, &leaf0, false),
    ]);
    std::fs::write(
        "tests/vectors.json",
        serde_json::to_string_pretty(&serde_json::json!({
            "test_inputs": "Public test data only, as tests/sampled.json: chain-start byte i = (i mod 251) xor 7; P = 18 bytes of 0x57; salt = first accepted counter LE32 padded to 21 bytes. Every invalid case must fail verification.",
            "public_key": to_hex(&tree_pk.0),
            "cases": cases,
        }))
        .unwrap()
            + "\n",
    )
    .unwrap();
}
