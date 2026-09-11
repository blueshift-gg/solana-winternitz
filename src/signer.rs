//! Host-side leaf allocation. Sample a salt, durably record it with the
//! message and next leaf, then compute the signature. A permanent kernel
//! lock serializes writers; retries use the recorded salt.

use std::fs::{self, File, TryLockError};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use crate::{ELEMENTS_LENGTH, MESSAGE_LENGTH, PARAMETER_LENGTH, PublicKey, SALT_LENGTH, encode};

/// Raw Construction 3 operations. These do not enforce one use per leaf;
/// use [`Signer`] for signing. Never reuse chain starts across keys.
pub trait OneTime: Sized {
    /// The instance's signature type.
    type Signature;
    /// Leaves per key: 1 or 256.
    const LEAVES: u32;
    /// In the key file, so a file opens only under its own instance.
    const HEIGHT: u8;
    /// Copy independently sampled chain starts in leaf-major, chain-major
    /// order (828 bytes per leaf), and the independently sampled `P`.
    /// Returns `None` for the wrong secret length. Records no usage state.
    fn new(secrets: &[u8], parameter: [u8; PARAMETER_LENGTH]) -> Option<Self>;
    /// Raw secret bytes for persistence. These alone cannot restore usage state.
    fn secrets(&self) -> &[u8];
    /// `root ‖ P`.
    fn public_key(&self) -> PublicKey;
    /// Sign with an accepted salt. `None` for an invalid leaf or encoding.
    /// Never use a spent leaf with a different message or salt.
    fn sign_at(
        &self,
        leaf: u32,
        message: &[u8; MESSAGE_LENGTH],
        salt: &[u8; SALT_LENGTH],
    ) -> Option<Self::Signature>;
}

/// Every variant fails closed: no signature is released.
#[derive(Debug)]
pub enum SignerError {
    /// `create` on an existing key file.
    Exists,
    /// `open` with no key file.
    Missing,
    /// Another signer holds the file.
    Locked,
    /// Wrong length, version, instance or retry state.
    Corrupt,
    /// The record is behind the chain: a restored old copy.
    BelowFloor {
        /// The file's next leaf.
        next_leaf: u32,
        /// The chain's last accepted leaf plus one.
        floor: u32,
    },
    /// Every leaf is spent.
    Exhausted,
    /// All `K` salts missed; no leaf was spent.
    SaltsExhausted,
    /// The operating system could not provide randomness.
    Random(getrandom::Error),
    /// A previous write failed. Drop the signer and reopen the file.
    Unusable,
    /// The file system refused; the leaf may or may not be recorded.
    Io(io::Error),
}

impl From<io::Error> for SignerError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl core::fmt::Display for SignerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Exists => f.write_str("a key file already exists at this path: open it instead"),
            Self::Missing => f.write_str("no key file at this path: usage state is required"),
            Self::Locked => f.write_str("the key file is held by another signer"),
            Self::Corrupt => f.write_str("the key file is not a record of this instance"),
            Self::BelowFloor { next_leaf, floor } => write!(
                f,
                "the key file is behind the chain: next leaf {next_leaf}, floor {floor}"
            ),
            Self::Exhausted => f.write_str("every leaf is spent"),
            Self::SaltsExhausted => {
                f.write_str("4096 salts missed the target sum; no leaf was spent")
            }
            Self::Random(error) => write!(f, "randomness unavailable: {error}"),
            Self::Unusable => {
                f.write_str("a write failed: drop the signer and reopen the key file")
            }
            Self::Io(error) => write!(f, "{error}"),
        }
    }
}
impl std::error::Error for SignerError {}

// v2: version || height || P || next leaf BE || message flag || message ||
// accepted salt || chain starts. The fixed header is 78 bytes.
const VERSION: u8 = 2;
const PARAMETER: usize = 2;
const NEXT_LEAF: usize = PARAMETER + PARAMETER_LENGTH;
const HAS_MESSAGE: usize = NEXT_LEAF + 4;
const MESSAGE: usize = HAS_MESSAGE + 1;
const SALT: usize = MESSAGE + MESSAGE_LENGTH;
const SECRETS: usize = SALT + SALT_LENGTH;

/// A newly sampled key or an existing key file, held exclusively. Every
/// new message spends a leaf; the last message returns the same signature.
pub struct Signer<K: OneTime> {
    key: K,
    path: PathBuf,
    _lock: File,
    next_leaf: u32,
    last_message: Option<[u8; MESSAGE_LENGTH]>,
    last_salt: [u8; SALT_LENGTH],
    failed: bool,
}

impl<K: OneTime> Signer<K> {
    /// Sample every chain start and `P` from the OS random source, as in
    /// Construction 3 Gen. Refuses an existing file. Back up the whole file.
    pub fn create(path: impl AsRef<Path>) -> Result<Self, SignerError> {
        let path = path.as_ref().to_path_buf();
        let lock = lock(&path)?;
        let mut file = options()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| match error.kind() {
                io::ErrorKind::AlreadyExists => SignerError::Exists,
                _ => SignerError::Io(error),
            })?;
        let mut secrets = std::vec![0; K::LEAVES as usize * ELEMENTS_LENGTH];
        let mut parameter = [0; PARAMETER_LENGTH];
        let sampled = getrandom::fill(&mut secrets).and_then(|()| getrandom::fill(&mut parameter));
        let key = sampled
            .map_err(SignerError::Random)
            .and_then(|()| K::new(&secrets, parameter).ok_or(SignerError::Corrupt));
        crate::wipe(&mut secrets);
        let signer = Self {
            key: key?,
            path,
            _lock: lock,
            next_leaf: 0,
            last_message: None,
            last_salt: [0; SALT_LENGTH],
            failed: false,
        };
        signer.write_record(&mut file)?;
        file.sync_all()?;
        sync_dir(&signer.path)?;
        Ok(signer)
    }

    /// Continue from a v2 key file, holding its permanent sidecar lock.
    /// Seed-based v1 files are rejected; they cannot become sampled keys.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SignerError> {
        let path = path.as_ref().to_path_buf();
        let lock = lock(&path)?;
        let mut file = File::open(&path).map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => SignerError::Missing,
            _ => SignerError::Io(error),
        })?;
        let mut header = [0; SECRETS];
        if file.metadata()?.len() != (SECRETS + K::LEAVES as usize * ELEMENTS_LENGTH) as u64 {
            return Err(SignerError::Corrupt);
        }
        file.read_exact(&mut header)?;
        let next_leaf = u32::from_be_bytes(header[NEXT_LEAF..HAS_MESSAGE].try_into().unwrap());
        let parameter: [u8; PARAMETER_LENGTH] = header[PARAMETER..NEXT_LEAF].try_into().unwrap();
        let last_message =
            (header[HAS_MESSAGE] == 1).then(|| header[MESSAGE..SALT].try_into().unwrap());
        let last_salt: [u8; SALT_LENGTH] = header[SALT..].try_into().unwrap();
        if header[0] != VERSION
            || header[1] != K::HEIGHT
            || header[HAS_MESSAGE] > 1
            || next_leaf > K::LEAVES
            || last_message.is_some() != (next_leaf > 0)
            || match &last_message {
                Some(message) => encode(&last_salt, &parameter, next_leaf - 1, message).is_none(),
                None => header[MESSAGE..].iter().any(|&b| b != 0),
            }
        {
            return Err(SignerError::Corrupt);
        }
        let mut secrets = std::vec![0; K::LEAVES as usize * ELEMENTS_LENGTH];
        let key = file
            .read_exact(&mut secrets)
            .map_err(SignerError::Io)
            .and_then(|()| K::new(&secrets, parameter).ok_or(SignerError::Corrupt));
        crate::wipe(&mut secrets);
        Ok(Self {
            key: key?,
            path,
            _lock: lock,
            next_leaf,
            last_message,
            last_salt,
            failed: false,
        })
    }

    /// `floor` is the chain's last accepted leaf plus one. Catches a restored
    /// old copy, not leaves exposed by transactions that never landed.
    pub fn floor(self, floor: u32) -> Result<Self, SignerError> {
        if self.next_leaf < floor {
            return Err(SignerError::BelowFloor {
                next_leaf: self.next_leaf,
                floor,
            });
        }
        Ok(self)
    }
    /// `root ‖ P`.
    pub fn public_key(&self) -> PublicKey {
        self.key.public_key()
    }
    /// The leaf the next new message spends.
    pub fn next_leaf(&self) -> u32 {
        self.next_leaf
    }
    /// Leaves not yet spent.
    pub fn remaining(&self) -> u32 {
        K::LEAVES - self.next_leaf
    }

    /// Sample salt candidates, persist the accepted salt and allocation,
    /// then sign. Retrying the last message uses the persisted salt.
    pub fn sign(&mut self, message: &[u8; MESSAGE_LENGTH]) -> Result<K::Signature, SignerError> {
        self.sign_with(message, |salt| {
            getrandom::fill(salt).map_err(SignerError::Random)
        })
    }

    // Private entropy seam also tests exhaustion and RNG failure without a
    // public deterministic-signing alternative to the safe signer.
    fn sign_with(
        &mut self,
        message: &[u8; MESSAGE_LENGTH],
        mut fill: impl FnMut(&mut [u8]) -> Result<(), SignerError>,
    ) -> Result<K::Signature, SignerError> {
        if self.failed {
            return Err(SignerError::Unusable);
        }
        if self.last_message.as_ref() == Some(message) {
            return self
                .key
                .sign_at(self.next_leaf - 1, message, &self.last_salt)
                .ok_or(SignerError::Corrupt);
        }
        if self.next_leaf >= K::LEAVES {
            return Err(SignerError::Exhausted);
        }
        let leaf = self.next_leaf;
        let parameter = self.public_key();
        let mut salt = [0; SALT_LENGTH];
        for _ in 0..crate::signing::MAX_TRIALS {
            fill(&mut salt)?;
            if encode(&salt, parameter.parameter(), leaf, message).is_none() {
                continue;
            }
            self.next_leaf = leaf + 1;
            self.last_message = Some(*message);
            self.last_salt = salt;
            if let Err(error) = self.write() {
                self.failed = true;
                return Err(error);
            }
            return self
                .key
                .sign_at(leaf, message, &salt)
                .ok_or(SignerError::Corrupt);
        }
        Err(SignerError::SaltsExhausted)
    }

    fn write_record(&self, file: &mut File) -> Result<(), SignerError> {
        let mut header = [0; SECRETS];
        header[0] = VERSION;
        header[1] = K::HEIGHT;
        header[PARAMETER..NEXT_LEAF].copy_from_slice(self.public_key().parameter());
        header[NEXT_LEAF..HAS_MESSAGE].copy_from_slice(&self.next_leaf.to_be_bytes());
        if let Some(message) = &self.last_message {
            header[HAS_MESSAGE] = 1;
            header[MESSAGE..SALT].copy_from_slice(message);
            header[SALT..].copy_from_slice(&self.last_salt);
        }
        file.write_all(&header)?;
        file.write_all(self.key.secrets())?;
        Ok(())
    }

    fn write(&self) -> Result<(), SignerError> {
        let tmp = sibling(&self.path, ".tmp");
        let mut file = options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        self.write_record(&mut file)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, &self.path)?;
        sync_dir(&self.path)
    }
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    path.with_file_name(name)
}

fn options() -> fs::OpenOptions {
    let mut options = File::options();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

/// The `.lock` sidecar, permanent, held through `flock(LOCK_EX | LOCK_NB)`
/// for the signer's lifetime: `File::try_lock`, the same call the
/// TypeScript package makes through Bun's FFI, so each refuses a file the
/// other holds, and the kernel releases a dead holder's lock, so there is
/// no stale-owner decision to race on. A sidecar because rename would
/// orphan a lock on the record; never deleted, since a new file at the
/// path would be a second lock.
fn lock(path: &Path) -> Result<File, SignerError> {
    let file = options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(sibling(path, ".lock"))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(SignerError::Locked),
        Err(TryLockError::Error(error)) => Err(error.into()),
    }
}

/// A rename is durable only once its directory is synced.
fn sync_dir(path: &Path) -> Result<(), SignerError> {
    #[cfg(unix)]
    {
        let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
        File::open(parent.unwrap_or(Path::new(".")))?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::winternitz;

    #[test]
    fn failed_grinding_and_persistence_never_release_a_signature() {
        let dir =
            std::env::temp_dir().join(std::format!("winternitz-failure-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("once.key");
        let mut signer = Signer::<winternitz::SecretKey>::create(&path).unwrap();
        let before = std::fs::read(&path).unwrap();
        let message = [0; MESSAGE_LENGTH];
        let mut bad = [0; SALT_LENGTH];
        for counter in 0u32.. {
            bad[..4].copy_from_slice(&counter.to_le_bytes());
            if encode(&bad, signer.public_key().parameter(), 0, &message).is_none() {
                break;
            }
        }
        let mut trials = 0;
        assert!(matches!(
            signer.sign_with(&message, |salt| {
                trials += 1;
                salt.copy_from_slice(&bad);
                Ok(())
            }),
            Err(SignerError::SaltsExhausted)
        ));
        assert_eq!(trials, crate::signing::MAX_TRIALS);
        assert!(matches!(
            signer.sign_with(&message, |_| Err(SignerError::Io(io::Error::other(
                "entropy unavailable"
            )))),
            Err(SignerError::Io(_))
        ));
        assert_eq!(signer.next_leaf(), 0);
        assert_eq!(std::fs::read(&path).unwrap(), before);

        std::fs::create_dir(sibling(&path, ".tmp")).unwrap();
        assert!(matches!(signer.sign(&message), Err(SignerError::Io(_))));
        assert!(matches!(signer.sign(&message), Err(SignerError::Unusable)));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        drop(signer);
        std::fs::remove_dir(sibling(&path, ".tmp")).unwrap();
        let mut signer = Signer::<winternitz::SecretKey>::open(&path).unwrap();
        let sig = signer.sign(&message).unwrap();
        assert_eq!(
            signer
                .sign_with(&message, |_| panic!("retry drew randomness"))
                .unwrap(),
            sig
        );
        drop(signer);
        let mut signer = Signer::<winternitz::SecretKey>::open(&path).unwrap();
        assert_eq!(
            signer
                .sign_with(&message, |_| panic!("reopened retry drew randomness"))
                .unwrap(),
            sig
        );
        assert_eq!(sig.verify(&signer.public_key(), &message), Ok(()));
        drop(signer);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn inconsistent_retry_records_and_legacy_files_are_rejected() {
        let dir =
            std::env::temp_dir().join(std::format!("winternitz-corrupt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("once.key");
        let record = include_bytes!("../tests/winternitz.key");
        let mut variants = std::vec::Vec::new();
        let mut no_leaf = record.to_vec();
        no_leaf[NEXT_LEAF..HAS_MESSAGE].fill(0);
        variants.push(no_leaf);
        let mut no_message = record.to_vec();
        no_message[HAS_MESSAGE] = 0;
        variants.push(no_message);
        let mut invalid_salt = record.to_vec();
        for counter in 0u32.. {
            invalid_salt[SALT..SALT + 4].copy_from_slice(&counter.to_le_bytes());
            if encode(
                &invalid_salt[SALT..SECRETS],
                &invalid_salt[PARAMETER..NEXT_LEAF],
                0,
                record[MESSAGE..SALT].try_into().unwrap(),
            )
            .is_none()
            {
                break;
            }
        }
        variants.push(invalid_salt);
        let mut legacy = std::vec![0; 89];
        legacy[0] = 1;
        variants.push(legacy);
        let mut extra = record.to_vec();
        extra.push(0);
        variants.push(extra);
        for bytes in variants {
            std::fs::write(&path, bytes).unwrap();
            assert!(matches!(
                Signer::<winternitz::SecretKey>::open(&path),
                Err(SignerError::Corrupt)
            ));
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
