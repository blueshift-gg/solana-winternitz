//! Host-side signer owning leaf allocation, after winterwallet's client.
//! Here because Theorem 1 admits one signature per leaf and neither the
//! seed nor the chain records which leaves are spent: the record is
//! written before a signature exists, one instance holds a file, and a
//! file opens only from itself. The file holds the seed and `P`, which
//! Construction 3 samples independently and the caller supplies.

use std::fs::{self, File, TryLockError};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use crate::{MESSAGE_LENGTH, PARAMETER_LENGTH, PublicKey};

/// The two instances as the signer sees them. `sign_at` is Construction 3's
/// Sig with no one-use rule; [`Signer`] supplies the rule.
pub trait OneTime: Sized {
    /// The instance's signature type.
    type Signature;
    /// Leaves per key: 1 or 256.
    const LEAVES: u32;
    /// In the key file, so a file opens only under its own instance.
    const HEIGHT: u8;
    /// Construction 3 Gen from a 32-byte seed and the sampled parameter `P`.
    fn new(seed: [u8; 32], parameter: [u8; PARAMETER_LENGTH]) -> Self;
    /// `root ‖ P`.
    fn public_key(&self) -> PublicKey;
    /// Construction 3 Sig under `leaf`, recording nothing. `None` when the
    /// leaf is out of range or every salt misses.
    fn sign_at(&self, leaf: u32, message: &[u8; MESSAGE_LENGTH]) -> Option<Self::Signature>;
}

/// Every variant fails closed: no signature is released.
#[derive(Debug)]
pub enum SignerError {
    /// `create` on an existing key file.
    Exists,
    /// `open` with no key file: a seed cannot say which leaves are spent.
    Missing,
    /// Another signer holds the file.
    Locked,
    /// Wrong length, version or instance height.
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
    /// All `K` salts missed; the leaf is spent anyway.
    SaltsExhausted,
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
            Self::Missing => f.write_str(
                "no key file at this path: a seed alone cannot say which leaves are spent",
            ),
            Self::Locked => f.write_str("the key file is held by another signer"),
            Self::Corrupt => f.write_str("the key file is not a record of this instance"),
            Self::BelowFloor { next_leaf, floor } => write!(
                f,
                "the key file is behind the chain: next leaf {next_leaf}, floor {floor}"
            ),
            Self::Exhausted => f.write_str("every leaf is spent"),
            Self::SaltsExhausted => {
                f.write_str("4096 salts missed the target sum; the leaf is spent")
            }
            Self::Io(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for SignerError {}

// Key file: version ‖ height ‖ seed ‖ P ‖ next leaf BE ‖ message flag ‖
// last message, 89 bytes, byte-identical to the TypeScript package's.
const VERSION: u8 = 1;
const SEED: usize = 2;
const PARAMETER: usize = SEED + 32;
const NEXT_LEAF: usize = PARAMETER + PARAMETER_LENGTH;
const HAS_MESSAGE: usize = NEXT_LEAF + 4;
const MESSAGE: usize = HAS_MESSAGE + 1;
const RECORD: usize = MESSAGE + MESSAGE_LENGTH;

/// `create` from a fresh seed, `open` from the file, `sign` a message: a
/// new message spends the next leaf after the record is on disk, the last
/// message again returns the same bytes and spends nothing.
pub struct Signer<K: OneTime> {
    key: K,
    seed: [u8; 32],
    parameter: [u8; PARAMETER_LENGTH],
    path: PathBuf,
    _lock: File,
    next_leaf: u32,
    last_message: Option<[u8; MESSAGE_LENGTH]>,
}

impl<K: OneTime> Drop for Signer<K> {
    fn drop(&mut self) {
        crate::wipe(&mut self.seed);
    }
}

impl<K: OneTime> Signer<K> {
    /// `seed` and `parameter` are the caller's fresh randomness, Construction
    /// 3's `sk` and `P`; the seed must never have signed. The file is what
    /// to back up.
    pub fn create(
        path: impl AsRef<Path>,
        seed: [u8; 32],
        parameter: [u8; PARAMETER_LENGTH],
    ) -> Result<Self, SignerError> {
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
        let signer = Self {
            key: K::new(seed, parameter),
            seed,
            parameter,
            path,
            _lock: lock,
            next_leaf: 0,
            last_message: None,
        };
        file.write_all(&signer.record())?;
        file.sync_all()?;
        sync_dir(&signer.path)?;
        Ok(signer)
    }

    /// Continue from the key file at `path`, holding it.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SignerError> {
        let path = path.as_ref().to_path_buf();
        let lock = lock(&path)?;
        let mut bytes = std::vec::Vec::new();
        File::open(&path)
            .map_err(|error| match error.kind() {
                io::ErrorKind::NotFound => SignerError::Missing,
                _ => SignerError::Io(error),
            })?
            .read_to_end(&mut bytes)?;
        let record: &[u8; RECORD] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| SignerError::Corrupt)?;
        let next_leaf = u32::from_be_bytes(record[NEXT_LEAF..HAS_MESSAGE].try_into().unwrap());
        if record[0] != VERSION
            || record[1] != K::HEIGHT
            || record[HAS_MESSAGE] > 1
            || next_leaf > K::LEAVES
        {
            return Err(SignerError::Corrupt);
        }
        let seed: [u8; 32] = record[SEED..PARAMETER].try_into().unwrap();
        let parameter: [u8; PARAMETER_LENGTH] = record[PARAMETER..NEXT_LEAF].try_into().unwrap();
        Ok(Self {
            key: K::new(seed, parameter),
            seed,
            parameter,
            path,
            _lock: lock,
            next_leaf,
            last_message: (record[HAS_MESSAGE] == 1).then(|| record[MESSAGE..].try_into().unwrap()),
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

    /// Record first, sign second (RFC 8391 §4.1.9); the last message is
    /// repeated, never re-spent.
    pub fn sign(&mut self, message: &[u8; MESSAGE_LENGTH]) -> Result<K::Signature, SignerError> {
        if self.last_message.as_ref() == Some(message)
            && let Some(signature) = self.key.sign_at(self.next_leaf - 1, message)
        {
            return Ok(signature);
        }
        if self.next_leaf >= K::LEAVES {
            return Err(SignerError::Exhausted);
        }
        let leaf = self.next_leaf;
        self.next_leaf = leaf + 1;
        self.last_message = Some(*message);
        if let Err(error) = self.write() {
            // On disk or not, the leaf stays spent; the message goes so the
            // unrecorded signature can never be handed out.
            self.last_message = None;
            return Err(error);
        }
        self.key
            .sign_at(leaf, message)
            .ok_or(SignerError::SaltsExhausted)
    }

    fn record(&self) -> [u8; RECORD] {
        let mut record = [0u8; RECORD];
        record[0] = VERSION;
        record[1] = K::HEIGHT;
        record[SEED..PARAMETER].copy_from_slice(&self.seed);
        record[PARAMETER..NEXT_LEAF].copy_from_slice(&self.parameter);
        record[NEXT_LEAF..HAS_MESSAGE].copy_from_slice(&self.next_leaf.to_be_bytes());
        if let Some(message) = &self.last_message {
            record[HAS_MESSAGE] = 1;
            record[MESSAGE..].copy_from_slice(message);
        }
        record
    }

    fn write(&self) -> Result<(), SignerError> {
        let tmp = sibling(&self.path, ".tmp");
        let mut file = options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        file.write_all(&self.record())?;
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
