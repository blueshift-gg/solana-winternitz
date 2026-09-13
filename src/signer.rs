//! Persistent leaf allocation for DKKW25 Definition 8. Record each attempt
//! before returning; retries reproduce the recorded signature.

use std::fs::{self, File, TryLockError};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use crate::{
    ELEMENTS_LENGTH, Error, MESSAGE_LEN, PARAMETER_LEN, SALT_LENGTH, VerifyingKey, encode,
};

/// Raw Construction 3 operations. These do not enforce one use per leaf;
/// Use [`crate::xmss::SigningKey`] or [`crate::winternitz::SigningKey`] for
/// signing. Never reuse chain starts across keys.
/// Sealed to the built-in Winternitz and XMSS instances and their key-file tags.
pub trait OneTime: crate::sealed::OneTime + Sized {
    /// The instance's signature type.
    type Signature;
    /// Leaves per key: 1 or 256.
    const LEAVES: u32;
    /// Tree height; also the key-file instance tag.
    const HEIGHT: u8;
    /// Copy independently sampled chain starts in leaf-major, chain-major
    /// order (828 bytes per leaf), and the independently sampled `P`.
    /// Returns `Error::InvalidLength` for the wrong secret length. Records no usage state.
    fn from_secrets(secrets: &[u8], parameter: [u8; PARAMETER_LEN]) -> Result<Self, Error>;
    /// Raw secret bytes for persistence. These alone cannot restore usage state.
    fn secrets(&self) -> &[u8];
    /// `root ‖ P`.
    fn verifying_key(&self) -> VerifyingKey;
    /// Sign with an accepted salt. `None` for an invalid leaf or encoding.
    /// Never use a spent leaf with a different message or salt.
    fn sign_at_with_salt(
        &self,
        leaf: u32,
        message: &[u8; MESSAGE_LEN],
        salt: &[u8; SALT_LENGTH],
    ) -> Option<Self::Signature>;
}

/// Key-file or signing failure. No signature is returned on error.
#[derive(Debug)]
pub enum SigningError {
    /// `create` on an existing key file.
    Exists,
    /// `open` with no key file.
    Missing,
    /// Another signer holds the file.
    Locked,
    /// Wrong length, version, instance or retry state.
    Corrupt,
    /// The record is below the caller-supplied leaf minimum.
    LeafBelowMinimum {
        /// The file's next leaf.
        next_leaf: u32,
        /// The chain's last accepted leaf plus one.
        minimum: u32,
    },
    /// The requested leaf is outside this instance.
    InvalidLeaf,
    /// Every leaf is spent.
    Exhausted,
    /// All `K` salts missed; the leaf is spent.
    SaltsExhausted,
    /// The operating system could not provide randomness.
    Random(getrandom::Error),
    /// A previous write failed. Drop the signer and reopen the file.
    Unusable,
    /// I/O failed; an attempted state update may or may not be durable.
    Io(io::Error),
}

impl From<io::Error> for SigningError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl core::fmt::Display for SigningError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Exists => f.write_str("a key file already exists at this path: open it instead"),
            Self::Missing => f.write_str("no key file at this path: usage state is required"),
            Self::Locked => f.write_str("the key file is held by another signer"),
            Self::Corrupt => f.write_str("the key file is not a record of this instance"),
            Self::LeafBelowMinimum { next_leaf, minimum } => write!(
                f,
                "the key file is behind the chain: next leaf {next_leaf}, minimum {minimum}"
            ),
            Self::InvalidLeaf => f.write_str("leaf index is outside this instance"),
            Self::Exhausted => f.write_str("every leaf is spent"),
            Self::SaltsExhausted => {
                f.write_str("4096 salts missed the target sum; the leaf is spent")
            }
            Self::Random(error) => write!(f, "randomness unavailable: {error}"),
            Self::Unusable => {
                f.write_str("a write failed: drop the signer and reopen the key file")
            }
            Self::Io(error) => write!(f, "{error}"),
        }
    }
}
impl std::error::Error for SigningError {}

// v2: version || height || P || next leaf BE || message flag || message ||
// accepted salt || chain starts. The fixed header is 78 bytes.
const VERSION: u8 = 2;
const PARAMETER: usize = 2;
const NEXT_LEAF: usize = PARAMETER + PARAMETER_LEN;
const HAS_MESSAGE: usize = NEXT_LEAF + 4;
const MESSAGE: usize = HAS_MESSAGE + 1;
const SALT: usize = MESSAGE + MESSAGE_LEN;
const SECRETS: usize = SALT + SALT_LENGTH;

/// Makes Definition 8's signing state durable in an exclusively locked key file.
/// Retries of the recorded message return the same signature.
pub struct SigningKey<K: OneTime> {
    key: K,
    path: PathBuf,
    _lock: File,
    next_leaf: u32,
    last_message: Option<[u8; MESSAGE_LEN]>,
    last_salt: [u8; SALT_LENGTH],
    failed: bool,
}

impl<K: OneTime> SigningKey<K> {
    /// Sample every chain start and `P` from the OS random source, as in
    /// Construction 3 Gen. Refuses an existing file.
    pub fn create(path: impl AsRef<Path>) -> Result<Self, SigningError> {
        let path = path.as_ref().to_path_buf();
        let lock = lock(&path)?;
        let mut file = options()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| match error.kind() {
                io::ErrorKind::AlreadyExists => SigningError::Exists,
                _ => SigningError::Io(error),
            })?;
        let mut secrets = std::vec![0; K::LEAVES as usize * ELEMENTS_LENGTH];
        let mut parameter = [0; PARAMETER_LEN];
        let sampled = getrandom::fill(&mut secrets).and_then(|()| getrandom::fill(&mut parameter));
        let key = sampled
            .map_err(SigningError::Random)
            .and_then(|()| K::from_secrets(&secrets, parameter).map_err(|_| SigningError::Corrupt));
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

    /// Open a v2 key file and hold its permanent sidecar lock.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SigningError> {
        let path = path.as_ref().to_path_buf();
        let lock = lock(&path)?;
        let mut file = File::open(&path).map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => SigningError::Missing,
            _ => SigningError::Io(error),
        })?;
        let mut header = [0; SECRETS];
        if file.metadata()?.len() != (SECRETS + K::LEAVES as usize * ELEMENTS_LENGTH) as u64 {
            return Err(SigningError::Corrupt);
        }
        file.read_exact(&mut header)?;
        let next_leaf = u32::from_be_bytes(header[NEXT_LEAF..HAS_MESSAGE].try_into().unwrap());
        let parameter: [u8; PARAMETER_LEN] = header[PARAMETER..NEXT_LEAF].try_into().unwrap();
        let last_message =
            (header[HAS_MESSAGE] == 1).then(|| header[MESSAGE..SALT].try_into().unwrap());
        let last_salt: [u8; SALT_LENGTH] = header[SALT..].try_into().unwrap();
        if header[0] != VERSION
            || header[1] != K::HEIGHT
            || header[HAS_MESSAGE] > 1
            || next_leaf > K::LEAVES
            || (last_message.is_some() && next_leaf == 0)
            || match &last_message {
                Some(message) => encode(&last_salt, &parameter, next_leaf - 1, message).is_none(),
                None => header[MESSAGE..].iter().any(|&b| b != 0),
            }
        {
            return Err(SigningError::Corrupt);
        }
        let mut secrets = std::vec![0; K::LEAVES as usize * ELEMENTS_LENGTH];
        let key = file
            .read_exact(&mut secrets)
            .map_err(SigningError::Io)
            .and_then(|()| K::from_secrets(&secrets, parameter).map_err(|_| SigningError::Corrupt));
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

    /// Require the next unused leaf to be at least `minimum`, without advancing it.
    /// Returns `LeafBelowMinimum` and drops the lock if the stored state is behind.
    /// A chain's last accepted leaf plus one can detect some restored old copies;
    /// it cannot account for signatures exposed by transactions that never landed.
    pub fn require_next_leaf_at_least(self, minimum: u32) -> Result<Self, SigningError> {
        if self.next_leaf < minimum {
            return Err(SigningError::LeafBelowMinimum {
                next_leaf: self.next_leaf,
                minimum,
            });
        }
        Ok(self)
    }
    /// `root ‖ P`.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }
    /// The leaf allocated by the next attempt; retries do not advance it.
    pub fn next_leaf(&self) -> u32 {
        self.next_leaf
    }
    /// Leaves not yet spent.
    pub fn remaining(&self) -> u32 {
        K::LEAVES - self.next_leaf
    }

    /// Sample salts and persist the attempt before signing. Retrying the
    /// recorded message uses its salt. A new attempt replaces the record;
    /// salt exhaustion or randomness failure spends the leaf and clears it.
    pub fn sign(&mut self, message: &[u8; MESSAGE_LEN]) -> Result<K::Signature, SigningError> {
        self.sign_with_rng(message, |salt| {
            getrandom::fill(salt).map_err(SigningError::Random)
        })
    }

    /// Sign using an explicit cryptographically secure random-byte source.
    /// The callback must fill every requested byte with fresh CSPRNG output or return an error.
    /// Failed entropy or salt sampling still spends and persists the leaf. Exact retries do not
    /// call the source. The callback is used only for signature salts; creation uses OS randomness.
    pub fn sign_with_rng(
        &mut self,
        message: &[u8; MESSAGE_LEN],
        mut fill: impl FnMut(&mut [u8]) -> Result<(), SigningError>,
    ) -> Result<K::Signature, SigningError> {
        if self.failed {
            return Err(SigningError::Unusable);
        }
        if self.last_message.as_ref() == Some(message) {
            return self
                .key
                .sign_at_with_salt(self.next_leaf - 1, message, &self.last_salt)
                .ok_or(SigningError::Corrupt);
        }
        if self.next_leaf >= K::LEAVES {
            return Err(SigningError::Exhausted);
        }
        let leaf = self.next_leaf;
        let parameter = self.verifying_key();
        let sampled = crate::hazmat::sample_salt(parameter.parameter(), leaf, message, &mut fill);
        // Definition 8 permits one attempt per leaf, including failure.
        // Persist the attempt before returning either a signature or error.
        self.next_leaf = leaf + 1;
        self.last_message = sampled.is_ok().then_some(*message);
        self.last_salt = sampled.as_ref().copied().unwrap_or([0; SALT_LENGTH]);
        if let Err(error) = self.write() {
            self.failed = true;
            return Err(error);
        }
        self.key
            .sign_at_with_salt(leaf, message, &sampled?)
            .ok_or(SigningError::Corrupt)
    }

    fn write_record(&self, file: &mut File) -> Result<(), SigningError> {
        let mut header = [0; SECRETS];
        header[0] = VERSION;
        header[1] = K::HEIGHT;
        header[PARAMETER..NEXT_LEAF].copy_from_slice(self.verifying_key().parameter());
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

    fn write(&self) -> Result<(), SigningError> {
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

/// Lock a permanent sidecar: replacing the record must not replace its lock.
/// Never unlink the sidecar; another inode would allow a second holder.
/// On Unix, `try_lock` uses the same `flock` as the TypeScript signer.
fn lock(path: &Path) -> Result<File, SigningError> {
    let file = options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(sibling(path, ".lock"))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(SigningError::Locked),
        Err(TryLockError::Error(error)) => Err(error.into()),
    }
}

/// Sync the directory entry after creating or replacing the record.
fn sync_dir(path: &Path) -> Result<(), SigningError> {
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
    use crate::{winternitz, xmss};

    #[test]
    fn failed_grinding_and_persistence_never_release_a_signature() {
        let dir =
            std::env::temp_dir().join(std::format!("winternitz-failure-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("once.key");
        let mut signer = xmss::SigningKey::create(&path).unwrap();
        let message = [0; MESSAGE_LEN];
        let mut bad = [0; SALT_LENGTH];
        for counter in 0u32.. {
            bad[..4].copy_from_slice(&counter.to_le_bytes());
            if encode(&bad, signer.verifying_key().parameter(), 0, &message).is_none() {
                break;
            }
        }
        let mut trials = 0;
        assert!(matches!(
            signer.sign_with_rng(&message, |salt| {
                trials += 1;
                salt.copy_from_slice(&bad);
                Ok(())
            }),
            Err(SigningError::SaltsExhausted)
        ));
        assert_eq!(trials, crate::signing::MAX_TRIALS);
        assert!(matches!(
            signer.sign_with_rng(&message, |_| Err(SigningError::Io(io::Error::other(
                "entropy unavailable"
            )))),
            Err(SigningError::Io(_))
        ));
        assert_eq!(signer.next_leaf(), 2);
        let before = std::fs::read(&path).unwrap();
        assert_eq!(before[HAS_MESSAGE], 0);
        drop(signer);
        let mut signer = xmss::SigningKey::open(&path).unwrap();
        assert_eq!(signer.next_leaf(), 2);

        std::fs::create_dir(sibling(&path, ".tmp")).unwrap();
        assert!(matches!(signer.sign(&message), Err(SigningError::Io(_))));
        assert!(matches!(signer.sign(&message), Err(SigningError::Unusable)));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        drop(signer);
        std::fs::remove_dir(sibling(&path, ".tmp")).unwrap();
        let mut signer = xmss::SigningKey::open(&path).unwrap();
        let sig = signer.sign(&message).unwrap();
        assert_eq!(
            signer
                .sign_with_rng(&message, |_| panic!("retry drew randomness"))
                .unwrap(),
            sig
        );
        drop(signer);
        let mut signer = xmss::SigningKey::open(&path).unwrap();
        assert_eq!(
            signer
                .sign_with_rng(&message, |_| panic!("reopened retry drew randomness"))
                .unwrap(),
            sig
        );
        assert_eq!(sig.verify(&signer.verifying_key(), &message), Ok(()));
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
                winternitz::SigningKey::open(&path),
                Err(SigningError::Corrupt)
            ));
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
