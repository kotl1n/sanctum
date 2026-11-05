use crate::{
    Error, MAX_BODY, Result, json,
    redaction::{Policy, Redactor},
};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use fs2::FileExt;
use serde_json::{Value, json as value};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

const MAGIC: &[u8] = b"SANCTUM2";
const MAX_VAULT: usize = 32 * 1024 * 1024;
pub const DEFAULT_TTL: u64 = 24 * 60 * 60;

pub struct Vault {
    directory: PathBuf,
    ttl: u64,
}
impl Vault {
    pub fn new(directory: PathBuf) -> Result<Self> {
        private_directory(&directory)?;
        Ok(Self {
            directory,
            ttl: DEFAULT_TTL,
        })
    }
    pub fn with_ttl(mut self, seconds: u64) -> Result<Self> {
        if seconds == 0 || seconds > 30 * DEFAULT_TTL {
            return Err(Error("invalid_vault_ttl"));
        }
        self.ttl = seconds;
        Ok(self)
    }
    pub fn default_directory() -> Result<PathBuf> {
        if let Some(path) = std::env::var_os("SANCTUM_STATE_DIR") {
            return Ok(path.into());
        }
        let base = std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .or_else(|| crate::platform::home().ok().map(|p| p.join(".local/state")))
            .ok_or(Error("home_directory_unavailable"))?;
        Ok(base.join("sanctum"))
    }
    fn locked(&self) -> Result<File> {
        let path = self.directory.join("vault.lock");
        let file = private_open(&path, true)?;
        let until = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match file.try_lock_exclusive() {
                Ok(()) => return Ok(file),
                Err(e)
                    if (e.kind() == std::io::ErrorKind::WouldBlock
                        || (e.raw_os_error().is_some()
                            && e.raw_os_error() == fs2::lock_contended_error().raw_os_error()))
                        && std::time::Instant::now() < until =>
                {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(_) => return Err(Error("vault_busy")),
            }
        }
    }
    fn key(&self) -> Result<Zeroizing<Vec<u8>>> {
        let path = self.directory.join("master.key");
        if !path
            .try_exists()
            .map_err(|_| Error("vault_key_unavailable"))?
        {
            let mut key = Zeroizing::new(vec![0u8; 32]);
            getrandom::fill(&mut key).map_err(|_| Error("os_random_unavailable"))?;
            let mut file = private_create(&path)?;
            #[cfg(windows)]
            let stored = crate::windows::key_blob(&key, true)?;
            #[cfg(not(windows))]
            let stored = Zeroizing::new(key.to_vec());
            file.write_all(&stored)
                .and_then(|_| file.sync_all())
                .map_err(|_| Error("vault_key_write_failed"))?;
        }
        let mut raw = Zeroizing::new(Vec::new());
        private_open(&path, false)?
            .take(if cfg!(windows) { 65537 } else { 33 })
            .read_to_end(&mut raw)
            .map_err(|_| Error("vault_key_read_failed"))?;
        #[cfg(windows)]
        let raw = crate::windows::key_blob(&raw, false)?;
        if raw.len() != 32 {
            return Err(Error("invalid_vault_key"));
        }
        Ok(raw)
    }
    fn identity(session: &str) -> Result<String> {
        if session.is_empty() || session.len() > 512 {
            return Err(Error("session_id_required"));
        }
        Ok(format!("{:x}", Sha256::digest(session.as_bytes())))
    }
    fn read(&self, identity: &str, policy: Policy, key: &[u8]) -> Result<Redactor> {
        let path = self.directory.join(format!("{identity}.vault"));
        if !path.try_exists().map_err(|_| Error("vault_read_failed"))? {
            return Redactor::new(policy);
        }
        let mut raw = Vec::new();
        private_open(&path, false)?
            .take((MAX_VAULT + 1) as u64)
            .read_to_end(&mut raw)
            .map_err(|_| Error("vault_read_failed"))?;
        if raw.len() > MAX_VAULT || raw.len() < MAGIC.len() + 24 + 16 || !raw.starts_with(MAGIC) {
            return Err(Error("invalid_encrypted_vault"));
        }
        let cipher =
            XChaCha20Poly1305::new_from_slice(key).map_err(|_| Error("invalid_vault_key"))?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&raw[MAGIC.len()..MAGIC.len() + 24]),
                    Payload {
                        msg: &raw[MAGIC.len() + 24..],
                        aad: identity.as_bytes(),
                    },
                )
                .map_err(|_| Error("vault_authentication_failed"))?,
        );
        let saved = json::parse(&plaintext)?;
        let created = saved["created"].as_u64().ok_or(Error("invalid_snapshot"))?;

        if now()?.saturating_sub(created) >= self.ttl {
            return Err(Error("vault_expired"));
        }
        Redactor::from_snapshot(policy, &saved["state"])
    }
    fn write(&self, identity: &str, engine: &Redactor, key: &[u8]) -> Result<()> {
        let plaintext = Zeroizing::new(json::encode(
            &value!({"created":now()?,"state":engine.snapshot()}),
        )?);
        if plaintext.len() > MAX_VAULT - 64 {
            return Err(Error("vault_size_limit"));
        }
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce).map_err(|_| Error("os_random_unavailable"))?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(key).map_err(|_| Error("invalid_vault_key"))?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: identity.as_bytes(),
                },
            )
            .map_err(|_| Error("vault_encrypt_failed"))?;
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|_| Error("os_random_unavailable"))?;
        let temp = self
            .directory
            .join(format!("{:x}.tmp", Sha256::digest(random)));
        let result = (|| {
            let mut file = private_create(&temp)?;
            file.write_all(MAGIC)
                .and_then(|_| file.write_all(&nonce))
                .and_then(|_| file.write_all(&ciphertext))
                .and_then(|_| file.sync_all())
                .map_err(|_| Error("vault_write_failed"))?;
            fs::rename(&temp, self.directory.join(format!("{identity}.vault")))
                .map_err(|_| Error("vault_commit_failed"))?;
            #[cfg(unix)]
            File::open(&self.directory)
                .and_then(|f| f.sync_all())
                .map_err(|_| Error("vault_commit_failed"))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temp);
        }
        result
    }

    pub fn transact<T>(
        &self,
        session: &str,
        policy: Policy,
        operation: impl FnOnce(&mut Redactor) -> Result<T>,
    ) -> Result<T> {
        let identity = Self::identity(session)?;
        let _lock = self.locked()?;
        let key = self.key()?;
        let mut engine = self.read(&identity, policy, &key)?;
        let result = operation(&mut engine)?;
        self.write(&identity, &engine, &key)?;
        Ok(result)
    }
    pub fn forget(&self, session: &str) -> Result<()> {
        let identity = Self::identity(session)?;
        let _lock = self.locked()?;
        let path = self.directory.join(format!("{identity}.vault"));
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(Error("vault_delete_failed")),
        }
    }
    pub fn exists(&self, session: &str) -> Result<bool> {
        let id = Self::identity(session)?;
        self.directory
            .join(format!("{id}.vault"))
            .try_exists()
            .map_err(|_| Error("vault_read_failed"))
    }
    pub fn copy_session(&self, source: &str, target: &str, policy: Policy) -> Result<()> {
        let source = Self::identity(source)?;
        let target = Self::identity(target)?;
        let _lock = self.locked()?;
        let key = self.key()?;
        if self.directory.join(format!("{target}.vault")).exists() {
            return Err(Error("session_already_exists"));
        }
        let engine = self.read(&source, policy, &key)?;
        self.write(&target, &engine, &key)
    }
    pub fn mask(&self, session: &str, policy: Policy, input: &Value) -> Result<Value> {
        if json::encode(input)?.len() > MAX_BODY {
            return Err(Error("input_size_limit"));
        }
        self.transact(session, policy, |engine| {
            engine.reserve(input)?;
            let first = engine.value(input)?;
            engine.value(&first)
        })
    }
}
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Error("clock_unavailable"))
}

fn private_directory(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(Error("absolute_state_path_required"));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| Error("state_directory_failed"))?;
    }
    let builder = fs::DirBuilder::new();
    #[cfg(unix)]
    let mut builder = builder;
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(Error("state_directory_failed")),
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| Error("state_directory_failed"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(Error("private_directory_required"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error("private_directory_required"));
        }
    }
    #[cfg(windows)]
    crate::windows::protect_path(path)?;
    #[cfg(not(any(unix, windows)))]
    return Err(Error("vault_platform_unsupported"));
    Ok(())
}
fn private_create(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(path)
        .map_err(|_| Error("private_file_create_failed"))?;
    #[cfg(windows)]
    {
        crate::windows::protect_path(path)?;
        crate::windows::check_file(&file)?;
    }
    Ok(file)
}
fn private_open(path: &Path, create: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(create).create(create);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(path)
        .map_err(|_| Error("vault_file_unavailable"))?;
    #[cfg(windows)]
    crate::windows::check_file(&file)?;
    let metadata = file
        .metadata()
        .map_err(|_| Error("vault_file_unavailable"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Error("private_file_required"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0 || metadata.nlink() != 1 {
            return Err(Error("private_file_required"));
        }
    }
    Ok(file)
}
