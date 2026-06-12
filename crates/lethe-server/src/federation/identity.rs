//! Persistent server identity (Ed25519 keypair).
//!
//! The 32-byte seed lives in a single file at the path supplied by
//! `Config::server_key_path` — typically `/var/lib/lethe/server-key`,
//! owned by the server's runtime user, mode 0600. The public key is
//! derived deterministically from the seed, so the file is the only
//! piece of state needed to restore federation identity.
//!
//! Threat model rationale: this seed signs every event this server
//! emits to its peers. Keeping it out of the database means a routine
//! DB compromise (SQL injection, a leaked role password, an attacker
//! with read-only DB access) cannot extract it. Routine `pg_dump`
//! backups carry no copy of it either.
//!
//! Legacy migration: an older release stored the seed in
//! `instance_identity.server_privkey`. On first boot of this release
//! with the key file absent, we read that row, write the file, and
//! NULL the column so the seed only exists on disk thereafter.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::RngCore as _;
use sqlx::PgPool;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// 32-byte Ed25519 public key.
pub type ServerPubkey = [u8; 32];

const SEED_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("server key file {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "server key file {path} has mode {mode:o}; must be owner-readable only \
         (0600). Fix with: chmod 0600 {path}"
    )]
    Insecure { path: PathBuf, mode: u32 },
    #[error(
        "server key file {path} is {actual} bytes; expected exactly {expected}. \
         The file is corrupt or was not written by this server."
    )]
    BadLength {
        path: PathBuf,
        actual: usize,
        expected: usize,
    },
    #[error("database error during identity load: {0}")]
    Db(#[from] sqlx::Error),
}

#[derive(Clone)]
pub struct Identity {
    pubkey: [u8; 32],
    signing_key: SigningKey,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the private key.
        f.debug_struct("Identity")
            .field("pubkey", &hex(&self.pubkey))
            .finish()
    }
}

impl Identity {
    pub fn pubkey(&self) -> &[u8; 32] {
        &self.pubkey
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing_key.sign(msg).to_bytes()
    }

    /// Loads the server identity from `key_path`, or — for first-boot
    /// or post-upgrade installs — creates it. Three cases:
    ///
    ///   1. File exists: read it, verify mode is 0600, derive identity.
    ///   2. File missing AND a legacy DB row holds a seed: migrate the
    ///      seed into the file and NULL the DB column.
    ///   3. File missing AND no legacy DB row: generate a fresh seed
    ///      and write it.
    ///
    /// After loading, stamps the originating server id on any pre-
    /// federation rows that are still NULL so they federate correctly.
    pub async fn load_or_create(
        db: &PgPool,
        key_path: &Path,
    ) -> Result<Self, IdentityError> {
        let id = if key_path.exists() {
            load_from_file(key_path)?
        } else if let Some(seed) = read_legacy_seed(db).await? {
            write_seed_file(key_path, &seed)?;
            clear_legacy_seed(db).await?;
            tracing::warn!(
                path = %key_path.display(),
                "migrated server identity seed from DB to file; \
                 server_privkey column set to NULL"
            );
            Self::from_seed(seed)
        } else {
            let mut seed = [0u8; SEED_LEN];
            rand::thread_rng().fill_bytes(&mut seed);
            write_seed_file(key_path, &seed)?;
            let id = Self::from_seed(seed);
            // Persist the pubkey (only) so other tooling that wants
            // the server identity from the DB has a stable lookup.
            // Private key NEVER goes here.
            sqlx::query(
                "INSERT INTO instance_identity (server_pubkey, server_privkey)
                 VALUES ($1, NULL)
                 ON CONFLICT DO NOTHING",
            )
            .bind(&id.pubkey[..])
            .execute(db)
            .await?;
            tracing::info!(
                path = %key_path.display(),
                "generated fresh server identity seed"
            );
            id
        };

        // Backfill: pre-federation posts and threads have NULL origin
        // columns. Stamp them with this server's pubkey so they
        // federate. Idempotent — only touches NULL rows.
        sqlx::query(
            "UPDATE threads SET origin_server_id = $1 WHERE origin_server_id IS NULL",
        )
        .bind(&id.pubkey[..])
        .execute(db)
        .await?;
        sqlx::query(
            "UPDATE posts
             SET origin_server_id = $1, origin_post_id = id
             WHERE origin_server_id IS NULL",
        )
        .bind(&id.pubkey[..])
        .execute(db)
        .await?;

        Ok(id)
    }

    fn from_seed(seed: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let pubkey = signing_key.verifying_key().to_bytes();
        Self { pubkey, signing_key }
    }
}

fn load_from_file(path: &Path) -> Result<Identity, IdentityError> {
    let meta = std::fs::metadata(path).map_err(|e| IdentityError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    // 0o077 are the group + other bits. Any of them set means another
    // user could read the seed; refuse to start.
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(IdentityError::Insecure {
            path: path.to_path_buf(),
            mode,
        });
    }
    let bytes = std::fs::read(path).map_err(|e| IdentityError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    if bytes.len() != SEED_LEN {
        return Err(IdentityError::BadLength {
            path: path.to_path_buf(),
            actual: bytes.len(),
            expected: SEED_LEN,
        });
    }
    let mut seed = [0u8; SEED_LEN];
    seed.copy_from_slice(&bytes);
    Ok(Identity::from_seed(seed))
}

/// Atomically creates `path` with mode 0600 and writes `seed`. Fails
/// if the file already exists (we never overwrite — that's how
/// generation stays single-attempt).
fn write_seed_file(path: &Path, seed: &[u8; SEED_LEN]) -> Result<(), IdentityError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| IdentityError::Io {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| IdentityError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
    use std::io::Write as _;
    f.write_all(seed).map_err(|e| IdentityError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    f.sync_all().map_err(|e| IdentityError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    Ok(())
}

/// Reads a legacy seed from `instance_identity.server_privkey` if the
/// row exists and the column is non-NULL. Returns `Ok(None)` when
/// there's nothing to migrate.
async fn read_legacy_seed(db: &PgPool) -> Result<Option<[u8; 32]>, sqlx::Error> {
    let row: Option<(Option<Vec<u8>>,)> = sqlx::query_as(
        "SELECT server_privkey FROM instance_identity LIMIT 1",
    )
    .fetch_optional(db)
    .await?;
    match row {
        Some((Some(seed),)) if seed.len() == SEED_LEN => {
            let mut arr = [0u8; SEED_LEN];
            arr.copy_from_slice(&seed);
            Ok(Some(arr))
        }
        Some((Some(other),)) => Err(sqlx::Error::Protocol(format!(
            "legacy server_privkey has wrong length: {} (expected {})",
            other.len(),
            SEED_LEN
        ))),
        _ => Ok(None),
    }
}

async fn clear_legacy_seed(db: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE instance_identity SET server_privkey = NULL")
        .execute(db)
        .await?;
    Ok(())
}

/// Verifies an Ed25519 signature produced by some peer's server key.
/// Uses `verify_strict` so a peer can't substitute a malleable variant
/// of an otherwise-valid signature — federation pulls match the same
/// strict mode `crypto::verify_ed25519` uses for local routes.
pub fn verify_server_signature(
    server_pubkey: &[u8],
    signature: &[u8],
    msg: &[u8],
) -> Result<(), &'static str> {
    let pk: [u8; 32] = server_pubkey.try_into().map_err(|_| "bad server pubkey")?;
    let sig: [u8; 64] = signature.try_into().map_err(|_| "bad signature")?;
    let vk = VerifyingKey::from_bytes(&pk).map_err(|_| "bad server pubkey")?;
    vk.verify_strict(msg, &Signature::from_bytes(&sig))
        .map_err(|_| "signature does not verify")
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
