//! Persistent server identity (Ed25519 keypair) stored in the
//! `instance_identity` table. Generated on first boot if absent.
//!
//! The 32-byte seed is the only value stored on disk; the public key is
//! derived deterministically from the seed. This keeps the schema small
//! and lets operators back up the seed alone.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore as _;
use sqlx::PgPool;

/// 32-byte Ed25519 public key.
pub type ServerPubkey = [u8; 32];

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

    /// Loads the identity row, generating one if the table is empty.
    /// After loading, stamps the originating server id on any pre-
    /// federation rows that are still NULL so they federate correctly.
    pub async fn load_or_create(db: &PgPool) -> Result<Self, sqlx::Error> {
        let existing: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT server_pubkey, server_privkey FROM instance_identity LIMIT 1",
        )
        .fetch_optional(db)
        .await?;

        let id = match existing {
            Some((pk, sk)) => Self::from_seed_bytes(&sk).map_err(|e| sqlx::Error::Protocol(
                format!("instance_identity row corrupt: {e}; stored pubkey was {}", hex(&pk)),
            ))?,
            None => {
                let mut seed = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut seed);
                let id = Self::from_seed(seed);
                sqlx::query(
                    "INSERT INTO instance_identity (server_pubkey, server_privkey)
                     VALUES ($1, $2)
                     ON CONFLICT DO NOTHING",
                )
                .bind(&id.pubkey[..])
                .bind(&seed[..])
                .execute(db)
                .await?;
                // Race-safe re-read in case another process inserted first.
                let row: (Vec<u8>, Vec<u8>) = sqlx::query_as(
                    "SELECT server_pubkey, server_privkey FROM instance_identity LIMIT 1",
                )
                .fetch_one(db)
                .await?;
                Self::from_seed_bytes(&row.1).map_err(|e| sqlx::Error::Protocol(
                    format!("instance_identity row corrupt after insert: {e}"),
                ))?
            }
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

    fn from_seed_bytes(seed: &[u8]) -> Result<Self, &'static str> {
        let arr: [u8; 32] = seed.try_into().map_err(|_| "wrong seed length")?;
        Ok(Self::from_seed(arr))
    }
}

/// Verifies an Ed25519 signature produced by some peer's server key.
pub fn verify_server_signature(
    server_pubkey: &[u8],
    signature: &[u8],
    msg: &[u8],
) -> Result<(), &'static str> {
    let pk: [u8; 32] = server_pubkey.try_into().map_err(|_| "bad server pubkey")?;
    let sig: [u8; 64] = signature.try_into().map_err(|_| "bad signature")?;
    let vk = VerifyingKey::from_bytes(&pk).map_err(|_| "bad server pubkey")?;
    vk.verify(msg, &Signature::from_bytes(&sig))
        .map_err(|_| "signature does not verify")
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
