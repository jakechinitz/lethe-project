//! Operator-side CLI for managing a Lethe server's federation peers
//! and admin tokens. Talks to the running server's HTTP API; doesn't
//! touch the database directly.
//!
//! Two env vars are required for any command that hits an admin
//! endpoint:
//!
//!   LETHE_ADMIN_URL   — base URL, e.g. https://lethe.example or
//!                       http://127.0.0.1:8080
//!   LETHE_ADMIN_TOKEN — bearer token (env-bootstrap or table-minted)
//!
//! `info` doesn't need a token; everything under `peers` and `tokens`
//! does.

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(name = "lethe-cli", version, about = "Manage a Lethe federation node")]
struct Cli {
    /// Server base URL. Defaults to $LETHE_ADMIN_URL.
    #[arg(long, env = "LETHE_ADMIN_URL")]
    url: Option<String>,
    /// Bearer admin token. Defaults to $LETHE_ADMIN_TOKEN.
    #[arg(long, env = "LETHE_ADMIN_TOKEN")]
    token: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print the server's federation info (pubkey, versions, hashes).
    Info,
    /// Manage federation peers.
    #[command(subcommand)]
    Peers(PeersCmd),
    /// Manage admin tokens for delegating peer-management to others.
    #[command(subcommand)]
    Tokens(TokensCmd),
}

#[derive(Subcommand)]
enum PeersCmd {
    /// List all peers (enabled and disabled).
    List,
    /// Add (or re-enable) a peer.
    Add {
        /// Peer's server pubkey, urlsafe-base64 (32 bytes).
        #[arg(long)]
        pubkey: String,
        /// Base URL of the peer, e.g. https://other.example
        #[arg(long)]
        endpoint: String,
        /// Optional human label for the peer.
        #[arg(long)]
        label: Option<String>,
    },
    /// Disable a peer (defederate). Existing replicated content stays.
    Disable {
        #[arg(long)]
        pubkey: String,
    },
    /// Re-enable a previously-disabled peer.
    Enable {
        #[arg(long)]
        pubkey: String,
    },
}

#[derive(Subcommand)]
enum TokensCmd {
    /// List minted admin tokens (label + status only; never the token).
    List,
    /// Mint a new admin token. The token is returned exactly once.
    Add {
        #[arg(long)]
        label: String,
    },
    /// Revoke all tokens with a given label.
    Revoke {
        #[arg(long)]
        label: String,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let url = cli
        .url
        .ok_or("LETHE_ADMIN_URL not set (or pass --url)")?
        .trim_end_matches('/')
        .to_string();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    match cli.cmd {
        Cmd::Info => {
            let r: serde_json::Value = client
                .get(format!("{url}/api/federation/info"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            println!("{}", serde_json::to_string_pretty(&r)?);
        }
        Cmd::Peers(PeersCmd::List) => {
            let token = cli.token.ok_or("LETHE_ADMIN_TOKEN not set")?;
            let r: PeersList = client
                .get(format!("{url}/api/federation/peers"))
                .bearer_auth(&token)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            if r.peers.is_empty() {
                println!("(no peers)");
            } else {
                for p in r.peers {
                    let status = if p.enabled { "enabled" } else { "disabled" };
                    let label = p.label.as_deref().unwrap_or("-");
                    println!("{status:9}  {label:24}  {}  {}", p.endpoint, p.server_pubkey);
                }
            }
        }
        Cmd::Peers(PeersCmd::Add { pubkey, endpoint, label }) => {
            let token = cli.token.ok_or("LETHE_ADMIN_TOKEN not set")?;
            client
                .post(format!("{url}/api/federation/peers"))
                .bearer_auth(&token)
                .json(&serde_json::json!({
                    "server_pubkey": pubkey,
                    "endpoint": endpoint,
                    "label": label,
                }))
                .send()
                .await?
                .error_for_status()?;
            println!("ok: peer added/updated");
        }
        Cmd::Peers(PeersCmd::Disable { pubkey }) => {
            set_peer(&client, &url, cli.token.as_deref(), &pubkey, false).await?;
        }
        Cmd::Peers(PeersCmd::Enable { pubkey }) => {
            set_peer(&client, &url, cli.token.as_deref(), &pubkey, true).await?;
        }
        Cmd::Tokens(TokensCmd::List) => {
            let token = cli.token.ok_or("LETHE_ADMIN_TOKEN not set")?;
            let r: TokensList = client
                .get(format!("{url}/api/federation/admin/tokens"))
                .bearer_auth(&token)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            if r.tokens.is_empty() {
                println!("(no tokens)");
            } else {
                for t in r.tokens {
                    let status = match t.revoked_at.as_deref() {
                        Some(d) => format!("revoked {d}"),
                        None => "active".to_string(),
                    };
                    println!("{:24} {:24} {status}", t.label, t.created_at);
                }
            }
        }
        Cmd::Tokens(TokensCmd::Add { label }) => {
            let token = cli.token.ok_or("LETHE_ADMIN_TOKEN not set")?;
            let r: MintTokenResp = client
                .post(format!("{url}/api/federation/admin/tokens"))
                .bearer_auth(&token)
                .json(&serde_json::json!({"label": label}))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            println!("label: {}", r.label);
            println!("token: {}", r.token);
            eprintln!();
            eprintln!("This is the only time the token will be shown. Save it now.");
        }
        Cmd::Tokens(TokensCmd::Revoke { label }) => {
            let token = cli.token.ok_or("LETHE_ADMIN_TOKEN not set")?;
            client
                .post(format!("{url}/api/federation/admin/tokens/revoke"))
                .bearer_auth(&token)
                .json(&serde_json::json!({"label": label}))
                .send()
                .await?
                .error_for_status()?;
            println!("ok: revoked {label}");
        }
    }
    Ok(())
}

async fn set_peer(
    client: &reqwest::Client,
    url: &str,
    token: Option<&str>,
    pubkey: &str,
    enabled: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let token = token.ok_or("LETHE_ADMIN_TOKEN not set")?;
    client
        .post(format!("{url}/api/federation/peers/disable"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "server_pubkey": pubkey,
            "enabled": enabled,
        }))
        .send()
        .await?
        .error_for_status()?;
    println!("ok: peer {pubkey} → enabled={enabled}");
    Ok(())
}

#[derive(Deserialize)]
struct PeersList {
    peers: Vec<PeerView>,
}

#[derive(Deserialize)]
struct PeerView {
    server_pubkey: String,
    endpoint: String,
    label: Option<String>,
    enabled: bool,
}

#[derive(Deserialize)]
struct TokensList {
    tokens: Vec<TokenView>,
}

#[derive(Deserialize)]
struct TokenView {
    label: String,
    created_at: String,
    #[serde(default)]
    revoked_at: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct MintTokenResp {
    label: String,
    token: String,
}
