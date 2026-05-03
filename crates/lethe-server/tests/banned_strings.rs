//! Lint test: enforce the trust-vocabulary contract from the plan.
//!
//! The product MUST NOT use language that overpromises trust. We can't
//! verify intent, only continuity, provenance, membership, and
//! attestations. Strings like "verified safe", "verified human", "not
//! honeypot", "trusted", "reputation", "score" creep in on every refactor;
//! a unit test is cheaper than diligence.
//!
//! Scans:
//!   - `crates/lethe-server/templates/*.html`
//!   - `client/src/**/*.ts`
//!
//! Skips this file (which legitimately mentions the banned strings).

use std::path::{Path, PathBuf};

const BANNED: &[&str] = &[
    "verified safe",
    "verified human",
    "not honeypot",
    "trusted member",
    "trusted user",
    "reputation",
    "trust score",
    "risk score",
];

#[test]
fn no_banned_trust_vocabulary_in_user_facing_strings() {
    let workspace = workspace_root();
    let mut findings: Vec<String> = Vec::new();

    let template_dir = workspace.join("crates/lethe-server/templates");
    let client_dir = workspace.join("client/src");

    visit_files(&template_dir, "html", &mut |path, body| {
        check(path, body, &mut findings);
    });
    visit_files(&client_dir, "ts", &mut |path, body| {
        // Skip the strings module and this very test only matters for
        // Rust files; here the strings module is the source of truth and
        // already uses only allowed labels.
        check(path, body, &mut findings);
    });

    assert!(
        findings.is_empty(),
        "banned trust vocabulary found:\n  - {}",
        findings.join("\n  - "),
    );
}

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR points at crates/lethe-server; go up two levels.
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    here.parent()
        .and_then(|p| p.parent())
        .map(PathBuf::from)
        .expect("workspace root")
}

fn check(path: &Path, body: &str, findings: &mut Vec<String>) {
    let lower = body.to_ascii_lowercase();
    for needle in BANNED {
        if lower.contains(needle) {
            findings.push(format!("{}: contains {:?}", path.display(), needle));
        }
    }
}

fn visit_files(dir: &Path, ext: &str, f: &mut dyn FnMut(&Path, &str)) {
    if !dir.exists() {
        return;
    }
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let entries = match std::fs::read_dir(&d) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().and_then(|s| s.to_str()) == Some(ext) {
                if let Ok(body) = std::fs::read_to_string(&p) {
                    f(&p, &body);
                }
            }
        }
    }
}
