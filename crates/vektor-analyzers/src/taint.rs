//! Cross-tool Session Taint Fingerprinting & Exfiltration Detector.
//!
//! Computes irreversible SHA-256 fingerprints of sensitive values (raw, Base64, Hex, URL-encoded)
//! so Vektor can detect multi-step secret/PII exfiltration across `PostToolUse` -> `PreToolUse`
//! in sub-millisecond time without ever persisting plaintext secrets to disk.

use std::collections::HashSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Minimum length of a sensitive value eligible for token fingerprinting.
const MIN_TAINT_TOKEN_LEN: usize = 8;
/// Maximum fingerprints extracted from a single file read (bounds memory & `SQLite` writes).
const MAX_FINGERPRINTS_PER_FILE: usize = 128;

/// An irreversible fingerprint derived from a sensitive value read during a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintFingerprint {
    /// Hex-encoded SHA-256 digest of the sensitive token (or its encoded form).
    pub token_hash: String,
    /// Category (`env_value`, `secret_token`, `pii_value`, `sensitive_file`).
    pub kind: String,
    /// Representation hashed (`raw`, `base64`, `hex`, `url`, `marker`).
    pub encoding: String,
}

/// Active taint record retrieved from session state for matching in `PreToolUse`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveTaint {
    pub token_hash: String,
    pub source_path: String,
    pub kind: String,
    pub encoding: String,
}

/// Result when a `PreToolUse` payload matches an active tainted fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintMatch {
    pub source_path: String,
    pub kind: String,
    pub encoding: String,
}

/// Returns `true` if `path` looks like a sensitive credential/key/environment file.
#[must_use]
pub fn is_sensitive_path(path: &str) -> bool {
    let norm = path.replace('\\', "/").to_ascii_lowercase();
    let file_name = Path::new(&norm)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(&norm);

    if file_name == ".env"
        || (file_name.starts_with(".env.")
            && !matches!(file_name, ".env.example" | ".env.sample" | ".env.template"))
    {
        return true;
    }

    if matches!(
        file_name,
        "id_rsa"
            | "id_ed25519"
            | "id_ecdsa"
            | "id_dsa"
            | ".npmrc"
            | ".pypirc"
            | ".netrc"
            | "_netrc"
            | "credentials"
            | "credentials.json"
            | "service-account.json"
            | "secrets.yml"
            | "secrets.yaml"
            | "secrets.json"
            | "secrets.toml"
            | ".htpasswd"
    ) {
        return true;
    }

    if norm.contains("/.aws/credentials") || norm.contains("/.ssh/id_") {
        return true;
    }

    Path::new(file_name)
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| {
            matches!(
                ext.to_ascii_lowercase().as_str(),
                "pem" | "key" | "p12" | "pfx" | "jks" | "kdbx"
            )
        })
}

/// Extract irreversible SHA-256 taint fingerprints from a file read by an agent.
///
/// Returns an empty vector if the file is neither a sensitive path nor contains
/// high-severity secrets/PII. Plaintext values are never stored or returned.
#[must_use]
pub fn extract_taint_fingerprints(path: &str, content: &str) -> Vec<TaintFingerprint> {
    let sensitive_path = is_sensitive_path(path);
    let mut raw_values: Vec<(String, &'static str)> = Vec::new();
    let mut seen_values: HashSet<String> = HashSet::new();

    if sensitive_path {
        // Parse KEY=VALUE lines (e.g. `.env`, `.npmrc`, `credentials`).
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let stripped = trimmed.strip_prefix("export ").unwrap_or(trimmed).trim();
            if let Some((_, raw_val)) = stripped.split_once('=') {
                let val = raw_val.trim().trim_matches(['"', '\'']).trim().to_string();
                if is_fingerprint_worthy(&val) && seen_values.insert(val.clone()) {
                    raw_values.push((val, "env_value"));
                }
            }
        }
    }

    // Also inspect lines flagged by secrets or high-severity PII scanners.
    let secret_hits = crate::secrets::scan_text(path, content);
    let pii_hits: Vec<_> = crate::pii::scan_text(path, content)
        .into_iter()
        .filter(|h| h.severity >= crate::Severity::High)
        .collect();

    if !secret_hits.is_empty() || !pii_hits.is_empty() {
        let lines: Vec<&str> = content.lines().collect();
        let mut flagged_lines: HashSet<(usize, &'static str)> = HashSet::new();
        for hit in &secret_hits {
            if hit.line > 0 {
                flagged_lines.insert((hit.line - 1, "secret_token"));
            }
        }
        for hit in &pii_hits {
            if hit.line > 0 {
                flagged_lines.insert((hit.line - 1, "pii_value"));
            }
        }

        for (idx, kind) in flagged_lines {
            if let Some(line) = lines.get(idx) {
                for candidate in extract_candidate_tokens(line) {
                    if is_fingerprint_worthy(candidate) && seen_values.insert(candidate.to_string())
                    {
                        raw_values.push((candidate.to_string(), kind));
                    }
                }
            }
        }
    }

    if !sensitive_path && raw_values.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut seen_hashes: HashSet<String> = HashSet::new();

    // Always include a session-level file marker so network exfil guards know the session is tainted.
    let marker_hash = sha256_hex(format!("vektor-taint-marker:{path}").as_bytes());
    if seen_hashes.insert(marker_hash.clone()) {
        out.push(TaintFingerprint {
            token_hash: marker_hash,
            kind: if sensitive_path {
                "sensitive_file".to_string()
            } else {
                "secret_source".to_string()
            },
            encoding: "marker".to_string(),
        });
    }

    for (val, kind) in raw_values {
        let variants = [
            ("raw", val.clone()),
            ("base64", base64_encode(val.as_bytes())),
            ("hex", hex_encode(val.as_bytes())),
            ("url", url_encode(&val)),
        ];
        for (encoding, encoded) in variants {
            if out.len() >= MAX_FINGERPRINTS_PER_FILE {
                return out;
            }
            if encoded.len() < MIN_TAINT_TOKEN_LEN {
                continue;
            }
            let hash = sha256_hex(encoded.as_bytes());
            if seen_hashes.insert(hash.clone()) {
                out.push(TaintFingerprint {
                    token_hash: hash,
                    kind: kind.to_string(),
                    encoding: encoding.to_string(),
                });
            }
        }
    }

    out
}

/// Scan an outbound payload (`run_command` or `write_file`/`edit_file` content) against active
/// session taint fingerprints in sub-millisecond time.
#[must_use]
pub fn detect_exfiltration(payload: &str, active: &[ActiveTaint]) -> Option<TaintMatch> {
    if payload.len() < MIN_TAINT_TOKEN_LEN || active.is_empty() {
        return None;
    }

    let mut index: std::collections::HashMap<&str, &ActiveTaint> =
        std::collections::HashMap::with_capacity(active.len());
    for entry in active {
        if entry.encoding != "marker" {
            index.insert(entry.token_hash.as_str(), entry);
        }
    }
    if index.is_empty() {
        return None;
    }

    for candidate in extract_candidate_tokens(payload) {
        if candidate.len() < MIN_TAINT_TOKEN_LEN {
            continue;
        }
        let digest = sha256_hex(candidate.as_bytes());
        if let Some(hit) = index.get(digest.as_str()) {
            return Some(TaintMatch {
                source_path: hit.source_path.clone(),
                kind: hit.kind.clone(),
                encoding: hit.encoding.clone(),
            });
        }
        // Also check lowercase form for case-insensitive hex exfiltration.
        if candidate.bytes().any(|b| b.is_ascii_uppercase())
            && candidate.bytes().all(|b| b.is_ascii_hexdigit())
        {
            let lower_digest = sha256_hex(candidate.to_ascii_lowercase().as_bytes());
            if let Some(hit) = index.get(lower_digest.as_str()) {
                return Some(TaintMatch {
                    source_path: hit.source_path.clone(),
                    kind: hit.kind.clone(),
                    encoding: hit.encoding.clone(),
                });
            }
        }
    }

    None
}

fn is_fingerprint_worthy(val: &str) -> bool {
    if val.len() < MIN_TAINT_TOKEN_LEN || val.len() > 4096 {
        return false;
    }
    let lower = val.to_ascii_lowercase();
    !matches!(
        lower.as_str(),
        "localhost"
            | "127.0.0.1"
            | "0.0.0.0"
            | "development"
            | "production"
            | "staging"
            | "changeme"
            | "placeholder"
            | "your_api_key"
            | "replace_me"
            | "example_value"
    )
}

fn extract_candidate_tokens(text: &str) -> Vec<&str> {
    let mut tokens = Vec::new();
    for rough in text.split(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                '"' | '\'' | '`' | ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>'
            )
    }) {
        if rough.len() < MIN_TAINT_TOKEN_LEN {
            continue;
        }
        tokens.push(rough);
        // Split key=value, header:value, query?k=v&k2=v2 so embedded tokens are also matched.
        for sub in rough.split(['&', '?']) {
            if sub.len() >= MIN_TAINT_TOKEN_LEN && sub != rough {
                tokens.push(sub);
            }
            if let Some((_, rhs)) = sub.split_once('=') {
                if rhs.len() >= MIN_TAINT_TOKEN_LEN {
                    tokens.push(rhs);
                }
            }
            if let Some((_, rhs)) = sub.split_once(':') {
                if rhs.len() >= MIN_TAINT_TOKEN_LEN {
                    tokens.push(rhs);
                }
            }
        }
    }
    tokens
}

// ---------------------------------------------------------------------------
// Zero-dependency Pure-Rust SHA-256 (FIPS 180-4), Base64, Hex, URL encoders
// ---------------------------------------------------------------------------

const SHA256_K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// Compute lowercase hex-encoded SHA-256 digest (pure safe Rust, zero dependencies).
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    let mut state: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(data.len() + 72);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut schedule = [0u32; 64];
        for (idx, word) in chunk.chunks_exact(4).enumerate() {
            schedule[idx] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for idx in 16..64 {
            let s0 = schedule[idx - 15].rotate_right(7)
                ^ schedule[idx - 15].rotate_right(18)
                ^ (schedule[idx - 15] >> 3);
            let s1 = schedule[idx - 2].rotate_right(17)
                ^ schedule[idx - 2].rotate_right(19)
                ^ (schedule[idx - 2] >> 10);
            schedule[idx] = schedule[idx - 16]
                .wrapping_add(s0)
                .wrapping_add(schedule[idx - 7])
                .wrapping_add(s1);
        }

        let [mut v0, mut v1, mut v2, mut v3, mut v4, mut v5, mut v6, mut v7] = state;
        for idx in 0..64 {
            let s1 = v4.rotate_right(6) ^ v4.rotate_right(11) ^ v4.rotate_right(25);
            let ch = (v4 & v5) ^ ((!v4) & v6);
            let temp1 = v7
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[idx])
                .wrapping_add(schedule[idx]);
            let s0 = v0.rotate_right(2) ^ v0.rotate_right(13) ^ v0.rotate_right(22);
            let maj = (v0 & v1) ^ (v0 & v2) ^ (v1 & v2);
            let temp2 = s0.wrapping_add(maj);

            v7 = v6;
            v6 = v5;
            v5 = v4;
            v4 = v3.wrapping_add(temp1);
            v3 = v2;
            v2 = v1;
            v1 = v0;
            v0 = temp1.wrapping_add(temp2);
        }

        state[0] = state[0].wrapping_add(v0);
        state[1] = state[1].wrapping_add(v1);
        state[2] = state[2].wrapping_add(v2);
        state[3] = state[3].wrapping_add(v3);
        state[4] = state[4].wrapping_add(v4);
        state[5] = state[5].wrapping_add(v5);
        state[6] = state[6].wrapping_add(v6);
        state[7] = state[7].wrapping_add(v7);
    }

    let mut out = String::with_capacity(64);
    for word in state {
        for byte in word.to_be_bytes() {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    out
}

#[must_use]
pub fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = if chunk.len() > 1 {
            u32::from(chunk[1])
        } else {
            0
        };
        let b2 = if chunk.len() > 2 {
            u32::from(chunk[2])
        } else {
            0
        };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((triple >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((triple >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(triple & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[must_use]
pub fn hex_encode(input: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(input.len() * 2);
    for &b in input {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn url_encode(input: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_nist_test_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn detects_raw_base64_and_hex_exfiltration_without_storing_plaintext() {
        let synthetic_val = ["vektor_env_", "fixture_9942_alpha"].concat();
        let env_content = format!("APP_RUNTIME_SALT={synthetic_val}\n");
        let fps = extract_taint_fingerprints(".env", &env_content);
        assert!(!fps.is_empty());
        assert!(fps.iter().all(|f| !f.token_hash.contains(&synthetic_val)));

        let active: Vec<ActiveTaint> = fps
            .into_iter()
            .map(|f| ActiveTaint {
                token_hash: f.token_hash,
                source_path: ".env".to_string(),
                kind: f.kind,
                encoding: f.encoding,
            })
            .collect();

        // Raw exfil
        let raw_hit = detect_exfiltration(&format!("echo {synthetic_val}"), &active);
        assert_eq!(raw_hit.as_ref().map(|m| m.encoding.as_str()), Some("raw"));

        // Base64 exfil
        let b64 = base64_encode(synthetic_val.as_bytes());
        let b64_hit = detect_exfiltration(&format!("data={b64}"), &active);
        assert_eq!(
            b64_hit.as_ref().map(|m| m.encoding.as_str()),
            Some("base64")
        );

        // Hex exfil (uppercase)
        let hex_upper = hex_encode(synthetic_val.as_bytes()).to_ascii_uppercase();
        let hex_hit = detect_exfiltration(&format!("payload:{hex_upper}"), &active);
        assert_eq!(hex_hit.as_ref().map(|m| m.encoding.as_str()), Some("hex"));

        // Benign payload
        assert!(detect_exfiltration("cargo test --workspace", &active).is_none());
    }

    #[test]
    fn classifies_sensitive_paths_and_ignores_templates() {
        assert!(is_sensitive_path(".env"));
        assert!(is_sensitive_path("apps/api/.env.production"));
        assert!(is_sensitive_path("/home/dev/.ssh/id_ed25519"));
        assert!(is_sensitive_path("certs/server.pem"));
        assert!(!is_sensitive_path(".env.example"));
        assert!(!is_sensitive_path("src/main.rs"));
    }
}
