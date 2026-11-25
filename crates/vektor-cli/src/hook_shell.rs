use std::path::Path;

pub(crate) fn split_shell_segments(cmd: &str) -> Vec<&str> {
    cmd.split([';', '|', '&', '\n', '\r'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
}

pub(crate) fn tokenize_shell_segment(segment: &str) -> Vec<String> {
    segment
        .split_whitespace()
        .map(|tok| tok.trim_matches(['"', '\'']).to_ascii_lowercase())
        .filter(|tok| !tok.is_empty())
        .collect()
}

pub(crate) fn is_force_push_to_protected_branch(tokens: &[String]) -> bool {
    let Some(first) = tokens.first() else {
        return false;
    };
    let bin = Path::new(first)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(first);
    if bin != "git" && bin != "git.exe" {
        return false;
    }

    // Walk past global git flags (`-C <dir>`, `-c <k=v>`, `--git-dir <dir>`, etc.).
    let mut idx = 1usize;
    while idx < tokens.len() {
        let tok = tokens[idx].as_str();
        if tok == "push" {
            break;
        }
        if matches!(tok, "-c" | "--git-dir" | "--work-tree" | "--namespace") {
            idx += 2;
        } else if tok.starts_with('-') {
            idx += 1;
        } else {
            return false;
        }
    }

    if tokens.get(idx).map(String::as_str) != Some("push") {
        return false;
    }

    let push_args = &tokens[idx + 1..];
    let mut is_force = false;
    let mut targets_protected = false;

    for arg in push_args {
        if matches!(
            arg.as_str(),
            "--force" | "--force-with-lease" | "--force-if-includes"
        ) || arg.starts_with("--force-with-lease=")
            || (arg.starts_with('-') && !arg.starts_with("--") && arg[1..].contains('f'))
        {
            is_force = true;
            continue;
        }
        if arg.starts_with('+') {
            is_force = true;
        }
        let branch_ref = arg.trim_start_matches('+');
        let target = branch_ref.rsplit(':').next().unwrap_or(branch_ref);
        if matches!(
            target,
            "main" | "master" | "refs/heads/main" | "refs/heads/master"
        ) {
            targets_protected = true;
        }
    }

    is_force && targets_protected
}

pub(crate) fn is_destructive_root_deletion(tokens: &[String]) -> bool {
    let Some(first) = tokens.first() else {
        return false;
    };
    let bin = Path::new(first)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(first);

    match bin {
        "rm" | "rm.exe" => {
            let mut recursive = false;
            let mut force = false;
            let mut hits_root = false;
            for arg in &tokens[1..] {
                if arg == "--recursive" {
                    recursive = true;
                } else if arg == "--force" {
                    force = true;
                } else if arg.starts_with('-') && !arg.starts_with("--") {
                    if arg[1..].contains('r') {
                        recursive = true;
                    }
                    if arg[1..].contains('f') {
                        force = true;
                    }
                } else if is_root_target(arg) {
                    hits_root = true;
                }
            }
            recursive && force && hits_root
        }
        "remove-item" | "ri" | "rm-item" => {
            let has_recurse = tokens.iter().any(|t| t == "-recurse" || t == "-r");
            let has_force = tokens.iter().any(|t| t == "-force" || t == "-fo");
            let hits_root = tokens[1..].iter().any(|t| is_root_target(t));
            has_recurse && has_force && hits_root
        }
        "rd" | "rmdir" => {
            let has_s = tokens.iter().any(|t| t == "/s");
            let hits_root = tokens[1..].iter().any(|t| is_root_target(t));
            has_s && hits_root
        }
        _ => false,
    }
}

fn is_root_target(arg: &str) -> bool {
    let norm = arg.replace('\\', "/");
    if matches!(norm.as_str(), "/" | "/*" | "~" | "~/" | "$home" | "${home}") {
        return true;
    }
    // Windows drive root: `c:`, `c:/`, `c:/*`
    let bytes = norm.as_bytes();
    bytes.len() >= 2
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(&norm[2..], "" | "/" | "/*")
}

/// Detect outbound network or remote-transfer commands that could exfiltrate tainted session data.
pub(crate) fn detect_network_exfil_command(
    tokens: &[String],
    raw_segment: &str,
) -> Option<&'static str> {
    let first = tokens.first()?;
    let bin = Path::new(first)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(first);
    let bin_no_ext = bin.strip_suffix(".exe").unwrap_or(bin);

    match bin_no_ext {
        "curl" => Some("curl"),
        "wget" => Some("wget"),
        "nc" | "ncat" | "netcat" => Some("netcat"),
        "socat" => Some("socat"),
        "scp" => Some("scp"),
        "sftp" => Some("sftp"),
        "rsync" => Some("rsync"),
        "ssh" => Some("ssh"),
        "ftp" | "tftp" | "telnet" => Some("ftp/telnet"),
        "invoke-webrequest" | "iwr" => Some("Invoke-WebRequest"),
        "invoke-restmethod" | "irm" => Some("Invoke-RestMethod"),
        "start-bitstransfer" => Some("Start-BitsTransfer"),
        "send-mailmessage" => Some("Send-MailMessage"),
        "python" | "python3" | "py" => {
            let lower = raw_segment.to_ascii_lowercase();
            if lower.contains("urllib")
                || lower.contains("requests.")
                || lower.contains("http.client")
                || lower.contains("httpx")
                || lower.contains("socket.")
            {
                Some("python-network")
            } else {
                None
            }
        }
        "node" | "deno" | "bun" => {
            let lower = raw_segment.to_ascii_lowercase();
            if lower.contains("fetch(")
                || lower.contains("http.request")
                || lower.contains("https.request")
                || lower.contains("net.connect")
            {
                Some("js-runtime-network")
            } else {
                None
            }
        }
        "powershell" | "pwsh" => {
            let lower = raw_segment.to_ascii_lowercase();
            if lower.contains("webclient")
                || lower.contains("httpclient")
                || lower.contains("invoke-webrequest")
                || lower.contains("invoke-restmethod")
            {
                Some("powershell-network")
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Extract candidate file paths referenced in a shell command that match sensitive filenames.
pub(crate) fn extract_sensitive_paths_from_command(cmd: &str) -> Vec<String> {
    let mut out = Vec::new();
    for segment in split_shell_segments(cmd) {
        for raw_tok in segment.split_whitespace() {
            let clean = raw_tok.trim_matches(['"', '\'', '`', ',', ';', '(', ')']);
            if clean.is_empty() || clean.starts_with('-') {
                continue;
            }
            if vektor_analyzers::taint::is_sensitive_path(clean) && !out.iter().any(|p| p == clean)
            {
                out.push(clean.to_string());
            }
        }
    }
    out
}
