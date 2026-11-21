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
