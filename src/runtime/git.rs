use anyhow::{bail, Result};
use std::path::Path;
use std::process::Command;

pub fn clone(repo: &str, dest: &Path) -> Result<()> {
    let normalized = normalize_repo(repo);
    let ok = Command::new("git")
        .args(["clone", "--depth", "1", &normalized, dest.to_str().unwrap()])
        .status()?
        .success();

    if !ok {
        bail!("git clone failed: {repo} (normalized={normalized})")
    }
    Ok(())
}

pub fn checkout(dest: &Path, target: &str) -> Result<()> {
    let ok = Command::new("git")
        .args(["checkout", target])
        .current_dir(dest)
        .status()?
        .success();

    if !ok {
        bail!("git checkout failed: {target}")
    }
    Ok(())
}

pub fn fetch_and_checkout(dest: &Path, commit: &str) -> Result<()> {
    let ok = Command::new("git")
        .args(["fetch", "--unshallow"])
        .current_dir(dest)
        .status()?
        .success();

    if !ok {
        bail!("git fetch failed")
    }
    checkout(dest, commit)
}

fn normalize_repo(repo: &str) -> String {
    let trimmed = repo.trim();
    if trimmed.is_empty() {
        return trimmed.to_string();
    }

    if trimmed.starts_with("http://")
        || trimmed.starts_with("https://")
        || trimmed.starts_with("git@")
        || trimmed.starts_with("ssh://")
    {
        return trimmed.to_string();
    }

    let shorthand = trimmed.trim_matches('/');
    if is_owner_repo_shorthand(shorthand) {
        return format!("https://github.com/{shorthand}.git");
    }

    trimmed.to_string()
}

fn is_owner_repo_shorthand(input: &str) -> bool {
    let mut parts = input.split('/');
    let Some(owner) = parts.next() else {
        return false;
    };
    let Some(repo) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }

    is_slug(owner) && is_slug(repo)
}

fn is_slug(v: &str) -> bool {
    !v.is_empty()
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}
