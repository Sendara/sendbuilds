use anyhow::{bail, Result};
use std::path::Path;
use std::process::Command;

pub fn clone(repo: &str, dest: &Path) -> Result<()> {
    let ok = Command::new("git")
        .args(["clone", "--depth", "1", repo, dest.to_str().unwrap()])
        .status()?
        .success();

    if !ok {
        bail!("git clone failed: {repo}")
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
