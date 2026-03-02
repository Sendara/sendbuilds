use anyhow::Result;
use std::process::Command;
use crate::errors::BuildError;

pub fn validate() -> Result<()> {
    let out = Command::new("node").arg("--version").output();

    match out {
        Ok(o) if o.status.success() => Ok(()),
        _ => Err(BuildError::RuntimeNotFound("node".to_string()).into()),
    }
}
