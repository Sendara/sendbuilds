use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Instant;

#[derive(Debug, Default)]
pub struct ShellRunOutput {
    pub logs: Vec<String>,
    pub duration_secs: f32,
    pub success: bool,
    pub exit_code: Option<i32>,
}

pub fn run(cmd: &str, cwd: &Path, env: &HashMap<String, String>, sandbox: bool) -> Result<ShellRunOutput> {
    let output = run_allow_failure(cmd, cwd, env, sandbox)?;
    if !output.success {
        bail!("command failed [{:.1}s]: {cmd}", output.duration_secs);
    }
    Ok(output)
}

pub fn run_allow_failure(
    cmd: &str,
    cwd: &Path,
    env: &HashMap<String, String>,
    sandbox: bool,
) -> Result<ShellRunOutput> {
    if sandbox && is_blocked_command(cmd) {
        bail!("sandbox blocked command: {cmd}");
    }

    let start = Instant::now();
    let mut logs = vec![format!("cmd: {cmd}")];

    let mut command = shell_cmd(cmd);
    command.current_dir(cwd);
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());

    if sandbox {
        command.env_clear();
        keep_minimal_env(&mut command);
    }
    for (k, v) in env {
        command.env(k, v);
    }

    let mut child = command
        .spawn()
        .with_context(|| format!("failed to spawn: {cmd}"))?;

    if let Some(out) = child.stdout.take() {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            logs.push(format!("stdout: {line}"));
        }
    }

    if let Some(err) = child.stderr.take() {
        for line in BufReader::new(err).lines().map_while(Result::ok) {
            logs.push(format!("stderr: {line}"));
        }
    }

    let status = child.wait()?;
    let secs = start.elapsed().as_secs_f32();
    let success = status.success();
    let exit_code = status.code();

    Ok(ShellRunOutput {
        logs,
        duration_secs: secs,
        success,
        exit_code,
    })
}

fn keep_minimal_env(command: &mut Command) {
    let keys = [
        "PATH",
        "Path",
        "SYSTEMROOT",
        "SystemRoot",
        "COMSPEC",
        "ComSpec",
        "TEMP",
        "TMP",
        "HOME",
        "USERPROFILE",
    ];
    for key in keys {
        if let Ok(val) = std::env::var(key) {
            command.env(key, val);
        }
    }
}

fn is_blocked_command(cmd: &str) -> bool {
    let lower = cmd.to_lowercase();
    let blocked = [
        "rm -rf /",
        "rm -rf c:\\",
        "del /s /q c:\\",
        "format c:",
        "mkfs",
        "shutdown",
        "reboot",
    ];
    blocked.iter().any(|token| lower.contains(token))
}

fn shell_cmd(cmd: &str) -> Command {
    #[cfg(target_os = "windows")]
    {
        let mut c = Command::new("cmd");
        c.args(["/C", cmd]);
        c
    }
    #[cfg(not(target_os = "windows"))]
    {
        let mut c = Command::new("sh");
        c.args(["-c", cmd]);
        c
    }
}
