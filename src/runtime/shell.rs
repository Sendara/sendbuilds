use anyhow::{bail, Context, Result};
use std::collections::HashMap;
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

pub fn run(
    cmd: &str,
    cwd: &Path,
    env: &HashMap<String, String>,
    sandbox: bool,
) -> Result<ShellRunOutput> {
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

    let child = command
        .spawn()
        .with_context(|| format!("failed to spawn: {cmd}"))?;
    let output = child.wait_with_output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        logs.push(format!("stdout: {line}"));
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    for line in stderr.lines() {
        logs.push(format!("stderr: {line}"));
    }

    let status = output.status;
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

#[cfg(test)]
mod tests {
    use super::{is_blocked_command, run_allow_failure};
    use std::collections::HashMap;

    #[test]
    fn blocked_command_detection_is_case_insensitive() {
        assert!(is_blocked_command("RM -rf C:\\"));
        assert!(!is_blocked_command("echo safe"));
    }

    #[test]
    fn run_allow_failure_captures_stdout_and_stderr() {
        let wd = std::env::current_dir().expect("current dir");
        let env = HashMap::new();
        let run = run_allow_failure("echo hello && echo boom 1>&2", &wd, &env, false).expect("run");
        assert!(run.success);
        assert!(run.logs.iter().any(|l| l.contains("stdout: hello")));
        assert!(run.logs.iter().any(|l| l.contains("stderr: boom")));
    }
}
