mod node;

use anyhow::{Result, bail};
use std::process::Command;
use crate::errors::BuildError;

pub fn validate(language: &str) -> Result<()> {
    match normalize_language(language).as_str() {
        "nodejs" => node::validate(),
        "python" => check_runtime("python", &["--version"])
            .or_else(|_| check_runtime("python3", &["--version"])),
        "ruby" => check_runtime("ruby", &["--version"]),
        "go" => check_runtime("go", &["version"]),
        "java" => check_runtime("java", &["-version"]),
        "php" => check_runtime("php", &["--version"]),
        "rust" => check_runtime("cargo", &["--version"]).or_else(|_| check_runtime("rustc", &["--version"])),
        "shell" => check_runtime("sh", &["--version"]).or_else(|_| check_runtime("bash", &["--version"])),
        "c_cpp" => check_runtime("gcc", &["--version"])
            .or_else(|_| check_runtime("clang", &["--version"]))
            .or_else(|_| check_runtime("cl", &[])),
        "gleam" => check_runtime("gleam", &["--version"]),
        "elixir" => check_runtime("elixir", &["--version"]),
        "deno" => check_runtime("deno", &["--version"]),
        "dotnet" => check_runtime("dotnet", &["--version"]),
        "static" => Ok(()),
        other => Err(BuildError::UnsupportedLanguage(other.to_string()).into()),
    }
}

fn normalize_language(language: &str) -> String {
    match language.to_lowercase().as_str() {
        "node" | "nodejs" => "nodejs".to_string(),
        "python" | "py" => "python".to_string(),
        "ruby" | "rb" => "ruby".to_string(),
        "go" | "golang" => "go".to_string(),
        "java" | "jvm" => "java".to_string(),
        "php" => "php".to_string(),
        "rust" | "rs" => "rust".to_string(),
        "shell" | "sh" | "bash" => "shell".to_string(),
        "c" | "cpp" | "c++" | "c_cpp" | "cc" => "c_cpp".to_string(),
        "gleam" => "gleam".to_string(),
        "elixir" | "ex" | "exs" => "elixir".to_string(),
        "deno" => "deno".to_string(),
        "dotnet" | ".net" | "net" | "csharp" | "c#" => "dotnet".to_string(),
        "static" | "static_site" => "static".to_string(),
        other => other.to_string(),
    }
}

fn check_runtime(bin: &str, args: &[&str]) -> Result<()> {
    let out = Command::new(bin).args(args).output();
    match out {
        Ok(o) if o.status.success() => Ok(()),
        _ => bail!("runtime not found: {}", bin),
    }
}
