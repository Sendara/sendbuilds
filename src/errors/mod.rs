use thiserror::Error;

#[derive(Debug, Error)]
pub enum BuildError {
    #[error("unsupported language: {0}. supported: nodejs, python, ruby, go, java, php, rust, shell, c_cpp, gleam, elixir, deno, dotnet, static")]
    UnsupportedLanguage(String),

    #[error("runtime not found: {0} — is it installed?")]
    RuntimeNotFound(String),

    #[error("output directory missing: {0}")]
    MissingOutput(String),

    // phase 2+
    // #[error("cache error: {0}")]
    // CacheFailure(String),

    // #[error("security scan failed: {0}")]
    // ScanFailed(String),
}
