# sendbuilds

Build automation CLI with step events, caching, auto-detection, metrics, sandbox controls, artifact signing, and multi-target outputs.

## Supported Language/Frameworks
- Next.js, Rails, Django, Flask, Spring (Maven/Gradle), Laravel, plus generic toolchain detection by language.
- Node.js, Python, Ruby, Go, Java, PHP, Rust, Static Sites, Shell Scripts, C/C++, Gleam, Elixir, Deno, and .NET.

## Run

```bash
sendbuilds build --config sendbuild.toml
```

## Install from Releases

Release assets are packaged for direct CLI install:
- Linux/macOS: `.tar.gz` (contains `sendbuilds` + `install.sh`)
- Windows: `.zip` (contains `sendbuilds.exe` + `install.ps1`)

Linux/macOS:

```bash
tar -xzf sendbuilds-linux-x86_64.tar.gz
./install.sh
sendbuilds --help
```

Windows PowerShell:

```powershell
Expand-Archive .\sendbuilds-windows-x86_64.zip -DestinationPath .\sendbuilds
.\sendbuilds\install.ps1
sendbuilds.exe --help
```

## Local development and testing

Build and run the CLI locally:

```bash
cargo build --release
./target/release/sendbuilds --help
./target/release/sendbuilds build --config sendbuild.toml
```

On Windows PowerShell:

```powershell
cargo build --release
.\target\release\sendbuilds.exe --help
.\target\release\sendbuilds.exe build --config sendbuild.toml
```

Run without a release build:

```bash
cargo run -- build --config sendbuild.toml
```

Localhost testing flow for a web app:

1. Build with `sendbuilds` (`build` command).
2. Enter the produced artifact folder under `deploy.artifact_dir`.
3. Start your framework runtime from that artifact (for example `pnpm run start`, `python manage.py runserver`, etc.).

If `[source]` is omitted in `sendbuild.toml`, `sendbuilds` uses the current workspace as source input.

## CLI commands

```bash
sendbuilds build [--config sendbuild.toml] [--events true|false]
sendbuilds build [--config sendbuild.toml] [--in-place] [--events true|false]
sendbuilds build --git <repo> --docker [--branch <name>] [--image <tag>]
sendbuilds init [--template <framework>] [--yes]
sendbuilds cache save|restore|clear|status [--config sendbuild.toml]
sendbuilds clean [--all] [--cache-only] [--config sendbuild.toml]
sendbuilds info [--env] [--dependencies] [--config sendbuild.toml]
```

Use `--in-place` to build directly in the current workspace instead of a temp copy (useful for Next.js `pnpm start` expecting `.next` in project root).
If `sendbuild.toml` is missing, `sendbuilds build` automatically falls back to a smart local mode with inferred defaults and in-place build.
For zero-config enterprise mode, use `sendbuilds build --git <repo> --docker`: it auto-generates runtime config, enables security-first checks, signs artifacts, emits SBOM/supply-chain metadata, and builds container images even when no Dockerfile exists.
Accepted repo formats include:
- `owner/repo` (for example `notsliver/sendara-landing`)
- `https://github.com/owner/repo`
- `https://github.com/owner/repo.git`

## Minimal config

```toml
[project]
name = "my-app"

[deploy]
artifact_dir = "./artifacts"
```

`source`, `language`, `install_cmd`, `build_cmd`, and `output_dir` are optional. If `[source]` is omitted, `sendbuilds` uses the current folder contents as build input.

## Full config (all features)

```toml
[project]
name = "my-app"
language = "nodejs" # optional override

[source] # optional
repo = "https://github.com/you/my-app.git" # optional
branch = "main" # optional

[build]
install_cmd = "pnpm install --frozen-lockfile --prefer-offline" # optional override
build_cmd = "pnpm run build"                                     # optional override
parallel_build_cmds = ["pnpm run build:client", "pnpm run build:server"] # optional
output_dir = ".next"                                             # optional override

[deploy]
artifact_dir = "./artifacts"
targets = ["directory", "tarball", "serverless_zip", "container_image", "kubernetes"] # optional
container_image = "my-app:latest"                                       # optional
container_platforms = ["linux/amd64", "linux/arm64"]                    # optional (buildx)
push_container = true                                                    # optional (required for multi-arch)
rebase_base = "gcr.io/distroless/nodejs20-debian12"                     # optional runtime rebase base

[deploy.kubernetes] # optional (used by target="kubernetes")
enabled = true
namespace = "default"
replicas = 2
container_port = 3000
service_port = 80
image_pull_policy = "IfNotPresent"

[deploy.gc] # optional automatic artifact garbage collection
enabled = true
keep_last = 5
max_age_days = 14

[output]
events = false # default hidden; set true to show EVENT {...} lines

[cache]
enabled = true
dir = "./artifacts/.sendbuild-cache"
registry_ref = "ghcr.io/your-org/my-app-buildcache" # optional buildx registry cache

[scan]
enabled = true
command = "npm audit --json --omit=dev --audit-level=high"

[security]
enabled = true
fail_on_critical = true
critical_threshold = 0
fail_on_scanner_unavailable = true
generate_sbom = true
auto_distroless = true
# distroless_base = "gcr.io/distroless/nodejs20-debian12"
# rewrite_dockerfile_in_place = false

[sandbox]
enabled = true

[signing]
enabled = true
key_env = "SENDBUILD_SIGNING_KEY"
generate_provenance = true
cosign = false
# cosign_key = "env://COSIGN_PRIVATE_KEY"

[compatibility]
target_os = "linux"
target_arch = "x86_64"
target_node_major = 20

env_from_host = ["GITHUB_TOKEN", "NPM_TOKEN"]

[env]
NODE_ENV = "production"
API_BASE_URL = "https://api.example.com"
```

## Step events

When `[output].events = true` (or `--events true`), machine-readable step events are emitted to stdout:

```text
EVENT {"type":"STEP_STARTED","channel":"build-step","step":"install","status":"running","timestamp":"..."}
EVENT {"type":"STEP_COMPLETED","channel":"build-step","step":"install","status":"completed","timestamp":"...","duration_ms":1234,"cpu_percent":5.2,"memory_mb":24,"disk_mb":300}
EVENT {"type":"STEP_FAILED","channel":"build-step","step":"build","status":"failed","timestamp":"...","duration_ms":4321,"error":"..."}
```

## Added capabilities

1. Build metrics: per-step duration, status, cache hit/miss accounting, plus `build-metrics.json` in the artifact root.
2. Resource usage tracking: per-step CPU, memory delta, and disk delta in events and step summaries.
3. Sandboxing controls: optional sandbox mode (`[sandbox].enabled`) with basic command blocking and restricted env baseline.
4. Signed artifacts: optional HMAC-SHA256 manifest signing with `artifact-manifest.json` and `artifact-manifest.sig`.
5. Environment variable injection: explicit `[env]` values and `env_from_host` passthrough.
6. Multiple output targets: `directory`, `static_site`, `tarball`, `serverless_zip` / `serverless_function`, `container_image`, and `kubernetes` (Kubernetes manifests).
7. Compatibility checks: optional warnings for target OS/arch/node-major mismatches, including `engines.node` checks when available.
8. Multi-language support: Node.js, Python, Ruby, Go, Java, PHP, Rust, Static Sites, Shell Scripts, C/C++, Gleam, Elixir, Deno, and .NET.
9. Multi-framework support: Next.js, Rails, Django, Flask, Spring (Maven/Gradle), Laravel, plus generic toolchain detection by language.
10. Automatic artifact garbage collection: optional `[deploy.gc]` retention by count and age after each successful deploy.
11. Security-First Buildpack (enterprise): auto-generates SBOM (`sbom.json`), runs vulnerability scans during build, enforces critical-CVE build failure policy, auto-switches Dockerfile final base to distroless, and emits `security-report.json` plus `supply-chain-metadata.json`.
12. CNB lifecycle parity metadata: exports `cnb/lifecycle-contract.json` and `cnb/lifecycle-metadata.json` with standardized detect/analyze/restore/build/export phase mapping.
13. Layered and rebase-ready container output: generated layered Dockerfiles and `.sendbuild-rebase-plan.json` for runtime-base upgrades.
14. Registry-backed container cache/export: optional buildx `--cache-from/--cache-to` via `[cache].registry_ref`.
15. First-class multi-arch container builds: optional `container_platforms` with buildx push flow.
16. Provenance attestations and cosign integration: emits `provenance.intoto.jsonl`; optional cosign sign/attest.

## Security scan failure details

When legacy `security-scan` fails, the error includes vulnerable package names and actionable suggestions.

Example:

```text
EVENT {"type":"STEP_FAILED","channel":"build-step","step":"security-scan","status":"failed","timestamp":"...","duration_ms":2065,"error":"security scan failed. command=`npm audit --json --omit=dev --audit-level=high` exit=Some(1). vulnerable packages: minimist(high,fix:available), braces(high,fix:upgrade). suggestions: 1) npm audit fix 2) update vulnerable packages/lockfile 3) if blocked, pin safe versions and rebuild cache"}
```

## Notes

- Builds run in temporary work directories under system temp.
- Deploy artifacts are emitted under timestamped directories in `deploy.artifact_dir`.
- With target `kubernetes`, `sendbuilds` writes `kubernetes/deployment.yaml` and `kubernetes/service.yaml` into the artifact root.
- If `[deploy.gc].enabled = true`, old timestamped artifact directories are pruned automatically after deploy.
- Security-first output is written to artifact root as `sbom.json`, `security-report.json`, and `supply-chain-metadata.json`, and embedded in `build-metrics.json`.
- CNB lifecycle parity output is written to artifact root under `cnb/lifecycle-contract.json` and `cnb/lifecycle-metadata.json`.
- Provenance output is written as `provenance.intoto.jsonl` when signing provenance is enabled.
- If both `[security].enabled` and `[scan].enabled` are true, `security-first` runs and legacy `security-scan` is skipped to avoid duplicate scanning.
- For Next.js production runtime, prefer `output: "standalone"` and set `output_dir` accordingly.

## Contributing

1. Fork and create a branch from `master`.
2. Make focused changes with clear commit messages.
3. Run local checks before opening a PR:

```bash
cargo fmt --all -- --check
cargo check
cargo test
```

4. If you changes, update `README.md` and `sendbuild.toml` examples.
5. Open a PR with:
- what changed
- why it changed
- how you tested it

## CI

GitHub Actions CI runs on push and pull requests. It validates formatting, compilation, tests, and release build output for Linux and Windows.