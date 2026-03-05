Features most modern buildpacks usually have (and what they are)
1. CNB lifecycle parity (detect/analyze/restore/build/export): standardized phase contract and metadata between builder and buildpacks.
Current implementation is custom pipeline, not CNB lifecycle-compatible.
2. Layered/rebasable images: reuse app/build layers and rebase on new base image without full rebuild.
Current flow builds image with Docker build context, not lifecycle layer rebasing.
3. Non-root runtime defaults: final launch image runs as unprivileged user by default.
Generated Dockerfiles currently do not enforce USER.
4. Provenance attestations (SLSA/in-toto) + Sigstore/cosign: verifiable origin/signing beyond shared-secret HMAC.
Current signing is HMAC manifest (signing.rs).
5. Registry-backed cache/export cache: cache layers in OCI registry for CI speed/consistency across runners.
Current cache is local filesystem-oriented.
6. First-class multi-arch output: easy amd64/arm64 image publishing from one pipeline.
Not first-class in current implementation.
