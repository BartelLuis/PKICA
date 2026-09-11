# CI/CD

## CI — `.github/workflows/ci.yml`

Runs on every push/PR to `main`. Nothing is ever pushed to a registry here —
this is pure validation:

| Job | What it checks |
|---|---|
| `lint` | `ruff` over the whole repo (real errors only — unused imports etc. are intentionally not blocking, see `ruff.toml`) |
| `hadolint` | Every `services/*/Dockerfile` against Dockerfile best-practice rules (`.hadolint.yaml` documents the few intentionally-ignored rules) |
| `unit-tests` | `pytest` for `common/pkicore` against a real ephemeral Postgres service container (the models use the Postgres-specific `UUID` type, so SQLite can't run these) |
| `compose-validate` | `docker compose config -q` — catches YAML/interpolation errors before they reach a real deployment |
| `build-python-images` | Builds each of the 7 Python service images, smoke-tests them (`python3 -c "import app.main"` with the minimum env vars needed to pass each service's startup guards), then scans with Trivy (report-only) |
| `build-nginx-images` | Generates throwaway dev certs, builds `gateway` + `ca-mtls-proxy`, validates with `nginx -t`, then scans with Trivy (report-only) |
| `trivy-repo-scan` | Scans the whole repo for secrets and IaC misconfigurations — **this one fails the build** on CRITICAL/HIGH findings |

## CD — `.github/workflows/cd.yml`

Runs on push to `main` and on `v*.*.*` tags. For each of the 9 service
images:

1. Build locally (not pushed yet).
2. **Trivy scan the built image and fail the pipeline on CRITICAL/HIGH**
   fixable vulnerabilities — nothing vulnerable reaches the registry.
3. Push to `ghcr.io/<owner>/pkica-<service>` tagged with the commit SHA,
   branch name, semver (on tags), and `latest` (on `main`).
4. Generate an SPDX SBOM (`anchore/sbom-action`) and upload it as a build
   artifact.
5. Attest SLSA build provenance for the pushed digest
   (`actions/attest-build-provenance`).
6. **Keylessly sign** the image digest with `cosign` via GitHub's OIDC
   identity (Sigstore/Fulcio/Rekor) — no long-lived signing key to leak.

### Verifying a published image

```bash
cosign verify \
  --certificate-identity-regexp "https://github.com/<owner>/<repo>/.github/workflows/cd.yml@.*" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/<owner>/pkica-ca:latest
```

## Required repository configuration

* No secrets need to be created manually — `GITHUB_TOKEN` (auto-provided)
  is sufficient for GHCR push + cosign keyless signing, since the
  workflows request `packages: write` and `id-token: write` permissions.
* Enable **Settings → Actions → General → Workflow permissions →
  Read and write permissions** (or leave the explicit `permissions:` blocks
  in each workflow, which already scope this correctly without a repo-wide
  setting change).
* Recommended branch protection on `main`: require the `CI` workflow's
  jobs to pass before merge.
* CodeQL (`.github/workflows/codeql.yml`) runs on push/PR to `main` and
  weekly on a schedule; results appear under the repo's **Security →
  Code scanning** tab.
* Dependabot (`.github/dependabot.yml`) tracks: pip dependencies per
  service, Docker base image bumps per service, and the GitHub Actions
  used by these workflows themselves.
