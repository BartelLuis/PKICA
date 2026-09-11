# Deployment Guide

## 1. Prerequisites

* Docker Engine 25+ / Docker Compose v2
* Python 3.12 (only needed locally to run `scripts/generate-dev-certs.py`
  and the seeding scripts — not required inside containers)
* A KMS/HSM of your choice for production (AWS KMS, Azure Key Vault, GCP
  KMS, HashiCorp Vault Transit, or a PKCS#11 HSM). The bundled `software`
  backend is for local development/testing only.

## 2. Bootstrap (single host, all components)

```bash
cp .env.example .env                     # fill in real secrets
python scripts/generate-dev-certs.py     # dev-only internal mTLS material
docker compose up -d --build
docker compose exec ca python -m app.bootstrap create-root \
    --name root-ca --subject '{"cn":"PKICA Root CA","o":"ACME Corp"}'
docker compose exec ca python -m app.bootstrap create-intermediate \
    --name issuing-ca-1 --parent root-ca --subject '{"cn":"PKICA Issuing CA 1","o":"ACME Corp"}'
docker compose exec ca python scripts/seed-profiles.py --issuing-ca issuing-ca-1
```

Verify:

```bash
curl -k https://localhost:8443/healthz
curl -k https://localhost:8443/directory          # ACME directory
curl -k "https://localhost:8443/scep?operation=GetCACaps"
```

## 3. Choosing a KMS/HSM backend

Set `CA_KEY_BACKEND` in `.env` to one of `aws_kms`, `azure_key_vault`,
`gcp_kms`, `vault_transit`, `pkcs11_hsm`. Each requires backend-specific
credentials — see the commented variables in `.env.example`. Credentials
should be supplied via Docker secrets or your orchestrator's secret store
in production, never as plain environment variables in a committed file.

For `pkcs11_hsm`, mount the vendor PKCS#11 module (`.so`) into the `ca`
container and set `PKICA_PKCS11_MODULE_PATH`, `PKICA_PKCS11_SLOT`,
`PKICA_PKCS11_PIN` (as a Docker secret file, referenced via the
`file://` convention supported by `pkicore.config`).

## 4. Production hardening checklist

* [ ] Enable CockroachDB TLS: generate node/client certs with
      `cockroach cert create-ca` / `create-node` / `create-client` and run
      each node with `--certs-dir` instead of `--insecure`
      ([CockroachDB docs](https://www.cockroachlabs.com/docs/stable/security-reference/transport-layer-security)).
* [ ] Replace `scripts/generate-dev-certs.py` output with real, short-lived
      internal mTLS certificates issued by your own infra CA; automate
      rotation (e.g. a sidecar that re-requests certs every 24h via EST/ACME
      against a dedicated "infra" profile).
* [ ] Configure a real OIDC provider (Keycloak, Azure AD, Okta, ...) and set
      `OIDC_ISSUER` / `OIDC_AUDIENCE` / `OIDC_JWKS_URL`; the RA refuses to
      start in `PKICA_ENVIRONMENT=production` without them.
* [ ] Pin all base images to digests, scan images with `trivy`/`docker scout`
      in CI, sign images (cosign) and verify signatures at deploy time.
* [ ] Ship container stdout logs (structured JSON) to your SIEM; configure
      `PKICA_SIEM_FORWARD_URL` and alert on `audit.record` anomalies.
* [ ] Run `pkicore.audit.verify_chain` periodically (cron/Kubernetes
      CronJob) and alert on any break.
* [ ] Put the gateway behind a WAF/CDN (Cloudflare, AWS WAF, ModSecurity)
      for internet-facing deployments.
* [ ] Store `.env` secrets in a real secret manager (Vault, AWS Secrets
      Manager, Azure Key Vault) and inject at container start, never bake
      into images or commit to git.
* [ ] Restrict outbound network egress from every container to only the
      hosts it needs (DB, KMS endpoint, internal peers) via firewall/
      security-group rules or a service mesh's egress policy.

## 5. High availability

* Scale any stateless service horizontally: `docker compose up -d --scale ra=3 --scale ocsp=3 --scale crl=3`
  (put a load balancer in front, or migrate to Kubernetes — see
  docs/SPLIT_DEPLOYMENT.md for the general pattern).
* CockroachDB: run 3 nodes minimum (5+ across 3 AZs/regions for full HA)
  and set `ZONE` survival goals per your requirements.
* The CA service is intentionally *not* meant to be scaled to many replicas
  in the same way — treat it like a safe/vault: a small, fixed number of
  replicas (2 for failover), tightly access-controlled, ideally on
  dedicated hardware/hosts for the Root CA in particular. Consider keeping
  the Root CA fully offline and only bringing it online to sign new
  Intermediate CAs.
