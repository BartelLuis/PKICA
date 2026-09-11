# Architecture

See the diagram and component table in [README.md](../README.md). This
document covers data flow, extension points, and design rationale in more
depth.

## Request lifecycle (REST enrollment)

1. Client authenticates to the RA (`ra` service) via OIDC bearer token,
   `POST /api/v1/requests` with a PEM CSR and a `profile_name`.
2. RA (`app/service.py::RAService.submit_request`) loads the named
   `CertProfile`, checks the protocol is allowed for that profile, and
   parses/validates the CSR signature.
3. If `profile.require_approval` is true, the request sits as `pending`
   until a human with the `pkica-ra-approver` role calls
   `POST /api/v1/requests/approve`.
4. On approval (or immediately, if auto-issue is allowed), RA calls the CA's
   internal `/internal/v1/issue` endpoint over mTLS via `ca-mtls-proxy`.
5. CA (`services/ca/app/service.py::CAService.issue_certificate`)
   re-validates the profile policy, builds the TBSCertificate with
   `pkicore.crypto`, and asks the configured `KMSBackend.sign()` for a raw
   signature — the private key never leaves the KMS/HSM.
6. The signed certificate is persisted and returned up the chain to the RA,
   which stores it on the `CertificateRequest` row and returns it to the
   caller (or the ACME/EST/SCEP adapter that originated the request).

## Why CertificateBuilder isn't used for signing

`cryptography.x509.CertificateBuilder.sign()` is implemented in Rust since
v3.5 and only accepts native OpenSSL-backed private key objects — it cannot
be handed a duck-typed "please call my KMS" key. `pkicore/crypto.py`
therefore builds the ASN.1 `TBSCertificate` directly with `asn1crypto`,
asks the `KMSBackend` for a raw signature over the DER bytes, and hand-
assembles the final DER certificate. This is the same technique used by
production cloud-KMS-backed CA tooling.

## Extension points

* **New KMS/HSM backend**: implement `pkicore.kms.base.KMSBackend`, wire it
  up in `pkicore/kms/factory.py`.
* **New cert profile / policy rule**: add fields to `CertProfile`
  (`pkicore/db/models.py`) and enforce them in both
  `RAService.submit_request` (fail fast) and `CAService._enforce_profile`
  (defense in depth — the CA must never trust the RA blindly).
* **New enrollment protocol**: add a new `services/<protocol>` adapter that
  calls RA's `/internal/v1/requests` endpoint over mTLS — never call the CA
  directly.
* **HA / multi-region**: every service is stateless except for the
  database; scale each `docker-compose` service to N replicas behind a
  load balancer, and run CockroachDB across 3+ nodes (5+ for multi-region)
  with `REGIONAL BY ROW` tables for locality-aware reads.

## Known scaffolding limitations

See the "Known scaffolding limitations" section in
[THREAT_MODEL.md](THREAT_MODEL.md).
