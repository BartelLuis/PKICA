# Quickstart limitations and production requirements

The Debian 13 quickstarts describe **evaluation deployments**. Their examples
include the database driver and TLS compatibility adjustments described below.
Successful startup, an HTTP 200 response, or a request marked `issued` does not
establish that the resulting certificate chain is usable. The remaining
application limitations apply to both deployment layouts.

## Database dialect compatibility

The root reference Compose file uses SQLAlchemy URLs beginning with
`postgresql+psycopg://`, and the
[shared dependencies](../common/pkicore/pyproject.toml) do not include the
CockroachDB SQLAlchemy dialect. SQLAlchemy's PostgreSQL dialect queries
`pg_catalog.version()` on the first connection and expects a PostgreSQL or
EnterpriseDB version string. CockroachDB v24.1.5 returns a string beginning with
`CockroachDB`, so version detection raises `AssertionError: Could not determine
version from string ...`. The pinned server's
[`version()` implementation](https://github.com/cockroachdb/cockroach/blob/v24.1.5/pkg/sql/sem/builtins/builtins.go#L4491)
and [build string formatter](https://github.com/cockroachdb/cockroach/blob/v24.1.5/pkg/build/info.go#L123)
confirm that behavior.

Without the quickstart adjustments, this prevents CA bootstrap and CA/RA/ACME
application startup even when
`cockroach sql` successfully connects and the `pkica` database exists. Successful
database CLI checks therefore do not establish application database connectivity;
stop at a failed application bootstrap command.

The quickstarts use
[`Dockerfile.database-client`](examples/quickstart/Dockerfile.database-client)
for CA, RA, and ACME. It installs `sqlalchemy-cockroachdb==2.0.4`, which requires
SQLAlchemy `>=2.0.47,<2.1`; their example Compose files use
`cockroachdb+psycopg://` database URLs. This follows the
[CockroachDB dialect's Psycopg 3 guide](https://github.com/cockroachdb/sqlalchemy-cockroachdb/blob/master/README.psycopg.md).
These adjustments leave the root service Dockerfiles and reference Compose file
unchanged. Changing only the URL without installing the dialect fails to load
the plugin.

This dialect also skips automatic sequence creation. The quickstarts therefore
create `audit_log_seq` in the `pkica` database before application bootstrap; the
[`audit model`](../common/pkicore/pkicore/db/models.py) requires that sequence in
its column default. Preserve this sequence with the database. Production
deployments need equivalent dependency, URL, and schema configuration, plus
validation of schema creation, bootstrap, and transactions against their selected
CockroachDB version.

## Certificate chain validation is a required release gate

The CA stores a subject using `asn1crypto.x509.Name.human_friendly`, which produces
text such as `Common Name: PKICA Root CA, Organization: ACME Corp`. Its
`_dn_string_to_attrs()` function expects `CN=..., O=...` instead. Reconstructing an
issuer from that stored text therefore produces an empty name. Intermediate and
leaf certificates can be created without the correct issuer distinguished name;
a successful REST issuance is only a check of application connectivity.

Correct the issuer reconstruction in
[`services/ca/app/service.py`](../services/ca/app/service.py) before using issued
certificates. Read the issuer's name from its stored certificate, or preserve a
structured name that can be reconstructed without information loss. Verify a
new root, intermediate, and leaf with `openssl verify`, including their issuer
and subject names. Certificates already issued with an incorrect issuer name
need replacement after the fix. This is separate from trusting the quickstart
gateway's development infrastructure CA.

Leaf issuance also leaves CRL distribution point, OCSP, and CA issuer URL fields
unset. Configure and implement the intended public URLs before relying on
automatic client discovery of revocation services or issuer certificates. See
[`CAService.issue_certificate()`](../services/ca/app/service.py) and
[`ExtensionSpec`](../common/pkicore/pkicore/crypto.py).

## HTTPX client certificate compatibility

The shared [`CAClient`](../common/pkicore/pkicore/ca_client.py) passes both a CA
file path as `verify` and a client certificate as `cert`. HTTPX 0.28.1, permitted
by the repository's dependency range, returns an SSL context for the CA file
path before loading the client certificate. The CA proxy therefore rejects
requests that would otherwise have the correct client identity configured.

The quickstart Compose files work around this for RA, OCSP, and CRL by setting
`PKICA_INTERNAL_TLS_CA` to an empty string and `SSL_CERT_FILE` to the mounted
`/certs/infra-ca.crt`. `CAClient` then passes `verify=True`; HTTPX loads the trust
file from `SSL_CERT_FILE` and also loads the client certificate. Server certificate
and hostname verification remain enabled. This only resolves that client's TLS
configuration issue; the adapter and certificate-chain defects below remain.

For a production fix, construct an explicit `ssl.SSLContext` with the intended
trust bundle and load the client certificate into it, then test against the
selected HTTPX version. The laboratory `SSL_CERT_FILE` contains only the lab CA;
HTTPS calls to an external OIDC provider or another service may need additional
trusted roots. Do not disable certificate verification to resolve either issue.

## Protocol adapters need additional integration work

| Current implementation | Consequence and required action |
|---|---|
| The reference Compose file sends ACME, EST, and SCEP requests directly to `http://ra:8000`. The adapters supply no verified identity headers, while RA requires an authenticated peer identity of `acme`, `est`, or `scep`. | Adapter enrollment fails authentication. Add an RA proxy that verifies a separate client certificate for each adapter and overwrites the identity headers, mount its trust material, and change each adapter's RA URL. Sending client certificates to a plain HTTP listener does not authenticate requests. |
| EST and SCEP request CA certificates through the CA mTLS proxy, but their Compose services have no internal client certificates or infrastructure CA trust mounts. The development generator does not issue adapter identities. | CA certificate retrieval fails. Supply the necessary certificate identities and trust, and permit the intended certificate retrieval route through a verified proxy. |
| The gateway uses variable-based `proxy_pass` with a literal URI for `/acme/`, `/.well-known/est/`, `/scep`, `/ocsp/`, and `/crl/`. | Requested suffixes and query arguments are replaced. Correct and test URI/query forwarding before using these public protocol routes. `/api/` preserves the request URI; `/directory` can return discovery JSON but does not prove ACME enrollment works. |
| ACME advertises `https://acme.pkica.local/acme` as a hard-coded external base URL. | Directory and order links do not match an arbitrary installed hostname or port. Make the external URL configurable and verify all advertised links. The implemented challenge method is HTTP-01, which requires the ACME service to reach the requested DNS name over TCP 80. |
| EST and SCEP contain calls to `c_x509.Encoding.DER`. | These certificate serialization paths fail because `Encoding` belongs to `cryptography.hazmat.primitives.serialization`. Correct the calls and exercise certificate download and enrollment. |

Evidence:
[`docker-compose.yml`](../docker-compose.yml),
[`RA internal API`](../services/ra/app/api.py),
[`identity enforcement`](../common/pkicore/pkicore/auth/mtls.py),
[`gateway routing`](../services/gateway/nginx.conf),
[`certificate generator`](../scripts/generate-dev-certs.py),
[`ACME`](../services/acme/app/main.py),
[`EST`](../services/est/app/main.py), and
[`SCEP`](../services/scep/app/main.py).

## Authentication and network boundaries

With `PKICA_ENVIRONMENT=development` and no OIDC JWKS URL, RA gives every caller
the `dev-user` identity with the `pkica-admin` role. This includes callers that
provide no bearer token. Limit the evaluation gateway to the administrator's
machine or a restricted laboratory network. A gateway client certificate is
not a substitute for RA's OIDC authentication. Production mode refuses startup
without a JWKS URL; configure the issuer, audience, JWKS URL, and the
`pkica_roles` claim, then test access with valid, missing, and unauthorized
tokens. See [`RA startup`](../services/ra/app/main.py),
[`OIDC verification`](../common/pkicore/pkicore/auth/oidc.py), and
[`RA authorization`](../services/ra/app/api.py).

The Python services trust `X-Client-Cert-Verify` and `X-Client-Cert-CN` headers
supplied by a proxy. Keep their raw HTTP listeners private to that trusted
proxy and prevent other hosts or containers from injecting these headers. The
reference CA proxy enforces mTLS, but the reference deployment does not provide
equivalent mTLS protection on every service hop. Firewall rules alone do not
add TLS or validate service identities.

## Production requirements

- **Key custody and egress:** the software backend is explicitly for development
  and testing. The default CA is attached only to Docker networks marked
  `internal: true`, so opening the host firewall alone does not give it internet
  access to a cloud KMS. Provide a controlled network path to the selected
  provider. Add the provider's actual credentials, trust, workload identity, or
  HSM libraries to the CA container configuration. Several credential names
  listed in `.env.example` are not forwarded by the Compose service; editing
  that file alone is insufficient. See
  [`Compose`](../docker-compose.yml), [`.env.example`](../.env.example), and
  [`backend factory`](../common/pkicore/pkicore/kms/factory.py).
- **Database security and availability:** the reference CockroachDB cluster uses
  `--insecure` and the root SQL account. Enable node and client TLS, verify server
  names, and provision appropriately scoped application accounts before using
  it outside a restricted evaluation network. CA, RA, and ACME require database
  access. Three database containers on one host do not tolerate losing that
  host. The [distributed database quickstart](QUICKSTART_DATABASE_CLUSTER.md)
  supplies a separate node per host and a `DB_SQL_URL` listing all three SQL
  endpoints. That enables new-connection failover; interrupted transactions can
  still fail, including with CockroachDB serialization errors (`40001`). The
  application does not automatically replay them. The root reference and the
  default `DB_HOST_IP` configuration still select one SQL address.
- **Schema changes:** startup calls `Base.metadata.create_all()`; the repository
  does not ship a production schema migration workflow. Create the `pkica`
  database before starting applications, serialize first-time schema creation,
  and introduce reviewed migrations before upgrading a populated deployment.
  See [`database initialization`](../common/pkicore/pkicore/db/session.py).
- **Certificates and secrets:** replace development infrastructure certificates
  with correctly named service and gateway certificates and implement renewal
  and reload procedures. Give each container access only to its required
  private key. Keep root signing material out of general service mounts.
  Preserve the software KMS master key with its encrypted key volume during
  evaluation; regenerating the master key makes existing keys unreadable.
- **Recovery and operation:** establish database, key custody, and configuration
  backups and test restoration together. Supply monitoring, protected audit
  log retention, and certificate expiration alerts. The gateway's `/healthz`
  only proves nginx is serving requests. Check application, database, signing,
  and certificate validation separately. The CA is contacted for signing by
  the CRL and OCSP services, so this running CA service cannot be routinely
  air-gapped while those requests need to succeed. An offline root needs a
  separate operational design.

Before accepting a production deployment, verify a trusted certificate chain,
the REST approval and revocation workflow, each enabled enrollment protocol,
CRL and OCSP results, rejected unauthorized requests, and recovery after a
service or host failure. The quickstarts do not claim those acceptance checks
have passed.
