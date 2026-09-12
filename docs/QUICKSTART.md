# Debian 13 quickstart: single host

This guide takes a fresh Debian 13 (Trixie) server through Docker installation,
database initialization, CA bootstrap, and service checks. For separate servers,
complete the **Prepare Debian 13** section on each server, then follow the
[multi-host quickstart](QUICKSTART_MULTI_HOST.md). Review the
[installation and runtime firewall rules](FIREWALL_RULES.md) before starting.

The supplied quickstarts are **isolated evaluation deployments**. They explicitly
enable the software key backend and the development identity, which gives callers
administrator access without a login, and use an insecure CockroachDB cluster.
Keep access restricted to the lab's administrators. The current application also
has certificate-chain and enrollment defects: see
[current limitations and production requirements](QUICKSTART_LIMITATIONS.md).
Successful bootstrap or an HTTP 200 does not establish that issued certificates
are usable or that the system is ready for production.

## 1. Plan the installation

| Item | Single-host example |
|---|---|
| Operating system | Fresh Debian 13, amd64, with root access |
| Starting lab capacity | 4 vCPU, 16 GiB RAM, 50 GiB free SSD space; allow additional build/cache space |
| Working directory | `/opt/PKICA` |
| Docker | Docker Engine and the Compose plugin from Docker's APT repository |
| Client endpoint | `https://localhost:8443`, bound to loopback by the quickstart override |
| Database | Three CockroachDB containers on one server; no host-failure tolerance |
| Time and name resolution | Working DNS and synchronized clocks on hosts and clients |

Capacity figures are starting estimates, not measured production requirements.
This guide uses rootful Docker and Bash commands run as root. Container users
remain unprivileged. The host is Debian 13; the repository's Dockerfiles choose
their own container OS and Python versions. Do not change those to match the host.

## 2. Prepare Debian 13

Run this section on **every** host used for either topology. Start a root shell
with `sudo -i`, or `su -` if the minimal installation does not include sudo.

```bash
cat /etc/os-release
dpkg --print-architecture
apt-get update
apt-get install -y ca-certificates curl git openssl python3 \
  python3-cryptography jq netcat-openbsd
timedatectl status
```

Confirm `VERSION_ID="13"`, architecture `amd64`, and a synchronized system clock.
Configure your organization's NTP service if synchronization is missing. Other
architectures require checking every container image and dependency first.
The Debian `python3-cryptography` package runs the certificate generator without
installing Python packages into the system interpreter with pip.

On an existing Docker host, review conflicting distribution packages before
installing Docker CE (`docker.io`, legacy `docker-compose`, `docker-doc`,
`docker-buildx`, `podman-docker`, standalone `containerd` and `runc`). The following
commands assume a fresh host. Docker's official installation instructions support
[Debian 13 and describe package conflicts](https://docs.docker.com/engine/install/debian/).

```bash
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg \
  -o /etc/apt/keyrings/docker.asc
chmod 0644 /etc/apt/keyrings/docker.asc
cat > /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/debian
Suites: trixie
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker
docker run --rm hello-world
docker compose version
```

Use the current Compose plugin, with support for `!override` (Compose 2.24.4 or
newer). The single-host override replaces the original gateway port mapping;
merging two ordinary port lists would leave the original public binding in place.
See [Compose merge and override rules](https://docs.docker.com/reference/compose-file/merge/).

Clone the repository into a new directory:

```bash
git clone https://github.com/BartelLuis/PKICA.git /opt/PKICA
cd /opt/PKICA
git rev-parse HEAD
```

Record the commit used. For multi-host installations, check out that same commit
on every server. If `/opt/PKICA` already exists, use the existing checkout after
checking its changes instead of cloning over it.

**Multi-host installations:** continue at
[the multi-host guide](QUICKSTART_MULTI_HOST.md). The remaining sections on this
page deploy all components on this one server.

## 3. Create the single-host configuration

Run from `/opt/PKICA`. Generate secrets once; keep `.env` with your recovery
material. Changing the software master key makes existing encrypted CA keys
unreadable. The guard below preserves an existing configuration.

```bash
if [ -e .env ]; then
  echo '.env already exists; review it before continuing.'
else
  (
    umask 077
    cat > .env <<EOF
PKICA_ENVIRONMENT=development
CA_KEY_BACKEND=software
ALLOW_SOFTWARE_KMS=true
AUDIT_HASH_CHAIN_SECRET=$(openssl rand -base64 32)
SOFTWARE_KMS_MASTER_KEY=$(openssl rand -base64 32)
EST_ENROLLMENT_USERS=device1:$(openssl rand -hex 24)
GATEWAY_BIND_IP=127.0.0.1
EOF
  )
fi
chmod 0600 .env

dc() {
  docker compose --env-file .env -p pkica \
    -f docker-compose.yml \
    -f docs/examples/quickstart/compose.single.yml "$@"
}
dc config --quiet
dc pull roach1 roach2 roach3 roach-init
dc build
```

`dc` is a Bash function used throughout this single-host guide. Recreate it after
opening a new shell, and always run it from `/opt/PKICA`. Avoid bare
`docker compose up`: that omits the quickstart override. `config --quiet` checks
the manifest without printing resolved secrets.

The override limits each database process's SQL/cache settings to 256 MiB each
for this lab; these are not total process memory limits. The original relative
25% settings would multiply across the three database containers.

CA, RA, and ACME use the quickstart
[database-client Dockerfile](examples/quickstart/Dockerfile.database-client),
which adds the CockroachDB SQLAlchemy dialect. Their database URLs use
`cockroachdb+psycopg://`. Both are necessary: the reference images and PostgreSQL
URLs cannot identify CockroachDB correctly. The service source code is unchanged.

It also configures RA/OCSP/CRL to load the infrastructure trust root through
`SSL_CERT_FILE`, preserving their client certificates with HTTPX 0.28.1. This
lab trust setting and its implications for external OIDC providers are explained
in [the compatibility note](QUICKSTART_LIMITATIONS.md#httpx-client-certificate-compatibility).

## 4. Generate TLS material and set file permissions

For a **new lab only**, generate the common trust root and service identities:

```bash
if [ -e certs/infra-ca.crt ]; then
  echo 'TLS material already exists; preserve it or plan a coordinated rotation.'
else
  python3 scripts/generate-dev-certs.py
fi
chmod 0755 certs
chmod 0644 certs/*.crt
chmod 0600 certs/*.key

GATEWAY_UID="$(dc run --rm --no-deps --entrypoint id gateway -u)"
PROXY_UID="$(dc run --rm --no-deps --entrypoint id ca-mtls-proxy -u)"
chown "$GATEWAY_UID" certs/gateway.key
chown "$PROXY_UID" certs/ca-mtls-proxy.key
chown 65532 certs/ra.key certs/ocsp.key certs/crl.key

dc run --rm --no-deps gateway nginx -t
dc run --rm --no-deps ca-mtls-proxy nginx -t
```

The Python services run as UID 65532. Query nginx's UID from the built images
instead of assuming it is the same. Mode `0600` keys generated by root are not
readable by those container users until ownership is set. The extra
`infra-ca.key` and `server.key` generated by the script stay root-only and are
not mounted by these manifests. Never make private keys world-readable to fix
a startup error.

The generated gateway certificate covers `localhost`, `127.0.0.1`, and `gateway`;
the CA proxy certificate covers `ca-mtls-proxy`. Service leaf certificates expire
after 90 days. Rerunning the generator replaces the trust root and all identities;
it is not a renewal procedure.

## 5. Initialize the database

Start only the database nodes first:

```bash
dc up -d roach1 roach2 roach3
dc run --rm --no-deps roach-init

for attempt in $(seq 1 60); do
  dc exec -T roach1 ./cockroach sql --insecure --host=roach1 \
    --execute='SELECT 1;' && break
  sleep 2
done
dc exec -T roach1 ./cockroach sql --insecure --host=roach1 \
  --execute='CREATE DATABASE IF NOT EXISTS pkica;'
dc exec -T roach1 ./cockroach sql --insecure --host=roach1 --database=pkica \
  --execute='CREATE SEQUENCE IF NOT EXISTS audit_log_seq;'
```

The init command is a **one-time cluster operation**. If run again on a cluster
that is already initialized, it reports that fact; do not delete its volumes.
If it fails on a new cluster, inspect `dc logs --tail=100 roach1 roach2 roach3`
and retry initialization after correcting the error. Proceed only when the SQL
commands succeed. Cluster initialization alone does not create the `pkica`
database. Create `audit_log_seq` explicitly because the CockroachDB dialect does
not create the sequence referenced by the audit model during `create_all()`.

## 6. Bootstrap the CAs and certificate profiles

Run these commands **once on a new database**, before starting the application
services. The one-off CA containers create the schema and persist software keys
in the same named volume later used by the CA service.

```bash
dc run --rm --no-deps --entrypoint python3 ca -m app.bootstrap create-root \
  --name root-ca --subject '{"cn":"PKICA Root CA","o":"Example Lab"}'
dc run --rm --no-deps --entrypoint python3 ca -m app.bootstrap create-intermediate \
  --name issuing-ca-1 --parent root-ca \
  --subject '{"cn":"PKICA Issuing CA 1","o":"Example Lab"}'
dc run --rm --no-deps --entrypoint python3 ca scripts/seed-profiles.py \
  --issuing-ca issuing-ca-1
```

Use `python3`: the distroless runtime does not provide the `python` command or an
interactive shell. Root/intermediate creation is not idempotent; do not rerun it
against existing CA names. Profile seeding skips profiles that already exist.
This sequence also avoids several services racing to create the initial schema.

Start the services after all three commands succeed:

```bash
dc up -d --no-deps ca ca-mtls-proxy ra ocsp crl acme est scep gateway
dc ps -a
dc logs --tail=100 ca ca-mtls-proxy ra gateway
```

## 7. Verify the installation

Use the lab trust root explicitly; do not disable TLS verification:

```bash
curl --fail --retry 15 --retry-delay 2 --retry-connrefused \
  --cacert certs/infra-ca.crt https://localhost:8443/healthz
curl --fail --cacert certs/infra-ca.crt \
  https://localhost:8443/api/v1/healthz
curl --fail --cacert certs/infra-ca.crt \
  https://localhost:8443/api/v1/requests
curl --fail --cacert certs/infra-ca.crt \
  https://localhost:8443/directory

dc exec -T ra python3 - <<'PY'
from pkicore.ca_client import CAClient
from pkicore.config import get_settings
result = CAClient(get_settings()).get_ca_certificate("issuing-ca-1")
assert "BEGIN CERTIFICATE" in result["certificate_pem"]
print("RA -> CA mTLS and CA database lookup succeeded:", result["name"])
PY
```

Expect `ok` from nginx, a JSON status from the RA, a JSON list of requests
(initially `[]`), directory metadata, and the final mTLS confirmation. Repeat an
application check after reviewing logs if it was still starting. `/healthz`
alone checks nginx; the RA request list checks database access. The final check
exercises the CA proxy, client certificate, and CA database lookup. The ACME
directory is a metadata check; it does not prove that ACME enrollment works.

To access this loopback-only deployment from your workstation, copy the **public**
`certs/infra-ca.crt` there and open an SSH tunnel (replace `admin` and the server):

```bash
ssh -N -L 8443:127.0.0.1:8443 admin@YOUR_DEBIAN_HOST
```

Use `https://localhost:8443` on the workstation with that trust root. No incoming
gateway port is needed for this option. For direct access from an approved lab
subnet, set `GATEWAY_BIND_IP` to the host's private address, apply the firewall
allowlist, and recreate only the gateway with `dc up -d --no-deps gateway`.
Use a certificate whose SAN covers your chosen name; for a temporary lab check,
`curl --resolve gateway:8443:HOST_IP --cacert certs/infra-ca.crt
https://gateway:8443/healthz` preserves verification of the generated `gateway`
name. There is no bundled browser management UI.

## 8. Exercise the REST approval workflow

This optional lab check creates a CSR, submits it, and asks the RA to approve it.
It checks the application wiring. **Do not deploy the resulting certificate:**
the current issuer-DN defect described in [limitations](QUICKSTART_LIMITATIONS.md)
prevents treating this as a trusted certificate-chain test.

Run on the single host, or on the APP host after completing the multi-host guide.
For APP, set `PKICA_URL=https://gateway:8443` and use its local hostname mapping
from that guide. Use a private directory outside the repository for test keys.

```bash
PKICA_URL="${PKICA_URL:-https://localhost:8443}"
PKICA_TRUST=/opt/PKICA/certs/infra-ca.crt
PKICA_TEST_DIR="$(mktemp -d /root/pkica-smoke.XXXXXX)"
chmod 0700 "$PKICA_TEST_DIR"
cd "$PKICA_TEST_DIR"
openssl req -new -newkey rsa:2048 -noenc \
  -keyout leaf.key -out leaf.csr -subj '/CN=test.example.internal' \
  -addext 'subjectAltName=DNS:test.example.internal'
chmod 0600 leaf.key
jq -n --rawfile csr leaf.csr \
  '{profile_name:"rest-tls-server",csr_pem:$csr,requested_sans:["dns:test.example.internal"]}' \
  > request.json
curl --fail-with-body --cacert "$PKICA_TRUST" \
  -H 'Content-Type: application/json' --data-binary @request.json \
  "$PKICA_URL/api/v1/requests" > request-response.json
jq . request-response.json
jq -e '.status == "pending"' request-response.json
jq '{request_id:.id}' request-response.json > approval.json
curl --fail-with-body --cacert "$PKICA_TRUST" \
  -H 'Content-Type: application/json' --data-binary @approval.json \
  "$PKICA_URL/api/v1/requests/approve" > approval-response.json
jq . approval-response.json
jq -e '.status == "issued"' approval-response.json
jq -r '.issued_certificate_pem' approval-response.json > leaf.crt
openssl x509 -in leaf.crt -noout -subject -issuer -dates
cd /opt/PKICA
```

Stop and inspect the response and RA/CA logs if a step fails; an empty output
file is not a successful issuance. This example intentionally relies on the
development identity. A production OIDC setup requires an access token with the
configured issuer/audience and an appropriate `pkica_roles` claim, supplied as
`Authorization: Bearer ...` on protected requests.

## 9. Stop, restart, and preserve data

```bash
cd /opt/PKICA
dc stop
dc start
dc ps -a
```

Recreate the `dc` function if this is a new shell. `stop`/`start` retain containers,
networks, and named volumes. For a previously initialized installation whose
containers were removed, start the database nodes, check SQL readiness, then
start the application service list from section 6 with `--no-deps`. Skip cluster
init and CA creation. Never use `down -v` or volume pruning as a restart procedure.

Preserve the database, `software-kms-data`, `scep-ra-data`, `.env`, and TLS material
as a coordinated recovery set, with private keys and secrets encrypted and access
restricted. The software master key is needed in addition to the encrypted key
volume. Record the Git commit and image IDs (`dc images`). Establish and rehearse
a consistent database/key backup and restore procedure before retaining valuable
state; copying live CockroachDB files is not such a procedure.

## 10. Troubleshooting

| Symptom | Check / action |
|---|---|
| Docker or pip downloads time out | Check host and build-container DNS/egress against the [installation firewall table](FIREWALL_RULES.md); a working host curl alone does not test container forwarding. |
| Compose says a required secret is missing | Run from `/opt/PKICA`, check `.env`, and use the `dc` function. Do not paste resolved `compose config` output into tickets. |
| RA exits with an OIDC configuration error | This lab requires `PKICA_ENVIRONMENT=development`; production requires a real OIDC/JWKS configuration. |
| `database "pkica" does not exist` | Execute `CREATE DATABASE IF NOT EXISTS pkica` after successful cluster initialization. |
| `relation "audit_log_seq" does not exist` | Create the sequence in the `pkica` database using section 5 before schema bootstrap. |
| `Could not determine version from string 'CockroachDB ...'` or missing `cockroachdb.psycopg` plugin | Use the quickstart Compose files and rebuild CA/RA/ACME with the supplied database-client Dockerfile; both the dialect package and `cockroachdb+psycopg` URLs are required. |
| Schema/table startup errors | Complete one-off CA bootstrap first; do not start RA/ACME while initial schema creation is in progress. |
| nginx/client says `Permission denied` reading a key | Recheck key ownership against the container UID and keep mode `0600`; rerunning the generator changes ownership. |
| Mount says a file is a directory | Ensure each `certs/*.crt`/`*.key` source exists as a file before container creation; a missing bind source can become a directory. |
| Software KMS fails to start/decrypt | Check opt-in, a base64 value encoding exactly 32 random bytes, the original master key, and ownership of existing key volumes by UID 65532. |
| TLS hostname mismatch / unknown issuer | Match SANs to the URL and use the matching `infra-ca.crt`; do not switch to `curl -k`. |
| Gateway 502 | Check `dc ps -a`, service logs, DNS, and the CA/RA checks above. |
| EST/SCEP/ACME fail, or CRL/OCSP paths return 404 | Review the [known application and routing limitations](QUICKSTART_LIMITATIONS.md); opening extra firewall ports will not fix them. |
| Certificate verification fails after issuance | Review the issuer-DN defect in [limitations](QUICKSTART_LIMITATIONS.md). Bootstrap success is not a chain-validity test. |

Proceed to the [production requirements](QUICKSTART_LIMITATIONS.md#production-requirements)
before expanding this evaluation beyond a restricted lab.
