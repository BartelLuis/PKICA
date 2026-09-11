# Splitting components across separate hosts/servers

Every service in this repository is a standalone container with its own
Dockerfile and its own network requirements — nothing hard-codes "all on
one Docker Compose project". To split the platform across dedicated
machines (recommended for production: at minimum, an isolated host for the
CA), run each service's `docker compose` fragment on its own host and
replace in-cluster DNS names (`ca-mtls-proxy`, `roach1`, `ra`, ...) with the
real reachable addresses/hostnames of your other hosts, over a private
network (VPN/VPC peering/dedicated VLAN — never route CA traffic over the
public internet even with mTLS).

## Example: 3-host split

| Host | Services | Network exposure |
|---|---|---|
| `host-ca` (most restricted, ideally offline/air-gapped except for scheduled sync windows) | `ca`, `ca-mtls-proxy` | Only reachable from `host-core` over a private link/VPN on port 8443 |
| `host-core` | `cockroachdb` (3-node cluster spread across this + 2 more DB hosts for real HA), `ra`, `ocsp`, `crl` | Reachable from `host-edge` on 8000, and pushes/reads to CockroachDB |
| `host-edge` | `gateway`, `acme`, `est`, `scep` | Internet-facing, behind your load balancer/WAF |

## Steps

1. **Generate real internal mTLS certificates** for each service identity
   (`ra`, `ocsp`, `crl`, `ca-mtls-proxy`) from your own infra CA — do not
   reuse `scripts/generate-dev-certs.py` output across hosts/production.
2. On `host-ca`: run only the `ca` + `ca-mtls-proxy` compose fragment
   (extract those two services into their own `docker-compose.ca.yml`).
   Configure `PKICA_DATABASE_URL` to point at the CockroachDB cluster's
   load-balanced address on `host-core`/DB hosts. Firewall this host so
   *only* `host-core`'s RA/OCSP/CRL source IPs can reach port 8443, and
   only outbound access to the DB + your KMS/HSM endpoint is allowed.
3. On `host-core`: run `ra`, `ocsp`, `crl`, and (if colocating) CockroachDB.
   Set `PKICA_CA_INTERNAL_URL=https://<host-ca-address>:8443`.
4. On `host-edge`: run `gateway`, `acme`, `est`, `scep`. Set
   `PKICA_RA_INTERNAL_URL=http://<host-core-address>:8000` (put this over a
   private network or add TLS — the reference `ra` app serves plain HTTP
   because it assumes an isolated network; add a TLS-terminating proxy in
   front of `ra` if the RA-to-adapter hop crosses an untrusted network).
5. Repeat CockroachDB's standard multi-node join flow
   (`--join=<db-host-1>,<db-host-2>,<db-host-3>`) across your DB hosts —
   see [CockroachDB's own multi-node deployment docs](https://www.cockroachlabs.com/docs/stable/manual-deployment)
   for the authoritative, up-to-date process (cert generation, load
   balancing, backup/restore).

## Kubernetes

If you outgrow Docker Compose, each `services/<name>/Dockerfile` builds a
standard OCI image usable as-is in a Kubernetes `Deployment` +
`NetworkPolicy` per the same segmentation model (`ca` in its own namespace
with a restrictive `NetworkPolicy` allowing ingress only from
`ca-mtls-proxy`'s pod selector, etc.). This repository ships Docker Compose
manifests only; converting them to Helm charts is a mechanical exercise
once you've validated the Compose-based topology.
