# Splitting components across hosts

Use the [Debian 13 multi-host quickstart](QUICKSTART_MULTI_HOST.md) for a complete
three-server evaluation deployment. It provides standalone Compose manifests,
per-host configuration, certificate distribution, ordered bootstrap, and
connectivity checks. Apply the accompanying [firewall rules](FIREWALL_RULES.md).

The database can also run on separate hosts. The
[distributed database quickstart](QUICKSTART_DATABASE_CLUSTER.md) gives a complete
five-host variant: CA, APP, DB1, DB2, and DB3, with one CockroachDB node per DB host
and all three SQL addresses configured on CA, RA, and ACME.

The executable baseline uses this placement:

| Host | Services | Published port |
|---|---|---|
| CA | `ca`, `ca-mtls-proxy` | Private TCP 8443 for the CA proxy, allowed only from APP |
| DB | Three local CockroachDB nodes | Private TCP 26257 on `roach1`, allowed only from CA and APP |
| APP | `gateway`, `ra`, `ocsp`, `crl`, `acme`, `est`, `scep` | TCP 8443, restricted to approved lab clients |

This separates the signing service and database from the application host while
keeping gateway backends on one local Docker network. It does not provide
host-level HA. The [known application limitations](QUICKSTART_LIMITATIONS.md)
apply regardless of service placement.

## Additional separation

A dedicated edge/DMZ host or one host per service requires additional network and
proxy configuration. Docker bridge service names are local to each host; use
explicit private addresses or managed DNS for cross-host connections. Update
every relevant service URL and gateway upstream, preserve paths/query strings,
and provision server SANs for the names actually used by clients.

For adapter-to-RA connections, provide a proxy that verifies adapter client
certificates and sets the verified identity headers. RA currently serves HTTP
and expects those headers for its internal API. Do not publish its raw port 8000
to an untrusted network. EST/SCEP also need authenticated CA-certificate access.
The existing adapter authentication and routing defects must be resolved before
using those enrollment paths; see [the detailed limitations](QUICKSTART_LIMITATIONS.md).

Gateway-to-RA, OCSP, and CRL connections crossing hosts need their own protected
transport and narrowly scoped firewall rules. Different HTTP services cannot all
bind the same host IP and port; assign distinct private ports or route through
an authenticated reverse proxy. Keep the CA application itself unexposed and
reachable through its mTLS proxy.

## High availability and an offline root

Distribute CockroachDB nodes across independent machines, enable node/client
TLS, advertise reachable names, and supply a tested SQL failover endpoint.
Expand node-to-node TCP 26257 firewall rules only to the selected DB peers and
SQL clients. The [distributed database guide](QUICKSTART_DATABASE_CLUSTER.md)
provides per-node Compose configuration and direct SQL host-list failover for an
isolated lab. New connections can use surviving nodes; in-flight transactions
can still fail and are not automatically replayed by PKICA.

The online CA is needed for issuance and responder signing. Taking this same
service offline interrupts those operations. An offline root requires a
separate root-key lifecycle and operational design; merely moving the running
CA container to an air-gapped machine does not provide one.

Application replication needs load balancing, durable state, certificate
distribution/renewal, and failure testing. The repository supplies Docker Compose
examples; it does not supply a Kubernetes or Helm deployment. A Kubernetes
deployment would also need explicit network policies, workload identity,
persistent storage, and rollout/recovery procedures.
