# Firewall rules for Debian 13 installation and operation

Use this list with the [single-host Quickstart](QUICKSTART.md),
[multi-host Quickstart](QUICKSTART_MULTI_HOST.md), or
[distributed database Quickstart](QUICKSTART_DATABASE_CLUSTER.md). It covers installation,
image builds, and the connections that must remain available after bootstrap.
Ports below are **destination ports**; reply traffic uses connection tracking.

The Quickstarts use software key storage and an insecure CockroachDB cluster
for an isolated evaluation environment. Restrict access to trusted test
systems. Production requires the additional authentication, database TLS, and
key-custody work described in the guides; a firewall alone does not provide it.

## 1. Addresses and policy

Replace the following example addresses with your actual addresses:

| Name | Example | Role |
|---|---|---|
| `ADMIN_NET` | Your management subnet or jump-host IP | SSH and administration |
| `CLIENT_NET` | Your authorized test-client subnet | PKICA gateway clients |
| `CA_HOST` | `10.20.0.10` | `ca`, `ca-mtls-proxy` |
| `DB_HOST` | `10.20.0.20` | Alternative with all three nodes on one database host: `roach1`, `roach2`, `roach3` |
| `DB1` | `10.20.0.21` | Distributed database option: one `roach` container on the first database host |
| `DB2` | `10.20.0.22` | Distributed database option: one `roach` container on the second database host |
| `DB3` | `10.20.0.23` | Distributed database option: one `roach` container on the third database host |
| `APP_HOST` | `10.20.0.30` | `gateway`, `ra`, `acme`, `est`, `scep`, `ocsp`, `crl` |
| `DNS_SERVERS` | Your configured resolver IPs | Host and container DNS |
| `NTP_SERVERS` | Your configured time-server IPs | Host clock synchronization |

For single-host deployment, all application roles are on the same machine.
The three-host example puts all three database containers on `DB_HOST`, so
it does **not** survive loss of that host. The distributed database option
replaces `DB_HOST` with `DB1`, `DB2`, and `DB3`, for five Debian hosts in total
including CA and APP. Database-node traffic is a mandatory host-to-host
requirement in that option; use section 4.2 instead of section 4.1.

Apply a default-deny policy for unsolicited inbound connections. Permit the
specific sources below, established/related replies, and required network
control traffic. Do not add an inbound ephemeral-port range on a stateful
firewall. Stateless network ACLs need matching return-path rules using the
actual client ephemeral-port range.

The runtime addresses must be reachable from containers as well as hosts.
Docker normally translates outbound bridge-container traffic to the source
host's egress IP. If you use routed container networks, a VPN, or another NAT
gateway, allow the source address that the destination actually sees.
[Docker port publishing and masquerading](https://docs.docker.com/engine/network/port-publishing/)
describes the default behavior.

## 2. Rules needed before installation

Allow these connections from each machine on which you install packages,
clone the repository, pull images, or build images. Build containers also
need the APT and PyPI connections; host-only egress permission is insufficient
if forwarded container traffic is denied.

For the distributed database option, apply the installation rules separately
on **each of DB1, DB2, and DB3**, as well as CA and APP. All database hosts
need package installation, the repository checkout, Docker image pulls, DNS,
and time synchronization. Python application builds and their PyPI downloads
run on CA and APP in the documented procedure.

| Direction / source | Destination | Protocol / port | Purpose and duration |
|---|---|---|---|
| Inbound: `ADMIN_NET` | Each Debian host | TCP `22` | SSH, `scp`/SFTP, and remote bootstrap. Use your configured SSH port if different. Keep for administration. |
| Outbound: hosts and build containers | `DNS_SERVERS` | UDP **and** TCP `53` | Name resolution, including TCP fallback. Keep for operation. Restrict to your resolvers. |
| Outbound: Debian hosts | `NTP_SERVERS` | UDP `123` | Clock synchronization for TLS and token validity. Keep for operation. Containers use the host clock. |
| Outbound: hosts and build containers | Configured Debian mirrors, usually `deb.debian.org`, `security.debian.org`, and their selected CDN/mirror destinations | TCP `80` for HTTP sources; TCP `443` for HTTPS sources | Debian packages and security updates. Builds run `apt-get` inside Python builder images, whose sources may still use HTTP even when the host uses HTTPS. Keep the update route or reopen during maintenance. |
| Outbound: Debian hosts | `download.docker.com` | TCP `443` | Docker repository signing key and Docker Engine/Compose packages. Needed again for updates. |
| Outbound: hosts running Git | `github.com` | TCP `443` | Clone/fetch this repository over HTTPS. Archive downloads may additionally use `codeload.github.com`; raw-file downloads may use `raw.githubusercontent.com`. Those extra domains are not required by a normal HTTPS clone. |
| Outbound: Docker daemon / image builder | `registry-1.docker.io`, `auth.docker.io`, plus registry-provided blob/CDN destinations such as `production.cloudfront.docker.com` | TCP `443` | Pull `cockroachdb/cockroach`, `python`, `nginxinc/nginx-unprivileged`, and the `docker/dockerfile` build frontend. Authentication and image layers can use different destinations. Needed again for builds/pulls. |
| Outbound: Docker daemon / image builder | `gcr.io` and any blob-storage host returned by that registry, such as `storage.googleapis.com` | TCP `443` | Pull `gcr.io/distroless/python3-debian12:nonroot`, used by the application Dockerfiles. Needed again for builds/pulls. |
| Outbound: Python build containers | `pypi.org`, `files.pythonhosted.org` | TCP `443` | Python package index, wheels, source packages, and isolated build dependencies. Needed again for uncached builds. |

Debian documents its [APT source configuration](https://www.debian.org/doc/manuals/debian-reference/ch02#_debian_archive_basics)
and [mirror/CDN redirection](https://deb.debian.org/). Docker's
[Debian installation instructions](https://docs.docker.com/engine/install/debian/)
confirm Debian 13 support and the `download.docker.com` repository.

Docker lists the shared registry/authentication/pull destinations in its
[domain allowlist](https://docs.docker.com/desktop/setup/allow-list/); only the
registry-related entries apply to these Linux Engine pulls. Distroless lists
its `gcr.io` images in the [official project](https://github.com/GoogleContainerTools/distroless).
The [PyPI index API](https://docs.pypi.org/api/index-api/) shows the separate
index and package-file hosts.

Registry storage/CDN destinations and mirror IPs can change. Use a maintained
FQDN-aware egress policy or approved package/container mirrors, and check
blocked requests during a real image pull and uncached build. A static list
of current public IP addresses will not be a durable installation allowlist.
If an organization proxy is required, allow its configured address and port
and configure APT, Git, the Docker daemon, and build tools separately.

No public inbound HTTP/HTTPS connection is required to install Docker or
download dependencies. Installation downloads are outbound connections.
If using an offline installation, stage the repository, all image layers,
and build dependencies through your approved transfer process instead.

## 3. Single-host runtime rules

| Source | Destination | Protocol / port | Required use |
|---|---|---|---|
| `ADMIN_NET` | Single Debian host | TCP `22` | Administration |
| `CLIENT_NET` | Gateway on the single Debian host | TCP `8443` | HTTPS API, gateway health check, and configured enrollment/revocation endpoints |
| Host / permitted containers | `DNS_SERVERS` | UDP/TCP `53` | External and configured private DNS |
| Debian host | `NTP_SERVERS` | UDP `123` | Time synchronization |

The root `docker-compose.yml` publishes only gateway TCP `8443`. If the
single-host Quickstart binds this port to `127.0.0.1`, access it locally or
through the documented SSH tunnel: **no gateway inbound firewall exception
is needed** until you deliberately bind a reachable host address. An SSH
tunnel uses the existing TCP `22` rule.

Do not publish CockroachDB, the CA proxy, or application TCP `8000` merely to
make the containers communicate. Their local bridge-network connections
are summarized in section 5. Keep Docker's inter-container forwarding intact.

The development OIDC identity fallback permits administrative API access
without a real login. Do not allow untrusted clients to reach the evaluation
gateway. The optional production egress rules are in section 6.

## 4. Multi-host runtime rules

### 4.1. Three hosts with all database nodes on DB_HOST

These are the complete additional host-to-host rules for the CA / database /
application split in [the multi-host Quickstart](QUICKSTART_MULTI_HOST.md).

| Source | Destination | Protocol / destination port | Purpose |
|---|---|---|---|
| `ADMIN_NET` | `CA_HOST`, `DB_HOST`, `APP_HOST` | TCP `22` | SSH and certificate/configuration transfer |
| `CLIENT_NET` | `APP_HOST` | TCP `8443` | Gateway HTTPS |
| `APP_HOST` (`10.20.0.30`) | `CA_HOST` (`10.20.0.10`) | TCP `8443` | RA issuance/revocation; OCSP/CRL signing; CA-certificate retrieval by configured callers, all through the CA mTLS proxy |
| `CA_HOST` (`10.20.0.10`) | `DB_HOST` (`10.20.0.20`) | TCP `26257` | CA data and bootstrap/schema/profile commands |
| `APP_HOST` (`10.20.0.30`) | `DB_HOST` (`10.20.0.20`) | TCP `26257` | RA data and ACME accounts, nonces, authorizations, orders |
| Each host / permitted containers | `DNS_SERVERS` | UDP/TCP `53` | DNS |
| Each Debian host | `NTP_SERVERS` | UDP `123` | Time synchronization |

Apply each cross-host rule at both the source egress policy and destination
ingress policy when both are restricted. Replies are established traffic;
the CA does not initiate an application-host connection as part of these APIs.

Bind CA TCP `8443` to the CA private IP and database TCP `26257` to the DB
private IP. Restrict the CA port to the application host and the database
port to the CA/application hosts. **Never expose either service to the
Internet.** Do not substitute an entire untrusted LAN for these source IPs.

Only `roach1` publishes host TCP `26257` in this example. `roach2` and `roach3`
communicate with it inside the DB host's Docker network. The SQL endpoint is
therefore also a single connection endpoint; three local database processes
do not make this topology highly available.

There is no multi-host TCP `8000` requirement: gateway and application
backends remain together on `APP_HOST`. The CA's HTTP TCP `8000` endpoint
stays private to its local container networks and is never a host-published
port. No Docker Swarm/overlay network is used.

### 4.2. Five hosts with one database node per host

Use this matrix for the [distributed database Quickstart](QUICKSTART_DATABASE_CLUSTER.md).
It replaces the section 4.1 runtime matrix. The installation rules in section 2
still apply to every host.

| Source | Destination | Protocol / destination port | Purpose |
|---|---|---|---|
| `ADMIN_NET` | `CA_HOST`, `APP_HOST`, `DB1`, `DB2`, `DB3` | TCP `22` | SSH and certificate/configuration transfer on all five hosts |
| `CLIENT_NET` | `APP_HOST` (`10.20.0.30`) | TCP `8443` | Gateway HTTPS |
| `APP_HOST` (`10.20.0.30`) | `CA_HOST` (`10.20.0.10`) | TCP `8443` | RA and responder calls through the CA mTLS proxy |
| `CA_HOST` (`10.20.0.10`) | **Each of** `DB1` (`10.20.0.21`), `DB2` (`10.20.0.22`), `DB3` (`10.20.0.23`) | TCP `26257` | CA SQL connections and bootstrap/schema/profile commands, including connections to another node after a node fails |
| `APP_HOST` (`10.20.0.30`) | **Each of** `DB1` (`10.20.0.21`), `DB2` (`10.20.0.22`), `DB3` (`10.20.0.23`) | TCP `26257` | RA and ACME SQL connections, including connections to another node after a node fails |
| `DB1` (`10.20.0.21`) | `DB2` (`10.20.0.22`), `DB3` (`10.20.0.23`) | TCP `26257` | Required node RPC, replication, cluster join, and bootstrap |
| `DB2` (`10.20.0.22`) | `DB1` (`10.20.0.21`), `DB3` (`10.20.0.23`) | TCP `26257` | Required node RPC, replication, cluster join, and bootstrap |
| `DB3` (`10.20.0.23`) | `DB1` (`10.20.0.21`), `DB2` (`10.20.0.22`) | TCP `26257` | Required node RPC, replication, cluster join, and bootstrap |
| Each host / permitted containers | `DNS_SERVERS` | UDP/TCP `53` | DNS |
| Each Debian host | `NTP_SERVERS` | UDP `123` | Time synchronization |

Apply cross-host rules at both source egress and destination ingress where
restricted, including forwarded Docker traffic. All six directed database
peer connections are required **before cluster initialization** and throughout
operation. Allowing only connections to DB1 or only database-to-application
traffic is insufficient. SQL and node RPC share TCP `26257`; this deployment
does not use a separate replication port.

The `compose.db-node.yml` example publishes TCP `26257` only on each node's
private `DB_NODE_IP`. Admit that port only from the other two database hosts,
CA, and APP, using their actual source addresses after NAT. Restrict CA TCP
`8443` to APP. The database uses `--insecure`, so these connections must stay
within the isolated lab network or an existing encrypted private tunnel.

CA, RA, and ACME use a client URL listing all three database addresses directly;
no SQL load balancer is part of this deployment. Opening access to one node
does not provide access to the other failover candidates. The nodes advertise
their private host addresses for peer communication; independent Docker
networks do not resolve other hosts' container names.

No database console TCP `8080`, application TCP `8000`, Docker daemon, Swarm,
or overlay-network port is published or required for this layout. Bootstrap
uses the same TCP `26257` rules and administration uses SSH; no additional
bootstrap listener is needed.

## 5. Container-local connections

These are relevant when implementing host forwarding filters or container
network policies. They are **not additional Internet/host published ports**.

| Container source | Container destination | TCP port | Notes |
|---|---|---|---|
| `gateway` | `ra`, `acme`, `est`, `scep`, `ocsp`, `crl` | `8000` | HTTP reverse-proxy backends on the application network |
| `ca-mtls-proxy` | `ca` | `8000` | Verified CA proxy request forwarded to CA HTTP app |
| `ra`, `ocsp`, `crl` | `ca-mtls-proxy` | `8443` | Client-certificate-authenticated CA requests; cross-host in the multi-host layout |
| `est`, `scep` | `ca-mtls-proxy` | `8443` | CA-certificate retrieval requires configured client certificates and trust; see Quickstart limitations |
| `acme`, `est`, `scep` | `ra` | `8000` in the reference Compose | Adapter-to-RA requests. Reference authentication wiring needs additional work before enrollment; an allowed TCP connection alone does not make it operational. |
| `ca`, `ra`, `acme` | `roach1` | `26257` | Actual direct application database consumers; distributed deployment instead reaches every DB host as specified in section 4.2 |
| `roach1`, `roach2`, `roach3` | Each other | `26257` | Database replication and cluster traffic on one host; mandatory cross-host traffic between DB1, DB2, and DB3 in section 4.2 |
| `roach-init` / bootstrap CLI | Database nodes | `26257` | Initialization and SQL bootstrap |

`ocsp` and `crl` do not connect directly to the database in the implementation;
they call the CA. `est` and `scep` have no direct database connection either.
Do not infer SQL access from older architecture diagrams.

The CA is also attached to a database network in the root Compose. Container
network membership and host firewall rules are different layers: an
unpublished port is not a guarantee of isolation from other containers on
the same network. Review the complete Compose network membership when
hardening this reference deployment.

## 6. Optional integrations and topology changes

Open only the rules for integrations you actually configure. The software
backend and development OIDC fallback need none of the cloud rules below.

| Source | Destination | Protocol / port | When needed |
|---|---|---|---|
| RA container / `APP_HOST` | Configured `PKICA_OIDC_JWKS_URL` host | TCP `443`, or the explicitly configured URL port | OIDC public-key downloads and refreshes. The RA fetches JWKS directly; it does not need an inbound IdP callback listener. |
| Administrator's client | Your OIDC provider | Provider HTTPS port, normally TCP `443` | Obtain the access token used with the RA API. This connection originates at the client. |
| CA container / `CA_HOST` | Selected AWS KMS regional endpoint, for example `kms.eu-central-1.amazonaws.com` | TCP `443` | AWS KMS key operations. See [AWS KMS endpoints](https://docs.aws.amazon.com/general/latest/gr/kms.html). |
| CA container / `CA_HOST` | Configured Azure vault, for example `<vault>.vault.azure.net`, plus your tenant's identity endpoint, commonly `login.microsoftonline.com` | TCP `443` | Azure Key Vault and credential acquisition. Other clouds/federated tenants have different endpoints; see [Azure Key Vault firewall requirements](https://learn.microsoft.com/en-us/azure/key-vault/general/access-behind-firewall). |
| CA container / `CA_HOST` | `cloudkms.googleapis.com` and endpoints used by your selected Google credentials | TCP `443` | GCP KMS and authentication. See [Google KMS service endpoints](https://docs.cloud.google.com/kms/docs/reference/service-apis-overview). |
| CA container / `CA_HOST` | AWS STS, Google OAuth/token endpoints, cloud metadata endpoint, or your workload identity provider | Exact credential-provider port(s) | Conditional SDK credential exchange. A key-service rule does not automatically cover authentication. Derive this list from the credential mechanism you deploy. |
| CA container / `CA_HOST` | Host in `PKICA_VAULT_ADDR` | Configured TCP port, commonly `8200` or HTTPS `443` | Vault Transit. Use TLS; port `8201` is Vault's own cluster traffic, not a PKICA client requirement. See [Vault TCP listener](https://developer.hashicorp.com/vault/docs/configuration/listener/tcp). |
| CA container / `CA_HOST` | Your network HSM | Vendor-configured ports | Only for network HSMs. PKCS#11 is an API, not a standard network-port assignment; locally attached HSMs do not add a remote HSM rule. |
| ACME container / `APP_HOST` | Approved certificate-validation target web servers | TCP `80`; redirected targets' ports only if explicitly allowed | HTTP-01 validation, once adapter functionality is configured. The code makes an outbound HTTP request and follows redirects. The target server must admit that traffic from the application host. |
| External clients | Optional load balancer | TCP `443` | Standard HTTPS entry point if you deploy one |
| Optional load balancer | `APP_HOST` | TCP `8443` | Backend gateway and `/healthz` probes. Restrict gateway ingress to load-balancer sources if direct clients are not intended. |
| Monitoring/admin network | DB node management interface | TCP `8080` only if deliberately published | Optional CockroachDB console/metrics. Keep private or use an SSH tunnel. |
| Your installed logging/backup agent | Configured collector/backup destination | Agent-specific port | External logging and backups are separate integrations; no SIEM listener is required merely by setting up PKICA. |

The CA's networks in the root Compose are marked `internal: true`; opening
a perimeter egress rule does **not** give that container an external route.
A cloud/Vault deployment also needs an explicitly controlled egress network
or reachable private endpoint, trust material, and credentials mounted or
passed to the container. Several cloud credential variables listed in
`.env.example` are not automatically passed through by the root Compose.

The ACME HTTP-01 direction is **application host to the enrolling web server**.
It does not require inbound TCP `80` on the PKICA gateway. The reference
adapter has additional application/configuration limitations described in
the Quickstarts; opening port `80` does not fix those limitations.

If you split the gateway and adapters onto further hosts, define separate
reachable backend endpoints, TLS/authentication, and matching firewall rules
for each connection. The gateway currently uses local Docker service names;
these names are not shared between independent Compose hosts.

The [distributed database Quickstart](QUICKSTART_DATABASE_CLUSTER.md) supplies
reachable `--advertise-addr` and `--join` values and SQL client URLs containing
all three hosts. Its required firewall rules are in section 4.2, rather than
being an optional integration. Node/client TLS remains a production requirement.
CockroachDB's [production checklist](https://www.cockroachlabs.com/docs/v24.1/recommended-production-settings)
documents the default SQL/cluster TCP `26257` and management TCP `8080` ports.

## 7. Debian and Docker firewall behavior

**Use a network firewall/security group for the source/destination matrices,
and verify any host firewall also filters Docker forwarding.** Allowing or
denying ports only in UFW's usual host-input rules is insufficient: Docker
published-port traffic can bypass those rules. Keep Docker's managed rules
enabled; disabling Docker firewall management can break bridge connectivity.
See [Docker packet filtering and firewalls](https://docs.docker.com/engine/network/packet-filtering-firewalls/).

For Docker's default **iptables backend** on Debian (including the
`iptables-nft` compatibility tools), put container-forwarding restrictions
in `DOCKER-USER`, ahead of a terminal `RETURN`. Preserve established/related
traffic, allow the required source/destination pairs, then drop other
unsolicited traffic arriving through the protected external interface.
Scope those drops to the relevant interface/destination so they do not
break local bridge communication or permitted outbound builds.

Packets have already undergone destination NAT when `DOCKER-USER` sees them.
A normal destination-port match uses the **container** port. Use conntrack's
original destination/address fields if filtering by the host-published
address and port, especially with a `443:8443` mapping. Docker documents the
ordering and `--ctorigdst` / `--ctorigdstport` matches in
[Docker with iptables](https://docs.docker.com/engine/network/firewall-iptables/).

SSH terminates on the host and needs a separate host-input rule. Persist
your firewall configuration, apply it in the correct order after Docker
creates its chains, and test it again after a reboot. Keep console access
or an existing management session available while changing SSH rules.

Do not mix this `DOCKER-USER` procedure with an explicitly selected native
nftables Docker backend: that backend uses a different ruleset and has no
`DOCKER-USER` chain. Follow [Docker with nftables](https://docs.docker.com/engine/network/firewall-nftables/)
if your installation deliberately uses it.

Check **IPv6 as well as IPv4**. A generic Docker port mapping can expose
additional host addresses; an IPv4-only filter does not secure IPv6.
Bind published services to the intended private/loopback addresses and
either apply equivalent IPv6 rules or deliberately leave the service
unpublished on IPv6. Preserve required ICMP/ICMPv6 for path-MTU discovery
and, where used, IPv6 neighbor discovery.

Do not open these ports for the documented Quickstarts: Docker daemon TCP
`2375`/`2376`, Swarm TCP `2377`, Swarm TCP/UDP `7946`, overlay UDP `4789`,
application HTTP TCP `8000`, or database console TCP `8080`.

## 8. Validate from both allowed and denied sources

On each host, as root, inspect listeners and the active Docker/firewall mappings:

```bash
ss -lntup
docker ps --format 'table {{.Names}}\t{{.Ports}}'
iptables -S DOCKER-USER
iptables -t nat -S DOCKER
ip6tables -S
```

Use the appropriate backend inspection commands if you selected native
nftables. `ss` alone does not reveal every Docker NAT mapping.

From the **application host** in the three-host layout (section 4.1):

```bash
nc -vz -w 3 10.20.0.10 8443
nc -vz -w 3 10.20.0.20 26257
```

From the **CA host** in the three-host layout:

```bash
nc -vz -w 3 10.20.0.20 26257
```

For the **distributed database layout** (section 4.2), after all database
containers have started, run this on **both CA and APP**. Every probe must
succeed:

```bash
for db_ip in 10.20.0.21 10.20.0.22 10.20.0.23; do
  nc -vz -w 3 "$db_ip" 26257 || exit 1
done
```

On APP, also check the CA proxy:

```bash
nc -vz -w 3 10.20.0.10 8443
```

Run the following block separately on **DB1, DB2, and DB3**, setting
`DB_NODE_IP` to the private address of the host on which you run it. Both
remote-node probes on each host must succeed before initialization:

```bash
DB_NODE_IP=10.20.0.21  # Use .22 on DB2 and .23 on DB3.
for db_ip in 10.20.0.21 10.20.0.22 10.20.0.23; do
  if [ "$db_ip" != "$DB_NODE_IP" ]; then
    nc -vz -w 3 "$db_ip" 26257 || exit 1
  fi
done
```

These host probes verify basic reachability. Follow the distributed guide's
container-level node-status, SQL, and failover checks as well; a successful
host probe alone does not verify Docker forwarding or database quorum.

From an authorized client, check the gateway using the correct hostname,
CA trust file, and port from your Quickstart:

```bash
curl --fail --cacert certs/infra-ca.crt https://localhost:8443/healthz
```

That example is for a local endpoint/SSH tunnel and the generated lab trust
file. A remote gateway certificate must contain the remote hostname in its
SAN; use its hostname and issuer trust file instead. A successful `/healthz`
response only proves the gateway is reachable. Complete the guide's API,
database, and certificate-issuance verification as well.

Also run the connection checks from a **denied client source**: CA TCP
`8443` and DB TCP `26257` must be unreachable. Check each host's TCP `8000`
and `8080` are unreachable from remote clients, and verify unintended IPv6
access is blocked. A TLS/mTLS rejection proves a connection reached the
service; it does not prove the firewall denied it.

For the distributed layout, explicitly check **all three database addresses**
from a denied source. None of the following connection attempts may succeed:

```bash
for db_ip in 10.20.0.21 10.20.0.22 10.20.0.23; do
  if nc -vz -w 3 "$db_ip" 26257; then
    echo "Unexpected database access to $db_ip" >&2
    exit 1
  fi
done
```

Finally, perform the actual `apt update`, image pulls, and image builds on
the intended hosts, then run the application checks from containers as
shown in the guides. DNS failures, TLS trust/hostname errors, HTTP
`401`/`403`, and missing OIDC/KMS credentials are different problems from a
TCP timeout. Use firewall counters and service logs to distinguish them.
