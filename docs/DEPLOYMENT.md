# Deployment guide

For a new Debian 13 (Trixie) installation, use the following guides. They include
the executable commands and Compose examples for the current repository.

| Guide | Deployment |
|---|---|
| [Single-host quickstart](QUICKSTART.md) | All components on one Debian 13 server; gateway bound to loopback by default |
| [Multi-host quickstart](QUICKSTART_MULTI_HOST.md) | Separate CA, database, and application servers on an isolated private network |
| [Distributed database quickstart](QUICKSTART_DATABASE_CLUSTER.md) | Five hosts: CA, APP, and three independent CockroachDB nodes with SQL connection failover |
| [Firewall rules](FIREWALL_RULES.md) | Installation egress, administration, service connections, and optional integrations |
| [Limitations and production requirements](QUICKSTART_LIMITATIONS.md) | Known application defects and the work required before production acceptance |

Both quickstarts use the software key backend, an insecure database, and a
development administrator identity. Keep them in a restricted evaluation
environment. Certificate-chain and enrollment defects currently prevent treating
these instructions as a production installation procedure.

The bootstrap sequence matters: initialize CockroachDB, explicitly create the
`pkica` database and audit sequence, create the schema/CAs with a one-off CA
container, seed profiles, then start the applications. Container commands use
`python3`. Generated private keys need permissions for their actual container
users. The quickstarts cover
these details and distinguish service liveness from functional validation.

## Planning a production deployment

Resolve the [documented implementation limitations](QUICKSTART_LIMITATIONS.md)
first. Configure managed service TLS, OIDC, database TLS and scoped users,
KMS/HSM credentials and egress, backups, monitoring, and renewal procedures.
Validate certificate trust, issuance, revocation, each enabled enrollment
protocol, authorization, and restoration before accepting the deployment.

The root `.env.example` lists configuration hints; it is not a complete
production configuration. Some provider SDK credentials require explicit
environment forwarding, file mounts, or workload identity in the CA service.
The reference CA's internal Docker networks also need an explicit egress design
before a cloud KMS is reachable.

Three database containers on one machine do not tolerate host loss. Application
replication also requires a defined load-balancing and state-management design;
a `docker compose --scale` command alone does not establish high availability.
For separate database hosts, use the [distributed database guide](QUICKSTART_DATABASE_CLUSTER.md).
See also the [multi-host extension notes](QUICKSTART_MULTI_HOST.md#9-moving-beyond-this-topology)
and [split-deployment design notes](SPLIT_DEPLOYMENT.md).
