# Security model and release gates

## Boundaries

1. An endpoint's client certificate must chain to the configured CA and match an explicitly registered SHA-256 certificate fingerprint. Certificate identity, not a JSON field, determines ownership.
2. The API validates a whole batch before committing it. Monotonic per-endpoint sequence numbers and durable SQLite transactions control ordering and replay.
3. The receiver is unprivileged. The PF helper authenticates its local Unix-socket peer UID using OS-provided credentials and accepts only the fixed `replace` operation.
4. The helper reads the whitelist from a root-controlled directory. The API service must not be able to replace that directory, file, socket or TLS trust configuration.
5. Only canonical single IPv4/IPv6 addresses can enter PF tables. Networks and hostnames are invalid ban targets. Loopback, unspecified, multicast, link-local and IPv4-mapped IPv6 ban targets are rejected.
6. Replacing the two address-family tables is not one atomic PF transaction. The helper snapshots both and attempts rollback if either replacement fails. It returns failure rather than reporting success after a partial update. A later retry converges state. A rollback failure requires administrator attention.
7. Missing or invalid whitelist data blocks new table updates; it never means an empty whitelist. Valid whitelist changes are rechecked during periodic enforcement.

## Remaining risk

A compromised registered endpoint can report false bans within its scope. mTLS proves origin, not truth. Quotas and whitelists limit this risk; they do not independently validate abuse. The sender therefore exports only explicitly configured permanent-ban jails and must fail reconciliation on incomplete enumeration.

IP addresses can be reassigned. History is never an enforcement input. No automatic permanent escalation exists.

PF rules affect new connections. Targeted termination of already established states is a separate feature and must not be claimed by this baseline. Existing pass/NAT rules may bypass intended filtering; firewall rule placement must be validated on the target pfSense version.

## Release gates

- [x] Build and install development version 0.1.6 on pfSense 2.9/FreeBSD 16 with Python 3.11.
- [ ] Validate native UI authorization, CSRF, certificate export and field validation on pfSense.
- [x] Verify table hooks across filter reload and service restart in the test environment.
- [ ] Verify reboot recovery and package removal on the supported target versions.
- [x] Verify new IPv4 connections to WAN, CARP and a port-forwarded test application.
- [ ] Verify IPv6 traffic and interactions with conflicting rules.
- [ ] Verify whitelist changes remove existing blocks without broad allow rules.
- [ ] Test malformed mTLS requests, expired/unknown/revoked client identities and overload limits.
- [ ] Test sender/receiver restart, lost acknowledgements, duplicate/reordered delivery and snapshot races.
- [ ] Implement authenticated durable runtime HA replication, tombstones and recovery.
- [ ] Define partition behavior and prevent unsafe dual writers before enabling automatic HA takeover.
- [ ] Verify failover/failback under traffic on two actual pfSense nodes.
- [ ] Add operational views for history, stale endpoints, effective versus desired state, and administrative claim retirement.
- [ ] Add targeted existing-state termination with tests before advertising immediate connection cutoff.

These are concrete release blockers, not hidden claims of implemented behavior. The first development artifact is intended for review and controlled lab testing.

## Primary references

- [Netgate package development](https://docs.netgate.com/pfsense/en/latest/development/develop-packages.html)
- [Netgate HA](https://docs.netgate.com/pfsense/en/latest/highavailability/index.html)
- [Netgate floating rules](https://docs.netgate.com/pfsense/en/latest/firewall/floating-rules.html)
- [FreeBSD getpeereid](https://man.freebsd.org/cgi/man.cgi?query=getpeereid)
