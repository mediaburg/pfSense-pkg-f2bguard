# Testing

## Automated checks

Run `python3 tools/check.py --require-php` with Python 3.11 or newer, PHP CLI
and OpenSSL available. The suite creates disposable certificates and loopback
listeners; it needs permission to open local TCP and Unix sockets. It does not
connect to a deployment or use stored credentials.

The tests cover claim ownership, ordering, snapshots, replay, validation,
whitelist precedence, TLS authentication, receiver restart binding, sender
queues, privileged-helper boundaries and package staging. PHP checks cover
configuration conversion and generated rules; they do not replace a native
pfSense test.

## Native validation scope

Development version 0.1.6 was built and installed on pfSense CE 2.9 with
FreeBSD 16 and Python 3.11. In a controlled test environment the following
were verified using new connections:

- Qualified Fail2Ban bans blocked traffic to a WAN address, a CARP address
  and a port-forwarded test application.
- A temporary test jail did not export a qualifying remote claim.
- The last owner's unban restored connectivity; an earlier owner's unban
  did not remove another endpoint's claim.
- Replayed events were idempotent. CIDR ban targets were rejected.
- Whitelisted sources produced no effective block.
- An unknown certificate and a missing certificate were rejected.
- Claims survived filter reload, service restart and package update.

The tests uncovered fixes for XML boolean serialization, PF table reservation,
FreeBSD command paths and TCP listener reuse. These have regression coverage.

## Reproducing a controlled traffic test

Use a snapshot of a test firewall and a separate Linux host running Fail2Ban
and the sender. Create a dedicated CA and endpoint certificates. Keep client
private keys on their endpoint; transfer only public certificate requests for
signing. Configure a trusted administration alias before enabling enforcement.

Use a controlled traffic source outside that whitelist. Limit temporary WAN
pass rules and any port forward to this source and the test application. Verify
initial connectivity, trigger the selected jail's threshold, check actual
connection blocking, then unban and verify connectivity returns. Repeat with
two endpoint identities. Remove all test claims when finished.

## Not yet verified or implemented

Runtime HA replication is not implemented. IPv6 traffic, reboot recovery,
existing-state termination and sustained overload need separate validation.
Native authentication/CSRF integration needs a dedicated authorization audit.
No private deployment addresses, host identifiers, certificates, credentials
or packet captures are included in this repository.
