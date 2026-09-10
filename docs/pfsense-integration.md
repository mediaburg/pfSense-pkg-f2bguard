# pfSense integration

This directory contains a native pfSense package skeleton for Fail2Ban Guard. It follows the pfSense package layout: `info.xml` registers the package, `f2bguard.xml` adds the Services menu entry and package filter callback, the PHP include writes runtime files, and the web pages use `guiconfig.inc` plus the normal `head.inc`/`foot.inc` framework. The pages are disabled by default and do not open a listener or add PF rules until the General page is explicitly enabled.

## Native 0.1.6 verification status

Package version 0.1.6 has been built and installed on the pfSense CE 2.9 test node A. Basic Services > Fail2Ban Guard GUI navigation and configuration, service lifecycle checks, and package-owned PF table preservation checks passed there. This is a native installation check, not a release claim for the remaining HA, traffic, reboot, or security gates below.

## Runtime ownership and service lifecycle

The package creates a dedicated `f2bguard` group and unprivileged service user. The backend runs as that user:

```text
PYTHONPATH=/usr/local/share/f2bguard python3 -m f2bguard.server --config /usr/local/etc/f2bguard/config.json
```

The PF helper runs separately as root and is restricted to its fixed socket and tables:

```text
PYTHONPATH=/usr/local/share/f2bguard python3 -m f2bguard.pf_helper \
  --socket /var/run/f2bguard/pf.sock \
  --whitelist /usr/local/etc/f2bguard/whitelist.txt \
  --user f2bguard
```

`/usr/local/etc/rc.d/f2bguard` starts the helper and backend as separate processes. It uses `/usr/local/etc/rc.conf.d/f2bguard` for the normal pfSense service enable flag, reloads the pfSense filter before starting, and does not send commands to tables outside `f2bguard_v4` and `f2bguard_v6`. The FreeBSD rc script uses the platform paths `/bin/cat` and `/bin/ps` for PID checks, verifies that each PID belongs to the expected Fail2Ban Guard module, waits for each child to become observable, and stops a partial startup if the second process fails. It runs through `daemon -S` so background errors reach syslog. Stop leaves package-owned PF table contents untouched so a transient service stop cannot alter unrelated firewall state.

The web UI writes the following root-owned files atomically:

* `/usr/local/etc/f2bguard/config.json` (mode `0640`, group `f2bguard`)
* `/usr/local/etc/f2bguard/whitelist.txt` (mode `0640`, group `f2bguard`)
* `/usr/local/etc/f2bguard/tls/server.crt`, `server.key`, and `ca.crt` (mode `0640`, group `f2bguard`)

The durable database remains `/var/db/f2bguard/state.sqlite`, owned by `f2bguard`. Package removal stops the processes and removes generated configuration and TLS snapshots but keeps the database directory for a safe reinstall.

## Configuration model

The General page requires an explicit IP address and port. Wildcard listen addresses are rejected. Server and client trust material is selected by pfSense Certificate Manager reference IDs; PEM snapshots are generated from those references and private keys are never exposed through the HTTP API. Clients are configured with one or more 64-hex SHA-256 DER certificate fingerprints and at least one allowed jail.

WAN interface selections and the jail catalogue are stored in pfSense configuration for the PHP filter callback and UI validation. They are intentionally omitted from the backend JSON because the service contract has a strict schema. The generated JSON contains the contract fields (`enabled`, explicit listen address and port, TLS paths, clients, durable paths, limits, and history retention).

The package stores the client, jail, and interface lists as scalar JSON values (`clients_json`, `jails_json`, and `wan_interfaces_json`) under `installedpackages/f2bguard/config/0`. This avoids pfSense list-tag serialization losing numeric arrays or nested client permissions. A malformed stored list is treated as a configuration error and disables the runtime rather than falling back to stale client credentials.

The enabled setting is stored as the explicit XML-safe scalar `yes` or `no` and normalized when read. An empty legacy XML tag is treated as disabled, so a config serialization problem cannot unexpectedly start the service. The generated runtime JSON uses a real boolean `enabled` field.

Whitelist aliases are resolved by the privileged pfSense integration only when every entry is a literal IP or CIDR. Dynamic aliases, URL tables, DNS names, ranges, nested aliases, and missing aliases fail closed. A failed update preserves the last valid snapshot, writes a disabled runtime configuration, stops the package service, and reloads the filter; the operator must correct the alias before new enforcement updates can resume.

## PF filter reload behavior

`f2bguard.xml` registers `f2bguard_generate_rules` through pfSense's `filter_rules_needed` package callback. The callback emits rules in the `pfearly` phase, before ordinary user rules. During that callback it registers `f2bguard_v4` and `f2bguard_v6` in pfSense's reserved table registry as well as declaring them as persistent PF tables. This prevents the normal pfSense table cleanup from removing the package-owned declarations. On each filter generation it also refreshes the whitelist from the current pfSense alias without recursively reloading the filter. When the firewall filter is generated, the callback emits interface-scoped inbound block rules:

```pf
table <f2bguard_v4> persist
table <f2bguard_v6> persist
block in quick on <selected-interface> inet from <f2bguard_v4> to any
block in quick on <selected-interface> inet6 from <f2bguard_v6> to any
```

The helper owns table contents; the callback does not embed event data in generated rules. The rc script invokes `/etc/rc.filter_configure_sync` through pfSense's supported filter reload path. A filter reload can replace the generated ruleset, so the backend/helper must re-apply the durable desired state after reload; a manually populated PF table is not treated as permanent configuration. The package does not edit `/tmp/rules.debug` or claim that a hand-written PF table survives a reload.

This uses the pfSense package callback documented in the [pfSense package development guide](https://docs.netgate.com/pfsense/en/latest/development/develop-packages.html) and the current package `filter_rules_needed` mechanism. The generated rules follow pfSense's normal `filter_configure_sync` lifecycle; final behavior still requires testing against the target pfSense release.

## HA status

Runtime claim replication and automatic failover are not implemented. CARP/pfsync and pfSense XMLRPC may carry static package configuration only when an administrator explicitly enables those systems; they do not replicate the SQLite database, event sequence state, or active claims. The Status tab reports HA as unsupported/degraded, and this package must not be presented as production-ready for automatic HA failover until a separate durable replication design exists.

## Build and validation

`pfsense/` contains the port definition. Run `tools/prepare_port.py` to assemble
its Python sources into a self-contained port before overlaying it into the
pfSense FreeBSD ports tree. See [building](build.md) for the exact commands and
the pinned GitHub Actions build environment. The workflow invokes `make package`.

Native development version 0.1.6 was installed and tested on pfSense CE 2.9.
The public source version includes packaging changes for reproducible builds;
see [testing](testing.md) for the runtime evidence. Authentication/CSRF audit,
reboot recovery, certificate rotation, IPv6 traffic and application HA remain
separate release gates.
