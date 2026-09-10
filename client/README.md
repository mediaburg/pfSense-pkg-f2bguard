# Linux sender

The sender keeps Fail2Ban hooks offline and fast. `enqueue ban` and
`enqueue unban` allocate the next durable sequence and write SQLite before
returning. The systemd worker delivers the outbox over HTTPS with mutual TLS
and retries in sequence with exponential backoff.

Install this repository on the host at `/usr/local/lib/f2bguard`, then create a
root-owned, mode `0640` JSON file such as:

```json
{
  "database": "/var/db/f2bguard/sender.sqlite",
  "endpoint": "https://guard.example/v1",
  "tls": {
    "ca": "/etc/f2bguard/ca.pem",
    "cert": "/etc/f2bguard/client.pem",
    "key": "/etc/f2bguard/client.key"
  },
  "permanent_jails": [
    {"name": "recidive", "bantime": -1}
  ]
}
```

TLS verification and hostname checking are always enabled. There is no
configuration switch to disable them. Keep the private key readable only by
the worker user; it is never accepted as a command-line argument.

Install the action as `/etc/fail2ban/action.d/f2bguard.conf`, add
`action = f2bguard` to explicitly selected jails, and install the systemd
units. For example, as root:

```sh
install -d -m 0750 /var/db/f2bguard
install -m 0644 client/f2bguard-action.conf /etc/fail2ban/action.d/f2bguard.conf
install -m 0644 client/f2bguard-sender.service client/f2bguard-snapshot.service client/f2bguard-snapshot.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now f2bguard-sender.service f2bguard-snapshot.timer
```

The snapshot timer runs `f2bguard-snapshot.service` every minute to reconcile
the full permanent-ban set. The snapshot command calls
`fail2ban-client get JAIL banip --with-time` for each explicitly configured
jail and includes only ticket lines whose actual duration is `-1`; temporary
bans in an otherwise permanent jail are never presented as permanent.

The action’s `actionflush` is an intentional `/usr/bin/true`. Fail2Ban uses
that hook for a jail stop or reload; acknowledging the bulk flush keeps those
technical lifecycle events from becoming individual unban/ban lifecycles in
the sender. Individual expiry or explicit per-IP unban operations still use
`actionunban`. The snapshot timer remains the authority for a real complete
state change.

If any enumeration command fails, returns a non-zero status, or emits a token
that is not an IP literal, the command exits without writing a snapshot. This
prevents an empty snapshot from clearing valid remote claims. Existing claim
IDs are retained in SQLite across worker restarts, and a fresh ban after an
unban receives a new ID.

The sender rejects scoped, loopback, link-local, multicast, unspecified, and
IPv4-mapped IPv6 addresses, matching the PF enforcement helper. The outbox is
bounded and delivered rows are pruned when the database opens; a full outbox
causes the hook to fail explicitly so delivery can catch up.
