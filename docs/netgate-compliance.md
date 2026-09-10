# Compatibility with Netgate's package guide

The package follows the structure described in [Developing Packages](https://docs.netgate.com/pfsense/en/latest/development/develop-packages.html)
and [Package Port Directory Structure](https://docs.netgate.com/pfsense/en/latest/development/package-directories.html).
This is a compatibility assessment, not Netgate approval or inclusion in its
package repository.

| Documented element | Implementation |
| --- | --- |
| FreeBSD port and dependencies | `pfsense/Makefile`, Python and SQLite dependencies; the preparation tool assembles a self-contained port for a ports-tree build. |
| Package manifest | `files/usr/local/share/pfSense-pkg-f2bguard/info.xml`, with `%%PKGVERSION%%` substitution. |
| Package configuration | `files/usr/local/pkg/f2bguard.xml`, menu/service registration and lifecycle hooks. |
| Supporting code | Native PHP pages, package include and service script in the normal pfSense locations. |
| Configuration conversion | PHP converts pfSense XML settings into root-managed JSON, certificate snapshots and a whitelist for the receiver. |
| File inventory | `pkg-plist` and staging checks cover the installed payload. |
| Installation lifecycle | Native `rc.packages` registration, resynchronization and deinstallation hooks. |
| Package building | The CI build uses a FreeBSD VM and `make package`; see [build instructions](build.md). |

Custom PHP pages are compatible with the guide's optional XML UI framework.
The package still uses pfSense's native authentication and configuration
mechanisms. The PF callback and reserved-table registration are version-specific
integration points that need regression checks on each supported pfSense version.

## Scope and remaining work

Version 0.1.6 was built, installed and functionally tested on a pfSense CE 2.9
system with FreeBSD 16 and Python 3.11. This does not establish compatibility
with every development snapshot or release. See [testing](testing.md) for
observed results and [release gates](security-and-release.md) for the remaining
IPv6, reboot, authorization and HA work.

Netgate's contribution process additionally calls for development-branch testing
and submission to its FreeBSD ports repository. Publishing this independent
repository does not perform that submission or make the package an official
Netgate package.

## Public source hygiene

The publication excludes deployment topology, management addresses, hostnames,
VM identifiers, credentials, certificates, certificate fingerprints, local build
artifacts and agent metadata. Test certificates are generated at runtime.
Standard installation paths and fixed service/table names remain documented
because they are part of the package interface.
