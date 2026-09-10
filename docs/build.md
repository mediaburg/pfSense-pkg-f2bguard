# Building the pfSense package

Netgate packages are FreeBSD ports. The release artifact is built by placing a
self-contained port in the pfSense `FreeBSD-ports` tree and running `make
package`; the portable `pkg create` lab helper is not the release build.

Generate the standalone port from this development repository with:

```sh
python3 tools/prepare_port.py --output /new/path/pfSense-pkg-f2bguard
```

The command refuses to overwrite an existing directory. Copy its output to
`security/pfSense-pkg-f2bguard` in a compatible pfSense ports checkout and run
`make package` there on the target FreeBSD major version.

GitHub Actions is configured to automate this process for the pfSense 2.9
development target. It boots an official, checksum-pinned FreeBSD 16.0-CURRENT amd64 cloud image,
checks that `pkg` reports `FreeBSD:16:amd64`, overlays the generated port onto a
pinned pfSense ports commit, and runs `make package` with Python 3.11 selected.
The no-arch package must report `FreeBSD:16:*` before upload. The workflow has
read-only repository permission and does not publish or connect to a firewall.
The workflow must not be described as a successful CI build until a GitHub run
has completed and its package metadata has been inspected.

The VM image and pfSense ports commit are pinned in
`tools/ci_freebsd16_package.sh`. Update both explicitly when the pfSense 2.9
builder baseline changes, then validate the package on pfSense.

The local lab staging path remains available for controlled target-side builds:

```sh
python3 tools/build_lab_package.py \
  --abi FreeBSD:16:amd64 \
  --python-version 3.11 \
  --python-package-version VERSION \
  --sqlite-package-version VERSION \
  --output /new/path/f2bguard-lab-package
```

That command only stages files and metadata. It does not install, deploy, or
replace the FreeBSD ports `make package` validation used by CI.
