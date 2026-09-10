#!/bin/sh
# Build with the official pfSense ports tree in a pinned FreeBSD 16 VM.
set -eu

FREEBSD_IMAGE_URL='https://download.freebsd.org/snapshots/VM-IMAGES/16.0-CURRENT/amd64/20260831/FreeBSD-16.0-CURRENT-amd64-BASIC-CLOUDINIT-20260831-9bec8a959bd6-288738-ufs.qcow2.xz'
FREEBSD_IMAGE_SHA256='88ed07e3c3cecb4a6bca34a9bda1f88b75dd8c62fa02bbbd5f0317b1178d93f1'
PFSENSE_PORTS_COMMIT='a621624266b19a7f48b1f94a60821d2c2fc6ee4c'

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
artifacts=${ARTIFACT_DIR:-"$repo/artifacts"}
work=$(mktemp -d "${RUNNER_TEMP:-/tmp}/f2bguard-freebsd16.XXXXXX")
port="$work/pfSense-pkg-f2bguard"
ssh_key="$work/id_ed25519"
qemu_pid="$work/qemu.pid"

cleanup()
{
	if [ -r "$qemu_pid" ]; then
		pid=$(/bin/cat "$qemu_pid" 2>/dev/null || true)
		case "$pid" in ''|*[!0-9]*) ;; *) kill "$pid" 2>/dev/null || true ;; esac
	fi
}
trap cleanup EXIT INT TERM

for command in curl xz qemu-img qemu-system-x86_64 cloud-localds ssh scp ssh-keygen sha256sum tar; do
	command -v "$command" >/dev/null || { echo "missing CI command: $command" >&2; exit 1; }
done

[ ! -e "$artifacts" ] || { echo "refusing existing artifact directory: $artifacts" >&2; exit 1; }
mkdir -p "$work" "$artifacts"
python3 "$repo/tools/prepare_port.py" --output "$port"
tar -C "$work" -czf "$work/port.tar.gz" pfSense-pkg-f2bguard
ssh-keygen -q -t ed25519 -N '' -f "$ssh_key"

image_xz="$work/freebsd.qcow2.xz"
curl --fail --location --proto '=https' --tlsv1.2 --retry 3 -o "$image_xz" "$FREEBSD_IMAGE_URL"
printf '%s  %s\n' "$FREEBSD_IMAGE_SHA256" "$image_xz" | sha256sum -c -
xz -d "$image_xz"
image="$work/freebsd.qcow2"
qemu-img resize "$image" +8G

pubkey=$(/bin/cat "$ssh_key.pub")
cat >"$work/user-data" <<EOF
#cloud-config
users:
  - name: ci
    groups: wheel
    shell: /bin/sh
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - $pubkey
ssh_pwauth: false
disable_root: true
packages:
  - sudo
growpart:
  mode: auto
resize_rootfs: true
EOF
cat >"$work/meta-data" <<'EOF'
instance-id: f2bguard-freebsd16-ci
local-hostname: f2bguard-ci
EOF
cloud-localds "$work/seed.img" "$work/user-data" "$work/meta-data"

qemu-system-x86_64 \
	-machine accel=kvm:tcg -m 4096 -smp 2 -display none -monitor none -daemonize \
	-pidfile "$qemu_pid" -serial "file:$work/console.log" \
	-drive "file=$image,if=virtio,format=qcow2" \
	-drive "file=$work/seed.img,if=virtio,format=raw" \
	-netdev user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22 \
	-device virtio-net-pci,netdev=net0

common_opts="-i $ssh_key -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"
i=0
until ssh $common_opts -p 2222 ci@127.0.0.1 true 2>/dev/null; do
	i=$((i + 1))
	[ "$i" -lt 120 ] || { /bin/cat "$work/console.log" >&2; exit 1; }
	sleep 2
done
# FreeBSD BASIC-CLOUDINIT uses nuageinit, not the Linux cloud-init CLI.
# SSH can become ready before nuageinit installs sudo in its post-network phase.
i=0
until ssh $common_opts -p 2222 ci@127.0.0.1 /usr/local/bin/sudo -n true 2>/dev/null; do
	i=$((i + 1))
	[ "$i" -lt 120 ] || { /bin/cat "$work/console.log" >&2; exit 1; }
	sleep 5
done

scp $common_opts -P 2222 "$work/port.tar.gz" ci@127.0.0.1:/tmp/port.tar.gz
ssh $common_opts -p 2222 ci@127.0.0.1 "PFSENSE_PORTS_COMMIT='$PFSENSE_PORTS_COMMIT' sh -s" <<'EOF'
set -eux
freebsd-version | grep '^16\.0-CURRENT'
sudo env ASSUME_ALWAYS_YES=yes pkg bootstrap -f
[ "$(pkg config ABI)" = 'FreeBSD:16:amd64' ]
sudo pkg install -y ca_root_nss
sudo pkg install -y python311
sudo pkg install -y py311-sqlite3 || echo 'Building py311-sqlite3 from the pinned ports tree.' >&2
fetch -o /tmp/ports.tar.gz "https://codeload.github.com/pfsense/FreeBSD-ports/tar.gz/$PFSENSE_PORTS_COMMIT"
mkdir /tmp/ports
tar -xzf /tmp/ports.tar.gz -C /tmp/ports --strip-components 1
sudo mkdir -p /tmp/ports/security
sudo tar -xzf /tmp/port.tar.gz -C /tmp/ports/security
cd /tmp/ports/security/pfSense-pkg-f2bguard
sudo env BATCH=yes DEFAULT_VERSIONS=python=3.11 make PORTSDIR=/tmp/ports package
package=$(find work/pkg -type f -name 'pfSense-pkg-f2bguard-*.pkg' | head -1)
[ -n "$package" ]
[ "$(pkg query -F "$package" '%n')" = 'pfSense-pkg-f2bguard' ]
[ "$(pkg query -F "$package" '%q')" = 'FreeBSD:16:*' ]
cp "$package" "/tmp/$(basename "$package")"
EOF
scp $common_opts -P 2222 'ci@127.0.0.1:/tmp/pfSense-pkg-f2bguard-*.pkg' "$artifacts/"
package=$(find "$artifacts" -type f -name 'pfSense-pkg-f2bguard-*.pkg' | head -1)
[ -n "$package" ]
package_name=$(basename "$package")
package_sha256=$(sha256sum "$package" | awk '{print $1}')
(cd "$artifacts" && printf '%s  %s\n' "$package_sha256" "$package_name" >"$package_name.sha256")
source_revision=${GITHUB_SHA:-local}
cat >"$artifacts/BUILD-PROVENANCE.json" <<EOF
{
  "build_method": "FreeBSD ports make package",
  "freebsd_image": "$FREEBSD_IMAGE_URL",
  "freebsd_image_sha256": "$FREEBSD_IMAGE_SHA256",
  "package": "$package_name",
  "package_sha256": "$package_sha256",
  "pfsense_ports_commit": "$PFSENSE_PORTS_COMMIT",
  "source_revision": "$source_revision",
  "target_abi": "FreeBSD:16:amd64"
}
EOF
