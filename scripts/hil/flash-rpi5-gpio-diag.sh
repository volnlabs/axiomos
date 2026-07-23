#!/usr/bin/env bash
set -Eeuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE_DIR="${AXIOM_GPIO_DIAG_IMAGE_DIR:-$REPO_ROOT/artifacts/runs/axiomos-hil-20260720T134903Z/02-pi-boot/image-v03-handler-diag}"
PI_BOOT_DEV="${1:-${PI_BOOT_DEV:-}}"
MOUNT_POINT=""

# Expected hash comes from the image's own build.toml, not a baked-in constant,
# so this flasher tracks whatever image IMAGE_DIR points at.
EXPECTED_KERNEL_SHA256="$(awk -F'"' '/^kernel8_sha256/ {print $2}' "$IMAGE_DIR/build.toml" 2>/dev/null || true)"
[[ "$EXPECTED_KERNEL_SHA256" =~ ^[0-9a-f]{64}$ ]] ||
    { echo "ABORT: no kernel8_sha256 in $IMAGE_DIR/build.toml" >&2; exit 1; }

die() {
    echo "ABORT: $*" >&2
    exit 1
}

cleanup() {
    if [[ -n "$MOUNT_POINT" ]] && findmnt -rn -S "$PI_BOOT_DEV" >/dev/null 2>&1; then
        sync
        udisksctl unmount -b "$PI_BOOT_DEV" >/dev/null || true
    fi
}
trap cleanup EXIT

[[ -n "$PI_BOOT_DEV" ]] || die "pass the Pi boot partition, for example: $0 /dev/sdb1"
[[ "$PI_BOOT_DEV" == /dev/* ]] || die "target must be an absolute /dev path"
[[ -b "$PI_BOOT_DEV" ]] || die "$PI_BOOT_DEV is not a block device"
[[ "$(lsblk -dnro TYPE "$PI_BOOT_DEV" | tr -d ' ')" == "part" ]] ||
    die "$PI_BOOT_DEV is not a partition"

PARENT_NAME="$(lsblk -nro PKNAME "$PI_BOOT_DEV" | head -n 1 | tr -d ' ')"
[[ -n "$PARENT_NAME" ]] || die "could not resolve the parent disk for $PI_BOOT_DEV"
PARENT_DEV="/dev/$PARENT_NAME"

[[ "$(lsblk -dnro RM "$PARENT_DEV" | tr -d ' ')" == "1" ]] ||
    die "$PARENT_DEV is not marked removable"

PARTITION_SIZE="$(lsblk -bdnro SIZE "$PI_BOOT_DEV" | tr -d ' ')"
[[ "$PARTITION_SIZE" =~ ^[0-9]+$ ]] || die "could not read the partition size"
(( PARTITION_SIZE >= 134217728 )) ||
    die "$PI_BOOT_DEV is smaller than 128 MiB; it is not the expected Pi boot partition"

MODEL="$(lsblk -dnro MODEL "$PARENT_DEV" | sed 's/[[:space:]]*$//')"
[[ "${MODEL,,}" != *shrike* ]] || die "$PARENT_DEV is the Shrike USB device"

[[ -f "$IMAGE_DIR/kernel8.img" ]] || die "diagnostic kernel is missing from $IMAGE_DIR"
[[ -f "$IMAGE_DIR/SHA256SUMS" ]] || die "SHA256SUMS is missing from $IMAGE_DIR"

echo "Verifying diagnostic image..."
(
    cd "$IMAGE_DIR"
    sha256sum -c SHA256SUMS
)

ACTUAL_IMAGE_SHA256="$(sha256sum "$IMAGE_DIR/kernel8.img" | awk '{print $1}')"
[[ "$ACTUAL_IMAGE_SHA256" == "$EXPECTED_KERNEL_SHA256" ]] ||
    die "diagnostic kernel hash does not match the expected build"

echo
echo "Target partition: $PI_BOOT_DEV"
lsblk -p -o NAME,SIZE,RM,RO,TYPE,FSTYPE,LABEL,MODEL,TRAN,MOUNTPOINTS "$PARENT_DEV"
echo
read -r -p "Type FLASH $PI_BOOT_DEV to continue: " CONFIRMATION
[[ "$CONFIRMATION" == "FLASH $PI_BOOT_DEV" ]] || die "confirmation did not match"

MOUNT_POINT="$(findmnt -nr -S "$PI_BOOT_DEV" -o TARGET | head -n 1 || true)"
if [[ -z "$MOUNT_POINT" ]]; then
    udisksctl mount -b "$PI_BOOT_DEV" >/dev/null
    MOUNT_POINT="$(findmnt -nr -S "$PI_BOOT_DEV" -o TARGET | head -n 1 || true)"
fi
[[ -n "$MOUNT_POINT" ]] || die "could not mount $PI_BOOT_DEV"

for required_file in config.txt start4.elf fixup4.dat bcm2712-rpi-5-b.dtb; do
    [[ -f "$MOUNT_POINT/$required_file" ]] ||
        die "$MOUNT_POINT is missing $required_file; this does not look like the Pi 5 boot partition"
done

BACKUP_DIR="$IMAGE_DIR/flash-backups"
BACKUP_STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$BACKUP_DIR"
if [[ -f "$MOUNT_POINT/kernel8.img" ]]; then
    cp "$MOUNT_POINT/kernel8.img" "$BACKUP_DIR/kernel8-before-$BACKUP_STAMP.img"
    sha256sum "$BACKUP_DIR/kernel8-before-$BACKUP_STAMP.img" \
        >"$BACKUP_DIR/kernel8-before-$BACKUP_STAMP.img.sha256"
fi

echo "Flashing diagnostic kernel..."
cp "$IMAGE_DIR/kernel8.img" "$MOUNT_POINT/kernel8.img"
cp "$IMAGE_DIR/rpi5-artifacts.sha256" "$MOUNT_POINT/axiomos-rpi5-artifacts.sha256"
sync

FLASHED_SHA256="$(sha256sum "$MOUNT_POINT/kernel8.img" | awk '{print $1}')"
[[ "$FLASHED_SHA256" == "$EXPECTED_KERNEL_SHA256" ]] ||
    die "flashed kernel verification failed"

udisksctl unmount -b "$PI_BOOT_DEV" >/dev/null
MOUNT_POINT=""

echo
echo "FLASH_OK kernel8.img sha256=$FLASHED_SHA256"
echo "The Pi boot partition is unmounted and safe to remove."
