#!/bin/bash
# Build the axiomos kernel for Raspberry Pi 5
#
# This script builds the kernel for the aarch64-unknown-none target
# with the rpi5 feature enabled, then creates a raw binary suitable
# for the Pi 5 bootloader.
#
# The disk image (ext2 rootfs with userspace binaries) is embedded
# directly into the kernel binary via include_bytes!().
#
# Usage: cargo xtask build rpi5 -- [release|debug] [kernel_features]
# Example: cargo xtask build rpi5 -- release embedded-rpi5,bench

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
TARGET="aarch64-unknown-none"
PROFILE="${1:-release}"
FEATURES="${2:-embedded-rpi5}"

echo "=== Building axiomos for Raspberry Pi 5 ==="
echo "Profile: $PROFILE"
echo "Kernel features: $FEATURES"
echo ""

cd "$PROJECT_DIR"

if [ -z "${AXIOM_BPF_TRUSTED_KEY_PATH:-}" ] || [ ! -f "$AXIOM_BPF_TRUSTED_KEY_PATH" ]; then
    echo "Error: AXIOM_BPF_TRUSTED_KEY_PATH must name the 32-byte production Ed25519 public key."
    echo "The key is compiled into the kernel; this script will not generate a substitute."
    exit 1
fi
if [ "$(wc -c < "$AXIOM_BPF_TRUSTED_KEY_PATH")" -ne 32 ]; then
    echo "Error: AXIOM_BPF_TRUSTED_KEY_PATH must contain exactly 32 bytes."
    exit 1
fi
AXIOM_BPF_TRUSTED_KEY_PATH=$(realpath "$AXIOM_BPF_TRUSTED_KEY_PATH")
export AXIOM_BPF_TRUSTED_KEY_PATH

# Ensure target is installed
if ! rustup target list | grep -q "$TARGET (installed)"; then
    echo "Installing $TARGET target..."
    rustup target add "$TARGET"
fi

# Step 1: Build disk image with userspace binaries
echo "Building userspace binaries and disk image..."
ARTIFACT_PATHS=$(mktemp "$PROJECT_DIR/target/rpi5-artifacts.XXXXXX")
trap 'rm -f "$ARTIFACT_PATHS"' EXIT
export AXIOM_ARTIFACT_PATHS="$ARTIFACT_PATHS"

# Run image assembly at the requested profile with a unique artifact-manifest
# path. The environment value makes build.rs emit the paths from this exact
# invocation; no timestamp or stale target-directory search is involved.
ROOT_BUILD_ARGS=(build -p axiomos --target "$TARGET" --no-default-features --features aarch64_deps)
if [ "$PROFILE" = "release" ]; then
    ROOT_BUILD_ARGS+=(--release)
fi
cargo "${ROOT_BUILD_ARGS[@]}"

DISK_PATH=$(sed -n 's/^DISK_IMAGE=//p' "$ARTIFACT_PATHS")
if [ -z "$DISK_PATH" ] || [ ! -f "$DISK_PATH" ]; then
    echo "Error: build did not report a valid DISK_IMAGE in $ARTIFACT_PATHS"
    exit 1
fi
echo "Using disk image: $DISK_PATH ($(stat -c%s "$DISK_PATH" 2>/dev/null || stat -f%z "$DISK_PATH") bytes)"

# Step 2: Build the kernel with embedded disk image
export AXIOM_DISK_IMAGE="$DISK_PATH"
echo "Building kernel (AXIOM_DISK_IMAGE=$AXIOM_DISK_IMAGE)..."
if [ "$PROFILE" = "release" ]; then
    cargo build --target "$TARGET" --features "$FEATURES" --release -p kernel
    BUILD_DIR="target/$TARGET/release"
else
    cargo build --target "$TARGET" --features "$FEATURES" -p kernel
    BUILD_DIR="target/$TARGET/debug"
fi

# Check if llvm-objcopy is available
if command -v llvm-objcopy &> /dev/null; then
    OBJCOPY="llvm-objcopy"
elif command -v rust-objcopy &> /dev/null; then
    OBJCOPY="rust-objcopy"
else
    echo "Error: Neither llvm-objcopy nor rust-objcopy found."
    echo "Install with: cargo install cargo-binutils && rustup component add llvm-tools-preview"
    exit 1
fi

# Create raw binary
echo "Creating kernel8.img..."
$OBJCOPY -O binary "$BUILD_DIR/kernel" "$BUILD_DIR/kernel8.img"

# Retain hashes for the exact ELF, raw kernel, and rootfs used by this build.
# The artifact recipe is generated from ci/manifests/artifacts.toml.
PROVENANCE_MANIFEST="$BUILD_DIR/rpi5-artifacts.sha256"
sha256sum "$BUILD_DIR/kernel" "$BUILD_DIR/kernel8.img" "$DISK_PATH" \
    "$AXIOM_BPF_TRUSTED_KEY_PATH" \
    > "$PROVENANCE_MANIFEST"

# Report results
SIZE=$(stat -c%s "$BUILD_DIR/kernel8.img" 2>/dev/null || stat -f%z "$BUILD_DIR/kernel8.img")
echo ""
echo "=== Build Complete ==="
echo "Kernel ELF: $BUILD_DIR/kernel"
echo "Kernel Binary: $BUILD_DIR/kernel8.img"
echo "Provenance: $PROVENANCE_MANIFEST"
echo "Size: $SIZE bytes"
echo ""
echo "To deploy to SD card, run:"
echo "  cargo xtask deploy rpi5 -- /path/to/sdcard/boot"
