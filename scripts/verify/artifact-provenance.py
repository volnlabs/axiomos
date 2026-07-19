#!/usr/bin/env python3
"""Enforce exact artifact selection and retained provenance recipes."""

from pathlib import Path
import tomllib


ROOT = Path(__file__).resolve().parents[2]


def source(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def main() -> None:
    manifest = tomllib.loads(source("ci/manifests/artifacts.toml"))
    artifacts = manifest.get("artifact", [])
    if not artifacts:
        raise SystemExit("ci/manifests/artifacts.toml contains no artifact recipes")

    names = [artifact["name"] for artifact in artifacts]
    if len(names) != len(set(names)):
        raise SystemExit("ci/manifests/artifacts.toml contains duplicate artifact names")
    for artifact in artifacts:
        missing = {
            "platform",
            "status",
            "format",
            "producer",
            "output",
            "selection",
            "immutable_inputs",
            "hash_evidence",
        } - artifact.keys()
        if missing:
            raise SystemExit(f"{artifact['name']} is missing fields: {sorted(missing)}")
        if "SHA-256" not in artifact["hash_evidence"]:
            raise SystemExit(f"{artifact['name']} has no SHA-256 evidence contract")

    run_virt_path = "scripts/run/virt.sh"
    run_virt = source(run_virt_path)
    for forbidden in ("%T@", "sort -n", "tail -n", "most recently modified"):
        if forbidden in run_virt:
            raise SystemExit(f"{run_virt_path} retains time-based selection: {forbidden}")
    for required in (
        "AXIOM_ARTIFACT_PATHS",
        "AXIOM_BPF_TRUSTED_KEY_PATH",
        "s/^DISK_IMAGE=//p",
        'file="$DISK_PATH"',
        "sha256sum",
    ):
        if required not in run_virt:
            raise SystemExit(f"{run_virt_path} is missing exact selection token: {required}")

    build_rpi5_path = "scripts/build/rpi5.sh"
    build_rpi5 = source(build_rpi5_path)
    for required in (
        "AXIOM_ARTIFACT_PATHS",
        "AXIOM_BPF_TRUSTED_KEY_PATH",
        'ROOT_BUILD_ARGS+=(--release)',
        "rpi5-artifacts.sha256",
        'sha256sum "$BUILD_DIR/kernel" "$BUILD_DIR/kernel8.img" "$DISK_PATH"',
    ):
        if required not in build_rpi5:
            raise SystemExit(f"{build_rpi5_path} is missing provenance token: {required}")

    deploy_rpi5_path = "scripts/deploy/rpi5.sh"
    deploy_rpi5 = source(deploy_rpi5_path)
    for required in (
        "rpi5-artifacts.sha256",
        "sha256sum -c",
        "axiomos-rpi5-artifacts.sha256",
    ):
        if required not in deploy_rpi5:
            raise SystemExit(f"{deploy_rpi5_path} is missing provenance token: {required}")

    generated = source("docs/reference/generated/artifacts.md")
    for name in names:
        if f"| {name} |" not in generated:
            raise SystemExit(f"generated artifact table is missing {name}")

    print(f"artifact provenance clean: {len(artifacts)} image recipes")


if __name__ == "__main__":
    main()
