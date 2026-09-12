#!/usr/bin/env python3
"""Exercise Cargo caching of the real kernel rootfs build script in a host fixture.

Checks external A -> external B -> unset -> unset clean rebuild. The fixture
uses cargo check (no kernel linking); it does not qualify full image determinism.
"""
import os
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def main():
    with tempfile.TemporaryDirectory(prefix="axiomos-rootfs-") as directory:
        fixture = Path(directory)
        (fixture / "Cargo.toml").write_text(
            '[package]\nname="rootfs-selection-probe"\nversion="0.0.0"\n'
            'edition="2021"\n[lib]\npath="lib.rs"\n'
            '[build-dependencies]\ncc="1"\n[workspace]\n')
        (fixture / "lib.rs").write_text("// Build-script-only fixture.\n")
        # Keep Cargo's normal cached build-script execution, while exercising
        # the real Pi rootfs branch without compiling/linking the whole kernel.
        (fixture / "build.rs").write_text(
            'mod production { include!(' + json.dumps(str(ROOT / "kernel/build.rs")) + ');\n'
            'pub fn run() { main(); } }\n'
            'fn main() {\n'
            'std::env::set_var("CARGO_CFG_TARGET_OS", "none");\n'
            'std::env::set_var("CARGO_CFG_TARGET_ARCH", "x86_64");\n'
            'std::env::set_var("CARGO_FEATURE_RPI5", "1");\n'
            'std::env::set_var("CARGO_MANIFEST_DIR", ' + json.dumps(str(ROOT / "kernel")) + ');\n'
            'production::run();\n}\n')
        a, b = fixture / "a.img", fixture / "b.img"
        a.write_bytes(b"first external rootfs")
        b.write_bytes(b"second external rootfs")

        def build(image, target):
            env = os.environ.copy()
            env["CARGO_TARGET_DIR"] = str(target)
            env.pop("AXIOM_DISK_IMAGE", None)
            if image is not None:
                env["AXIOM_DISK_IMAGE"] = str(image)
            result = subprocess.run([
                "cargo", "check", "--offline", "--quiet", "--manifest-path",
                str(fixture / "Cargo.toml"),
            ], env=env, capture_output=True, text=True)
            if result.returncode:
                raise SystemExit(result.stdout + result.stderr)
            images = list(target.glob("debug/build/rootfs-selection-probe-*/out/disk.img"))
            assert len(images) == 1, images
            return images[0].read_bytes()

        target = fixture / "target"
        assert build(a, target) == a.read_bytes()
        assert build(b, target) == b.read_bytes(), "Cargo reused rootfs A after selecting B"
        fallback = build(None, target)
        assert fallback != b.read_bytes(), "Cargo reused external rootfs after unsetting selection"
        assert fallback == build(None, fixture / "target-clean"), "fallback clean rebuild differs"
        print("PASS: rootfs A -> B -> unset and clean fallback rebuild")


if __name__ == "__main__":
    main()
