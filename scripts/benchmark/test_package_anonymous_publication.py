#!/usr/bin/env python3
"""Small deterministic-packaging check."""

import hashlib
import importlib.util
import tempfile
from pathlib import Path


SCRIPT = Path(__file__).with_name("package-anonymous-publication.py")
spec = importlib.util.spec_from_file_location("anonymous_packager", SCRIPT)
packager = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(packager)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    repo = SCRIPT.resolve().parents[2]
    target = Path(__import__("os").environ["CARGO_TARGET_DIR"]) / "anonymous-publication-check"
    target.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=target) as first, tempfile.TemporaryDirectory(dir=target) as second:
        a = packager.build(repo, Path(first))
        b = packager.build(repo, Path(second))
        assert a[0].joinpath("MANIFEST.sha256").read_bytes() == b[0].joinpath("MANIFEST.sha256").read_bytes()
        assert digest(a[1]) == digest(b[1])
        packager.scan_tree(a[0])
        packager.scan_zip(a[1])
    print("PASS: anonymous artifact is reproducible and identity-clean")


if __name__ == "__main__":
    main()
