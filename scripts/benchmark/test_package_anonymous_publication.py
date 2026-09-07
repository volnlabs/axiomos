#!/usr/bin/env python3
"""Small deterministic-packaging check."""

import hashlib
import importlib.util
import json
import os
import sys
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
    environment = json.loads(packager.recorded_environment(repo))
    assert packager.ARTIFACT == "artifact-r2"
    assert environment["processor"]["model"] == "AMD Ryzen 7 7735HS with Radeon Graphics"
    assert environment["processor"]["selected_affinity"] == {"dispatch": 12, "update": 14}
    assert environment["processor"]["boost_enabled"] is True
    assert environment["compiler"] == {
        "cargo_release": "1.98.0-nightly",
        "compiler_date": "2026-07-01",
        "llvm_version": "22.1.8",
        "rustc_release": "1.98.0-nightly",
        "target": "x86_64-unknown-linux-gnu",
    }
    assert environment["captured_build"]["profile"] == "release"
    assert environment["captured_build"]["tests"] == [
        "publication_campaign", "publication_measurements"]
    validation = packager.retained_validation_log(repo)
    assert "running 1 test" in validation
    assert "test result: ok. 1 passed; 0 failed" in validation
    packager.scan_text("recorded environment", json.dumps(environment))
    packager.scan_text("retained validation", validation)
    assert '"--raw-cost"' in packager.REPRODUCE
    if "--helpers-only" in sys.argv:
        print("PASS: r2 environment and validation exports are identity-clean")
        return
    target = Path(os.environ["CARGO_TARGET_DIR"]) / "anonymous-publication-r2-check"
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
