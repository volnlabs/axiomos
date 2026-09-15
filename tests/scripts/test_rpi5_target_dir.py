#!/usr/bin/env python3
"""An overridden Cargo target must supply the deployed image and provenance."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory() as directory:
    target = Path(directory) / 'custom target'
    bin_dir = Path(directory) / 'bin'
    bin_dir.mkdir()
    mocks = {
        'rustup': 'print("aarch64-unknown-none (installed)")',
        'cargo': """import os, sys, json
from pathlib import Path
target = Path(os.environ['CARGO_TARGET_DIR'])
with (target / 'cargo-calls.jsonl').open('a') as log:
    log.write(json.dumps(sys.argv[1:]) + '\\n')
build = target / 'aarch64-unknown-none/release'
build.mkdir(parents=True, exist_ok=True)
(build / 'kernel').write_bytes(b'custom-target-image')
disk = target / 'disk.img'
disk.write_bytes(b'exact-rootfs')
Path(os.environ['AXIOM_ARTIFACT_PATHS']).write_text(f'DISK_IMAGE={disk}\\n')
""",
        'llvm-objcopy': 'import shutil, sys; shutil.copyfile(sys.argv[-2], sys.argv[-1])',
    }
    for name, code in mocks.items():
        path = bin_dir / name
        path.write_text('#!/usr/bin/env python3\n' + code)
        path.chmod(0o755)
    key = Path(directory) / 'key.pub'
    key.write_bytes(bytes(32))
    environment = {**os.environ, 'CARGO_TARGET_DIR': str(target),
                   'AXIOM_BPF_TRUSTED_KEY_PATH': str(key),
                   'PATH': str(bin_dir) + os.pathsep + os.environ['PATH']}
    subprocess.run(['bash', str(ROOT / 'scripts/build/rpi5.sh')],
                   env=environment, check=True, stdout=subprocess.DEVNULL)
    build = target / 'aarch64-unknown-none/release'
    image = build / 'kernel8.img'
    manifest = build / 'rpi5-artifacts.sha256'
    assert image.read_bytes() == b'custom-target-image'
    assert str(build / 'kernel') in manifest.read_text()
    boot = Path(directory) / 'boot'
    boot.mkdir()
    (boot / 'config.txt').write_text('preserve me\n')
    subprocess.run(['bash', str(ROOT / 'scripts/deploy/rpi5.sh'), str(boot)],
                   env={**os.environ, 'CARGO_TARGET_DIR': str(target)},
                   check=True, stdout=subprocess.DEVNULL)
    assert (boot / 'kernel8.img').read_bytes() == image.read_bytes()
    assert (boot / 'axiomos-rpi5-artifacts.sha256').read_bytes() == manifest.read_bytes()
    assert (boot / 'config.txt').read_text() == 'preserve me\n'
    (target / 'cargo-calls.jsonl').write_text('')
    subprocess.run(['bash', str(ROOT / 'scripts/build/rpi5.sh'), 'release',
                    'embedded-rpi5,managed-runtime'], env=environment,
                   check=True, stdout=subprocess.DEVNULL)
    calls = [json.loads(line) for line in (target / 'cargo-calls.jsonl').read_text().splitlines()]
    image_call = next(call for call in calls if 'axiomos' in call)
    features = image_call[image_call.index('--features') + 1].split(',')
    assert 'managed-runtime-aarch64' in features, 'managed kernel requires the managed installer in its rootfs'
print('PASS: custom Cargo target deployment and preserved config')
