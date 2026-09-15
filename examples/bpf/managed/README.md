# Managed controller examples

These examples consume the managed runtime's frozen sensor snapshot and make
one capture-only `ManagedMotorPairV1` request. The sensor value is the raw sonar
echo duration received from Shrike, in microseconds. It is not a calibrated
distance.

- `conservative_obstacle.c` stops below 1400 us and otherwise requests a 250
  per-mille cruise.
- `slow_approach.c` stops through 600 us, requests 100 per-mille through 1399
  us, and otherwise requests 300 per-mille.
- `clear_streak.c` uses private array handle 1 and waits for three consecutive
  samples of at least 1400 us before requesting 180 per-mille. Invalid or nearer
  samples reset its streak.

Every example requests `(0, 0)` for an invalid sensor flag or a nonpositive
echo. The constants are compile-time demonstration knobs pending final sensor
and chassis calibration. These examples have no physical safety qualification.
The kernel still applies its trusted actuation monitor after capture.

Build little-endian raw instruction streams with Clang and native LLVM objcopy:

```sh
examples/bpf/managed/build.sh
```

The default output is `target/managed-bpf/`. Create signed managed bundles with
an external PKCS#8 private key and the `rk bundle` command:

```sh
rk bundle --input target/managed-bpf/conservative_obstacle.bin \
  --output target/managed-bpf/conservative_obstacle.axmb \
  --key /path/to/signing-key.pk8 \
  --behavior-id 00000000000000000000000000000001 --revision 1 --motor-pair

rk bundle --input target/managed-bpf/slow_approach.bin \
  --output target/managed-bpf/slow_approach.axmb \
  --key /path/to/signing-key.pk8 \
  --behavior-id 00000000000000000000000000000002 --revision 1 --motor-pair

rk bundle --input target/managed-bpf/clear_streak.bin \
  --output target/managed-bpf/clear_streak.axmb \
  --key /path/to/signing-key.pk8 \
  --behavior-id 00000000000000000000000000000003 --revision 1 --motor-pair \
  --array-value-size 4 --array-entries 1
```

Keep private keys outside the source tree. Generated `.bin`, `.o`, and `.axmb`
files are build artifacts and are not included in the boot image.
