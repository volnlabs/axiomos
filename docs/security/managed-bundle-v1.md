# Managed controller bundle v1

This is the binary input contract for the v0.5 preparation worker. Authentication
does not admit, publish or execute a controller. The worker must independently
verify normalized instructions against the exact local bindings and managed
helper policy, enforce fallible memory budgets, and perform timing admission.
The legacy `RBPF` container is unchanged and cannot substitute for this format.

All integers are unsigned little-endian. The format is exactly a 224-byte header
followed by `instruction_count * 8` bytes of little-endian BPF instructions.
The complete bundle is at most 256 KiB. Empty payloads, truncated input, trailing
bytes, unknown versions/features and nonzero reserved bytes reject. No native
struct layout or pointer alignment is assumed.

| Byte offset | Length | Field |
|---|---|---|
| 0 | 4 | Magic `AXMB` |
| 4 | 2 | Bundle version, exactly 1 |
| 6 | 2 | Header length, exactly 224 |
| 8 | 4 | Complete bundle length |
| 12 | 4 | Instruction slot count, including wide-immediate continuation slots |
| 16 | 16 | Opaque logical behavior ID |
| 32 | 8 | Signer-provided revision |
| 40 | 2 | Managed control slot, exactly 0 |
| 42 | 2 | Managed context version, exactly 1 |
| 44 | 2 | Managed helper contract version, exactly 1 |
| 46 | 2 | Binding flags: bit 0 declares read-only envelope at local handle 0 |
| 48 | 4 | Requested effect ceiling: bit 0 permits requesting a wheel pair |
| 52 | 4 | Private ARRAY value size in bytes |
| 56 | 4 | Private ARRAY maximum entries |
| 60 | 4 | Reserved zero |
| 64 | 32 | SHA3-256 of all executable payload bytes |
| 96 | 32 | Full Ed25519 signer public key |
| 128 | 32 | Reserved zero |
| 160 | 64 | Ed25519 signature |
| 224 | variable | Executable payload |

Both ARRAY fields zero means no private state. Otherwise both must be nonzero
and their checked product must be at most 16 KiB. The key size is fixed at four
bytes, the binding is local handle 1, and each instance receives newly zeroed
storage. There is no initializer, external map reference, pinning or shared-map
encoding. Other flags and effects reject. A zero effect ceiling grants no wheel
pair request authority. Declarations remain requests constrained by kernel
trust policy and the fixed control slot; a signature grants no direct actuation.

The signing message is the 32-byte SHA3-256 digest of:

```text
ASCII("axiomos managed bundle v1") || 0x00 || header[0..160]
```

The manifest's payload digest binds the entire executable payload. This nested
hash composition permits the existing strict Ed25519 verifier and SHA3-256
implementation to authenticate without a payload-sized temporary allocation.
It is ordinary Ed25519 over the digest above, not Ed25519ph. A signature over
only the executable digest (as used by legacy signing) is not accepted.

Trust selection compares all 32 public-key bytes with a provisioned key. The
retained signer fingerprint is SHA3-256 of those bytes. The artifact retains
both SHA3-256 of the complete signed bundle (including signature) and SHA3-256
of its executable payload, plus the manifest and full signer identity. Runtime
installation generations are kernel-issued and never encoded here; activating
the same bundle again must produce a new installation generation.

The parser borrows immutable upload bytes, performs fixed-size field copies and
hashing, and allocates no storage. Its instruction iterator only decodes bytes;
authentication of arbitrary instruction bytes does not prove that they are
normalized, safe or within a profile's executable budget. Those checks belong
to worker preparation before artifact registration. Cryptography and payload
hashing likewise run in the worker, never in a bounded upload syscall or timer.

The implementation and executable negative cases are in
[managed.rs](../../kernel/crates/kernel_bpf/src/signing/managed.rs).
