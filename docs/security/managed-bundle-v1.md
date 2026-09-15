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

## Managed verification and invocation

`ManagedContract` retains the binding declarations and the intersection of the
signed, signer-policy and control-slot effect ceilings. Bounded verification
returns a `ManagedProgram`; ordinary hook and JIT APIs cannot accept this type.
Authentication, timing admission and installation remain separate steps.

Only map lookup, private-array update and `ManagedMotorPairV1` (1009) are
permitted. Map handles must be proven constants: exactly 0 or 1 with local
generation zero. The existing envelope entry size and read-only permission are
used for handle 0; handle 1 uses the declared array value size. Both maps use
four-byte keys. Undeclared/global/stale handles, unsupported instruction modes,
pseudo bindings, non-normalized calls, malformed wide immediates and loops reject.
Key/update-value buffers must fit their exact declared extent and contain
initialized scalar bytes. Nullable map values require refinement. Managed
pointer spills and pointer-to-scalar conversion reject because the existing
stack model cannot restore typed pointer spills.

Helper 1009 takes two canonical sign-extended 64-bit signed per-mille values,
each in [-1000, 1000]. Success records one invocation-local request. A second or
malformed request aborts the invocation even if bytecode ignores the helper
result. Execution and map failures return no captured request. Successful
completion preserves `None` versus an explicit `(0, 0)` request for audit;
`motor_pair()` maps `None` to the defined zero result. The interpreter does not
submit wheel commands. Legacy `MotorPairV1` retains its separate semantics.

The managed payload uses the existing context wrapper and a new sealed,
padding-free `ManagedControlContextV1`: version/size (u32), cycle ID,
scheduled/actual/sensor nanoseconds (u64), sensor value (i64), validity/reserved
(u32). It is 56 bytes; version is 1, size is 56, validity is 0 or 1, reserved is
zero. Existing IIO/context layouts are unchanged. The managed sensor producer
and timestamp provenance remain integration work. The current Pi adapter emits
raw sonar echo microseconds; selecting and documenting the managed source is
required before its reference image is qualified.

`BehaviorArtifact::prepare` decodes and verifies the same authenticated payload
under a `VerificationBudget`. It retains identity, binding contract, code and
scalar verifier results; temporary decode and handle buffers are released.
The trusted worker supplies signer and slot policy. The returned code capacity
remains charged to the budget. When passing an artifact to
`BpfManager::register_managed_artifact`, the caller saves `code_bytes()` and
releases that originating output charge after every return, including duplicate
or rejected registration. Insertion transfers ownership and accounting to the
existing manager; other outcomes drop the supplied artifact.

The manager retains at most three artifacts and two instances using the existing
generational tables and explicit `KernelManaged` ownership. Before execution,
`prepare_managed_storage` fallibly preallocates and charges those tables.
`begin_managed_instance` reserves the instance position, private map slot and
allocation charges. Its single-use preparation object builds zeroed ARRAY state
outside `BPF_MANAGER` with IRQs enabled; `finish_managed_instance` registers it
or refunds a failed/cancelled build. The worker must always finish its accepted
preparation, including cancellation. Dropping the permit alone leaves its
bounded reservation busy.

`BehaviorInstance::execute` uses the existing interpreter, CPU stack and map
leases with exactly the retained local sizes, permissions and generations.
Fresh instances share immutable code but no private state. Ordinary hooks and
legacy map APIs cannot access these managed objects. Worker reclamation requires
exclusive ownership, including absence of weak references that would retain an
allocation header. Code, array capacity, boxes, reference-count headers and
registry capacity stay charged until release. Layout charges match the pinned
Rust toolchain and `linked_list_allocator` implementation; the real allocator
fixture checks Box/Arc charges and final release under Miri.

The asynchronous worker, global upload/verifier-workspace reservation and timing
admission remain integration work. Kernel dispatch must also discard captured
requests on later deadline/policy/queue failure. No installation generation,
timer slot, retirement batch, publication, UART handoff or physical qualification
is established by these tests. Helper costs remain uncalibrated model values.

See [managed verification](../../kernel/crates/kernel_bpf/src/verifier/managed.rs)
and [managed execution](../../kernel/crates/kernel_bpf/src/execution/interpreter.rs),
plus [kernel ownership and bindings](../../kernel/src/bpf/managed.rs).
