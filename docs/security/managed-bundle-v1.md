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

## Host authoring and authentication

`rk bundle` signs a raw, nonempty stream of little-endian 8-byte instruction
slots using an external Ed25519 PKCS#8 key. Supply `--behavior-id` as exactly
32 hexadecimal characters, `--revision`, and explicit `--motor-pair` and/or
`--envelope` declarations when needed. Private state requires both
`--array-value-size` and `--array-entries`; their checked product cannot exceed
16 KiB. Unsupported declarations, ELF input and payloads exceeding the complete
256 KiB bundle limit reject. The output must be a new file, preventing an
existing bundle or signing key from being overwritten.

The command reuses the kernel's canonical manifest builder and signing hash.
`rk verify --input controller.axmb --key /path/to/signer.pub` reuses its managed
authenticator and reports the full signed identity. Directory trust selection
also matches the full public key; a legacy eight-byte prefix match is
insufficient. Both commands keep authentication separate from bytecode
verification and live admission. Legacy `rk sign` and `RBPF` verification remain
available for legacy callers.

The [C examples](../../examples/bpf/managed/README.md) include build and signing
commands. Their host tests compile the actual sources and use the existing
artifact verifier, manager, instance factory and interpreter to check their
requests and fresh private state. These are software fixtures; their sonar
thresholds and requested speeds remain unqualified calibration values.

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
zero. Existing IIO/context layouts are unchanged. The managed Pi adapter copies
raw sonar echo microseconds at completion of a CRC-validated Sensor frame. Its
timestamp is Pi receive time from CNTPCT, converted with the same checked
frequency as scheduled/actual releases; it is not MCU acquisition time. Zero
echo, unsupported flags, asserted e-stop, missing/future samples and samples at
least 80 ms old are invalid. The 80 ms receive-age ceiling reuses the link timeout
and remains provisional pending adapter calibration. Signed controllers receive
validity explicitly; a valid receive timestamp does not establish physical
measurement accuracy. Link faults invalidate the mailbox and inhibit control.

`BehaviorArtifact::prepare` decodes and verifies the same authenticated payload
under a `VerificationBudget`. It retains identity, binding contract, code and
scalar verifier results; temporary decode and handle buffers are released.
The trusted worker supplies signer and slot policy. The returned code capacity
remains charged to the budget through `output_charge()`. The worker transfers
that charge to its already-held global workspace reservation after fallible Arc
construction. It retains a second Arc through `register_managed_shared`, so
duplicate or rejected code is released outside the manager lock. Insertion
transfers the retained code/wrapper charge from workspace to the existing table.
The by-value registration convenience exists only in tests; those callers release
the originating output charge after every return, including rejection.

The manager retains at most three artifacts and two instances using the existing
generational tables and explicit `KernelManaged` ownership. Before execution,
`prepare_managed_storage` fallibly preallocates and charges those tables.
`begin_managed_instance` reserves the instance position, private map slot and
allocation charges. Its single-use preparation object builds zeroed ARRAY state
outside `BPF_MANAGER` with IRQs enabled; `finish_managed_instance` registers it
or refunds a failed/cancelled build whose storage is already released. A
completed instance rejected at registration is returned in an owned error; the
worker releases it outside the lock, then consumes its receipt to refund the
reservation. The worker must always finish accepted preparation, including
cancellation. Dropping the permit or a receipt leaves bounded capacity busy.

`BehaviorInstance::execute` uses the existing interpreter, CPU stack and map
leases with exactly the retained local sizes, permissions and generations.
Fresh instances share immutable code but no private state. Ordinary hooks and
legacy map APIs cannot access these managed objects. Worker reclamation requires
exclusive ownership, including absence of weak references that would retain an
allocation header. Code, array capacity, boxes, reference-count headers and
registry capacity stay charged until release. Layout charges match the pinned
Rust toolchain and `linked_list_allocator` implementation; the real allocator
fixture checks Box/Arc charges and final release under Miri.

The reclamation API extracts one instance/private-map pair or one artifact from
the existing tables without releasing its charges or capacity. The worker drops
that owned object outside the manager lock, then consumes an opaque receipt to
refund the exact reservation. Pending reclamation prevents program/map slot
reuse and new preparation; accepted preparation likewise prevents reclamation
from disrupting its reserved resources. Private-map reclamation temporarily
removes the instance's redundant reference while the table retains ownership,
then uses atomic Arc uniqueness to exclude both strong and weak readers. A busy
reader or lease restores the original binding and leaves charges unchanged.
The kernel-private installation slot uses one retirement batch for both displaced
state and evicted previous code. Worker cleanup extracts those exact objects,
drops them outside locks, refunds their charges and consumes a final receipt
before reusing capacity. Rollback retains the artifact that has become active;
its new instance starts zeroed. The permanent worker dispatch and CPU0 slot
synchronization are connected; physical publication eligibility remains open.

The asynchronous worker and global upload/verifier-workspace reservation are
implemented below. The private slot reserves the retained artifact's verified
model cost at 100 Hz through the existing utilization ledger. It holds the larger
of active and prepared costs alongside legacy contributions; the installation's
active charge changes at publication and its opaque ticket settles only after
worker cleanup. Rejection and cancellation preserve the old charge. Kernel dispatch
discards captured requests on invocation or pre-enqueue deadline failure and
inhibits control on policy/queue failure. A later failure preserves any actual
queue outcome and invokes trusted stop. The internal installation
boundary tests cover fresh generations, ownership moves, cancellation, stop and
100,000 transitions with bounded retained resources. Public activation/rollback
now require BEHAVIOR_ADMIN and use this same worker and the correlated UART
handoff boundary. Physical session drain/rearm remains closed pending adapter
integration; live hardware activation is not qualified. Absolute timer scheduling
is connected. Helper costs remain uncalibrated model values.

See [managed verification](../../kernel/crates/kernel_bpf/src/verifier/managed.rs)
and [managed execution](../../kernel/crates/kernel_bpf/src/execution/interpreter.rs),
plus [kernel ownership and bindings](../../kernel/src/bpf/managed.rs) and
[installation ownership](../../kernel/src/bpf/installation.rs).

## Bounded upload and preparation administration

The `managed-runtime` kernel feature preallocates one 256 KiB upload buffer and
starts one permanent root-process worker using the existing task and wait queue.
It is opt-in; the root build forwards `managed-runtime` for x86 and
`managed-runtime-aarch64` for AArch64. Direct Pi 5 kernel builds use
`embedded-rpi5,managed-runtime`. Physical actuation remains disabled.

The upload backing stays charged against the existing program-byte limit even
when idle. Finalize reserves another 512 KiB for verification and the artifact
wrapper before accepting kernel ownership. Buffers use the pinned allocator's
16-byte minimum and 8-byte size quantum, including old and replacement buffers
during growth. The retained code's raw capacity and originating budget charge
are separate values. Registration transfers retained code/wrapper charges to the
existing table; the remaining reservation is refunded only after rejected or
duplicate code references have actually been dropped by the worker. Four fixed
terminal receipts retain scalar status and identity without retaining artifacts.

Bulk authentication, verification and allocation run outside `BPF_MANAGER` with
IRQs enabled. Allocator lock access masks local IRQs and restores their entry
state, preventing a same-CPU context switch while that lock is held. Buffer
zeroing/copying and verifier work are outside that scope. This does not establish
a timing bound for the linked-list allocator's fragmentation-dependent traversal;
the qualified workload still needs IRQ-off and deadline measurements.

Eleven commands use independently versioned, padding-free native ABI structures
through `SYS_BPF`, dispatched before the legacy `BpfAttr` size check. All require
`BEHAVIOR_ADMIN`, exact version 1 and structure length, and zero reserved fields.
Ordinary init children have no administration capability. The
[dedicated installer](runtime-installer-v1.md) provides bounded debug-UART
transport and receives only administration authority in the managed image.

| Command | Number | Structure / bytes | Result |
|---|---|---|---|
| Upload begin | 256 | `ManagedUploadBeginV1` / 24 | New upload/operation ID |
| Upload chunk | 257 | `ManagedUploadChunkV1` / 288 | Total bytes received |
| Upload finalize | 258 | `ManagedOperationRequestV1` / 24 | Accepted operation ID |
| Operation query | 259 | `ManagedOperationV1` / 200 | Fixed status written to the same address |
| Cancel upload | 260 | `ManagedOperationRequestV1` / 24 | Upload cancellation requested |
| Activate | 261 | `ManagedInstallationRequestV1` / 32 | Accepted operation ID |
| Rollback | 262 | `ManagedInstallationRequestV1` / 32 | Accepted operation ID |
| Slot query | 263 | `ManagedSlotV1` / 64 | Consistent slot/candidate/operation status |
| Cancel installation | 264 | `ManagedInstallationCancelV1` / 40 | Lifecycle cancellation requested |
| Deactivate | 265 | `ManagedInstallationRequestV1` / 32 | Accepted operation ID |
| Retire inactive artifact | 266 | `ManagedInstallationRequestV1` / 32 | Accepted operation ID |

Activate and rollback compare both the last issued operation ID and current
installation generation. Their artifact handle must exactly identify the resident
candidate or retained previous artifact, respectively. Both prepare fresh private
state through the existing worker; neither grants physical rearm or bypasses
SafeAck. Query the original/latest operation after a lost response; repeating
an accepted activation with its old expected ID returns `ESTALE`.

Deactivate supplies the same expected last operation ID and slot generation,
with the exact active artifact handle. It prepares no instance, reserves a zero
replacement admission charge, and follows the same SafeBarrier/SafeAck boundary.
Commit advances the slot generation, removes the active instance and keeps the
slot inhibited. The active artifact becomes previous; the displaced previous
artifact is evicted unless the candidate still retains it. Activation from an
empty slot preserves its previous artifact, allowing an explicit later rollback.
The worker releases old state and any evicted artifact before settling admission;
held readers keep the operation and its charges busy. Cancellation also settles
its reservation through the worker, even though no new instance was built.
Failure before commitment preserves active/previous identity and admission; once
handoff has started, the old installation remains stopped. Shared wheel ownership
is released only by a committed empty-slot boundary, without an e-stop release or
automatic resumption. Deactivation consumes a generation even though it creates
no installation, so stale requests cannot match a later activation.
Activation, rollback and deactivation require space for two cleanup IDs before
acceptance: one displaced instance and one evicted artifact. Counter exhaustion
returns `EOVERFLOW` before changing the slot, IDs or reservations. The accepted
operation excludes unrelated reclamation until its batch finishes.

Retire supplies the same expected last operation ID and slot generation with an
exact inactive artifact handle. It removes all candidate/previous aliases of
that artifact; any active alias returns `EBUSY`, and an absent inactive handle
returns `ESTALE`. Acceptance reserves one cleanup ID and the existing worker
batch, preserving roles and charges until the worker commits their removal. It
constructs no instance, changes no generation or admission charge, and needs no
physical session or handoff. It also works at the maximum slot generation.
Before worker commitment, cancellation or an already-latched stop preserves
the artifact. Afterward, query reports `COMMITTED` and cancellation returns
`EALREADY`, even while readers keep cleanup busy. The public pending ID/kind and
storage charge remain until actual worker release; the bounded terminal receipt
retains the artifact's signed identity. Inactive retirement never releases shared
wheel ownership or resumes a controller.

Lifecycle cancellation specifies the operation ID, expected current generation,
artifact handle and target kind (1 candidate, 2 previous, 3 deactivate, 4 retire).
It cannot undo a committed installation or artifact retirement. The original
24-byte upload cancellation remains unchanged.
Slot queries return the latest public operation ID, generation, active charge,
artifact handles and presence/inhibited/retiring flags. A present artifact may
have handle zero; use the presence flags. The pending ID is the public lifecycle
operation ID, never the private instance cleanup ID, and remains present through
worker retirement. Output fields and reserved fields must be zero on query input.

Operation queries immediately reflect handoff and cleanup status under the same
slot-before-manager lock order. Activation/rollback receipts retain the selected
artifact's complete signed identity. Failed handoff preserves its first positive
errno through cleanup into a `FAILED` receipt; generic stop or a later cancel
cannot replace it with `ECANCELED`. Timeout uses the existing kernel errno number
74 (`ETIMEDEOUT`); missing link uses `ENOLINK`, protocol/clock failures `EPROTO`,
and exhausted counters `EOVERFLOW`. An earlier explicit stop/cancel remains a
cancellation. Stale transport operation IDs cannot assign errors to a newer
operation. The worker consumes this same stop mailbox before retirement commits.

Begin compares `expected_last_id` with the latest issued ID. IDs increase without
wrapping or entering the syscall error range. Query ID 0 returns the latest ID;
before any upload it reports idle ID 0. Chunks contain at most 256 bytes, with a
zero unused tail, and must arrive at the next expected offset. An exact replay
of bytes already received is idempotent; gaps, conflicting or partially
overlapping chunks reject. An incomplete upload belongs to its process and is
cancelled through the existing owner-exit cleanup path.

Finalize accepts only a complete upload with capacity available. The accepted
operation survives installer exit. One resident candidate is retained, and a
second upload is busy until its activation cleanup releases that role. Slot
preparation and retirement also block upload acceptance. One operation remains busy through queued,
preparing and worker cleanup, including cancellation. The current conservative
capacity check rejects preparation when all three artifact positions are
occupied, even for a possible duplicate. A retry of an accepted finalize returns
the same ID while work is pending; terminal work returns `EALREADY` and remains
queryable. A lost response is resolved by querying the original/latest ID before
starting another upload. Query callers must zero every output field. Receipts expose
upload progress, phase, positive errno, artifact handle, workspace high-water and
the complete authenticated identity. Unauthenticated rejection has no trusted
identity. An expired receipt returns `ESTALE`.

Malformed requests use `EINVAL`; unsupported versions/features use `ENOTSUP`;
authentication uses `EACCES`; rejected bytecode uses `ENOEXEC`; capacity/allocation
exhaustion uses `ENOMEM`; a busy operation uses `EBUSY`; stale identities use
`ESTALE`; counter exhaustion uses `EOVERFLOW`. Wrong upload ownership uses `EPERM`.
Cancellation before registration prevents residency; after registration it
returns `EALREADY` and does not unload code. Finalize does not perform timing
admission, construct an instance or authorize activation. Resident means only
authenticated and verified code retained in the existing manager.

The [request layouts](../../kernel/crates/kernel_abi/src/managed.rs),
[bounded dispatcher](../../kernel/src/syscall/managed.rs) and
[preparation worker](../../kernel/src/bpf/preparation.rs) implement this slice.
Host tests exercise actual authentication/verification and manager transitions;
they do not establish a qualified control schedule or a live UART upload.
