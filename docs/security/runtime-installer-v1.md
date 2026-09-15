# Managed runtime installer v1

The managed Pi image connects `rk runtime` on a Linux host to a dedicated
`signed_bpf_loader` process over the **debug UART** (BCM2712 UART10). The RP1
control UART remains separate. The installer forwards bounded requests to the
existing versioned `SYS_BPF` management ABI and preparation worker.

This is software integration. Physical actuation stays disabled; bilateral
control-link session establishment, FPGA qualification and measured UART receive
capacity remain final qualification work. A successful upload or accepted
operation is not an activation or a claim of observed output.

## Image and authority

Build with an explicitly supplied trusted public key:

```sh
AXIOM_BPF_TRUSTED_KEY_PATH=/path/to/trusted-ed25519.pub \
  bash scripts/build/rpi5.sh release embedded-rpi5,managed-runtime
```

The script builds the matching managed init and installer into the rootfs before
building the Pi kernel. The managed bootstrap receives only `BEHAVIOR_ADMIN`,
delegates it to one installer, and permanently drops its own capabilities.
Ordinary spawned children receive none. Legacy image provisioning is unchanged.
Administration grants no direct GPIO, PWM, motor or e-stop release permission.

The kernel gives the installer exclusive raw fd0/fd1 ownership after checking
its capability and open descriptor. Each call copies at most 16 stack bytes,
returns an exact prefix, and never waits for FIFO space. Idle/contention yields
`EAGAIN`; competing ownership yields `EBUSY`; RX faults yield `EIO`. Formatted
console writes are suppressed while owned, with a saturating suppression count.
Emergency/raw diagnostic paths are not an audit stream or a timing guarantee.
Owner exit releases UART ownership without cancelling accepted kernel operations.
Incomplete uploads still follow the existing process-owned cleanup rule.

## Operator commands

Build the existing CLI with `cargo build --manifest-path userspace/tools/rk_cli/Cargo.toml`.
Replace the example port with the connected debug-UART device. The host configures
115200 baud, raw nonblocking I/O and no software/hardware flow control.

```sh
rk runtime --port /dev/ttyUSB0 query
rk runtime --port /dev/ttyUSB0 upload controller.axmb
rk runtime --port /dev/ttyUSB0 query --operation 0
rk runtime --port /dev/ttyUSB0 activate --expected-generation 0 --artifact 0
rk runtime --port /dev/ttyUSB0 stop
```

Use the **observed** generation and exact artifact handle for activation;
zero above is an example, and zero can be a valid artifact handle. Slot presence
flags distinguish an absent artifact from handle zero. `rollback`, `deactivate`
and `retire` take the same two required options. Rollback selects the exact
retained previous artifact. Deactivate selects the active artifact; retire
selects an inactive artifact. Stop inhibits without unloading or releasing e-stop.

`cancel ID` cancels an upload/preparation. To cancel a lifecycle operation, also
supply `--expected-generation`, `--artifact` and `--target-kind` (1 candidate,
2 previous, 3 deactivate, 4 retire). Queries return JSON, including the retained
operation's full signer fingerprint, public key and signed artifact digests.

Upload accepts the [canonical managed bundle](managed-bundle-v1.md), not the
legacy ELF container emitted by `rk sign`. It streams 256-byte management chunks
into the one bounded kernel upload. Finalize reports an accepted operation ID;
query that ID to distinguish preparation, resident state, handoff, commitment
and failure. Use `rk bundle` to sign normalized raw instructions and `rk verify`
to authenticate the result locally. The [managed C examples](../../examples/bpf/managed/README.md)
provide two stateless controllers and one fresh-private-array controller with
build/sign commands. Local signing and authentication do not perform kernel
verification, admission or activation. Recorder export remains open.

On a timeout or serial error, the CLI exits with an unknown-outcome diagnostic;
it does not automatically retransmit or re-execute the operation. Reconnect and
query the slot/retained operation before deciding whether to cancel or submit a
new request. A lost upload-begin response is recoverable through the slot's
`last_id` and operation query. Expected IDs and generations remain authoritative.

## Bounded framing

Each request credit permits one complete 16-byte frame:

| Bytes | Content |
|---|---|
| 0 | v1 magic `0xA5` |
| 1 | kind in high nibble; payload length 0..8 in low nibble |
| 2..5 | little-endian u32 sequence |
| 6..13 | payload, zero-padded |
| 14..15 | existing CRC16 over bytes 0..13, little-endian |

Kinds are Request=0, RequestLast=1, Poll=2, Reset=3, Ack=8, Response=9,
ResponseLast=10 and Error=11. The bounded decoder rejects invalid CRC, kind,
length and padding, and resynchronizes through arbitrary binary payload.
Reset contains an eight-byte challenge echoed by Ack and establishes the next
checked sequence. It resets only transport assembly/cursors; it never rearms,
activates or cancels a kernel operation. There is no persistent boot-identity or
malicious-peer security claim. The host's finite boot-text drain is independent
of the required bilateral 200 ms actuator-link reset procedure.

The endpoint retains one 320-byte request, one 320-byte response and one exact
previous frame/reply pair. An exact duplicate returns the same reply without
redispatch. An altered duplicate or stale/exhausted sequence rejects without
replacing that cache. RequestLast dispatches once and returns Ack; empty Poll
requests retrieve eight-byte response fragments. New requests reject while a
response remains unread. The installer preserves partial TX and reads no further
frame until its reply is written. `EAGAIN`/`EINTR` preserve partial RX;
other RX errors invalidate transport state and require Reset.

Messages begin with the little-endian u16 management command (256..268), then its
exact versioned ABI structure. The only additional command, `0xffff` with no body,
invokes trusted stop. Responses begin with the signed 64-bit syscall result;
successful slot/operation/recorder queries append the entire updated ABI structure.
No legacy BPF or arbitrary syscall forwarding exists. The kernel validates
versions, reserved fields, authority, identity, capacities and admission.

Host checks exercise the real codec, installer transport/dispatcher and CLI
through partial I/O, lost replies and full-width identities. These checks do not
replace post-boot hardware upload, receive-capacity measurements, timing under
upload pressure or the physical acceptance campaign.

## Bounded audit export

`rk runtime --port /dev/ttyUSB0 audit-status` queries the preallocated 2,048-record
kernel window. `rk runtime --port /dev/ttyUSB0 audit-export --output audit.jsonl`
creates a new file and exports the interval retained at the initial status query.
Existing output files are rejected. These commands require the dedicated
installer's existing `BEHAVIOR_ADMIN` authority and do not actuate or rearm.

The native ABI contains 96-byte records and copies at most two per read. Status
contains clock frequency, control-link session, exclusive retained interval,
overwrite/drop/suppression counters and independent latest-stop custody. On the
qualified single CPU, recorder status/read and append use a bounded IRQ-masked critical
section; no program-manager lock, allocation or waiting occurs in that section.

JSONL starts with a versioned `axiomos-managed-audit` header, followed by record
envelopes and explicit gap entries, then an end marker with record/gap counts.
The host freezes the original end cursor, so ongoing recording cannot prolong
export indefinitely. Overwrite during export advances only through a reported
gap. Invalid sizes, flags, record kinds, sequence order, reversed timestamps or
unaccounted cursor movement fail export. Interrupted transport leaves an
incomplete file without the end marker; write/flush errors are reported. The
export is not crash-persistent or an atomic file transaction.

The export header also contains `slot_generation`, `slot_last_id` and at most
three `artifacts`. These are copied through version-2 slot queries from the
existing manager; active/previous/candidate aliases are queried once. Each query
checks the exact generation, latest operation ID, handle and complete role mask
from the slot snapshot. A concurrent change fails export with no completion
marker; the CLI does not blindly retry. Identity queries hold the existing slot
then manager locks only for a fixed-size read, and never inspect private state.

`rk runtime --port /dev/ttyUSB0 query --artifact HANDLE` retrieves the same full
identity and binding declaration independently. It conflicts with `--operation`.
Signer fingerprints are checked against the complete public key using the
existing SHA3-256 implementation. The returned `modeled_wcet_cycles` is the
kernel's model estimate, not signed admission authority or measured hardware WCET.

Ticks use CNTPCT, the same domain as managed releases. Session remains zero and
`session_established` false until bilateral control-link integration lands; the
clock value is never presented as a persistent boot identity. Payload bytes are
exported losslessly as `payload_hex`, with `payloads_decoded: false`; this envelope
export is not yet the semantic acceptance decoder or a qualified runtime trace.

#### Offline inspection

Decode a saved export without opening a serial device:

```sh
rk audit-decode audit.jsonl --output audit.decoded.json
```

The input is the current canonical compact JSONL produced by `audit-export`,
including its retained-artifact header and final end marker. The decoder caps
input at 8 MiB, each line at 16 KiB, and line count at twice the recorder capacity
plus header/end. The retained interval still permits at most 2,048 records.
Unknown fields/versions, duplicate JSON keys, noncanonical lines, inconsistent
counters, malformed payloads, reversed timestamps, reordered sequences and an
absent/inconsistent end marker reject before creating output. Existing output
files are never overwritten. Source exports remain unchanged.

The decoded JSON retains the source header and raw records, adds named events,
requested/decided pairs and distinct local queue outcomes, and resolves full
identities from current retained context or complete historical fragment groups.
No-request invocations with a known successful return expose the effective zero
request; unknown discarded requests remain unknown. Lifecycle events join public
and internal IDs through recorded acceptance. Conflicting immutable identities,
fragment ordering, generations, operation mappings and impossible retained
handoff/commit order reject. Missing retained context or prerequisites lost in an
explicit overwrite gap are listed in `semantic_gaps`; missing information is not
filled from another handle or inferred as sink acceptance.

The latest-stop summary is decoded separately, including when its record has
been overwritten or sequence exhaustion prevented recording it. Transport gaps
and original loss counters remain visible alongside semantic gaps. Decoding
uses bounded transient host storage; it adds no kernel registry or history store.

Decoded output sets `payloads_decoded: true`, `qualification_evaluated: false`
and `signature_reverified: false`. It checks recorded manifest shapes and full
signer fingerprints; signature bytes are absent from these records, so it does
not independently authenticate the original bundle. Retain the signed bundles
and provenance required by the qualification plan. This is an inspectable
interpretation of the retained kernel observations, not timing admission,
observed movement, a complete run history or a release-acceptance verdict.

### Current record payloads

All fields below are little-endian on the shipped Pi5/x86 platforms. The envelope
contains sequence, recording ticks, correlation, kind and 64 payload bytes. An
artifact handle is a generational manager handle, not the signed artifact digest.
The header supplies identity for currently retained artifacts even after their
registration records are overwritten. Authenticated upload outcomes also retain
the historical manifest and identity fragments described below. Strict identity
resolution still needs integration: absent identity for an evicted artifact or
an incomplete fragment group must become an explicit error/gap, never be inferred
from another handle.
Global events have correlation zero and no cycle/artifact flags, so consumers
must not infer an installation identity from those zero fields.

#### Upload outcomes and historical identity

OPERATION records currently describe upload operations (`operation_kind = 1`).
Their correlation is the public operation ID, **not** an installation generation.
The fixed 64-byte payload is `ManagedAuditUploadV1`: kind, phase, positive errno,
flags, artifact handle, total bytes, received bytes and reserved zero (eight u32s),
workspace high-water and modeled interpreter cost (two u64s), then 16 zero bytes.
Flags are `HAS_IDENTITY = 1`, `HAS_ARTIFACT = 2`, `HAS_COST = 4`.

Producers run at accepted upload begin, finalize/queue, worker preparation start,
incomplete-upload cancellation (including loader exit), and actual registration
success/failure/cancellation. Repeated chunks and idempotent finalize retries do
not duplicate these records. Registration produces RESIDENT; it does not claim
installation, timing admission, sink readiness or execution. HAS_ARTIFACT is set
only for that successful registration, including valid handle zero. HAS_COST
means a verified artifact yielded a kernel model estimate, which may also exist
for a subsequently cancelled or registration-rejected candidate.

When authentication succeeded, the final outcome sets HAS_IDENTITY and is followed
by exactly four consecutive ARTIFACT records. Each 64-byte fragment contains its
u32 index (0 through 3), the same u32 artifact handle, and 56 data bytes. All five
records share operation correlation and recording ticks and append under one
bounded recorder critical section. The 224 concatenated data bytes are the
canonical signed manifest (160 bytes, including full payload digest/public key,
supported versions and requested state/effect declarations), full signed-bundle
digest (32 bytes), and full signer fingerprint (32 bytes). See the
[bundle format](managed-bundle-v1.md) for manifest offsets. These declarations are
authenticated requests; acceptance and modeled cost come from the outcome.

Bad signatures and malformed/unsupported unauthenticated bundles carry no trusted
identity. A verifier rejection or cancellation after successful authentication
can retain identity without a registered artifact. Missing, reordered, mismatched
or partial identity fragments cannot establish identity; the future semantic
decoder must reject them or report an explicit gap. Ring loss never fails an
operation. Sink correlation and semantic acceptance decoding remain open; raw export still declares
`payloads_decoded: false`.

#### Lifecycle boundaries

OPERATION `operation_kind = 2` uses `ManagedAuditLifecycleV1`. Its 64 bytes are
kind/event (two u32s), internal instance ID, expected/target/observed generations
(four u64s), then artifact handle, action, phase, positive errno, flags and
reserved zero (six u32s). Actions are activate (1), rollback (2), deactivate (3),
and retire inactive artifact (4). The handle always names that operation's target.
Flags are `HAS_PUBLIC_ID = 1` and `INHIBITED = 2`.

Events are acceptance (1), worker preparation start (2), build outcome (3), safe
handoff entry (4), authoritative commit (5), cancellation/inhibition of pending
work (6), retirement custody transferred to the worker (7), and reclamation
settled (8). The phase is the observed operation phase; event 6 carries CLEANUP,
since final CANCELLED/FAILED status waits for worker settlement. Build failure
also carries CLEANUP and its retained errno. An unchanged cancellation or handoff
entry is not recorded repeatedly.

Acceptance and worker records carry the public operation ID in envelope
correlation and set HAS_PUBLIC_ID. Slot-boundary records use correlation zero
without that flag; their internal instance ID joins the earlier acceptance
mapping. Public operation IDs and internal IDs are independent counters. The
timer neither acquires the manager lock nor invents equality between them.
Missing mappings after recorder wrap must be reported as gaps by the decoder.

Handoff entry records inhibition before sink readiness. Commit records append
only after the authoritative ownership/scalar changes, so a replacement or
rollback shows the new generation. Inactive artifact retirement leaves that
generation unchanged. The later reclamation-settled event occurs only after
retained readers release their references and the worker completes refunds;
reader-Busy retries do not repeat the event. A handoff timeout retains its first
error through inhibition and reclamation and never manufactures a commit.
Event 8 settles the operation's retirement batch; it does not mean the named
target artifact was unloaded (a newly activated target remains active).

These records describe software lifecycle boundaries. The existing transport
receipt guards publication, but detailed sink command/acknowledgement records,
physical output observation, session qualification and acceptance reduction
are still required. Offline decoding covers the current producer schemas.

LINK subtype 1 has its u32 subtype at byte 0 and the physical counter frequency
at byte 8 (u64); other payload bytes are zero. LINK subtype 2 stores a local
monitor release and its u32 source at byte 4. It establishes neither physical
rearm nor execution permission, and it does not erase latest-stop custody.

CYCLE correlation is the installation generation captured with the artifact
handle under the control-slot lock, after the handoff boundary and before the
invocation. The payload is `ManagedAuditCycleV1`:

| Byte | Field | Meaning |
|---|---|---|
| 0 | cycle_id / u64 | Scheduled release sequence |
| 8 | scheduled_ticks / u64 | Absolute release deadline origin |
| 16 | actual_ticks / u64 | Timer's observed release time |
| 24 | missed_releases / u64 | Scheduled releases missed before this invocation |
| 32 | artifact_handle / u32 | Valid only with flag 1, including handle zero |
| 36 | flags / u32 | 1 artifact present, 2 safe mode, 4 handoff, 8 request present, 16 request known |
| 40, 42 | requested pair / i16 each | Signed per-mille request, valid with flag 8 |
| 44, 46 | decided pair / i16 each | Policy's signed per-mille pair, valid with nonzero decision |
| 48 | decision / u32 | 0 absent, 1 allow, 2 clamp, 3 safe |
| 52 | queue_outcome / u32 | 0 absent, 1 queued, 2 ownership rejected, 3 expired deadline, 4 reversed clock, 5 queue failure |
| 56, 60 | failure, detail / u32 each | Fault code and associated detail |

Flag 16 means the interpreter returned successfully: no request then means the
defined zero-output result. Without it, a failed invocation's discarded request
is unknown. An interpreter fault cannot be reported as a controller that chose
not to request output. A queued outcome remains queued if a later fault occurs;
recording cannot undo physical actions. No queue outcome implies sink acceptance.

The cycle event precedes the timer's final deadline check. Failure zero means no
fault detected at this observation point, not successful completion of all timer
work. A later deadline miss produces a separate STOP event with the same captured
cycle and installation identity and the actual observed completion ticks. The
final timer check includes the earlier cycle-recording overhead.

Ordinary unchanged inhibited cycles increment `suppressed` without consuming
records or replacing the latest stop. Scheduled handoff cycles, controller
failures and missed releases still produce records. Repeated identical trusted
stops are suppressed; real controller execution resets that suppression.
The counter includes both kinds of deliberate suppression, separate from loss.

STOP payload is `ManagedAuditStopV1`. Its fields are cycle_id (u64, byte 0),
observed_ticks (u64, 8), deadline_ticks (u64, 16), artifact_handle (u32, 24),
flags (u32, 28), category (u32, 32), source (u32, 36), reason (u32, 40),
detail (u32, 44) and 16 reserved-zero bytes. Flags 1 and 2 indicate cycle and
artifact validity. Categories are 1 trusted e-stop assertion, 2 cycle fault,
3 timer fault and 4 final timer completion miss. Only category 4 sets
observed_ticks; recording ticks always come from the append point.

Sources are 0 unspecified, 1 operator, 2 watchdog, 3 GPIO hook, 4 learned behavior,
5 mission, 6 PWM syscall and 7 managed control. Trusted assertion records prove
that the kernel entered its stop path; they do not acknowledge remote zero output.
Cycle/completion stops correlate their captured generation. Global trusted stops
and timer faults intentionally make no generation claim. The independent latest
stop survives ring overwrite, unchanged stopped cycles and sequence exhaustion.
Managed images use these producers instead of synchronous V04_ESTOP formatting;
legacy images retain their existing messages.

Cycle fault codes (also STOP category 2 reasons) are 0 none, 1 invalid release,
2 missed release, 3 invalid clock, 4 reversed clock, 5 deadline, 6 submission and
7 policy stop. Code 6 detail is the queue-outcome code. Interpreter codes 1001
through 1021, in order, are division by zero, bounds, stack overflow, invalid
helper, timeout, invalid instruction, not loaded, out of memory, resource limit,
busy, permission, reentrant execution, verification, signature, admission,
GPIO fanout, read-only map, managed context, duplicate request, invalid request
and managed map failure. Code 1004 detail preserves the helper's complete i32 bit
pattern; other interpreter details are zero. Handoff codes 2001 through 2009 are
not established, busy, bad identity, invalid timeout, exhaustion, stale, timeout,
reversed clock and invalid release; their details are zero.

STOP category 1 reason/detail are zero. Category 3 reasons 1 through 8 are timer
busy, not started, already started, invalid period, reversed clock, exhaustion,
stopped and managed-control boundary failure. Category 4 reason is 5 (deadline).
These timer details are zero. Lifecycle events, complete signed identity,
command sequences, correlated sink acknowledgements and dedicated link/reset
events remain required before the trace can satisfy the release acceptance gate.
