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
qualified single CPU, queries and append use a bounded IRQ-masked critical
section; no program-manager lock, allocation or waiting occurs in that section.

JSONL starts with a versioned `axiomos-managed-audit` header, followed by record
envelopes and explicit gap entries, then an end marker with record/gap counts.
The host freezes the original end cursor, so ongoing recording cannot prolong
export indefinitely. Overwrite during export advances only through a reported
gap. Invalid sizes, flags, record kinds, sequence order, reversed timestamps or
unaccounted cursor movement fail export. Interrupted transport leaves an
incomplete file without the end marker; write/flush errors are reported. The
export is not crash-persistent or an atomic file transaction.

Current coverage is deliberately explicit: the kernel emits the physical-clock
initialization event only. Its LINK payload has little-endian subtype 1 at bytes
0..4 and the frequency at bytes 8..16, with all other payload bytes zero. Ticks
use CNTPCT, the same domain as managed releases. Session remains zero and
`session_established` false until bilateral control-link integration lands; the
clock value is never presented as a persistent boot identity. Lifecycle, cycle,
actual stop and sink-ack producers remain to be connected. Payload bytes are
exported losslessly as `payload_hex`, with `payloads_decoded: false`; this envelope
export is not yet the semantic acceptance decoder or a qualified runtime trace.
