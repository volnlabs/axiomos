# BPF trust, authorization, and lifecycle

**Status:** Normative for the shipped BPF control and execution planes.

The versioned [ABI catalog](../reference/generated/abi.md) is the authority for supported
commands, map types, helpers, and attach types. This document defines how those
operations acquire authority and how their objects remain bounded.

## Trust pipeline

Program admission is ordered and fail-closed:

1. **Authenticate.** In production builds, the Ed25519 public key supplied by
   `AXIOM_BPF_TRUSTED_KEY_PATH` is compiled into an immutable one-key trust
   store. Signed containers are verified before their ELF payload is parsed.
   Malformed or unverifiable containers fail even in development mode.
2. **Authorize the caller.** Process credentials select privileged or
   unprivileged verification, permitted map access, and whether actuation
   helpers are available.
3. **Parse and normalize.** The loader accepts the supported ELF shape and
   canonicalizes BPF-to-BPF calls into the flat program consumed by the
   verifier.
4. **Verify.** Only verifier-produced `VerifiedProgram` values can enter the
   runtime. Verification includes control-flow, register/pointer state,
   direction-specific map permissions, current handle generations, helper
   policy, stack use, and static cost.
5. **Charge and publish.** Object and byte quotas are checked before a
   generation-safe handle is published. Attach admission also checks the
   profile utilization budget before an immutable hook snapshot is published.

Raw instruction loads have no signature container and are rejected whenever
signature enforcement is active.

## Production and development policy

- A non-test build without `bpf-unsigned-development` is signed-only. The
  trusted key must be present and valid at build time.
- Unit tests and explicit `bpf-unsigned-development` builds accept unsigned
  objects. This feature is diagnostic/development policy and is not a shipped
  production claim.
- `bpf-production-signed` and `bpf-unsigned-development` are mutually
  exclusive at compile time.
- Shipped profiles use the interpreter. JIT policy is defined separately by
  [ADR-0004](../decisions/0004-bpf-jit-policy.md).

## Process capabilities

`Credentials` carries a monotonic `BpfCapabilities` mask. Fork and exec inherit
the exact current mask. A process can restrict or drop rights but cannot regain
them through the capability API.

The command boundary checks narrow rights for program load, map creation,
read/write access, object pinning, object administration, privileged
verification, and trace/scheduler/device attachment. Actuation helpers require
the separate `ACTUATE` capability. The initial userspace process deliberately
lacks trace/device attach and actuation rights.

Capability checks are only the outer gate. Manager methods also enforce object
ownership, per-map grants, offered pin access, and verifier-time map visibility.

## Handles, maps, and sharing

Program and map identifiers encode a slot and generation. Removing an object
advances the generation before a reusable slot can represent another object;
stale handles therefore do not resolve to a replacement object.

Maps are owner-scoped by default. A pinned path can offer read, write, or
read/write access, but a caller may request only rights present in both its
credentials and the pin's offered mask. A successful foreign lookup installs a
bounded per-owner grant. Allocation failure while extending grants or the pin
table publishes neither new authority nor a new path and preserves existing
state.

Interpreter map access uses the immutable map set captured in `ProgramRuntime`.
Runtime `MapLease` ownership prevents userspace mutation or destruction while a
map value is exposed to execution.

## Hook publication and execution

Control-plane operations run behind the serialized `BpfManager`. Hook and GPIO
readers do not take that manager lock. Attach/detach prepares a fixed-fanout
immutable snapshot, publishes it through `EpochSnapshot`, and reclaims the old
snapshot only after its reader epoch drains.

Each CPU has a guarded interpreter stack and a CPU-local current-execution
pointer for helper map resolution. Nested execution is rejected. The
interpreter clears only the verifier-recorded stack depth, not an unverified
caller-supplied size.

Actuation calls pass through the actuation monitor before platform output. The
authorization snapshot stored with a program determines whether actuation
helpers were admitted; later privilege changes do not expand an existing
program's authority.

## Quotas and reclamation

`BpfLimits` bounds live program/map counts, handle slots, per-object sizes,
global charged bytes, per-owner objects/bytes, pin count/path length, grants,
and attach fanout. Arithmetic that computes charges is checked.

Unload/destroy operations fail while an object is attached, pinned, leased, or
otherwise referenced. Scheduler-owned process teardown:

1. removes the owner's attachments and admission charges;
2. publishes the replacement hook snapshot;
3. revokes grants made to the exiting owner;
4. transfers still-pinned maps to the pinned-object owner; and
5. reclaims programs and unpinned maps only when no execution reference remains.

This is deterministic lifecycle ownership, not garbage collection.

## Evidence and limits

The required gate covers signed production loading, command/capability mapping,
generation-safe handles, quotas, unload/reclamation, map leases, publication
failure, `EpochSnapshot` Loom models, and the cloud-profile Miri suite. The
[quality boundary](../reference/generated/quality.md) publishes the current BPF coverage
and verifier mutation floor.

Remaining assurance limits are recorded in `ENGINEERING_AUDIT.md`: physical
GPIO/control-link HIL, an independent unsafe/concurrency review, and measured
coverage for deferred host-capable components are not replaced by these local
tests.
