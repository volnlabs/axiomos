# ADR-0002: Kernel error policy

- Status: Accepted
- Date: 2026-07-14

## Decision

Kernel failures are classified by boundary and handled consistently:

| Class | Representation | Required behavior |
|---|---|---|
| Invalid userspace request | `Errno` or typed error mapped once to `Errno` | Return to the caller; never panic or log synchronously on a hot path. |
| Malformed untrusted input | Typed parser/validation error | Reject without partial publication or leaked ownership. |
| Resource exhaustion | Typed allocation/quota error | Roll back, return an error, or terminate only the affected task when no caller exists. |
| Would block | Typed readiness result | Register on a wait channel and retry after wake; preserve nonblocking semantics. |
| Recoverable device/filesystem error | Typed subsystem error | Propagate with context through adapters; do not collapse to `()`. |
| Boot prerequisite failure | `BootError` | Emit one bounded fatal record/marker and enter the architecture halt path. |
| Kernel invariant violation | Dedicated assertion/fatal path | Panic in debug/test; fail closed with a bounded diagnostic in release. |

Public subsystem traits must not use `Result<_, ()>` or `Result<_, &'static str>`.
Errors own stable machine-readable variants; human-readable formatting is not
part of the ABI. Operations that acquire resources publish them only after all
fallible preparation succeeds, or carry a rollback guard that restores the old
state on every error path.

Interrupt handlers cannot format errors. They increment bounded counters, store
a compact trace record, move hardware to its defined safe state when necessary,
and defer recovery to task context.

## Enforcement

- Clippy plus a repository check rejects unit/string errors at designated public
  kernel boundaries.
- Failure-injection tests cover every transactional allocation/mapping API.
- Syscall adapters contain the only subsystem-error-to-`Errno` mapping tables.
