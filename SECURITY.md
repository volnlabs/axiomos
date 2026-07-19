# Security Policy

axiomos is a research kernel for robotics workloads. It is pre-1.0: the safety
architecture is real and load-bearing, but it has not had an external audit
and makes no formal assurance claims. See [docs/security/threat-model.md](docs/security/threat-model.md)
for what is and is not defended.

## Reporting a vulnerability

Email **projects.utkarshmaurya@gmail.com** with subject `[axiomos-security]`,
or use GitHub's private vulnerability reporting on this repository.

Please include:

- A description of the issue and the safety property it violates.
- A reproducer where possible. For verifier soundness bugs, the ideal report
  is a BPF program (bytes or assembly) that **passes verification but
  performs an unsafe action** — see the target list in
  [docs/reviews/implementation/verifier-review-call.md](docs/reviews/implementation/verifier-review-call.md).
- The commit hash you tested against.

## What counts as a security bug

In rough priority order:

1. **Verifier soundness**: any program accepted by the verifier that reads or
   writes outside its verified regions, overflows the stack, exceeds its
   execution bound, or bypasses a helper argument contract.
2. **Syscall boundary**: userspace input that corrupts kernel state through
   `sys_bpf` or any other syscall.
3. **Isolation**: a BPF program observing or modifying state of another
   program or of the kernel outside the helper API.
4. **Denial of service from unprivileged input** (e.g., verifier state
   explosion, unbounded admission).

Out of scope today (documented gaps, not surprises): speculative-execution
side channels (#89), program-signing enforcement being off by default (#20 —
the Ed25519 mechanism exists but `allow_unsigned` defaults to `true`), and
physical attacks (JTAG, SD-card swap).

## Response expectations

Solo-maintainer project. Acknowledgement within **7 days**, triage verdict
within **14 days**. Confirmed soundness bugs are fixed before the next tagged
release. You will be credited in the fix commit and release notes unless you
ask otherwise.

## Safe harbor

Good-faith security research against your own builds of axiomos is welcome.
This project will not pursue legal action for research conducted under this
policy.
