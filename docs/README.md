# axiomos Documentation

## Start Here

- [`architecture/`](architecture/system-overview.md) for implemented architecture and supported behavior.
- [`decisions/`](decisions/) for architectural decisions and implementation gaps.
- [`security/`](security/) for threat, unsafe-code, audit, and gate evidence.
- [`reviews/`](reviews/) for point-in-time engineering findings.
- [`archive/`](archive/) for superseded or historical material.
- [`../plan_refactor.md`](../plan_refactor.md) for the repository migration plan.

## Sources of Truth

| Question | Authority |
|---|---|
| How does axiomos currently work? | `docs/architecture/` |
| Why was a decision made? | `docs/decisions/` |
| What problems were found? | `docs/reviews/` and `docs/security/` |
| Which files are generated? | `docs/reference/generated/` and checked-in manifests |
| How do I build, test, run, or debug it? | root docs, `scripts/`, and `docs/operations/` |

During migration, existing paths remain authoritative where this table points
to them. A document move must not silently change authority.

## Documentation Lifecycle

```text
proposed design -> accepted decision -> implementation
-> current architecture/reference -> completed plan -> historical review
```

Substantial documents should identify status, owner, review date, applicability,
and related sources. Reviews identify the reviewed commit and follow-up issues.
Generated documents identify their generator and are not edited by hand.

axiomos documentation is divided by authority:

- [`architecture/`](architecture/system-overview.md) is normative for the implementation and
  supported release surface.
- [`decisions/`](decisions/) records accepted architecture decisions. Later ADRs supersede
  earlier ones; accepted ADRs are not edited to hide historical decisions.
- [`reference/generated/`](reference/generated/README.md) is produced from checked-in manifests and
  ABI descriptors. Generated files must not be edited by hand.
- [`archive/`](archive/README.md) contains historical proposals, plans, audits,
  and specifications that are retained for traceability but are not current
  implementation contracts.
- [`security/`](security/) contains the generated unsafe ledger and release-gate
  evidence.

The original proposal, execution plans, branch-specific engineering review, and
superseded design specifications are indexed under `archive/`. Files still
located directly under `docs/` are legacy material awaiting normalization;
their claims are not normative unless linked from `current/README.md`.
