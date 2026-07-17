# axiomos Documentation

## Start Here

- [`architecture/`](architecture/system-overview.md) for implemented architecture and supported behavior.
- [`reference/`](reference/) for exact contracts and generated inventories.
- [`decisions/`](decisions/) for architectural decisions and implementation gaps.
- [`design/`](design/) for proposed and accepted design reasoning.
- [`plans/`](plans/) for active and completed execution plans.
- [`security/`](security/) for threat, unsafe-code, audit, and gate evidence.
- [`reviews/`](reviews/) for point-in-time engineering findings.
- [`operations/`](operations/) for build, boot, test, debug, and release procedures.
- [`performance/`](performance/) for benchmark methodology, results, and evidence.
- [`archive/`](archive/) for superseded or historical material.
- [`../plan_refactor.md`](../plan_refactor.md) for the repository migration plan.

## Sources of Truth

| Question | Authority |
|---|---|
| How does axiomos currently work? | `docs/architecture/` |
| Why was a decision made? | `docs/decisions/` |
| What problems were found? | `docs/reviews/` and `docs/security/` |
| Which files are generated? | `docs/reference/generated/` and checked-in manifests |
| How do I build, test, run, or debug it? | `docs/operations/` |

## Documentation Lifecycle

```text
proposed design -> accepted decision -> implementation
-> current architecture/reference -> completed plan -> historical review
```

Substantial documents should identify status, owner, review date, applicability,
and related sources. Reviews identify the reviewed commit and follow-up issues.
Generated documents identify their generator and are not edited by hand.

axiomos documentation is divided by authority:

- [`architecture/`](architecture/) is normative for implemented behavior and
  subsystem boundaries.
- [`reference/`](reference/) defines exact supported interfaces and generated
  inventories.
- [`decisions/`](decisions/) records accepted architecture decisions. Later ADRs supersede
  earlier ones; accepted ADRs are not edited to hide historical decisions.
- [`reference/generated/`](reference/generated/README.md) is produced from checked-in manifests and
  ABI descriptors. Generated files must not be edited by hand.
- [`archive/`](archive/README.md) contains historical proposals, plans, audits,
  and specifications that are retained for traceability but are not current
  implementation contracts.
- [`security/`](security/) contains threat, assurance, unsafe-code, and gate
  authorities.

The original proposal, execution plans, branch-specific engineering review, and
superseded design specifications are indexed under `archive/`. No generic
`current/` namespace exists: document type and lifecycle encode authority.
