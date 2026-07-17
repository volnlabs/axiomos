# Documentation authority

axiomos documentation is divided by authority:

- [`current/`](current/README.md) is normative for the implementation and
  supported release surface.
- [`adr/`](adr/) records accepted architecture decisions. Later ADRs supersede
  earlier ones; accepted ADRs are not edited to hide historical decisions.
- [`generated/`](generated/README.md) is produced from checked-in manifests and
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
