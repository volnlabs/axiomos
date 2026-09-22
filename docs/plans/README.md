# Plans

Plans contain milestones, tasks, dependencies, rollout order, ownership, and
validation gates. They are execution sequencing, not specifications.

- `active/`: work in progress
- `completed/`: retained execution history

Hardware campaign: [bring-up plan](active/axiomos-hardware-bringup/plan.mdx)
and [first-boot card](active/axiomos-hardware-bringup/first-boot-card.md).

Release foundation record:
[v0.5.0-alpha.1 release plan](active/v0.5-alpha-release.md).

Canonical runtime contract and M0–M7 sequence:
[v0.5 bounded runtime evolution](active/v0.5-bounded-runtime-evolution.md).
The [engineering draft v2](active/v0.5-runtime-evolution-engineering-draft-v2.md)
is retained as superseded historical input.

Current development sequencing is owned by the
[canonical v0.5 bounded runtime evolution plan](active/v0.5-bounded-runtime-evolution.md):
complete the M1 software prerequisites and M2–M6 first, then run deferred M1
electronics qualification with the final M7 hardware campaign. The
[September 11 hardware-first plan](active/v04-hardware-first.md) remains the
historical sequencing record and an active source of electrical and physical
release gates; its requirement to finish unloaded electronics acceptance before
v0.5 software work was superseded by the accepted September 15 sequence.
Powered-motor and assembled-car acceptance remain required for robot release claims.
