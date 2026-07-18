# Release Verification

The required local release-oriented gate is:

```sh
cargo xtask check all --profile full
```

Use `--format json` for machine-readable output. The full profile includes
build, test, static policy, target, fuzz-build, Miri, and QEMU checks defined by
the [local audit gate](../security/gates/local-audit-gate.md). Physical HIL and
independent review remain separate evidence and must not be inferred from a
local pass.

For releases containing the Shrike-lite hardware safety envelope, the same full
gate also compiles and runs the self-checking SystemVerilog testbench for
`firmware/shrike/fpga/shrike_safety_gate.sv` with Icarus Verilog. That proves
the RTL truth table only; a ForgeFPGA project, pin constraints, synthesized
bitstream, logic-analyzer timing capture, and physical e-stop HIL remain
separate release evidence.

## v0.5.0-alpha.1 scope

The alpha is a repository tag for the v0.3/v0.4 software foundation and the
initial FPGA safety-gate RTL. It is not a claim that physical robot HIL, hosted
CI, a ForgeFPGA bitstream, or the v0.5 behavior registry/hot-swap/rollback/
flight-recorder deliverables are complete. Record the exact tagged commit and
the retained local-gate output with the prerelease notes.
