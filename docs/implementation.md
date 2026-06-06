# Axiom Implementation Plan

**Date:** 2026-03-19
**Status:** Active execution plan
**Scope:** Kernel runtime programmability first, demoability second, optimization third

---

## Purpose

This document defines what Axiom is trying to prove next, what already exists, what is still missing, and the order in which implementation work should happen.

The goal is not to expand scope. The goal is to finish the strongest version of the thesis already present in the codebase:

**Axiom is a runtime-programmable kernel whose behavior can be changed on a running system by loading verified programs, without reflashing or rebooting.**

---

## Current State

The project is further along than a high-level summary suggests.

What is already working in the repository:

- Bootable kernel on `x86_64`, `aarch64`/RPi5, and `riscv64`
- BPF loader, verifier, interpreter, JIT, and map support
- Timer hook execution on live hardware interrupts
- GPIO interrupt hook execution on RPi5
- Syscall entry hook execution in the syscall dispatcher
- Ring buffer infrastructure and userspace bridge scaffolding
- Hardware benchmark results on Raspberry Pi 5

What is not yet complete enough for the thesis:

- `rk-bridge` is not yet connected to live kernel event sources through a stable exported object interface
- `rk-bridge` ROS2 publishing is still placeholder code behind a feature flag
- The final durable bridge/export interface is not yet packaged
- Kernel heap at init is above the proposal target

---

## Primary Objective

### Objective 1: Prove live kernel programmability

This is the main objective for the next implementation phase.

Axiom must demonstrate that:

- a verified program can be loaded into a running kernel
- the program can attach to a real kernel event
- the program executes on that event without reboot
- the program can observe or influence kernel behavior in a way that is visible and measurable

This objective matters more than new subsystems, more than more benchmarks, and more than userspace polish.

If this objective is not completed, the system is still technically impressive, but the core claim remains under-demonstrated.

---

## Secondary Objectives

### Objective 2: Make the hook model coherent

The hook system must become an explicit part of the kernel ABI and implementation model, not just a set of attach constants.

We need:

- a clear list of supported hook types
- clear event context for each hook
- clear execution semantics for each hook
- clear statement of what a hook may and may not change

### Objective 3: Build one compelling hardware demo

The demo should show behavior change on a running RPi5 system with no reboot.

The demo is successful if an external observer can understand the effect immediately.

### Objective 4: Quantify overhead and footprint

After the live hook path is complete, we need:

- syscall latency measurements
- hook overhead measurements
- memory reduction work to get below the proposal target

### Objective 5: Complete the ROS2 bridge as a parallel demo track

The ROS2 bridge matters because it connects Axiom to an actual robotics software graph and turns the kernel proof into something a robotics engineer immediately understands.

It is not the kernel critical path, but it should proceed in parallel once the event path it depends on is real.

---

## What We Will Not Do Yet

The following work is explicitly deferred:

- networking stack expansion
- building a Copper-like runtime
- forking Copper
- broad benchmark expansion before hook completion
- major new subsystems unrelated to runtime programmability

These may all matter later, but they are not the bottleneck now.

---

## Implementation Strategy

The implementation strategy is to move from proof of concept surfaces to a minimal, coherent, demonstrable runtime programming model.

The implementation work has one critical path and one parallel presentation track.

Critical path:

- finish the live kernel hook model
- wire the missing scheduler and syscall semantics
- prove runtime programmability on real hardware

Parallel track:

- complete `rk-bridge` ROS2 publication
- use the bridge as the presentation layer for the final demo
- keep the bridge honest by feeding it only from live kernel events in the final demonstration

The demo narrative should be explicit:

`runtime-loaded verified program -> live scheduler/syscall hook -> ring buffer -> rk-bridge -> /rk/* ROS2 topic`

Each layer has value on its own. Together they form the complete thesis in one visible flow.

---

## Phase 1: Define the Runtime Hook Model

### Goal

Turn the current collection of hook entry points into a clear implementation contract.

### Why this comes first

Without a stable hook model, each new integration point will be implemented ad hoc. That creates duplicated semantics, weak demos, and a poor foundation for both the paper and future userspace tooling.

### Target outcome

A documented hook taxonomy with explicit meaning.

The minimum useful hook set is:

- `timer`
- `gpio`
- `sys_enter`
- `sys_exit`
- `sched_switch`

Optional later additions:

- `sched_enqueue`
- `sched_dequeue`
- `pwm_event`
- `iio_event`

### Required decisions

For each hook type, define:

- when it fires
- what context struct is provided
- whether programs are observe-only or may affect behavior
- whether multiple programs may attach
- execution ordering if multiple programs attach
- failure behavior if a program errors

### Done criteria

- Hook types are named consistently across docs, kernel code, and userspace tooling
- Each hook has a clearly defined context shape
- Hook semantics are clear enough that demos and benchmarks can target them directly

### Current Hook Contract

The runtime hook model is now explicit enough to describe directly from the implementation.

Supported attach types in the kernel today:

- `timer` = attach type `1`
- `gpio` = attach type `2`
- `pwm` = attach type `3`
- `iio` = attach type `4`
- `sys_enter` = attach type `5`
- `sys_exit` = attach type `6`
- `sched_switch` = attach type `7`

The kernel currently executes attached programs in attachment order for a given attach type.
Multiple programs may attach to the same hook type.

Execution model:

- The BPF VM passes a pointer to `BpfContext` in `R1`
- Hook-specific payload is exposed through `BpfContext.data`
- `BpfContext.data_end` bounds the payload range
- Programs are expected to load `ctx.data` first and then read the hook payload from that pointer

The common wrapper context is:

```c
struct BpfContext {
    const u8 *data;
    const u8 *data_end;
    const u8 *data_meta;
    u64 interrupt_latency_ns;
    u64 boot_time_ms;
    u64 kernel_heap_kb;
    u64 kernel_image_mb;
};
```

Hook payloads currently implemented:

`sys_enter`

- Fires at syscall dispatcher entry before syscall execution
- Attach type: `5`
- Context:

```c
struct SyscallTraceContext {
    u64 syscall_nr;
    u64 arg1;
    u64 arg2;
    u64 arg3;
    u64 arg4;
    u64 arg5;
    u64 arg6;
};
```

`sys_exit`

- Fires in the syscall dispatcher after the syscall result is computed
- Attach type: `6`
- Context:

```c
struct SyscallExitContext {
    u64 syscall_nr;
    i64 result;
};
```

`sched_switch`

- Fires in the live scheduler path during `reschedule()` before the low-level context switch
- Attach type: `7`
- Context:

```c
struct SchedSwitchContext {
    u64 cpu_id;
    u64 prev_pid;
    u64 prev_tid;
    u64 next_pid;
    u64 next_tid;
};
```

Current semantics:

- `sys_enter`, `sys_exit`, and `sched_switch` are observe-only
- Programs may emit trace output, update maps, and write ring buffer events
- Programs do not currently modify syscall results, deny syscalls, or override scheduling decisions
- Program failure is logged and does not change the kernel decision path

This is enough for the current thesis claim:

`runtime-loaded verified program -> live kernel hook -> ring buffer -> userspace-visible effect`

---

## Phase 2: Finish Live Scheduler Hooks

### Goal

Wire BPF execution into real scheduler events so a running kernel can execute verified programs during scheduling activity.

### Why this is the highest-value missing implementation

Timer hooks already prove interrupt-driven execution.
GPIO hooks already prove hardware event execution.
Syscall entry hooks already prove dispatcher-level attachment.

The major missing piece is the scheduler. Once scheduler hooks are live, Axiom can claim runtime programmability at one of the core control points of the kernel itself.

### Scope

Start with the smallest useful scheduler surface:

- hook on task switch
- expose read-only scheduling context first
- keep semantics observational in the first version

Do not begin with dynamic policy mutation unless the dispatch path is already stable.

### What “live” means

The hook must execute inside the actual scheduler path used by the kernel on running hardware, not in a synthetic test-only path.

### Demo value

A scheduler hook can produce:

- trace output
- per-task timing metrics
- ring buffer events
- scheduling decision visibility

That is enough to prove runtime programmability even before allowing policy override.

### Done criteria

- Scheduler hook dispatch is wired into the real scheduling path
- A verified program can attach at runtime
- The program executes during real task switches on RPi5
- The effect is observable through logs, metrics, or ring buffer output

---

## Phase 3: Upgrade Syscall Hooks Into a Real Interface

### Goal

Turn current syscall hook support into a clear and complete hook interface.

### Current state

The syscall dispatcher already runs BPF programs at syscall entry.
That is useful, but still incomplete.

### Missing pieces

- separate `sys_enter` and `sys_exit`
- return value visibility on exit
- ability to target or filter specific syscalls
- explicit contract for whether hooks may only observe or may also deny or modify behavior

### Recommended approach

Implement this in two passes.

Pass 1:

- split entry and exit hooks
- provide stable context structs
- keep hooks observational

Pass 2:

- evaluate whether policy semantics are worth adding
- if policy semantics are added, define them narrowly and safely

### Why this matters

Syscall hooks are easy to explain and benchmark.
They are also a direct answer to the question: “What changes on a running kernel when I load a program?”

### Done criteria

- Entry and exit hooks are both supported
- Exit context includes result code
- Targeting specific syscalls is possible
- Hook semantics are documented and testable

---

## Phase 4: Build the Main No-Reboot Demo

### Goal

Produce one short, obvious demo that shows the thesis in action.

### Demo requirement

The demo must communicate the following in one sentence:

“A running kernel changed its behavior because a verified program was loaded and attached live.”

The preferred visible form of that demo is:

`runtime-loaded verified program -> live scheduler/syscall hook -> ring buffer -> rk-bridge -> /rk/* ROS2 topic`

This is the strongest version of the story because it shows the entire path from live kernel event to robotics-visible output.

### Best demo candidates

Candidate A: syscall tracing or policy

- attach a program to a syscall hook at runtime
- show immediate trace or enforcement effect
- no reboot, no reflashing

Candidate B: scheduler visibility

- attach a program to scheduler events
- show task-switch telemetry live
- publish through logs or ring buffer

Candidate C: GPIO to PWM safety path

- attach a program to a GPIO interrupt
- trigger hardware response immediately
- strong robotics story, but depends more on hardware setup

### Recommendation

Use scheduler or syscall as the first core thesis demo.
Use `rk-bridge` and ROS2 topics as the presentation layer for that demo once live hook events are feeding the ring buffer.
Use GPIO/PWM as the second robotics-flavored demo once the core hook model is complete.

### Current validated state

The kernel-side proof path is now in place and validated on RPi5 hardware.

What is already proven:

- `sys_enter`, `sys_exit`, and `sched_switch` are live runtime hook points
- `sys_exit` can drive ring-buffer output to userspace without reboot
- `sched_switch` can drive ring-buffer output to userspace without reboot
- `sched_switch` can export live events to a second userspace consumer in the same boot using a kernel-held exported map ID
- `sched_switch` can now export live events to a second userspace consumer through a pinned BPF map object on RPi5 hardware
- AArch64 `fork()`/child return was repaired enough to support real scheduler demo workloads

This means the remaining Phase 4 bottleneck is no longer kernel hook bring-up.
It is event export, bridge integration, and demo presentation.

### Phase 4 execution strategy

Phase 4 will proceed in two passes.

The short-term goal is to finish the strongest honest demo path as quickly as possible.
The long-term goal is to converge on the cleaner durable architecture.

#### Pass 1: Pragmatic in-kernel handoff path

The first pass uses the kernel and syscall surface that already exists today, without pretending that pinned object export or host-side bridge consumption already exists.

Implementation plan:

- add a small export producer: `sched_switch_export_demo`
- add a second userspace consumer: `sched_switch_bridge_demo`
- let the export demo create the ring buffer, attach the program, and export the live map ID into a kernel-held handoff slot
- let the bridge demo read that exported map ID in the same boot and consume live ring-buffer events through `BPF_RINGBUF_POLL`

The proof target for this pass is:

`runtime-loaded verified program -> live sched_switch hook -> shared exported map id -> second userspace consumer`

Why we are doing this:

- the current kernel does not yet expose pinned BPF objects as a stable consumable userspace interface
- the root ext2 image is not writable, so file-based handoff is the wrong dependency
- host-side `rk_bridge` is a standalone `std` tool, while the live ring-buffer polling surface that exists today is an Axiom in-kernel syscall path
- a kernel-held exported map ID is the smallest honest transport that matches the system as built today
- this proves cross-process event export on the running kernel without waiting for pinned-object infrastructure

This is a proof-oriented interim transport, not the final architecture.

Current status:

- Pass 1 is complete and validated on RPi5 hardware
- the validated sequence is:
  `sched_switch_export_demo -> SYS_DEBUG handoff -> sched_switch_bridge_demo`
- the proven output line is:
  `Pipeline proven: runtime attach -> sched_switch -> shared map-id -> bridge consumer`

#### Pass 2: Durable bridge architecture

The second pass replaces the pragmatic transport with the cleaner long-term interface.

Implementation plan:

- implement `BPF_OBJ_PIN`
- implement `BPF_OBJ_GET`
- implement the required object info/query path for bridge discovery
- expose ring buffer maps as stable kernel objects
- update `rk_bridge` to consume pinned paths instead of transient map IDs
- replace placeholder ROS2 publication with real `/rk/*` topic publication

The final target for this pass is:

`runtime-loaded verified program -> live sched_switch/sys_exit hook -> pinned ring buffer -> rk_bridge -> /rk/* ROS2 topic`

Why this is the right longer-run architecture:

- pinned objects are stable across process boundaries
- the bridge becomes a real consumer instead of a demo-only peer process
- the system aligns better with established BPF object lifecycle patterns
- ROS2 publication becomes a presentation layer over a stable kernel event interface, not a special-case demo path

Current status:

- Pass 2A is complete and validated on RPi5 hardware for map objects
- the validated sequence is:
  `sched_switch_export_demo -> BPF_OBJ_PIN -> sched_switch_bridge_demo -> BPF_OBJ_GET`
- the proven output line is:
  `Pipeline proven: runtime attach -> sched_switch -> pinned object -> bridge consumer`
- the remaining Pass 2 work is bridge integration and real ROS2 publication, not kernel-side pinned map bring-up

### Validity constraint

The demo is only valid when the event source is a live kernel hook.

That means:

- the attached program must be loaded into the running kernel
- the event must originate from a real scheduler or syscall hook
- the ring buffer must be fed by that live hook path
- `rk-bridge` must not be the primary proof if it is only consuming synthetic or mocked events

`rk-bridge` development may proceed in parallel using synthetic data for local development, but the final demo and the thesis claim only count when the source is a real kernel event.

### Done criteria

- Demo runs on RPi5
- Demo requires no reboot between “before” and “after”
- A reviewer can understand the change immediately from output alone
- Pass 1 done:
  - live kernel scheduler events reach a second userspace consumer in the same boot
  - the handoff mechanism is kernel-owned and requires no reboot or reflashing between producer and consumer
  - output is clean enough to demonstrate the end-to-end path on hardware
- Pass 2 done:
  - pinned-object event export exists
  - `rk_bridge` consumes stable named kernel objects
  - real ROS2 topic publication works from the live kernel event stream

---

## Phase 5: Measure the Cost of Programmability

### Goal

Quantify how much overhead the live hook system adds.

### Metrics to capture

- baseline syscall latency
- syscall latency with empty hook attached
- syscall latency with non-trivial hook attached
- scheduler hook overhead if measurable
- ring buffer publication overhead where relevant

### Why this phase comes after hook stabilization

Benchmarking before the hook model is stable wastes time and produces numbers that will have to be discarded.

### Main benchmark target

Matched RPi5 measurements for:

- `sys_write`
- `sys_read`
- `sys_getpid`

Compare:

- Axiom without active hook
- Axiom with active hook
- Linux baseline

### Done criteria

- Benchmarks are reproducible
- Results are tied to a specific commit and hardware setup
- Overhead of runtime hooks is quantifiable, not speculative

---

## Phase 6: Reduce Kernel Heap Below 10 MB

### Goal

Meet the proposal target for kernel heap usage at init.

### Current state

Current measured kernel heap at init on RPi5 is approximately `12290 KB`, which is above target.

### Approach

Do this after the main hook work lands, not before.

Heap reduction should be measurement-driven:

- identify largest allocators at init
- separate one-time setup allocation from persistent footprint
- trim scheduler, VFS, and BPF subsystem overhead where possible

### Why this is not first

Heap work improves the story, but it does not prove the thesis.
Live runtime programmability does.

### Done criteria

- Heap at init is below `10 MB`
- Measurement method is documented
- Tradeoffs are understood and recorded

---

## Phase 7: Complete rk-bridge ROS2 Publishing

### Goal

Finish the bridge from kernel events to actual ROS2 topics.

### Current state

The ring buffer consumer and userspace bridge structure exist.
`RosPublisher` is still a placeholder.

### Why this matters

This makes Axiom legible to robotics developers.
It places kernel events directly into the ROS2 graph and strengthens the integration story around Axiom as a robotics kernel.

This phase is not strictly “after everything else.”
It can proceed in parallel with demo preparation, provided the final proof uses live kernel-originated events.

### Scope

- implement `RosPublisher` behind the `ros2` feature
- publish IMU, motor, safety, and related events to `/rk/*`
- preserve non-ROS stdout mode for development and testing

### Done criteria

- `ros2` feature produces real ROS2 publication
- event types map to stable topics
- end-to-end bridge works from kernel event to visible ROS2 topic

### Parallel track constraint

Parallel bridge work is allowed and encouraged, but the main demo is blocked until:

- the ring buffer is fed by a live scheduler or syscall hook
- the published `/rk/*` topic reflects that live hook output

---

## Work Priority

Priority order for implementation:

1. Define and document the hook model
2. Wire scheduler hooks into the real scheduler path
3. Upgrade syscall hooks to explicit entry and exit semantics
4. In parallel, complete ROS2 publishing in `rk-bridge`
5. Produce one strong no-reboot hardware demo backed by live kernel hook events
6. Benchmark syscall and hook overhead
7. Reduce heap below target

Practical execution split:

- Kernel track: scheduler hooks plus syscall entry and exit semantics
- Bridge track: `RosPublisher` plus topic wiring
- Demo gate: the bridge-backed demo is only valid when the event source is a live kernel hook, not a fixture

---

## Success Conditions

The next phase is successful if all of the following are true:

- A reviewer can see that Axiom supports live kernel behavior changes without reboot
- The hook model is coherent and documented
- Scheduler and syscall hooks are both real, not implied
- There is at least one short, repeatable RPi5 demo
- The demo can be shown end-to-end through `/rk/*` ROS2 topic output from a live kernel event path
- Performance impact of hooks is measured
- Memory reduction work has a clear follow-up path

---

## Failure Modes To Avoid

We should actively avoid the following mistakes:

- expanding the hook surface before defining semantics
- building a demo around a path that is not yet a first-class interface
- treating synthetic bridge output as if it proves the kernel event path
- optimizing heap too early and delaying thesis-critical work
- spending time on ROS2 polish before the kernel proof is complete
- presenting timer hooks alone as if they finish the runtime programmability story

---

## Immediate Execution Focus

If we only do one thing next, it should be this:

**Finish the live hook model by wiring scheduler hooks and formalizing syscall hooks.**

That is the shortest path to making Axiom's core claim undeniable.
