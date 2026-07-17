# axiomos

A bare-metal Rust kernel with runtime-programmable behavior through verified eBPF programs.

axiomos targets robotics and embedded systems where kernel logic should evolve without reflashing firmware. Instead of recompiling to change kernel behavior, verified programs are loaded and attached to kernel hooks at runtime.

> **Status: research kernel under active hardware bring-up on Raspberry Pi 5.** Not production-ready. See [Limitations](#limitations) for the current honest list of what works and what doesn't. The current [benchmark authority](docs/performance/current-results.md) contains one attributable host-verifier campaign; legacy Pi/QEMU/Linux numbers are archived until rerun with retained raw logs and artifact hashes.

**Repository structure:**
- `kernel/src` — core kernel implementation
- `kernel/crates` — modular kernel subsystems (BPF, VFS, etc.)
- `userspace/` — userspace programs and libraries
- `scripts/` — build system and deployment tools
- `docs/` — architecture, benchmarks, protocols — or visit [docs](https://deepwiki.com/pro-utkarshM/axiom-ebpf)

---

## Why axiomos Exists

Embedded systems deployed in the field need behavioral updates — new sensor fusion algorithms, modified control loops, updated safety policies. Traditional kernels require full reflash cycles: risky, slow, and capable of bricking devices. axiomos instead hot-loads verified eBPF programs onto kernel hooks (syscalls, timers, GPIO, PWM, IIO) at runtime, detachable on the fly.

This is proven in Linux, but Linux is unsuitable for hard real-time robotics due to unpredictable latency and resource overhead:

| Approach | Latency | Footprint | Control | Complexity |
|----------|---------|-----------|---------|------------|
| Linux + eBPF | ~2,000ns jitter | ~60MB (kernel) | Limited | Lower |
| RTOS + custom | <10,000ns | ~1MB | Partial | Medium |
| **axiomos (Pi5)** | **Not currently attributable** | **Not currently attributable** | **Total** | **Unmeasured under the current evidence contract** |

Historical latency methodology covered hardware vector entry → BPF dispatch on one core without contention, but its raw capture and artifact hash were not retained. Tail latency under load is also unmeasured ([#74](https://github.com/pro-utkarshM/axiomOS/issues/74)); see the [benchmark evidence policy](docs/performance/current-results.md).

---

## Design

Three decisions define the kernel — detail and rationale in the
[current architecture](docs/architecture/system-overview.md):

1. **Bare metal, monolithic.** No host OS, no RTOS. Limine bootloader (x86_64) or device tree (AArch64). Microkernel IPC overhead is unacceptable for control loops; Rust trait boundaries provide the modularity instead.
2. **Rust core, `no_std`, `panic=abort`.** ~95% Rust; assembly limited to boot stubs and exception vectors. Memory-safety bug classes (use-after-free, double-free, data races) are eliminated at compile time; `unsafe` blocks are explicit and audited.
3. **eBPF for runtime extension.** Programs are verified, then attached to hooks:

```c
// Loaded at runtime, verified, then attached to GPIO line 23
BPF_PROG(gpio_handler, struct gpio_event *event) {
    if (event->line == 23 && event->rising_edge) {
        sys_wake_task(PID_MOTOR_CONTROLLER);
        metrics.gpio_triggers++;
    }
    return 0;
}
```

**What the verifier guarantees today:** bounded execution, constrained stack, validated memory access, termination proof, and a static WCET cycle bound per program. The verifier gates the `sys_bpf` load path — programs that fail do not load. Loads are admission-controlled: a program that cannot fit one control-loop period is rejected, and attaches commit `wcet × freq` against a utilization budget. The model and admission behavior are tested in the required gate; the historical Pi5 calibration is not current benchmark evidence because its raw capture and kernel-artifact hash were not retained. Program provenance is authenticated on load (Ed25519, fail-closed; unsigned loads still allowed by default until a userspace signer ships). A libfuzzer harness runs on every PR and nightly.

**Execution:** interpreter (portable, ~50ns/insn on x86_64) or JIT (AArch64, <5ns overhead), selected per compile-time profile (8KB-stack embedded → 512KB-stack cloud).

---

## Supported Platforms

| Arch | Targets | Status |
|------|---------|--------|
| x86_64 | QEMU, VMware, bare metal | Boot, userspace, VirtIO; Limine (UEFI+BIOS), APIC |
| AArch64 | QEMU virt, **Raspberry Pi 5** | Primary hardware target; GICv2/v3, RP1 GPIO/UART/PWM, device tree boot |
| RISC-V | QEMU virt | Early bring-up — boot only, no userspace; not on critical path |

---

## Build & Run

**Requirements:** Rust nightly, `cargo`, QEMU, cross targets (`x86_64-unknown-none`, `aarch64-unknown-none`). The build also assembles a rootfs image and (x86_64) an ISO, so it needs `e2fsprogs` (`mke2fs`), `xorriso`, `git`, and `make` on `PATH` — a clean box without these fails in `build.rs`.

```bash
# Build and run in QEMU (x86_64)
cargo run

# RPi5 build (kernel8.img with embedded ext2 rootfs)
./scripts/build-rpi5.sh
```

---

## Implementation Status

**Working:** boot (x86_64, AArch64); virtual memory + paging; interrupts (APIC, GIC); preemptive scheduling; syscalls; kernel heap; eBPF runtime (interpreter + AArch64 JIT); eBPF verifier gating the load path (CFG, bounds, tnum, pruning, liveness); WCET admission control; BPF signing (enforcement opt-in); VFS + ext2 (read-only); RPi5 GPIO/UART/PWM; VirtIO; shell + basic utilities.

**Not yet:** RPi5 SPI/I²C, USB, full DMA; POSIX compatibility (partial); RISC-V beyond boot.

---

## Limitations

The kernel boots and runs real BPF programs on a Raspberry Pi 5. Several load-bearing pieces are not yet in place; pretending otherwise wastes a reader's time.

**Kernel core:**
- **User-mode page faults panic the kernel** — there is no signal delivery, so a faulting user task takes the kernel with it ([#52](https://github.com/pro-utkarshM/axiomOS/issues/52), [#53](https://github.com/pro-utkarshM/axiomOS/issues/53))
- **No demand paging** — every user page is pre-allocated at process creation; `brk` / `mmap` don't grow lazily ([#54](https://github.com/pro-utkarshM/axiomOS/issues/54))
- **No copy-on-write fork on x86_64** — full page copy; aarch64 path has CoW
- **`sys_nanosleep` busy-spins** — wait queues not yet wired ([#56](https://github.com/pro-utkarshM/axiomOS/issues/56))
- **No POSIX signals** — `kill`, `sigaction`, `SIGSEGV` delivery all absent
- **Boot panics on missing `/bin/init`** — no recovery path ([#55](https://github.com/pro-utkarshM/axiomOS/issues/55))

**Scheduler:**
- **Single global run queue** across all CPUs — work-stealing + per-CPU queues tracked under [#57](https://github.com/pro-utkarshM/axiomOS/issues/57)
- **No priority inheritance** on kernel mutexes — classic priority inversion possible ([#60](https://github.com/pro-utkarshM/axiomOS/issues/60))
- **No `preempt_disable` / `preempt_enable` primitive** — critical sections either use IRQ-disable or hope ([#62](https://github.com/pro-utkarshM/axiomOS/issues/62))
- **EDF scheduling exists for BPF programs only**, not for native OS tasks ([#61](https://github.com/pro-utkarshM/axiomOS/issues/61))

**BPF subsystem:**
- **Unsigned loads accepted by default** — provenance enforcement is wired ([#20](https://github.com/pro-utkarshM/axiomOS/issues/20)) and fails closed on bad signatures, but `allow_unsigned = true` until a userspace signer ships
- **BPF Manager guarded by one global mutex** — every map op / load / attach serializes ([#58](https://github.com/pro-utkarshM/axiomOS/issues/58))
- **BPF-to-BPF calls are supported for the loader's single-section subprogram layout** ([#87](https://github.com/pro-utkarshM/axiomOS/issues/87)); cross-section subprogram linking, BTF integration ([#90](https://github.com/pro-utkarshM/axiomOS/issues/90)), and Spectre mitigations ([#89](https://github.com/pro-utkarshM/axiomOS/issues/89)) remain unsupported
- **WCET admission assumes one nominal 1 kHz fire rate for every hook** — per-hook-type / caller-declared frequencies are future work; PREVAIL head-to-head comparison not yet run

**Memory:**
- **AddressSpace doesn't track per-frame ownership on Drop** — long-running systems with process churn slowly leak physical memory ([#69](https://github.com/pro-utkarshM/axiomOS/issues/69))
- **Task stack isolation FIXME** — stacks in higher half may be cross-writable; security audit pending ([#70](https://github.com/pro-utkarshM/axiomOS/issues/70))

**Drivers:**
- **No I²C, SPI, CAN, or Ethernet drivers** today — only GPIO / PWM / UART on the RP1. Tracked under [#63](https://github.com/pro-utkarshM/axiomOS/issues/63), [#64](https://github.com/pro-utkarshM/axiomOS/issues/64), [#66](https://github.com/pro-utkarshM/axiomOS/issues/66), [#67](https://github.com/pro-utkarshM/axiomOS/issues/67)
- **No hardware watchdog integration** ([#72](https://github.com/pro-utkarshM/axiomOS/issues/72))

**Operations:**
- **No persistent crash dump** ([#73](https://github.com/pro-utkarshM/axiomOS/issues/73)), no A/B kernel slots / rollback ([#75](https://github.com/pro-utkarshM/axiomOS/issues/75)), no hardware-in-loop CI — Pi5 testing is manual ([#76](https://github.com/pro-utkarshM/axiomOS/issues/76))

**Benchmark caveats:**
- Historical interrupt-latency and boot-time comparisons are not current release evidence: their raw captures and artifact hashes were not retained. New multi-core RT claims require the per-CPU run-queue work in [#57](https://github.com/pro-utkarshM/axiomOS/issues/57), a 24h soak with P99/P99.9 histograms ([#74](https://github.com/pro-utkarshM/axiomOS/issues/74)), and attributable comparisons against Zephyr, NuttX, or Linux PREEMPT_RT ([#78](https://github.com/pro-utkarshM/axiomOS/issues/78)).

The full picture lives in [issue #81 — execution roadmap](https://github.com/pro-utkarshM/axiomOS/issues/81). If a feature isn't in the list above, treat it as not yet implemented and check the roadmap before relying on it.

---

## Design Philosophy

axiomos is **not** a production kernel (yet), not POSIX-compliant (by design), and not a Linux replacement. It **is** a research platform for runtime kernel extension, exploring:

1. Can eBPF verification provide sufficient safety for kernel extensions?
2. Does Rust's type system meaningfully reduce kernel bugs in practice?
3. What's the performance overhead of safe abstractions in bare-metal contexts?
4. How minimal can a usable kernel be while supporting dynamic behavior?

---

## Contributing

This is experimental research code. Contributions welcome, especially architecture ports, drivers (USB, DMA, network), eBPF optimizations, and userspace POSIX compatibility.

**Code standards:** all `unsafe` blocks need safety comments; public APIs need documentation; tests for verifiable components; benchmark critical paths.

---

## License

Triple-licensed under MIT, Apache 2.0, and MPL 2.0.

## Author

Utkarsh Maurya  
GitHub: https://github.com/pro-utkarshM  
Email: utkarsh@kernex.sbs

---

**Further reading:**
- [docs/architecture/system-overview.md](docs/architecture/system-overview.md) — normative system layers and links to VM, BPF trust, scheduler, target, and JIT contracts
- [docs/performance/current-results.md](docs/performance/current-results.md) — attributable benchmark campaigns and historical-claim disposition
- [kernel_bpf docs](kernel/crates/kernel_bpf/docs/) — eBPF runtime architecture, scheduling, verification, profiles
