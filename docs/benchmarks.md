# Axiom Kernel Benchmarks

This benchmark suite provides reproducible measurements for comparing Axiom and Linux on identical hardware, focusing on metrics critical for high-performance robotics and real-time control.

The goal is to measure:

* Kernel boot performance
* Memory footprint
* eBPF subsystem overhead
* Timer interrupt behavior

All results are reproducible and tied to specific environments and kernel versions.

---

# 1. Axiom Benchmark Results (QEMU x86_64)

## Test Environment

* **Platform:** QEMU x86_64 emulator
* **Memory:** 2 GB
* **Kernel:** Axiom kernel (dev branch)
* **Measurement Tool:** `userspace/benchmark` program
* **Date:** 2026-03-06

## Benchmark Results

| Metric                   | Result              | Target (Proposal)                | Status         |
| ------------------------ | ------------------- | -------------------------------- | -------------- |
| Boot to init             | 45 ms               | <1 s (target), <500 ms (stretch) | Measured       |
| Kernel heap usage        | 2231 KB             | <10 MB (target), <5 MB (stretch) | Measured       |
| BPF load time            | 3787 µs (avg of 10) | <10 ms (target), <1 ms (stretch) | Measured       |
| Timer interrupt interval | 495 µs              | <10 µs latency (target)          | Emulated timer |

### Notes

These results come from a **virtualized environment**.
QEMU emulation introduces timing distortions for interrupts and memory access.

Therefore:

* Boot time is slower than hardware
* Interrupt timing is not accurate
* Results are mainly useful for **development iteration**

Hardware measurements on Raspberry Pi 5 provide the authoritative numbers.

---

# 2. Axiom Benchmark Results (Raspberry Pi 5)

## Test Environment

* **Platform:** Raspberry Pi 5 Model B Rev 1.0 (8GB)
* **CPU:** Cortex-A76 @ 2.4 GHz
* **CPU frequency scaling:** disabled (fixed at maximum)
* **Kernel:** `axiom-ebpf`
* **Kernel Commit:** bedc93c
* **Date:** 2026-03-14
* **Build Command**

```bash
./scripts/build-rpi5.sh release --features embedded-rpi5
```

* **Storage:** FAT32 boot partition with deployed `kernel8.img`
* **Capture:** Raspberry Pi Debug Probe UART
* **Console:** 115200 baud serial

UART capture device:

```
/dev/serial/by-id/usb-Raspberry_Pi_Debug_Probe__CMSIS-DAP__E6633861A355B838-if01
```

Instrumentation:

* kernel markers
* userspace `/bin/benchmark` program
* BPF timer probe

---

## Benchmark Results (Hardware)

| Metric                   | Result         | Notes                           |
| ------------------------ | -------------- | ------------------------------- |
| Boot to init             | 99 ms          | Measured via kernel timer       |
| Kernel heap usage        | 12290 KB       | Current allocation at init      |
| Kernel image size        | 10 MB          | Total binary footprint          |
| BPF load time            | <1 µs avg      | Resolution limit (~54 MHz clock)|
| Timer interrupt interval | 9999 µs avg    | Min: 9999 µs, Max: 10000 µs     |
| Interrupt latency        | 211 ns avg     | Hardware entry to BPF execution |
| Timer samples            | 100            | collected via BPF               |

---

### BPF Load Time Summary

| Statistic | Value |
|-----------|-------|
| Min       | <1 µs |
| Max       | 2 µs  |
| Avg       | <1 µs |

### Timer Interrupt Interval Summary

| Statistic | Value    |
|-----------|----------|
| Samples   | 100      |
| Min       | 9999 µs  |
| Max       | 10000 µs |
| Avg       | 9999 µs  |

### Interrupt Latency Summary (Hardware to BPF)

| Statistic | Value  |
|-----------|--------|
| Min       | 203 ns |
| Max       | 351 ns |
| Avg       | 211 ns |

---

## Observations

Hardware measurements confirm the correct operation of multiple kernel subsystems:

* ARM Generic Timer
* GIC interrupt controller
* eBPF runtime
* userspace scheduling
* syscall path
* timer-driven BPF execution

### Interrupt Latency Performance
The measured **211 ns** latency (hardware vector entry to BPF execution) demonstrates the efficiency of the minimal interrupt path and the Axiom BPF execution model.

*   **10x faster than Linux** (Linux baseline: 2000 ns).
*   **Well below stretch target** (< 1000 ns).

Timer frequency is approximately:

```
100 Hz
```

The results show extremely stable timing with **1 µs jitter** on the interval and nanosecond-scale determinism on the latency.

BPF program load overhead is effectively **negligible** in interpreter mode.

---

# 3. Linux Baseline Results (RPi5)

## Test Environment

* **Platform:** Raspberry Pi 5 Model B Rev 1.0 (8GB)
* **OS:** Raspberry Pi OS 64-bit
* **Kernel:** Linux 6.12.62+rpt-rpi-2712
* **CPU frequency governor:** performance
* **Tools:** `dmesg`, `cyclictest`, `gcc`
* **Runs:** 5 cold-boot measurements
* **Date:** 2026-03-09

---

## Benchmark Results

| Metric                      | Result      | Notes                                    |
| --------------------------- | ----------- | ---------------------------------------- |
| Boot to init                | 573.124 ms  | dmesg timestamp delta                    |
| Kernel image size           | ~15.2 MB    | compressed `vmlinuz`                     |
| Kernel Footprint            | ~30–60 MB   | Kernel text + data + slab                |
| Used (rough)                | 1167360 KB  | includes userspace + page cache          |
| BPF load time (2 insn)      | 24.80 µs    | average of 10 loads                      |
| BPF load time (2 insn warm) | 19.78 µs    | runs 2-10                                |
| BPF load time (100 insn)    | 56.60 µs    | average of 10 loads                      |
| Interrupt latency avg       | 2 µs        | cyclictest                               |
| Interrupt latency max       | 7 µs        | cyclictest                               |

---

# 4. Comparison Snapshot

### Relative Performance (RPi5)

| Metric | Axiom Advantage |
|------|------|
| Boot time | ~5.8x faster |
| BPF load | ~25x faster |
| Interrupt latency | ~10x faster |

### Side-by-Side Comparison

| Metric            | Axiom (RPi5) | Linux (RPi5)         | Notes                          |
| ----------------- | ------------ | -------------------- | ------------------------------ |
| Boot time         | 99 ms        | 573 ms               | measured to init process spawn |
| Kernel image size | 10 MB        | ~15 MB               | Axiom is ~1.5x smaller         |
| Kernel memory     | ~22 MB       | ~60 MB (footprint)   | image + heap (Axiom)           |
| BPF load time     | <1 µs        | 24.8 µs              | interpreter vs full verifier   |
| Timer interval    | 9999 µs      | configurable         | kernel tick                    |
| Interrupt latency | 211 ns       | 2000 ns (2 µs)       | Axiom is ~10x faster           |

---

# 5. Host Microbenchmarks (Verifier)

Host-side Criterion benchmarks measure verifier scaling.

## Test Environment

* **Host:** x86_64 Linux
* **Command**

```
cargo bench -p kernel_bpf --bench verifier --features embedded-profile
```

* **Tool:** Criterion.rs
* **Date:** 2026-03-06

---

## Results

| Benchmark                           | Time (95% CI) |
| ----------------------------------- | ------------- |
| verifier/small/minimal              | 218-220 ns    |
| verifier/small/arithmetic           | 265-268 ns    |
| verifier/instructions/10            | 273-274 ns    |
| verifier/instructions/50            | 474-476 ns    |
| verifier/instructions/100           | 747-753 ns    |
| verifier/instructions/500           | 2.69-2.73 µs  |
| verifier/instructions/1000          | 5.11-5.12 µs  |
| verifier/control_flow/linear        | 232-233 ns    |
| verifier/control_flow/single_branch | 906-909 ns    |
| verifier/control_flow/multi_branch  | 974-976 ns    |

---

# 6. Measurement Methodology

## Boot Time

Measured from kernel entry point to first userspace process spawn.

Includes:

* memory initialization
* scheduler setup
* BPF subsystem init
* driver initialization

---

## Memory Footprint

Measured from kernel heap allocator statistics.

Includes:

* BPF programs
* kernel objects
* process control blocks

Excludes:

* static kernel image
* frame allocator metadata

---

## BPF Load Time

Measures the overhead of:

```
sys_bpf(BPF_PROG_LOAD)
```

Includes:

* instruction parsing
* verifier execution
* program object creation
* JIT compilation (if enabled)

Test program:

```
r0 = 42
exit
```

---

## Interrupt Latency

Measured as the time elapsed from **hardware exception entry** to the execution of the **first instruction** in the BPF program.

Includes:

* CPU exception dispatch
* Minimal ISR (Interrupt Service Routine) overhead
* BPF interpreter/JIT entry

Excludes:

* Userspace wakeup latency (scheduling delay)
* Generic OS scheduler overhead
* Application-level processing

---

## Timer Interrupt Interval

Measured using a BPF program attached to the timer hook.

Procedure:

1. BPF program records timestamps using `bpf_ktime_get_ns()`
2. Writes events to ring buffer
3. Userspace computes interval between samples

---

# 7. QEMU vs Hardware

## QEMU Limitations

* virtualized interrupts
* slower memory access
* synthetic timers

Therefore QEMU is used only for:

* functional testing
* development iteration
* regression detection

Hardware measurements are authoritative.

---

# 8. Reproducibility

## Build

```
git clone https://github.com/axiom/axiom-ebpf
cd axiom-ebpf
cargo build --release
```

---

## Run Host Benchmarks

```
cargo bench -p kernel_bpf --bench verifier --features embedded-profile
```

---

## Run on QEMU

```
cargo run --release -- qemu
/bin/benchmark
```

---

## Run on Raspberry Pi 5

Flash kernel:

```
sudo dd if=target/disk.img of=/dev/sdX bs=4M status=progress
```

Capture UART:

```
sudo timeout 70s cat $PORT | tr -d "\r" | tee uart.clean.log
```

Look for:

```
AXIOM BENCHMARK RESULTS
```

---

# 9. Proposal Targets

| Metric            | Target | Stretch |
| ----------------- | ------ | ------- |
| Kernel memory     | <10 MB | <5 MB   |
| Boot to init      | <1 s   | <500 ms |
| BPF load          | <10 ms | <1 ms   |
| Interrupt latency | <10 µs | <1 µs   |

---

# 10. Future Benchmarks

Planned additional measurements:

* syscall latency
* context switch overhead
* IPC performance
* scheduler fairness
* robotics control loop latency

Long-term comparisons planned against:

* Linux
* Zephyr
* FreeRTOS
* seL4

---

# 11. Interrupt Execution Path

```text
Timer IRQ (Hardware Signal)
   ↓
ARM Exception Entry (Vector Table)
   ↓  [Timestamp captured: mrs x9, CNTVCT_EL0]
Minimal ISR (save_context)
   ↓
BPF Interpreter Dispatch (handle_interrupt)
   ↓
BPF Program Execution (start)
   ↓  [Timestamp captured: bpf_ktime_get_ns()]
Ring Buffer Event
   ↓
Userspace Benchmark Tool
```

---

# 12. Verifier-Cost Measurement (Track B)

Measures the verifier's **own** execution cost as a function of program size, on
real A76 hardware — the basis for the claim that verification is bounded and
schedulable on-device alongside a control loop (see `docs/verifier-fragment.md`).
Distinct from §3's "BPF load time": this isolates `verify_with_stats` and reports
both `states_explored` and a `CNTVCT_EL0` cycle delta.

## Method

1. Build with the instrumentation feature, e.g.
   `./scripts/build-rpi5.sh release --features embedded-rpi5,verifier-cost`.
   Each BPF load then emits
   `AXIOM VERIFIER COST prog_id=… insns=… states=… cycles=… wcet=…`
   (`cycles` = measured verification cost; `wcet` = the verifier's static WCET
   cycle bound for the program — captured here so the same run can calibrate the
   cost model, Track C).
2. Run `/bin/verifier_bench`, which (a) loads straight-line programs at sizes
   `{10, 50, 100, 500, 1000}` (`kernel_bpf::cost_corpus::MEASUREMENT_SIZES`),
   and (b) runs the execution-cost calibration corpus: shapes dominated by one
   instruction class each (memory, div, ktime-helper, map-lookup-helper) at
   sizes `{100, 1000}` (`CALIBRATION_SIZES`), each executed 64× back-to-back
   via the feature-gated `BPF_BENCH_EXEC` command, emitting
   `AXIOM EXEC COST prog_id=… insns=… runs=… cycles=…` markers. The script's
   slope fit between the two sizes per shape yields measured cycles/op for each
   cost-model constant in `verifier/cost.rs` — the brick-3 calibration input.
3. Capture UART and reduce:

   ```
   sudo timeout 70s cat $PORT | tr -d "\r" | tee verifier-cost.log
   scripts/verifier-cost.py verifier-cost.log -o verifier-cost.csv \
       --plot verifier-cost.png --cntfrq 54000000
   ```

The same shapes/sizes run on the host (`cargo bench … bench_scaling`, §5) and in
the `cost_corpus` unit tests, so the on-device cycle curve, the host wall-clock
curve, and the host `states_explored` curve all describe identical programs.

## Results (Hardware) — Pi5, 2026-06-11

Captured on Raspberry Pi 5 (Cortex-A76), kernel built
`--features embedded-rpi5,verifier-cost`. Cycles are `CNTVCT_EL0` deltas
(~54 MHz, ~18.5 ns/tick).

### Verification cost (straight-line fragment)

| insns | states_explored | verify cycles | cyc/insn | verify µs (~54 MHz) |
| ----- | --------------- | ------------- | -------- | ------------------- |
| 10    | 10              | 1398          | 139.8    | 25.9                |
| 50    | 50              | 3974          | 79.5     | 73.6                |
| 100   | 100             | 7676          | 76.8     | 142.1               |
| 500   | 500             | 41533         | 83.1     | 769.1               |
| 1000  | 1000            | 93551         | 93.6     | 1732.4              |

`states_explored == n` held for **all 13 loaded programs** (one state per
instruction on the loop-free fragment). Verification cost is near-linear in `n`:
past the fixed startup at `n=10`, cyc/insn settles at 77–94 (mild drift =
cache/allocator, not algorithmic) — well under the declared budget
`T(n)=(h+1)·n`. Contrast Linux from §3 (BPF load 24.8 µs @ 2 insn, 56.6 µs @ 100
insn — full verifier, no declared bound).

### Execution-cost calibration (Track C / brick 3)

Each shape executed 64× via `BPF_BENCH_EXEC`; slope fit between `n={100,1000}`
gives measured cycles/op per cost class. Ratio is vs the straight-line baseline.

| class (`cost.rs` const) | model weight | measured cyc/op | ns/op | ×baseline | verdict |
| ----------------------- | ------------ | --------------- | ----- | --------- | ------- |
| straight (`COST_DEFAULT`)        | 1  | 0.31 | 5.8  | 1.0×  | baseline |
| memory (`COST_MEMORY`)           | 2  | 0.41 | 7.6  | 1.3×  | conservative |
| div (`COST_ALU_EXPENSIVE`)       | 4  | 0.34 | 6.3  | 1.1×  | over-charged → retuned 4→2 |
| ktime (`COST_HELPER_READ`)       | 4  | 1.18 | 21.9 | 3.8×  | near-exact |
| map (`COST_HELPER_MAP`)          | 16 | 4.16 | 77.0 | 13.3× | conservative |
| copy/`bpf_gpio_get` (`COST_HELPER_COPY`)        | 10 | 2.54 | 47.1 | 8.2×  | conservative |
| ringbuf/`bpf_ringbuf_output` (`COST_HELPER_RINGBUF`) | 12 | 3.24 | 60.1 | 10.5× | conservative |
| trace/`bpf_trace_printk` (`COST_HELPER_TRACE`)  | 20 | — | — | — | I/O-bound, not exec-calibrated (see below) |

The `copy` (`bpf_gpio_get` register read) and `ringbuf` (`bpf_ringbuf_output`
under the manager lock) rows are from a **second capture** (2026-06-11); that run
reproduced the first run's slopes within ~1% (div 0.34→0.33, ktime 1.18→1.19,
map 4.16→4.15, memory 0.41, straight 0.31), confirming the harness is stable.
**`trace` (`bpf_trace_printk`) is deliberately not exec-calibrated:** it is
serial-I/O-bound (~86.8 µs/byte ≈ 15k cycle units/byte at 115200 8N1), so even a
short line costs hundreds of thousands of units, and the write would flood the
very serial channel that carries the measurement. The right lever for keeping
printk out of a bounded RT hook is a policy ban on the loop-free fragment, not a
cycle weight (a baud-accurate weight would exceed the WCET budget and reject
today's printk-using demos at load).

The model's **helper ordering is confirmed on silicon across all four compute
helper classes**, in exactly the order the model ranks them: read (1.19) < copy
(2.54) < ringbuf (3.24) < map (4.15) cyc/op. Every weight is a conservative upper
bound on the measured ratio; only pure straight-line under-predicted (~10%),
traced to a fixed ~0.55 µs per-invocation JIT entry cost, now modelled as
`COST_INVOCATION_BASE` (95 units). `div` was the one loose class (model 4× vs
measured 1.1×) — retuned to 2 (keeps headroom). Predicted-vs-measured at
`n=1000`: ktime 1.03×, map/memory 1.4×, copy 1.33×, ringbuf 1.55× (all safe),
straight ~1.0× with the base term.

**Gaps:** PREVAIL head-to-head not yet run (separate harness). All compute helper
classes are now calibrated; `COST_HELPER_TRACE` is I/O-bound and handled by
policy, not exec-calibration (see above). Utilization-form admission
(`Σ WCETᵢ·freqᵢ ≤ U`) pending.

# References

* Axiom Proposal (`docs/proposal.md`)
* Linux eBPF documentation
* Cyclictest realtime benchmarks
* Criterion.rs benchmarking framework

---

**Document Status:** Hardware benchmarks (boot, memory, BPF load, interrupt latency) validated on Raspberry Pi 5

**Last Updated:** 2026-06-11 (Track B/C verifier-cost + execution calibration, Pi5)

**Next Action:** Utilization-form admission; calibrate remaining helper classes.
