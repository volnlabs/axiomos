//! Secondary CPU bring-up (issue #59, child issue A+B).
//!
//! Core 0 stashes its MMU register values, cleans them to the point of
//! coherency, then PSCI-`CPU_ON`s each secondary at `secondary_start`
//! (boot.S). The secondary joins the shared address space *in assembly*
//! before its first stack write — with caches off, stack writes would
//! bypass coherency and core 0's dirty cache lines could clobber them,
//! and load/store-exclusives on non-cacheable memory are UNPREDICTABLE.
//! Only once the MMU and caches are on does it call [`secondary_rust`].
//!
//! Secondaries come up with their own GICC, banked timer PPI, and
//! `TPIDR_EL1` context, then idle.
// ponytail: secondaries service their own timer but do NOT schedule tasks
// or run BPF timer hooks — that stays on CPU 0 until #40 (scheduler SMP
// safety) and #58 (BpfManager locking) land.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::cpu::MAX_CPUS;
use super::{cpu, gic, interrupts, psci};

/// MMU register values for secondaries to apply before enabling the MMU.
/// Written by core 0, read by secondaries with caches off — keep it in one
/// cache line and clean it to PoC after writing.
#[repr(C, align(64))]
struct SecondaryMmuRegs {
    mair: u64,
    tcr: u64,
    ttbr0: u64,
    ttbr1: u64,
}

#[unsafe(no_mangle)]
static mut SECONDARY_MMU_REGS: SecondaryMmuRegs = SecondaryMmuRegs {
    mair: 0,
    tcr: 0,
    ttbr0: 0,
    ttbr1: 0,
};

/// Number of CPUs that completed per-CPU init (core 0 counts itself).
pub static CPUS_ONLINE: AtomicU32 = AtomicU32::new(1);

/// Timer ticks observed per CPU (secondaries only bump their own slot).
pub static TIMER_TICKS: [AtomicU64; MAX_CPUS] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

/// Bring all secondary CPUs online via PSCI `CPU_ON`. Non-fatal: failures
/// are logged and the system continues on the cores that did come up.
///
/// Must be called on core 0 after the heap and interrupts are initialized
/// (secondaries allocate their `ExecutionContext` and log during init).
pub fn bring_up_secondary_cpus() {
    unsafe extern "C" {
        fn secondary_start();
    }

    // Stash core 0's MMU configuration for the secondaries and clean the
    // line to PoC so their non-cacheable reads see it.
    // SAFETY: Single writer (core 0), written strictly before any CPU_ON;
    // secondaries only read it.
    unsafe {
        let regs = &raw mut SECONDARY_MMU_REGS;
        let (mut mair, mut tcr, mut ttbr0, mut ttbr1): (u64, u64, u64, u64);
        core::arch::asm!(
            "mrs {}, mair_el1",
            "mrs {}, tcr_el1",
            "mrs {}, ttbr0_el1",
            "mrs {}, ttbr1_el1",
            out(reg) mair, out(reg) tcr, out(reg) ttbr0, out(reg) ttbr1,
            options(nostack, preserves_flags)
        );
        (*regs).mair = mair;
        (*regs).tcr = tcr;
        (*regs).ttbr0 = ttbr0;
        (*regs).ttbr1 = ttbr1;
        core::arch::asm!(
            "dc cvac, {}",
            "dsb sy",
            in(reg) regs as usize,
            options(nostack, preserves_flags)
        );
    }

    let entry = secondary_start as *const () as u64;
    let mut started = 0u32;
    for cpu_num in 1..MAX_CPUS as u64 {
        let ret = psci::cpu_on(cpu_num, entry, 0);
        match ret {
            psci::SUCCESS => {
                started += 1;
                log::info!("SMP: CPU_ON cpu{} issued", cpu_num);
            }
            psci::ALREADY_ON => log::warn!("SMP: cpu{} already on", cpu_num),
            e => log::warn!("SMP: CPU_ON cpu{} failed: {}", cpu_num, e),
        }
    }
    if started == 0 {
        log::info!("SMP: 1/{} CPUs online", MAX_CPUS);
        return;
    }

    // Bounded wait (~200ms) for secondaries to reach post-init.
    let (freq, start): (u64, u64) = unsafe {
        let (f, s): (u64, u64);
        core::arch::asm!(
            "mrs {}, cntfrq_el0",
            "mrs {}, cntvct_el0",
            out(reg) f, out(reg) s,
            options(nostack, preserves_flags)
        );
        (f, s)
    };
    let deadline = start + freq / 5;
    while CPUS_ONLINE.load(Ordering::Acquire) < MAX_CPUS as u32 {
        let now: u64 = unsafe {
            let n: u64;
            core::arch::asm!("mrs {}, cntvct_el0", out(reg) n, options(nostack, preserves_flags));
            n
        };
        if now >= deadline {
            break;
        }
        core::hint::spin_loop();
    }

    log::info!(
        "SMP: {}/{} CPUs online",
        CPUS_ONLINE.load(Ordering::Acquire),
        MAX_CPUS
    );

    // ponytail: assumes online secondaries are contiguous from cpu1, which
    // holds for QEMU virt and Pi 5 (PSCI either boots a core or the count
    // stops there). Track a per-CPU online mask if that ever changes.
    ipi_self_test();
}

/// Rust entry for secondary CPUs. Called from `secondary_start` (boot.S)
/// with MMU + caches already on, running on this CPU's dedicated stack,
/// exception vectors installed, all interrupts still masked.
#[unsafe(no_mangle)]
pub extern "C" fn secondary_rust() -> ! {
    let cpu_id = cpu::cpu_id();

    // Per-CPU context (TPIDR_EL1) — logs the post-init marker for #59.
    cpu::init_current_cpu(cpu_id);

    // Per-CPU GIC CPU interface + banked SGI/PPI group config.
    gic::init_per_cpu();

    // Banked PPI enable + per-CPU generic timer.
    gic::enable_irq(gic::irq::TIMER_PHYS);
    gic::set_priority(gic::irq::TIMER_PHYS, 0x80);
    interrupts::init_timer();

    CPUS_ONLINE.fetch_add(1, Ordering::Release);

    // SAFETY: Per-CPU init is complete; unmask IRQs on this core.
    unsafe {
        core::arch::asm!("msr daifclr, #2", options(nostack, preserves_flags));
    }

    loop {
        // SAFETY: wfi in an idle loop is always safe.
        unsafe {
            core::arch::asm!("wfi", options(nostack, preserves_flags));
        }
    }
}

/// Called from the IRQ path when a secondary CPU's timer fires.
pub fn note_secondary_tick(cpu_id: usize) {
    let ticks = TIMER_TICKS[cpu_id].fetch_add(1, Ordering::Relaxed) + 1;
    if ticks == 1 {
        log::info!("SMP: cpu{} timer ticking", cpu_id);
    }
}

/// IPIs received per CPU.
pub static IPI_COUNTS: [AtomicU64; MAX_CPUS] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

/// Called from the IRQ path when an SGI (IPI) arrives on this CPU.
pub fn note_ipi(cpu_id: usize, _sgi_id: u32) {
    IPI_COUNTS[cpu_id].fetch_add(1, Ordering::Release);
}

/// Send a reschedule IPI from this CPU to each online secondary and verify
/// receipt (bounded ~10ms per CPU). Boot-time diagnostic for the #59 IPI
/// acceptance test.
fn ipi_self_test() {
    let freq: u64 = unsafe {
        let f: u64;
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) f, options(nostack, preserves_flags));
        f
    };

    for cpu_num in 1..CPUS_ONLINE.load(Ordering::Acquire) as usize {
        let before = IPI_COUNTS[cpu_num].load(Ordering::Acquire);
        gic::send_sgi(cpu_num as u32, gic::sgi::RESCHEDULE);

        let start: u64 = unsafe {
            let s: u64;
            core::arch::asm!("mrs {}, cntvct_el0", out(reg) s, options(nostack, preserves_flags));
            s
        };
        let deadline = start + freq / 100;
        let mut acked = false;
        while !acked {
            acked = IPI_COUNTS[cpu_num].load(Ordering::Acquire) > before;
            let now: u64 = unsafe {
                let n: u64;
                core::arch::asm!("mrs {}, cntvct_el0", out(reg) n, options(nostack, preserves_flags));
                n
            };
            if now >= deadline {
                break;
            }
            core::hint::spin_loop();
        }

        if acked {
            log::info!("SMP: IPI cpu0->cpu{} acked", cpu_num);
        } else {
            log::warn!("SMP: IPI cpu0->cpu{} NOT acked", cpu_num);
        }
    }
}
