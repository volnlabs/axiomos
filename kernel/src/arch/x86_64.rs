use core::hint::spin_loop;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use x86_64::instructions::port::Port;
use x86_64::instructions::{interrupts, tlb};

use crate::arch::idt::InterruptIndex;
use crate::mcore::context::{online_cpu_mask, online_lapic_id, ExecutionContext};

const MAX_TRACKED_CPUS: usize = 64;
static TLB_SHOOTDOWN_EPOCH: AtomicU64 = AtomicU64::new(0);
static TLB_SHOOTDOWN_REPORTED: AtomicBool = AtomicBool::new(false);
static TLB_SHOOTDOWN_ACKS: [AtomicU64; MAX_TRACKED_CPUS] =
    [const { AtomicU64::new(0) }; MAX_TRACKED_CPUS];

fn acknowledge_latest_tlb_epoch() {
    let Some(context) = ExecutionContext::try_load() else {
        return;
    };
    let epoch = TLB_SHOOTDOWN_EPOCH.load(Ordering::Acquire);
    tlb::flush_all();
    TLB_SHOOTDOWN_ACKS[context.cpu_id()].fetch_max(epoch, Ordering::Release);
}

fn targets_acknowledged(mut targets: u64, epoch: u64) -> bool {
    while targets != 0 {
        let cpu_id = targets.trailing_zeros() as usize;
        if TLB_SHOOTDOWN_ACKS[cpu_id].load(Ordering::Acquire) < epoch {
            return false;
        }
        targets &= targets - 1;
    }
    true
}

pub fn shootdown_tlb(targets: u64) {
    let Some(context) = ExecutionContext::try_load() else {
        tlb::flush_all();
        return;
    };
    let current_cpu = context.cpu_id();
    let current_bit = 1u64 << current_cpu;
    let targets = targets & online_cpu_mask() & !current_bit;
    let epoch = TLB_SHOOTDOWN_EPOCH.fetch_add(1, Ordering::AcqRel) + 1;

    acknowledge_latest_tlb_epoch();
    if targets == 0 {
        return;
    }

    // Keep the LAPIC lock out of interrupt preemption, but do not mask
    // interrupts while waiting for acknowledgements from other CPUs.
    interrupts::without_interrupts(|| {
        let mut lapic = context.lapic().lock();
        let mut remaining = targets;
        // SAFETY: The current CPU owns its LAPIC lock. Only CPUs that published
        // their context and IDT through mark_online are addressed.
        unsafe {
            while remaining != 0 {
                let cpu_id = remaining.trailing_zeros() as usize;
                let lapic_id = online_lapic_id(cpu_id).expect("online CPU must publish LAPIC id");
                lapic.send_ipi(InterruptIndex::TlbShootdown.as_u8(), lapic_id);
                remaining &= remaining - 1;
            }
        }
    });

    while !targets_acknowledged(targets, epoch) {
        // This also breaks simultaneous-shootdown waits when the caller entered
        // with interrupts masked: each sender can acknowledge the other's epoch.
        acknowledge_latest_tlb_epoch();
        spin_loop();
    }

    if !TLB_SHOOTDOWN_REPORTED.swap(true, Ordering::Relaxed) {
        log::info!("TLB_SHOOTDOWN_OK epoch={epoch} targets={targets:#x}");
    }
}

pub fn handle_tlb_shootdown_ipi() {
    acknowledge_latest_tlb_epoch();
}

pub fn shutdown() -> ! {
    let mut port = Port::new(0xf4);
    // SAFETY: We are writing to the QEMU/KVM debug exit port to shut down the system.
    // This is the standard way to trigger a shutdown in QEMU.
    unsafe {
        port.write(0x00_u32);
    }
    loop {
        x86_64::instructions::hlt();
    }
}
