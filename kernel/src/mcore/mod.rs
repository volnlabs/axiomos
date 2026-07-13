#[cfg(target_arch = "x86_64")]
use alloc::boxed::Box;
#[cfg(target_arch = "x86_64")]
use core::sync::atomic::Ordering::{Acquire, Release};

#[cfg(target_arch = "x86_64")]
use log::info;
#[cfg(target_arch = "x86_64")]
use log::trace;
#[cfg(target_arch = "x86_64")]
use x86_64::instructions::segmentation::{CS, DS, SS};
#[cfg(target_arch = "x86_64")]
use x86_64::instructions::tables::load_tss;
#[cfg(target_arch = "x86_64")]
use x86_64::instructions::{hlt, interrupts};
#[cfg(target_arch = "x86_64")]
use x86_64::registers::control::{Cr3, Cr3Flags};
#[cfg(target_arch = "x86_64")]
use x86_64::registers::model_specific::KernelGsBase;
#[cfg(target_arch = "x86_64")]
use x86_64::registers::segmentation::Segment;

#[cfg(target_arch = "x86_64")]
use crate::apic::io_apic;
#[cfg(target_arch = "x86_64")]
use crate::arch::gdt::create_gdt_and_tss;
#[cfg(target_arch = "x86_64")]
use crate::arch::idt::create_idt;
#[cfg(target_arch = "x86_64")]
use crate::arch::types::{PhysAddr, PhysFrame, VirtAddr};
#[cfg(target_arch = "x86_64")]
use crate::limine::MP_REQUEST;
use crate::mcore::mtask::scheduler::cleanup::TaskCleanup;
use crate::mcore::mtask::scheduler::global::GlobalTaskQueue;
use crate::mcore::mtask::scheduler::sleep::TaskSleep;
#[cfg(target_arch = "x86_64")]
use crate::sse;

pub mod context;
#[cfg(target_arch = "x86_64")]
use crate::mcore::context::ExecutionContext;
#[cfg(target_arch = "x86_64")]
mod lapic;
pub mod mtask;

#[allow(clippy::missing_panics_doc)]
pub fn init() {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: We need to get the mutable response to write to the `extra` field.
        // This is done during initialization before other CPUs are fully brought up
        // and accessing this data, ensuring exclusive access.
        let resp = unsafe {
            #[allow(static_mut_refs)] // we need this to set the `extra` field in the CPU structs
            MP_REQUEST.get_response_mut()
        }
        .unwrap();

        let extra_val = {
            let (frame, flags) = Cr3::read();
            frame.start_address().as_u64() | flags.bits()
        };

        // set the extra field in the CPU structs to the CR3 value (or other arch-specific data)
        resp.cpus().iter().for_each(|cpu| {
            cpu.extra.store(extra_val, Release);
        });

        GlobalTaskQueue::init();
        TaskSleep::init();

        // then call the `cpu_init` function on each CPU (no-op on bootstrap CPU)
        resp.cpus().iter().skip(1).for_each(|cpu| {
            cpu.goto_address.write(cpu_init_and_idle);
        });

        // then call the `cpu_init` function on the bootstrap CPU
        // SAFETY: We are initializing the BSP (Bootstrap Processor).
        // The pointer to the CPU struct is valid as it comes from Limine.
        unsafe { cpu_init_and_return(resp.cpus()[0]) };
    }

    #[cfg(target_arch = "aarch64")]
    {
        GlobalTaskQueue::init();
        TaskSleep::init();
    }

    TaskCleanup::init();
}

// SAFETY: This function initializes a CPU. It is unsafe because it modifies global state
// and performs low-level initialization (CR3, GDT, IDT, etc.).
#[cfg(target_arch = "x86_64")]
unsafe extern "C" fn cpu_init_and_return(cpu: &limine::mp::Cpu) {
    let _cpu_arg = cpu.extra.load(Acquire);
    trace!("booting cpu {} with argument {}", cpu.id, _cpu_arg,);

    #[cfg(target_arch = "x86_64")]
    {
        // set the memory mapping that we got as a parameter
        // SAFETY: We are loading the CR3 register with the value passed from the BSP.
        // This switches the address space for this CPU.
        unsafe {
            let flags = Cr3Flags::from_bits_truncate(_cpu_arg);
            Cr3::write(
                PhysFrame::containing_address(PhysAddr::new(_cpu_arg)),
                flags,
            );
        }

        // set up the GDT
        let (gdt, sel, tss) = create_gdt_and_tss();
        let gdt = Box::leak(Box::new(gdt));
        gdt.load();
        // SAFETY: We are setting the segment registers to the selectors we just created.
        // The GDT has been loaded, so these selectors are valid.
        unsafe {
            CS::set_reg(sel.kernel_code);
            DS::set_reg(sel.kernel_data);
            SS::set_reg(sel.kernel_data);
            load_tss(sel.tss);
        }

        // set up the IDT
        let idt = create_idt();
        let idt = Box::leak(Box::new(idt));
        idt.load();

        let lapic = lapic::init();

        // create the execution context for the CPU and store it
        {
            let ctx = ExecutionContext::new(cpu, gdt, sel, idt, tss, lapic);
            let addr = VirtAddr::from_ptr(Box::leak(Box::new(ctx)));
            KernelGsBase::write(addr);
        }

        sse::init();

        init_interrupts();
    }

    #[cfg(target_arch = "aarch64")]
    {
        // On AArch64, much of the initialization (page tables, vector table) is done
        // in arch::aarch64::init() which is called before this for the BSP.
        // For APs, we might need more setup (TODO).

        // Create execution context and store in TPIDR_EL1
        let ctx = ExecutionContext::new(cpu.id as usize);
        let ctx_ptr = Box::leak(Box::new(ctx)) as *const _ as u64;

        // SAFETY: Writing to TPIDR_EL1 is safe.
        unsafe {
            core::arch::asm!("msr tpidr_el1, {}", in(reg) ctx_ptr);
        }
    }

    // load it back and print a message
    let ctx = ExecutionContext::load();
    ctx.mark_online();
    info!("cpu {} initialized", ctx.cpu_id());

    #[cfg(target_arch = "x86_64")]
    interrupts::enable();
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("msr daifclr, #2"); // Enable IRQs
    }
}

// SAFETY: This is the entry point for APs (Application Processors).
// It initializes the CPU and then enters the idle loop.
#[cfg(target_arch = "x86_64")]
unsafe extern "C" fn cpu_init_and_idle(cpu: &limine::mp::Cpu) -> ! {
    // SAFETY: Initialize the CPU. The pointer is valid from Limine.
    unsafe { cpu_init_and_return(cpu) };

    turn_idle()
}

/// Makes the current task an idle task.
///
/// This adapts the current task priority and affinity.
pub fn turn_idle() -> ! {
    // This is an idle-task now.
    // TODO: pin this task to this CPU
    // TODO: make this task lowest (idle) priority, so that it doesn't get scheduled if there are any other tasks
    loop {
        #[cfg(target_arch = "x86_64")]
        hlt();
        #[cfg(target_arch = "aarch64")]
        unsafe {
            core::arch::asm!("wfi");
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn init_interrupts() {
    let mut io_apic = io_apic().lock();
    // SAFETY: Initializing the IO APIC. The offset is chosen to avoid conflicts with exceptions.
    unsafe {
        const OFFSET: u8 = 32;
        io_apic.init(OFFSET);

        // TODO: redirect interrupt vectors

        // for vector in 0..u8::MAX - OFFSET {
        //     let mut entry = RedirectionTableEntry::default();
        //     entry.set_mode(IrqMode::Fixed);
        //     entry.set_flags(IrqFlags::LEVEL_TRIGGERED | IrqFlags::LOW_ACTIVE);
        //     entry.set_vector(vector);
        //     entry.set_dest(u8::try_from(lapic_id).expect("invalid lapic id"));
        //
        //     io_apic.set_table_entry(vector, entry);
        //     io_apic.enable_irq(vector);
        // }
    }
}
