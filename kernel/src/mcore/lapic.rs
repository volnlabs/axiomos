use core::hint::spin_loop;
use core::ops::{Deref, DerefMut};
use core::ptr::{read_volatile, write_volatile};

use x2apic::lapic::{xapic_base, LocalApicBuilder, TimerDivide, TimerMode};
use x86_64::registers::model_specific::Msr;
use x86_64::structures::paging::{Page, PageTableFlags, PhysFrame, Size4KiB};
use x86_64::PhysAddr;

use crate::arch::idt::InterruptIndex;
use crate::mem::address_space::AddressSpace;
use crate::mem::virt::{OwnedSegment, VirtualMemoryAllocator, VirtualMemoryHigherHalf};

#[derive(Debug)]
pub struct Lapic {
    _segment: OwnedSegment<'static>,
    inner: x2apic::lapic::LocalApic,
}

impl Deref for Lapic {
    type Target = x2apic::lapic::LocalApic;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for Lapic {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl Lapic {
    /// Send a fixed, edge-triggered IPI to one physical APIC destination.
    ///
    /// # Safety
    ///
    /// The destination must identify a CPU whose LAPIC and interrupt handler
    /// are online. The caller must serialize access to this local APIC.
    pub unsafe fn send_ipi(&mut self, vector: u8, destination: u32) {
        const IA32_APIC_BASE: u32 = 0x1b;
        const X2APIC_ENABLE: u64 = 1 << 10;
        const XAPIC_ICR_LOW: u64 = 0x300;
        const XAPIC_ICR_HIGH: u64 = 0x310;
        const ICR_DELIVERY_PENDING: u32 = 1 << 12;

        // x2apic 0.5.0 encodes the destination correctly for x2APIC MSRs, but
        // writes an unshifted destination into xAPIC's ICR-high register. Keep
        // the dependency's x2APIC path and encode xAPIC's bits 24..=31 here.
        // SAFETY: These are the architectural LAPIC mode and ICR interfaces.
        // `_segment` owns the mapped xAPIC page for this CPU, and the caller
        // guarantees exclusive LAPIC access and a live destination.
        unsafe {
            if Msr::new(IA32_APIC_BASE).read() & X2APIC_ENABLE != 0 {
                self.inner.send_ipi(vector, destination);
                return;
            }

            let destination = u8::try_from(destination)
                .expect("xAPIC physical destination must fit in eight bits");
            let base = self._segment.start.as_u64();
            let icr_low = (base + XAPIC_ICR_LOW) as *mut u32;
            let icr_high = (base + XAPIC_ICR_HIGH) as *mut u32;
            while read_volatile(icr_low) & ICR_DELIVERY_PENDING != 0 {
                spin_loop();
            }
            write_volatile(icr_high, u32::from(destination) << 24);
            write_volatile(icr_low, u32::from(vector));
        }
    }
}

pub fn init() -> Lapic {
    // SAFETY: We are initializing the LAPIC, so reading the base address is necessary and safe
    // as we trust the hardware/bootloader configuration at this stage.
    let xapic_base = unsafe { xapic_base() };
    let phys_addr = PhysAddr::new(xapic_base);
    let frame = PhysFrame::containing_address(phys_addr);

    let segment = VirtualMemoryHigherHalf
        .reserve(1)
        .expect("should have enough virtual memory for LAPIC");
    let virt_page = Page::containing_address(segment.start);

    let address_space = AddressSpace::kernel();

    // Unmap first in case bootloader left something mapped here
    // (ignore errors if nothing was mapped)
    let _ = address_space.unmap(virt_page);

    // Now map our LAPIC region
    address_space
        .map::<Size4KiB>(
            virt_page,
            frame,
            PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::NO_CACHE
                | PageTableFlags::NO_EXECUTE,
        )
        .expect("should be able to map LAPIC region after unmapping");

    let mut lapic = LocalApicBuilder::new()
        .timer_vector(InterruptIndex::Timer.as_usize())
        .error_vector(InterruptIndex::LapicErr.as_usize())
        .spurious_vector(InterruptIndex::Spurious.as_usize())
        .set_xapic_base(segment.start.as_u64())
        .timer_mode(TimerMode::Periodic)
        .timer_initial(312_500)
        .timer_divide(TimerDivide::Div16)
        .build()
        .expect("should be able to build lapic");

    // SAFETY: Enabling the LAPIC is safe as we have configured it correctly above.
    unsafe {
        lapic.enable();
    }

    Lapic {
        _segment: segment,
        inner: lapic,
    }
}
