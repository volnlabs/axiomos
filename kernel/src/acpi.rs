use core::ptr::NonNull;

use acpi::{AcpiHandler, AcpiTables, PhysicalMapping};
use conquer_once::spin::OnceCell;
use kernel_virtual_memory::Segment;
use spin::Mutex;

use crate::arch::types::{Page, PageSize, PageTableFlags, PhysAddr, PhysFrame, Size4KiB, VirtAddr};
use crate::limine::RSDP_REQUEST;
use crate::mem::address_space::AddressSpace;
use crate::mem::virt::{VirtualMemoryAllocator, VirtualMemoryHigherHalf};
use crate::U64Ext;

mod mapping;
use mapping::plan_mapping;

static ACPI_TABLES: OnceCell<Mutex<AcpiTables<AcpiHandlerImpl>>> = OnceCell::uninit();

pub fn acpi_tables() -> &'static Mutex<AcpiTables<AcpiHandlerImpl>> {
    ACPI_TABLES
        .get()
        .expect("ACPI tables should be initialized")
}

pub fn init() {
    ACPI_TABLES.init_once(|| {
        let rsdp = PhysAddr::new(RSDP_REQUEST.get_response().unwrap().address() as u64);
        // SAFETY: We trust the RSDP address provided by the Limine bootloader response.
        // The bootloader guarantees this points to a valid RSDP structure.
        let tables = unsafe { AcpiTables::from_rsdp(AcpiHandlerImpl, rsdp.as_u64().into_usize()) }
            .expect("should be able to get ACPI tables from rsdp");

        Mutex::new(tables)
    });
}

#[derive(Debug, Copy, Clone)]
pub struct AcpiHandlerImpl;

impl AcpiHandler for AcpiHandlerImpl {
    // SAFETY: The caller guarantees that the physical range belongs to an ACPI
    // table. This implementation maps every page covering the requested range.
    unsafe fn map_physical_region<T>(
        &self,
        physical_address: usize,
        size: usize,
    ) -> PhysicalMapping<Self, T> {
        let plan = plan_mapping(physical_address, size, size_of::<T>())
            .expect("ACPI physical mapping range must be non-empty and not overflow");
        let segment = VirtualMemoryHigherHalf
            .reserve(plan.page_count)
            .expect("should reserve virtual memory for ACPI mapping");

        let address_space = AddressSpace::kernel();

        // The higher-half allocator does not know which temporary mappings the
        // bootloader left behind, so clear the complete reservation first.
        for index in 0..plan.page_count {
            let page = Page::<Size4KiB>::containing_address(
                segment.start + (index as u64 * Size4KiB::SIZE),
            );
            let _ = address_space.unmap(page);
        }

        let frames = (0..plan.page_count).map(|index| {
            PhysFrame::containing_address(PhysAddr::new(
                (plan.physical_base + index * Size4KiB::SIZE.into_usize()) as u64,
            ))
        });
        address_space
            .map_range::<Size4KiB>(
                &*segment,
                frames,
                PageTableFlags::PRESENT | PageTableFlags::NO_EXECUTE | PageTableFlags::WRITABLE,
            )
            .expect("should map the complete ACPI physical range");

        let virtual_start = segment.start + plan.offset as u64;
        let segment = segment.leak();
        debug_assert_eq!(segment.len.into_usize(), plan.mapped_len);

        // SAFETY: `virtual_start` preserves the physical page offset, and the
        // complete type/requested range is backed by the mapped reservation.
        unsafe {
            PhysicalMapping::new(
                physical_address,
                NonNull::new(virtual_start.as_mut_ptr()).unwrap(),
                size,
                plan.mapped_len,
                Self,
            )
        }
    }

    fn unmap_physical_region<T>(region: &PhysicalMapping<Self, T>) {
        let vaddr = VirtAddr::from_ptr(region.virtual_start().as_ptr());
        let mapping_base = vaddr.align_down(Size4KiB::SIZE);
        let segment = Segment::new(mapping_base, region.mapped_length() as u64);

        let address_space = AddressSpace::kernel();
        // Do not deallocate physical frames: firmware owns ACPI memory.
        address_space.unmap_range::<Size4KiB>(&segment, |_| {});

        // SAFETY: We own this segment (created in map_physical_region) and are now releasing it.
        // It's not used after this point.
        unsafe {
            assert!(VirtualMemoryHigherHalf.release(segment));
        }
    }
}
