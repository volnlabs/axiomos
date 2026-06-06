//! JIT Memory Allocation
//!
//! Provides functions to allocate executable memory for BPF JIT compilation.
//! These functions are exposed via `extern "C"` so they can be linked against
//! by the `kernel_bpf` crate which does not depend on the kernel directly.

#[cfg(target_arch = "aarch64")]
pub mod aarch64 {
    use core::sync::atomic::{AtomicUsize, Ordering};

    use crate::arch::aarch64::mem::{pte_flags, PAGE_SIZE};
    use crate::arch::aarch64::paging::PageTableWalker;
    use crate::arch::aarch64::{mm, phys};

    // Dedicated region for BPF JIT programs: 0xFFFF_FFFF_9000_0000 (256MB)
    // This is below the kernel image and MMIO.
    const BPF_JIT_START: usize = 0xFFFF_FFFF_9000_0000;
    const BPF_JIT_SIZE: usize = 256 * 1024 * 1024;
    const BPF_JIT_END: usize = BPF_JIT_START + BPF_JIT_SIZE;

    // Simple bump allocator for JIT memory
    // In a real system, we'd use a proper bitmap or slab allocator
    static JIT_OFFSET: AtomicUsize = AtomicUsize::new(0);

    /// Allocate executable memory
    ///
    /// # Safety
    /// This function performs raw memory mapping and returns a raw pointer.
    #[no_mangle]
    pub unsafe extern "C" fn bpf_jit_alloc_exec(size: usize) -> *mut u8 {
        if size == 0 {
            return core::ptr::null_mut();
        }

        let pages_needed = size.div_ceil(PAGE_SIZE);
        let alloc_size = pages_needed * PAGE_SIZE;

        // Reserve virtual address space
        let offset = JIT_OFFSET.fetch_add(alloc_size, Ordering::SeqCst);
        let virt_addr = BPF_JIT_START + offset;

        if virt_addr + alloc_size >= BPF_JIT_END {
            log::error!("BPF JIT OOM: exhausted virtual space");
            return core::ptr::null_mut();
        }

        // Allocate and map pages
        // For JIT, we map as RWX initially to simplify writing code and executing it.
        // In a strictly secure system, we would map RW, write, then remap RX.
        // Or map RW, write, then remap RX.
        // Since we are inside the kernel and this is an "MVP", RWX is acceptable but discouraged.
        // Let's stick to RWX for now to avoid complex remapping logic in the first pass.
        let flags = pte_flags::KERNEL_RWX;

        // We need a walker to map the pages
        let l0_phys = mm::kernel_page_table_phys();
        // We create a temporary walker on the current L0 table
        // This assumes we are running on the kernel page table or one that shares kernel mappings
        let mut walker = PageTableWalker::new(l0_phys as *mut _);

        for i in 0..pages_needed {
            let page_addr = virt_addr + i * PAGE_SIZE;

            // Allocate physical frame
            let frame = match phys::allocate_frame::<crate::arch::types::Size4KiB>() {
                Some(f) => f,
                None => {
                    log::error!("BPF JIT OOM: physical allocation failed");
                    // TODO: Rollback previous allocations
                    return core::ptr::null_mut();
                }
            };

            // Map the page
            if let Err(e) = walker.map_page(page_addr, frame.addr() as usize, flags) {
                log::error!("BPF JIT Map failed: {}", e);
                // TODO: Rollback
                return core::ptr::null_mut();
            }
        }

        // Flush TLB for this range to ensure new mappings are visible
        // We loop through pages and flush
        for i in 0..pages_needed {
            crate::arch::aarch64::paging::flush_tlb_page(virt_addr + i * PAGE_SIZE);
        }

        virt_addr as *mut u8
    }

    /// Free executable memory
    ///
    /// # Safety
    /// The pointer must have been allocated by `bpf_jit_alloc_exec`.
    #[no_mangle]
    pub unsafe extern "C" fn bpf_jit_free_exec(_ptr: *mut u8, _size: usize) {
        // Implementation TODO:
        // In a bump allocator, we can't easily free individual allocations.
        // For a proof of concept, we just leak the memory.
        // A proper implementation would use a free list or bitmap.
        log::warn!("bpf_jit_free_exec: leaking memory (bump allocator implementation)");
    }
}

#[cfg(not(target_arch = "aarch64"))]
pub mod generic {
    // Stub for non-aarch64 architectures or use existing memory manager

    /// Allocates executable memory for JIT-compiled BPF code.
    ///
    /// # Safety
    /// This function is a stub for non-aarch64 architectures and always returns null.
    #[no_mangle]
    pub unsafe extern "C" fn bpf_jit_alloc_exec(_size: usize) -> *mut u8 {
        core::ptr::null_mut()
    }

    /// Frees executable memory previously allocated by `bpf_jit_alloc_exec`.
    ///
    /// # Safety
    /// This function is a stub for non-aarch64 architectures and performs no operation.
    #[no_mangle]
    pub unsafe extern "C" fn bpf_jit_free_exec(_ptr: *mut u8, _size: usize) {}
}
