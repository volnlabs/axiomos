use core::ffi::c_void;
use core::fmt::{Debug, Formatter};
use core::mem::size_of;
#[cfg(target_arch = "x86_64")]
use core::slice::from_raw_parts_mut;

use kernel_virtual_memory::Segment;
use thiserror::Error;
#[cfg(target_arch = "x86_64")]
use x86_64::registers::rflags::RFlags;

#[cfg(target_arch = "aarch64")]
use crate::arch::aarch64::context::init_task_stack_with_arg;
#[cfg(target_arch = "aarch64")]
use crate::arch::PageRangeInclusive;
use crate::arch::{
    restore_user_context, PageSize, PageTableFlags, Size4KiB, UserContext, VirtAddr,
};
use crate::mem::address_space::AddressSpace;
#[cfg(target_arch = "x86_64")]
use crate::mem::phys::PhysicalMemory;
use crate::mem::virt::{OwnedSegment, VirtualMemoryAllocator, VirtualMemoryHigherHalf};
#[cfg(target_arch = "x86_64")]
use crate::{U64Ext, UsizeExt};

#[derive(Debug, Copy, Clone, Error)]
pub enum StackAllocationError {
    #[error("out of virtual memory")]
    OutOfVirtualMemory,
    #[error("out of physical memory")]
    OutOfPhysicalMemory,
}

pub struct HigherHalfStack {
    segment: OwnedSegment<'static>,
    mapped_segment: Segment,
    rsp: VirtAddr,
}

impl Debug for HigherHalfStack {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Stack")
            .field("segment", &self.segment)
            .finish_non_exhaustive()
    }
}

impl Drop for HigherHalfStack {
    fn drop(&mut self) {
        let address_space = AddressSpace::kernel();
        address_space.with_active(|address_space| {
            #[cfg(target_arch = "x86_64")]
            address_space.unmap_range::<Size4KiB>(&*self.segment, PhysicalMemory::deallocate_frame);
            #[cfg(target_arch = "aarch64")]
            {
                let page_range = PageRangeInclusive::<Size4KiB>::from(&*self.segment);
                address_space.unmap_range::<Size4KiB>(page_range, |frame| {
                    crate::mem::phys::PhysicalMemory::deallocate_frame(frame);
                });
            }
        });
    }
}

impl HigherHalfStack {
    /// Allocates a new stack with the given number of pages.
    ///
    /// # Errors
    /// Returns an error if stack memory couldn't be allocated, either
    /// physical or virtual.
    pub fn allocate(
        pages: usize,
        entry_point: extern "C" fn(*mut c_void),
        arg: *mut c_void,
        exit_fn: extern "C" fn(),
    ) -> Result<Self, StackAllocationError> {
        log::info!(
            "HigherHalfStack::allocate: pages={}, entry_point={:p}, arg={:p}",
            pages,
            entry_point,
            arg
        );
        let mut stack = Self::allocate_plain(pages)?;
        let mapped_segment = stack.mapped_segment;

        #[cfg(target_arch = "x86_64")]
        {
            // set up stack
            let entry_point_ptr = (entry_point as *const ()).cast::<usize>();
            // SAFETY: The mapped segment is valid memory allocated for the stack.
            // We have exclusive access to it during initialization.
            let slice = unsafe {
                from_raw_parts_mut(
                    mapped_segment.start.as_mut_ptr::<u8>(),
                    mapped_segment.len.into_usize(),
                )
            };
            slice.fill(0xCD);

            let mut writer = StackWriter::new(slice);
            writer.push(0xDEAD_BEEF_0BAD_F00D_DEAD_BEEF_0BAD_F00D_u128); // marker at stack bottom
            debug_assert_eq!(size_of_val(&exit_fn), size_of::<u64>());
            writer.push(exit_fn);
            let rsp = writer.offset - size_of::<Registers>();
            writer.push(Registers {
                rsp,
                rbp: 0,
                rdi: arg as usize,
                rip: entry_point_ptr as usize,
                rflags: (RFlags::IOPL_LOW | RFlags::INTERRUPT_FLAG)
                    .bits()
                    .into_usize(),
                ..Default::default()
            });

            stack.rsp = mapped_segment.start + rsp.into_u64();
        }

        #[cfg(target_arch = "aarch64")]
        {
            let stack_top = (mapped_segment.start + mapped_segment.len).as_u64() as usize;
            let entry_point_addr = entry_point as usize;
            let arg_addr = arg as usize;
            let exit_addr = exit_fn as usize;

            let rsp = init_task_stack_with_arg(stack_top, entry_point_addr, arg_addr, exit_addr);
            stack.rsp = VirtAddr::new(rsp as u64);
        }

        log::info!(
            "HigherHalfStack::allocate: stack initialized, rsp={:p}",
            stack.rsp.as_ptr::<()>()
        );
        Ok(stack)
    }

    /// Allocates a new stack for a forked task.
    ///
    /// The stack will be initialized such that when the task is switched to,
    /// it will execute `restore_user_context` with the provided `user_context`.
    pub fn allocate_fork(
        pages: usize,
        user_context: &UserContext,
    ) -> Result<Self, StackAllocationError> {
        log::info!("HigherHalfStack::allocate_fork: pages={}", pages);
        let mut stack = Self::allocate_plain(pages)?;
        let mapped_segment = stack.mapped_segment;

        #[cfg(target_arch = "x86_64")]
        {
            let entry_point = restore_user_context;
            // SAFETY: The mapped segment is valid memory allocated for the stack.
            // We have exclusive access to it during initialization.
            let slice = unsafe {
                from_raw_parts_mut(
                    mapped_segment.start.as_mut_ptr::<u8>(),
                    mapped_segment.len.into_usize(),
                )
            };
            slice.fill(0xCD);

            let mut writer = StackWriter::new(slice);

            // 1. Push UserContext data
            writer.push(*user_context);
            // Calculate the address of the pushed context
            let context_addr = mapped_segment.start + writer.offset as u64;

            // 2. Push return address (dummy, since restore_user_context doesn't return)
            writer.push(0usize);

            // 3. Push Registers for switch_impl
            let rsp = writer.offset - size_of::<Registers>();
            writer.push(Registers {
                rsp,
                rbp: 0,
                rdi: context_addr.as_u64() as usize, // arg1 for restore_user_context
                rip: entry_point as *const () as usize, // Return address for switch_impl
                rflags: (RFlags::IOPL_LOW | RFlags::INTERRUPT_FLAG)
                    .bits()
                    .into_usize(),
                ..Default::default()
            });

            stack.rsp = mapped_segment.start + rsp.into_u64();
        }

        #[cfg(target_arch = "aarch64")]
        {
            let stack_top = (mapped_segment.start + mapped_segment.len).as_u64() as usize;

            // 1. Write UserContext to the top of the stack
            let context_size = size_of::<UserContext>();
            // Align to 16 bytes
            let context_addr = (stack_top - context_size) & !0xF;

            unsafe {
                let ptr = context_addr as *mut UserContext;
                ptr.write(*user_context);
            }

            // 2. Initialize stack with trampoline
            let entry_point_addr = restore_user_context as *const () as usize;
            let arg_addr = context_addr;
            let exit_addr = 0; // restore_user_context does not return

            let rsp = init_task_stack_with_arg(context_addr, entry_point_addr, arg_addr, exit_addr);
            stack.rsp = VirtAddr::new(rsp as u64);
        }

        Ok(stack)
    }

    /// Allocates a plain, unmodified stack with the given number of 4KiB pages.
    /// The stack will be mapped according to the given arguments.
    ///
    /// One page is reserved for the guard page, which is not mapped. It is at the
    /// bottom of the stack. This implies that for `pages` pages, the usable stack
    /// size is `pages - 1`.
    ///
    /// # Errors
    /// Returns an error if stack memory couldn't be allocated, either
    /// physical or virtual, or if mapping failed.
    pub fn allocate_plain(pages: usize) -> Result<Self, StackAllocationError> {
        log::info!("HigherHalfStack::allocate_plain: pages={}", pages);
        let segment = VirtualMemoryHigherHalf
            .reserve(pages)
            .ok_or(StackAllocationError::OutOfVirtualMemory)?;

        log::info!(
            "HigherHalfStack::allocate_plain: segment reserved: {:?}",
            *segment
        );

        let mapped_segment =
            Segment::new(segment.start + Size4KiB::SIZE, segment.len - Size4KiB::SIZE);

        AddressSpace::kernel().with_active(|address_space| {
            #[cfg(target_arch = "x86_64")]
            {
                address_space
                    .map_range::<Size4KiB>(
                        &mapped_segment,
                        PhysicalMemory::allocate_frames_non_contiguous(),
                        // FIXME: must be user accessible for user tasks, but can only be user accessible if in lower half, otherwise it can be modified by unrelated tasks/processes
                        PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
                    )
                    .map_err(|_| StackAllocationError::OutOfPhysicalMemory)
            }
            #[cfg(target_arch = "aarch64")]
            {
                log::info!("HigherHalfStack::allocate_plain: mapping range...");
                let frames = crate::arch::aarch64::phys::allocate_frames(
                    (mapped_segment.len / Size4KiB::SIZE) as usize,
                )
                .expect("out of phys memory");
                let res = address_space
                    .map_range::<Size4KiB>(
                        &mapped_segment,
                        frames.into_iter(),
                        PageTableFlags::PRESENT
                            | PageTableFlags::WRITABLE
                            | PageTableFlags::NO_EXECUTE,
                    )
                    .map_err(|_| StackAllocationError::OutOfPhysicalMemory);
                log::info!("HigherHalfStack::allocate_plain: range mapped");
                res
            }
        })?;
        let rsp = mapped_segment.start + mapped_segment.len;
        Ok(Self {
            segment,
            mapped_segment,
            rsp,
        })
    }
}

impl HigherHalfStack {
    #[must_use]
    pub fn initial_rsp(&self) -> VirtAddr {
        self.rsp
    }

    /// Returns the segment of the guard page, which is the lowest page of the stack segment.
    #[must_use]
    pub fn guard_page(&self) -> Segment {
        Segment::new(self.segment.start, Size4KiB::SIZE)
    }

    /// Returns the full stack segment, including the guard page (which is not mapped).
    pub fn segment(&self) -> &OwnedSegment<'_> {
        &self.segment
    }

    /// Returns the mapped segment, which is the part of the stack that is actually mapped in memory.
    #[must_use]
    pub fn mapped_segment(&self) -> Segment {
        self.mapped_segment
    }
}

#[cfg(target_arch = "x86_64")]
#[repr(C, packed)]
#[derive(Debug, Default)]
struct Registers {
    r15: usize,
    r14: usize,
    r13: usize,
    r12: usize,
    r11: usize,
    r10: usize,
    r9: usize,
    r8: usize,
    rdi: usize,
    rsi: usize,
    rbp: usize,
    rsp: usize,
    rdx: usize,
    rcx: usize,
    rbx: usize,
    rax: usize,
    rflags: usize,
    rip: usize,
}

#[cfg(target_arch = "x86_64")]
struct StackWriter<'a> {
    stack: &'a mut [u8],
    offset: usize,
}

#[cfg(target_arch = "x86_64")]
impl<'a> StackWriter<'a> {
    fn new(stack: &'a mut [u8]) -> Self {
        let len = stack.len();
        Self { stack, offset: len }
    }

    fn push<T>(&mut self, value: T) {
        self.offset = self
            .offset
            .checked_sub(size_of::<T>())
            .expect("should not underflow stack during setup");
        let ptr = self
            .stack
            .as_mut_ptr()
            .wrapping_offset(
                isize::try_from(self.offset).expect("stack offset should not overflow isize"),
            )
            .cast::<T>();
        // SAFETY: The pointer is calculated from the stack slice and offset,
        // ensuring it points to valid memory within the stack.
        unsafe { ptr.write(value) };
    }
}
