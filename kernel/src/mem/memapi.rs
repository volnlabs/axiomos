use alloc::sync::Arc;
use core::alloc::Layout;
use core::fmt::{Debug, Formatter};
use core::marker::PhantomData;
use core::ops::Deref;
use core::slice::{from_raw_parts, from_raw_parts_mut};

use kernel_memapi::{Allocation, Guarded, Location, MemoryApi, UserAccessible, WritableAllocation};
use kernel_virtual_memory::Segment;

use crate::arch::types::{PageSize, PageTableFlags, Size4KiB, VirtAddr};
use crate::mcore::mtask::process::Process;
use crate::mem::phys::PhysicalMemory;
use crate::mem::virt::{OwnedSegment, VirtualMemoryAllocator};
use crate::{U64Ext, UsizeExt};

#[derive(Clone)]
pub struct LowerHalfMemoryApi {
    process: Arc<Process>,
}

impl LowerHalfMemoryApi {
    pub fn new(process: Arc<Process>) -> Self {
        Self { process }
    }
}

impl MemoryApi for LowerHalfMemoryApi {
    type ReadonlyAllocation = LowerHalfAllocation<Readonly>;
    type WritableAllocation = LowerHalfAllocation<Writable>;
    type ExecutableAllocation = LowerHalfAllocation<Executable>;

    fn allocate(
        &mut self,
        location: Location,
        layout: Layout,
        user_accessible: UserAccessible,
        guarded: Guarded,
    ) -> Option<Self::WritableAllocation> {
        assert!(layout.align() <= Size4KiB::SIZE.into_usize());

        let num_pages = layout.size().div_ceil(Size4KiB::SIZE.into_usize())
            + match guarded {
                Guarded::Yes => 2, // Reserve two extra pages for guard pages
                Guarded::No => 0,
            };

        let (start, segment) = match location {
            Location::Anywhere => {
                let segment = self.process.vmm().reserve(num_pages)?;
                (None, segment)
            }
            Location::Fixed(v) => {
                let v = VirtAddr::new(v);

                // We don't enforce strict alignment check here because ELF segments might not be page-aligned.
                // The logic below ensures we map the containing pages.
                if !v.is_aligned(layout.align() as u64) {
                    log::warn!("LowerHalfMemoryApi: Fixed location {:p} is not aligned to {}, but proceeding by mapping containing pages.", v.as_ptr::<()>(), layout.align());
                }

                let aligned_start_addr = v.align_down(Size4KiB::SIZE)
                    - match guarded {
                        Guarded::Yes => Size4KiB::SIZE,
                        Guarded::No => 0,
                    };
                let aligned_end_addr = (v + layout.size().into_u64()).align_up(Size4KiB::SIZE)
                    + match guarded {
                        Guarded::Yes => Size4KiB::SIZE,
                        Guarded::No => 0,
                    };
                let segment = Segment::new(
                    kernel_virtual_memory::VirtAddr::new(aligned_start_addr.as_u64()),
                    aligned_end_addr.as_u64() - aligned_start_addr.as_u64(),
                );
                let vmm = self.process.vmm();
                let segment = vmm.mark_as_reserved(segment).ok()?;
                (Some(v), segment)
            }
        };

        let mapped_segment = match guarded {
            Guarded::Yes => Segment::new(
                segment.start + Size4KiB::SIZE,
                segment.len - (2 * Size4KiB::SIZE),
            ),
            Guarded::No => *segment,
        };

        self.process
            .with_address_space(|as_| {
                as_.map_range::<Size4KiB>(
                    &mapped_segment,
                    PhysicalMemory::allocate_frames_non_contiguous(),
                    PageTableFlags::PRESENT
                        | PageTableFlags::WRITABLE
                        | PageTableFlags::NO_EXECUTE
                        | if user_accessible == UserAccessible::Yes {
                            PageTableFlags::USER_ACCESSIBLE
                        } else {
                            PageTableFlags::empty()
                        },
                )
            })
            .ok()?;

        let start = start.unwrap_or(mapped_segment.start);
        Some(LowerHalfAllocation {
            start,
            layout,
            inner: Inner {
                process: self.process.clone(),
                segment,
                mapped_segment,
            },
            _typ: PhantomData,
        })
    }

    fn make_executable(
        &mut self,
        allocation: Self::WritableAllocation,
    ) -> Result<Self::ExecutableAllocation, Self::WritableAllocation> {
        #[cfg(target_arch = "aarch64")]
        unsafe {
            extern "C" {
                fn aarch64_jit_sync_cache(start: usize, len: usize);
            }
            // Sync caches before marking executable to ensure I-cache sees the written instructions
            aarch64_jit_sync_cache(allocation.start().as_u64() as usize, allocation.len());
        }

        let res = self.process.with_address_space(|as_| {
            as_.remap_range::<Size4KiB, _>(&*allocation.segment, |mut flags: PageTableFlags| {
                flags.remove(PageTableFlags::WRITABLE);
                flags.remove(PageTableFlags::NO_EXECUTE);
                flags
            })
        });
        if res.is_err() {
            return Err(allocation);
        }

        Ok(LowerHalfAllocation {
            start: allocation.start,
            layout: allocation.layout,
            inner: allocation.inner,
            _typ: PhantomData,
        })
    }

    fn make_writable(
        &mut self,
        allocation: Self::ExecutableAllocation,
    ) -> Result<Self::WritableAllocation, Self::ExecutableAllocation> {
        let res = self.process.with_address_space(|as_| {
            as_.remap_range::<Size4KiB, _>(&*allocation.segment, |mut flags: PageTableFlags| {
                flags.insert(PageTableFlags::WRITABLE);
                flags.insert(PageTableFlags::NO_EXECUTE);
                flags
            })
        });
        if res.is_err() {
            return Err(allocation);
        }

        Ok(LowerHalfAllocation {
            start: allocation.start,
            layout: allocation.layout,
            inner: allocation.inner,
            _typ: PhantomData,
        })
    }

    fn make_readonly(
        &mut self,
        allocation: Self::WritableAllocation,
    ) -> Result<Self::ReadonlyAllocation, Self::WritableAllocation> {
        let res = self.process.with_address_space(|as_| {
            as_.remap_range::<Size4KiB, _>(&*allocation.segment, |mut flags: PageTableFlags| {
                flags.remove(PageTableFlags::WRITABLE);
                flags.insert(PageTableFlags::NO_EXECUTE);
                flags
            })
        });
        if res.is_err() {
            return Err(allocation);
        }

        Ok(LowerHalfAllocation {
            start: allocation.start,
            layout: allocation.layout,
            inner: allocation.inner,
            _typ: PhantomData,
        })
    }
}

trait Sealed {}
#[allow(private_bounds)]
pub trait AllocationType: Sealed + AllocationFlags {}
#[derive(Debug)]
pub struct Readonly;
impl Sealed for Readonly {}
impl AllocationType for Readonly {}
#[derive(Debug)]
pub struct Writable;
impl Sealed for Writable {}
impl AllocationType for Writable {}
#[derive(Debug)]
pub struct Executable;
impl Sealed for Executable {}
impl AllocationType for Executable {}

pub struct LowerHalfAllocation<T> {
    start: VirtAddr,
    layout: Layout,
    inner: Inner,
    _typ: PhantomData<T>,
}

impl<T: AllocationType> LowerHalfAllocation<T> {
    #[must_use]
    pub fn start(&self) -> VirtAddr {
        self.start
    }

    #[allow(clippy::len_without_is_empty)]
    #[must_use]
    pub fn len(&self) -> usize {
        self.layout.size()
    }

    /// Clones this allocation into another process.
    ///
    /// Read-only and executable allocations are shared directly. Writable allocations are
    /// remapped into copy-on-write shared pages in both parent and child.
    pub fn clone_to_process(&self, new_process: Arc<Process>) -> Option<Self> {
        let new_segment_inner = kernel_virtual_memory::Segment::new(
            self.inner.mapped_segment.start,
            self.inner.mapped_segment.len,
        );
        let new_segment = new_process.vmm().mark_as_reserved(new_segment_inner).ok()?;

        let page_count = (self.inner.mapped_segment.len / Size4KiB::SIZE) as usize;
        let mut shared_frames = alloc::vec::Vec::with_capacity(page_count);
        for i in 0..page_count {
            let page_vaddr = self.inner.mapped_segment.start + (i as u64 * Size4KiB::SIZE);
            let (phys, _) = self
                .process
                .with_address_space(|as_| as_.translate_page_flags(page_vaddr))?;
            let frame = crate::arch::types::PhysFrame::<Size4KiB>::containing_address(phys);
            PhysicalMemory::retain_frame(frame);
            shared_frames.push(frame);
        }

        if T::fork_requires_cow() {
            let cow_flags = T::fork_mapping_flags();
            self.process
                .with_address_space(|as_| {
                    as_.remap_range::<Size4KiB, _>(&self.inner.mapped_segment, |_| cow_flags)
                })
                .ok()?;
        }

        new_process
            .with_address_space(|as_| {
                as_.map_range(
                    &self.inner.mapped_segment,
                    shared_frames.into_iter(),
                    T::fork_mapping_flags(),
                )
            })
            .ok()?;

        Some(LowerHalfAllocation {
            start: self.start,
            layout: self.layout,
            inner: Inner {
                segment: new_segment,
                mapped_segment: self.inner.mapped_segment,
                process: new_process,
            },
            _typ: PhantomData,
        })
    }
}

pub trait AllocationFlags {
    fn flags() -> PageTableFlags;
    fn fork_requires_cow() -> bool {
        false
    }

    fn fork_mapping_flags() -> PageTableFlags {
        Self::flags() | PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE
    }
}

impl AllocationFlags for Writable {
    fn flags() -> PageTableFlags {
        PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE
    }

    fn fork_requires_cow() -> bool {
        cfg!(target_arch = "aarch64")
    }

    fn fork_mapping_flags() -> PageTableFlags {
        #[cfg(target_arch = "aarch64")]
        {
            PageTableFlags::PRESENT
                | PageTableFlags::USER_ACCESSIBLE
                | PageTableFlags::NO_EXECUTE
                | PageTableFlags::COPY_ON_WRITE
        }

        #[cfg(not(target_arch = "aarch64"))]
        {
            Self::flags() | PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE
        }
    }
}

impl AllocationFlags for Readonly {
    fn flags() -> PageTableFlags {
        PageTableFlags::NO_EXECUTE
    }
}

impl AllocationFlags for Executable {
    fn flags() -> PageTableFlags {
        PageTableFlags::empty() // Executable (no NO_EXECUTE) and ReadOnly (no WRITABLE)
    }
}

pub struct Inner {
    segment: OwnedSegment<'static>,
    mapped_segment: Segment,
    process: Arc<Process>,
}

impl<T: AllocationType> Deref for LowerHalfAllocation<T> {
    type Target = Inner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T: AllocationType> Debug for LowerHalfAllocation<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LowerHalfAllocation")
            .field("process_id", &self.process.pid())
            .field("segment", &self.segment)
            .field("typ", &self._typ)
            .finish_non_exhaustive()
    }
}

impl<T: AllocationType> AsRef<[u8]> for LowerHalfAllocation<T> {
    fn as_ref(&self) -> &[u8] {
        let ptr = self.start.as_ptr();
        // SAFETY: self.start points to the start of the allocation, and self.layout.size()
        // is the size of the allocation. The allocation is valid for the lifetime of self.
        unsafe { from_raw_parts(ptr, self.layout.size()) }
    }
}

impl<T: AllocationType> Allocation for LowerHalfAllocation<T> {
    fn layout(&self) -> Layout {
        self.layout
    }
}

impl AsMut<[u8]> for LowerHalfAllocation<Writable> {
    fn as_mut(&mut self) -> &mut [u8] {
        let ptr = self.start.as_mut_ptr();
        // SAFETY: self.start points to the start of the allocation, and self.layout.size()
        // is the size of the allocation. We have exclusive access via &mut self.
        unsafe { from_raw_parts_mut(ptr, self.layout.size()) }
    }
}

impl WritableAllocation for LowerHalfAllocation<Writable> {}

impl Drop for Inner {
    fn drop(&mut self) {
        self.process.with_address_space(|as_| {
            as_.unmap_range::<Size4KiB>(&self.mapped_segment, PhysicalMemory::deallocate_frame)
        });
    }
}
