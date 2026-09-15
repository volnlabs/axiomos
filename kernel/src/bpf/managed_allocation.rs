//! Heap charges for the fixed managed artifact/instance object graph.
//!
//! This matches `linked_list_allocator` 0.10.5 (`Cargo.lock`): every requested
//! layout is raised to a two-word free-hole minimum and rounded to word
//! alignment. `Arc` layout matches pinned Rust nightly-2026-07-02's
//! `ArcInner { strong: AtomicUsize, weak: AtomicUsize, data: T }`.
//! Update the checks below when either pin changes.

use core::alloc::Layout;
use core::sync::atomic::AtomicUsize;

use kernel_bpf::execution::BpfError;

const WORD: usize = core::mem::size_of::<usize>();
const MIN_ALLOCATION: usize = WORD * 2;

const _: () = assert!(WORD == 8);
const _: () = assert!(core::mem::align_of::<usize>() == 8);

fn normalized(layout: Layout) -> Result<usize, BpfError> {
    if layout.size() == 0 {
        return Ok(0);
    }
    let size = layout.size().max(MIN_ALLOCATION);
    size.checked_add(WORD - 1)
        .map(|rounded| rounded & !(WORD - 1))
        .ok_or(BpfError::ResourceLimit)
}

/// Charge a byte buffer allocated with the global allocator.
pub(super) fn buffer(bytes: usize) -> Result<usize, BpfError> {
    let layout = Layout::array::<u8>(bytes).map_err(|_| BpfError::ResourceLimit)?;
    normalized(layout)
}

/// Charge one `Box<T>` allocation. Zero-sized boxes allocate no storage.
pub(super) fn boxed<T>() -> Result<usize, BpfError> {
    normalized(Layout::new::<T>())
}

/// Charge one pinned-layout `Arc<T>` allocation, including both refcounts.
pub(super) fn arc<T>() -> Result<usize, BpfError> {
    let (header, _) = Layout::new::<AtomicUsize>()
        .extend(Layout::new::<AtomicUsize>())
        .map_err(|_| BpfError::ResourceLimit)?;
    let (inner, _) = header
        .extend(Layout::new::<T>())
        .map_err(|_| BpfError::ResourceLimit)?;
    normalized(inner.pad_to_align())
}

#[cfg(test)]
mod tests {
    use alloc::alloc::{AllocError, Allocator};
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use core::alloc::Layout;
    use core::cell::{RefCell, UnsafeCell};
    use core::mem::MaybeUninit;
    use core::ptr::NonNull;

    use linked_list_allocator::Heap;

    use super::*;

    struct HeapAllocator {
        heap: RefCell<Heap>,
        storage: Box<UnsafeCell<[MaybeUninit<u8>; 4096]>>,
    }

    impl HeapAllocator {
        fn new() -> Self {
            Self {
                heap: RefCell::new(Heap::empty()),
                storage: Box::new(UnsafeCell::new([MaybeUninit::uninit(); 4096])),
            }
        }

        fn init(&mut self) {
            // SAFETY: the boxed backing has a stable address, remains owned by
            // this now-stationary allocator, and is dropped only after `heap`.
            unsafe {
                self.heap
                    .get_mut()
                    .init((*self.storage.get()).as_mut_ptr().cast(), 4096)
            };
        }

        fn used(&self) -> usize {
            self.heap.borrow().used()
        }
    }

    // SAFETY: Heap serializes mutation through RefCell for these single-threaded
    // tests and deallocation receives the identical layout used for allocation.
    unsafe impl Allocator for HeapAllocator {
        fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
            let ptr = self
                .heap
                .borrow_mut()
                .allocate_first_fit(layout)
                .map_err(|()| AllocError)?;
            Ok(NonNull::slice_from_raw_parts(ptr, layout.size()))
        }

        unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
            // SAFETY: `ptr` and `layout` are returned by this allocator above.
            unsafe { self.heap.borrow_mut().deallocate(ptr, layout) };
        }
    }

    #[test]
    fn buffer_charge_handles_zero_minimum_rounding_and_overflow() {
        assert_eq!(buffer(0), Ok(0));
        assert_eq!(buffer(1), Ok(16));
        assert_eq!(buffer(16), Ok(16));
        assert_eq!(buffer(17), Ok(24));
        assert_eq!(buffer(usize::MAX), Err(BpfError::ResourceLimit));
    }

    #[test]
    fn real_box_and_arc_requests_match_pinned_heap_charges() {
        #[repr(C, align(32))]
        struct Odd([u8; 37]);

        let mut allocator = HeapAllocator::new();
        allocator.init();
        let before = allocator.used();
        let value = Box::try_new_in(Odd([0; 37]), &allocator).unwrap();
        assert_eq!(allocator.used() - before, boxed::<Odd>().unwrap());
        assert_eq!(value.0[0], 0);
        drop(value);
        assert_eq!(allocator.used(), before);

        let before = allocator.used();
        let value = Arc::try_new_in(Odd([1; 37]), &allocator).unwrap();
        assert_eq!(allocator.used() - before, arc::<Odd>().unwrap());
        assert_eq!(value.0[0], 1);
        let clone = Arc::clone(&value);
        assert_eq!(allocator.used() - before, arc::<Odd>().unwrap());
        drop(clone);
        drop(value);
        assert_eq!(allocator.used(), before);
    }
}
