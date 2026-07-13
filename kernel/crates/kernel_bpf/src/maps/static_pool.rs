//! Static Memory Pool for Embedded Profile
//!
//! This module provides a pre-allocated memory pool for BPF maps in the
//! embedded profile. All map memory must come from this pool, and no
//! runtime allocation is allowed.
//!
//! # Compile-Time Erasure
//!
//! This entire module is gated behind `#[cfg(feature = "embedded-profile")]`.
//! It is completely erased from cloud builds.
//!
//! # Usage
//!
//! ```rust,ignore
//! use kernel_bpf::maps::StaticPool;
//!
//! // Allocate 1KB from the pool
//! let mem = StaticPool::allocate(1024)?;
//!
//! // Check remaining capacity
//! let remaining = StaticPool::remaining();
//! ```

use core::cell::UnsafeCell;

use spin::Mutex;

/// Default pool size for embedded systems (64KB).
///
/// This can be overridden at compile time via build configuration.
const DEFAULT_POOL_SIZE: usize = 64 * 1024;

/// Global static pool.
static POOL: StaticPoolInner = StaticPoolInner::new();

/// Internal pool state.
///
/// The buffer is separated from the metadata to avoid Stacked Borrows violations.
/// The metadata is protected by a mutex, while the buffer is accessed via raw pointers.
struct StaticPoolInner {
    /// Pool metadata protected by mutex
    metadata: Mutex<PoolMetadata>,
    /// Raw buffer - accessed via raw pointers only after lock is acquired
    buffer: UnsafeCell<[u8; DEFAULT_POOL_SIZE]>,
}

// SAFETY: The buffer is only accessed while holding the metadata lock,
// ensuring exclusive access. The UnsafeCell is used to allow returning
// 'static mut slices that outlive the lock guard.
unsafe impl Sync for StaticPoolInner {}

/// Pool allocation metadata.
struct PoolMetadata {
    /// Current allocation watermark
    watermark: usize,
    /// Number of allocations
    alloc_count: usize,
}

impl PoolMetadata {
    /// Create new pool metadata.
    const fn new() -> Self {
        Self {
            watermark: 0,
            alloc_count: 0,
        }
    }
}

impl StaticPoolInner {
    /// Create a new static pool.
    const fn new() -> Self {
        Self {
            metadata: Mutex::new(PoolMetadata::new()),
            buffer: UnsafeCell::new([0u8; DEFAULT_POOL_SIZE]),
        }
    }
}

/// Static memory pool for BPF maps.
///
/// This pool provides pre-allocated memory for embedded deployments
/// where runtime allocation is not permitted.
///
/// # Allocation Strategy
///
/// The pool uses a simple bump allocator. Memory is allocated linearly
/// from the pool and cannot be freed individually. The entire pool
/// can be reset if needed.
///
/// # Thread Safety
///
/// The pool is protected by a spinlock and is safe to use from
/// multiple threads.
pub struct StaticPool;

impl StaticPool {
    /// Allocate memory from the static pool.
    ///
    /// # Arguments
    ///
    /// * `size` - Number of bytes to allocate
    ///
    /// # Returns
    ///
    /// A mutable slice of zeroed memory, or `None` if the pool
    /// doesn't have enough space.
    ///
    /// # Safety
    ///
    /// The returned memory is valid for the lifetime of the program.
    /// It should not be freed - the pool manages the memory.
    pub fn allocate(size: usize) -> Option<&'static mut [u8]> {
        // Get buffer pointer before locking to avoid Stacked Borrows issues.
        // The pointer is stable because POOL is a static.
        let buffer_ptr = POOL.buffer.get() as *mut u8;

        let mut metadata = POOL.metadata.lock();

        // Align to 8 bytes
        let aligned_size = size.checked_add(7)? & !7;

        // Check if we have enough space
        let end = metadata.watermark.checked_add(aligned_size)?;
        if end > DEFAULT_POOL_SIZE {
            return None;
        }

        let start = metadata.watermark;
        metadata.watermark = end;
        metadata.alloc_count += 1;

        // SAFETY: We're returning a unique mutable slice from the pool.
        // The slice is valid for 'static because the pool lives for
        // the entire program duration. The buffer pointer is obtained
        // independently of the lock, avoiding Stacked Borrows violations.
        Some(unsafe { core::slice::from_raw_parts_mut(buffer_ptr.add(start), size) })
    }

    /// Get the remaining capacity in the pool.
    pub fn remaining() -> usize {
        let metadata = POOL.metadata.lock();
        DEFAULT_POOL_SIZE - metadata.watermark
    }

    /// Get the total pool size.
    pub const fn total_size() -> usize {
        DEFAULT_POOL_SIZE
    }

    /// Get the number of allocations made.
    pub fn allocation_count() -> usize {
        let metadata = POOL.metadata.lock();
        metadata.alloc_count
    }

    /// Get the amount of memory used.
    pub fn used() -> usize {
        let metadata = POOL.metadata.lock();
        metadata.watermark
    }

    /// Reset the pool (for testing only).
    ///
    /// # Safety
    ///
    /// This is extremely unsafe in production. It invalidates all
    /// previously allocated memory. Only use in tests.
    #[cfg(test)]
    pub unsafe fn reset() {
        let buffer_ptr = POOL.buffer.get();
        let mut metadata = POOL.metadata.lock();
        metadata.watermark = 0;
        metadata.alloc_count = 0;
        // Zero the buffer
        // SAFETY: We hold the metadata lock, ensuring exclusive access.
        // This is a test-only function.
        unsafe {
            (*buffer_ptr) = [0u8; DEFAULT_POOL_SIZE];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn setup() -> spin::MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock();
        // SAFETY: TEST_LOCK serializes every test that can reset or allocate
        // from the shared test pool, and the guard lives for the full test.
        unsafe { StaticPool::reset() };
        guard
    }

    #[test]
    fn allocate_basic() {
        let _guard = setup();

        let mem = StaticPool::allocate(100).expect("allocate");
        assert_eq!(mem.len(), 100);

        // Memory should be zeroed
        assert!(mem.iter().all(|&b| b == 0));

        // Can write to allocated memory
        mem[0] = 42;
        assert_eq!(mem[0], 42);
    }

    #[test]
    fn allocate_multiple() {
        let _guard = setup();

        let mem1 = StaticPool::allocate(100).expect("allocate 1");
        let mem2 = StaticPool::allocate(200).expect("allocate 2");

        // Should be different memory regions
        assert_ne!(mem1.as_ptr(), mem2.as_ptr());

        // Both should be usable
        mem1[0] = 1;
        mem2[0] = 2;
        assert_eq!(mem1[0], 1);
        assert_eq!(mem2[0], 2);
    }

    #[test]
    fn allocate_alignment() {
        let _guard = setup();

        // Allocate odd-sized chunks
        let _ = StaticPool::allocate(3).expect("allocate 3");
        let mem2 = StaticPool::allocate(16).expect("allocate 16");

        // Second allocation should be 8-byte aligned
        assert_eq!(mem2.as_ptr() as usize % 8, 0);
    }

    #[test]
    fn pool_exhaustion() {
        let _guard = setup();

        // Allocate most of the remaining pool capacity
        let remaining = StaticPool::remaining();
        let large_alloc = remaining.saturating_sub(100);
        if large_alloc > 0 {
            let _ = StaticPool::allocate(large_alloc).expect("large alloc");
        }

        // Small allocation should still work (if space remains)
        if StaticPool::remaining() >= 56 {
            // 50 aligned to 8 = 56
            let _ = StaticPool::allocate(50).expect("small alloc");
        }

        // Another large allocation should fail
        let result = StaticPool::allocate(StaticPool::total_size());
        assert!(result.is_none());
    }

    #[test]
    fn allocation_size_overflow_is_rejected_without_moving_watermark() {
        let _guard = setup();
        let before = StaticPool::used();

        assert!(StaticPool::allocate(usize::MAX).is_none());
        assert_eq!(StaticPool::used(), before);
    }

    #[test]
    fn remaining_capacity() {
        let _guard = setup();

        let initial = StaticPool::remaining();
        assert_eq!(initial, StaticPool::total_size());

        // Use a non-aligned size to test alignment padding
        StaticPool::allocate(1001).expect("allocate");

        // Remaining should account for alignment (1001 -> 1008)
        let remaining = StaticPool::remaining();
        assert!(remaining < initial - 1001); // Less because of alignment padding
        assert!(remaining >= initial - 1008); // 1001 aligned up to 1008
    }
}
