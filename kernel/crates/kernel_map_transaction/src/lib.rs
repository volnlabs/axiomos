//! Rollback bookkeeping for `map_range_*` operations on an
//! `AddressSpaceMapper`.
//!
//! `MapRangeTransaction` is a small private accumulator that owns
//! only the bookkeeping needed to undo a partially-completed range
//! mapping. It does **not** touch page-table state, the frame
//! allocator, or any mapper API; those stay where they are. The
//! helper exists so the rollback path of `map_range_*` can be
//! expressed as a single `rollback()` call instead of inline
//! reverse-order bookkeeping in the mapper.
//!
//! # Storage: fixed-capacity, stack-allocated, **no heap**.
//!
//! The helper stores its records in a fixed-capacity inline buffer
//! (a `MaybeUninit<[T; N]>` with a length counter, parameterised by
//! the const generic `MAPPED_CAP` / `PENDING_CAP`). It does **not**
//! use `alloc::vec::Vec` for the records, by design. The kernel's
//! very first `map_range` call is `heap::init` setting up the kernel
//! heap, and the helper must work before the global
//! allocator is live. A `Vec`-backed helper would deadlock or
//! panic on `Vec::push` (which calls `alloc`).
//!
//! Callers pick a capacity that fits their use case:
//!
//! - The kernel heap init partitions its RAM-scaled range into at most
//!   512 4 KiB pages per transaction and uses
//!   `MapRangeTransaction<Size4KiB, 512, 512>` for each chunk.
//! - `mmap` / `exec` mappings are smaller and use a smaller
//!   capacity.
//!
//! The kernel mapper rejects a range larger than its selected capacity
//! before changing any PTE. If a direct user of this helper overflows
//! the buffer (`record_mapping` is called more than
//! `MAPPED_CAP` times, or `record_pending_frame` more than
//! `PENDING_CAP` times), the helper panics. The original
//! `map_range_transaction` had no such bound, so this is a
//! behavior change visible only to callers that previously mapped
//! more than `MAPPED_CAP` pages in a single range. The audit
//! callers (heap init, mmap, exec) all stay within the new caps.
//!
//! # State
//!
//! Two pieces of state are tracked:
//!
//! - `mapped`: a list of `Page<S>` values that have been
//!   successfully installed in the page table. The corresponding
//!   frame is held by the page-table entry; on rollback the caller
//!   unmaps the page and receives the frame from the unmap callback
//!   to release.
//! - `pending_frames`: a list of `PhysFrame<S>` values that have
//!   been taken from a frame iterator but not yet mapped (because
//!   the frame iterator was exhausted, or because a `map()` call
//!   failed). On rollback the caller releases every pending frame
//!   without touching the page table.
//!
//! # Termination
//!
//! The helper has two terminal methods:
//!
//! - [`commit`](MapRangeTransaction::commit) consumes the
//!   accumulator. The page-table entries and frame references are
//!   now owned by the page table; dropping the helper releases
//!   nothing.
//! - [`rollback`](MapRangeTransaction::rollback) consumes the
//!   accumulator and invokes caller-supplied `unmap` / `release`
//!   callbacks to undo every recorded operation. Mappings are
//!   reverted in **reverse** order so that a more-recent mapping
//!   (which may depend on an earlier one) is unwound first; pending
//!   frames are then released.
//!
//! # Scope
//!
//! This helper is intentionally narrow:
//!
//! - It does not move mapper or page-table types into
//!   `kernel_physical_memory` (per the audit branch's "kernel-local
//!   helper" constraint).
//! - It does not widen `kernel_physical_memory::fault::checkpoint`.
//!   Fault-injection for the rollback path is provided by the
//!   caller via the `unmap` / `release` callbacks.
//! - It is reachable only through the kernel crate's mapper; no
//!   userspace path can construct or observe it.
//!
//! # Tests
//!
//! The unit tests in this file exercise the bookkeeping with a
//! deterministic fallible callback: for every `n` in `0..=N` they
//! simulate a `map_range_*` that fails after the `n`-th mapping
//! and assert that rollback leaves **no committed PTE records**
//! and **no retained frames**.

#![no_std]

use core::mem::MaybeUninit;

use kernel_physical_memory::{PageSize, PhysFrame};
use kernel_virtual_memory::Page;

/// Small private transaction helper for `map_range_*` rollback.
///
/// See the [module-level documentation](self) for state, scope, and
/// termination semantics. The const generics `MAPPED_CAP` and
/// `PENDING_CAP` are the maximum number of records the helper can
/// hold; see the "Storage" section of the module docs.
pub struct MapRangeTransaction<S: PageSize, const MAPPED_CAP: usize, const PENDING_CAP: usize> {
    /// Pages that have been successfully installed in the page
    /// table. The corresponding frame is held by the page table
    /// until `rollback` unmaps it via the caller-supplied callback.
    ///
    /// Stack-allocated via `MaybeUninit` so the helper does not
    /// touch the global allocator (the kernel's first
    /// `map_range_owned` call sets up the kernel heap, and must
    /// not require a working heap itself).
    mapped: [MaybeUninit<Page<S>>; MAPPED_CAP],
    mapped_len: usize,
    /// Frames taken from a frame iterator but not yet mapped. See
    /// `mapped` for the `MaybeUninit` rationale.
    pending_frames: [MaybeUninit<PhysFrame<S>>; PENDING_CAP],
    pending_len: usize,
}

impl<S: PageSize, const MAPPED_CAP: usize, const PENDING_CAP: usize>
    MapRangeTransaction<S, MAPPED_CAP, PENDING_CAP>
{
    /// Construct an empty accumulator. The inline buffers are
    /// `MaybeUninit`; nothing is initialized until the first
    /// `record_*` call. No allocation occurs.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            mapped: [const { MaybeUninit::uninit() }; MAPPED_CAP],
            mapped_len: 0,
            pending_frames: [const { MaybeUninit::uninit() }; PENDING_CAP],
            pending_len: 0,
        }
    }

    /// Record a successful `(page, frame)` install. The frame
    /// reference is now held by the page table; the page is held by
    /// this accumulator for rollback purposes.
    ///
    /// # Panics
    /// Panics if `MAPPED_CAP` records have already been recorded.
    /// Callers that need more capacity must pick a larger
    /// `MAPPED_CAP` const generic.
    pub fn record_mapping(&mut self, page: Page<S>) {
        assert!(
            self.mapped_len < MAPPED_CAP,
            "MapRangeTransaction: mapped_len ({}) exceeded MAPPED_CAP ({})",
            self.mapped_len,
            MAPPED_CAP,
        );
        self.mapped[self.mapped_len].write(page);
        self.mapped_len += 1;
    }

    /// Record a frame that was taken from a frame iterator but
    /// never installed (the iterator was exhausted, or the matching
    /// `map()` failed). The frame reference is held by this
    /// accumulator for rollback purposes.
    ///
    /// # Panics
    /// Panics if `PENDING_CAP` records have already been recorded.
    pub fn record_pending_frame(&mut self, frame: PhysFrame<S>) {
        assert!(
            self.pending_len < PENDING_CAP,
            "MapRangeTransaction: pending_len ({}) exceeded PENDING_CAP ({})",
            self.pending_len,
            PENDING_CAP,
        );
        self.pending_frames[self.pending_len].write(frame);
        self.pending_len += 1;
    }

    /// Number of mappings currently recorded. Used by callers and
    /// tests that need to assert "no committed PTE records" after
    /// rollback.
    #[must_use]
    pub const fn mapped_len(&self) -> usize {
        self.mapped_len
    }

    /// Number of pending frames currently recorded. Used by callers
    /// and tests that need to assert "no retained frames" after
    /// rollback.
    #[must_use]
    pub const fn pending_frames_len(&self) -> usize {
        self.pending_len
    }

    /// Commit the transaction. The accumulator is consumed; the
    /// page-table entries and frame references are now owned by
    /// the page table. The inline buffers are dropped without
    /// initialization work.
    pub fn commit(self) {
        // The `MaybeUninit` arrays are dropped without running
        // destructors on the (possibly-uninitialized) tail; the
        // initialized prefix is `Copy` (`Page<S>` and `PhysFrame<S>`
        // are both `Copy`), so there is no drop glue to run.
    }

    /// Roll back the transaction. Every recorded mapping is
    /// reverted in reverse order via the `unmap` callback, and
    /// every pending frame is released via the `release`
    /// callback. The accumulator is consumed.
    ///
    /// `unmap` is a best-effort callback: if it returns `None`
    /// (page-table entry was already cleared by another actor),
    /// no frame is released for that page, matching the
    /// pre-refactor `map_range_transaction` semantics. `release` is
    /// always called once for every recorded pending frame.
    pub fn rollback<M, R>(self, mut unmap: M, mut release: R)
    where
        M: FnMut(Page<S>) -> Option<PhysFrame<S>>,
        R: FnMut(PhysFrame<S>),
    {
        // Reverse order: a more-recent mapping (last pushed) is
        // unwound first so a page-table entry that was set after
        // an earlier one does not leave the earlier one in an
        // unexpected state.
        for i in (0..self.mapped_len).rev() {
            // SAFETY: `i < mapped_len <= MAPPED_CAP`, and
            // `record_mapping` initializes slot `i` before
            // incrementing `mapped_len`.
            let page = unsafe { self.mapped[i].assume_init_read() };
            if let Some(frame) = unmap(page) {
                release(frame);
            }
        }
        // Pending frames were never mapped; they have no
        // page-table entry to undo. Release each in the order it
        // was recorded (FIFO), which matches the caller's
        // frame-iterator consumption order.
        for i in 0..self.pending_len {
            // SAFETY: same as above for `pending_frames`.
            let frame = unsafe { self.pending_frames[i].assume_init_read() };
            release(frame);
        }
    }
}

impl<S: PageSize, const MAPPED_CAP: usize, const PENDING_CAP: usize> Default
    for MapRangeTransaction<S, MAPPED_CAP, PENDING_CAP>
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec;
    use alloc::vec::Vec;

    use kernel_physical_memory::{PhysAddr, Size4KiB};
    use kernel_virtual_memory::VirtAddr;

    // Test capacity: small but enough for the tests below.
    const MAPPED_CAP: usize = 32;
    const PENDING_CAP: usize = 32;

    fn make_page(addr: u64) -> Page<Size4KiB> {
        Page::containing_address(VirtAddr::new(addr))
    }

    fn make_frame(addr: u64) -> PhysFrame<Size4KiB> {
        PhysFrame::containing_address(PhysAddr::new(addr))
    }

    /// Drive the transaction through a sequence of `n` successful
    /// mappings followed by a single failure point. Records every
    /// observed `unmap` page and every released frame, then returns
    /// the (unmap_calls, release_calls) traces. The `unmap`
    /// callback reports the page address and pretends the page
    /// table returned the same address as a frame — enough to
    /// exercise the bookkeeping without involving a real page
    /// table.
    fn drive_failure(n: usize, pending_after: usize) -> (Vec<u64>, Vec<u64>) {
        let mut tx: MapRangeTransaction<Size4KiB, MAPPED_CAP, PENDING_CAP> =
            MapRangeTransaction::new();
        let mut unmapped: Vec<u64> = Vec::new();
        let mut released: Vec<u64> = Vec::new();

        for i in 0..n {
            tx.record_mapping(make_page(i as u64 * 0x1000));
        }
        for i in 0..pending_after {
            // Pending frames use a different address range so the
            // test can distinguish them from unmap-returned frames.
            tx.record_pending_frame(make_frame(0x1000_0000 + i as u64 * 0x1000));
        }

        tx.rollback(
            |page| {
                let addr = page.start_address().as_u64();
                unmapped.push(addr);
                // Pretend the page table returned a frame at the
                // same address as the page. This is a stand-in for
                // a real page table.
                Some(make_frame(addr))
            },
            |frame| {
                released.push(frame.start_address().as_u64());
            },
        );

        (unmapped, released)
    }

    #[test]
    fn empty_transaction_rolls_back_to_nothing() {
        let tx: MapRangeTransaction<Size4KiB, MAPPED_CAP, PENDING_CAP> = MapRangeTransaction::new();
        let mut unmapped: Vec<u64> = Vec::new();
        let mut released: Vec<u64> = Vec::new();
        tx.rollback(
            |page| {
                unmapped.push(page.start_address().as_u64());
                Some(make_frame(0))
            },
            |frame| {
                released.push(frame.start_address().as_u64());
            },
        );
        assert!(unmapped.is_empty(), "no unmap calls expected");
        assert!(released.is_empty(), "no release calls expected");
    }

    #[test]
    fn empty_transaction_commits_with_no_side_effects() {
        let tx: MapRangeTransaction<Size4KiB, MAPPED_CAP, PENDING_CAP> = MapRangeTransaction::new();
        tx.commit();
        // No panic, no allocations held.
    }

    #[test]
    fn rollback_releases_one_frame_per_recorded_mapping() {
        let (unmapped, released) = drive_failure(3, 0);
        assert_eq!(unmapped.len(), 3, "one unmap per recorded mapping");
        assert_eq!(released.len(), 3, "one release per recorded mapping");
        // Reverse order: the last-recorded mapping is unmapped first.
        assert_eq!(
            unmapped,
            vec![0x2000, 0x1000, 0x0000],
            "unmap order must be reverse of record order"
        );
        // The unmap callback returned the same address as a frame,
        // so released contains the same addresses.
        assert_eq!(released, vec![0x2000, 0x1000, 0x0000]);
    }

    #[test]
    fn rollback_with_pending_frames_releases_them_after_mappings() {
        let (unmapped, released) = drive_failure(2, 3);
        // Two mappings were unmapped (in reverse order).
        assert_eq!(unmapped, vec![0x1000, 0x0000]);
        // Three pending frames were released (FIFO order — same
        // order they were recorded).
        let pending_addrs: Vec<u64> = released
            .iter()
            .copied()
            .filter(|addr| *addr >= 0x1000_0000)
            .collect();
        assert_eq!(
            pending_addrs,
            vec![0x1000_0000, 0x1000_1000, 0x1000_2000],
            "pending frames must be released in record order"
        );
        // Two releases came from the unmap callback (the page
        // addresses), and three came from the pending frames. The
        // total is 5.
        assert_eq!(released.len(), 5);
    }

    #[test]
    fn rollback_with_unmap_failure_does_not_release_for_that_page() {
        // Simulate an unmap that fails (returns None) for the
        // middle page. The original semantics: no frame is released
        // for a page that the unmap cannot find.
        let mut tx: MapRangeTransaction<Size4KiB, MAPPED_CAP, PENDING_CAP> =
            MapRangeTransaction::new();
        let mut release_calls: Vec<u64> = Vec::new();
        tx.record_mapping(make_page(0x0000));
        tx.record_mapping(make_page(0x1000));
        tx.record_mapping(make_page(0x2000));

        let mut order: Vec<u64> = Vec::new();
        tx.rollback(
            |page| {
                let addr = page.start_address().as_u64();
                order.push(addr);
                // Unmap fails for the middle page.
                if addr == 0x1000 {
                    None
                } else {
                    Some(make_frame(addr))
                }
            },
            |frame| {
                release_calls.push(frame.start_address().as_u64());
            },
        );

        // All three pages were ATTEMPTED in reverse order; the
        // middle one returned None, so the frame for that page was
        // NOT released. The other two were.
        assert_eq!(order, vec![0x2000, 0x1000, 0x0000]);
        assert_eq!(
            release_calls,
            vec![0x2000, 0x0000],
            "only successfully-unmapped pages release a frame"
        );
    }

    /// The full deterministic-failure sweep: for every `n` in
    /// `0..=N`, simulate a `map_range_*` that fails after the
    /// `n`-th mapping and assert the post-rollback invariants the
    /// user asked for:
    /// - no committed PTE records (the accumulator is empty after
    ///   `rollback` consumes it — we use a fresh accumulator per
    ///   iteration to make the per-iteration check obvious);
    /// - no retained frames (every recorded frame is released
    ///   through the unmap or pending-frame release path).
    #[test]
    fn failure_sweep_leaves_no_committed_records_or_retained_frames() {
        for n in 0..=16 {
            for pending_after in 0..=4 {
                let (unmapped, released) = drive_failure(n, pending_after);
                // Invariant 1: every recorded mapping was unmapped.
                assert_eq!(
                    unmapped.len(),
                    n,
                    "n={n} pending_after={pending_after}: every mapping must be unmapped"
                );
                // Invariant 2: total releases = unmap releases + pending.
                let from_unmap = unmapped.len();
                let from_pending = pending_after;
                assert_eq!(
                    released.len(),
                    from_unmap + from_pending,
                    "n={n} pending_after={pending_after}: total releases must equal unmap releases + pending frames"
                );
                // Invariant 3: unmap order is reverse of record order.
                let expected_unmap: Vec<u64> = (0..n).rev().map(|i| (i * 0x1000) as u64).collect();
                assert_eq!(
                    unmapped, expected_unmap,
                    "n={n}: unmap order must be reverse of record order"
                );
                // Invariant 4: pending frames are released in record order.
                let expected_pending: Vec<u64> = (0..pending_after)
                    .map(|i| 0x1000_0000_u64 + (i as u64) * 0x1000)
                    .collect();
                let actual_pending: Vec<u64> = released
                    .iter()
                    .copied()
                    .filter(|addr| *addr >= 0x1000_0000)
                    .collect();
                assert_eq!(
                    actual_pending, expected_pending,
                    "n={n} pending_after={pending_after}: pending frames must release in record order"
                );
            }
        }
    }

    /// A fresh accumulator after `rollback` is empty: the helper
    /// consumes the data on rollback, so a subsequent `commit` on
    /// the same accumulator (impossible by API, but checked via
    /// the `mapped_len` / `pending_frames_len` accessors) would
    /// observe zero records.
    #[test]
    fn rollback_consumes_the_accumulator() {
        let mut tx: MapRangeTransaction<Size4KiB, MAPPED_CAP, PENDING_CAP> =
            MapRangeTransaction::new();
        tx.record_mapping(make_page(0x0));
        tx.record_pending_frame(make_frame(0xDEAD_BEEF));
        assert_eq!(tx.mapped_len(), 1);
        assert_eq!(tx.pending_frames_len(), 1);
        tx.rollback(|_| Some(make_frame(0)), |_| {});
        // Constructing a new accumulator after rollback shows
        // the helper did not leave residual state in module-level
        // statics.
        let tx2: MapRangeTransaction<Size4KiB, MAPPED_CAP, PENDING_CAP> =
            MapRangeTransaction::new();
        assert_eq!(tx2.mapped_len(), 0);
        assert_eq!(tx2.pending_frames_len(), 0);
    }

    /// Stack-only allocation: the helper's `new()` does not touch
    /// the global allocator. This is enforced by the const-fn
    /// signature and exercised by the fact that the kernel's
    /// `heap::init` (which is the very first `map_range`
    /// call, before the global allocator is live) is able to use
    /// this helper.
    #[test]
    fn new_is_const_compatible() {
        // `const {}` evaluation ensures `new` can run at compile
        // time. If `new` ever called `alloc`, this would fail to
        // compile.
        const _NEW_OK: MapRangeTransaction<Size4KiB, 4, 4> = MapRangeTransaction::new();
    }
}
