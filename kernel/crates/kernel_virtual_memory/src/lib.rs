#![no_std]

extern crate alloc;

use alloc::collections::BTreeSet;

#[cfg(not(target_arch = "x86_64"))]
pub use addr::{InvalidVirtAddrError, Page, PageNotAlignedError, PageRangeInclusive, VirtAddr};
use log::debug;
pub use segment::*;
use thiserror::Error;
#[cfg(target_arch = "x86_64")]
pub use x86_64::VirtAddr;
#[cfg(target_arch = "x86_64")]
pub use x86_64::structures::paging::Page;
#[cfg(target_arch = "x86_64")]
pub use x86_64::structures::paging::page::PageRangeInclusive;

#[cfg(not(target_arch = "x86_64"))]
mod addr;
mod segment;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Error)]
#[error("segment already reserved")]
pub struct AlreadyReserved;

#[derive(Eq, PartialEq)]
pub struct VirtualMemoryManager {
    mem_start: VirtAddr,
    mem_size: u64,
    segments: BTreeSet<Segment>,
}

impl VirtualMemoryManager {
    #[must_use]
    pub fn new(mem_start: VirtAddr, mem_size: u64) -> Self {
        Self {
            mem_start,
            mem_size,
            segments: BTreeSet::default(),
        }
    }

    pub fn reserve(&mut self, n: usize) -> Option<Segment> {
        if n == 0 {
            return None;
        }

        let mut segment = Segment::new(self.mem_start, n as u64);
        while let Some(existing) = self.find_overlapping(&segment) {
            segment.start = existing.start + existing.len;
        }
        if self.mem_start + (self.mem_size - 1) < segment.start + (segment.len - 1) {
            return None;
        }

        self.segments.insert(segment);

        Some(Segment {
            start: segment.start,
            len: n as u64,
        })
    }

    pub fn release(&mut self, segment: Segment) -> bool {
        self.segments.remove(&segment)
    }

    /// Mark a segment as reserved, preventing it from being reserved again.
    ///
    /// # Errors
    ///
    /// Returns an error if the segment overlaps with an already reserved segment.
    pub fn mark_as_reserved(&mut self, segment: Segment) -> Result<(), AlreadyReserved> {
        if let Some(overlapping) = self.find_overlapping(&segment) {
            debug!("segment {segment:x?} overlaps with existing segment: {overlapping:x?}");
            return Err(AlreadyReserved);
        }
        self.segments.insert(segment);

        Ok(())
    }

    pub fn segments(&self) -> impl Iterator<Item = &Segment> {
        self.segments.iter()
    }

    fn find_overlapping(&self, segment: &Segment) -> Option<&Segment> {
        self.segments.iter().find(|existing| {
            segment.start <= existing.start + (existing.len - 1)
                && existing.start <= segment.start + (segment.len - 1)
        })
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    fn segment(start: u64, len: u64) -> Segment {
        Segment::new(VirtAddr::new(start), len)
    }

    fn snapshot(vmm: &VirtualMemoryManager) -> Vec<Segment> {
        vmm.segments().copied().collect()
    }

    #[test]
    fn test_reserve_release() {
        let size = 50000_usize;
        let mut vmm = VirtualMemoryManager::new(VirtAddr::new(0xabcd), size as u64);
        for n in (1..=size).step_by(713) {
            let segment = vmm
                .reserve(n)
                .expect("each request should fit after the previous release");

            assert_eq!(segment.len, n as u64);

            vmm.release(segment);
        }
    }

    #[test]
    fn test_mark_as_used() {
        let mut vmm = VirtualMemoryManager::new(VirtAddr::new(0xdeff), 400);
        let segment0 = Segment::new(VirtAddr::new(0xdeff), 100);
        let segment1 = Segment::new(VirtAddr::new(0xdeff + 100), 100);
        let segment1_5 = Segment::new(VirtAddr::new(0xdeff + 150), 100);
        let segment2 = Segment::new(VirtAddr::new(0xdeff + 200), 100);
        let segment3 = Segment::new(VirtAddr::new(0xdeff + 300), 100);

        vmm.mark_as_reserved(segment0).unwrap();
        vmm.mark_as_reserved(segment1).unwrap();
        vmm.mark_as_reserved(segment2).unwrap();
        vmm.mark_as_reserved(segment3).unwrap();

        assert_eq!(vmm.mark_as_reserved(segment1_5), Err(AlreadyReserved));

        vmm.release(segment1);
        assert_eq!(vmm.mark_as_reserved(segment1_5), Err(AlreadyReserved));

        vmm.mark_as_reserved(segment1).unwrap();
        vmm.release(segment2);
        assert_eq!(vmm.mark_as_reserved(segment1_5), Err(AlreadyReserved));

        vmm.release(segment1);
        vmm.mark_as_reserved(segment1_5).unwrap();
    }

    #[test]
    fn reserve_rejects_zero_without_changing_state() {
        let mut vmm = VirtualMemoryManager::new(VirtAddr::new(0x1000), 0x1000);

        assert_eq!(vmm.reserve(0), None);
        assert!(vmm.segments().next().is_none());
    }

    #[test]
    fn reserve_uses_the_first_gap_large_enough_for_the_request() {
        let mut vmm = VirtualMemoryManager::new(VirtAddr::new(0x1000), 0x1000);
        vmm.mark_as_reserved(segment(0x1000, 0x100)).unwrap();
        vmm.mark_as_reserved(segment(0x1200, 0x100)).unwrap();

        assert_eq!(vmm.reserve(0x80), Some(segment(0x1100, 0x80)));
        assert_eq!(vmm.reserve(0x90), Some(segment(0x1300, 0x90)));
    }

    #[test]
    fn reserve_accepts_a_request_that_ends_at_the_manager_boundary() {
        let mut vmm = VirtualMemoryManager::new(VirtAddr::new(0x1000), 0x200);

        assert_eq!(vmm.reserve(0x200), Some(segment(0x1000, 0x200)));
        assert_eq!(vmm.reserve(1), None);
    }

    #[test]
    fn failed_reserve_leaves_existing_reservations_unchanged() {
        let mut vmm = VirtualMemoryManager::new(VirtAddr::new(0x1000), 0x300);
        let occupied = segment(0x1000, 0x200);
        vmm.mark_as_reserved(occupied).unwrap();
        let before = snapshot(&vmm);

        assert_eq!(vmm.reserve(0x200), None);
        assert_eq!(snapshot(&vmm), before);
    }

    #[test]
    fn failed_overlapping_mark_leaves_reservations_unchanged() {
        let mut vmm = VirtualMemoryManager::new(VirtAddr::new(0x1000), 0x1000);
        let occupied = segment(0x1200, 0x100);
        vmm.mark_as_reserved(occupied).unwrap();

        for overlapping in [
            segment(0x1180, 0x100),
            segment(0x1280, 0x100),
            segment(0x1100, 0x300),
            segment(0x1240, 0x20),
            occupied,
        ] {
            let before = snapshot(&vmm);
            assert_eq!(vmm.mark_as_reserved(overlapping), Err(AlreadyReserved));
            assert_eq!(snapshot(&vmm), before);
        }
    }

    #[test]
    fn mark_accepts_segments_adjacent_to_existing_reservations() {
        let mut vmm = VirtualMemoryManager::new(VirtAddr::new(0x1000), 0x1000);
        vmm.mark_as_reserved(segment(0x1200, 0x100)).unwrap();

        assert_eq!(vmm.mark_as_reserved(segment(0x1100, 0x100)), Ok(()));
        assert_eq!(vmm.mark_as_reserved(segment(0x1300, 0x100)), Ok(()));
        assert_eq!(
            snapshot(&vmm),
            [
                segment(0x1100, 0x100),
                segment(0x1200, 0x100),
                segment(0x1300, 0x100),
            ]
        );
    }

    #[test]
    fn release_only_removes_the_exact_owned_segment_and_frees_its_gap() {
        let mut vmm = VirtualMemoryManager::new(VirtAddr::new(0x1000), 0x400);
        let first = vmm.reserve(0x100).unwrap();
        let second = vmm.reserve(0x100).unwrap();

        assert!(!vmm.release(segment(first.start.as_u64(), first.len / 2)));
        assert_eq!(snapshot(&vmm), [first, second]);
        assert!(vmm.release(first));
        assert!(!vmm.release(first));
        assert_eq!(vmm.reserve(0x80), Some(segment(0x1000, 0x80)));
    }
}
