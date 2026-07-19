#[cfg(target_arch = "x86_64")]
use x86_64::structures::paging::page::PageRangeInclusive;
#[cfg(target_arch = "x86_64")]
use x86_64::structures::paging::{Page, PageSize};

use crate::VirtAddr;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct Segment {
    pub start: VirtAddr,
    pub len: u64,
}

impl Segment {
    #[must_use]
    pub const fn new(start: VirtAddr, len: u64) -> Self {
        Self { start, len }
    }

    #[must_use]
    pub fn contains(&self, addr: VirtAddr) -> bool {
        self.start <= addr && addr < self.start + self.len
    }
}

#[cfg(target_arch = "x86_64")]
impl<S: PageSize> From<&Segment> for PageRangeInclusive<S> {
    fn from(value: &Segment) -> Self {
        assert!(value.len > 0);
        Self {
            start: Page::containing_address(value.start),
            end: Page::containing_address(value.start + value.len - 1),
        }
    }
}

#[cfg(target_arch = "x86_64")]
impl<S: PageSize> From<Segment> for PageRangeInclusive<S> {
    fn from(value: Segment) -> Self {
        Self::from(&value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contains_uses_an_inclusive_start_and_exclusive_end() {
        let segment = Segment::new(VirtAddr::new(0x1000), 0x100);

        assert!(segment.contains(VirtAddr::new(0x1000)));
        assert!(segment.contains(VirtAddr::new(0x10ff)));
        assert!(!segment.contains(VirtAddr::new(0x0fff)));
        assert!(!segment.contains(VirtAddr::new(0x1100)));
    }

    #[test]
    fn zero_length_segment_contains_no_addresses() {
        let segment = Segment::new(VirtAddr::new(0x1000), 0);

        assert!(!segment.contains(VirtAddr::new(0x0fff)));
        assert!(!segment.contains(VirtAddr::new(0x1000)));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn page_range_conversion_covers_every_touched_page() {
        use x86_64::structures::paging::Size4KiB;

        let segment = Segment::new(VirtAddr::new(0x1fff), 0x1002);
        let pages = PageRangeInclusive::<Size4KiB>::from(&segment);

        assert_eq!(pages.start.start_address(), VirtAddr::new(0x1000));
        assert_eq!(pages.end.start_address(), VirtAddr::new(0x3000));

        let owned_pages = PageRangeInclusive::<Size4KiB>::from(segment);
        assert_eq!(owned_pages.start, pages.start);
        assert_eq!(owned_pages.end, pages.end);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    #[should_panic(expected = "assertion failed: value.len > 0")]
    fn page_range_conversion_rejects_empty_segments() {
        use x86_64::structures::paging::Size4KiB;

        let _ = PageRangeInclusive::<Size4KiB>::from(Segment::new(VirtAddr::new(0x1000), 0));
    }
}
