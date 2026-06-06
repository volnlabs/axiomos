use core::fmt;
use core::ops::{Add, AddAssign, Sub, SubAssign};

use kernel_physical_memory::{PageSize, Size4KiB};

use crate::Segment;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct VirtAddr(pub u64);

impl VirtAddr {
    #[inline]
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }

    #[inline]
    #[allow(clippy::result_unit_err)]
    pub fn try_new(addr: u64) -> Result<Self, ()> {
        // For now, we don't implement strict canonicality checks on AArch64
        // as they depend on the specific configuration (T0SZ, etc.)
        Ok(Self::new(addr))
    }

    #[inline]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    #[inline]
    pub fn as_ptr<T>(self) -> *const T {
        self.0 as *const T
    }

    #[inline]
    pub fn as_mut_ptr<T>(self) -> *mut T {
        self.0 as *mut T
    }

    #[inline]
    pub const fn is_aligned(self, align: u64) -> bool {
        self.0.wrapping_rem(align) == 0
    }

    #[inline]
    pub const fn align_down(self, align: u64) -> Self {
        Self(self.0 & !(align - 1))
    }

    #[inline]
    pub const fn align_up(self, align: u64) -> Self {
        Self((self.0 + align - 1) & !(align - 1))
    }

    #[inline]
    pub const fn as_usize(self) -> usize {
        self.0 as usize
    }
}

impl fmt::Display for VirtAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VirtAddr(0x{:x})", self.0)
    }
}

impl Add<u64> for VirtAddr {
    type Output = Self;
    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0 + rhs)
    }
}

impl AddAssign<u64> for VirtAddr {
    fn add_assign(&mut self, rhs: u64) {
        self.0 += rhs;
    }
}

impl Sub<u64> for VirtAddr {
    type Output = Self;
    fn sub(self, rhs: u64) -> Self::Output {
        Self(self.0 - rhs)
    }
}

impl SubAssign<u64> for VirtAddr {
    fn sub_assign(&mut self, rhs: u64) {
        self.0 -= rhs;
    }
}

impl Sub<VirtAddr> for VirtAddr {
    type Output = u64;
    fn sub(self, rhs: VirtAddr) -> Self::Output {
        self.0 - rhs.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Page<S: PageSize = Size4KiB> {
    pub start_address: VirtAddr,
    pub size: core::marker::PhantomData<S>,
}

impl<S: PageSize> Page<S> {
    pub const fn containing_address(address: VirtAddr) -> Self {
        Self {
            start_address: VirtAddr::new(address.0 & !(S::SIZE - 1)),
            size: core::marker::PhantomData,
        }
    }

    #[allow(clippy::result_unit_err)]
    pub const fn from_start_address(address: VirtAddr) -> Result<Self, ()> {
        if address.0 & (S::SIZE - 1) != 0 {
            return Err(());
        }
        Ok(Self {
            start_address: address,
            size: core::marker::PhantomData,
        })
    }

    pub const fn start_address(self) -> VirtAddr {
        self.start_address
    }

    pub const fn size(self) -> u64 {
        S::SIZE
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageRangeInclusive<S: PageSize = Size4KiB> {
    pub start: Page<S>,
    pub end: Page<S>,
}

impl<S: PageSize> Iterator for PageRangeInclusive<S> {
    type Item = Page<S>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.start.start_address.as_u64() > self.end.start_address.as_u64() {
            return None;
        }
        let page = self.start;
        self.start = Page::containing_address(self.start.start_address + S::SIZE);
        Some(page)
    }
}

impl<S: PageSize> From<Segment> for PageRangeInclusive<S> {
    fn from(segment: Segment) -> Self {
        Self {
            start: Page::containing_address(segment.start),
            end: Page::containing_address(segment.start + segment.len - 1),
        }
    }
}

impl<S: PageSize> From<&Segment> for PageRangeInclusive<S> {
    fn from(segment: &Segment) -> Self {
        Self {
            start: Page::containing_address(segment.start),
            end: Page::containing_address(segment.start + segment.len - 1),
        }
    }
}
