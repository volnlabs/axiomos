use core::fmt;
use core::ops::{Add, AddAssign, Sub, SubAssign};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct PhysAddr(pub u64);

impl PhysAddr {
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }

    pub const fn as_u64(self) -> u64 {
        self.0
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
}

impl Add<u64> for PhysAddr {
    type Output = Self;
    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0 + rhs)
    }
}

impl AddAssign<u64> for PhysAddr {
    fn add_assign(&mut self, rhs: u64) {
        self.0 += rhs;
    }
}

impl Sub<u64> for PhysAddr {
    type Output = Self;
    fn sub(self, rhs: u64) -> Self::Output {
        Self(self.0 - rhs)
    }
}

impl SubAssign<u64> for PhysAddr {
    fn sub_assign(&mut self, rhs: u64) {
        self.0 -= rhs;
    }
}

impl fmt::Display for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PhysAddr(0x{:x})", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct PhysFrame<S: PageSize = Size4KiB> {
    start_address: PhysAddr,
    size: core::marker::PhantomData<S>,
}

impl<S: PageSize> PhysFrame<S> {
    pub const fn containing_address(address: PhysAddr) -> Self {
        Self {
            start_address: PhysAddr(address.0 & !(S::SIZE - 1)),
            size: core::marker::PhantomData,
        }
    }

    #[allow(clippy::result_unit_err)]
    pub const fn from_start_address(address: PhysAddr) -> Result<Self, ()> {
        if address.0 & (S::SIZE - 1) != 0 {
            return Err(());
        }
        Ok(Self {
            start_address: address,
            size: core::marker::PhantomData,
        })
    }

    pub const fn start_address(self) -> PhysAddr {
        self.start_address
    }

    #[inline]
    pub const fn addr(self) -> u64 {
        self.start_address.0
    }

    #[inline]
    pub const fn number(self) -> u64 {
        self.start_address.0 / S::SIZE
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysFrameRangeInclusive<S: PageSize = Size4KiB> {
    pub start: PhysFrame<S>,
    pub end: PhysFrame<S>,
}

impl<S: PageSize> Iterator for PhysFrameRangeInclusive<S> {
    type Item = PhysFrame<S>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.start.start_address > self.end.start_address {
            return None;
        }
        let frame = self.start;
        self.start = PhysFrame::containing_address(self.start.start_address + S::SIZE);
        Some(frame)
    }
}

pub trait PageSize: Copy + Eq + PartialOrd + Ord + fmt::Debug {
    const SIZE: u64;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Size4KiB;

impl PageSize for Size4KiB {
    const SIZE: u64 = 4096;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Size2MiB;

impl PageSize for Size2MiB {
    const SIZE: u64 = 2 * 1024 * 1024;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Size1GiB;

impl PageSize for Size1GiB {
    const SIZE: u64 = 1024 * 1024 * 1024;
}
