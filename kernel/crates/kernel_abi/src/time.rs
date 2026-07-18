use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub const CLOCK_REALTIME: i32 = 0;
pub const CLOCK_MONOTONIC: i32 = 1;

#[repr(C)]
#[derive(Debug, Copy, Clone, Default, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}
