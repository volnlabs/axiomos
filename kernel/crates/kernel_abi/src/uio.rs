pub const UIO_MAXIOV: usize = 1024;

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct iovec {
    pub iov_base: usize, // *const c_void
    pub iov_len: usize,
}
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};
