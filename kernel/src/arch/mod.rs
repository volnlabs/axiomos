pub mod traits;
pub mod types;

// Re-export common types
pub use types::{
    PageRangeInclusive, PageSize, PageTableFlags, PhysAddr, PhysFrame, PhysFrameRange, Size4KiB,
    VirtAddr,
};

#[cfg(target_arch = "x86_64")]
pub mod gdt;

#[cfg(target_arch = "x86_64")]
pub mod idt;

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "x86_64")]
pub use self::x86_64::*;

#[cfg(target_arch = "x86_64")]
pub type UserContext = crate::arch::idt::UserContext;

#[cfg(target_arch = "x86_64")]
pub use crate::arch::idt::restore_user_context;

#[cfg(target_arch = "riscv64")]
pub mod riscv64;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(target_arch = "aarch64")]
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct UserContext {
    pub inner: crate::arch::aarch64::exceptions::ExceptionContext,
    pub sp: u64,
}

// Re-export the current architecture
#[cfg(target_arch = "riscv64")]
pub use self::riscv64::*;
#[cfg(target_arch = "aarch64")]
pub use crate::arch::aarch64::context::restore_user_context;
