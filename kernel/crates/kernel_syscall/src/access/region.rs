use kernel_abi::ProtFlags;

use crate::UserspacePtr;
use crate::access::{AllocationStrategy, CreateMappingError, Location};

/// Represents a tracked memory region within a process.
/// Memory regions can be accessed by kernel components like interrupt handlers.
pub trait MemoryRegion {
    /// Returns the starting address of this memory region.
    fn addr(&self) -> UserspacePtr<u8>;

    /// Returns the size in bytes of this memory region.
    fn size(&self) -> usize;
}

/// Trait for managing memory regions within a process.
/// This provides an abstraction over the process's memory region tracking.
pub trait MemoryRegionAccess {
    type Region: MemoryRegion;

    /// Creates a mapping and immediately tracks it as a memory region in the process.
    /// Returns the address of the created mapping.
    fn create_and_track_mapping(
        &self,
        location: Location,
        size: usize,
        allocation_strategy: AllocationStrategy,
        protection: ProtFlags,
    ) -> Result<UserspacePtr<u8>, CreateMappingError>;

    /// Adds a memory region to the process's memory region tracking.
    /// This makes the region available to other kernel components.
    fn add_memory_region(&self, region: Self::Region);

    /// Removes a memory region from the process's memory region tracking.
    /// This effectively frees the memory associated with the region.
    fn remove_memory_region(&self, addr: UserspacePtr<u8>) -> Result<(), CreateMappingError>;
}
