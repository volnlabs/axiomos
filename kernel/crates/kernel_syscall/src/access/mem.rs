use kernel_abi::ProtFlags;

use crate::UserspacePtr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocationStrategy {
    Eager,
    Lazy,
}

pub enum Location {
    Anywhere,
    Fixed(UserspacePtr<u8>),
}

/// An uncommitted mapping transaction.
///
/// Implementations must roll back mapped pages, backing resources, and virtual
/// reservations when dropped before [`commit`](Self::commit). Committing
/// transfers that ownership into the returned tracked region.
#[must_use = "dropping an uncommitted mapping rolls the transaction back"]
pub trait Mapping: Sized {
    type Region: crate::access::MemoryRegion;

    /// Returns the address at which this mapping exists.
    fn addr(&self) -> UserspacePtr<u8>;

    /// Returns the length of this mapping.
    fn size(&self) -> usize;

    /// Returns the enforced protection policy.
    fn protection(&self) -> ProtFlags;

    /// Commit the transaction into an owned, tracked-region value.
    fn commit(self) -> Self::Region;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateMappingError {
    InvalidRequest,
    LocationAlreadyMapped,
    OutOfMemory,
    NotFound,
    Unsupported,
}

pub trait MemoryAccess {
    type Mapping: Mapping;

    fn create_mapping(
        &self,
        location: Location,
        size: usize,
        allocation_strategy: AllocationStrategy,
        protection: ProtFlags,
    ) -> Result<Self::Mapping, CreateMappingError>;
}
