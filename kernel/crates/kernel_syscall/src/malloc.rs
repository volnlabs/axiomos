use kernel_abi::{EINVAL, ENOMEM, Errno, ProtFlags};

use crate::UserspacePtr;
use crate::access::{AllocationStrategy, CreateMappingError, Location, MemoryRegionAccess};

pub fn sys_malloc<Cx: MemoryRegionAccess>(cx: &Cx, size: usize) -> Result<usize, Errno> {
    if size == 0 {
        return Err(EINVAL);
    }

    // AllocationStrategy::Eager is what we support for now
    let mapped_addr = cx
        .create_and_track_mapping(
            Location::Anywhere,
            size,
            AllocationStrategy::Eager,
            ProtFlags::READ | ProtFlags::WRITE,
        )
        .map_err(|e| match e {
            CreateMappingError::InvalidRequest => EINVAL,
            CreateMappingError::LocationAlreadyMapped => EINVAL,
            CreateMappingError::OutOfMemory => ENOMEM,
            CreateMappingError::NotFound => EINVAL,
            CreateMappingError::Unsupported => EINVAL,
        })?;

    Ok(mapped_addr.addr())
}

pub fn sys_free<Cx: MemoryRegionAccess>(cx: &Cx, ptr: usize) -> Result<usize, Errno> {
    if ptr == 0 {
        return Err(EINVAL);
    }

    // SAFETY: We validate that ptr is in the userspace address range via try_from_usize.
    // It doesn't guarantee it points to a valid allocation, but it prevents kernel pointers.
    let user_ptr = unsafe { UserspacePtr::<u8>::try_from_usize(ptr)? };

    cx.remove_memory_region(user_ptr).map_err(|e| match e {
        CreateMappingError::NotFound => EINVAL,
        _ => EINVAL,
    })?;

    Ok(0)
}
