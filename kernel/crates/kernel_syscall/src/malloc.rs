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

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use kernel_abi::{EINVAL, ENOMEM};
    use spin::Mutex;

    use super::*;
    use crate::access::MemoryRegion;

    const MAPPED_ADDR: usize = 0x4000;

    struct TestRegion;

    impl MemoryRegion for TestRegion {
        fn addr(&self) -> UserspacePtr<u8> {
            unreachable!("malloc tests never construct tracked regions")
        }

        fn size(&self) -> usize {
            0
        }

        fn protection(&self) -> ProtFlags {
            ProtFlags::NONE
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct MappingRequest {
        anywhere: bool,
        size: usize,
        allocation_strategy: AllocationStrategy,
        protection: ProtFlags,
    }

    struct TestMemoryAccess {
        create_error: Option<CreateMappingError>,
        remove_error: Option<CreateMappingError>,
        requests: Mutex<Vec<MappingRequest>>,
        removed: Mutex<Vec<usize>>,
    }

    impl TestMemoryAccess {
        fn succeeds() -> Self {
            Self {
                create_error: None,
                remove_error: None,
                requests: Mutex::new(Vec::new()),
                removed: Mutex::new(Vec::new()),
            }
        }

        fn create_fails(error: CreateMappingError) -> Self {
            Self {
                create_error: Some(error),
                ..Self::succeeds()
            }
        }

        fn remove_fails(error: CreateMappingError) -> Self {
            Self {
                remove_error: Some(error),
                ..Self::succeeds()
            }
        }
    }

    impl MemoryRegionAccess for TestMemoryAccess {
        type Region = TestRegion;

        fn create_and_track_mapping(
            &self,
            location: Location,
            size: usize,
            allocation_strategy: AllocationStrategy,
            protection: ProtFlags,
        ) -> Result<UserspacePtr<u8>, CreateMappingError> {
            self.requests.lock().push(MappingRequest {
                anywhere: matches!(location, Location::Anywhere),
                size,
                allocation_strategy,
                protection,
            });
            if let Some(error) = self.create_error {
                return Err(error);
            }

            // SAFETY: the test only compares the lower-half address; it never
            // dereferences the pointer.
            Ok(unsafe { UserspacePtr::try_from_usize(MAPPED_ADDR).unwrap() })
        }

        fn add_memory_region(&self, _region: Self::Region) {
            unreachable!("sys_malloc commits through create_and_track_mapping")
        }

        fn remove_memory_region(&self, addr: UserspacePtr<u8>) -> Result<(), CreateMappingError> {
            self.removed.lock().push(addr.addr());
            self.remove_error.map_or(Ok(()), Err)
        }
    }

    #[test]
    fn malloc_rejects_zero_without_creating_a_mapping() {
        let cx = TestMemoryAccess::succeeds();

        assert_eq!(sys_malloc(&cx, 0), Err(EINVAL));
        assert!(cx.requests.lock().is_empty());
    }

    #[test]
    fn malloc_requests_an_eager_read_write_mapping_anywhere() {
        let cx = TestMemoryAccess::succeeds();

        assert_eq!(sys_malloc(&cx, 4096), Ok(MAPPED_ADDR));
        assert_eq!(
            cx.requests.lock().as_slice(),
            [MappingRequest {
                anywhere: true,
                size: 4096,
                allocation_strategy: AllocationStrategy::Eager,
                protection: ProtFlags::READ | ProtFlags::WRITE,
            }]
        );
    }

    #[test]
    fn malloc_maps_all_context_errors_to_the_documented_errno() {
        for (error, expected) in [
            (CreateMappingError::InvalidRequest, EINVAL),
            (CreateMappingError::LocationAlreadyMapped, EINVAL),
            (CreateMappingError::OutOfMemory, ENOMEM),
            (CreateMappingError::NotFound, EINVAL),
            (CreateMappingError::Unsupported, EINVAL),
        ] {
            let cx = TestMemoryAccess::create_fails(error);
            assert_eq!(sys_malloc(&cx, 4096), Err(expected));
        }
    }

    #[test]
    fn free_rejects_null_and_kernel_addresses_without_removing_a_region() {
        let cx = TestMemoryAccess::succeeds();

        assert_eq!(sys_free(&cx, 0), Err(EINVAL));
        assert_eq!(sys_free(&cx, 0xffff_8000_0000_0000), Err(EINVAL));
        assert!(cx.removed.lock().is_empty());
    }

    #[test]
    fn free_removes_the_requested_userspace_region() {
        let cx = TestMemoryAccess::succeeds();

        assert_eq!(sys_free(&cx, MAPPED_ADDR), Ok(0));
        assert_eq!(cx.removed.lock().as_slice(), [MAPPED_ADDR]);
    }

    #[test]
    fn free_maps_context_errors_to_invalid_argument() {
        for error in [
            CreateMappingError::NotFound,
            CreateMappingError::OutOfMemory,
        ] {
            let cx = TestMemoryAccess::remove_fails(error);
            assert_eq!(sys_free(&cx, MAPPED_ADDR), Err(EINVAL));
            assert_eq!(cx.removed.lock().as_slice(), [MAPPED_ADDR]);
        }
    }
}
