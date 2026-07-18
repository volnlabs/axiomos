// Crash and boundary oracle for syscall-shaped mmap arguments. The mock
// context never maps host memory; it only lets the real syscall validation
// reach its transaction boundary.

#![no_main]

use kernel_abi::{MapFlags, ProtFlags};
use kernel_syscall::UserspacePtr;
use kernel_syscall::access::{
    AllocationStrategy, CreateMappingError, Location, MemoryRegion, MemoryRegionAccess,
};
use kernel_syscall::mman::sys_mmap;
use libfuzzer_sys::fuzz_target;

struct FuzzRegion;

impl MemoryRegion for FuzzRegion {
    fn addr(&self) -> UserspacePtr<u8> {
        UserspacePtr::try_from(0x1000usize as *const u8).expect("fixed address is user space")
    }

    fn size(&self) -> usize {
        0
    }

    fn protection(&self) -> ProtFlags {
        ProtFlags::READ
    }
}

struct FuzzMemory;

impl MemoryRegionAccess for FuzzMemory {
    type Region = FuzzRegion;

    fn create_and_track_mapping(
        &self,
        location: Location,
        size: usize,
        allocation_strategy: AllocationStrategy,
        protection: ProtFlags,
    ) -> Result<UserspacePtr<u8>, CreateMappingError> {
        if size == 0 || allocation_strategy != AllocationStrategy::Eager || protection.is_empty() {
            return Err(CreateMappingError::InvalidRequest);
        }
        match location {
            Location::Anywhere => UserspacePtr::try_from(0x1000usize as *const u8)
                .map_err(|_| CreateMappingError::InvalidRequest),
            Location::Fixed(address) => {
                address
                    .validate_range(size)
                    .map_err(|_| CreateMappingError::InvalidRequest)?;
                Ok(address)
            }
        }
    }

    fn add_memory_region(&self, _region: Self::Region) {}

    fn remove_memory_region(&self, _addr: UserspacePtr<u8>) -> Result<(), CreateMappingError> {
        Ok(())
    }
}

fn word(data: &[u8], offset: usize) -> usize {
    let mut bytes = [0u8; core::mem::size_of::<usize>()];
    let available = data.get(offset..).unwrap_or_default();
    let count = available.len().min(bytes.len());
    bytes[..count].copy_from_slice(&available[..count]);
    usize::from_le_bytes(bytes)
}

fn exercise_raw_arguments(data: &[u8]) {
    let address = word(data, 0);
    let length = word(data, core::mem::size_of::<usize>());
    let prot = word(data, core::mem::size_of::<usize>() * 2) as i32;
    let flags = word(
        data,
        core::mem::size_of::<usize>() * 2 + core::mem::size_of::<i32>(),
    ) as i32;
    let fd = word(
        data,
        core::mem::size_of::<usize>() * 2 + core::mem::size_of::<i32>() * 2,
    ) as i32;
    let offset = word(
        data,
        core::mem::size_of::<usize>() * 2 + core::mem::size_of::<i32>() * 3,
    );

    let Ok(address) = UserspacePtr::try_from(address as *const u8) else {
        return;
    };
    let result = sys_mmap(&FuzzMemory, address, length, prot, flags, fd, offset);
    if let Ok(mapped) = result {
        assert!(mapped < (1usize << 47));
    }
}

fn exercise_structured_arguments(data: &[u8]) {
    let control = data.first().copied().unwrap_or_default();
    let requested_address = 0x1000usize + (word(data, 1) & 0x0000_0000_0fff_e000);
    let length = ((usize::from(control) & 0x0f) + 1) * 4096;
    let protection = match (control >> 4) & 0x03 {
        0 => ProtFlags::READ,
        1 => ProtFlags::WRITE,
        2 => ProtFlags::EXEC,
        _ => ProtFlags::READ | ProtFlags::WRITE,
    };
    let flags = MapFlags::ANONYMOUS | MapFlags::PRIVATE;
    let (address, flags) = if control & 0x40 == 0 {
        (
            UserspacePtr::try_from(0usize as *const u8).expect("null is a valid hint"),
            flags,
        )
    } else {
        (
            UserspacePtr::try_from(requested_address as *const u8)
                .expect("masked address stays in user space"),
            flags | MapFlags::FIXED,
        )
    };

    let mapped = sys_mmap(
        &FuzzMemory,
        address,
        length,
        protection.bits(),
        flags.bits(),
        -1,
        0,
    )
    .expect("structured mmap request must reach and pass the transaction boundary");
    assert!(mapped < (1usize << 47));
}

fuzz_target!(|data: &[u8]| {
    exercise_raw_arguments(data);
    exercise_structured_arguments(data);
});
