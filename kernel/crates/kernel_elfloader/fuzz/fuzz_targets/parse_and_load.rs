#![no_main]

use core::alloc::Layout;

use kernel_elfloader::{ElfFile, ElfLoader};
use kernel_memapi::{Allocation, Guarded, Location, MemoryApi, UserAccessible, WritableAllocation};
use libfuzzer_sys::fuzz_target;

const MAX_TOTAL_ALLOCATION: usize = 1024 * 1024;

#[derive(Debug)]
struct FuzzAllocation {
    bytes: Vec<u8>,
    layout: Layout,
}

impl AsRef<[u8]> for FuzzAllocation {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl AsMut<[u8]> for FuzzAllocation {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

impl Allocation for FuzzAllocation {
    fn layout(&self) -> Layout {
        self.layout
    }
}

impl WritableAllocation for FuzzAllocation {}

#[derive(Clone, Debug)]
struct FuzzMemoryApi {
    remaining: usize,
}

impl Default for FuzzMemoryApi {
    fn default() -> Self {
        Self {
            remaining: MAX_TOTAL_ALLOCATION,
        }
    }
}

impl MemoryApi for FuzzMemoryApi {
    type ReadonlyAllocation = FuzzAllocation;
    type WritableAllocation = FuzzAllocation;
    type ExecutableAllocation = FuzzAllocation;

    fn allocate(
        &mut self,
        _location: Location,
        layout: Layout,
        _user_accessible: UserAccessible,
        _guarded: Guarded,
    ) -> Option<Self::WritableAllocation> {
        if layout.size() > self.remaining {
            return None;
        }
        self.remaining -= layout.size();
        Some(FuzzAllocation {
            bytes: vec![0; layout.size()],
            layout,
        })
    }

    fn make_executable(
        &mut self,
        allocation: Self::WritableAllocation,
    ) -> Result<Self::ExecutableAllocation, Self::WritableAllocation> {
        Ok(allocation)
    }

    fn make_writable(
        &mut self,
        allocation: Self::ExecutableAllocation,
    ) -> Result<Self::WritableAllocation, Self::ExecutableAllocation> {
        Ok(allocation)
    }

    fn make_readonly(
        &mut self,
        allocation: Self::WritableAllocation,
    ) -> Result<Self::ReadonlyAllocation, Self::WritableAllocation> {
        Ok(allocation)
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(elf) = ElfFile::try_parse(data) {
        let _ = ElfLoader::new(FuzzMemoryApi::default()).load(elf);
    }
});
