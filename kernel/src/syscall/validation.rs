use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::mem::size_of;

use kernel_abi::{Errno, EFAULT, EINVAL};
use kernel_usermem::{UserMemError, UserMemory, MAX_USER_COPY};
use kernel_virtual_memory::VirtAddr;
use zerocopy::{FromBytes, Immutable, KnownLayout};

use crate::mcore::context::ExecutionContext;
use crate::mcore::mtask::process::Process;

struct CurrentUserMemory {
    process: Arc<Process>,
}

impl CurrentUserMemory {
    fn new() -> Self {
        Self {
            process: ExecutionContext::load().current_process(),
        }
    }

    fn map_error(error: UserMemError) -> Errno {
        log::debug!("userspace copy rejected: {error}");
        error.into()
    }
}

impl UserMemory for CurrentUserMemory {
    fn copy_from_user(&mut self, dst: &mut [u8], src_addr: VirtAddr) -> Result<(), UserMemError> {
        self.process
            .with_address_space(|address_space| address_space.copy_from_user(dst, src_addr))
    }

    fn copy_to_user(&mut self, dst_addr: VirtAddr, src: &[u8]) -> Result<(), UserMemError> {
        self.process
            .with_address_space(|address_space| address_space.copy_to_user(dst_addr, src))
    }

    fn copy_cstr_from_user(
        &mut self,
        dst: &mut [u8],
        src_addr: VirtAddr,
    ) -> Result<usize, UserMemError> {
        self.process
            .with_address_space(|address_space| address_space.copy_cstr_from_user(dst, src_addr))
    }
}

/// Copy a byte-valid plain-data value from the current process.
pub fn copy_from_userspace<T>(ptr: usize) -> Result<T, Errno>
where
    T: FromBytes + KnownLayout + Immutable,
{
    let mut bytes = vec![0u8; size_of::<T>()];
    CurrentUserMemory::new()
        .copy_from_user(&mut bytes, VirtAddr::new(ptr as u64))
        .map_err(CurrentUserMemory::map_error)?;
    T::read_from_bytes(&bytes).map_err(|_| EFAULT)
}

/// Read an owned byte slice from the current process.
pub fn read_userspace_slice(ptr: usize, len: usize) -> Result<Vec<u8>, Errno> {
    if len == 0 {
        return Ok(Vec::new());
    }
    if len > MAX_USER_COPY {
        return Err(EINVAL);
    }

    let mut bytes = vec![0u8; len];
    CurrentUserMemory::new()
        .copy_from_user(&mut bytes, VirtAddr::new(ptr as u64))
        .map_err(CurrentUserMemory::map_error)?;
    Ok(bytes)
}

/// Read a NUL-terminated UTF-8 string from the current process.
pub fn read_userspace_string(ptr: usize, max_len: usize) -> Result<String, Errno> {
    if max_len == 0 || max_len > MAX_USER_COPY {
        return Err(EINVAL);
    }

    let mut bytes = vec![0u8; max_len];
    let len = CurrentUserMemory::new()
        .copy_cstr_from_user(&mut bytes, VirtAddr::new(ptr as u64))
        .map_err(CurrentUserMemory::map_error)?;
    bytes.truncate(len);
    String::from_utf8(bytes).map_err(|_| EINVAL)
}

/// Read a NUL-terminated array of userspace pointers to UTF-8 strings.
pub fn read_userspace_string_array(
    ptr: usize,
    max_count: usize,
    max_string_len: usize,
) -> Result<Vec<String>, Errno> {
    if ptr == 0 {
        return Ok(Vec::new());
    }
    if max_count > MAX_USER_COPY / size_of::<usize>() || max_string_len > MAX_USER_COPY {
        return Err(EINVAL);
    }

    let mut strings = Vec::new();
    for index in 0..max_count {
        let offset = index.checked_mul(size_of::<usize>()).ok_or(EINVAL)?;
        let current_addr = ptr.checked_add(offset).ok_or(EINVAL)?;
        let string_ptr = copy_from_userspace::<usize>(current_addr)?;
        if string_ptr == 0 {
            return Ok(strings);
        }
        strings.push(read_userspace_string(string_ptr, max_string_len)?);
    }

    Err(EINVAL)
}

/// Copy kernel bytes to a writable range in the current process.
pub fn copy_to_userspace(ptr: usize, data: &[u8]) -> Result<(), Errno> {
    if data.is_empty() {
        return Ok(());
    }
    CurrentUserMemory::new()
        .copy_to_user(VirtAddr::new(ptr as u64), data)
        .map_err(CurrentUserMemory::map_error)
}
