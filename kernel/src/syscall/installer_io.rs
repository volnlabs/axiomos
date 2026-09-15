use kernel_abi::{Errno, EAGAIN, EBUSY, EINVAL, EIO};
#[cfg(all(target_arch = "aarch64", feature = "rpi5", feature = "managed-runtime"))]
use kernel_abi::{EBADF, EPERM, ESRCH};
#[cfg(all(target_arch = "aarch64", feature = "rpi5", feature = "managed-runtime"))]
use spin::Mutex;

#[cfg(all(target_arch = "aarch64", feature = "rpi5", feature = "managed-runtime"))]
use crate::mcore::mtask::process::{fd::FdNum, BpfCapabilities, Process};

const MAX_IO: usize = 16;

fn validate_len(len: usize) -> Result<(), Errno> {
    if len > MAX_IO {
        Err(EINVAL)
    } else {
        Ok(())
    }
}

fn read_prefix<E>(
    bytes: &mut [u8],
    mut read: impl FnMut() -> Result<Option<u8>, E>,
) -> Result<usize, Errno> {
    let mut count = 0;
    while count < bytes.len() {
        match read().map_err(|_| EIO)? {
            Some(byte) => {
                bytes[count] = byte;
                count += 1;
            }
            None => break,
        }
    }
    if count == 0 && !bytes.is_empty() {
        Err(EAGAIN)
    } else {
        Ok(count)
    }
}

fn write_prefix(bytes: &[u8], mut write: impl FnMut(u8) -> bool) -> Result<usize, Errno> {
    let count = bytes
        .iter()
        .copied()
        .take_while(|byte| write(*byte))
        .count();
    if count == 0 && !bytes.is_empty() {
        Err(EAGAIN)
    } else {
        Ok(count)
    }
}

struct OwnerState {
    owner: Option<u64>,
    active: bool,
    release_on_idle: bool,
}

impl OwnerState {
    const fn new() -> Self {
        Self {
            owner: None,
            active: false,
            release_on_idle: false,
        }
    }

    fn begin(&mut self, pid: u64) -> Result<(), Errno> {
        match self.owner {
            Some(owner) if owner != pid => return Err(EBUSY),
            Some(_) if self.active => return Err(EAGAIN),
            None => self.owner = Some(pid),
            Some(_) => {}
        }
        self.active = true;
        Ok(())
    }

    fn finish(&mut self, pid: u64) {
        if self.owner != Some(pid) || !self.active {
            return;
        }
        self.active = false;
        if self.release_on_idle {
            self.owner = None;
            self.release_on_idle = false;
        }
    }

    fn release(&mut self, pid: u64) {
        if self.owner != Some(pid) {
            return;
        }
        if self.active {
            self.release_on_idle = true;
        } else {
            self.owner = None;
        }
    }

    #[cfg(test)]
    fn owner(&self) -> Option<u64> {
        self.owner
    }
}

#[cfg(all(target_arch = "aarch64", feature = "rpi5", feature = "managed-runtime"))]
static OWNER: Mutex<OwnerState> = Mutex::new(OwnerState::new());

#[cfg(all(target_arch = "aarch64", feature = "rpi5", feature = "managed-runtime"))]
struct OperationGuard {
    pid: u64,
}

#[cfg(all(target_arch = "aarch64", feature = "rpi5", feature = "managed-runtime"))]
impl OperationGuard {
    fn begin(process: &Process) -> Result<Self, Errno> {
        let pid = process.pid().as_u64();
        let mut state = OWNER.try_lock().ok_or(EAGAIN)?;
        state.begin(pid)?;
        drop(state);

        let guard = Self { pid };
        if process.exit_code().read().is_some() {
            OWNER.lock().release(pid);
            return Err(ESRCH);
        }
        Ok(guard)
    }
}

#[cfg(all(target_arch = "aarch64", feature = "rpi5", feature = "managed-runtime"))]
impl Drop for OperationGuard {
    fn drop(&mut self) {
        OWNER.lock().finish(self.pid);
    }
}

#[cfg(all(target_arch = "aarch64", feature = "rpi5", feature = "managed-runtime"))]
fn has_descriptor(process: &Process, fd: i32) -> bool {
    process
        .file_descriptors()
        .read()
        .contains_key(&FdNum::from(fd))
}

#[cfg(all(target_arch = "aarch64", feature = "rpi5", feature = "managed-runtime"))]
fn check_request(process: &Process, fd: i32, len: usize) -> Result<(), Errno> {
    validate_len(len)?;
    if !process
        .bpf_capabilities()
        .contains(BpfCapabilities::BEHAVIOR_ADMIN)
    {
        return Err(EPERM);
    }
    if !has_descriptor(process, fd) {
        return Err(EBADF);
    }
    Ok(())
}

#[cfg(all(target_arch = "aarch64", feature = "rpi5", feature = "managed-runtime"))]
pub(super) fn dispatch_read(fd: usize, ptr: usize, len: usize) -> Option<Result<usize, Errno>> {
    let process = crate::mcore::context::ExecutionContext::load().current_process();
    if fd != 0
        || !process
            .bpf_capabilities()
            .contains(BpfCapabilities::BEHAVIOR_ADMIN)
    {
        return None;
    }
    Some(read(&process, ptr, len))
}

#[cfg(all(target_arch = "aarch64", feature = "rpi5", feature = "managed-runtime"))]
fn read(process: &Process, ptr: usize, len: usize) -> Result<usize, Errno> {
    check_request(process, 0, len)?;
    if len == 0 {
        return Ok(0);
    }
    let _operation = OperationGuard::begin(process)?;
    let uart = crate::arch::aarch64::platform::rpi5::UART
        .try_lock()
        .ok_or(EAGAIN)?;
    let mut bytes = [0; MAX_IO];
    let read = read_prefix(&mut bytes[..len], || uart.try_getc_checked())?;
    drop(uart);
    super::validation::copy_to_userspace_bounded(ptr, &bytes[..read])?;
    Ok(read)
}

#[cfg(all(target_arch = "aarch64", feature = "rpi5", feature = "managed-runtime"))]
pub(super) fn dispatch_write(fd: usize, ptr: usize, len: usize) -> Option<Result<usize, Errno>> {
    let process = crate::mcore::context::ExecutionContext::load().current_process();
    if fd != 1
        || !process
            .bpf_capabilities()
            .contains(BpfCapabilities::BEHAVIOR_ADMIN)
    {
        return None;
    }
    Some(write(&process, ptr, len))
}

#[cfg(all(target_arch = "aarch64", feature = "rpi5", feature = "managed-runtime"))]
fn write(process: &Process, ptr: usize, len: usize) -> Result<usize, Errno> {
    check_request(process, 1, len)?;
    if len == 0 {
        return Ok(0);
    }
    let mut bytes = [0; MAX_IO];
    super::validation::copy_from_userspace_into(ptr, &mut bytes[..len])?;
    let _operation = OperationGuard::begin(process)?;
    let uart = crate::arch::aarch64::platform::rpi5::UART
        .try_lock()
        .ok_or(EAGAIN)?;
    write_prefix(&bytes[..len], |byte| uart.try_putc(byte))
}

#[cfg(all(target_arch = "aarch64", feature = "rpi5", feature = "managed-runtime"))]
pub(crate) fn release(pid: u64) {
    OWNER.lock().release(pid);
}

#[cfg(all(target_arch = "aarch64", feature = "rpi5", feature = "managed-runtime"))]
pub(crate) fn console_is_suppressed() -> bool {
    OWNER.try_lock().map_or(true, |state| state.owner.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ownership_is_exclusive_and_exit_waits_for_the_accepted_operation() {
        let mut state = OwnerState::new();

        assert_eq!(state.begin(7), Ok(()));
        assert_eq!(state.begin(7), Err(kernel_abi::EAGAIN));
        assert_eq!(state.begin(8), Err(kernel_abi::EBUSY));

        state.release(8);
        assert_eq!(state.owner(), Some(7));
        state.release(7);
        assert_eq!(state.owner(), Some(7));

        state.finish(7);
        assert_eq!(state.owner(), None);
        assert_eq!(state.begin(8), Ok(()));
    }

    #[test]
    fn requests_are_bounded_before_io() {
        assert_eq!(validate_len(0), Ok(()));
        assert_eq!(validate_len(16), Ok(()));
        assert_eq!(validate_len(17), Err(kernel_abi::EINVAL));
        assert_eq!(validate_len(usize::MAX), Err(kernel_abi::EINVAL));
    }

    #[test]
    fn read_returns_an_exact_prefix_and_distinguishes_idle_from_faults() {
        let mut bytes = [0; 4];
        let mut source = [
            Ok::<_, ()>(Some(0xa5)),
            Ok::<_, ()>(Some(0x5a)),
            Ok::<_, ()>(None),
        ]
        .into_iter();
        assert_eq!(read_prefix(&mut bytes, || source.next().unwrap()), Ok(2));
        assert_eq!(&bytes[..2], &[0xa5, 0x5a]);

        assert_eq!(
            read_prefix(&mut bytes, || Ok::<_, ()>(None)),
            Err(kernel_abi::EAGAIN)
        );
        assert_eq!(read_prefix(&mut bytes, || Err(())), Err(kernel_abi::EIO));
        let mut source = [Ok(Some(0xa5)), Err(())].into_iter();
        assert_eq!(
            read_prefix(&mut bytes, || source.next().unwrap()),
            Err(kernel_abi::EIO)
        );
    }

    #[test]
    fn write_returns_the_prefix_accepted_before_backpressure() {
        let mut accepted = [0; 2];
        let mut count = 0;
        assert_eq!(
            write_prefix(&[1, 2, 3], |byte| {
                if count == accepted.len() {
                    return false;
                }
                accepted[count] = byte;
                count += 1;
                true
            }),
            Ok(2)
        );
        assert_eq!(accepted, [1, 2]);
        assert_eq!(write_prefix(&[1], |_| false), Err(kernel_abi::EAGAIN));
    }
}
