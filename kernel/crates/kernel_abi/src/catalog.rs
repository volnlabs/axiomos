//! Versioned, shipped userspace ABI catalog.
//!
//! Entries in these tables are implemented by production kernel builds. Reserved
//! numbers and development-only instrumentation deliberately do not appear here.

use crate::bpf::*;
use crate::syscall::*;

/// Current axiomos userspace ABI major version.
pub const AXIOMOS_ABI_MAJOR: u16 = 1;
/// Current axiomos userspace ABI minor version.
pub const AXIOMOS_ABI_MINOR: u16 = 0;

/// One supported numeric ABI entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbiEntry {
    pub id: u32,
    pub name: &'static str,
    pub availability: &'static str,
}

macro_rules! entry {
    ($id:ident, $availability:literal) => {
        AbiEntry {
            id: $id as u32,
            name: stringify!($id),
            availability: $availability,
        }
    };
}

/// Syscalls dispatched by shipped x86_64 and AArch64 kernels.
pub const SUPPORTED_SYSCALLS: &[AbiEntry] = &[
    entry!(SYS_EXIT, "all shipped kernels"),
    entry!(SYS_OPEN, "all shipped kernels"),
    entry!(SYS_FSTAT, "all shipped kernels"),
    entry!(SYS_MALLOC, "all shipped kernels"),
    entry!(SYS_FREE, "all shipped kernels"),
    entry!(SYS_ABORT, "all shipped kernels"),
    entry!(SYS_GETCWD, "all shipped kernels"),
    entry!(SYS_READ, "all shipped kernels"),
    entry!(SYS_WRITE, "all shipped kernels"),
    entry!(SYS_WRITEV, "all shipped kernels"),
    entry!(SYS_LSEEK, "all shipped kernels"),
    entry!(SYS_CLOSE, "all shipped kernels"),
    entry!(SYS_MMAP, "all shipped kernels"),
    entry!(SYS_DUP, "all shipped kernels"),
    entry!(SYS_DUP2, "all shipped kernels"),
    entry!(SYS_PIPE, "all shipped kernels"),
    entry!(SYS_BPF, "all shipped kernels"),
    entry!(SYS_PWM_CONFIG, "Raspberry Pi 5"),
    entry!(SYS_PWM_WRITE, "Raspberry Pi 5"),
    entry!(SYS_PWM_ENABLE, "Raspberry Pi 5"),
    entry!(SYS_CLOCK_GETTIME, "all shipped kernels"),
    entry!(SYS_NANOSLEEP, "all shipped kernels"),
    entry!(SYS_SPAWN, "all shipped kernels"),
    entry!(SYS_FORK, "all shipped kernels"),
    entry!(SYS_EXECVE, "all shipped kernels"),
    entry!(SYS_WAITPID, "all shipped kernels"),
    entry!(SYS_DEBUG, "all shipped kernels"),
    entry!(SYS_ESTOP, "all shipped kernels"),
    entry!(SYS_SPAWN_RESTRICTED, "all shipped kernels"),
    entry!(SYS_RESTRICT_BPF_CAPABILITIES, "all shipped kernels"),
    entry!(SYS_INTERRUPT_SLEEP, "all shipped kernels"),
];

/// BPF commands implemented by shipped kernels.
pub const SUPPORTED_BPF_COMMANDS: &[AbiEntry] = &[
    entry!(BPF_MAP_CREATE, "all shipped kernels"),
    entry!(BPF_MAP_LOOKUP_ELEM, "all shipped kernels"),
    entry!(BPF_MAP_UPDATE_ELEM, "all shipped kernels"),
    entry!(BPF_MAP_DELETE_ELEM, "all shipped kernels"),
    entry!(BPF_PROG_LOAD, "all shipped kernels"),
    entry!(BPF_OBJ_PIN, "all shipped kernels"),
    entry!(BPF_OBJ_GET, "all shipped kernels"),
    entry!(BPF_PROG_ATTACH, "all shipped kernels"),
    entry!(BPF_PROG_DETACH, "all shipped kernels"),
    entry!(BPF_OBJ_GET_INFO_BY_FD, "all shipped kernels"),
    entry!(BPF_PROG_LOAD_ELF, "all shipped kernels"),
    entry!(BPF_RINGBUF_POLL, "all shipped kernels"),
    entry!(BPF_PROG_UNLOAD, "all shipped kernels"),
    entry!(BPF_MAP_DESTROY, "all shipped kernels"),
    entry!(BPF_OBJ_UNPIN, "all shipped kernels"),
];

/// Map types accepted by `BPF_MAP_CREATE`.
pub const SUPPORTED_BPF_MAP_TYPES: &[AbiEntry] = &[
    entry!(BPF_MAP_TYPE_HASH, "cloud and embedded profiles"),
    entry!(BPF_MAP_TYPE_ARRAY, "cloud and embedded profiles"),
    entry!(BPF_MAP_TYPE_RINGBUF, "cloud and embedded profiles"),
    entry!(BPF_MAP_TYPE_TIMESERIES, "cloud and embedded profiles"),
];

/// Attach types accepted by `BPF_PROG_ATTACH`.
pub const SUPPORTED_BPF_ATTACH_TYPES: &[AbiEntry] = &[
    entry!(BPF_ATTACH_TYPE_TIMER, "cloud and embedded profiles"),
    entry!(BPF_ATTACH_TYPE_GPIO, "Raspberry Pi 5"),
    entry!(BPF_ATTACH_TYPE_IIO, "Raspberry Pi 5"),
    entry!(BPF_ATTACH_TYPE_SYS_ENTER, "cloud and embedded profiles"),
    entry!(BPF_ATTACH_TYPE_SYS_EXIT, "cloud and embedded profiles"),
    entry!(BPF_ATTACH_TYPE_SCHED_SWITCH, "cloud and embedded profiles"),
];

/// Helpers dispatched by the shipped interpreter.
pub const SUPPORTED_BPF_HELPERS: &[AbiEntry] = &[
    entry!(BPF_HELPER_KTIME_GET_NS, "cloud and embedded profiles"),
    entry!(BPF_HELPER_TRACE_PRINTK, "cloud profile"),
    entry!(BPF_HELPER_MAP_LOOKUP_ELEM, "cloud and embedded profiles"),
    entry!(BPF_HELPER_MAP_UPDATE_ELEM, "cloud and embedded profiles"),
    entry!(BPF_HELPER_MAP_DELETE_ELEM, "cloud and embedded profiles"),
    entry!(BPF_HELPER_RINGBUF_OUTPUT, "cloud and embedded profiles"),
    entry!(BPF_HELPER_TIMESERIES_PUSH, "cloud and embedded profiles"),
    entry!(
        BPF_HELPER_GET_INTERRUPT_LATENCY_NS,
        "cloud and embedded profiles"
    ),
    entry!(BPF_HELPER_GET_BOOT_TIME_MS, "cloud and embedded profiles"),
    entry!(BPF_HELPER_GET_KERNEL_HEAP_KB, "cloud and embedded profiles"),
    entry!(
        BPF_HELPER_GET_KERNEL_IMAGE_MB,
        "cloud and embedded profiles"
    ),
    entry!(BPF_HELPER_GPIO_SET, "Raspberry Pi 5"),
    entry!(BPF_HELPER_GPIO_GET, "Raspberry Pi 5"),
    entry!(BPF_HELPER_PWM_WRITE, "Raspberry Pi 5"),
    entry!(BPF_HELPER_MOTOR_PAIR_V1, "Raspberry Pi 5 (experimental v1)"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_catalogs_have_unique_ids() {
        for catalog in [
            SUPPORTED_SYSCALLS,
            SUPPORTED_BPF_COMMANDS,
            SUPPORTED_BPF_MAP_TYPES,
            SUPPORTED_BPF_ATTACH_TYPES,
            SUPPORTED_BPF_HELPERS,
        ] {
            for (index, entry) in catalog.iter().enumerate() {
                assert!(
                    catalog[index + 1..]
                        .iter()
                        .all(|other| other.id != entry.id),
                    "duplicate ABI id {} in catalog containing {}",
                    entry.id,
                    entry.name
                );
            }
        }
    }
}
