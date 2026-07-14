use bitflags::bitflags;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

bitflags! {
    pub struct BpfMapTags: u32 {
        const UNSPEC       = 0;
        const HASH         = 1;
        const ARRAY        = 2;
        const PROG_ARRAY   = 3;
        const PERF_EVENT_ARRAY = 4;
        const PER_CPU_HASH = 5;
        const PER_CPU_ARRAY = 6;
        const STACK_TRACE  = 7;
        const CGROUP_ARRAY = 8;
        const LRU_HASH     = 9;
        const LRU_PER_CPU_HASH = 10;
        const LPM_TRIE     = 11;
        const ARRAY_OF_MAPS = 12;
        const HASH_OF_MAPS = 13;
        const DEVMAP       = 14;
        const SOCKMAP      = 15;
        const CPUMAP       = 16;
        const XSKMAP       = 17;
        const SOCKHASH     = 18;
        const CGROUP_STORAGE = 19;
        const REUSEPORT_SOCKARRAY = 20;
        const PERCPU_CGROUP_STORAGE = 21;
        const QUEUE        = 22;
        const STACK        = 23;
        const SK_STORAGE   = 24;
        const DEVMAP_HASH  = 25;
        const STRUCT_OPS   = 26;
        const RINGBUF      = 27;
        const INODE_STORAGE = 28;
    }
}

pub const BPF_MAP_CREATE: u32 = 0;
pub const BPF_MAP_LOOKUP_ELEM: u32 = 1;
pub const BPF_MAP_UPDATE_ELEM: u32 = 2;
pub const BPF_MAP_DELETE_ELEM: u32 = 3;
pub const BPF_MAP_GET_NEXT_KEY: u32 = 4;
pub const BPF_PROG_LOAD: u32 = 5;
pub const BPF_OBJ_PIN: u32 = 6;
pub const BPF_OBJ_GET: u32 = 7;
pub const BPF_PROG_ATTACH: u32 = 8;
pub const BPF_PROG_DETACH: u32 = 9;
pub const BPF_PROG_TEST_RUN: u32 = 10;
pub const BPF_PROG_GET_NEXT_ID: u32 = 11;
pub const BPF_MAP_GET_NEXT_ID: u32 = 12;
pub const BPF_PROG_GET_FD_BY_ID: u32 = 13;
pub const BPF_MAP_GET_FD_BY_ID: u32 = 14;
pub const BPF_OBJ_GET_INFO_BY_FD: u32 = 15;
pub const BPF_PROG_QUERY: u32 = 16;
pub const BPF_RAW_TRACEPOINT_OPEN: u32 = 17;
pub const BPF_BTF_LOAD: u32 = 18;
pub const BPF_BTF_GET_FD_BY_ID: u32 = 19;
pub const BPF_TASK_FD_QUERY: u32 = 20;
pub const BPF_MAP_LOOKUP_AND_DELETE_ELEM: u32 = 21;
pub const BPF_MAP_FREEZE: u32 = 22;
pub const BPF_BTF_GET_NEXT_ID: u32 = 23;
pub const BPF_MAP_LOOKUP_BATCH: u32 = 24;
pub const BPF_MAP_LOOKUP_AND_DELETE_BATCH: u32 = 25;
pub const BPF_MAP_UPDATE_BATCH: u32 = 26;
pub const BPF_MAP_DELETE_BATCH: u32 = 27;
pub const BPF_LINK_CREATE: u32 = 28;
pub const BPF_LINK_UPDATE: u32 = 29;
pub const BPF_LINK_GET_FD_BY_ID: u32 = 30;
pub const BPF_LINK_GET_NEXT_ID: u32 = 31;
pub const BPF_ENABLE_STATS: u32 = 32;
pub const BPF_ITER_CREATE: u32 = 33;
pub const BPF_LINK_DETACH: u32 = 34;
pub const BPF_PROG_BIND_MAP: u32 = 35;
pub const BPF_PROG_LOAD_ELF: u32 = 36; // Custom command for loading ELF files
pub const BPF_RINGBUF_POLL: u32 = 37; // Custom command for polling ringbuf events

// Custom command: execute a loaded program N times and emit an
// `AXIOM EXEC COST` timing marker over serial. Only honoured by kernels built
// with the `verifier-cost` measurement feature; rejected otherwise.
// attach_prog_fd = program id, attach_btf_id = run count.
pub const BPF_BENCH_EXEC: u32 = 100;
/// Custom lifecycle commands. Object handles encode a slot plus generation;
/// reclaimed slots can be reused without allowing stale-handle aliasing.
pub const BPF_PROG_UNLOAD: u32 = 101;
pub const BPF_MAP_DESTROY: u32 = 102;
pub const BPF_OBJ_UNPIN: u32 = 103;

/// Map type identifiers accepted by shipped kernels.
pub const BPF_MAP_TYPE_HASH: u32 = 1;
pub const BPF_MAP_TYPE_ARRAY: u32 = 2;
pub const BPF_MAP_TYPE_RINGBUF: u32 = 27;
pub const BPF_MAP_TYPE_TIMESERIES: u32 = 100;

/// Program attach identifiers accepted by shipped kernels.
pub const BPF_ATTACH_TYPE_TIMER: u32 = 1;
pub const BPF_ATTACH_TYPE_GPIO: u32 = 2;
pub const BPF_ATTACH_TYPE_PWM: u32 = 3;
pub const BPF_ATTACH_TYPE_IIO: u32 = 4;
pub const BPF_ATTACH_TYPE_SYS_ENTER: u32 = 5;
pub const BPF_ATTACH_TYPE_SYSCALL: u32 = BPF_ATTACH_TYPE_SYS_ENTER;
pub const BPF_ATTACH_TYPE_SYS_EXIT: u32 = 6;
pub const BPF_ATTACH_TYPE_SCHED_SWITCH: u32 = 7;

/// Helper identifiers dispatched by shipped kernels.
pub const BPF_HELPER_KTIME_GET_NS: i32 = 1;
pub const BPF_HELPER_TRACE_PRINTK: i32 = 2;
pub const BPF_HELPER_GET_PRANDOM_U32: i32 = 3;
pub const BPF_HELPER_GET_SMP_PROCESSOR_ID: i32 = 4;
pub const BPF_HELPER_MAP_LOOKUP_ELEM: i32 = 5;
pub const BPF_HELPER_MAP_UPDATE_ELEM: i32 = 6;
pub const BPF_HELPER_MAP_DELETE_ELEM: i32 = 7;
pub const BPF_HELPER_RINGBUF_OUTPUT: i32 = 8;
pub const BPF_HELPER_TIMESERIES_PUSH: i32 = 9;
pub const BPF_HELPER_GET_CURRENT_PID_TGID: i32 = 10;
pub const BPF_HELPER_GET_CURRENT_UID_GID: i32 = 11;
pub const BPF_HELPER_GET_CURRENT_COMM: i32 = 12;
pub const BPF_HELPER_GET_INTERRUPT_LATENCY_NS: i32 = 13;
pub const BPF_HELPER_PROBE_READ: i32 = 14;
pub const BPF_HELPER_GET_BOOT_TIME_MS: i32 = 15;
pub const BPF_HELPER_GET_KERNEL_HEAP_KB: i32 = 16;
pub const BPF_HELPER_GET_KERNEL_IMAGE_MB: i32 = 17;
pub const BPF_HELPER_RINGBUF_RESERVE: i32 = 40;
pub const BPF_HELPER_RINGBUF_SUBMIT: i32 = 41;
pub const BPF_HELPER_RINGBUF_DISCARD: i32 = 42;
pub const BPF_HELPER_SENSOR_LAST_TIMESTAMP: i32 = 1002;
pub const BPF_HELPER_GPIO_SET: i32 = 1003;
pub const BPF_HELPER_GPIO_GET: i32 = 1004;
pub const BPF_HELPER_PWM_WRITE: i32 = 1005;
pub const BPF_HELPER_IIO_READ: i32 = 1006;
pub const BPF_HELPER_CAN_SEND: i32 = 1007;

/// Requested/offered access rights in [`BpfAttr::file_flags`] for object pin/open.
/// Zero is accepted as a backwards-compatible read-only request.
pub const BPF_OBJ_ACCESS_READ: u32 = 1 << 0;
pub const BPF_OBJ_ACCESS_WRITE: u32 = 1 << 1;
pub const BPF_OBJ_ACCESS_MASK: u32 = BPF_OBJ_ACCESS_READ | BPF_OBJ_ACCESS_WRITE;

/// Capability bits accepted by `SYS_SPAWN_RESTRICTED`.
pub const BPF_CAP_PROGRAM_LOAD: u32 = 1 << 0;
pub const BPF_CAP_MAP_CREATE: u32 = 1 << 1;
pub const BPF_CAP_MAP_READ: u32 = 1 << 2;
pub const BPF_CAP_MAP_WRITE: u32 = 1 << 3;
pub const BPF_CAP_ATTACH_TRACE: u32 = 1 << 4;
pub const BPF_CAP_ATTACH_SCHEDULER: u32 = 1 << 5;
pub const BPF_CAP_ATTACH_DEVICE: u32 = 1 << 6;
pub const BPF_CAP_OBJECT_PIN: u32 = 1 << 7;
pub const BPF_CAP_ACTUATE: u32 = 1 << 8;
pub const BPF_CAP_PRIVILEGED_VERIFY: u32 = 1 << 9;
pub const BPF_CAP_OBJECT_ADMIN: u32 = 1 << 10;
pub const BPF_CAP_ALL: u32 = BPF_CAP_PROGRAM_LOAD
    | BPF_CAP_MAP_CREATE
    | BPF_CAP_MAP_READ
    | BPF_CAP_MAP_WRITE
    | BPF_CAP_ATTACH_TRACE
    | BPF_CAP_ATTACH_SCHEDULER
    | BPF_CAP_ATTACH_DEVICE
    | BPF_CAP_OBJECT_PIN
    | BPF_CAP_ACTUATE
    | BPF_CAP_PRIVILEGED_VERIFY
    | BPF_CAP_OBJECT_ADMIN;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, KnownLayout, Immutable)]
pub struct BpfAttr {
    // Field 0-1: Used by multiple commands
    // - MAP_CREATE: map_type, key_size
    // - PROG_LOAD: prog_type, insn_cnt
    pub prog_type: u32, // Also used as map_type for MAP_CREATE
    pub insn_cnt: u32,  // Also used as key_size for MAP_CREATE

    // Field 2-3: Command-specific
    // - MAP_CREATE: value_size, max_entries
    // - PROG_LOAD: insns pointer (u64)
    pub insns: u64, // Also: value_size (low u32) + max_entries (high u32) for MAP_CREATE

    pub license: u64, // pointer to license string
    pub log_level: u32,
    pub log_size: u32,
    pub log_buf: u64, // pointer to log buffer
    pub kern_version: u32,
    pub prog_flags: u32,
    pub prog_name: [u8; 16],
    pub prog_ifindex: u32,
    pub expected_attach_type: u32,
    pub prog_btf_fd: u32,
    pub func_info_rec_size: u32,
    pub func_info: u64,
    pub func_info_cnt: u32,
    pub line_info_rec_size: u32,
    pub line_info: u64,
    pub line_info_cnt: u32,
    pub attach_btf_id: u32,
    pub attach_prog_fd: u32, // Also used as map_fd for MAP_LOOKUP/UPDATE

    // Map element operations (MAP_LOOKUP_ELEM, MAP_UPDATE_ELEM, MAP_DELETE_ELEM)
    pub map_fd: u32,
    pub key: u64,   // pointer to key
    pub value: u64, // pointer to value (or next_key for GET_NEXT_KEY)
    pub flags: u64, // update flags

    // Object pin/get operations
    pub pathname: u64, // pointer to null-terminated object path
    pub path_len: u32, // maximum path length including null terminator
    pub file_flags: u32,

    // Object info queries
    pub info: u64,     // pointer to output info struct
    pub info_len: u32, // output info buffer length
    pub _reserved: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct BpfObjectInfo {
    pub id: u32,
    pub object_kind: u32,
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
}

pub const BPF_OBJECT_KIND_MAP: u32 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bpf_capabilities_are_independent_and_covered_by_all() {
        let capabilities = [
            BPF_CAP_PROGRAM_LOAD,
            BPF_CAP_MAP_CREATE,
            BPF_CAP_MAP_READ,
            BPF_CAP_MAP_WRITE,
            BPF_CAP_ATTACH_TRACE,
            BPF_CAP_ATTACH_SCHEDULER,
            BPF_CAP_ATTACH_DEVICE,
            BPF_CAP_OBJECT_PIN,
            BPF_CAP_ACTUATE,
            BPF_CAP_PRIVILEGED_VERIFY,
            BPF_CAP_OBJECT_ADMIN,
        ];

        for (index, capability) in capabilities.iter().enumerate() {
            assert_eq!(capability.count_ones(), 1);
            assert_ne!(BPF_CAP_ALL & capability, 0);
            assert!(
                capabilities[index + 1..]
                    .iter()
                    .all(|other| capability & other == 0)
            );
        }
    }
}
