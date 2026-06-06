use bitflags::bitflags;

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

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
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
#[derive(Debug, Clone, Copy, Default)]
pub struct BpfObjectInfo {
    pub id: u32,
    pub object_kind: u32,
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
}

pub const BPF_OBJECT_KIND_MAP: u32 = 1;
