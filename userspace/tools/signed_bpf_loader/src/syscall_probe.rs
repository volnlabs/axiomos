//! Opt-in QEMU probe run by the real dedicated installer, before UART service.
//! Uses actual syscalls, credentials, process memory and preparation worker.
use core::mem::size_of;

use kernel_abi::*;
use minilib::{exit, write};

const UNMAPPED: usize = 0x0000_7000_0000_0000;
const POLL_LIMIT: usize = 500;

// An immutable ELF data segment: input is valid, but query copy-back must fail.
static READ_ONLY_SLOT: [u8; size_of::<ManagedSlotV1>()] = {
    let mut bytes = [0; size_of::<ManagedSlotV1>()];
    bytes[0] = MANAGED_ADMIN_VERSION as u8;
    bytes[4] = size_of::<ManagedSlotV1>() as u8;
    bytes
};

fn decimal(value: isize) {
    if value < 0 {
        write(1, b"-");
    }
    let mut value = value.unsigned_abs();
    let mut buffer = [0u8; 20];
    let mut position = buffer.len();
    loop {
        position -= 1;
        buffer[position] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    write(1, &buffer[position..]);
}

fn fail(stage: &[u8], observed: isize, expected: isize) -> ! {
    write(1, b"MANAGED_SYSCALL_PROBE_FAIL stage=");
    write(1, stage);
    write(1, b" observed=");
    decimal(observed);
    write(1, b" expected=");
    decimal(expected);
    write(1, b"\n");
    exit(1)
}

fn check(stage: &[u8], observed: isize, expected: isize) {
    if observed != expected {
        fail(stage, observed, expected);
    }
}

fn require(stage: &[u8], condition: bool) {
    check(stage, isize::from(condition), 1);
}

fn syscall(command: u32, address: usize, size: usize) -> isize {
    minilib::syscall3(SYS_BPF, command as usize, address, size) as isize
}

fn call<T>(command: u32, request: &mut T) -> isize {
    syscall(
        command,
        core::ptr::from_mut(request) as usize,
        size_of::<T>(),
    )
}

fn slot_request() -> ManagedSlotV1 {
    ManagedSlotV1 {
        version: MANAGED_ADMIN_VERSION,
        size: size_of::<ManagedSlotV1>() as u32,
        ..Default::default()
    }
}

fn operation(id: u64) -> ManagedOperationV1 {
    let mut request = ManagedOperationV1 {
        version: MANAGED_ADMIN_VERSION,
        size: size_of::<ManagedOperationV1>() as u32,
        id,
        ..Default::default()
    };
    check(
        b"operation-query",
        call(BPF_MANAGED_OPERATION_QUERY, &mut request),
        0,
    );
    request
}

fn shape_and_copy_checks() {
    let mut slot = slot_request();
    check(b"slot-query", call(BPF_MANAGED_SLOT_QUERY, &mut slot), 0);
    require(
        b"slot-copyback",
        slot.generation == 0 && slot.last_id == 0 && slot.flags == MANAGED_SLOT_INHIBITED,
    );
    let query = operation(0);
    require(
        b"empty-operation",
        query.id == 0 && query.phase == MANAGED_OPERATION_IDLE,
    );
    write(1, b"MANAGED_SYSCALL_QUERY_OK\n");

    for size in [0, size_of::<ManagedSlotV1>() - 1, usize::MAX] {
        check(
            b"syscall-size",
            syscall(BPF_MANAGED_SLOT_QUERY, UNMAPPED, size),
            -isize::from(EINVAL),
        );
    }
    let mut slot = slot_request();
    slot.version += 1;
    check(
        b"version",
        call(BPF_MANAGED_SLOT_QUERY, &mut slot),
        -isize::from(ENOTSUP),
    );
    slot = slot_request();
    slot.size -= 1;
    check(
        b"embedded-size",
        call(BPF_MANAGED_SLOT_QUERY, &mut slot),
        -isize::from(EINVAL),
    );
    slot = slot_request();
    slot.reserved = 1;
    check(
        b"reserved",
        call(BPF_MANAGED_SLOT_QUERY, &mut slot),
        -isize::from(EINVAL),
    );
    write(1, b"MANAGED_SYSCALL_SHAPES_OK\n");

    check(
        b"unmapped-input",
        syscall(BPF_MANAGED_SLOT_QUERY, UNMAPPED, size_of::<ManagedSlotV1>()),
        -isize::from(EFAULT),
    );
    check(
        b"readonly-copyback",
        syscall(
            BPF_MANAGED_SLOT_QUERY,
            READ_ONLY_SLOT.as_ptr() as usize,
            READ_ONLY_SLOT.len(),
        ),
        -isize::from(EFAULT),
    );
    write(1, b"MANAGED_SYSCALL_USERCOPY_OK\n");
}

fn upload_worker_checks() {
    let mut begin = ManagedUploadBeginV1 {
        version: MANAGED_ADMIN_VERSION,
        size: size_of::<ManagedUploadBeginV1>() as u32,
        expected_last_id: 0,
        total_bytes: 16,
        reserved: 0,
    };
    let accepted = call(BPF_MANAGED_UPLOAD_BEGIN, &mut begin);
    if accepted <= 0 {
        fail(b"upload-begin", accepted, 1);
    }
    let id = accepted as u64;
    let query = operation(id);
    require(
        b"upload-status",
        query.id == id
            && query.phase == MANAGED_OPERATION_UPLOADING
            && query.total_bytes == 16
            && query.received_bytes == 0,
    );
    let mut chunk = ManagedUploadChunkV1 {
        version: MANAGED_ADMIN_VERSION,
        size: size_of::<ManagedUploadChunkV1>() as u32,
        id,
        offset: 0,
        length: 16,
        reserved: 0,
        bytes: [0; MANAGED_UPLOAD_CHUNK_BYTES],
    };
    check(
        b"upload-chunk",
        call(BPF_MANAGED_UPLOAD_CHUNK, &mut chunk),
        16,
    );
    let mut finalize = ManagedOperationRequestV1 {
        version: MANAGED_ADMIN_VERSION,
        size: size_of::<ManagedOperationRequestV1>() as u32,
        id,
        reserved: 0,
    };
    check(
        b"upload-finalize",
        call(BPF_MANAGED_UPLOAD_FINALIZE, &mut finalize),
        accepted,
    );
    // Deliberately truncated unsigned bytes: only the asynchronous worker can
    // authenticate/parse and produce this terminal error. No valid code runs.
    let mut terminal = false;
    for _ in 0..POLL_LIMIT {
        let query = operation(id);
        require(
            b"worker-identity",
            query.id == id && query.total_bytes == 16 && query.received_bytes == 16,
        );
        if query.phase == MANAGED_OPERATION_FAILED {
            check(b"worker-error", query.error as isize, isize::from(EINVAL));
            terminal = true;
            break;
        }
        require(
            b"worker-phase",
            matches!(
                query.phase,
                MANAGED_OPERATION_QUEUED | MANAGED_OPERATION_PREPARING | MANAGED_OPERATION_CLEANUP
            ),
        );
        minilib::msleep(10);
    }
    require(b"worker-poll-limit", terminal);
    let mut slot = slot_request();
    check(b"terminal-slot", call(BPF_MANAGED_SLOT_QUERY, &mut slot), 0);
    require(
        b"terminal-slot-copyback",
        slot.last_id == id && slot.generation == 0 && slot.flags == MANAGED_SLOT_INHIBITED,
    );
    write(1, b"MANAGED_SYSCALL_WORKER_OK\n");
}

fn capability_checks() {
    let mut legacy = BpfAttr::default();
    check(
        b"admin-legacy-map",
        call(BPF_MAP_CREATE, &mut legacy),
        -isize::from(EPERM),
    );
    write(1, b"MANAGED_SYSCALL_LEGACY_DENY_OK\n");
    let child = minilib::fork();
    if child < 0 {
        fail(b"fork", child as isize, 0);
    }
    if child == 0 {
        check(
            b"child-drop-capabilities",
            minilib::restrict_bpf_capabilities(0) as isize,
            0,
        );
        let mut slot = slot_request();
        check(
            b"child-managed-denial",
            call(BPF_MANAGED_SLOT_QUERY, &mut slot),
            -isize::from(EPERM),
        );
        check(
            b"child-denial-before-copy",
            syscall(BPF_MANAGED_SLOT_QUERY, UNMAPPED, size_of::<ManagedSlotV1>()),
            -isize::from(EPERM),
        );
        exit(0);
    }
    let mut waited = false;
    for _ in 0..POLL_LIMIT {
        let mut status = -1;
        let result = minilib::waitpid(child, &mut status, minilib::WNOHANG);
        if result == child {
            check(b"child-exit", status as isize, 0);
            waited = true;
            break;
        }
        check(b"child-wait", result as isize, 0);
        minilib::msleep(10);
    }
    require(b"child-wait-limit", waited);
    // Child capability restriction must not alter its installer parent's rights.
    let mut slot = slot_request();
    check(
        b"parent-authority-retained",
        call(BPF_MANAGED_SLOT_QUERY, &mut slot),
        0,
    );
    write(1, b"MANAGED_SYSCALL_CHILD_DENY_OK\n");
}

pub(super) fn run() -> ! {
    shape_and_copy_checks();
    upload_worker_checks();
    capability_checks();
    write(1, b"MANAGED_SYSCALL_PROBE_OK\n");
    exit(0)
}
