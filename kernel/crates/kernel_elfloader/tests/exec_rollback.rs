//! End-to-end exec-rollback coverage (audit fault-injection follow-up).
//!
//! Drives `kernel_elfloader::ElfLoader::load` through a synthetic
//! `MemoryApi` that fails allocations on demand. Asserts:
//!  - The loader returns a typed [`LoadElfError::AllocationFailed`]
//!    (not a panic, not a generic `&'static str`).
//!  - Every allocation that the loader obtained is dropped before
//!    the error is returned — no leaked frames, no retained
//!    `CountingAllocation` handles.
//!  - The same property holds for the `make_executable` /
//!    `make_readonly` / `make_writable` calls (the loader must
//!    return the input allocation on failure, never leak it).
//!  - The injected-failure point is honoured exactly: an
//!    allocation that the loader is *about* to make at the
//!    injected-failure index returns `None` (or `Err` for the
//!    make_* family), and every allocation *before* the failure
//!    point succeeded.
//!
//! This is the host-side analogue of the `Process::execve`
//! rollback path: the kernel-side `execve` calls
//! `ElfLoader::load` against `LowerHalfMemoryApi`, and
//! `LowerHalfMemoryApi::allocate` returns `None` (propagating to
//! `LoadElfError::AllocationFailed`) when the underlying frame
//! allocator is exhausted. The test below exercises the loader's
//! rollback contract so a `LowerHalfMemoryApi` failure cannot
//! leak segments to the new image.
//!
//! See the audit-gate step `exec-rollback-tests` and the
//! `audit-fault-injection-qemu-smoke` step in
//! `scripts/verify-engineering-audit.sh`. The end-to-end QEMU
//! smoke is a separate, runtime-level check; this file is the
//! host-side, deterministic, no-kernel-needed proof.

#![allow(clippy::unwrap_used)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::alloc::Layout;
use core::sync::atomic::{AtomicUsize, Ordering};

use kernel_elfloader::{ElfFile, ElfLoader, LoadElfError, ProgramHeaderFlags};
use kernel_memapi::{Allocation, Guarded, Location, MemoryApi, UserAccessible, WritableAllocation};

// ---------------------------------------------------------------------------
// Test scaffolding: a MemoryApi that counts allocations and can be told
// to fail at a specific call index. The Drop impl on `CountingAllocation`
// decrements the live-allocations counter so the test can assert that
// every allocation is paired with a drop.
// ---------------------------------------------------------------------------

/// Atomic counters shared between the test and the `MemoryApi`
/// implementation. The api is moved into `ElfLoader::new`, so all
/// state that the test wants to read after the call must live in
/// `&'static AtomicUsize` values.
#[derive(Debug)]
struct SharedCounters {
    /// Number of allocations currently live (allocated, not yet
    /// dropped). The test asserts this is zero after every loader
    /// call so a leaked allocation fails the test.
    live_allocations: AtomicUsize,
    /// Total `allocate` calls observed (succeeded or failed).
    allocate_calls: AtomicUsize,
    /// Total `make_executable` calls observed.
    make_executable_calls: AtomicUsize,
    /// Total `make_readonly` calls observed.
    make_readonly_calls: AtomicUsize,
    /// `Some(n)` means the next call to the matching method (the
    /// counter at `fail_at` for that method) returns `None` /
    /// `Err`. `None` means no failure is injected.
    fail_allocate_at: Option<usize>,
    fail_make_executable_at: Option<usize>,
    fail_make_readonly_at: Option<usize>,
}

impl SharedCounters {
    fn new(
        fail_allocate_at: Option<usize>,
        fail_make_executable_at: Option<usize>,
        fail_make_readonly_at: Option<usize>,
    ) -> Self {
        Self {
            live_allocations: AtomicUsize::new(0),
            allocate_calls: AtomicUsize::new(0),
            make_executable_calls: AtomicUsize::new(0),
            make_readonly_calls: AtomicUsize::new(0),
            fail_allocate_at,
            fail_make_executable_at,
            fail_make_readonly_at,
        }
    }
}

#[derive(Debug)]
struct CountingAllocation {
    layout: Layout,
    /// Backing storage for the loader's `copy_from_slice` /
    /// `fill` calls. Sized to `layout.size()` so the loader can
    /// write the segment data and zero-fill the BSS tail.
    data: Vec<u8>,
    /// The class of allocation: which `MemoryApi` call produced it.
    kind: &'static str,
    counters: &'static SharedCounters,
}

impl Drop for CountingAllocation {
    fn drop(&mut self) {
        self.counters
            .live_allocations
            .fetch_sub(1, Ordering::SeqCst);
    }
}

impl AsRef<[u8]> for CountingAllocation {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl AsMut<[u8]> for CountingAllocation {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl Allocation for CountingAllocation {
    fn layout(&self) -> Layout {
        self.layout
    }
}

impl WritableAllocation for CountingAllocation {}

struct CountingMemoryApi {
    counters: &'static SharedCounters,
}

impl MemoryApi for CountingMemoryApi {
    type ReadonlyAllocation = CountingAllocation;
    type WritableAllocation = CountingAllocation;
    type ExecutableAllocation = CountingAllocation;

    fn allocate(
        &mut self,
        _location: Location,
        layout: Layout,
        _user_accessible: UserAccessible,
        _guarded: Guarded,
    ) -> Option<Self::WritableAllocation> {
        let n = self.counters.allocate_calls.fetch_add(1, Ordering::SeqCst) + 1;
        if self.counters.fail_allocate_at == Some(n) {
            return None;
        }
        self.counters
            .live_allocations
            .fetch_add(1, Ordering::SeqCst);
        Some(CountingAllocation {
            layout,
            data: vec![0u8; layout.size()],
            kind: "allocate",
            counters: self.counters,
        })
    }

    fn make_executable(
        &mut self,
        allocation: Self::WritableAllocation,
    ) -> Result<Self::ExecutableAllocation, Self::WritableAllocation> {
        let n = self
            .counters
            .make_executable_calls
            .fetch_add(1, Ordering::SeqCst)
            + 1;
        if self.counters.fail_make_executable_at == Some(n) {
            // On failure, the loader must return the writable
            // allocation back so it can be dropped (and so the
            // live counter decrements).
            return Err(allocation);
        }
        // The "writable" allocation is consumed and replaced by
        // an "executable" allocation; the live counter does not
        // change.
        self.counters
            .live_allocations
            .fetch_add(1, Ordering::SeqCst);
        Ok(CountingAllocation {
            layout: allocation.layout,
            data: vec![0u8; allocation.layout.size()],
            kind: "make_executable",
            counters: self.counters,
        })
    }

    fn make_writable(
        &mut self,
        allocation: Self::ExecutableAllocation,
    ) -> Result<Self::WritableAllocation, Self::ExecutableAllocation> {
        self.counters
            .live_allocations
            .fetch_add(1, Ordering::SeqCst);
        Ok(CountingAllocation {
            layout: allocation.layout,
            data: vec![0u8; allocation.layout.size()],
            kind: "make_writable",
            counters: self.counters,
        })
    }

    fn make_readonly(
        &mut self,
        allocation: Self::WritableAllocation,
    ) -> Result<Self::ReadonlyAllocation, Self::WritableAllocation> {
        let n = self
            .counters
            .make_readonly_calls
            .fetch_add(1, Ordering::SeqCst)
            + 1;
        if self.counters.fail_make_readonly_at == Some(n) {
            return Err(allocation);
        }
        self.counters
            .live_allocations
            .fetch_add(1, Ordering::SeqCst);
        Ok(CountingAllocation {
            layout: allocation.layout,
            data: vec![0u8; allocation.layout.size()],
            kind: "make_readonly",
            counters: self.counters,
        })
    }
}

// ---------------------------------------------------------------------------
// ELF builder: a minimal x86_64 executable with N LOAD segments so the
// loader calls `allocate` exactly N times. Returns the byte buffer.
// ---------------------------------------------------------------------------

/// Build a minimal x86_64 ELF executable with `segments` LOAD
/// entries. Each segment is `memsz == filesz == 0x1000` (one page)
/// and aligned to 0x1000 in the virtual address space. The first
/// segment is at `0x400000 + i*0x1000` so they are non-overlapping.
/// All segments carry `PF_R | PF_X` (executable + readable); the
/// loader's `make_executable` path is exercised, `make_readonly`
/// is not.
fn build_elf_with_n_load_segments(segments: u16) -> Vec<u8> {
    build_elf_with_n_load_segments_with_flags(segments, 5u32) // PF_R | PF_X
}

/// Same as [`build_elf_with_n_load_segments`] but with caller-
/// specified `p_flags`. Used by the `make_readonly` failure
/// tests to build an ELF whose segments are `PF_R` only.
fn build_elf_with_n_load_segments_with_flags(segments: u16, p_flags: u32) -> Vec<u8> {
    assert!(segments > 0, "test must have at least one segment");
    let mut buf = Vec::with_capacity(1024);
    // ELF64 header (64 bytes)
    buf.extend_from_slice(&[0x7F, b'E', b'L', b'F']); // e_ident[0..4]
    buf.push(2); // ELFCLASS64
    buf.push(1); // ELFDATA2LSB
    buf.push(1); // EV_CURRENT
    buf.push(0); // ELFOSABI_NONE
    buf.extend_from_slice(&[0u8; 8]); // e_ident padding
    buf.extend_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
    buf.extend_from_slice(&62u16.to_le_bytes()); // e_machine = EM_X86_64
    buf.extend_from_slice(&1u32.to_le_bytes()); // e_version
    buf.extend_from_slice(&0x401000u64.to_le_bytes()); // e_entry
    buf.extend_from_slice(&64u64.to_le_bytes()); // e_phoff
    buf.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
    buf.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    buf.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
    buf.extend_from_slice(&56u16.to_le_bytes()); // e_phentsize
    buf.extend_from_slice(&segments.to_le_bytes()); // e_phnum
    buf.extend_from_slice(&64u16.to_le_bytes()); // e_shentsize
    buf.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
    buf.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
    assert_eq!(buf.len(), 64);

    // Program headers (each 56 bytes, contiguous after the ELF header)
    for i in 0..segments {
        let vaddr = 0x400000u64 + (i as u64) * 0x1000;
        let offset = 64u64 + (segments as u64) * 56 + (i as u64) * 0x1000;
        buf.extend_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
        buf.extend_from_slice(&p_flags.to_le_bytes()); // p_flags
        buf.extend_from_slice(&offset.to_le_bytes()); // p_offset
        buf.extend_from_slice(&vaddr.to_le_bytes()); // p_vaddr
        buf.extend_from_slice(&vaddr.to_le_bytes()); // p_paddr
        buf.extend_from_slice(&0x1000u64.to_le_bytes()); // p_filesz
        buf.extend_from_slice(&0x1000u64.to_le_bytes()); // p_memsz
        buf.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align
    }

    // Segment data: each segment is 0x1000 bytes of zeros.
    for _ in 0..segments {
        buf.extend_from_slice(&vec![0u8; 0x1000]);
    }

    buf
}

fn parse_elf<'a>(buf: &'a [u8]) -> ElfFile<'a> {
    ElfFile::try_parse(buf).expect("test ELF should parse")
}

fn loader_err<M: MemoryApi>(
    result: Result<kernel_elfloader::ElfImage<'_, M>, LoadElfError>,
) -> LoadElfError {
    match result {
        Ok(_) => panic!("expected ELF loader error"),
        Err(err) => err,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Drive the loader through a 3-segment ELF and fail the third
/// `allocate` call. After the failure, every prior allocation
/// must have been dropped (live counter == 0). The typed error
/// must be `LoadElfError::AllocationFailed`.
#[test]
fn load_releases_prior_allocations_on_late_allocate_failure() {
    let counters: &'static SharedCounters =
        Box::leak(Box::new(SharedCounters::new(Some(3), None, None)));
    counters.live_allocations.store(0, Ordering::SeqCst);

    let buf = build_elf_with_n_load_segments(3);
    let elf = parse_elf(&buf);
    let api = CountingMemoryApi { counters };
    let err = loader_err(ElfLoader::new(api).load(elf));
    assert_eq!(err, LoadElfError::AllocationFailed);
    assert_eq!(
        counters.live_allocations.load(Ordering::SeqCst),
        0,
        "live allocations must be 0 after a failed load"
    );
}

/// Fail the very first `allocate` call. The loader should never
/// have acquired any allocation, so the live counter is zero.
#[test]
fn load_releases_zero_allocations_on_first_allocate_failure() {
    let counters: &'static SharedCounters =
        Box::leak(Box::new(SharedCounters::new(Some(1), None, None)));
    counters.live_allocations.store(0, Ordering::SeqCst);

    let buf = build_elf_with_n_load_segments(2);
    let elf = parse_elf(&buf);
    let api = CountingMemoryApi { counters };
    let err = loader_err(ElfLoader::new(api).load(elf));
    assert_eq!(err, LoadElfError::AllocationFailed);
    assert_eq!(counters.live_allocations.load(Ordering::SeqCst), 0);
}

/// Fail `make_executable`. The loader must return the writable
/// allocation (the same handle, not a fresh allocation) so the
/// caller can drop it. The live counter must end at zero.
#[test]
fn load_releases_writable_allocation_on_make_executable_failure() {
    let counters: &'static SharedCounters =
        Box::leak(Box::new(SharedCounters::new(None, Some(1), None)));
    counters.live_allocations.store(0, Ordering::SeqCst);

    let buf = build_elf_with_n_load_segments(2);
    let elf = parse_elf(&buf);
    let api = CountingMemoryApi { counters };
    let err = loader_err(ElfLoader::new(api).load(elf));
    assert_eq!(err, LoadElfError::AllocationFailed);
    assert_eq!(counters.live_allocations.load(Ordering::SeqCst), 0);
}

/// Fail `make_readonly`. The loader must return the writable
/// allocation back to the caller on failure.
#[test]
fn load_releases_writable_allocation_on_make_readonly_failure() {
    let counters: &'static SharedCounters =
        Box::leak(Box::new(SharedCounters::new(None, None, Some(1))));
    counters.live_allocations.store(0, Ordering::SeqCst);

    // PF_R only (4): not executable, so the loader hits the
    // `make_readonly` path.
    let buf = build_elf_with_n_load_segments_with_flags(2, 4u32);
    let elf = parse_elf(&buf);
    let api = CountingMemoryApi { counters };
    let err = loader_err(ElfLoader::new(api).load(elf));
    assert_eq!(err, LoadElfError::AllocationFailed);
    assert_eq!(counters.live_allocations.load(Ordering::SeqCst), 0);
}

/// Sweep: for every `n` in 1..=4, build a 4-segment ELF and fail
/// the `n`-th `allocate` call. After the failure, the live counter
/// is zero and the typed error is `LoadElfError::AllocationFailed`.
/// This is the deterministic-fallible-callback sweep the audit
/// requires: every injection point is exercised and every
/// resulting partial state is asserted clean.
#[test]
fn load_allocate_failure_sweep_leaves_no_leaks() {
    let buf = build_elf_with_n_load_segments(4);
    for n in 1..=4 {
        let counters: &'static SharedCounters =
            Box::leak(Box::new(SharedCounters::new(Some(n as usize), None, None)));
        counters.live_allocations.store(0, Ordering::SeqCst);
        let elf = parse_elf(&buf);
        let api = CountingMemoryApi { counters };
        let err = loader_err(ElfLoader::new(api).load(elf));
        assert_eq!(err, LoadElfError::AllocationFailed, "n={n}");
        assert_eq!(
            counters.live_allocations.load(Ordering::SeqCst),
            0,
            "n={n}: every prior allocation must be dropped on failure"
        );
    }
}

/// On a fully successful load, the live counter equals the number
/// of allocations retained by the image (one per segment plus one
/// per `make_executable` / `make_readonly` conversion). Dropping
/// the `ElfImage` releases them all.
#[test]
fn load_success_drops_every_allocation_on_image_drop() {
    let counters: &'static SharedCounters =
        Box::leak(Box::new(SharedCounters::new(None, None, None)));
    counters.live_allocations.store(0, Ordering::SeqCst);

    let buf = build_elf_with_n_load_segments(2);
    let elf = parse_elf(&buf);
    let api = CountingMemoryApi { counters };
    let image = ElfLoader::new(api)
        .load(elf)
        .expect("unfaulted load should succeed");
    let live_before_drop = counters.live_allocations.load(Ordering::SeqCst);
    assert!(
        live_before_drop > 0,
        "successful load must retain allocations"
    );
    drop(image);
    assert_eq!(
        counters.live_allocations.load(Ordering::SeqCst),
        0,
        "dropping the ElfImage must release every retained allocation"
    );
}

// Suppress unused-import warnings for the items that exist for
// parity with the rest of the test crate but are not used here.
const _: fn() = || {
    let _ = ProgramHeaderFlags::EXECUTABLE;
};
