//! Fault-safe user memory access contract (audit finding C-01).
//!
//! The previous boundary (`kernel_syscall::UserspacePtr` + raw deref in
//! `kernel/src/syscall/validation.rs`) only validated the numeric address
//! class. Any unmapped canonical userspace address would panic the kernel via
//! a ring-0 page fault.
//!
//! This crate defines the contract that every syscall-level user-memory
//! accessor must honor:
//!
//! 1. Walk the calling task's page tables for the **whole** range.
//! 2. Check direction-specific permissions (`copy_from_user` requires Read,
//!    `copy_to_user` requires Write).
//! 3. Copy in bounded chunks (never unbounded), into a kernel-side buffer
//!    the caller pre-allocates.
//! 4. Convert any recoverable fault into [`UserMemError`]. Never deref a raw
//!    pointer that hasn't been proven mapped and permissioned.
//!
//! The live kernel adapter implements this contract over the current process's
//! page tables. [`MockUserMemory`] keeps the same semantics host-testable.
//!
//! The crate is intentionally `#![no_std]` and dependency-light so the same
//! contract can be hosted inside `kernel_bpf`'s helper layer and the syscall
//! ABI crate.

#![no_std]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use kernel_abi::Errno;
use kernel_virtual_memory::VirtAddr;
use thiserror::Error;

/// Direction-specific permission requested by a user-memory operation.
///
/// `Read` is required for `copy_from_user` (kernel reading userspace).
/// `Write` is required for `copy_to_user` (kernel writing userspace).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum UserMemPerm {
    Read,
    Write,
}

/// Recoverable failure modes for user-memory access.
///
/// Every variant must map cleanly to `EFAULT` at the syscall boundary, with
/// the underlying cause preserved for diagnostics (audit Q-02: error policy
/// alternates between Result/panic/halt, callers cannot respond correctly).
#[derive(Debug, Error, Eq, PartialEq)]
pub enum UserMemError {
    /// Address is canonical lower-half but no page table entry exists for it.
    /// Most common cause: caller passed a stack/heap pointer past its mapped
    /// region. Pre-fix this used to be a kernel panic.
    #[error("user memory at {0:#x} is not mapped")]
    Unmapped(VirtAddr),

    /// Address is mapped but lacks the requested permission.
    #[error("user memory at {0:#x} lacks permission for {1:?}")]
    PermissionDenied(VirtAddr, UserMemPerm),

    /// `addr + len` overflowed, the range crossed into kernel space, or the
    /// address was non-canonical. This is the "address class" check that the
    /// old `UserspacePtr::validate_range` did (correctly) — kept here so the
    /// single API surface covers both shape and access validation.
    #[error("user memory range [{0:#x}, {0:#x}+{1:#x}) is not a valid userspace range")]
    BadRange(VirtAddr, usize),

    /// Null pointer (0x0) passed by userspace. Pre-fix code only checked this
    /// in `validation.rs::copy_from_userspace`; the trait checks it uniformly
    /// to keep callers from forgetting.
    #[error("null user memory address")]
    Null,

    /// Destination buffer was too small for a C string — caller must retry
    /// with a larger buffer. Distinct from `Unmapped` so the syscall can
    /// return `ENAMETOOLONG` instead of `EFAULT` if it wants to.
    #[error("user C string at {0:#x} longer than {1} bytes")]
    Truncated(VirtAddr, usize),

    /// A requested length exceeded a defensive cap (e.g. argv array > 65 536).
    /// Returning this instead of allocating unbounded buffers is part of the
    /// DoS hardening (audit C-07 spirit).
    #[error("user memory length {0} exceeds limit {1}")]
    TooLong(usize, usize),
}

impl From<UserMemError> for Errno {
    fn from(_: UserMemError) -> Self {
        // Audit: keep one errno at the boundary, preserve cause in logs.
        // Every variant maps to EFAULT today; future callers can pattern-match
        // on `UserMemError` before converting if they need finer granularity
        // (e.g. `Truncated` → `ENAMETOOLONG`).
        kernel_abi::EFAULT
    }
}

/// Result alias for user-memory operations.
pub type UserMemResult<T> = Result<T, UserMemError>;

/// Defensive upper bound on a single user-memory copy. Anything bigger than
/// this must be issued as multiple chunked calls (or rejected outright).
///
/// 64 KiB matches the largest typical syscall argument (`iov_len` style
/// reads in Linux). Audit C-07 spirit: callers cannot ask for `usize::MAX`
/// bytes and exhaust kernel memory.
pub const MAX_USER_COPY: usize = 64 * 1024;

/// Page-table view that the live kernel adapter will eventually provide.
///
/// For PR #2.1 we only model the contract; [`MockUserMemory`] exercises the
/// trait against a synthetic `BTreeMap<VirtAddr, PageTableEntry>`. The real
/// kernel adapter (PR #2.2) implements this trait over the x86_64 and
/// AArch64 page walkers, and adds recoverable-fault handling per PR #3.
pub trait UserMemory {
    /// Copy `src_addr..src_addr+src.len()` from userspace into `dst`.
    ///
    /// `src_addr` must point to mapped, Read-permitted userspace memory for
    /// the entire range. On any fault returns [`UserMemError::Unmapped`] or
    /// [`UserMemError::PermissionDenied`].
    ///
    /// Implementation must copy in chunks small enough to never trip the
    /// page-fault-recovery path on a single chunk crossing an unmapped page.
    /// Callers supply `src.len()` up to [`MAX_USER_COPY`].
    fn copy_from_user(&mut self, dst: &mut [u8], src_addr: VirtAddr) -> UserMemResult<()>;

    /// Copy `src` into userspace at `dst_addr`.
    ///
    /// `dst_addr..dst_addr+src.len()` must point to mapped, Write-permitted
    /// userspace memory.
    fn copy_to_user(&mut self, dst_addr: VirtAddr, src: &[u8]) -> UserMemResult<()>;

    /// Copy a NUL-terminated C string from userspace into `dst`.
    ///
    /// `src_addr` must be mapped and Read-permitted at least through the
    /// terminating NUL. If the string (excluding NUL) does not fit in
    /// `dst.len() - 1` bytes, returns [`UserMemError::Truncated`]; the
    /// caller is responsible for sizing `dst` from `PATH_MAX`/`MAX_STRING`
    /// before calling.
    ///
    /// Returns the number of bytes written (excluding NUL terminator).
    fn copy_cstr_from_user(&mut self, dst: &mut [u8], src_addr: VirtAddr) -> UserMemResult<usize>;
}

// ─── MockUserMemory: host-testable backend ──────────────────────────────────

/// Synthetic page-table entry for [`MockUserMemory`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MockPageEntry {
    pub readable: bool,
    pub writable: bool,
}

/// A purely-host-testable [`UserMemory`] backed by an explicit
/// `BTreeMap<VirtAddr, MockPageEntry>` indexed by **page-aligned** virtual
/// address. Lets every error path be exercised without a real page walker.
///
/// Pages are 4 KiB. Address arithmetic uses `kernel_virtual_memory::VirtAddr`
/// so the test backend matches what the live adapter will see.
#[derive(Default, Debug)]
pub struct MockUserMemory {
    /// page-aligned VirtAddr -> perms. Absence = unmapped.
    pages: BTreeMap<u64, MockPageEntry>,
    /// Optional synthetic backing storage keyed by page-aligned address.
    /// Lets tests seed user-visible content.
    backing: BTreeMap<u64, Vec<u8>>,
}

impl MockUserMemory {
    pub fn new() -> Self {
        Self::default()
    }

    /// Map one 4 KiB page with the given permissions. `vaddr` is truncated
    /// to the page boundary; the caller is expected to pass page-aligned
    /// addresses.
    pub fn map_page(&mut self, vaddr: VirtAddr, perms: MockPageEntry) {
        let page_addr = vaddr.as_u64() & !0xFFF;
        self.pages.insert(page_addr, perms);
        // Pre-fill backing so reads see zeroes; resize preserves content.
        self.backing
            .entry(page_addr)
            .or_insert_with(|| alloc::vec![0u8; 4096]);
    }

    /// Write content into a mapped page. Useful for seeding argv/envp tests.
    /// Panics in tests if the page is not mapped (caught by a test).
    pub fn seed_page(&mut self, vaddr: VirtAddr, offset: usize, bytes: &[u8]) {
        let page_addr = vaddr.as_u64() & !0xFFF;
        let backing = self
            .backing
            .get_mut(&page_addr)
            .expect("seed_page: page not mapped");
        let end = offset
            .checked_add(bytes.len())
            .expect("seed_page: offset overflow");
        assert!(end <= backing.len(), "seed_page: write past page end");
        backing[offset..end].copy_from_slice(bytes);
    }

    fn page_of(vaddr: VirtAddr) -> u64 {
        vaddr.as_u64() & !0xFFF
    }

    fn offset_within_page(vaddr: VirtAddr) -> usize {
        (vaddr.as_u64() & 0xFFF) as usize
    }

    fn validate_range(
        &self,
        addr: VirtAddr,
        len: usize,
        permission: UserMemPerm,
    ) -> UserMemResult<()> {
        if addr.as_u64() == 0 {
            return Err(UserMemError::Null);
        }
        if len > MAX_USER_COPY {
            return Err(UserMemError::TooLong(len, MAX_USER_COPY));
        }
        if len == 0 {
            return Ok(());
        }

        let end = addr
            .as_u64()
            .checked_add(len as u64)
            .ok_or(UserMemError::BadRange(addr, len))?;
        #[cfg(target_arch = "x86_64")]
        const USER_END_EXCLUSIVE: u64 = 0x0000_8000_0000_0000;
        #[cfg(target_arch = "aarch64")]
        const USER_END_EXCLUSIVE: u64 = 0x0001_0000_0000_0000;
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        const USER_END_EXCLUSIVE: u64 = u64::MAX;
        if addr.as_u64() >= USER_END_EXCLUSIVE || end > USER_END_EXCLUSIVE {
            return Err(UserMemError::BadRange(addr, len));
        }

        let mut current = addr.as_u64();
        while current < end {
            let current_addr = VirtAddr::new(current);
            let perms = self
                .pages
                .get(&Self::page_of(current_addr))
                .copied()
                .ok_or(UserMemError::Unmapped(current_addr))?;
            let allowed = match permission {
                UserMemPerm::Read => perms.readable,
                UserMemPerm::Write => perms.writable,
            };
            if !allowed {
                return Err(UserMemError::PermissionDenied(current_addr, permission));
            }
            current = (current | 0xFFF).saturating_add(1).min(end);
        }

        Ok(())
    }
}

impl UserMemory for MockUserMemory {
    fn copy_from_user(&mut self, dst: &mut [u8], src_addr: VirtAddr) -> UserMemResult<()> {
        self.validate_range(src_addr, dst.len(), UserMemPerm::Read)?;

        let mut copied = 0usize;
        while copied < dst.len() {
            let cur = VirtAddr::new(src_addr.as_u64() + copied as u64);
            let page = Self::page_of(cur);
            let off = Self::offset_within_page(cur);

            let backing = self.backing.get(&page).expect("mapped page has no backing");
            let remaining_in_page = 4096 - off;
            let remaining_in_dst = dst.len() - copied;
            let chunk = remaining_in_page.min(remaining_in_dst);

            dst[copied..copied + chunk].copy_from_slice(&backing[off..off + chunk]);
            copied += chunk;
        }

        Ok(())
    }

    fn copy_to_user(&mut self, dst_addr: VirtAddr, src: &[u8]) -> UserMemResult<()> {
        self.validate_range(dst_addr, src.len(), UserMemPerm::Write)?;

        let mut copied = 0usize;
        while copied < src.len() {
            let cur = VirtAddr::new(dst_addr.as_u64() + copied as u64);
            let page = Self::page_of(cur);
            let off = Self::offset_within_page(cur);

            let remaining_in_page = 4096 - off;
            let remaining_in_src = src.len() - copied;
            let chunk = remaining_in_page.min(remaining_in_src);

            let page_key = page;
            let backing_len = self.backing[&page_key].len();
            assert!(off + chunk <= backing_len, "chunk exceeds page");
            let src_chunk = &src[copied..copied + chunk];
            let backing_mut = self
                .backing
                .get_mut(&page_key)
                .expect("backing present for mapped page");
            backing_mut[off..off + chunk].copy_from_slice(src_chunk);

            copied += chunk;
        }

        Ok(())
    }

    fn copy_cstr_from_user(&mut self, dst: &mut [u8], src_addr: VirtAddr) -> UserMemResult<usize> {
        if src_addr.as_u64() == 0 {
            return Err(UserMemError::Null);
        }
        if dst.is_empty() {
            return Err(UserMemError::Truncated(src_addr, 0));
        }

        // Read one byte at a time so we never copy past the terminating NUL
        // into the kernel buffer. A future PR can optimize this to page-bounded
        // memchr when the implementation has a real backing store.
        let mut written = 0usize;
        let mut cur = src_addr;
        loop {
            // Reserve one slot for the NUL terminator.
            if written + 1 > dst.len() {
                return Err(UserMemError::Truncated(src_addr, dst.len()));
            }
            let page = Self::page_of(cur);
            let off = Self::offset_within_page(cur);

            let perms = self
                .pages
                .get(&page)
                .copied()
                .ok_or(UserMemError::Unmapped(cur))?;
            if !perms.readable {
                return Err(UserMemError::PermissionDenied(cur, UserMemPerm::Read));
            }

            let backing = self.backing.get(&page).expect("mapped page has backing");
            let byte = backing[off];
            if byte == 0 {
                dst[written] = 0;
                return Ok(written);
            }
            dst[written] = byte;
            written += 1;
            cur = VirtAddr::new(cur.as_u64() + 1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rwx_page(p: MockUserMemory, vaddr: u64, content: &[u8]) -> MockUserMemory {
        let mut p = p;
        p.map_page(
            VirtAddr::new(vaddr),
            MockPageEntry {
                readable: true,
                writable: true,
            },
        );
        if !content.is_empty() {
            p.seed_page(VirtAddr::new(vaddr), 0, content);
        }
        p
    }

    #[test]
    fn copy_from_user_round_trips_within_a_page() {
        let mut mem = MockUserMemory::new();
        mem = rwx_page(mem, 0x1000_0000, b"hello");
        let mut buf = [0u8; 5];
        mem.copy_from_user(&mut buf, VirtAddr::new(0x1000_0000))
            .unwrap();
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn copy_from_user_spans_two_pages() {
        let mut mem = MockUserMemory::new();
        // Page at 0x2000_0000: fill LAST 8 bytes with a sentinel so the
        // chunked copy reads the page-end tail here.
        mem.map_page(
            VirtAddr::new(0x2000_0000),
            MockPageEntry {
                readable: true,
                writable: true,
            },
        );
        mem.seed_page(VirtAddr::new(0x2000_0000), 4088, b"END_OF_A");
        // Page at 0x2000_1000: "BBBBBBB." at offset 0 (sentinel for page-2).
        mem = rwx_page(mem, 0x2000_1000, b"BBBBBBB.");
        // Read 16 bytes starting at offset 4088 of the first page. Expected:
        //   bytes 0..8   = first-page offset 4088..4096 ("END_OF_A")
        //   bytes 8..16  = second-page offset 0..8 ("BBBBBBB.")
        let mut buf = [0u8; 16];
        mem.copy_from_user(&mut buf, VirtAddr::new(0x2000_0FF8))
            .unwrap();
        assert_eq!(&buf[..8], b"END_OF_A");
        assert_eq!(&buf[8..], b"BBBBBBB.");
    }

    #[test]
    fn copy_from_user_unmapped_returns_error() {
        let mut mem = MockUserMemory::new();
        let mut buf = [0u8; 4];
        let err = mem
            .copy_from_user(&mut buf, VirtAddr::new(0x1000_0000))
            .unwrap_err();
        assert!(matches!(err, UserMemError::Unmapped(_)));
        // And the kernel buffer was not partially scribbled.
        assert_eq!(buf, [0u8; 4]);
    }

    #[test]
    fn copy_from_user_permission_denied_returns_error() {
        let mut mem = MockUserMemory::new();
        mem.map_page(
            VirtAddr::new(0x1000_0000),
            MockPageEntry {
                readable: false,
                writable: false,
            },
        );
        let mut buf = [0u8; 4];
        let err = mem
            .copy_from_user(&mut buf, VirtAddr::new(0x1000_0000))
            .unwrap_err();
        assert!(matches!(
            err,
            UserMemError::PermissionDenied(_, UserMemPerm::Read)
        ));
    }

    #[test]
    fn copy_to_user_writes_through_to_backing() {
        let mut mem = MockUserMemory::new();
        mem = rwx_page(mem, 0x1000_0000, &[0u8; 16]);
        mem.copy_to_user(VirtAddr::new(0x1000_0000), b"abcdef")
            .unwrap();
        let mut read_back = [0u8; 6];
        mem.copy_from_user(&mut read_back, VirtAddr::new(0x1000_0000))
            .unwrap();
        assert_eq!(&read_back, b"abcdef");
    }

    #[test]
    fn copy_to_user_readonly_page_rejected() {
        let mut mem = MockUserMemory::new();
        mem.map_page(
            VirtAddr::new(0x1000_0000),
            MockPageEntry {
                readable: true,
                writable: false,
            },
        );
        let err = mem
            .copy_to_user(VirtAddr::new(0x1000_0000), b"abc")
            .unwrap_err();
        assert!(matches!(
            err,
            UserMemError::PermissionDenied(_, UserMemPerm::Write)
        ));
    }

    #[test]
    fn copy_cstr_from_user_terminates_at_nul() {
        let mut mem = MockUserMemory::new();
        mem = rwx_page(mem, 0x1000_0000, b"hello\0world\0");
        let mut buf = [0u8; 16];
        let n = mem
            .copy_cstr_from_user(&mut buf, VirtAddr::new(0x1000_0000))
            .unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf[..6], b"hello\0");
    }

    #[test]
    fn copy_cstr_from_user_truncated_when_buffer_too_small() {
        let mut mem = MockUserMemory::new();
        mem = rwx_page(mem, 0x1000_0000, b"hello world");
        let mut buf = [0u8; 4];
        let err = mem
            .copy_cstr_from_user(&mut buf, VirtAddr::new(0x1000_0000))
            .unwrap_err();
        assert!(matches!(err, UserMemError::Truncated(_, 4)));
    }

    #[test]
    fn copy_cstr_from_user_crosses_page_with_unmapped_second_page() {
        let mut mem = MockUserMemory::new();
        // Page 0x1000_0000: fill the LAST three bytes with non-NUL data so
        // the cstr reader will walk past the page boundary and fault on the
        // unmapped next page (0x1000_1000).
        mem.map_page(
            VirtAddr::new(0x1000_0000),
            MockPageEntry {
                readable: true,
                writable: true,
            },
        );
        mem.seed_page(VirtAddr::new(0x1000_0000), 4093, b"abc");
        // No page mapped at 0x1000_1000.
        let mut buf = [0u8; 16];
        let err = mem
            .copy_cstr_from_user(&mut buf, VirtAddr::new(0x1000_0FFD))
            .unwrap_err();
        assert!(matches!(err, UserMemError::Unmapped(_)));
    }

    #[test]
    fn null_address_is_rejected_uniformly() {
        let mut mem = MockUserMemory::new();
        let mut buf = [0u8; 4];
        assert!(matches!(
            mem.copy_from_user(&mut buf, VirtAddr::new(0)),
            Err(UserMemError::Null)
        ));
        assert!(matches!(
            mem.copy_to_user(VirtAddr::new(0), b"x"),
            Err(UserMemError::Null)
        ));
        assert!(matches!(
            mem.copy_cstr_from_user(&mut buf, VirtAddr::new(0)),
            Err(UserMemError::Null)
        ));
    }

    #[test]
    fn oversized_copy_rejected_with_too_long() {
        let mut mem = MockUserMemory::new();
        let mut buf = alloc::vec![0u8; MAX_USER_COPY + 1];
        let err = mem
            .copy_from_user(&mut buf, VirtAddr::new(0x1000_0000))
            .unwrap_err();
        assert!(matches!(err, UserMemError::TooLong(_, MAX_USER_COPY)));
    }

    #[test]
    fn empty_copy_is_noop() {
        let mut mem = MockUserMemory::new();
        let mut buf: [u8; 0] = [];
        // Empty copy does not need a mapped page; still must not panic.
        mem.copy_from_user(&mut buf, VirtAddr::new(0xDEAD_BEEF))
            .unwrap();
    }

    #[test]
    fn cross_page_read_failure_does_not_partially_modify_kernel_buffer() {
        let mut mem = rwx_page(MockUserMemory::new(), 0x3000_0000, &[0xAA; 4096]);
        let mut dst = [0x55; 16];

        let error = mem
            .copy_from_user(&mut dst, VirtAddr::new(0x3000_0FF8))
            .unwrap_err();

        assert!(matches!(error, UserMemError::Unmapped(_)));
        assert_eq!(dst, [0x55; 16]);
    }

    #[test]
    fn cross_page_write_failure_does_not_partially_modify_user_memory() {
        let mut mem = rwx_page(MockUserMemory::new(), 0x4000_0000, &[0xAA; 4096]);

        let error = mem
            .copy_to_user(VirtAddr::new(0x4000_0FF8), &[0x55; 16])
            .unwrap_err();

        assert!(matches!(error, UserMemError::Unmapped(_)));
        let mut tail = [0u8; 8];
        mem.copy_from_user(&mut tail, VirtAddr::new(0x4000_0FF8))
            .unwrap();
        assert_eq!(tail, [0xAA; 8]);
    }

    #[test]
    fn overflowing_range_is_rejected_before_page_lookup() {
        let mut mem = MockUserMemory::new();
        let mut dst = [0u8; 16];
        let address = VirtAddr::new(0x0000_7FFF_FFFF_FFF8);

        let error = mem.copy_from_user(&mut dst, address).unwrap_err();

        assert!(matches!(error, UserMemError::BadRange(_, 16)));
    }
}
