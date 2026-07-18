//! Adversarial malformed-ELF inputs (audit H-05).
//!
//! The pre-fix `kernel_elfloader::ElfFile::try_parse` and downstream
//! `section_data` / `program_data` / `headers` would panic on truncated
//! or out-of-bounds inputs because:
//!
//!   * `try_parse` sliced `&source[..size_of::<ElfHeader>()]` without an
//!     explicit input-size check (relying on `try_ref_from_bytes`'s
//!     internal guard).
//!   * `headers` computed `header_num * size` without overflow checks and
//!     then sliced `source[header_offset..]` directly.
//!   * `section_data` / `program_data` indexed `source[offset..offset+size]`
//!     without bounds checks.
//!   * `section_name` indexed `shstrtab_data[name as usize..]` without
//!     bounds checks.
//!
//! Each test below feeds an input that exercises one of these failure
//! modes and asserts the new fallible API returns a typed
//! [`ElfParseError`] variant instead of panicking.

#![allow(clippy::unwrap_used)]

use core::alloc::Layout;
use core::mem::size_of;

use kernel_elfloader::{
    ElfFile, ElfLoader, ElfParseError, ElfType, LoadElfError, ProgramHeaderFlags, SectionHeader,
    SectionHeaderFlags, SectionHeaderType, Symbol,
};
use kernel_memapi::{Allocation, Guarded, Location, MemoryApi, UserAccessible, WritableAllocation};

fn set_elf_header_basics(buf: &mut [u8], elf_type: u16, phoff: u64, phnum: u16) {
    buf[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    buf[4] = 2; // ELFCLASS64
    buf[5] = 1; // ELFDATA2LSB
    buf[6] = 1; // EV_CURRENT
    buf[7] = 0; // ELFOSABI_NONE
    buf[16..18].copy_from_slice(&elf_type.to_le_bytes());
    buf[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    buf[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
    buf[32..40].copy_from_slice(&phoff.to_le_bytes());
    buf[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    buf[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    buf[56..58].copy_from_slice(&phnum.to_le_bytes());
    buf[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
}

fn write_program_header(
    out: &mut Vec<u8>,
    typ: u16,
    flags: u32,
    offset: u64,
    filesz: u64,
    memsz: u64,
) {
    let mut ph = [0u8; 56];
    ph[0..2].copy_from_slice(&typ.to_le_bytes());
    ph[4..8].copy_from_slice(&flags.to_le_bytes());
    ph[8..16].copy_from_slice(&offset.to_le_bytes());
    ph[16..24].copy_from_slice(&0x400000u64.to_le_bytes());
    ph[24..32].copy_from_slice(&0x400000u64.to_le_bytes());
    ph[32..40].copy_from_slice(&filesz.to_le_bytes());
    ph[40..48].copy_from_slice(&memsz.to_le_bytes());
    out.extend_from_slice(&ph);
}

#[derive(Clone, Debug)]
struct TestAllocation {
    data: Vec<u8>,
    layout: Layout,
}

impl TestAllocation {
    fn new(layout: Layout) -> Self {
        Self {
            data: vec![0; layout.size()],
            layout,
        }
    }
}

impl AsRef<[u8]> for TestAllocation {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl AsMut<[u8]> for TestAllocation {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl Allocation for TestAllocation {
    fn layout(&self) -> Layout {
        self.layout
    }
}

impl WritableAllocation for TestAllocation {}

#[derive(Clone, Debug, Default)]
struct TestMemoryApi;

impl MemoryApi for TestMemoryApi {
    type ReadonlyAllocation = TestAllocation;
    type WritableAllocation = TestAllocation;
    type ExecutableAllocation = TestAllocation;

    fn allocate(
        &mut self,
        _location: Location,
        layout: Layout,
        _user_accessible: UserAccessible,
        _guarded: Guarded,
    ) -> Option<Self::WritableAllocation> {
        Some(TestAllocation::new(layout))
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

fn loader_err<M: MemoryApi>(
    result: Result<kernel_elfloader::ElfImage<'_, M>, LoadElfError>,
) -> LoadElfError {
    match result {
        Ok(_) => panic!("expected ELF loader error"),
        Err(err) => err,
    }
}

/// 64-byte ELF64 header for x86_64 (little-endian). All-zero magic.
fn zero_header() -> [u8; 64] {
    [0u8; 64]
}

/// Truncate `src` to `len` bytes (or panic if `len > src.len()`).
fn truncated(src: &[u8], len: usize) -> Vec<u8> {
    src[..len].to_vec()
}

#[test]
fn empty_input_rejected_with_input_too_small() {
    let err = ElfFile::try_parse(&[]).unwrap_err();
    assert!(
        matches!(err, ElfParseError::InputTooSmall { have: 0, need: 64 }),
        "expected InputTooSmall, got {err:?}"
    );
}

#[test]
fn truncated_input_rejected_with_input_too_small() {
    let buf = truncated(&zero_header(), 32);
    let err = ElfFile::try_parse(&buf).unwrap_err();
    assert!(
        matches!(err, ElfParseError::InputTooSmall { have: 32, need: 64 }),
        "expected InputTooSmall, got {err:?}"
    );
}

#[test]
fn single_byte_rejected() {
    let err = ElfFile::try_parse(&[0x7F]).unwrap_err();
    assert!(matches!(err, ElfParseError::InputTooSmall { have: 1, .. }));
}

#[test]
fn full_size_zero_header_rejected_as_invalid_magic() {
    // Header is the right size but magic is zero (all-zero header).
    let buf = zero_header();
    let err = ElfFile::try_parse(&buf).unwrap_err();
    assert!(matches!(err, ElfParseError::InvalidMagic));
}

#[test]
fn bad_endian_rejected() {
    let mut buf = zero_header();
    buf[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    // ident[EI_DATA] = 2 means big-endian; we always parse as host endian
    // (little on x86_64 host). Pre-fix this would silently misparse the
    // header; post-fix it returns UnsupportedEndian.
    buf[5] = 2;
    let err = ElfFile::try_parse(&buf).unwrap_err();
    assert!(matches!(err, ElfParseError::UnsupportedEndian));
}

/// Build a syntactically valid ELF64 header (so `try_parse` accepts it)
/// but with `phoff` / `phnum` / `shoff` / `shnum` set to nonsense values
/// that would have triggered an out-of-bounds panic in the pre-fix code.
fn valid_header_with_bogus_phoff(phoff: u64, phnum: u16) -> Vec<u8> {
    let mut buf = zero_header();
    buf[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    buf[4] = 2; // ELFCLASS64
    buf[5] = 1; // ELFDATA2LSB (little-endian)
    buf[6] = 1; // EV_CURRENT
    buf[7] = 0; // ELFOSABI_NONE
    // e_type = ET_EXEC = 2 at offset 16
    buf[16..18].copy_from_slice(&2u16.to_le_bytes());
    // e_machine = EM_X86_64 = 62 at offset 18
    buf[18..20].copy_from_slice(&62u16.to_le_bytes());
    // e_version = 1 at offset 20
    buf[20..24].copy_from_slice(&1u32.to_le_bytes());
    // e_entry at offset 24 (8 bytes) — leave zero
    // e_phoff at offset 32 (8 bytes)
    buf[32..40].copy_from_slice(&phoff.to_le_bytes());
    // e_shoff at offset 40 (8 bytes) — leave zero
    // e_flags at offset 48 (4 bytes) — leave zero
    // e_ehsize = 64 at offset 52
    buf[52..54].copy_from_slice(&64u16.to_le_bytes());
    // e_phentsize = 56 (sizeof ProgramHeader) at offset 54
    buf[54..56].copy_from_slice(&56u16.to_le_bytes());
    // e_phnum at offset 56
    buf[56..58].copy_from_slice(&phnum.to_le_bytes());
    // e_shentsize = 64 at offset 58
    buf[58..60].copy_from_slice(&64u16.to_le_bytes());
    // e_shnum = 0 at offset 60
    // e_shstrndx = 0 at offset 62
    buf.to_vec()
}

#[test]
fn program_headers_iterator_returns_oob_error_not_panic() {
    // phoff points way past the end of the input.
    let buf = valid_header_with_bogus_phoff(0xFFFF_FFFF_FFFF_FFFF, 1);
    let elf = ElfFile::try_parse(&buf).expect("header should parse");
    let results: Vec<_> = elf.program_headers().collect();
    assert_eq!(results.len(), 1, "expected exactly one OOB error");
    let err = results[0].as_ref().unwrap_err();
    assert!(
        matches!(
            err,
            ElfParseError::HeaderArithmeticOverflow { .. }
                | ElfParseError::HeaderOutOfBounds { .. }
        ),
        "expected HeaderArithmeticOverflow or HeaderOutOfBounds, got {err:?}"
    );
}

#[test]
fn program_headers_iterator_returns_oob_when_offset_in_range_but_size_overflows() {
    // phoff fits in source but phnum * sizeof(ProgramHeader) overflows.
    let buf = valid_header_with_bogus_phoff(64, u16::MAX);
    let elf = ElfFile::try_parse(&buf).expect("header should parse");
    let results: Vec<_> = elf.program_headers().collect();
    assert_eq!(results.len(), 1, "expected exactly one error result");
    assert!(results[0].is_err());
}

#[test]
fn section_headers_iterator_returns_oob_when_section_table_truncated() {
    // shoff = 64 (right after the header) but shnum says there are 256
    // section headers; we only have a 64-byte input.
    let mut buf = valid_header_with_bogus_phoff(0, 0);
    // e_shoff = 64 at offset 40
    buf[40..48].copy_from_slice(&64u64.to_le_bytes());
    // e_shnum = 256 at offset 60
    buf[60..62].copy_from_slice(&256u16.to_le_bytes());
    let elf = ElfFile::try_parse(&buf).expect("header should parse");
    let results: Vec<_> = elf.section_headers().collect();
    assert_eq!(results.len(), 1, "expected exactly one error result");
    assert!(matches!(
        results[0].as_ref().unwrap_err(),
        ElfParseError::HeaderOutOfBounds { .. }
    ));
}

// ──────────────────────────────────────────────────────────────────────────────
// Round-2 (review fix R1): finish the audit H-05 surface. Every remaining
// panic surface in kernel_elfloader and the loader call sites that the
// review caught is covered here.
// ──────────────────────────────────────────────────────────────────────────────

/// Build a minimal ELF64 input that has one valid `SHT_STRTAB` section
/// plus one `SHT_PROGBITS` section whose `name` offset points past the
/// end of the string-table data. Section header table follows the
/// 64-byte ELF header; the string-table section is the second entry.
fn valid_elf_with_oversize_section_name() -> Vec<u8> {
    let mut buf = vec![0u8; 64];
    buf[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    buf[4] = 2; // ELFCLASS64
    buf[5] = 1; // ELFDATA2LSB
    buf[6] = 1; // EV_CURRENT
    buf[7] = 0; // ELFOSABI_NONE
    // e_type = ET_EXEC
    buf[16..18].copy_from_slice(&2u16.to_le_bytes());
    // e_machine = EM_X86_64
    buf[18..20].copy_from_slice(&62u16.to_le_bytes());
    // e_version
    buf[20..24].copy_from_slice(&1u32.to_le_bytes());
    // e_phoff = 0 (no phdrs)
    // e_shoff = 64 (sections start right after the ELF header)
    buf[40..48].copy_from_slice(&64u64.to_le_bytes());
    // e_ehsize
    buf[52..54].copy_from_slice(&64u16.to_le_bytes());
    // e_phentsize = sizeof(ProgramHeader) = 56
    buf[54..56].copy_from_slice(&56u16.to_le_bytes());
    // e_phnum = 0
    buf[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
    // e_shnum = 2: [0]=null, [1]=strtab
    buf[60..62].copy_from_slice(&2u16.to_le_bytes());
    // e_shstrndx = 1
    buf[62..64].copy_from_slice(&1u16.to_le_bytes());

    // Section header 0: SHT_NULL
    buf.extend_from_slice(&[0u8; 64]);

    // Section header 1: SHT_STRTAB with sh_offset and sh_size both = 0.
    // sh_name will be ignored because we'll point the second section's
    // sh_name at a u32::MAX value.
    let mut sh = [0u8; 64];
    sh[4..8].copy_from_slice(&3u32.to_le_bytes()); // sh_type = SHT_STRTAB
    sh[32..40].copy_from_slice(&0u64.to_le_bytes()); // sh_offset
    sh[40..48].copy_from_slice(&0u64.to_le_bytes()); // sh_size
    buf.extend_from_slice(&sh);

    buf
}

#[test]
fn section_name_returns_none_when_name_offset_past_end() {
    // Build a valid ELF, then locate section 1 (which is its own
    // shstrtab), and ask for the name with a deliberately out-of-bounds
    // sh_name.
    let buf = valid_elf_with_oversize_section_name();
    let elf = ElfFile::try_parse(&buf).expect("header parses");
    let sec1_owned: SectionHeader = elf
        .section_headers()
        .nth(1)
        .expect("section 1 present")
        .expect("section 1 parses")
        .clone();
    // sh_name = u32::MAX points past the end of shstrtab_data (size 0).
    // Pre-fix this sliced &shstrtab_data[u32::MAX as usize..] and
    // panicked. Post-fix it returns None.
    let sec1 = SectionHeader {
        name: u32::MAX,
        ..sec1_owned
    };
    assert!(elf.section_name(&sec1).is_none());
}

#[test]
fn symbol_name_returns_none_when_name_offset_past_end() {
    let buf = valid_elf_with_oversize_section_name();
    let elf = ElfFile::try_parse(&buf).expect("header parses");
    use kernel_elfloader::Symbol;
    let bad_sym = Symbol {
        name: 0,
        info: 0,
        other: 0,
        shndx: 0,
        value: 0,
        size: 0,
    };
    let sec1: SectionHeader = elf
        .section_headers()
        .nth(1)
        .expect("section 1 present")
        .expect("section 1 parses")
        .clone();
    let symtab = elf
        .symtab_data(&sec1)
        .expect("symtab_data succeeds for valid section");
    assert!(elf.symbol_name(&symtab, &bad_sym).is_none());
}

#[test]
fn program_data_returns_none_when_offset_plus_size_past_eof() {
    // Build a valid ELF with phoff pointing at a fake program header
    // whose offset+filesz exceeds source.len().
    let mut buf = vec![0u8; 64];
    buf[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    buf[4] = 2;
    buf[5] = 1;
    buf[6] = 1;
    buf[7] = 0;
    buf[16..18].copy_from_slice(&2u16.to_le_bytes());
    buf[18..20].copy_from_slice(&62u16.to_le_bytes());
    buf[20..24].copy_from_slice(&1u32.to_le_bytes());
    // e_phoff = 64 (one program header right after the ELF header)
    buf[32..40].copy_from_slice(&64u64.to_le_bytes());
    buf[52..54].copy_from_slice(&64u16.to_le_bytes());
    buf[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    buf[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum = 1
    buf[58..60].copy_from_slice(&64u16.to_le_bytes());
    buf[60..62].copy_from_slice(&0u16.to_le_bytes()); // e_shnum = 0
    buf.extend_from_slice(&[0u8; 56]); // one fake ProgramHeader at offset 64

    let elf = ElfFile::try_parse(&buf).expect("header parses");

    // Synthesize a ProgramHeader whose filesz spans past EOF and
    // whose offset+filesz would overflow. program_data must return
    // None instead of panicking.
    use kernel_elfloader::{ProgramHeader, ProgramHeaderFlags, ProgramHeaderType};
    let mut fake = ProgramHeader {
        typ: ProgramHeaderType::LOAD,
        flags: ProgramHeaderFlags::READABLE,
        offset: 50,
        vaddr: 0,
        paddr: 0,
        filesz: usize::MAX, // 50 + usize::MAX wraps to < 50
        memsz: 1024,
        align: 0,
    };
    assert!(elf.program_data(&fake).is_none());
    // Realistic OOB: small offset, filesz past EOF
    fake.offset = 50;
    fake.filesz = buf.len() as usize + 1024;
    assert!(elf.program_data(&fake).is_none());
}

#[test]
fn section_data_returns_none_when_offset_plus_size_past_eof() {
    let mut buf = vec![0u8; 64];
    buf[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    buf[4] = 2;
    buf[5] = 1;
    buf[6] = 1;
    buf[7] = 0;
    buf[16..18].copy_from_slice(&2u16.to_le_bytes());
    buf[18..20].copy_from_slice(&62u16.to_le_bytes());
    buf[20..24].copy_from_slice(&1u32.to_le_bytes());
    buf[40..48].copy_from_slice(&64u64.to_le_bytes()); // e_shoff
    buf[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    buf[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    buf[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
    buf[60..62].copy_from_slice(&1u16.to_le_bytes()); // e_shnum = 1
    buf.extend_from_slice(&[0u8; 64]); // one SHN_UNDEF section header

    let elf = ElfFile::try_parse(&buf).expect("header parses");
    use kernel_elfloader::SectionHeaderFlags;
    let mut fake = SectionHeader {
        name: 0,
        typ: SectionHeaderType::PROGBITS,
        flags: SectionHeaderFlags(0),
        addr: 0,
        offset: 100, // offset is valid (within 128-byte input)
        size: usize::MAX,
        link: 0,
        info: 0,
        addralign: 0,
        entsize: 0,
    };
    assert!(elf.section_data(&fake).is_none());
    fake.offset = usize::MAX;
    assert!(elf.section_data(&fake).is_none());
}

#[test]
fn loader_rejects_non_exec_elf_without_panic() {
    let mut buf = vec![0u8; 64];
    set_elf_header_basics(&mut buf, 3, 0, 0); // ET_DYN, not ET_EXEC
    let elf = ElfFile::try_parse(&buf).expect("header parses");
    let err = loader_err(ElfLoader::new(TestMemoryApi).load(elf));
    assert_eq!(err, LoadElfError::UnsupportedFileType(ElfType::Dyn));
}

#[test]
fn loader_rejects_load_segment_with_filesz_greater_than_memsz_without_panic() {
    let mut buf = vec![0u8; 64];
    set_elf_header_basics(&mut buf, 2, 64, 1);
    write_program_header(&mut buf, 1, ProgramHeaderFlags::READABLE.0, 120, 8, 4);
    buf.extend_from_slice(&[0xAA; 8]);

    let elf = ElfFile::try_parse(&buf).expect("header parses");
    let err = loader_err(ElfLoader::new(TestMemoryApi).load(elf));
    assert_eq!(err, LoadElfError::SegmentFileLargerThanMemory);
}

#[test]
fn loader_rejects_writable_executable_load_segment_without_panic() {
    let mut buf = vec![0u8; 64];
    set_elf_header_basics(&mut buf, 2, 64, 1);
    write_program_header(
        &mut buf,
        1,
        ProgramHeaderFlags::READABLE.0
            | ProgramHeaderFlags::WRITABLE.0
            | ProgramHeaderFlags::EXECUTABLE.0,
        120,
        4,
        4,
    );
    buf.extend_from_slice(&[0xAA; 4]);

    let elf = ElfFile::try_parse(&buf).expect("header parses");
    let err = loader_err(ElfLoader::new(TestMemoryApi).load(elf));
    assert_eq!(err, LoadElfError::WritableExecutableSegment);
}

#[test]
fn loader_rejects_tls_with_filesz_greater_than_memsz_without_panic() {
    let mut buf = vec![0u8; 64];
    set_elf_header_basics(&mut buf, 2, 64, 1);
    write_program_header(&mut buf, 7, ProgramHeaderFlags::READABLE.0, 120, 8, 4);
    buf.extend_from_slice(&[0xAA; 8]);

    let elf = ElfFile::try_parse(&buf).expect("header parses");
    let err = loader_err(ElfLoader::new(TestMemoryApi).load(elf));
    assert_eq!(err, LoadElfError::SegmentFileLargerThanMemory);
}

#[test]
fn symtab_symbols_skips_trailing_partial_symbol_without_panic() {
    let mut buf = valid_elf_with_oversize_section_name();
    let mut symtab_section = [0u8; 64];
    symtab_section[4..8].copy_from_slice(&2u32.to_le_bytes()); // SHT_SYMTAB
    symtab_section[24..32].copy_from_slice(&(buf.len() as u64 + 64).to_le_bytes());
    symtab_section[32..40].copy_from_slice(&(size_of::<Symbol>() as u64 + 1).to_le_bytes());
    buf.extend_from_slice(&symtab_section);
    buf.resize(buf.len() + size_of::<Symbol>() + 1, 0xAA);
    buf[60..62].copy_from_slice(&3u16.to_le_bytes()); // e_shnum

    let elf = ElfFile::try_parse(&buf).expect("header parses");
    let symtab_header: SectionHeader = elf
        .section_headers()
        .nth(2)
        .expect("symtab section present")
        .expect("symtab section parses")
        .clone();
    let symtab = elf
        .symtab_data(&symtab_header)
        .expect("symtab_data succeeds");

    assert_eq!(symtab.symbols().count(), 1);
}

#[test]
fn symbol_name_handles_bad_strtab_link_without_panic() {
    let buf = valid_elf_with_oversize_section_name();
    let elf = ElfFile::try_parse(&buf).expect("header parses");
    let bad_symtab_header = SectionHeader {
        name: 0,
        typ: SectionHeaderType::SYMTAB,
        flags: SectionHeaderFlags(0),
        addr: 0,
        offset: 0,
        size: 0,
        link: u32::MAX,
        info: 0,
        addralign: 0,
        entsize: 0,
    };
    let symtab = elf
        .symtab_data(&bad_symtab_header)
        .expect("symtab_data succeeds for zero-sized section");
    let sym = Symbol {
        name: 0,
        value: 0,
        size: 0,
        info: 0,
        other: 0,
        shndx: 0,
    };

    assert!(elf.symbol_name(&symtab, &sym).is_none());
}
