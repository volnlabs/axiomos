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

use kernel_elfloader::{ElfFile, ElfParseError};

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
