use core::ffi::CStr;
use core::fmt::{Debug, Display, Formatter};

use thiserror::Error;
use zerocopy::{Immutable, KnownLayout, TryFromBytes};

#[derive(Copy, Clone, Debug)]
pub struct ElfFile<'a> {
    pub(crate) source: &'a [u8],
    pub(crate) header: &'a ElfHeader,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Error)]
pub enum ElfParseError {
    #[error("input too small: have {have} bytes, need {need}")]
    InputTooSmall {
        /// Number of bytes actually present in the input buffer.
        have: usize,
        /// Number of bytes the parser required for this step.
        need: usize,
    },
    #[error("could not parse elf header")]
    HeaderParseError,
    #[error("invalid magic number")]
    InvalidMagic,
    #[error("invalid e_phentsize")]
    InvalidPhEntSize,
    #[error("invalid e_shentsize")]
    InvalidShEntSize,
    #[error("unsupported os abi")]
    UnsupportedOsAbi,
    #[error("unsupported elf version")]
    UnsupportedElfVersion,
    #[error("unsupported endianness")]
    UnsupportedEndian,
    #[error("header table arithmetic overflow: {detail}")]
    HeaderArithmeticOverflow {
        /// Human-readable cause, e.g. "phnum * phentsize overflows usize".
        detail: &'static str,
    },
    #[error(
        "header table out of bounds: offset {offset}, count {count}, entry size {entry_size}, source {source_len}"
    )]
    HeaderOutOfBounds {
        /// Byte offset of the first header.
        offset: usize,
        /// Number of header entries claimed by the ELF header.
        count: usize,
        /// Size of each header entry in bytes.
        entry_size: usize,
        /// Actual length of the input source buffer.
        source_len: usize,
    },
    #[error("section data out of bounds: offset {offset}, size {size}, source {source_len}")]
    SectionDataOutOfBounds {
        offset: usize,
        size: usize,
        source_len: usize,
    },
}

impl<'a> ElfFile<'a> {
    /// # Errors
    /// Returns a typed [`ElfParseError`] if the input is too small to
    /// contain an ELF64 header, or if any header field violates the
    /// parser's preconditions (magic, endian, version, OS ABI, entry
    /// size). All malformed-input paths return errors rather than
    /// panicking (audit H-05).
    pub fn try_parse(source: &'a [u8]) -> Result<Self, ElfParseError> {
        if source.len() < size_of::<ElfHeader>() {
            return Err(ElfParseError::InputTooSmall {
                have: source.len(),
                need: size_of::<ElfHeader>(),
            });
        }

        #[cfg(target_endian = "little")]
        const ENDIAN: u8 = 1;
        #[cfg(target_endian = "big")]
        const ENDIAN: u8 = 2;

        let header = ElfHeader::try_ref_from_bytes(&source[..size_of::<ElfHeader>()])
            .map_err(|_| ElfParseError::HeaderParseError)?;

        if header.ident.magic != [0x7F, 0x45, 0x4C, 0x46] {
            return Err(ElfParseError::InvalidMagic);
        }

        if header.ident.data != ENDIAN {
            return Err(ElfParseError::UnsupportedEndian);
        }

        if usize::from(header.phentsize) != size_of::<ProgramHeader>() {
            return Err(ElfParseError::InvalidPhEntSize);
        }
        if usize::from(header.shentsize) != size_of::<SectionHeader>() {
            return Err(ElfParseError::InvalidShEntSize);
        }
        if header.ident.version != 1 || header.version != 1 {
            return Err(ElfParseError::UnsupportedElfVersion);
        }
        if header.ident.os_abi != 0x00 {
            // not Sys V
            return Err(ElfParseError::UnsupportedOsAbi);
        }

        Ok(Self { source, header })
    }

    #[must_use]
    pub fn entry(&self) -> usize {
        self.header.entry
    }

    /// Iterate program headers as `Result`s so that any structural problem
    /// with the claimed table (offset out of range, count * size overflow,
    /// count * size + offset past EOF) surfaces as a single
    /// [`ElfParseError`] instead of panicking (audit H-05). On the happy
    /// path yields N references; on malformed input yields exactly one
    /// `Err` and stops.
    pub fn program_headers(&self) -> impl Iterator<Item = Result<&ProgramHeader, ElfParseError>> {
        self.headers(self.header.phoff, usize::from(self.header.phnum))
    }

    /// Iterate program headers of a given type. Malformed table errors
    /// propagate as `Err`; only matching-type entries are returned as
    /// `Ok`. Same iteration-length contract as [`Self::program_headers`]:
    /// yields at most one `Err`, then stops.
    pub fn program_headers_by_type(
        &self,
        typ: ProgramHeaderType,
    ) -> impl Iterator<Item = Result<&ProgramHeader, ElfParseError>> {
        ErrForwardingTypeFilter {
            inner: self.program_headers(),
            typ: u64::from(typ.0),
            done: false,
            _phantom: core::marker::PhantomData,
        }
    }

    /// See [`ElfFile::program_headers`].
    pub fn section_headers(&self) -> impl Iterator<Item = Result<&SectionHeader, ElfParseError>> {
        self.headers(self.header.shoff, usize::from(self.header.shnum))
    }

    pub fn section_headers_by_type(
        &self,
        typ: SectionHeaderType,
    ) -> impl Iterator<Item = Result<&SectionHeader, ElfParseError>> {
        ErrForwardingTypeFilter {
            inner: self.section_headers(),
            typ: u64::from(typ.0),
            done: false,
            _phantom: core::marker::PhantomData,
        }
    }

    /// Internal: yields `count` `Result<&T, ElfParseError>` items. If the
    /// claimed offset/count/entry_size is malformed, the *first* item is
    /// the corresponding `Err` and the iterator then stops. Otherwise
    /// every item is `Ok(&T)` borrowed from `self.source`.
    fn headers<T: TryFromBytes + KnownLayout + Immutable + 'a>(
        &self,
        header_offset: usize,
        header_num: usize,
    ) -> impl Iterator<Item = Result<&'a T, ElfParseError>> {
        // Local Either type to keep the function signature stable.
        enum Either<A, B> {
            Ok(A),
            Err(B),
        }
        impl<'a, T: 'a, A, B> Iterator for Either<A, B>
        where
            A: Iterator<Item = Result<&'a T, ElfParseError>>,
            B: Iterator<Item = Result<&'a T, ElfParseError>>,
        {
            type Item = Result<&'a T, ElfParseError>;
            fn next(&mut self) -> Option<Self::Item> {
                match self {
                    Either::Ok(it) => it.next(),
                    Either::Err(it) => it.next(),
                }
            }
        }

        let entry_size = size_of::<T>();
        let source_len = self.source.len();

        // Reject the overflow case first so we never panic in arithmetic.
        let total_bytes = match header_num.checked_mul(entry_size) {
            Some(n) => n,
            None => {
                return Either::Err(core::iter::once(Err(
                    ElfParseError::HeaderArithmeticOverflow {
                        detail: "count * entry_size overflows usize",
                    },
                )));
            }
        };

        let end = match header_offset.checked_add(total_bytes) {
            Some(n) => n,
            None => {
                return Either::Err(core::iter::once(Err(
                    ElfParseError::HeaderArithmeticOverflow {
                        detail: "offset + (count * entry_size) overflows usize",
                    },
                )));
            }
        };

        if end > source_len {
            return Either::Err(core::iter::once(Err(ElfParseError::HeaderOutOfBounds {
                offset: header_offset,
                count: header_num,
                entry_size,
                source_len,
            })));
        }

        // Safe: we just verified the bounds above. Slice the source.
        let data = &self.source[header_offset..end];
        Either::Ok(data.chunks_exact(entry_size).map(move |chunk| {
            // SAFETY: T is a TryFromBytes + KnownLayout + Immutable; the
            // chunks come from a properly aligned, correctly-sized slice.
            // The cast to &'a T is sound because `chunk` borrows from
            // `data` which borrows from `self.source` for lifetime 'a.
            let r: Result<&'a T, ElfParseError> = unsafe {
                core::mem::transmute_copy(
                    &T::try_ref_from_bytes(chunk).map_err(|_| ElfParseError::HeaderParseError),
                )
            };
            r
        }))
    }

    /// Return the byte slice for a section's data. Returns `None` if the
    /// claimed `offset + size` runs past the end of the input source
    /// instead of panicking (audit H-05).
    #[must_use]
    pub fn section_data(&self, header: &SectionHeader) -> Option<&[u8]> {
        let end = header.offset.checked_add(header.size)?;
        if end > self.source.len() {
            return None;
        }
        Some(&self.source[header.offset..end])
    }

    /// Return the name of a section, or `None` if the section's
    /// `shstrndx` lookup or name-string extraction fails for any
    /// reason (header table out of bounds, missing NUL terminator,
    /// non-UTF-8 bytes, or a `name` offset that runs past the
    /// section's string-table data). Never panics on malformed input
    /// (audit H-05).
    #[must_use]
    pub fn section_name(&self, header: &SectionHeader) -> Option<&str> {
        let idx = usize::from(self.header.shstrndx);
        let shstrtab = self.section_headers().nth(idx)?.ok()?;
        let shstrtab_data = self.section_data(shstrtab)?;
        let name_offset = usize::try_from(header.name).ok()?;
        let tail = shstrtab_data.get(name_offset..)?;
        CStr::from_bytes_until_nul(tail).ok()?.to_str().ok()
    }

    pub fn sections_by_name(&self, name: &str) -> impl Iterator<Item = &SectionHeader> {
        self.section_headers()
            .filter_map(Result::ok)
            .filter(move |h| self.section_name(h) == Some(name))
    }

    /// Return a program's bytes. Returns `None` if `offset + filesz`
    /// runs past the input source instead of panicking (audit H-05).
    #[must_use]
    pub fn program_data(&self, header: &ProgramHeader) -> Option<&[u8]> {
        let end = header.offset.checked_add(header.filesz)?;
        if end > self.source.len() {
            return None;
        }
        Some(&self.source[header.offset..end])
    }

    #[must_use]
    pub fn symtab_data(&'a self, header: &'a SectionHeader) -> Option<SymtabSection<'a>> {
        let data = self.section_data(header)?;
        Some(SymtabSection { header, data })
    }

    /// Return the symbol name, or `None` if any lookup fails (out-of-bounds
    /// `name` offset, missing NUL terminator, non-UTF-8 bytes, or any
    /// upstream section/strtab reference error). Never panics on
    /// malformed input (audit H-05).
    #[must_use]
    pub fn symbol_name(&self, symtab: &SymtabSection<'a>, symbol: &Symbol) -> Option<&str> {
        let strtab_index = symtab.header.link as usize;
        let strtab_hdr = self.section_headers().nth(strtab_index)?.ok()?;
        let strtab_data = self.section_data(strtab_hdr)?;
        let name_offset = usize::try_from(symbol.name).ok()?;
        let tail = strtab_data.get(name_offset..)?;
        CStr::from_bytes_until_nul(tail)
            .ok()
            .and_then(|cstr| cstr.to_str().ok())
    }
}

/// Iterator adapter for `program_headers_by_type` / `section_headers_by_type`.
/// Forwards any `Err` from the inner iterator unchanged (then stops) and
/// yields only `Ok` items whose `.typ` field matches the requested type.
///
/// The `Inner` type parameter is the concrete iterator type returned by
/// `ElfFile::headers`; its `Item` borrows from `ElfFile::source` with the
/// same lifetime `'a`, so we propagate that lifetime through `next` instead
/// of erasing it to `'static`.
struct ErrForwardingTypeFilter<T, Inner> {
    inner: Inner,
    /// Cached value of `T::TYP_TAG`. We compare by the underlying numeric
    /// type because both `ProgramHeaderType` and `SectionHeaderType` carry
    /// theirs as `pub` newtype fields, but their widths differ (u16 vs
    /// u32). Using `u64` covers both without losing precision.
    typ: u64,
    done: bool,
    _phantom: core::marker::PhantomData<T>,
}

impl<'a, T, Inner> Iterator for ErrForwardingTypeFilter<T, Inner>
where
    T: 'a,
    Inner: Iterator<Item = Result<&'a T, ElfParseError>>,
    T: HasTypeTag,
    T::Tag: Into<u64>,
{
    type Item = Result<&'a T, ElfParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        for item in &mut self.inner {
            match &item {
                Ok(h) if h.typ_tag().into() == self.typ => return Some(item),
                Ok(_) => continue,
                Err(_) => {
                    self.done = true;
                    return Some(item);
                }
            }
        }
        None
    }
}

/// Internal trait used by `ErrForwardingTypeFilter` to read the
/// discriminator field of a header without baking in the concrete type.
trait HasTypeTag {
    type Tag;
    fn typ_tag(&self) -> Self::Tag;
}

impl HasTypeTag for ProgramHeader {
    type Tag = u16;
    fn typ_tag(&self) -> u16 {
        self.typ.0
    }
}

impl HasTypeTag for SectionHeader {
    type Tag = u32;
    fn typ_tag(&self) -> u32 {
        self.typ.0
    }
}

const _: () = {
    assert!(64 == size_of::<ElfHeader>());
};

#[derive(TryFromBytes, KnownLayout, Immutable, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct ElfHeader {
    pub ident: ElfIdent,
    pub typ: ElfType,
    pub machine: u16,
    pub version: u32,
    pub entry: usize,
    pub phoff: usize,
    pub shoff: usize,
    pub flags: u32,
    pub ehsize: u16,
    pub phentsize: u16,
    pub phnum: u16,
    pub shentsize: u16,
    pub shnum: u16,
    pub shstrndx: u16,
}

#[derive(TryFromBytes, KnownLayout, Immutable, Debug, Eq, PartialEq, Clone)]
#[repr(u16)]
pub enum ElfType {
    None = 0x00,
    Rel = 0x01,
    Exec = 0x02,
    Dyn = 0x03,
    Core = 0x04,
}

const _: () = {
    assert!(16 == size_of::<ElfIdent>());
};

#[derive(TryFromBytes, KnownLayout, Immutable, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct ElfIdent {
    pub magic: [u8; 4],
    pub class: u8,
    pub data: u8,
    pub version: u8,
    pub os_abi: u8,
    pub abi_version: u8,
    _padding: [u8; 7],
}

const _: () = {
    assert!(56 == size_of::<ProgramHeader>());
};

#[derive(TryFromBytes, KnownLayout, Immutable, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct ProgramHeader {
    pub typ: ProgramHeaderType,
    pub flags: ProgramHeaderFlags,
    pub offset: usize,
    pub vaddr: usize,
    pub paddr: usize,
    pub filesz: usize,
    pub memsz: usize,
    pub align: usize,
}

#[derive(TryFromBytes, KnownLayout, Immutable, Eq, PartialEq)]
#[repr(transparent)]
pub struct ProgramHeaderType(pub u16);

impl ProgramHeaderType {
    pub const NULL: Self = Self(0x00);
    pub const LOAD: Self = Self(0x01);
    pub const DYNAMIC: Self = Self(0x02);
    pub const INTERP: Self = Self(0x03);
    pub const NOTE: Self = Self(0x04);
    pub const SHLIB: Self = Self(0x05);
    pub const PHDR: Self = Self(0x06);
    pub const TLS: Self = Self(0x07);
}

impl Debug for ProgramHeaderType {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "ProgramHeaderType({self})")
    }
}

impl Display for ProgramHeaderType {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match *self {
            ProgramHeaderType::NULL => write!(f, "NULL"),
            ProgramHeaderType::LOAD => write!(f, "LOAD"),
            ProgramHeaderType::DYNAMIC => write!(f, "DYNAMIC"),
            ProgramHeaderType::INTERP => write!(f, "INTERP"),
            ProgramHeaderType::NOTE => write!(f, "NOTE"),
            ProgramHeaderType::SHLIB => write!(f, "SHLIB"),
            ProgramHeaderType::PHDR => write!(f, "PHDR"),
            ProgramHeaderType::TLS => write!(f, "TLS"),
            _ => write!(f, "UNKNOWN({})", self.0),
        }
    }
}

#[derive(TryFromBytes, KnownLayout, Immutable, Eq, PartialEq)]
#[repr(transparent)]
pub struct ProgramHeaderFlags(pub u32);

impl ProgramHeaderFlags {
    pub const EXECUTABLE: Self = Self(0x01);
    pub const WRITABLE: Self = Self(0x02);
    pub const READABLE: Self = Self(0x04);
}

impl ProgramHeaderFlags {
    #[must_use]
    pub fn contains(&self, other: &Self) -> bool {
        self.0 & other.0 > 0
    }
}

impl Debug for ProgramHeaderFlags {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "ProgramHeaderFlags({self})")
    }
}

impl Display for ProgramHeaderFlags {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        if self.0 == 0 {
            return write!(f, "NONE");
        }

        let mut first = true;

        if self.contains(&ProgramHeaderFlags::READABLE) {
            write!(f, "R")?;
            first = false;
        }
        if self.contains(&ProgramHeaderFlags::WRITABLE) {
            if !first {
                write!(f, "|")?;
            }
            write!(f, "W")?;
            first = false;
        }
        if self.contains(&ProgramHeaderFlags::EXECUTABLE) {
            if !first {
                write!(f, "|")?;
            }
            write!(f, "X")?;
        }

        Ok(())
    }
}

const _: () = {
    assert!(64 == size_of::<SectionHeader>());
};

#[derive(TryFromBytes, KnownLayout, Immutable, Debug, Eq, PartialEq, Clone)]
#[repr(C)]
pub struct SectionHeader {
    pub name: u32,
    pub typ: SectionHeaderType,
    pub flags: SectionHeaderFlags,
    pub addr: usize,
    pub offset: usize,
    pub size: usize,
    pub link: u32,
    pub info: u32,
    pub addralign: usize,
    pub entsize: usize,
}

#[derive(TryFromBytes, KnownLayout, Immutable, Debug, Eq, PartialEq, Copy, Clone)]
#[repr(transparent)]
pub struct SectionHeaderType(pub u32);

impl SectionHeaderType {
    pub const NULL: Self = Self(0x00);
    pub const PROGBITS: Self = Self(0x01);
    pub const SYMTAB: Self = Self(0x02);
    pub const STRTAB: Self = Self(0x03);
    pub const RELA: Self = Self(0x04);
    pub const HASH: Self = Self(0x05);
    pub const DYNAMIC: Self = Self(0x06);
    pub const NOTE: Self = Self(0x07);
    pub const NOBITS: Self = Self(0x08);
    pub const REL: Self = Self(0x09);
    pub const SHLIB: Self = Self(0x0A);
    pub const DYNSYM: Self = Self(0x0B);
    pub const INITARRAY: Self = Self(0x0E);
    pub const FINIARRAY: Self = Self(0x0F);
    pub const PREINITARRAY: Self = Self(0x10);
    pub const GROUP: Self = Self(0x11);
    pub const SYMTABSHNDX: Self = Self(0x12);
    pub const NUM: Self = Self(0x13);
}

#[derive(TryFromBytes, KnownLayout, Immutable, Debug, Eq, PartialEq, Clone, Copy)]
#[repr(transparent)]
pub struct SectionHeaderFlags(pub u32);

impl SectionHeaderFlags {
    pub const WRITE: Self = Self(0x0001);
    pub const ALLOC: Self = Self(0x0002);
    pub const EXECINSTR: Self = Self(0x0004);
    pub const MERGE: Self = Self(0x0010);
    pub const STRINGS: Self = Self(0x0020);
    pub const INFOLINK: Self = Self(0x0040);
    pub const LINKORDER: Self = Self(0x0080);
    pub const OSNONCONFORMING: Self = Self(0x0100);
    pub const GROUP: Self = Self(0x0200);
    pub const TLS: Self = Self(0x0400);

    #[must_use]
    pub fn contains(&self, other: &Self) -> bool {
        self.0 & other.0 > 0
    }
}

pub struct SymtabSection<'a> {
    header: &'a SectionHeader,
    data: &'a [u8],
}

impl SymtabSection<'_> {
    // `chunks_exact` kept over `as_chunks`: the byte-slice item feeds
    // `Symbol::try_ref_from_bytes` (zerocopy), which the array form would not
    // coerce to in the `.map` chain. The newer clippy lint is style-only.
    #[allow(clippy::chunks_exact_to_as_chunks)]
    pub fn symbols(&self) -> impl Iterator<Item = &Symbol> {
        self.data
            .chunks_exact(size_of::<Symbol>())
            .map(Symbol::try_ref_from_bytes)
            .map(Result::unwrap)
    }
}

#[derive(TryFromBytes, KnownLayout, Immutable, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct Symbol {
    pub name: u32,
    pub value: usize,
    pub size: u32,
    pub info: u8,
    pub other: u8,
    pub shndx: u16,
}

#[cfg(test)]
mod tests {
    #[cfg(not(miri))]
    use zerocopy::TryFromBytes;

    #[cfg(not(miri))]
    use crate::file::{ElfHeader, ElfIdent, ElfType};

    #[cfg(not(miri))]
    #[test]
    fn test_elf_header_ref_from_bytes() {
        let data: [u8; 64] = [
            0x7f, 0x45, 0x4c, 0x46, // ELF magic
            0x02, // 64-bit
            0x01, // little-endian
            0x01, // ELF version
            0x06, // OS ABI
            0x07, // ABI Version
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding
            0x02, 0x00, // ET_EXEC (little endian)
            0x00, 0x00, // no specific instruction set
            0x01, 0x00, 0x00, 0x00, // ELF version 1
            0xE8, 0xE7, 0xE6, 0xE5, 0xE4, 0xE3, 0xE2, 0xE1, // entry point
            0xB8, 0xB7, 0xB6, 0xB5, 0xB4, 0xB3, 0xB2, 0xB1, // program header table offset
            0xC8, 0xC7, 0xC6, 0xC5, 0xC4, 0xC3, 0xC2, 0xC1, // section header table offset
            0xF4, 0xF3, 0xF2, 0xF1, // flags
            0x40, 0x00, // header size
            0x40, 0x00, // program header entry size
            0x22, 0x11, // num program headers
            0x40, 0x00, // section header entry size
            0x44, 0x33, // num section headers
            0x05, 0x00, // section names section header index
        ];

        let header = ElfHeader::try_ref_from_bytes(&data).unwrap();
        assert_eq!(
            header,
            &ElfHeader {
                ident: ElfIdent {
                    magic: [0x7f, 0x45, 0x4c, 0x46],
                    class: 2,
                    data: 1,
                    version: 1,
                    os_abi: 6,
                    abi_version: 7,
                    _padding: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                },
                typ: ElfType::Exec,
                machine: 0,
                version: 1,
                entry: 0xE1E2E3E4E5E6E7E8,
                phoff: 0xB1B2B3B4B5B6B7B8,
                shoff: 0xC1C2C3C4C5C6C7C8,
                flags: 0xF1F2F3F4,
                ehsize: 64,
                phentsize: 64,
                phnum: 0x1122,
                shentsize: 64,
                shnum: 0x3344,
                shstrndx: 5,
            }
        );
    }
}
