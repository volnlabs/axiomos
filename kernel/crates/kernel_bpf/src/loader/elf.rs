//! Minimal ELF64 Parser for BPF
//!
//! This module provides a minimal ELF parser specifically designed for
//! BPF object files. It extracts only the information needed for loading
//! BPF programs and maps.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use super::error::{LoadError, LoadResult};

// ELF constants
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1; // Little endian
const ELFDATA2MSB: u8 = 2; // Big endian
const EM_BPF: u16 = 247;

// Section types
const SHT_NULL: u32 = 0;
const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_RELA: u32 = 4;
const SHT_REL: u32 = 9;
const SHT_NOBITS: u32 = 8;

// Section flags
const SHF_EXECINSTR: u64 = 0x4;

/// Type of ELF section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionType {
    /// Null/unused section
    Null,
    /// BPF program section (executable code)
    Program,
    /// Data section (maps, rodata, etc.)
    Data,
    /// Symbol table
    SymTab,
    /// String table
    StrTab,
    /// Relocation section
    Rel,
    /// BSS (uninitialized data)
    Bss,
    /// License section
    License,
    /// Maps section
    Maps,
    /// BTF section
    Btf,
    /// BTF.ext section
    BtfExt,
    /// Unknown section type
    Unknown,
}

/// ELF section header information.
#[derive(Debug, Clone)]
pub struct SectionHeader {
    /// Section name offset in string table
    pub name_offset: u32,
    /// Section type
    pub section_type: SectionType,
    /// Section flags
    pub flags: u64,
    /// Virtual address
    pub addr: u64,
    /// Offset in file
    pub offset: u64,
    /// Section size
    pub size: u64,
    /// Link to another section
    pub link: u32,
    /// Additional info
    pub info: u32,
    /// Address alignment
    pub addralign: u64,
    /// Entry size for fixed-size entries
    pub entsize: u64,
    /// Section index
    pub index: usize,
}

/// ELF symbol entry.
#[derive(Debug, Clone)]
pub struct Symbol {
    /// Symbol name offset
    pub name_offset: u32,
    /// Symbol info (type and binding)
    pub info: u8,
    /// Symbol visibility
    pub other: u8,
    /// Section index
    pub shndx: u16,
    /// Symbol value
    pub value: u64,
    /// Symbol size
    pub size: u64,
}

impl Symbol {
    /// Get symbol type.
    pub fn sym_type(&self) -> u8 {
        self.info & 0xf
    }

    /// Get symbol binding.
    pub fn binding(&self) -> u8 {
        self.info >> 4
    }
}

/// Relocation entry.
#[derive(Debug, Clone)]
pub struct Relocation {
    /// Offset to apply relocation
    pub offset: u64,
    /// Symbol index
    pub sym_idx: u32,
    /// Relocation type
    pub rel_type: u32,
}

/// Minimal ELF parser.
pub struct ElfParser<'a> {
    /// Raw ELF data
    data: &'a [u8],
    /// Whether the ELF is little-endian
    little_endian: bool,
    /// Section header table offset
    shoff: u64,
    /// Number of section headers
    shnum: u16,
    /// Section header string table index
    shstrndx: u16,
    /// Cached section headers
    sections: Vec<SectionHeader>,
    /// String table data
    strtab: Option<&'a [u8]>,
    /// Section string table data
    shstrtab: Option<&'a [u8]>,
    /// Symbol table section index
    symtab_idx: Option<usize>,
}

impl<'a> ElfParser<'a> {
    /// Create a new ELF parser.
    pub fn new(data: &'a [u8]) -> LoadResult<Self> {
        // Minimum ELF header size
        if data.len() < 64 {
            return Err(LoadError::ElfTooSmall);
        }

        // Check magic
        if data[0..4] != ELF_MAGIC {
            return Err(LoadError::InvalidMagic);
        }

        // Check class (64-bit)
        if data[4] != ELFCLASS64 {
            return Err(LoadError::UnsupportedClass);
        }

        // Check endianness
        let little_endian = match data[5] {
            ELFDATA2LSB => true,
            ELFDATA2MSB => false,
            _ => return Err(LoadError::UnsupportedEndian),
        };

        // Parse header fields
        let e_machine = Self::read_u16(data, 18, little_endian);
        if e_machine != EM_BPF {
            return Err(LoadError::UnsupportedMachine);
        }

        let shoff = Self::read_u64(data, 40, little_endian);
        let shnum = Self::read_u16(data, 60, little_endian);
        let shstrndx = Self::read_u16(data, 62, little_endian);

        let mut parser = Self {
            data,
            little_endian,
            shoff,
            shnum,
            shstrndx,
            sections: Vec::new(),
            strtab: None,
            shstrtab: None,
            symtab_idx: None,
        };

        // Parse section headers
        parser.parse_sections()?;

        // Find string tables
        parser.find_string_tables()?;

        Ok(parser)
    }

    /// Read a u16 from data.
    fn read_u16(data: &[u8], offset: usize, little_endian: bool) -> u16 {
        let bytes = [data[offset], data[offset + 1]];
        if little_endian {
            u16::from_le_bytes(bytes)
        } else {
            u16::from_be_bytes(bytes)
        }
    }

    /// Read a u32 from data.
    fn read_u32(data: &[u8], offset: usize, little_endian: bool) -> u32 {
        let bytes = [
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ];
        if little_endian {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        }
    }

    /// Read a u64 from data.
    fn read_u64(data: &[u8], offset: usize, little_endian: bool) -> u64 {
        let bytes = [
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ];
        if little_endian {
            u64::from_le_bytes(bytes)
        } else {
            u64::from_be_bytes(bytes)
        }
    }

    /// Parse all section headers.
    fn parse_sections(&mut self) -> LoadResult<()> {
        const SH_SIZE: usize = 64; // Size of Elf64_Shdr

        for i in 0..self.shnum as usize {
            let offset = self.shoff as usize + i * SH_SIZE;
            if offset + SH_SIZE > self.data.len() {
                return Err(LoadError::SectionOutOfBounds);
            }

            let sh_name = Self::read_u32(self.data, offset, self.little_endian);
            let sh_type = Self::read_u32(self.data, offset + 4, self.little_endian);
            let sh_flags = Self::read_u64(self.data, offset + 8, self.little_endian);
            let sh_addr = Self::read_u64(self.data, offset + 16, self.little_endian);
            let sh_offset = Self::read_u64(self.data, offset + 24, self.little_endian);
            let sh_size = Self::read_u64(self.data, offset + 32, self.little_endian);
            let sh_link = Self::read_u32(self.data, offset + 40, self.little_endian);
            let sh_info = Self::read_u32(self.data, offset + 44, self.little_endian);
            let sh_addralign = Self::read_u64(self.data, offset + 48, self.little_endian);
            let sh_entsize = Self::read_u64(self.data, offset + 56, self.little_endian);

            // Determine section type
            let section_type = match sh_type {
                SHT_NULL => SectionType::Null,
                SHT_PROGBITS => {
                    if sh_flags & SHF_EXECINSTR != 0 {
                        SectionType::Program
                    } else {
                        SectionType::Data
                    }
                }
                SHT_SYMTAB => {
                    if self.symtab_idx.is_some() {
                        return Err(LoadError::InvalidRelocation);
                    }
                    self.symtab_idx = Some(i);
                    SectionType::SymTab
                }
                SHT_STRTAB => SectionType::StrTab,
                SHT_REL => SectionType::Rel,
                SHT_RELA => return Err(LoadError::InvalidRelocation),
                SHT_NOBITS => SectionType::Bss,
                _ => SectionType::Unknown,
            };

            self.sections.push(SectionHeader {
                name_offset: sh_name,
                section_type,
                flags: sh_flags,
                addr: sh_addr,
                offset: sh_offset,
                size: sh_size,
                link: sh_link,
                info: sh_info,
                addralign: sh_addralign,
                entsize: sh_entsize,
                index: i,
            });
        }

        Ok(())
    }

    /// Find string tables.
    fn find_string_tables(&mut self) -> LoadResult<()> {
        // Section header string table
        if self.shstrndx != 0 {
            let shstrtab_section = self
                .sections
                .get(self.shstrndx as usize)
                .filter(|section| section.section_type == SectionType::StrTab)
                .ok_or(LoadError::InvalidStringTable)?;
            let start = shstrtab_section.offset as usize;
            let end = start
                .checked_add(shstrtab_section.size as usize)
                .ok_or(LoadError::InvalidStringTable)?;
            if end > self.data.len() {
                return Err(LoadError::InvalidStringTable);
            }
            self.shstrtab = Some(&self.data[start..end]);
        }

        // Find regular string table (usually .strtab)
        if let Some(symtab_idx) = self.symtab_idx {
            let link = self.sections[symtab_idx].link as usize;
            let strtab_section = self
                .sections
                .get(link)
                .filter(|section| section.section_type == SectionType::StrTab)
                .ok_or(LoadError::InvalidStringTable)?;
            let start = strtab_section.offset as usize;
            let end = start
                .checked_add(strtab_section.size as usize)
                .ok_or(LoadError::InvalidStringTable)?;
            if end > self.data.len() {
                return Err(LoadError::InvalidStringTable);
            }
            self.strtab = Some(&self.data[start..end]);
        }

        Ok(())
    }

    /// Get section name.
    pub fn section_name(&self, section: &SectionHeader) -> LoadResult<String> {
        self.section_name_at(section.name_offset)
    }

    /// Get name from section string table at offset.
    pub fn section_name_at(&self, offset: u32) -> LoadResult<String> {
        let strtab = self.shstrtab.ok_or(LoadError::InvalidStringTable)?;
        let start = offset as usize;
        if start >= strtab.len() {
            return Err(LoadError::InvalidStringTable);
        }

        // Find null terminator
        let end = strtab[start..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| start + p)
            .unwrap_or(strtab.len());

        String::from_utf8(strtab[start..end].to_vec()).map_err(|_| LoadError::InvalidStringTable)
    }

    /// Get symbol name.
    pub fn symbol_name(&self, sym: &Symbol) -> LoadResult<String> {
        let strtab = self.strtab.ok_or(LoadError::InvalidStringTable)?;
        let start = sym.name_offset as usize;
        if start >= strtab.len() {
            return Err(LoadError::InvalidStringTable);
        }

        let end = strtab[start..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| start + p)
            .unwrap_or(strtab.len());

        String::from_utf8(strtab[start..end].to_vec()).map_err(|_| LoadError::InvalidStringTable)
    }

    /// Get section data.
    pub fn section_data(&self, section: &SectionHeader) -> LoadResult<&'a [u8]> {
        let start = section.offset as usize;
        let end = start + section.size as usize;

        if end > self.data.len() {
            return Err(LoadError::SectionDataOutOfBounds);
        }

        Ok(&self.data[start..end])
    }

    /// Get all section headers.
    pub fn sections(&self) -> LoadResult<&[SectionHeader]> {
        Ok(&self.sections)
    }

    /// Find a section by name.
    pub fn find_section(&self, name: &str) -> LoadResult<Option<SectionHeader>> {
        for section in &self.sections {
            if let Ok(section_name) = self.section_name(section)
                && section_name == name
            {
                return Ok(Some(section.clone()));
            }
        }
        Ok(None)
    }

    /// Find license string.
    pub fn find_license(&self) -> LoadResult<Option<String>> {
        if let Some(section) = self.find_section("license")? {
            let data = self.section_data(&section)?;
            let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
            return String::from_utf8(data[..end].to_vec())
                .map(Some)
                .map_err(|_| LoadError::InvalidLicense);
        }
        Ok(None)
    }

    /// Get relocations for a section.
    pub fn relocations(&self, section_idx: usize) -> LoadResult<Vec<Relocation>> {
        let mut relocs = Vec::new();

        for section in &self.sections {
            if section.section_type == SectionType::Rel && section.info as usize == section_idx {
                relocs.extend(self.parse_relocation_section(section)?);
            }
        }

        Ok(relocs)
    }

    /// Get every relocation, rejecting malformed or orphan relocation sections.
    pub fn all_relocations(&self) -> LoadResult<Vec<Relocation>> {
        let mut relocs = Vec::new();
        let symtab_idx = self.symtab_idx;
        for section in &self.sections {
            if section.section_type != SectionType::Rel {
                continue;
            }
            if section.info == 0
                || section.info as usize >= self.sections.len()
                || self.sections[section.info as usize].section_type != SectionType::Program
                || Some(section.link as usize) != symtab_idx
            {
                return Err(LoadError::InvalidRelocation);
            }
            let symbols = self.symbols_in_section(section.link as usize)?;
            let section_relocs = self.parse_relocation_section(section)?;
            if section_relocs
                .iter()
                .any(|relocation| relocation.sym_idx as usize >= symbols.len())
            {
                return Err(LoadError::UndefinedSymbol);
            }
            relocs.extend(section_relocs);
        }
        Ok(relocs)
    }

    fn parse_relocation_section(&self, section: &SectionHeader) -> LoadResult<Vec<Relocation>> {
        const REL_SIZE: usize = 16;
        let data = self.section_data(section)?;
        if !data.len().is_multiple_of(REL_SIZE) {
            return Err(LoadError::InvalidRelocation);
        }
        let mut relocs = Vec::new();
        for i in (0..data.len()).step_by(REL_SIZE) {
            let r_offset = Self::read_u64(data, i, self.little_endian);
            let r_info = Self::read_u64(data, i + 8, self.little_endian);
            relocs.push(Relocation {
                offset: r_offset,
                sym_idx: (r_info >> 32) as u32,
                rel_type: (r_info & 0xffff_ffff) as u32,
            });
        }
        Ok(relocs)
    }

    /// Get symbols from symbol table.
    pub fn symbols(&self) -> LoadResult<Vec<Symbol>> {
        let symtab_idx = self.symtab_idx.ok_or(LoadError::NoSymbolTable)?;
        self.symbols_in_section(symtab_idx)
    }

    fn symbols_in_section(&self, symtab_idx: usize) -> LoadResult<Vec<Symbol>> {
        let section = self
            .sections
            .get(symtab_idx)
            .filter(|section| section.section_type == SectionType::SymTab)
            .ok_or(LoadError::NoSymbolTable)?;
        let data = self.section_data(section)?;

        const SYM_SIZE: usize = 24; // Elf64_Sym size
        if !data.len().is_multiple_of(SYM_SIZE) {
            return Err(LoadError::InvalidRelocation);
        }
        let mut symbols = Vec::new();

        for i in (0..data.len()).step_by(SYM_SIZE) {
            symbols.push(Symbol {
                name_offset: Self::read_u32(data, i, self.little_endian),
                info: data[i + 4],
                other: data[i + 5],
                shndx: Self::read_u16(data, i + 6, self.little_endian),
                value: Self::read_u64(data, i + 8, self.little_endian),
                size: Self::read_u64(data, i + 16, self.little_endian),
            });
        }

        Ok(symbols)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    // Minimal valid BPF ELF header for testing
    fn minimal_bpf_elf() -> Vec<u8> {
        let mut data = vec![0u8; 128];

        // ELF magic
        data[0..4].copy_from_slice(&ELF_MAGIC);
        // Class: 64-bit
        data[4] = ELFCLASS64;
        // Endian: little
        data[5] = ELFDATA2LSB;
        // Version
        data[6] = 1;
        // Machine: BPF
        data[18..20].copy_from_slice(&EM_BPF.to_le_bytes());
        // Section header offset (64)
        data[40..48].copy_from_slice(&64u64.to_le_bytes());
        // Section header count (1)
        data[60..62].copy_from_slice(&1u16.to_le_bytes());
        // Section string table index (0)
        data[62..64].copy_from_slice(&0u16.to_le_bytes());

        data
    }

    #[test]
    fn parse_minimal_elf() {
        let data = minimal_bpf_elf();
        let parser = ElfParser::new(&data);
        assert!(parser.is_ok());
    }

    #[test]
    fn reject_invalid_magic() {
        let mut data = minimal_bpf_elf();
        data[0] = 0x00;
        let result = ElfParser::new(&data);
        assert!(matches!(result, Err(LoadError::InvalidMagic)));
    }

    #[test]
    fn reject_32bit_elf() {
        let mut data = minimal_bpf_elf();
        data[4] = 1; // ELFCLASS32
        let result = ElfParser::new(&data);
        assert!(matches!(result, Err(LoadError::UnsupportedClass)));
    }

    #[test]
    fn reject_non_bpf_machine() {
        let mut data = minimal_bpf_elf();
        data[18..20].copy_from_slice(&62u16.to_le_bytes()); // x86_64
        let result = ElfParser::new(&data);
        assert!(matches!(result, Err(LoadError::UnsupportedMachine)));
    }
}
