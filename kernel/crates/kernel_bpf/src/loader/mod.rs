//! libbpf-free BPF Loader
//!
//! This module provides a minimal BPF program loader that parses ELF files
//! directly without depending on libbpf. This achieves significant memory
//! savings (~1.5MB → ~50KB) for embedded deployments.
//!
//! # Memory Footprint
//!
//! ```text
//! Component                  Memory
//! ─────────────────────────────────────
//! ELF header cache           64 bytes
//! Section headers            ~2 KB (max 64 sections)
//! String table               ~4 KB
//! Program storage            variable
//! ─────────────────────────────────────
//! Total peak:                ~50 KB
//! ```
//!
//! # Supported Features
//!
//! - ELF64 parsing for BPF objects
//! - Multiple programs per object file
//! - Map definitions and relocations
//! - BTF parsing (optional, cloud profile only)
//! - License extraction
//!
//! # Usage
//!
//! ```ignore
//! use kernel_bpf::loader::{BpfLoader, LoadedProgram};
//!
//! let elf_data: &[u8] = include_bytes!("my_prog.o");
//! let mut loader = BpfLoader::new();
//! let obj = loader.load(elf_data)?;
//!
//! for prog in obj.programs() {
//!     println!("Found program: {} ({} instructions)",
//!              prog.name(), prog.insn_count());
//! }
//! ```

extern crate alloc;

mod elf;
mod error;
mod normalize;
mod object;
mod reloc;

use alloc::vec::Vec;
use core::marker::PhantomData;

pub use elf::{ElfParser, SectionType};
pub use error::{LoadError, LoadResult};
pub use normalize::{normalize, Normalized};
pub use object::{BpfObject, LoadedMap, LoadedProgram};
pub use reloc::Relocator;

use crate::bytecode::insn::BpfInsn;
use crate::bytecode::program::BpfProgType;
use crate::maps::MapDef;
use crate::profile::{ActiveProfile, PhysicalProfile};

/// BPF program loader.
///
/// Loads BPF programs from ELF object files without libbpf dependency.
pub struct BpfLoader<P: PhysicalProfile = ActiveProfile> {
    /// Maximum number of programs to load
    max_programs: usize,
    /// Maximum number of maps to load
    max_maps: usize,
    /// Profile marker
    _profile: PhantomData<P>,
}

impl<P: PhysicalProfile> BpfLoader<P> {
    /// Maximum programs for embedded profile.
    #[cfg(all(feature = "embedded-profile", not(feature = "cloud-profile")))]
    const DEFAULT_MAX_PROGRAMS: usize = 8;
    /// Maximum programs for cloud profile.
    #[cfg(feature = "cloud-profile")]
    const DEFAULT_MAX_PROGRAMS: usize = 64;

    /// Maximum maps for embedded profile.
    #[cfg(all(feature = "embedded-profile", not(feature = "cloud-profile")))]
    const DEFAULT_MAX_MAPS: usize = 16;
    /// Maximum maps for cloud profile.
    #[cfg(feature = "cloud-profile")]
    const DEFAULT_MAX_MAPS: usize = 128;

    /// Create a new loader with default settings.
    pub fn new() -> Self {
        Self {
            max_programs: Self::DEFAULT_MAX_PROGRAMS,
            max_maps: Self::DEFAULT_MAX_MAPS,
            _profile: PhantomData,
        }
    }

    /// Set maximum number of programs to load.
    pub fn max_programs(mut self, max: usize) -> Self {
        self.max_programs = max;
        self
    }

    /// Set maximum number of maps to load.
    pub fn max_maps(mut self, max: usize) -> Self {
        self.max_maps = max;
        self
    }

    /// Load a BPF object from ELF data.
    pub fn load(&mut self, elf_data: &[u8]) -> LoadResult<BpfObject<P>> {
        // Parse ELF header and sections
        let mut parser = ElfParser::new(elf_data)?;

        // Extract license
        let license = parser.find_license()?;

        // Extract maps
        let maps = self.load_maps(&mut parser)?;

        // Extract programs
        let programs = self.load_programs(&mut parser, &maps)?;

        Ok(BpfObject::new(programs, maps, license))
    }

    /// Load map definitions from the ELF file.
    fn load_maps(&self, parser: &mut ElfParser) -> LoadResult<Vec<LoadedMap>> {
        let mut maps = Vec::new();

        // Look for "maps" section
        if let Some(section) = parser.find_section(".maps")? {
            let data = parser.section_data(&section)?;

            // Parse map definitions
            let mut offset = 0;
            while offset + MAP_DEF_SIZE <= data.len() {
                if maps.len() >= self.max_maps {
                    return Err(LoadError::TooManyMaps);
                }

                let map_def = MapDef::from_bytes(&data[offset..offset + MAP_DEF_SIZE])?;
                let name = parser.section_name_at(section.name_offset + offset as u32)?;

                maps.push(LoadedMap { name, def: map_def });
                offset += MAP_DEF_SIZE;
            }
        }

        // Also check for BTF-defined maps
        // TODO: BTF parsing for cloud profile

        Ok(maps)
    }

    /// Load programs from the ELF file.
    fn load_programs(
        &self,
        parser: &mut ElfParser,
        maps: &[LoadedMap],
    ) -> LoadResult<Vec<LoadedProgram<P>>> {
        let mut programs = Vec::new();

        // Iterate through sections looking for program sections
        for section in parser.sections()? {
            if section.section_type != SectionType::Program {
                continue;
            }

            if programs.len() >= self.max_programs {
                return Err(LoadError::TooManyPrograms);
            }

            let name = parser.section_name(section)?;
            let prog_type = Self::section_to_prog_type(&name);
            let data = parser.section_data(section)?;

            // Parse instructions
            let insns = Self::parse_instructions(data)?;

            // Apply relocations
            let mut relocator = Relocator::new(maps);
            let insns = relocator.relocate(&name, insns, parser)?;

            // Resolve & inline BPF-to-BPF calls into a flat program (#87).
            let insns = normalize(&insns)?.insns;

            programs.push(LoadedProgram::new(name, prog_type, insns));
        }

        Ok(programs)
    }

    /// Convert section name to program type.
    fn section_to_prog_type(name: &str) -> BpfProgType {
        // Handle common section name prefixes
        if name.starts_with("socket") || name.starts_with("sk_") {
            BpfProgType::SocketFilter
        } else if name.starts_with("kprobe")
            || name.starts_with("kretprobe")
            || name.starts_with("fentry")
            || name.starts_with("fexit")
        {
            BpfProgType::Kprobe
        } else if name.starts_with("tracepoint")
            || name.starts_with("tp/")
            || name.starts_with("raw_tracepoint")
            || name.starts_with("raw_tp/")
            || name.starts_with("iter/")
        {
            BpfProgType::Tracepoint
        } else if name.starts_with("xdp") {
            BpfProgType::Xdp
        } else if name.starts_with("perf_event") {
            BpfProgType::PerfEvent
        } else if name.starts_with("cgroup") {
            BpfProgType::CgroupSkb
        } else if name.starts_with("sched_cls") || name.starts_with("tc") {
            BpfProgType::SchedCls
        } else if name.starts_with("lwt_") {
            BpfProgType::LwtIn
        } else {
            // Default to socket filter for unknown types (including struct_ops, lsm)
            BpfProgType::SocketFilter
        }
    }

    /// Parse instructions from raw bytes.
    fn parse_instructions(data: &[u8]) -> LoadResult<Vec<BpfInsn>> {
        if !data.len().is_multiple_of(INSN_SIZE) {
            return Err(LoadError::InvalidInstructionData);
        }

        let mut insns = Vec::with_capacity(data.len() / INSN_SIZE);

        for chunk in data.chunks_exact(INSN_SIZE) {
            let insn = BpfInsn::from_bytes_load(chunk)?;
            insns.push(insn);
        }

        Ok(insns)
    }
}

impl<P: PhysicalProfile> Default for BpfLoader<P> {
    fn default() -> Self {
        Self::new()
    }
}

/// Size of a map definition in bytes.
const MAP_DEF_SIZE: usize = 20; // type + key_size + value_size + max_entries + flags

impl MapDef {
    /// Parse a map definition from bytes.
    fn from_bytes(data: &[u8]) -> LoadResult<Self> {
        if data.len() < MAP_DEF_SIZE {
            return Err(LoadError::InvalidMapData);
        }

        let map_type_raw = u32::from_ne_bytes(data[0..4].try_into().unwrap());
        let key_size = u32::from_ne_bytes(data[4..8].try_into().unwrap());
        let value_size = u32::from_ne_bytes(data[8..12].try_into().unwrap());
        let max_entries = u32::from_ne_bytes(data[12..16].try_into().unwrap());
        let flags = u32::from_ne_bytes(data[16..20].try_into().unwrap());

        use crate::maps::MapType;
        let map_type = match map_type_raw {
            0 => MapType::Unspec,
            1 => MapType::Hash,
            2 => MapType::Array,
            3 => MapType::ProgArray,
            4 => MapType::PerfEventArray,
            5 => MapType::PerCpuHash,
            6 => MapType::PerCpuArray,
            7 => MapType::StackTrace,
            8 => MapType::CgroupArray,
            27 => MapType::RingBuf,
            #[cfg(feature = "cloud-profile")]
            9 => MapType::LruHash,
            #[cfg(feature = "cloud-profile")]
            10 => MapType::LruPerCpuHash,
            #[cfg(feature = "cloud-profile")]
            11 => MapType::LpmTrie,
            _ => return Err(LoadError::UnsupportedMapType(map_type_raw)),
        };

        Ok(Self {
            map_type,
            key_size,
            value_size,
            max_entries,
            flags,
        })
    }
}

/// Size of a BPF instruction in bytes.
const INSN_SIZE: usize = 8;

impl BpfInsn {
    /// Parse an instruction from bytes.
    fn from_bytes_load(data: &[u8]) -> LoadResult<Self> {
        if data.len() < INSN_SIZE {
            return Err(LoadError::InvalidInstructionData);
        }

        Ok(Self::new(
            data[0],                                            // opcode
            data[1] & 0x0f,                                     // dst_reg
            (data[1] >> 4) & 0x0f,                              // src_reg
            i16::from_ne_bytes(data[2..4].try_into().unwrap()), // offset
            i32::from_ne_bytes(data[4..8].try_into().unwrap()), // imm
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loader_creation() {
        let loader = BpfLoader::<ActiveProfile>::new();
        assert!(loader.max_programs > 0);
        assert!(loader.max_maps > 0);
    }

    #[test]
    fn section_to_prog_type_mapping() {
        assert_eq!(
            BpfLoader::<ActiveProfile>::section_to_prog_type("socket"),
            BpfProgType::SocketFilter
        );
        assert_eq!(
            BpfLoader::<ActiveProfile>::section_to_prog_type("kprobe/sys_write"),
            BpfProgType::Kprobe
        );
        assert_eq!(
            BpfLoader::<ActiveProfile>::section_to_prog_type("xdp"),
            BpfProgType::Xdp
        );
        assert_eq!(
            BpfLoader::<ActiveProfile>::section_to_prog_type("tracepoint/syscalls/sys_enter_write"),
            BpfProgType::Tracepoint
        );
    }

    #[test]
    fn insn_from_bytes() {
        // mov64 r0, 42 instruction
        let data = [0xb7, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00];
        let insn = BpfInsn::from_bytes_load(&data).unwrap();

        assert_eq!(insn.opcode, 0xb7); // mov64_imm
        assert_eq!(insn.dst_reg(), 0);
        assert_eq!(insn.src_reg(), 0);
        assert_eq!(insn.offset, 0);
        assert_eq!(insn.imm, 42);
    }
}
