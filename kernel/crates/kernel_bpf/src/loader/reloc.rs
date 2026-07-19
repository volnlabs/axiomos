//! BPF Relocation Handler
//!
//! Handles relocations for map references and other symbols in BPF programs.

extern crate alloc;

use alloc::vec::Vec;

use super::elf::{ElfParser, Relocation, SectionType, Symbol};
use super::error::{LoadError, LoadResult};
use super::normalize::BPF_PSEUDO_CALL;
use super::object::LoadedMap;
use crate::bytecode::insn::BpfInsn;
use crate::verifier::HelperId;

// BPF relocation types
const R_BPF_64_64: u32 = 1;
const R_BPF_64_ABS64: u32 = 2;
const R_BPF_64_ABS32: u32 = 3;
const R_BPF_64_32: u32 = 10;
const STT_FUNC: u8 = 2;
const SHN_UNDEF: u16 = 0;

/// Per-section relocation context shared by `apply_relocations` and
/// `relocate_call`. The three indices are always passed together; collapsing
/// them keeps call sites readable and lets both methods drop one argument each
/// (audit H-06 quick-win #2: argument-group refactor).
#[derive(Clone, Copy)]
struct SectionContext {
    /// Index of the section currently being relocated.
    section_idx: usize,
    /// Base instruction offset of `section_idx` in the combined instruction
    /// stream (`0` for the root program).
    section_base: usize,
    /// Index of the root program section. Cross-section calls targeting this
    /// index resolve to `section_base == 0`.
    root_section_idx: usize,
}

/// BPF instruction relocation handler.
pub struct Relocator<'a> {
    /// Map definitions for resolving map references
    maps: &'a [LoadedMap],
    /// Extra executable sections appended after the root program, with their
    /// base instruction index in the combined instruction stream.
    linked_sections: Vec<(usize, usize)>,
}

impl<'a> Relocator<'a> {
    /// Create a new relocator.
    pub fn new(maps: &'a [LoadedMap]) -> Self {
        Self {
            maps,
            linked_sections: Vec::new(),
        }
    }

    /// Provide executable sections that were appended to the root program.
    pub fn with_linked_sections(mut self, linked_sections: Vec<(usize, usize)>) -> Self {
        self.linked_sections = linked_sections;
        self
    }

    /// Discover executable sections reached by cross-section BPF-to-BPF calls.
    pub fn linked_call_sections(
        root_section_idx: usize,
        parser: &ElfParser,
    ) -> LoadResult<Vec<usize>> {
        let mut out = Vec::new();
        Self::collect_linked_call_sections(root_section_idx, root_section_idx, parser, &mut out)?;
        Ok(out)
    }

    /// Apply relocations to instructions.
    pub fn relocate(
        &mut self,
        section_name: &str,
        mut insns: Vec<BpfInsn>,
        parser: &ElfParser,
    ) -> LoadResult<Vec<BpfInsn>> {
        // Find the section index for this program
        let sections = parser.sections()?;
        let section_idx = sections
            .iter()
            .position(|s| {
                parser
                    .section_name(s)
                    .map(|n| n == section_name)
                    .unwrap_or(false)
            })
            .ok_or(LoadError::InvalidRelocation)?;

        let root_relocs = parser.relocations(section_idx)?;
        let mut linked_relocs = Vec::new();
        let mut has_relocations = !root_relocs.is_empty();
        for &(linked_idx, base_idx) in &self.linked_sections {
            let relocs = parser.relocations(linked_idx)?;
            has_relocations |= !relocs.is_empty();
            linked_relocs.push((linked_idx, base_idx, relocs));
        }

        if !has_relocations {
            return Ok(insns);
        }

        // Get symbol table
        let symbols = parser.symbols()?;

        self.apply_relocations(
            &mut insns,
            parser,
            &root_relocs,
            &symbols,
            SectionContext {
                section_idx,
                section_base: 0,
                root_section_idx: section_idx,
            },
        )?;
        for (linked_idx, base_idx, relocs) in linked_relocs {
            self.apply_relocations(
                &mut insns,
                parser,
                &relocs,
                &symbols,
                SectionContext {
                    section_idx: linked_idx,
                    section_base: base_idx,
                    root_section_idx: section_idx,
                },
            )?;
        }

        Ok(insns)
    }

    fn collect_linked_call_sections(
        root_section_idx: usize,
        section_idx: usize,
        parser: &ElfParser,
        out: &mut Vec<usize>,
    ) -> LoadResult<()> {
        let relocs = parser.relocations(section_idx)?;
        if relocs.is_empty() {
            return Ok(());
        }

        let sections = parser.sections()?;
        let symbols = parser.symbols()?;
        for reloc in relocs {
            if reloc.rel_type != R_BPF_64_32 {
                continue;
            }
            let sym = symbols
                .get(reloc.sym_idx as usize)
                .ok_or(LoadError::UndefinedSymbol)?;
            let sym_name = parser.symbol_name(sym)?;
            if Self::helper_name_to_id(&sym_name).is_some()
                || sym.sym_type() != STT_FUNC
                || sym.shndx == SHN_UNDEF
            {
                continue;
            }

            let target_idx = sym.shndx as usize;
            if target_idx == section_idx || target_idx == root_section_idx {
                continue;
            }

            match sections.get(target_idx) {
                Some(section) if section.section_type == SectionType::Program => {}
                _ => return Err(LoadError::InvalidRelocation),
            }

            if !out.contains(&target_idx) {
                out.push(target_idx);
                Self::collect_linked_call_sections(root_section_idx, target_idx, parser, out)?;
            }
        }

        Ok(())
    }

    fn apply_relocations(
        &self,
        insns: &mut [BpfInsn],
        parser: &ElfParser,
        relocs: &[Relocation],
        symbols: &[Symbol],
        ctx: SectionContext,
    ) -> LoadResult<()> {
        for reloc in relocs {
            if !reloc.offset.is_multiple_of(BpfInsn::SIZE as u64) {
                return Err(LoadError::InvalidRelocation);
            }
            let insn_idx = ctx
                .section_base
                .checked_add((reloc.offset / BpfInsn::SIZE as u64) as usize)
                .ok_or(LoadError::InvalidRelocation)?;
            if insn_idx >= insns.len() {
                return Err(LoadError::InvalidRelocation);
            }

            // Get symbol
            if reloc.sym_idx as usize >= symbols.len() {
                return Err(LoadError::UndefinedSymbol);
            }
            let sym = &symbols[reloc.sym_idx as usize];
            let sym_name = parser.symbol_name(sym)?;

            // Apply relocation based on type
            match reloc.rel_type {
                R_BPF_64_64 => {
                    // Map reference - 64-bit load immediate
                    self.relocate_map_ref(insns, insn_idx, &sym_name)?;
                }
                R_BPF_64_32 => {
                    // Helper or BPF-to-BPF function call.
                    self.relocate_call(insns, insn_idx, sym, &sym_name, ctx)?;
                }
                R_BPF_64_ABS64 | R_BPF_64_ABS32 => {
                    // Absolute references - typically for data
                    // These are handled differently based on context
                }
                _ => {
                    // Unknown relocation type - ignore for now
                }
            }
        }

        Ok(())
    }

    /// Relocate a map reference.
    fn relocate_map_ref(
        &self,
        insns: &mut [BpfInsn],
        insn_idx: usize,
        sym_name: &str,
    ) -> LoadResult<()> {
        // Find map by name
        let map_idx = self
            .maps
            .iter()
            .position(|m| m.name == sym_name)
            .ok_or(LoadError::UndefinedSymbol)?;

        // Update instruction with map index
        // BPF uses ld_imm64 for map references
        let insn = &mut insns[insn_idx];

        // src_reg = BPF_PSEUDO_MAP_FD (1) indicates map reference
        // imm contains the map index
        // regs format: dst (low 4 bits) | src (high 4 bits)
        insn.regs = (insn.regs & 0x0f) | (1 << 4); // Set src to BPF_PSEUDO_MAP_FD
        insn.imm = map_idx as i32;

        // If this is a wide instruction, update the second half too
        if insn_idx + 1 < insns.len() && insns[insn_idx].is_wide() {
            insns[insn_idx + 1].imm = 0;
        }

        Ok(())
    }

    /// Relocate a function call.
    fn relocate_call(
        &self,
        insns: &mut [BpfInsn],
        insn_idx: usize,
        sym: &Symbol,
        sym_name: &str,
        ctx: SectionContext,
    ) -> LoadResult<()> {
        // Check if this is a helper function call
        if let Some(helper_id) = Self::helper_name_to_id(sym_name) {
            insns[insn_idx].regs &= 0x0f;
            insns[insn_idx].imm = helper_id;
            return Ok(());
        }

        if sym.sym_type() != STT_FUNC || sym.shndx == SHN_UNDEF {
            return Ok(());
        }
        if !sym.value.is_multiple_of(BpfInsn::SIZE as u64) {
            return Err(LoadError::InvalidRelocation);
        }

        let target_section_idx = sym.shndx as usize;
        let target_base = self
            .section_base_for(
                target_section_idx,
                ctx.section_idx,
                ctx.section_base,
                ctx.root_section_idx,
            )
            .ok_or(LoadError::InvalidRelocation)?;
        let target_idx = target_base
            .checked_add((sym.value / BpfInsn::SIZE as u64) as usize)
            .ok_or(LoadError::InvalidRelocation)?;
        if target_idx >= insns.len() {
            return Err(LoadError::InvalidRelocation);
        }
        let imm = target_idx as i64 - insn_idx as i64 - 1;
        if imm < i32::MIN as i64 || imm > i32::MAX as i64 {
            return Err(LoadError::InvalidRelocation);
        }

        insns[insn_idx].regs = (insns[insn_idx].regs & 0x0f) | (BPF_PSEUDO_CALL << 4);
        insns[insn_idx].imm = imm as i32;

        Ok(())
    }

    fn section_base_for(
        &self,
        target_section_idx: usize,
        current_section_idx: usize,
        current_section_base: usize,
        root_section_idx: usize,
    ) -> Option<usize> {
        if target_section_idx == root_section_idx {
            return Some(0);
        }
        if target_section_idx == current_section_idx {
            return Some(current_section_base);
        }
        self.linked_sections
            .iter()
            .find_map(|&(idx, base)| (idx == target_section_idx).then_some(base))
    }

    /// Convert a helper function name to its runtime helper ID.
    ///
    /// Returns IDs from the kernel's *runtime ABI* ([`HelperId`]) — the same
    /// numbering the interpreter dispatches on and the WCET cost model reads —
    /// not the upstream Linux uapi numbering. Helpers the runtime does not
    /// implement (skb/csum/xdp/etc.) return `None`: better to leave a call
    /// unrelocated (and fail verification) than to emit an ID that would
    /// dispatch a different helper. Single source of truth for helper IDs, per
    /// #121.
    fn helper_name_to_id(name: &str) -> Option<i32> {
        let id = match name {
            "bpf_map_lookup_elem" => HelperId::MapLookupElem,
            "bpf_map_update_elem" => HelperId::MapUpdateElem,
            "bpf_map_delete_elem" => HelperId::MapDeleteElem,
            "bpf_probe_read" => HelperId::ProbeRead,
            "bpf_ktime_get_ns" => HelperId::KtimeGetNs,
            "bpf_trace_printk" => HelperId::TracePrintk,
            "bpf_get_prandom_u32" => HelperId::GetPrandomU32,
            "bpf_get_smp_processor_id" => HelperId::GetSmpProcessorId,
            "bpf_get_current_pid_tgid" => HelperId::GetCurrentPidTgid,
            "bpf_get_current_uid_gid" => HelperId::GetCurrentUidGid,
            "bpf_get_current_comm" => HelperId::GetCurrentComm,
            // Ring buffer helpers
            "bpf_ringbuf_output" => HelperId::RingbufOutput,
            "bpf_ringbuf_reserve" => HelperId::RingbufReserve,
            "bpf_ringbuf_submit" => HelperId::RingbufSubmit,
            "bpf_ringbuf_discard" => HelperId::RingbufDiscard,
            // rkBPF robotics-specific helpers
            "bpf_timeseries_push" => HelperId::TimeseriesPush,
            "bpf_sensor_last_timestamp" => HelperId::SensorLastTimestamp,
            _ => return None,
        };
        Some(id as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::normalize::BPF_PSEUDO_CALL;

    #[test]
    fn helper_name_mapping_uses_runtime_abi() {
        use crate::verifier::HelperId;
        // The loader must emit the *runtime* helper ABI (the IDs the interpreter
        // dispatches on and the cost model reads), not the upstream Linux uapi
        // numbering. Otherwise an ELF-loaded `bpf_map_lookup_elem` would be
        // dispatched as a different helper. See #121.
        assert_eq!(
            Relocator::helper_name_to_id("bpf_map_lookup_elem"),
            Some(HelperId::MapLookupElem as i32)
        );
        assert_eq!(
            Relocator::helper_name_to_id("bpf_ktime_get_ns"),
            Some(HelperId::KtimeGetNs as i32)
        );
        assert_eq!(
            Relocator::helper_name_to_id("bpf_ringbuf_output"),
            Some(HelperId::RingbufOutput as i32)
        );
        assert_eq!(
            Relocator::helper_name_to_id("bpf_motor_emergency_stop"),
            None
        );
        assert_eq!(Relocator::helper_name_to_id("unknown_helper"), None);
    }

    /// Every name the loader relocates must resolve, through the runtime ABI
    /// decoder, back to a real helper — no id the interpreter would reject or
    /// mis-dispatch. Guards against the loader/runtime drift #121 closed.
    #[test]
    fn every_relocated_helper_id_is_a_known_runtime_helper() {
        use crate::verifier::HelperId;
        for name in [
            "bpf_map_lookup_elem",
            "bpf_map_update_elem",
            "bpf_map_delete_elem",
            "bpf_probe_read",
            "bpf_ktime_get_ns",
            "bpf_trace_printk",
            "bpf_get_prandom_u32",
            "bpf_get_smp_processor_id",
            "bpf_get_current_pid_tgid",
            "bpf_get_current_uid_gid",
            "bpf_get_current_comm",
            "bpf_ringbuf_output",
            "bpf_ringbuf_reserve",
            "bpf_ringbuf_submit",
            "bpf_ringbuf_discard",
            "bpf_timeseries_push",
            "bpf_sensor_last_timestamp",
        ] {
            let id = Relocator::helper_name_to_id(name)
                .unwrap_or_else(|| panic!("{name} should relocate to a helper id"));
            assert!(
                HelperId::from_raw(id).is_some(),
                "{name} relocated to id {id}, which the runtime ABI does not know"
            );
        }
    }

    #[test]
    fn function_relocation_marks_section_local_pseudo_call() {
        let mut insns = alloc::vec![
            BpfInsn::call(-1),
            BpfInsn::mov64_imm(0, 0),
            BpfInsn::exit(),
            BpfInsn::mov64_imm(0, 1),
            BpfInsn::exit(),
        ];
        let sym = crate::loader::elf::Symbol {
            name_offset: 0,
            info: 2,
            other: 0,
            shndx: 7,
            value: (3 * BpfInsn::SIZE) as u64,
            size: (2 * BpfInsn::SIZE) as u64,
        };

        Relocator::new(&[])
            .relocate_call(
                &mut insns,
                0,
                &sym,
                "leaf",
                SectionContext {
                    section_idx: 7,
                    section_base: 0,
                    root_section_idx: 7,
                },
            )
            .unwrap();

        assert_eq!(insns[0].src_reg(), BPF_PSEUDO_CALL);
        assert_eq!(insns[0].imm, 2);
    }

    #[test]
    fn function_relocation_targets_linked_section() {
        let mut insns = alloc::vec![
            BpfInsn::call(-1),
            BpfInsn::exit(),
            BpfInsn::mov64_imm(0, 1),
            BpfInsn::exit(),
        ];
        let sym = crate::loader::elf::Symbol {
            name_offset: 0,
            info: 2,
            other: 0,
            shndx: 9,
            value: 0,
            size: (2 * BpfInsn::SIZE) as u64,
        };

        Relocator::new(&[])
            .with_linked_sections(alloc::vec![(9, 2)])
            .relocate_call(
                &mut insns,
                0,
                &sym,
                "leaf",
                SectionContext {
                    section_idx: 7,
                    section_base: 0,
                    root_section_idx: 7,
                },
            )
            .unwrap();

        assert_eq!(insns[0].src_reg(), BPF_PSEUDO_CALL);
        assert_eq!(insns[0].imm, 1);
    }
}
