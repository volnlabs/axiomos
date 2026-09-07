#[derive(Debug, Clone, Copy)]
pub(super) struct BpfLimits {
    pub(super) max_live_programs: usize,
    pub(super) max_program_slots: usize,
    pub(super) max_program_bytes: usize,
    pub(super) max_single_program_bytes: usize,
    pub(super) max_owner_programs: usize,
    pub(super) max_owner_program_bytes: usize,
    pub(super) max_elf_bytes: usize,
    pub(super) max_live_maps: usize,
    pub(super) max_map_slots: usize,
    pub(super) max_map_bytes: usize,
    pub(super) max_single_map_bytes: usize,
    pub(super) max_owner_maps: usize,
    pub(super) max_owner_map_bytes: usize,
    pub(super) max_pinned_maps: usize,
    pub(super) max_key_size: u32,
    pub(super) max_value_size: u32,
    pub(super) max_entries: u32,
}

impl BpfLimits {
    #[cfg(feature = "cloud-profile")]
    pub(super) const fn for_active_profile() -> Self {
        Self {
            max_live_programs: 128,
            max_program_slots: 1024,
            max_program_bytes: 16 * 1024 * 1024,
            max_single_program_bytes: 1024 * 1024,
            max_owner_programs: 32,
            max_owner_program_bytes: 4 * 1024 * 1024,
            max_elf_bytes: 1024 * 1024,
            max_live_maps: 64,
            max_map_slots: 512,
            max_map_bytes: 64 * 1024 * 1024,
            max_single_map_bytes: 16 * 1024 * 1024,
            max_owner_maps: 16,
            max_owner_map_bytes: 16 * 1024 * 1024,
            max_pinned_maps: 128,
            max_key_size: 512,
            max_value_size: 64 * 1024,
            max_entries: 1024 * 1024,
        }
    }

    #[cfg(all(
        not(feature = "cloud-profile"),
        any(feature = "embedded-profile", feature = "bpf-update-diagnostics")
    ))]
    pub(super) const fn for_active_profile() -> Self {
        Self {
            max_live_programs: 32,
            max_program_slots: 128,
            max_program_bytes: 2 * 1024 * 1024,
            max_single_program_bytes: 800 * 1024,
            max_owner_programs: 8,
            max_owner_program_bytes: 512 * 1024,
            max_elf_bytes: 1024 * 1024,
            max_live_maps: 16,
            max_map_slots: 64,
            max_map_bytes: 64 * 1024,
            max_single_map_bytes: 64 * 1024,
            max_owner_maps: 4,
            max_owner_map_bytes: 32 * 1024,
            max_pinned_maps: 32,
            max_key_size: 256,
            max_value_size: 4 * 1024,
            max_entries: 4 * 1024,
        }
    }
}
