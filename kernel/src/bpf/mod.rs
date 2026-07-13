pub mod helpers;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use kernel_abi::{BpfObjectInfo, BPF_OBJECT_KIND_MAP};
use kernel_bpf::actuation::EnvelopeMap;
use kernel_bpf::attach::{GpioEdge, GpioRouteTable};
use kernel_bpf::bytecode::insn::BpfInsn;
use kernel_bpf::bytecode::program::{BpfProgType, BpfProgram};
use kernel_bpf::execution::{BpfContext, BpfError, Interpreter};
use kernel_bpf::loader::BpfLoader;
use kernel_bpf::maps::{ArrayMap, BpfMap, HashMap as BpfHashMap, RingBufMap, TimeSeriesMap};
use kernel_bpf::profile::{ActiveProfile, PhysicalProfile};
use kernel_bpf::signing::{SignatureVerifier, TrustedKey};
use kernel_bpf::verifier::admission::AdmissionLedger;
use kernel_bpf::verifier::{LoadCaller, MapPerm, Verifier, VerifyConfig};
use spin::{Mutex, MutexGuard};

/// Serializes BPF execution against userspace map reads/mutations. Map lookup
/// helpers currently return raw value pointers after dropping the map's inner
/// lock; keeping one runtime guard live until program return prevents another
/// CPU from updating, deleting, polling, or destroying that storage meanwhile.
static BPF_RUNTIME: Mutex<()> = Mutex::new(());

pub(crate) fn lock_runtime() -> MutexGuard<'static, ()> {
    BPF_RUNTIME.lock()
}

/// Context size used for load-time verification (#122).
///
/// R1 at program entry points at a [`BpfContext`] — *uniformly for every attach
/// type*. The interpreter sets `R1 = &BpfContext` (see
/// `Interpreter::execute`) and bounds R1-relative reads to
/// `size_of::<BpfContext>()` (the "context access" arm of `execute_load`); the
/// per-hook structs (`SyscallTraceContext`, `SchedSwitchContext`, …) are reached
/// through the `BpfContext::data` pointer, not off R1. So the precise context
/// size is the same at load time as at attach time, and there is no attach-type
/// variance to defer: bound it to exactly the context the interpreter exposes.
/// The previous 256 placeholder let a program read past the real context into
/// adjacent kernel memory (the interpreter's generic-deref arm trusts the
/// verifier), which is the info-leak this closes.
const VERIFY_CTX_SIZE: u32 = core::mem::size_of::<BpfContext<'static>>() as u32;

const VERIFY_CTX_DATA_SIZE_NONE: u32 = 0;
const VERIFY_CTX_DATA_SIZE_GPIO: u32 = core::mem::size_of::<kernel_bpf::attach::GpioEvent>() as u32;
const VERIFY_CTX_DATA_SIZE_PWM: u32 = core::mem::size_of::<kernel_bpf::attach::PwmEvent>() as u32;
const VERIFY_CTX_DATA_SIZE_IIO: u32 = core::mem::size_of::<kernel_bpf::attach::IioEvent>() as u32;
const VERIFY_CTX_DATA_SIZE_SYS_ENTER: u32 =
    core::mem::size_of::<kernel_bpf::execution::SyscallTraceContext>() as u32;
const VERIFY_CTX_DATA_SIZE_SYS_EXIT: u32 =
    core::mem::size_of::<kernel_bpf::execution::SyscallExitContext>() as u32;
const VERIFY_CTX_DATA_SIZE_SCHED_SWITCH: u32 =
    core::mem::size_of::<kernel_bpf::execution::SchedSwitchContext>() as u32;

const fn max_u32(a: u32, b: u32) -> u32 {
    if a > b {
        a
    } else {
        b
    }
}

const VERIFY_CTX_DATA_SIZE_MAX: u32 = max_u32(
    VERIFY_CTX_DATA_SIZE_SYS_ENTER,
    max_u32(
        VERIFY_CTX_DATA_SIZE_SCHED_SWITCH,
        max_u32(
            VERIFY_CTX_DATA_SIZE_PWM,
            max_u32(VERIFY_CTX_DATA_SIZE_IIO, VERIFY_CTX_DATA_SIZE_GPIO),
        ),
    ),
);

/// Fallback map-value size, used only when no per-map sizes are available
/// (e.g. a `bpf_ringbuf_reserve` allocation return, or a program loaded before
/// any map exists). Precise per-map bounds come from [`map_value_sizes`] (#123).
const VERIFY_MAP_VALUE_SIZE: u32 = 256;

/// Architectural cycle counter for verifier-cost measurement (Track B).
///
/// Reads `CNTVCT_EL0` on AArch64 (the same counter the IRQ-latency benchmark
/// uses); returns 0 on other targets, where the marker still emits states but
/// no meaningful cycle delta. Only compiled under the `verifier-cost` feature.
#[cfg(feature = "verifier-cost")]
fn read_cycles() -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        let c: u64;
        unsafe { core::arch::asm!("mrs {}, cntvct_el0", out(reg) c) };
        c
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        0
    }
}

pub const ATTACH_TYPE_TIMER: u32 = 1;
pub const ATTACH_TYPE_GPIO: u32 = 2;
pub const ATTACH_TYPE_PWM: u32 = 3;
pub const ATTACH_TYPE_IIO: u32 = 4;
pub const ATTACH_TYPE_SYSCALL: u32 = 5;
pub const ATTACH_TYPE_SYS_ENTER: u32 = ATTACH_TYPE_SYSCALL;
pub const ATTACH_TYPE_SYS_EXIT: u32 = 6;
pub const ATTACH_TYPE_SCHED_SWITCH: u32 = 7;

pub const ENVELOPE_MAP_ID: u32 = 0;
pub const RESERVED_MAP_COUNT: u32 = 1;

const BPF_HANDLE_SLOT_BITS: u32 = 10;
const BPF_HANDLE_SLOT_MASK: u32 = (1 << BPF_HANDLE_SLOT_BITS) - 1;
// Keep the top bit clear: userspace returns handles through c_int and BPF map
// handles are commonly materialized through signed 32-bit immediates.
const BPF_HANDLE_MAX_GENERATION: u32 = (i32::MAX as u32) >> BPF_HANDLE_SLOT_BITS;

fn encode_handle(slot: usize, generation: u32) -> u32 {
    debug_assert!(slot <= BPF_HANDLE_SLOT_MASK as usize);
    debug_assert!(generation <= BPF_HANDLE_MAX_GENERATION);
    let handle = (generation << BPF_HANDLE_SLOT_BITS) | slot as u32;
    debug_assert!(i32::try_from(handle).is_ok());
    handle
}

fn decode_handle(generations: &[u32], handle: u32) -> Option<usize> {
    let slot = (handle & BPF_HANDLE_SLOT_MASK) as usize;
    let generation = handle >> BPF_HANDLE_SLOT_BITS;
    (generations.get(slot).copied() == Some(generation)).then_some(slot)
}

fn insert_handle_slot<T>(
    slots: &mut Vec<Option<T>>,
    generations: &mut Vec<u32>,
    max_slots: usize,
    value: T,
) -> Result<u32, BpfError> {
    if let Some(slot) = slots
        .iter()
        .enumerate()
        .find(|(slot, entry)| entry.is_none() && generations[*slot] < BPF_HANDLE_MAX_GENERATION)
        .map(|(slot, _)| slot)
    {
        let generation = generations[slot];
        let generation = generation + 1;
        generations[slot] = generation;
        slots[slot] = Some(value);
        return Ok(encode_handle(slot, generation));
    }
    if slots.len() >= max_slots || slots.len() > BPF_HANDLE_SLOT_MASK as usize {
        return Err(BpfError::ResourceLimit);
    }
    slots.try_reserve(1).map_err(|_| BpfError::OutOfMemory)?;
    generations
        .try_reserve(1)
        .map_err(|_| BpfError::OutOfMemory)?;
    let slot = slots.len();
    slots.push(Some(value));
    generations.push(0);
    Ok(encode_handle(slot, 0))
}

/// One resolved GPIO program slot for the zero-alloc dispatch buffer (#65):
/// `(prog_id, Arc<program>)`. Aliased so the hot-path buffer type stays legible.
pub type GpioProgramSlot = Option<(u32, Arc<BpfProgram<ActiveProfile>>)>;
/// One resolved generic hook slot for allocation-free dispatch.
pub type HookProgramSlot = Option<(u32, Arc<BpfProgram<ActiveProfile>>)>;
/// Maximum GPIO programs resolved for one IRQ edge. Must match the stack buffer
/// used by the Pi 5 GPIO IRQ handler.
pub const GPIO_IRQ_FANOUT_LIMIT: usize = 8;
/// Maximum programs on any single hook. Attach enforces this so dispatch never
/// truncates a configured hook when resolving into its stack buffer.
pub const HOOK_FANOUT_LIMIT: usize = 16;
/// Maximum byte length (including the trailing NUL supplied by userspace) for
/// a pinned-object path.
pub const BPF_PIN_PATH_MAX: usize = 256;

#[derive(Debug, Clone, Copy)]
struct BpfLimits {
    max_live_programs: usize,
    max_program_slots: usize,
    max_program_bytes: usize,
    max_single_program_bytes: usize,
    max_owner_programs: usize,
    max_owner_program_bytes: usize,
    max_elf_bytes: usize,
    max_live_maps: usize,
    max_map_slots: usize,
    max_map_bytes: usize,
    max_single_map_bytes: usize,
    max_owner_maps: usize,
    max_owner_map_bytes: usize,
    max_pinned_maps: usize,
    max_key_size: u32,
    max_value_size: u32,
    max_entries: u32,
}

impl BpfLimits {
    #[cfg(feature = "cloud-profile")]
    const fn for_active_profile() -> Self {
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

    #[cfg(all(feature = "embedded-profile", not(feature = "cloud-profile")))]
    const fn for_active_profile() -> Self {
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

struct ProgramEntry {
    program: Arc<BpfProgram<ActiveProfile>>,
    wcet_cycles: u64,
    charged_bytes: usize,
    owner: u64,
}

struct MapEntry {
    map: Box<dyn BpfMap<ActiveProfile>>,
    perm: MapPerm,
    charged_bytes: usize,
    owner: u64,
}

/// Global BPF resource usage. Per-process ceilings are enforced separately
/// while these counters retain the manager-wide hard ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfResourceUsage {
    pub live_programs: usize,
    pub program_bytes: usize,
    pub live_maps: usize,
    pub map_bytes: usize,
    pub pinned_maps: usize,
}

pub struct BpfManager {
    // Arc so the hot dispatch path (gpio_programs_into/get_hook_programs) clones
    // a refcount, not the whole instruction Vec — the IRQ handler runs this per
    // edge at up to ~200k/s (#65), where a deep BpfProgram::clone drops edges.
    programs: Vec<Option<ProgramEntry>>,
    program_generations: Vec<u32>,
    attachments: BTreeMap<u32, Vec<u32>>,
    maps: Vec<Option<MapEntry>>,
    map_generations: Vec<u32>,
    pinned_maps: Vec<(String, u32)>,
    /// Trust store for program provenance (#20). A program is authentic if it
    /// is an RBPF [`SignedProgram`] signed by a key in here.
    signature_verifier: SignatureVerifier,
    /// When true, programs without a signature container are accepted. Defaults
    /// to true for v0.1.x because no userspace signer ships yet; flip to false
    /// (via [`BpfManager::set_allow_unsigned`]) to enforce provenance.
    allow_unsigned: bool,
    /// Static WCET cycle bound per loaded program, indexed by prog id —
    /// `VerifyStats::wcet_cycles` captured at load (#43).
    /// Utilization-form admission ledger: an attach is refused when the summed
    /// `Σ WCETᵢ·freqᵢ` of all admitted programs would exceed the profile's CPU
    /// utilization budget (#43).
    admission: AdmissionLedger,
    /// Per-(chip,pin,edge) GPIO attachment routing. The type-keyed `attachments`
    /// map drives non-GPIO hooks; GPIO dispatch uses this so each program runs
    /// only for its own pin and edge.
    gpio_routes: GpioRouteTable,
    limits: BpfLimits,
    live_programs: usize,
    program_bytes: usize,
    live_maps: usize,
    map_bytes: usize,
}

/// Default fire frequency assumed for a hook, in Hz. Every hook is assumed to
/// fire at the control-loop rate (`1e9 / RT_PERIOD_NS` = 1 kHz on embedded);
/// per-hook-type and caller-declared frequencies are future work. On the cloud
/// profile `RT_PERIOD_NS` is unbounded so this is 0 — combined with the
/// unbounded utilization budget, admission never rejects there.
fn hook_frequency_hz(_attach_type: u32) -> u64 {
    let period = <ActiveProfile as PhysicalProfile>::RT_PERIOD_NS;
    if period == 0 || period == u64::MAX {
        0
    } else {
        1_000_000_000 / period
    }
}

const fn attach_ctx_data_size(attach_type: u32) -> u32 {
    match attach_type {
        ATTACH_TYPE_TIMER => VERIFY_CTX_DATA_SIZE_NONE,
        ATTACH_TYPE_GPIO => VERIFY_CTX_DATA_SIZE_GPIO,
        ATTACH_TYPE_PWM => VERIFY_CTX_DATA_SIZE_PWM,
        ATTACH_TYPE_IIO => VERIFY_CTX_DATA_SIZE_IIO,
        ATTACH_TYPE_SYS_ENTER => VERIFY_CTX_DATA_SIZE_SYS_ENTER,
        ATTACH_TYPE_SYS_EXIT => VERIFY_CTX_DATA_SIZE_SYS_EXIT,
        ATTACH_TYPE_SCHED_SWITCH => VERIFY_CTX_DATA_SIZE_SCHED_SWITCH,
        _ => VERIFY_CTX_DATA_SIZE_NONE,
    }
}

const fn is_supported_attach_type(attach_type: u32) -> bool {
    matches!(
        attach_type,
        ATTACH_TYPE_TIMER
            | ATTACH_TYPE_GPIO
            | ATTACH_TYPE_PWM
            | ATTACH_TYPE_IIO
            | ATTACH_TYPE_SYS_ENTER
            | ATTACH_TYPE_SYS_EXIT
            | ATTACH_TYPE_SCHED_SWITCH
    )
}

impl Default for BpfManager {
    fn default() -> Self {
        Self::new()
    }
}

impl BpfManager {
    pub fn new() -> Self {
        Self::new_with_limits(BpfLimits::for_active_profile())
    }

    fn new_with_limits(limits: BpfLimits) -> Self {
        let mut manager = Self {
            programs: Vec::new(),
            program_generations: Vec::new(),
            attachments: BTreeMap::new(),
            maps: Vec::new(),
            map_generations: Vec::new(),
            pinned_maps: Vec::new(),
            signature_verifier: SignatureVerifier::new(),
            allow_unsigned: true,
            admission: AdmissionLedger::new(
                <ActiveProfile as PhysicalProfile>::UTILIZATION_BUDGET_NS_PER_S,
                <ActiveProfile as PhysicalProfile>::CYCLE_UNIT_NS,
            ),
            gpio_routes: GpioRouteTable::new(),
            limits,
            live_programs: 0,
            program_bytes: 0,
            live_maps: 0,
            map_bytes: 0,
        };
        let envelope = EnvelopeMap::<ActiveProfile>::init_from_profile();
        crate::actuation::ACTUATION_MONITOR
            .lock()
            .init_envelope_cache(&envelope);
        let envelope_id = manager.register_reserved_map(Box::new(envelope), MapPerm::ReadOnly);
        debug_assert_eq!(envelope_id, ENVELOPE_MAP_ID);
        debug_assert_eq!(manager.maps.len() as u32, RESERVED_MAP_COUNT);
        manager
    }

    /// Register a trusted signing key (the kernel-held root of trust). Keys come
    /// from the kernel build, never from the untrusted syscall caller — that is
    /// what makes the signature check a provenance check rather than theater.
    pub fn add_trusted_key(&mut self, key: TrustedKey) -> Result<(), BpfError> {
        self.signature_verifier
            .add_trusted_key(key)
            .map_err(|_| BpfError::SignatureRejected)
    }

    /// Enable or disable signature enforcement. When `false`, only programs
    /// signed by a trusted key load.
    pub fn set_allow_unsigned(&mut self, allow: bool) {
        self.allow_unsigned = allow;
    }

    fn register_reserved_map(&mut self, map: Box<dyn BpfMap<ActiveProfile>>, perm: MapPerm) -> u32 {
        let slot = self.maps.len();
        self.maps.push(Some(MapEntry {
            map,
            perm,
            charged_bytes: 0,
            owner: 0,
        }));
        self.map_generations.push(0);
        encode_handle(slot, 0)
    }

    fn register_user_map(
        &mut self,
        map: Box<dyn BpfMap<ActiveProfile>>,
        charge: usize,
        owner: u64,
    ) -> Result<u32, BpfError> {
        let id = insert_handle_slot(
            &mut self.maps,
            &mut self.map_generations,
            self.limits.max_map_slots,
            MapEntry {
                map,
                perm: MapPerm::ReadWrite,
                charged_bytes: charge,
                owner,
            },
        )?;
        self.live_maps = self
            .live_maps
            .checked_add(1)
            .ok_or(BpfError::ResourceLimit)?;
        self.map_bytes = self
            .map_bytes
            .checked_add(charge)
            .ok_or(BpfError::ResourceLimit)?;
        Ok(id)
    }

    /// Per-map write permissions indexed by map id. This is the single source
    /// used by both load-time verification and runtime mutation guards.
    pub fn map_perms(&self) -> Vec<MapPerm> {
        self.maps
            .iter()
            .map(|entry| {
                entry
                    .as_ref()
                    .map(|entry| entry.perm)
                    .unwrap_or(MapPerm::ReadOnly)
            })
            .collect()
    }

    fn map_metadata_for_owner(&self, owner: u64) -> (Vec<u32>, Vec<MapPerm>, Vec<u32>) {
        let (sizes, perms) = self
            .maps
            .iter()
            .map(|slot| match slot.as_ref() {
                Some(entry) if entry.owner == owner || entry.charged_bytes == 0 => {
                    (entry.map.def().value_size, entry.perm)
                }
                _ => (0, MapPerm::Unavailable),
            })
            .unzip();
        (sizes, perms, self.map_generations.clone())
    }

    fn program_slot(&self, handle: u32) -> Option<usize> {
        let slot = decode_handle(&self.program_generations, handle)?;
        self.programs.get(slot)?.as_ref()?;
        Some(slot)
    }

    fn program_entry(&self, handle: u32) -> Option<&ProgramEntry> {
        self.programs.get(self.program_slot(handle)?)?.as_ref()
    }

    fn map_slot(&self, handle: u32) -> Option<usize> {
        let slot = decode_handle(&self.map_generations, handle)?;
        self.maps.get(slot)?.as_ref()?;
        Some(slot)
    }

    fn map_entry(&self, handle: u32) -> Option<&MapEntry> {
        self.maps.get(self.map_slot(handle)?)?.as_ref()
    }

    pub const fn resource_usage(&self) -> BpfResourceUsage {
        BpfResourceUsage {
            live_programs: self.live_programs,
            program_bytes: self.program_bytes,
            live_maps: self.live_maps,
            map_bytes: self.map_bytes,
            pinned_maps: self.pinned_maps.len(),
        }
    }

    /// Detach and reclaim every object charged to `owner`.
    ///
    /// The caller must hold [`lock_runtime`] so map backing storage cannot be
    /// reclaimed while an interpreter helper is using it. A `false` result
    /// means an already-captured program snapshot is still in flight; the
    /// caller should retry after releasing the runtime lock.
    pub(crate) fn reclaim_owner(&mut self, owner: u64) -> bool {
        let had_owned_objects = self
            .programs
            .iter()
            .filter_map(Option::as_ref)
            .any(|entry| entry.owner == owner)
            || self
                .maps
                .iter()
                .filter_map(Option::as_ref)
                .any(|entry| entry.owner == owner && entry.charged_bytes != 0);
        let programs = &self.programs;
        let program_generations = &self.program_generations;
        let (attachments, admission) = (&mut self.attachments, &mut self.admission);
        for (&attach_type, attached) in attachments.iter_mut() {
            let mut index = 0;
            while index < attached.len() {
                let prog_id = attached[index];
                let owned = decode_handle(program_generations, prog_id)
                    .and_then(|slot| programs.get(slot))
                    .and_then(Option::as_ref)
                    .is_some_and(|entry| entry.owner == owner);
                if owned {
                    attached.remove(index);
                    admission.release(attach_type, prog_id);
                } else {
                    index += 1;
                }
            }
        }
        attachments.retain(|_, attached| !attached.is_empty());

        for (slot, entry) in self.programs.iter().enumerate() {
            if entry.as_ref().is_some_and(|entry| entry.owner == owner) {
                self.gpio_routes
                    .remove(encode_handle(slot, self.program_generations[slot]));
            }
        }

        let maps = &self.maps;
        let map_generations = &self.map_generations;
        self.pinned_maps.retain(|(_, map_id)| {
            !decode_handle(map_generations, *map_id)
                .and_then(|slot| maps.get(slot))
                .and_then(Option::as_ref)
                .is_some_and(|entry| entry.owner == owner)
        });

        for slot in &mut self.programs {
            let Some(entry) = slot.as_ref() else {
                continue;
            };
            if entry.owner != owner || Arc::strong_count(&entry.program) != 1 {
                continue;
            }
            let entry = slot.take().expect("owned program entry was present");
            self.live_programs = self.live_programs.saturating_sub(1);
            self.program_bytes = self.program_bytes.saturating_sub(entry.charged_bytes);
        }

        if self
            .programs
            .iter()
            .filter_map(Option::as_ref)
            .any(|entry| entry.owner == owner)
        {
            return false;
        }

        for slot in &mut self.maps {
            let Some(entry) = slot.as_ref() else {
                continue;
            };
            if entry.owner != owner || entry.charged_bytes == 0 {
                continue;
            }
            let entry = slot.take().expect("owned map entry was present");
            self.live_maps = self.live_maps.saturating_sub(1);
            self.map_bytes = self.map_bytes.saturating_sub(entry.charged_bytes);
        }
        if had_owned_objects {
            log::info!("BPF_OWNER_RECLAIM_OK owner={owner}");
        }
        true
    }

    fn ensure_program_quota(&self, owner: u64, charge: usize) -> Result<(), BpfError> {
        let has_slot = self.programs.len() < self.limits.max_program_slots
            || self.programs.iter().enumerate().any(|(slot, entry)| {
                entry.is_none() && self.program_generations[slot] < BPF_HANDLE_MAX_GENERATION
            });
        if self.live_programs >= self.limits.max_live_programs
            || !has_slot
            || charge > self.limits.max_single_program_bytes
        {
            return Err(BpfError::ResourceLimit);
        }
        let total = self
            .program_bytes
            .checked_add(charge)
            .ok_or(BpfError::ResourceLimit)?;
        if total > self.limits.max_program_bytes {
            return Err(BpfError::ResourceLimit);
        }
        let (owner_objects, owner_bytes) = self
            .programs
            .iter()
            .filter_map(Option::as_ref)
            .filter(|entry| entry.owner == owner)
            .try_fold((0usize, 0usize), |(objects, bytes), entry| {
                Some((
                    objects.checked_add(1)?,
                    bytes.checked_add(entry.charged_bytes)?,
                ))
            })
            .ok_or(BpfError::ResourceLimit)?;
        if owner_objects >= self.limits.max_owner_programs
            || owner_bytes
                .checked_add(charge)
                .ok_or(BpfError::ResourceLimit)?
                > self.limits.max_owner_program_bytes
        {
            return Err(BpfError::ResourceLimit);
        }
        Ok(())
    }

    fn register_program(
        &mut self,
        program: BpfProgram<ActiveProfile>,
        wcet_cycles: u64,
        charge: usize,
        owner: u64,
    ) -> Result<u32, BpfError> {
        self.ensure_program_quota(owner, charge)?;
        let id = insert_handle_slot(
            &mut self.programs,
            &mut self.program_generations,
            self.limits.max_program_slots,
            ProgramEntry {
                program: Arc::new(program),
                wcet_cycles,
                charged_bytes: charge,
                owner,
            },
        )?;
        self.live_programs = self
            .live_programs
            .checked_add(1)
            .ok_or(BpfError::ResourceLimit)?;
        self.program_bytes = self
            .program_bytes
            .checked_add(charge)
            .ok_or(BpfError::ResourceLimit)?;
        Ok(id)
    }

    /// Build the verifier config for a load from the caller's map view.
    fn verify_config<'a>(
        &self,
        sizes: &'a [u32],
        perms: &'a [MapPerm],
        generations: &'a [u32],
    ) -> VerifyConfig<'a> {
        self.verify_config_with_ctx_data(sizes, perms, generations, VERIFY_CTX_DATA_SIZE_MAX)
    }

    fn verify_config_with_ctx_data<'a>(
        &self,
        sizes: &'a [u32],
        perms: &'a [MapPerm],
        generations: &'a [u32],
        ctx_data_size: u32,
    ) -> VerifyConfig<'a> {
        VerifyConfig {
            ctx_size: VERIFY_CTX_SIZE,
            ctx_data_size,
            map_value_size: VERIFY_MAP_VALUE_SIZE,
            map_value_sizes: sizes,
            map_perms: perms,
            map_generations: generations,
            map_handle_slot_bits: BPF_HANDLE_SLOT_BITS as u8,
            // No process-credential system yet: every load comes from the
            // privileged init context. TODO: derive Trusted from signature
            // authentication (#20) and Unprivileged from caller UID (#67).
            caller: LoadCaller::Privileged,
        }
    }

    pub fn load_program(&mut self, elf_bytes: &[u8]) -> Result<u32, BpfError> {
        self.load_program_for(0, elf_bytes)
    }

    pub fn load_program_for(&mut self, owner: u64, elf_bytes: &[u8]) -> Result<u32, BpfError> {
        if elf_bytes.len() > self.limits.max_elf_bytes {
            return Err(BpfError::ResourceLimit);
        }
        // Fail before parsing when the object table is already exhausted.
        self.ensure_program_quota(owner, 0)?;

        // Authenticate provenance before parsing (#20): a signed RBPF container
        // is verified against the trust store and unwrapped to its inner ELF; a
        // plain ELF is accepted only when unsigned loads are permitted.
        let elf_bytes = self
            .signature_verifier
            .authenticate(elf_bytes, self.allow_unsigned)
            .map_err(|e| {
                log::error!("BpfManager: ELF program failed authentication: {}", e);
                BpfError::SignatureRejected
            })?;

        let mut loader = BpfLoader::<ActiveProfile>::new();
        let obj = loader.load(elf_bytes).map_err(|_| BpfError::NotLoaded)?;

        if let Some(loaded_prog) = obj.programs().first() {
            let charge = loaded_prog
                .insns()
                .len()
                .checked_mul(core::mem::size_of::<BpfInsn>())
                .ok_or(BpfError::ResourceLimit)?;
            self.ensure_program_quota(owner, charge)?;

            // Verify before accepting: rejects unsafe bytecode and computes the
            // real stack usage (no longer the hardcoded 0). #48.
            let (map_value_sizes, map_perms, map_generations) = self.map_metadata_for_owner(owner);
            #[cfg(feature = "verifier-cost")]
            let insn_count = loaded_prog.insns().len();
            #[cfg(feature = "verifier-cost")]
            let start_cycles = read_cycles();
            let (bpf_prog, stats) = Verifier::<ActiveProfile>::verify_with_stats(
                loaded_prog.prog_type(),
                loaded_prog.insns(),
                self.verify_config(&map_value_sizes, &map_perms, &map_generations),
            )
            .map_err(|e| {
                log::error!("BpfManager: ELF program rejected by verifier: {}", e);
                BpfError::VerificationFailed
            })?;
            #[cfg(feature = "verifier-cost")]
            let verify_cycles = read_cycles().wrapping_sub(start_cycles);

            let id = self.register_program(bpf_prog, stats.wcet_cycles, charge, owner)?;
            #[cfg(feature = "verifier-cost")]
            crate::serial_println!(
                "{}",
                kernel_bpf::cost_corpus::CostRecord {
                    prog_id: id,
                    insns: insn_count,
                    states_explored: stats.states_explored,
                    cycles: verify_cycles,
                    wcet_cycles: stats.wcet_cycles,
                }
            );
            Ok(id)
        } else {
            Err(BpfError::NotLoaded)
        }
    }

    pub fn load_raw_program(&mut self, insns: Vec<BpfInsn>) -> Result<u32, BpfError> {
        self.load_raw_program_for(0, insns)
    }

    pub fn load_raw_program_for(
        &mut self,
        owner: u64,
        insns: Vec<BpfInsn>,
    ) -> Result<u32, BpfError> {
        // Raw instruction loads carry no signature container, so they cannot be
        // authenticated (#20). Reject them when enforcement is on.
        if !self.allow_unsigned {
            log::error!("BpfManager: raw program rejected (signature enforcement enabled)");
            return Err(BpfError::SignatureRejected);
        }

        let charge = insns
            .len()
            .checked_mul(core::mem::size_of::<BpfInsn>())
            .ok_or(BpfError::ResourceLimit)?;
        self.ensure_program_quota(owner, charge)?;

        // Verify before accepting: this is the gate that makes the verifier
        // load-bearing — unsafe bytecode is rejected and the real stack usage is
        // computed rather than trusting a hardcoded 0. #48.
        let (map_value_sizes, map_perms, map_generations) = self.map_metadata_for_owner(owner);
        #[cfg(feature = "verifier-cost")]
        let insn_count = insns.len();
        #[cfg(feature = "verifier-cost")]
        let start_cycles = read_cycles();
        let (bpf_prog, stats) = Verifier::<ActiveProfile>::verify_with_stats(
            BpfProgType::Unspec,
            &insns,
            self.verify_config(&map_value_sizes, &map_perms, &map_generations),
        )
        .map_err(|e| {
            log::error!("BpfManager: raw program rejected by verifier: {}", e);
            BpfError::VerificationFailed
        })?;
        #[cfg(feature = "verifier-cost")]
        let verify_cycles = read_cycles().wrapping_sub(start_cycles);

        let id = self.register_program(bpf_prog, stats.wcet_cycles, charge, owner)?;
        #[cfg(feature = "verifier-cost")]
        crate::serial_println!(
            "{}",
            kernel_bpf::cost_corpus::CostRecord {
                prog_id: id,
                insns: insn_count,
                states_explored: stats.states_explored,
                cycles: verify_cycles,
                wcet_cycles: stats.wcet_cycles,
            }
        );
        log::info!(
            "BpfManager: Loaded raw program. Assigned id={}. Total programs={}",
            id,
            self.live_programs
        );
        Ok(id)
    }

    pub fn attach(&mut self, attach_type: u32, prog_id: u32) -> Result<(), BpfError> {
        self.attach_for(0, attach_type, prog_id)
    }

    fn attach_verified_for(
        &mut self,
        owner: u64,
        attach_type: u32,
        prog_id: u32,
    ) -> Result<(), BpfError> {
        if !is_supported_attach_type(attach_type) {
            return Err(BpfError::InvalidInstruction);
        }
        log::info!(
            "BpfManager: Attaching prog_id={} to type={}. Total programs={}",
            prog_id,
            attach_type,
            self.programs.len()
        );
        let Some(program_entry) = self.program_entry(prog_id) else {
            log::error!(
                "BpfManager: Attach failed. prog_id={} is not loaded (slots={})",
                prog_id,
                self.programs.len()
            );
            return Err(BpfError::NotLoaded);
        };

        let (map_value_sizes, map_perms, map_generations) = self.map_metadata_for_owner(owner);
        let ctx_data_size = attach_ctx_data_size(attach_type);
        let program = &program_entry.program;
        Verifier::<ActiveProfile>::verify_with_stats(
            program.prog_type(),
            program.instructions(),
            self.verify_config_with_ctx_data(
                &map_value_sizes,
                &map_perms,
                &map_generations,
                ctx_data_size,
            ),
        )
        .map_err(|e| {
            log::error!(
                "BpfManager: attach rejected by verifier for type={} ctx_data_size={}: {}",
                attach_type,
                ctx_data_size,
                e
            );
            BpfError::VerificationFailed
        })?;

        // Utilization admission (#43): attaching commits the CPU to running
        // this program on every fire; refuse if `Σ WCETᵢ·freqᵢ` across all
        // admitted hooks would exceed the profile's utilization budget.
        // Safe-but-unschedulable is rejected.
        let already_attached = self
            .attachments
            .get(&attach_type)
            .is_some_and(|list| list.contains(&prog_id));
        if !already_attached {
            if self
                .attachments
                .get(&attach_type)
                .is_some_and(|programs| programs.len() >= HOOK_FANOUT_LIMIT)
            {
                return Err(BpfError::ResourceLimit);
            }
            let wcet = program_entry.wcet_cycles;
            let freq = hook_frequency_hz(attach_type);
            if let Err(e) = self.admission.admit(attach_type, prog_id, wcet, freq) {
                log::error!("BpfManager: {}", e);
                return Err(BpfError::AdmissionRejected);
            }
            let programs = self.attachments.entry(attach_type).or_default();
            if programs.try_reserve(1).is_err() {
                self.admission.release(attach_type, prog_id);
                return Err(BpfError::OutOfMemory);
            }
            programs.push(prog_id);
        }
        Ok(())
    }

    pub fn attach_for(
        &mut self,
        owner: u64,
        attach_type: u32,
        prog_id: u32,
    ) -> Result<(), BpfError> {
        self.ensure_program_owner(owner, prog_id)?;
        self.attach_verified_for(owner, attach_type, prog_id)
    }

    pub fn detach(&mut self, attach_type: u32, prog_id: u32) -> Result<(), BpfError> {
        if let Some(list) = self.attachments.get_mut(&attach_type) {
            if let Some(pos) = list.iter().position(|&id| id == prog_id) {
                list.remove(pos);
                // Return this attachment's utilization to the budget.
                self.admission.release(attach_type, prog_id);
                self.gpio_routes.remove(prog_id);
                return Ok(());
            }
        }
        Err(BpfError::NotLoaded)
    }

    pub fn detach_for(
        &mut self,
        owner: u64,
        attach_type: u32,
        prog_id: u32,
    ) -> Result<(), BpfError> {
        self.ensure_program_owner(owner, prog_id)?;
        self.detach(attach_type, prog_id)
    }

    fn ensure_program_owner(&self, owner: u64, prog_id: u32) -> Result<(), BpfError> {
        let entry = self.program_entry(prog_id).ok_or(BpfError::NotLoaded)?;
        if entry.owner == owner {
            Ok(())
        } else {
            Err(BpfError::PermissionDenied)
        }
    }

    /// Remove an unattached program and reclaim its verified bytecode.
    ///
    /// The operation is synchronous: if a hook snapshot still owns an `Arc`,
    /// it returns `ObjectBusy` instead of releasing the quota before the bytes
    /// have actually been freed. Reused slots increment their generation, so
    /// an old handle can never silently name the replacement program.
    pub fn unload_program(&mut self, prog_id: u32) -> Result<(), BpfError> {
        self.unload_program_for(0, prog_id)
    }

    pub fn unload_program_for(&mut self, owner: u64, prog_id: u32) -> Result<(), BpfError> {
        self.ensure_program_owner(owner, prog_id)?;
        if self
            .attachments
            .values()
            .any(|programs| programs.contains(&prog_id))
        {
            return Err(BpfError::ObjectBusy);
        }

        let slot = self.program_slot(prog_id).ok_or(BpfError::NotLoaded)?;
        let entry = self
            .programs
            .get_mut(slot)
            .and_then(Option::as_mut)
            .ok_or(BpfError::NotLoaded)?;
        if Arc::strong_count(&entry.program) != 1 {
            return Err(BpfError::ObjectBusy);
        }

        let charge = entry.charged_bytes;
        self.programs[slot] = None;
        self.live_programs = self.live_programs.saturating_sub(1);
        self.program_bytes = self.program_bytes.saturating_sub(charge);
        self.gpio_routes.remove(prog_id);
        Ok(())
    }

    pub fn execute(&self, program_id: u32, ctx: &BpfContext<'_>) -> Result<u64, BpfError> {
        let program = self.program_entry(program_id).ok_or(BpfError::NotLoaded)?;

        Self::execute_program(&program.program, ctx)
    }

    /// Execute a BPF program directly (without needing &self).
    ///
    /// This is useful when the caller has already cloned the program
    /// and released the BpfManager lock, allowing BPF helpers to
    /// re-acquire the lock for map operations.
    pub fn execute_program(
        program: &BpfProgram<ActiveProfile>,
        ctx: &BpfContext<'_>,
    ) -> Result<u64, BpfError> {
        let _runtime = lock_runtime();
        let cpu = crate::mcore::context::ExecutionContext::try_load()
            .ok_or(BpfError::ReentrantExecution)?;
        cpu.with_bpf_stack(|stack| {
            let interpreter = Interpreter::<ActiveProfile>::new();
            interpreter.execute_with_stack(program, ctx, stack)
        })
        .ok_or(BpfError::ReentrantExecution)?
    }

    /// Clone a loaded program by id (verifier-cost instrumentation only).
    ///
    /// The bench path clones and then executes *outside* the manager lock,
    /// same as `run_hook_programs` — helpers like `bpf_map_lookup_elem`
    /// re-acquire the lock and would deadlock if it were held during runs.
    #[cfg(feature = "verifier-cost")]
    pub fn get_program(&self, prog_id: u32) -> Option<Arc<BpfProgram<ActiveProfile>>> {
        self.program_entry(prog_id)
            .map(|entry| entry.program.clone())
    }

    #[cfg(feature = "verifier-cost")]
    pub fn get_program_for(
        &self,
        owner: u64,
        prog_id: u32,
    ) -> Result<Arc<BpfProgram<ActiveProfile>>, BpfError> {
        self.ensure_program_owner(owner, prog_id)?;
        self.get_program(prog_id).ok_or(BpfError::NotLoaded)
    }

    /// Execute `program` `runs` times back-to-back against an empty context
    /// and emit an `AXIOM EXEC COST` marker with the total CNTVCT_EL0 delta.
    /// Timing wraps the production execution path (`execute_program`: JIT on
    /// AArch64, interpreter elsewhere), so the measurement calibrates the cost
    /// of what actually runs on the device. Must be called without the
    /// manager lock held (see `get_program`).
    #[cfg(feature = "verifier-cost")]
    pub fn bench_execute(
        program: &BpfProgram<ActiveProfile>,
        prog_id: u32,
        runs: u32,
    ) -> Result<(), BpfError> {
        let ctx = BpfContext::empty();
        let start = read_cycles();
        for _ in 0..runs {
            Self::execute_program(program, &ctx)?;
        }
        let cycles = read_cycles().wrapping_sub(start);
        crate::serial_println!(
            "{}",
            kernel_bpf::cost_corpus::ExecRecord {
                prog_id,
                insns: program.instructions().len(),
                runs,
                cycles,
            }
        );
        Ok(())
    }

    /// Resolve one hook into caller-owned slots without touching the heap.
    pub fn hook_programs_into(&self, attach_type: u32, out: &mut [HookProgramSlot]) -> usize {
        let mut count = 0;
        if let Some(progs) = self.attachments.get(&attach_type) {
            for &prog_id in progs {
                if count >= out.len() {
                    break;
                }
                if let Some(program) = self.program_entry(prog_id) {
                    out[count] = Some((prog_id, program.program.clone()));
                    count += 1;
                }
            }
        }
        count
    }

    /// Return true if a GPIO route can be admitted without overflowing the
    /// fixed IRQ fan-out buffer.
    pub fn can_register_gpio_route(&self, chip: u8, pin: u8, edge: GpioEdge, prog_id: u32) -> bool {
        self.gpio_routes
            .can_insert_with_limit(chip, pin, edge, prog_id, GPIO_IRQ_FANOUT_LIMIT)
    }

    /// Attach a program to the GPIO hook and record its route atomically with
    /// respect to the manager lock.
    pub fn attach_gpio_route(
        &mut self,
        chip: u8,
        pin: u8,
        edge: GpioEdge,
        prog_id: u32,
    ) -> Result<(), BpfError> {
        self.attach_gpio_route_for(0, chip, pin, edge, prog_id)
    }

    pub fn attach_gpio_route_for(
        &mut self,
        owner: u64,
        chip: u8,
        pin: u8,
        edge: GpioEdge,
        prog_id: u32,
    ) -> Result<(), BpfError> {
        if !self.can_register_gpio_route(chip, pin, edge, prog_id) {
            log::error!(
                "BpfManager: GPIO route fan-out exceeded for chip={} pin={} edge={:?}",
                chip,
                pin,
                edge
            );
            return Err(BpfError::GpioFanoutExceeded);
        }

        self.attach_for(owner, ATTACH_TYPE_GPIO, prog_id)?;
        self.register_gpio_route(chip, pin, edge, prog_id)
    }

    /// Record a GPIO attachment route. Called from `BPF_PROG_ATTACH` after the
    /// pin IRQ is armed.
    pub fn register_gpio_route(
        &mut self,
        chip: u8,
        pin: u8,
        edge: GpioEdge,
        prog_id: u32,
    ) -> Result<(), BpfError> {
        if !self.can_register_gpio_route(chip, pin, edge, prog_id) {
            log::error!(
                "BpfManager: GPIO route fan-out exceeded for chip={} pin={} edge={:?}",
                chip,
                pin,
                edge
            );
            return Err(BpfError::GpioFanoutExceeded);
        }
        self.gpio_routes.insert(chip, pin, edge, prog_id);
        Ok(())
    }

    /// Resolve the programs attached to a fired GPIO `(chip, pin, edge)` into a
    /// caller-provided stack buffer, returning how many slots were filled.
    ///
    /// Zero heap allocation: the GPIO IRQ handler calls this per edge at up to
    /// ~200k/s (#65), and the global allocator is a spin-locked free list
    /// (`mem/heap.rs`), so a Vec here would serialize every edge on the heap
    /// lock and drop edges. Each entry is an `Arc` refcount clone (no bytecode
    /// copy). GPIO route admission keeps the configured IRQ fan-out within the
    /// Pi 5 handler's stack buffer; callers that pass a smaller scratch buffer
    /// still get a bounded prefix. Caller clones + drops the lock before
    /// executing so helpers can re-acquire the manager lock without deadlocking.
    pub fn gpio_programs_into(
        &self,
        chip: u8,
        pin: u8,
        fired: GpioEdge,
        out: &mut [GpioProgramSlot],
    ) -> usize {
        let mut n = 0;
        self.gpio_routes
            .for_each_program(chip, pin, fired, |prog_id| {
                if n >= out.len() {
                    return;
                }
                if let Some(program) = self.program_entry(prog_id) {
                    out[n] = Some((prog_id, program.program.clone()));
                    n += 1;
                }
            });
        n
    }

    pub fn run_hook_programs(
        attach_type: u32,
        ctx: &BpfContext<'_>,
        hook_name: &str,
    ) -> Result<usize, BpfError> {
        let Some(manager) = crate::BPF_MANAGER.get() else {
            return Ok(0);
        };

        let mut programs: [HookProgramSlot; HOOK_FANOUT_LIMIT] = core::array::from_fn(|_| None);
        let count = manager
            .lock()
            .hook_programs_into(attach_type, &mut programs);
        for slot in programs.iter_mut().take(count) {
            let (prog_id, program) = slot.take().expect("resolved hook slot must be populated");
            match Self::execute_program(&program, ctx) {
                Ok(res) => {
                    if res != 0 {
                        log::trace!("{hook_name} BPF Hook [id={prog_id}] returned: {res}");
                    }
                }
                Err(e) => {
                    log::error!("{hook_name} BPF Hook [id={prog_id}] failed: {:?}", e);
                    return Err(e);
                }
            }
        }

        Ok(count)
    }

    // --- Map operations ---

    fn map_allocation_charge(
        &self,
        owner: u64,
        map_type: u32,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
    ) -> Result<usize, BpfError> {
        if max_entries == 0
            || key_size > self.limits.max_key_size
            || value_size > self.limits.max_value_size
            || max_entries > self.limits.max_entries
        {
            return Err(BpfError::ResourceLimit);
        }

        let charge = match map_type {
            1 if key_size != 0 && value_size != 0 => {
                BpfHashMap::<ActiveProfile>::allocation_size(key_size, value_size, max_entries)
            }
            2 if key_size == 4 && value_size != 0 => {
                ArrayMap::<ActiveProfile>::allocation_size(value_size, max_entries)
            }
            27 if key_size == 0 && value_size == 0 && max_entries.is_power_of_two() => {
                Some(max_entries as usize)
            }
            100 if key_size == 8 && value_size != 0 => {
                TimeSeriesMap::<ActiveProfile>::allocation_size(value_size, max_entries)
            }
            1 | 2 | 27 | 100 => return Err(BpfError::InvalidInstruction),
            _ => return Err(BpfError::InvalidInstruction),
        }
        .ok_or(BpfError::ResourceLimit)?;

        let has_slot = self.maps.len() < self.limits.max_map_slots
            || self.maps.iter().enumerate().any(|(slot, entry)| {
                entry.is_none() && self.map_generations[slot] < BPF_HANDLE_MAX_GENERATION
            });
        if self.live_maps >= self.limits.max_live_maps
            || !has_slot
            || charge > self.limits.max_single_map_bytes
        {
            return Err(BpfError::ResourceLimit);
        }
        let total = self
            .map_bytes
            .checked_add(charge)
            .ok_or(BpfError::ResourceLimit)?;
        if total > self.limits.max_map_bytes {
            return Err(BpfError::ResourceLimit);
        }
        let (owner_objects, owner_bytes) = self
            .maps
            .iter()
            .filter_map(Option::as_ref)
            .filter(|entry| entry.owner == owner && entry.charged_bytes != 0)
            .try_fold((0usize, 0usize), |(objects, bytes), entry| {
                Some((
                    objects.checked_add(1)?,
                    bytes.checked_add(entry.charged_bytes)?,
                ))
            })
            .ok_or(BpfError::ResourceLimit)?;
        if owner_objects >= self.limits.max_owner_maps
            || owner_bytes
                .checked_add(charge)
                .ok_or(BpfError::ResourceLimit)?
                > self.limits.max_owner_map_bytes
        {
            return Err(BpfError::ResourceLimit);
        }
        Ok(charge)
    }

    pub fn create_map(
        &mut self,
        map_type: u32,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
    ) -> Result<u32, BpfError> {
        self.create_map_for(0, map_type, key_size, value_size, max_entries)
    }

    pub fn create_map_for(
        &mut self,
        owner: u64,
        map_type: u32,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
    ) -> Result<u32, BpfError> {
        let charge =
            self.map_allocation_charge(owner, map_type, key_size, value_size, max_entries)?;
        let map: Box<dyn BpfMap<ActiveProfile>> = match map_type {
            1 => {
                // Hash map
                Box::new(
                    BpfHashMap::<ActiveProfile>::with_sizes(key_size, value_size, max_entries)
                        .map_err(|_| BpfError::OutOfMemory)?,
                )
            }
            2 => {
                // Array map
                Box::new(
                    ArrayMap::<ActiveProfile>::with_entries(value_size, max_entries)
                        .map_err(|_| BpfError::OutOfMemory)?,
                )
            }
            27 => {
                // Ring buffer map - max_entries is the buffer size (must be power of 2)
                Box::new(
                    RingBufMap::<ActiveProfile>::new(max_entries as usize)
                        .map_err(|_| BpfError::OutOfMemory)?,
                )
            }
            100 => {
                // Time-series map
                Box::new(
                    TimeSeriesMap::<ActiveProfile>::new(value_size, max_entries)
                        .map_err(|_| BpfError::OutOfMemory)?,
                )
            }
            _ => {
                log::warn!("Unsupported map type: {}", map_type);
                return Err(BpfError::InvalidInstruction);
            }
        };

        let id = self.register_user_map(map, charge, owner)?;
        log::info!(
            "Created map id={} type={} key_size={} value_size={} max_entries={}",
            id,
            map_type,
            key_size,
            value_size,
            max_entries
        );
        Ok(id)
    }

    pub fn map_lookup(&self, map_id: u32, key: &[u8]) -> Option<Vec<u8>> {
        self.map_entry(map_id)?.map.lookup(key)
    }

    pub fn map_lookup_for(
        &self,
        owner: u64,
        map_id: u32,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, BpfError> {
        self.ensure_map_owner(owner, map_id)?;
        Ok(self.map_lookup(map_id, key))
    }

    /// Look up a value by key and return a raw pointer.
    ///
    /// # Safety
    /// The caller must ensure the map will not be resized or deleted while the
    /// pointer is in use. The returned pointer is only valid while the map lock
    /// is held by the caller.
    pub unsafe fn map_lookup_ptr(&self, map_id: u32, key: &[u8]) -> Option<*mut u8> {
        // SAFETY: caller ensures map will not be resized or deleted while pointer is in use
        unsafe { self.map_entry(map_id)?.map.lookup_ptr(key) }
    }

    fn ensure_map_writable(&self, map_id: u32) -> Result<(), BpfError> {
        match self.map_entry(map_id).ok_or(BpfError::NotLoaded)?.perm {
            MapPerm::Unavailable => Err(BpfError::PermissionDenied),
            MapPerm::ReadWrite => Ok(()),
            MapPerm::ReadOnly => Err(BpfError::ReadOnlyMap),
        }
    }

    fn ensure_map_owner(&self, owner: u64, map_id: u32) -> Result<(), BpfError> {
        let entry = self.map_entry(map_id).ok_or(BpfError::NotLoaded)?;
        if entry.owner == owner {
            Ok(())
        } else {
            Err(BpfError::PermissionDenied)
        }
    }

    pub fn map_update(
        &self,
        map_id: u32,
        key: &[u8],
        value: &[u8],
        flags: u64,
    ) -> Result<(), BpfError> {
        self.ensure_map_writable(map_id)?;
        let map = self.map_entry(map_id).ok_or(BpfError::NotLoaded)?;
        map.map
            .update(key, value, flags)
            .map_err(|_| BpfError::OutOfMemory)
    }

    pub fn map_update_for(
        &self,
        owner: u64,
        map_id: u32,
        key: &[u8],
        value: &[u8],
        flags: u64,
    ) -> Result<(), BpfError> {
        self.ensure_map_owner(owner, map_id)?;
        self.map_update(map_id, key, value, flags)
    }

    pub fn map_delete(&self, map_id: u32, key: &[u8]) -> Result<(), BpfError> {
        self.ensure_map_writable(map_id)?;
        let map = self.map_entry(map_id).ok_or(BpfError::NotLoaded)?;
        map.map.delete(key).map_err(|_| BpfError::NotLoaded)
    }

    pub fn map_delete_for(&self, owner: u64, map_id: u32, key: &[u8]) -> Result<(), BpfError> {
        self.ensure_map_owner(owner, map_id)?;
        self.map_delete(map_id, key)
    }

    pub fn get_map_def(&self, map_id: u32) -> Option<&kernel_bpf::maps::MapDef> {
        self.map_entry(map_id).map(|entry| entry.map.def())
    }

    pub fn get_map_def_for(
        &self,
        owner: u64,
        map_id: u32,
    ) -> Result<&kernel_bpf::maps::MapDef, BpfError> {
        self.ensure_map_owner(owner, map_id)?;
        self.get_map_def(map_id).ok_or(BpfError::NotLoaded)
    }

    pub fn pin_map(&mut self, path: String, map_id: u32) -> Result<(), BpfError> {
        if path.is_empty() || path.len() >= BPF_PIN_PATH_MAX {
            return Err(BpfError::ResourceLimit);
        }
        if self.map_entry(map_id).is_none() {
            return Err(BpfError::NotLoaded);
        }

        if let Some((_, existing_id)) = self
            .pinned_maps
            .iter()
            .find(|(existing_path, _)| existing_path == &path)
        {
            return if *existing_id == map_id {
                Ok(())
            } else {
                Err(BpfError::ObjectBusy)
            };
        }
        if self.pinned_maps.len() >= self.limits.max_pinned_maps {
            return Err(BpfError::ResourceLimit);
        }
        self.pinned_maps
            .try_reserve(1)
            .map_err(|_| BpfError::OutOfMemory)?;
        self.pinned_maps.push((path, map_id));
        Ok(())
    }

    pub fn pin_map_for(&mut self, owner: u64, path: String, map_id: u32) -> Result<(), BpfError> {
        self.ensure_map_owner(owner, map_id)?;
        self.pin_map(path, map_id)
    }

    pub fn get_pinned_map(&self, path: &str) -> Option<u32> {
        self.pinned_maps
            .iter()
            .find(|(pinned_path, _)| pinned_path == path)
            .map(|(_, map_id)| *map_id)
    }

    pub fn get_pinned_map_for(&self, owner: u64, path: &str) -> Result<u32, BpfError> {
        let map_id = self.get_pinned_map(path).ok_or(BpfError::NotLoaded)?;
        self.ensure_map_owner(owner, map_id)?;
        Ok(map_id)
    }

    pub fn unpin_map(&mut self, path: &str) -> Result<(), BpfError> {
        let index = self
            .pinned_maps
            .iter()
            .position(|(pinned_path, _)| pinned_path == path)
            .ok_or(BpfError::NotLoaded)?;
        self.pinned_maps.remove(index);
        Ok(())
    }

    pub fn unpin_map_for(&mut self, owner: u64, path: &str) -> Result<(), BpfError> {
        let map_id = self.get_pinned_map(path).ok_or(BpfError::NotLoaded)?;
        self.ensure_map_owner(owner, map_id)?;
        self.unpin_map(path)
    }

    /// Destroy an unpinned user map and reclaim its backing allocation.
    ///
    /// Until verified programs record their referenced map IDs, destruction is
    /// conservatively refused while any program is loaded. This prevents a map
    /// from disappearing under a helper's escaped raw value pointer.
    pub fn destroy_map(&mut self, map_id: u32) -> Result<(), BpfError> {
        self.destroy_map_for(0, map_id)
    }

    pub fn destroy_map_for(&mut self, owner: u64, map_id: u32) -> Result<(), BpfError> {
        let slot = self.map_slot(map_id).ok_or(BpfError::NotLoaded)?;
        if slot < RESERVED_MAP_COUNT as usize {
            return Err(BpfError::ReadOnlyMap);
        }
        self.ensure_map_owner(owner, map_id)?;
        if self
            .pinned_maps
            .iter()
            .any(|(_, pinned_map_id)| *pinned_map_id == map_id)
            || self.live_programs != 0
        {
            return Err(BpfError::ObjectBusy);
        }

        let entry = self.maps[slot]
            .take()
            .expect("map ownership was checked above");
        self.live_maps = self.live_maps.saturating_sub(1);
        self.map_bytes = self.map_bytes.saturating_sub(entry.charged_bytes);
        drop(entry);
        Ok(())
    }

    pub fn get_map_info(&self, map_id: u32) -> Option<BpfObjectInfo> {
        let def = self.get_map_def(map_id)?;
        Some(BpfObjectInfo {
            id: map_id,
            object_kind: BPF_OBJECT_KIND_MAP,
            map_type: def.map_type as u32,
            key_size: def.key_size,
            value_size: def.value_size,
            max_entries: def.max_entries,
        })
    }

    pub fn get_map_info_for(&self, owner: u64, map_id: u32) -> Result<BpfObjectInfo, BpfError> {
        self.ensure_map_owner(owner, map_id)?;
        self.get_map_info(map_id).ok_or(BpfError::NotLoaded)
    }

    /// Poll for the next event from a ring buffer map.
    ///
    /// Returns the event data if available, or None if the ringbuf is empty.
    /// This is used by the BPF_RINGBUF_POLL syscall command.
    pub fn ringbuf_poll(&self, map_id: u32) -> Option<Vec<u8>> {
        let map = self.map_entry(map_id)?;
        // RingBufMap::lookup() delegates to poll(), which reads and advances the tail
        map.map.lookup(&[])
    }

    pub fn ringbuf_poll_for(&self, owner: u64, map_id: u32) -> Result<Option<Vec<u8>>, BpfError> {
        self.ensure_map_owner(owner, map_id)?;
        Ok(self.ringbuf_poll(map_id))
    }

    /// Output data to a ring buffer map.
    ///
    /// This is used by the bpf_ringbuf_output helper. For ringbuf maps,
    /// the key is ignored and value is the event data.
    pub fn ringbuf_output(&self, map_id: u32, data: &[u8], flags: u64) -> Result<(), BpfError> {
        self.ensure_map_writable(map_id)?;
        let map = self.map_entry(map_id).ok_or(BpfError::NotLoaded)?;

        // Ring buffer maps use update() with empty key to output data
        map.map
            .update(&[], data, flags)
            .map_err(|_| BpfError::OutOfMemory)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use kernel_bpf::bytecode::insn::BpfInsn;
    use kernel_bpf::maps::MapType;
    use kernel_bpf::verifier::{HelperId, MapPerm};

    use super::*;

    fn tiny_limits() -> BpfLimits {
        let mut limits = BpfLimits::for_active_profile();
        limits.max_live_programs = 2;
        limits.max_program_slots = 4;
        limits.max_program_bytes = 32;
        limits.max_single_program_bytes = 16;
        limits.max_owner_programs = 1;
        limits.max_owner_program_bytes = 16;
        limits.max_live_maps = 2;
        limits.max_map_slots = 4;
        limits.max_map_bytes = 64;
        limits.max_single_map_bytes = 32;
        limits.max_owner_maps = 1;
        limits.max_owner_map_bytes = 32;
        limits.max_pinned_maps = 1;
        limits
    }

    #[test]
    fn reserves_envelope_map_id_before_user_maps() {
        let mut manager = BpfManager::new();

        assert_eq!(ENVELOPE_MAP_ID, 0);
        assert_eq!(
            manager.map_perms()[ENVELOPE_MAP_ID as usize],
            MapPerm::ReadOnly
        );
        assert!(manager.get_map_def(ENVELOPE_MAP_ID).is_some());

        let user_map = manager
            .create_map(MapType::Array as u32, 4, 8, 1)
            .expect("create user map");

        assert_eq!(user_map, RESERVED_MAP_COUNT);
        assert_ne!(user_map, ENVELOPE_MAP_ID);
    }

    #[test]
    fn map_value_sizes_and_perms_align_across_full_id_space() {
        let mut manager = BpfManager::new();
        let _ = manager
            .create_map(MapType::Array as u32, 4, 8, 1)
            .expect("create user map");

        let (sizes, perms, generations) = manager.map_metadata_for_owner(0);

        assert_eq!(sizes.len(), perms.len());
        assert_eq!(sizes.len(), generations.len());
        assert_eq!(perms[ENVELOPE_MAP_ID as usize], MapPerm::ReadOnly);
        assert_eq!(perms[RESERVED_MAP_COUNT as usize], MapPerm::ReadWrite);
    }

    #[test]
    fn runtime_guard_rejects_read_only_envelope_writes() {
        let manager = BpfManager::new();
        let key = 0u32.to_ne_bytes();
        let value = [0u8; 16];

        assert_eq!(
            manager.map_update(ENVELOPE_MAP_ID, &key, &value, 0),
            Err(BpfError::ReadOnlyMap)
        );
        assert_eq!(
            manager.map_delete(ENVELOPE_MAP_ID, &key),
            Err(BpfError::ReadOnlyMap)
        );
        assert_eq!(
            manager.ringbuf_output(ENVELOPE_MAP_ID, &value, 0),
            Err(BpfError::ReadOnlyMap)
        );
    }

    #[test]
    fn gpio_route_registration_enforces_irq_fanout_limit() {
        let mut manager = BpfManager::new();
        for prog_id in 0..GPIO_IRQ_FANOUT_LIMIT as u32 {
            manager
                .register_gpio_route(0, 17, GpioEdge::Rising, prog_id)
                .expect("route within fanout limit");
        }

        assert_eq!(
            manager.register_gpio_route(0, 17, GpioEdge::Rising, GPIO_IRQ_FANOUT_LIMIT as u32),
            Err(BpfError::GpioFanoutExceeded)
        );
    }

    #[test]
    fn map_quota_is_charged_and_reclaimed_without_id_reuse() {
        let mut manager = BpfManager::new_with_limits(tiny_limits());
        let first = manager
            .create_map(MapType::Array as u32, 4, 8, 1)
            .expect("first map within quota");
        assert_eq!(
            manager.resource_usage(),
            BpfResourceUsage {
                live_programs: 0,
                program_bytes: 0,
                live_maps: 1,
                map_bytes: 8,
                pinned_maps: 0,
            }
        );
        assert_eq!(
            manager.create_map(MapType::Array as u32, 4, 8, 1),
            Err(BpfError::ResourceLimit)
        );

        manager
            .pin_map("/map".into(), first)
            .expect("pin first map");
        assert_eq!(manager.destroy_map(first), Err(BpfError::ObjectBusy));
        manager.unpin_map("/map").expect("unpin first map");
        manager.destroy_map(first).expect("destroy first map");
        assert_eq!(manager.resource_usage().map_bytes, 0);

        let second = manager
            .create_map(MapType::Array as u32, 4, 8, 1)
            .expect("quota reclaimed");
        assert_eq!(second & BPF_HANDLE_SLOT_MASK, first & BPF_HANDLE_SLOT_MASK);
        assert_ne!(second, first, "reused slot must advance its generation");
        assert!(manager.get_map_def(first).is_none());
        assert!(manager.get_map_def(second).is_some());
    }

    #[test]
    fn map_dimensions_and_accounting_overflow_fail_before_allocation() {
        let mut manager = BpfManager::new_with_limits(tiny_limits());
        assert_eq!(
            manager.create_map(MapType::Hash as u32, u32::MAX, u32::MAX, u32::MAX),
            Err(BpfError::ResourceLimit)
        );
        assert_eq!(manager.resource_usage().map_bytes, 0);
        assert_eq!(manager.resource_usage().live_maps, 0);
    }

    #[test]
    fn map_quota_and_lifecycle_are_scoped_to_owner() {
        let mut manager = BpfManager::new_with_limits(tiny_limits());
        let owner_one = manager
            .create_map_for(1, MapType::Array as u32, 4, 8, 1)
            .expect("first owner map");
        assert_eq!(
            manager.create_map_for(1, MapType::Array as u32, 4, 8, 1),
            Err(BpfError::ResourceLimit)
        );
        let owner_two = manager
            .create_map_for(2, MapType::Array as u32, 4, 8, 1)
            .expect("second owner has an independent quota");

        assert!(matches!(
            manager.get_map_def_for(2, owner_one),
            Err(BpfError::PermissionDenied)
        ));
        assert_eq!(
            manager.map_update_for(2, owner_one, &0u32.to_ne_bytes(), &[0; 8], 0),
            Err(BpfError::PermissionDenied)
        );
        assert_eq!(
            manager.destroy_map_for(2, owner_one),
            Err(BpfError::PermissionDenied)
        );
        manager
            .destroy_map_for(1, owner_one)
            .expect("owner destroys own map");
        manager
            .destroy_map_for(2, owner_two)
            .expect("second owner destroys own map");
    }

    #[test]
    fn program_quota_unload_and_inflight_reclamation_are_synchronous() {
        let mut manager = BpfManager::new_with_limits(tiny_limits());
        let insns = vec![BpfInsn::mov64_imm(0, 0), BpfInsn::exit()];
        let first = manager
            .load_raw_program(insns.clone())
            .expect("first program within quota");
        assert_eq!(manager.resource_usage().program_bytes, 16);
        assert_eq!(
            manager.load_raw_program(insns.clone()),
            Err(BpfError::ResourceLimit)
        );

        let first_slot = manager.program_slot(first).expect("first program slot");
        let in_flight = manager.programs[first_slot]
            .as_ref()
            .expect("loaded entry")
            .program
            .clone();
        assert_eq!(manager.unload_program(first), Err(BpfError::ObjectBusy));
        drop(in_flight);
        manager.unload_program(first).expect("quiescent unload");
        assert_eq!(manager.resource_usage().program_bytes, 0);

        let second = manager
            .load_raw_program(insns)
            .expect("program quota reclaimed");
        assert_eq!(second & BPF_HANDLE_SLOT_MASK, first & BPF_HANDLE_SLOT_MASK);
        assert_ne!(second, first, "reused slot must advance its generation");
        assert_eq!(manager.unload_program(first), Err(BpfError::NotLoaded));
        manager
            .unload_program(second)
            .expect("replacement handle remains valid");
    }

    #[test]
    fn program_quota_and_lifecycle_are_scoped_to_owner() {
        let mut manager = BpfManager::new_with_limits(tiny_limits());
        let insns = vec![BpfInsn::mov64_imm(0, 0), BpfInsn::exit()];
        let owner_one = manager
            .load_raw_program_for(1, insns.clone())
            .expect("first owner program");
        assert_eq!(
            manager.load_raw_program_for(1, insns.clone()),
            Err(BpfError::ResourceLimit)
        );
        let owner_two = manager
            .load_raw_program_for(2, insns)
            .expect("second owner has an independent quota");

        assert_eq!(
            manager.attach_for(2, ATTACH_TYPE_TIMER, owner_one),
            Err(BpfError::PermissionDenied)
        );
        manager
            .attach_gpio_route_for(1, 0, 17, GpioEdge::Rising, owner_one)
            .expect("owner attaches its program to GPIO");
        manager
            .detach_for(1, ATTACH_TYPE_GPIO, owner_one)
            .expect("owner detaches its GPIO program");
        assert_eq!(
            manager.unload_program_for(2, owner_one),
            Err(BpfError::PermissionDenied)
        );
        manager
            .unload_program_for(1, owner_one)
            .expect("owner unloads own program");
        manager
            .unload_program_for(2, owner_two)
            .expect("second owner unloads own program");
    }

    #[test]
    fn program_verification_rejects_foreign_map_ids() {
        let mut manager = BpfManager::new_with_limits(tiny_limits());
        let map_id = manager
            .create_map_for(1, MapType::Array as u32, 4, 8, 1)
            .expect("owner map");
        let lookup_program = || {
            vec![
                BpfInsn::mov64_imm(1, 0),
                BpfInsn::new(0x7b, 10, 1, -8, 0),
                BpfInsn::mov64_imm(1, map_id as i32),
                BpfInsn::mov64_reg(2, 10),
                BpfInsn::add64_imm(2, -8),
                BpfInsn::call(HelperId::MapLookupElem as i32),
                BpfInsn::mov64_imm(0, 0),
                BpfInsn::exit(),
            ]
        };

        assert_eq!(
            manager.load_raw_program_for(2, lookup_program()),
            Err(BpfError::VerificationFailed)
        );
        let program_id = manager
            .load_raw_program_for(1, lookup_program())
            .expect("owner can reference its own map");
        manager
            .unload_program_for(1, program_id)
            .expect("unload owner program");
        manager
            .destroy_map_for(1, map_id)
            .expect("destroy owner map");
    }

    #[test]
    fn owner_reclamation_waits_for_inflight_program_snapshots() {
        let mut manager = BpfManager::new_with_limits(tiny_limits());
        let map_id = manager
            .create_map_for(7, MapType::Array as u32, 4, 8, 1)
            .expect("owner map");
        manager
            .pin_map_for(7, "/owner-map".into(), map_id)
            .expect("pin owner map");
        let program_id = manager
            .load_raw_program_for(7, vec![BpfInsn::mov64_imm(0, 0), BpfInsn::exit()])
            .expect("owner program");
        manager
            .attach_for(7, ATTACH_TYPE_TIMER, program_id)
            .expect("attach owner program");
        let program_slot = manager
            .program_slot(program_id)
            .expect("owner program slot");
        let in_flight = manager.programs[program_slot]
            .as_ref()
            .expect("program entry")
            .program
            .clone();

        assert!(!manager.reclaim_owner(7));
        assert_eq!(manager.resource_usage().live_programs, 1);
        assert_eq!(manager.resource_usage().live_maps, 1);
        assert_eq!(manager.resource_usage().pinned_maps, 0);
        assert!(manager
            .attachments
            .values()
            .all(|programs| !programs.contains(&program_id)));

        drop(in_flight);
        assert!(manager.reclaim_owner(7));
        assert_eq!(
            manager.resource_usage(),
            BpfResourceUsage {
                live_programs: 0,
                program_bytes: 0,
                live_maps: 0,
                map_bytes: 0,
                pinned_maps: 0,
            }
        );
    }

    #[test]
    fn attached_program_must_be_detached_before_unload() {
        let mut manager = BpfManager::new_with_limits(tiny_limits());
        let id = manager
            .load_raw_program(vec![BpfInsn::mov64_imm(0, 0), BpfInsn::exit()])
            .expect("load program");
        manager
            .attach(ATTACH_TYPE_TIMER, id)
            .expect("attach program");
        assert_eq!(manager.unload_program(id), Err(BpfError::ObjectBusy));
        manager
            .detach(ATTACH_TYPE_TIMER, id)
            .expect("detach program");
        manager.unload_program(id).expect("unload program");
    }

    #[test]
    fn generic_hook_fanout_is_bounded_and_snapshot_does_not_truncate() {
        let mut limits = BpfLimits::for_active_profile();
        limits.max_live_programs = HOOK_FANOUT_LIMIT + 1;
        limits.max_program_slots = HOOK_FANOUT_LIMIT + 1;
        limits.max_program_bytes = (HOOK_FANOUT_LIMIT + 1) * 16;
        limits.max_single_program_bytes = 16;
        let mut manager = BpfManager::new_with_limits(limits);
        let insns = vec![BpfInsn::mov64_imm(0, 0), BpfInsn::exit()];
        let mut ids = Vec::new();
        for _ in 0..=HOOK_FANOUT_LIMIT {
            ids.push(
                manager
                    .load_raw_program(insns.clone())
                    .expect("program within test quota"),
            );
        }
        manager
            .attachments
            .insert(ATTACH_TYPE_TIMER, ids[..HOOK_FANOUT_LIMIT].to_vec());

        assert_eq!(
            manager.attach(ATTACH_TYPE_TIMER, ids[HOOK_FANOUT_LIMIT]),
            Err(BpfError::ResourceLimit)
        );

        let mut slots: [HookProgramSlot; HOOK_FANOUT_LIMIT] = core::array::from_fn(|_| None);
        let count = manager.hook_programs_into(ATTACH_TYPE_TIMER, &mut slots);
        assert_eq!(count, HOOK_FANOUT_LIMIT);
        assert!(slots.iter().all(Option::is_some));
    }
}
