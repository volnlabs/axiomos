mod authorization;
mod handles;
pub mod helpers;
mod limits;
mod snapshot;
mod trust;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(test)]
use authorization::MAX_MAP_GRANTS;
use authorization::{append_pinned_map, MapGrants, PinnedMap};
pub use authorization::{BpfLoadAuthorization, MapAccess};
use kernel_abi::{
    BpfObjectInfo, BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_RINGBUF,
    BPF_MAP_TYPE_TIMESERIES, BPF_OBJECT_KIND_MAP,
};
pub use kernel_abi::{
    BPF_ATTACH_TYPE_GPIO as ATTACH_TYPE_GPIO, BPF_ATTACH_TYPE_IIO as ATTACH_TYPE_IIO,
    BPF_ATTACH_TYPE_PWM as ATTACH_TYPE_PWM,
    BPF_ATTACH_TYPE_SCHED_SWITCH as ATTACH_TYPE_SCHED_SWITCH,
    BPF_ATTACH_TYPE_SYSCALL as ATTACH_TYPE_SYSCALL,
    BPF_ATTACH_TYPE_SYS_ENTER as ATTACH_TYPE_SYS_ENTER,
    BPF_ATTACH_TYPE_SYS_EXIT as ATTACH_TYPE_SYS_EXIT, BPF_ATTACH_TYPE_TIMER as ATTACH_TYPE_TIMER,
};
use kernel_bpf::actuation::EnvelopeMap;
use kernel_bpf::attach::{GpioEdge, GpioRouteTable};
use kernel_bpf::bytecode::insn::BpfInsn;
use kernel_bpf::bytecode::program::{BpfProgType, BpfProgram};
use kernel_bpf::execution::{BpfContext, BpfError, Interpreter};
use kernel_bpf::loader::BpfLoader;
use kernel_bpf::maps::{ArrayMap, BpfMap, HashMap as BpfHashMap, RingBufMap, TimeSeriesMap};
use kernel_bpf::profile::{ActiveProfile, PhysicalProfile};
use kernel_bpf::signing::SignatureVerifier;
use kernel_bpf::verifier::admission::AdmissionLedger;
use kernel_bpf::verifier::{MapPerm, Verifier, VerifyConfig};
use limits::BpfLimits;
use snapshot::EpochSnapshot;
use trust::signing_policy;
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

pub const ENVELOPE_MAP_ID: u32 = 0;
pub const RESERVED_MAP_COUNT: u32 = 1;

const PINNED_MAP_OWNER: u64 = u64::MAX;
/// Maximum GPIO programs resolved for one IRQ edge. Must match the stack buffer
/// used by the Pi 5 GPIO IRQ handler.
pub const GPIO_IRQ_FANOUT_LIMIT: usize = 8;
/// Maximum programs on any single hook. Attach enforces this so dispatch never
/// truncates a configured hook when resolving into its stack buffer.
pub const HOOK_FANOUT_LIMIT: usize = 16;
/// Maximum byte length (including the trailing NUL supplied by userspace) for
/// a pinned-object path.
pub const BPF_PIN_PATH_MAX: usize = 256;
const BPF_GPIO_PIN_COUNT: u8 = 28;

const GENERIC_HOOK_SLOTS: usize = ATTACH_TYPE_SCHED_SWITCH as usize + 1;
const GPIO_EDGE_SLOTS: usize = 3;
const GPIO_ROUTE_SLOTS: usize = BPF_GPIO_PIN_COUNT as usize * GPIO_EDGE_SLOTS;

struct HookProgramList<const N: usize> {
    programs: [Option<Arc<ProgramRuntime>>; N],
    len: usize,
}

impl<const N: usize> HookProgramList<N> {
    fn empty() -> Self {
        Self {
            programs: core::array::from_fn(|_| None),
            len: 0,
        }
    }

    fn push(&mut self, runtime: &Arc<ProgramRuntime>) -> Result<(), BpfError> {
        let slot = self
            .programs
            .get_mut(self.len)
            .ok_or(BpfError::ResourceLimit)?;
        *slot = Some(runtime.clone());
        self.len += 1;
        Ok(())
    }

    fn iter(&self) -> impl Iterator<Item = &Arc<ProgramRuntime>> {
        self.programs[..self.len].iter().flatten()
    }
}

struct HookSnapshot {
    generic: [HookProgramList<HOOK_FANOUT_LIMIT>; GENERIC_HOOK_SLOTS],
    gpio: [HookProgramList<GPIO_IRQ_FANOUT_LIMIT>; GPIO_ROUTE_SLOTS],
}

impl HookSnapshot {
    fn empty() -> Self {
        Self {
            generic: core::array::from_fn(|_| HookProgramList::empty()),
            gpio: core::array::from_fn(|_| HookProgramList::empty()),
        }
    }

    fn generic(&self, attach_type: u32) -> Option<&HookProgramList<HOOK_FANOUT_LIMIT>> {
        self.generic.get(attach_type as usize)
    }

    fn generic_mut(&mut self, attach_type: u32) -> Option<&mut HookProgramList<HOOK_FANOUT_LIMIT>> {
        self.generic.get_mut(attach_type as usize)
    }

    fn gpio_index(chip: u8, pin: u8, edge_flags: u32) -> Option<usize> {
        if chip != 0 || pin >= BPF_GPIO_PIN_COUNT || !(1..=3).contains(&edge_flags) {
            return None;
        }
        Some(pin as usize * GPIO_EDGE_SLOTS + edge_flags as usize - 1)
    }

    fn gpio(
        &self,
        chip: u8,
        pin: u8,
        edge_flags: u32,
    ) -> Option<&HookProgramList<GPIO_IRQ_FANOUT_LIMIT>> {
        self.gpio.get(Self::gpio_index(chip, pin, edge_flags)?)
    }

    fn gpio_mut(
        &mut self,
        chip: u8,
        pin: u8,
        edge_flags: u32,
    ) -> Option<&mut HookProgramList<GPIO_IRQ_FANOUT_LIMIT>> {
        self.gpio.get_mut(Self::gpio_index(chip, pin, edge_flags)?)
    }
}

static HOOK_SNAPSHOTS: EpochSnapshot<HookSnapshot> = EpochSnapshot::empty();

#[cfg(not(test))]
struct PreparedHookSnapshot {
    snapshot: Box<HookSnapshot>,
}

struct ProgramEntry {
    program: Arc<ProgramRuntime>,
    wcet_cycles: u64,
    charged_bytes: usize,
    owner: u64,
    authorization: BpfLoadAuthorization,
}

struct MapEntry {
    runtime: Arc<MapRuntime>,
    perm: MapPerm,
    charged_bytes: usize,
    owner: u64,
    grants: MapGrants,
}

struct MapRuntime {
    map: Box<dyn BpfMap<ActiveProfile>>,
    leased: AtomicBool,
}

impl MapRuntime {
    fn new(map: Box<dyn BpfMap<ActiveProfile>>) -> Self {
        Self {
            map,
            leased: AtomicBool::new(false),
        }
    }

    fn try_lease(&self) -> Result<MapLease<'_>, BpfError> {
        self.leased
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| BpfError::ObjectBusy)?;
        Ok(MapLease(self))
    }
}

struct MapLease<'a>(&'a MapRuntime);

impl Drop for MapLease<'_> {
    fn drop(&mut self) {
        self.0.leased.store(false, Ordering::Release);
    }
}

struct ProgramMapRuntime {
    generation: u32,
    perm: MapPerm,
    runtime: Arc<MapRuntime>,
}

pub(crate) struct ProgramRuntime {
    program: BpfProgram<ActiveProfile>,
    maps: Vec<Option<ProgramMapRuntime>>,
}

impl ProgramRuntime {
    fn map(&self, handle: u32, required: MapAccess) -> Option<&MapRuntime> {
        let slot = handles::slot(handle);
        let generation = handles::generation(handle);
        let entry = self.maps.get(slot)?.as_ref()?;
        if entry.generation != generation {
            return None;
        }
        let permitted = match entry.perm {
            MapPerm::ReadWrite => MapAccess::READ_WRITE,
            MapPerm::ReadOnly => MapAccess::READ,
            MapPerm::WriteOnly => MapAccess::WRITE,
            MapPerm::Unavailable => MapAccess::NONE,
        };
        permitted
            .contains(required)
            .then_some(entry.runtime.as_ref())
    }
}

const MAX_EXECUTION_MAP_LEASES: usize = 128;

struct BpfExecution<'a> {
    runtime: &'a ProgramRuntime,
    leased: [*const MapRuntime; MAX_EXECUTION_MAP_LEASES],
    leased_count: usize,
}

impl<'a> BpfExecution<'a> {
    fn new(runtime: &'a ProgramRuntime) -> Self {
        Self {
            runtime,
            leased: [core::ptr::null(); MAX_EXECUTION_MAP_LEASES],
            leased_count: 0,
        }
    }

    fn map(&mut self, handle: u32, required: MapAccess) -> Option<&MapRuntime> {
        let map = self.runtime.map(handle, required)?;
        let ptr = core::ptr::from_ref(map);
        if self.leased[..self.leased_count].contains(&ptr) {
            return Some(map);
        }
        if self.leased_count == self.leased.len()
            || map
                .leased
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
        {
            return None;
        }
        self.leased[self.leased_count] = ptr;
        self.leased_count += 1;
        Some(map)
    }
}

impl Drop for BpfExecution<'_> {
    fn drop(&mut self) {
        for ptr in &self.leased[..self.leased_count] {
            // SAFETY: each pointer comes from the live ProgramRuntime and is
            // retained by its Arc until this execution returns.
            unsafe { &**ptr }.leased.store(false, Ordering::Release);
        }
    }
}

fn with_current_execution_map<R>(
    handle: u32,
    required: MapAccess,
    f: impl FnOnce(&MapRuntime) -> R,
) -> Option<R> {
    let cpu = crate::mcore::context::ExecutionContext::try_load()?;
    let execution = cpu.current_bpf_execution().cast::<BpfExecution<'static>>();
    if execution.is_null() {
        return None;
    }
    // SAFETY: execute_program installs this CPU-local pointer for the dynamic
    // extent of interpreter execution, and nested execution is rejected.
    let execution = unsafe { &mut *execution };
    execution.map(handle, required).map(f)
}

impl MapEntry {
    fn access_for(&self, owner: u64) -> Option<MapAccess> {
        if self.owner == owner {
            return Some(MapAccess::READ_WRITE);
        }
        self.grants.access_for(owner)
    }

    fn grant(&mut self, owner: u64, access: MapAccess) -> Result<(), BpfError> {
        self.grants.grant(owner, access)
    }
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
    // Arc ownership changes only when control-plane snapshots are published;
    // hook readers borrow immutable ProgramRuntime entries under an epoch pin.
    programs: Vec<Option<ProgramEntry>>,
    program_generations: Vec<u32>,
    attachments: BTreeMap<u32, Vec<u32>>,
    maps: Vec<Option<MapEntry>>,
    map_generations: Vec<u32>,
    pinned_maps: Vec<PinnedMap>,
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

const fn is_latency_sensitive_attach_type(attach_type: u32) -> bool {
    matches!(
        attach_type,
        ATTACH_TYPE_TIMER | ATTACH_TYPE_GPIO | ATTACH_TYPE_SCHED_SWITCH
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

    #[cfg(not(test))]
    fn prepare_hook_snapshot(&self) -> Result<PreparedHookSnapshot, BpfError> {
        let mut container = Vec::new();
        container
            .try_reserve_exact(1)
            .map_err(|_| BpfError::OutOfMemory)?;
        container.push(HookSnapshot::empty());
        let snapshot = container.into_boxed_slice();
        debug_assert_eq!(snapshot.len(), 1);
        let raw = Box::into_raw(snapshot).cast::<HookSnapshot>();
        // SAFETY: a boxed one-element slice has the same allocation layout as
        // its element. EpochSnapshot later reclaims it as that element type.
        Ok(PreparedHookSnapshot {
            snapshot: unsafe { Box::from_raw(raw) },
        })
    }

    #[cfg(not(test))]
    fn publish_hook_snapshot(&self, mut prepared: PreparedHookSnapshot) {
        let snapshot = &mut prepared.snapshot;
        for (&attach_type, program_ids) in &self.attachments {
            let programs = snapshot
                .generic_mut(attach_type)
                .expect("supported attach types have direct snapshot slots");
            for &prog_id in program_ids {
                if let Some(entry) = self.program_entry(prog_id) {
                    programs
                        .push(&entry.program)
                        .expect("attach admission enforces the fixed hook fanout");
                }
            }
        }
        for pin in 0..BPF_GPIO_PIN_COUNT {
            for edge_flags in [1, 2, 3] {
                let fired = GpioEdge::from_flags(edge_flags);
                let programs = snapshot
                    .gpio_mut(0, pin, edge_flags)
                    .expect("validated GPIO routes have direct snapshot slots");
                self.gpio_routes.for_each_program(0, pin, fired, |prog_id| {
                    if let Some(entry) = self.program_entry(prog_id) {
                        programs
                            .push(&entry.program)
                            .expect("GPIO route admission enforces the fixed IRQ fanout");
                    }
                });
            }
        }
        HOOK_SNAPSHOTS.publish(prepared.snapshot);
    }

    fn new_with_limits(limits: BpfLimits) -> Self {
        let (signature_verifier, allow_unsigned) = signing_policy();
        let mut manager = Self {
            programs: Vec::new(),
            program_generations: Vec::new(),
            attachments: BTreeMap::new(),
            maps: Vec::new(),
            map_generations: Vec::new(),
            pinned_maps: Vec::new(),
            signature_verifier,
            allow_unsigned,
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

    /// Enable or disable signature enforcement. When `false`, only programs
    /// signed by a trusted key load.
    #[cfg(test)]
    pub fn set_allow_unsigned(&mut self, allow: bool) {
        self.allow_unsigned = allow;
    }

    fn register_reserved_map(&mut self, map: Box<dyn BpfMap<ActiveProfile>>, perm: MapPerm) -> u32 {
        let slot = self.maps.len();
        self.maps.push(Some(MapEntry {
            runtime: Arc::new(MapRuntime::new(map)),
            perm,
            charged_bytes: 0,
            owner: 0,
            grants: MapGrants::new(),
        }));
        self.map_generations.push(0);
        handles::encode(slot, 0)
    }

    fn register_user_map(
        &mut self,
        map: Box<dyn BpfMap<ActiveProfile>>,
        charge: usize,
        owner: u64,
    ) -> Result<u32, BpfError> {
        let id = handles::insert(
            &mut self.maps,
            &mut self.map_generations,
            self.limits.max_map_slots,
            MapEntry {
                runtime: Arc::new(MapRuntime::new(map)),
                perm: MapPerm::ReadWrite,
                charged_bytes: charge,
                owner,
                grants: MapGrants::new(),
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

    fn map_metadata_for_owner(
        &self,
        owner: u64,
        authorized: MapAccess,
    ) -> (Vec<u32>, Vec<MapPerm>, Vec<u32>) {
        let (sizes, perms) = self
            .maps
            .iter()
            .map(|slot| match slot.as_ref() {
                Some(entry) if entry.charged_bytes == 0 => {
                    let access = MapAccess::READ_WRITE.intersect(authorized);
                    if access.contains(MapAccess::READ) && access.contains(MapAccess::WRITE) {
                        (entry.runtime.map.def().value_size, entry.perm)
                    } else if access.contains(MapAccess::READ) {
                        (entry.runtime.map.def().value_size, MapPerm::ReadOnly)
                    } else if access.contains(MapAccess::WRITE) && entry.perm == MapPerm::ReadWrite
                    {
                        (entry.runtime.map.def().value_size, MapPerm::WriteOnly)
                    } else {
                        (0, MapPerm::Unavailable)
                    }
                }
                Some(entry) => match entry
                    .access_for(owner)
                    .map(|access| access.intersect(authorized))
                {
                    Some(access)
                        if access.contains(MapAccess::READ)
                            && access.contains(MapAccess::WRITE) =>
                    {
                        (entry.runtime.map.def().value_size, entry.perm)
                    }
                    Some(access) if access.contains(MapAccess::READ) => {
                        (entry.runtime.map.def().value_size, MapPerm::ReadOnly)
                    }
                    Some(access)
                        if access.contains(MapAccess::WRITE)
                            && entry.perm == MapPerm::ReadWrite =>
                    {
                        (entry.runtime.map.def().value_size, MapPerm::WriteOnly)
                    }
                    _ => (0, MapPerm::Unavailable),
                },
                None => (0, MapPerm::Unavailable),
            })
            .unzip();
        (sizes, perms, self.map_generations.clone())
    }

    fn program_maps_for_owner(
        &self,
        owner: u64,
        authorized: MapAccess,
        referenced_map_handles: &[u32],
    ) -> Result<Vec<Option<ProgramMapRuntime>>, BpfError> {
        let (_, perms, generations) = self.map_metadata_for_owner(owner, authorized);
        let mut maps = Vec::new();
        maps.try_reserve_exact(self.maps.len())
            .map_err(|_| BpfError::OutOfMemory)?;
        maps.resize_with(self.maps.len(), || None);
        for &handle in referenced_map_handles {
            let slot = self.map_slot(handle).ok_or(BpfError::NotLoaded)?;
            let entry = self.maps[slot].as_ref().ok_or(BpfError::NotLoaded)?;
            let perm = perms[slot];
            if perm == MapPerm::Unavailable {
                return Err(BpfError::PermissionDenied);
            }
            maps[slot] = Some(ProgramMapRuntime {
                generation: generations[slot],
                perm,
                runtime: entry.runtime.clone(),
            });
        }
        Ok(maps)
    }

    fn program_slot(&self, handle: u32) -> Option<usize> {
        let slot = handles::decode(&self.program_generations, handle)?;
        self.programs.get(slot)?.as_ref()?;
        Some(slot)
    }

    fn program_entry(&self, handle: u32) -> Option<&ProgramEntry> {
        self.programs.get(self.program_slot(handle)?)?.as_ref()
    }

    fn map_slot(&self, handle: u32) -> Option<usize> {
        let slot = handles::decode(&self.map_generations, handle)?;
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

    fn reclaim_unpinned_orphan_maps_if_quiescent(&mut self) {
        let pinned_maps = &self.pinned_maps;
        let map_generations = &self.map_generations;
        for (map_slot, slot) in self.maps.iter_mut().enumerate() {
            let Some(entry) = slot.as_ref() else {
                continue;
            };
            if entry.owner != PINNED_MAP_OWNER || entry.charged_bytes == 0 {
                continue;
            }
            let map_id = handles::encode(map_slot, map_generations[map_slot]);
            if pinned_maps.iter().any(|pin| pin.map_id == map_id)
                || Arc::strong_count(&entry.runtime) != 1
            {
                continue;
            }
            let entry = slot.take().expect("orphan map entry was present");
            self.live_maps = self.live_maps.saturating_sub(1);
            self.map_bytes = self.map_bytes.saturating_sub(entry.charged_bytes);
        }
    }

    /// Detach and reclaim every object charged to `owner`.
    ///
    /// A `false` result means snapshot preparation could not reserve memory or
    /// an independently cloned program reference is still in flight.
    pub(crate) fn reclaim_owner(&mut self, owner: u64) -> bool {
        #[cfg(any(debug_assertions, feature = "audit-diagnostics"))]
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
        #[cfg(not(test))]
        let snapshot = match self.prepare_hook_snapshot() {
            Ok(snapshot) => snapshot,
            Err(_) => return false,
        };
        let programs = &self.programs;
        let program_generations = &self.program_generations;
        let (attachments, admission) = (&mut self.attachments, &mut self.admission);
        for (&attach_type, attached) in attachments.iter_mut() {
            let mut index = 0;
            while index < attached.len() {
                let prog_id = attached[index];
                let owned = handles::decode(program_generations, prog_id)
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
                    .remove(handles::encode(slot, self.program_generations[slot]));
            }
        }

        #[cfg(not(test))]
        self.publish_hook_snapshot(snapshot);

        for entry in self.maps.iter_mut().filter_map(Option::as_mut) {
            entry.grants.revoke_owner(owner);
        }
        for pin in &mut self.pinned_maps {
            if pin.owner == owner {
                pin.owner = PINNED_MAP_OWNER;
            }
        }

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

        let pinned_maps = &self.pinned_maps;
        let map_generations = &self.map_generations;
        for (map_slot, slot) in self.maps.iter_mut().enumerate() {
            let Some(entry) = slot.as_ref() else {
                continue;
            };
            if entry.owner != owner || entry.charged_bytes == 0 {
                continue;
            }
            let map_id = handles::encode(map_slot, map_generations[map_slot]);
            if pinned_maps.iter().any(|pin| pin.map_id == map_id) {
                slot.as_mut().expect("owned map entry was present").owner = PINNED_MAP_OWNER;
                continue;
            }
            if Arc::strong_count(&entry.runtime) != 1 {
                slot.as_mut().expect("owned map entry was present").owner = PINNED_MAP_OWNER;
                continue;
            }
            let entry = slot.take().expect("owned map entry was present");
            self.live_maps = self.live_maps.saturating_sub(1);
            self.map_bytes = self.map_bytes.saturating_sub(entry.charged_bytes);
        }
        #[cfg(any(debug_assertions, feature = "audit-diagnostics"))]
        if had_owned_objects {
            log::info!("BPF_OWNER_RECLAIM_OK owner={owner}");
            #[cfg(feature = "audit-diagnostics")]
            crate::serial_println!("BPF_OWNER_RECLAIM_OK owner={}", owner);
        }
        self.reclaim_unpinned_orphan_maps_if_quiescent();
        true
    }

    fn ensure_program_quota(&self, owner: u64, charge: usize) -> Result<(), BpfError> {
        let has_slot = self.programs.len() < self.limits.max_program_slots
            || self.programs.iter().enumerate().any(|(slot, entry)| {
                entry.is_none() && handles::can_reuse(self.program_generations[slot])
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
        referenced_map_handles: &[u32],
        charge: usize,
        owner: u64,
        authorization: BpfLoadAuthorization,
    ) -> Result<u32, BpfError> {
        self.ensure_program_quota(owner, charge)?;
        let maps =
            self.program_maps_for_owner(owner, authorization.map_access, referenced_map_handles)?;
        let id = handles::insert(
            &mut self.programs,
            &mut self.program_generations,
            self.limits.max_program_slots,
            ProgramEntry {
                program: Arc::new(ProgramRuntime { program, maps }),
                wcet_cycles,
                charged_bytes: charge,
                owner,
                authorization,
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
        authorization: BpfLoadAuthorization,
    ) -> VerifyConfig<'a> {
        self.verify_config_with_ctx_data(
            sizes,
            perms,
            generations,
            VERIFY_CTX_DATA_SIZE_MAX,
            authorization,
        )
    }

    fn verify_config_with_ctx_data<'a>(
        &self,
        sizes: &'a [u32],
        perms: &'a [MapPerm],
        generations: &'a [u32],
        ctx_data_size: u32,
        authorization: BpfLoadAuthorization,
    ) -> VerifyConfig<'a> {
        VerifyConfig {
            ctx_size: VERIFY_CTX_SIZE,
            ctx_data_size,
            map_value_size: VERIFY_MAP_VALUE_SIZE,
            map_value_sizes: sizes,
            map_perms: perms,
            map_generations: generations,
            map_handle_slot_bits: handles::SLOT_BITS as u8,
            caller: authorization.caller,
            allow_actuation: authorization.allow_actuation,
            forbid_logging_helpers: false,
        }
    }

    pub fn load_program(&mut self, elf_bytes: &[u8]) -> Result<u32, BpfError> {
        self.load_program_for(0, elf_bytes)
    }

    pub fn load_program_for(&mut self, owner: u64, elf_bytes: &[u8]) -> Result<u32, BpfError> {
        self.load_program_authorized(owner, elf_bytes, BpfLoadAuthorization::kernel())
    }

    pub fn load_program_authorized(
        &mut self,
        owner: u64,
        elf_bytes: &[u8],
        authorization: BpfLoadAuthorization,
    ) -> Result<u32, BpfError> {
        if elf_bytes.len() > self.limits.max_elf_bytes {
            return Err(BpfError::ResourceLimit);
        }
        // Fail before parsing when the object table is already exhausted.
        self.ensure_program_quota(owner, 0)?;

        // Authenticate provenance before parsing (#20): a signed RBPF container
        // is verified against the trust store and unwrapped to its inner ELF; a
        // plain ELF is accepted only when unsigned loads are permitted.
        let authenticated = self
            .signature_verifier
            .authenticate_with_provenance(elf_bytes, self.allow_unsigned)
            .map_err(|e| {
                log::error!("BpfManager: ELF program failed authentication: {}", e);
                BpfError::SignatureRejected
            })?;
        let elf_bytes = authenticated.program_data();

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
            let (map_value_sizes, map_perms, map_generations) =
                self.map_metadata_for_owner(owner, authorization.map_access);
            #[cfg(feature = "verifier-cost")]
            let insn_count = loaded_prog.insns().len();
            #[cfg(feature = "verifier-cost")]
            let start_cycles = read_cycles();
            let (bpf_prog, stats) = Verifier::<ActiveProfile>::verify_with_stats(
                loaded_prog.prog_type(),
                loaded_prog.insns(),
                self.verify_config(
                    &map_value_sizes,
                    &map_perms,
                    &map_generations,
                    authorization,
                ),
            )
            .map_err(|e| {
                log::error!("BpfManager: ELF program rejected by verifier: {}", e);
                BpfError::VerificationFailed
            })?;
            #[cfg(feature = "verifier-cost")]
            let verify_cycles = read_cycles().wrapping_sub(start_cycles);

            let id = self.register_program(
                bpf_prog,
                stats.wcet_cycles,
                &stats.referenced_map_handles,
                charge,
                owner,
                authorization,
            )?;
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
        self.load_raw_program_authorized(owner, insns, BpfLoadAuthorization::kernel())
    }

    pub fn load_raw_program_authorized(
        &mut self,
        owner: u64,
        insns: Vec<BpfInsn>,
        authorization: BpfLoadAuthorization,
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
        let (map_value_sizes, map_perms, map_generations) =
            self.map_metadata_for_owner(owner, authorization.map_access);
        #[cfg(feature = "verifier-cost")]
        let insn_count = insns.len();
        #[cfg(feature = "verifier-cost")]
        let start_cycles = read_cycles();
        let (bpf_prog, stats) = Verifier::<ActiveProfile>::verify_with_stats(
            BpfProgType::Unspec,
            &insns,
            self.verify_config(
                &map_value_sizes,
                &map_perms,
                &map_generations,
                authorization,
            ),
        )
        .map_err(|e| {
            log::error!("BpfManager: raw program rejected by verifier: {}", e);
            BpfError::VerificationFailed
        })?;
        #[cfg(feature = "verifier-cost")]
        let verify_cycles = read_cycles().wrapping_sub(start_cycles);

        let id = self.register_program(
            bpf_prog,
            stats.wcet_cycles,
            &stats.referenced_map_handles,
            charge,
            owner,
            authorization,
        )?;
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

    fn validate_attach_for(
        &self,
        owner: u64,
        attach_type: u32,
        prog_id: u32,
    ) -> Result<bool, BpfError> {
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

        let (map_value_sizes, map_perms, map_generations) =
            self.map_metadata_for_owner(owner, program_entry.authorization.map_access);
        let ctx_data_size = attach_ctx_data_size(attach_type);
        let program = &program_entry.program.program;
        let mut verify_config = self.verify_config_with_ctx_data(
            &map_value_sizes,
            &map_perms,
            &map_generations,
            ctx_data_size,
            program_entry.authorization,
        );
        verify_config.forbid_logging_helpers = is_latency_sensitive_attach_type(attach_type);
        Verifier::<ActiveProfile>::verify_with_stats(
            program.prog_type(),
            program.instructions(),
            verify_config,
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

        let already_attached = self
            .attachments
            .get(&attach_type)
            .is_some_and(|list| list.contains(&prog_id));
        if !already_attached
            && self
                .attachments
                .get(&attach_type)
                .is_some_and(|programs| programs.len() >= HOOK_FANOUT_LIMIT)
        {
            return Err(BpfError::ResourceLimit);
        }
        Ok(already_attached)
    }

    fn commit_attach(&mut self, attach_type: u32, prog_id: u32) -> Result<(), BpfError> {
        // Utilization admission (#43): attaching commits the CPU to running
        // this program on every fire; refuse if `Σ WCETᵢ·freqᵢ` across all
        // admitted hooks would exceed the profile's utilization budget.
        let wcet = self
            .program_entry(prog_id)
            .ok_or(BpfError::NotLoaded)?
            .wcet_cycles;
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
        Ok(())
    }

    fn attach_verified_for(
        &mut self,
        owner: u64,
        attach_type: u32,
        prog_id: u32,
    ) -> Result<(), BpfError> {
        if self.validate_attach_for(owner, attach_type, prog_id)? {
            return Ok(());
        }
        #[cfg(not(test))]
        let snapshot = self.prepare_hook_snapshot()?;
        self.commit_attach(attach_type, prog_id)?;
        #[cfg(not(test))]
        self.publish_hook_snapshot(snapshot);
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
        #[cfg(not(test))]
        let snapshot = self.prepare_hook_snapshot()?;
        if let Some(list) = self.attachments.get_mut(&attach_type) {
            if let Some(pos) = list.iter().position(|&id| id == prog_id) {
                list.remove(pos);
                // Return this attachment's utilization to the budget.
                self.admission.release(attach_type, prog_id);
                self.gpio_routes.remove(prog_id);
                #[cfg(not(test))]
                self.publish_hook_snapshot(snapshot);
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
        self.reclaim_unpinned_orphan_maps_if_quiescent();
        Ok(())
    }

    pub fn execute(&self, program_id: u32, ctx: &BpfContext<'_>) -> Result<u64, BpfError> {
        let program = self.program_entry(program_id).ok_or(BpfError::NotLoaded)?;

        Self::execute_program(&program.program, ctx)
    }

    /// Execute a BPF program directly against its immutable runtime view.
    pub(crate) fn execute_program(
        runtime: &ProgramRuntime,
        ctx: &BpfContext<'_>,
    ) -> Result<u64, BpfError> {
        let cpu = crate::mcore::context::ExecutionContext::try_load()
            .ok_or(BpfError::ReentrantExecution)?;
        cpu.with_bpf_stack(|stack| {
            let mut execution = BpfExecution::new(runtime);
            cpu.with_bpf_execution(core::ptr::from_mut(&mut execution).cast(), || {
                let interpreter = Interpreter::<ActiveProfile>::new();
                interpreter.execute_with_stack(&runtime.program, ctx, stack)
            })
            .ok_or(BpfError::ReentrantExecution)?
        })
        .ok_or(BpfError::ReentrantExecution)?
    }

    /// Clone a loaded runtime by id (verifier-cost instrumentation only).
    #[cfg(feature = "verifier-cost")]
    pub(crate) fn get_program(&self, prog_id: u32) -> Option<Arc<ProgramRuntime>> {
        self.program_entry(prog_id)
            .map(|entry| entry.program.clone())
    }

    #[cfg(feature = "verifier-cost")]
    pub fn get_program_for(
        &self,
        owner: u64,
        prog_id: u32,
    ) -> Result<Arc<ProgramRuntime>, BpfError> {
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
        program: &ProgramRuntime,
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
                insns: program.program.instructions().len(),
                runs,
                cycles,
            }
        );
        Ok(())
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

        self.ensure_program_owner(owner, prog_id)?;
        let already_attached = self.validate_attach_for(owner, ATTACH_TYPE_GPIO, prog_id)?;
        #[cfg(not(test))]
        let snapshot = self.prepare_hook_snapshot()?;
        if !already_attached {
            self.commit_attach(ATTACH_TYPE_GPIO, prog_id)?;
        }
        self.gpio_routes.insert(chip, pin, edge, prog_id);
        #[cfg(not(test))]
        self.publish_hook_snapshot(snapshot);
        Ok(())
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
        #[cfg(not(test))]
        let snapshot = self.prepare_hook_snapshot()?;
        self.gpio_routes.insert(chip, pin, edge, prog_id);
        #[cfg(not(test))]
        self.publish_hook_snapshot(snapshot);
        Ok(())
    }

    pub fn run_gpio_programs(
        chip: u8,
        pin: u8,
        fired: GpioEdge,
        ctx: &BpfContext<'_>,
    ) -> Result<usize, BpfError> {
        let edge_flags = match fired {
            GpioEdge::Rising => 1,
            GpioEdge::Falling => 2,
            GpioEdge::Both => 3,
        };
        let Some(snapshot) = HOOK_SNAPSHOTS.read() else {
            return Ok(0);
        };
        let Some(programs) = snapshot.gpio(chip, pin, edge_flags) else {
            return Ok(0);
        };
        Self::run_snapshot(programs.iter(), ctx)
    }

    pub fn run_hook_programs(
        attach_type: u32,
        ctx: &BpfContext<'_>,
        _hook_name: &str,
    ) -> Result<usize, BpfError> {
        let Some(snapshot) = HOOK_SNAPSHOTS.read() else {
            return Ok(0);
        };
        let Some(programs) = snapshot.generic(attach_type) else {
            return Ok(0);
        };
        Self::run_snapshot(programs.iter(), ctx)
    }

    fn run_snapshot<'a>(
        programs: impl Iterator<Item = &'a Arc<ProgramRuntime>>,
        ctx: &BpfContext<'_>,
    ) -> Result<usize, BpfError> {
        let mut count = 0;
        for program in programs {
            Self::execute_program(program, ctx)?;
            count += 1;
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
            BPF_MAP_TYPE_HASH if key_size != 0 && value_size != 0 => {
                BpfHashMap::<ActiveProfile>::allocation_size(key_size, value_size, max_entries)
            }
            BPF_MAP_TYPE_ARRAY if key_size == 4 && value_size != 0 => {
                ArrayMap::<ActiveProfile>::allocation_size(value_size, max_entries)
            }
            BPF_MAP_TYPE_RINGBUF
                if key_size == 0 && value_size == 0 && max_entries.is_power_of_two() =>
            {
                Some(max_entries as usize)
            }
            BPF_MAP_TYPE_TIMESERIES if key_size == 8 && value_size != 0 => {
                TimeSeriesMap::<ActiveProfile>::allocation_size(value_size, max_entries)
            }
            BPF_MAP_TYPE_HASH
            | BPF_MAP_TYPE_ARRAY
            | BPF_MAP_TYPE_RINGBUF
            | BPF_MAP_TYPE_TIMESERIES => return Err(BpfError::InvalidInstruction),
            _ => return Err(BpfError::InvalidInstruction),
        }
        .ok_or(BpfError::ResourceLimit)?;

        let has_slot = self.maps.len() < self.limits.max_map_slots
            || self.maps.iter().enumerate().any(|(slot, entry)| {
                entry.is_none() && handles::can_reuse(self.map_generations[slot])
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
            BPF_MAP_TYPE_HASH => {
                // Hash map
                Box::new(
                    BpfHashMap::<ActiveProfile>::with_sizes(key_size, value_size, max_entries)
                        .map_err(|_| BpfError::OutOfMemory)?,
                )
            }
            BPF_MAP_TYPE_ARRAY => {
                // Array map
                Box::new(
                    ArrayMap::<ActiveProfile>::with_entries(value_size, max_entries)
                        .map_err(|_| BpfError::OutOfMemory)?,
                )
            }
            BPF_MAP_TYPE_RINGBUF => {
                // Ring buffer map - max_entries is the buffer size (must be power of 2)
                Box::new(
                    RingBufMap::<ActiveProfile>::new(max_entries as usize)
                        .map_err(|_| BpfError::OutOfMemory)?,
                )
            }
            BPF_MAP_TYPE_TIMESERIES => {
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
        let map = &self.map_entry(map_id)?.runtime;
        let _lease = map.try_lease().ok()?;
        map.map.lookup(key)
    }

    pub fn map_lookup_for(
        &self,
        owner: u64,
        map_id: u32,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, BpfError> {
        self.ensure_map_access(owner, map_id, MapAccess::READ)?;
        let map = &self.map_entry(map_id).ok_or(BpfError::NotLoaded)?.runtime;
        let _lease = map.try_lease()?;
        Ok(map.map.lookup(key))
    }

    fn ensure_map_writable(&self, map_id: u32) -> Result<(), BpfError> {
        match self.map_entry(map_id).ok_or(BpfError::NotLoaded)?.perm {
            MapPerm::Unavailable => Err(BpfError::PermissionDenied),
            MapPerm::WriteOnly | MapPerm::ReadWrite => Ok(()),
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

    fn ensure_map_access(
        &self,
        owner: u64,
        map_id: u32,
        required: MapAccess,
    ) -> Result<(), BpfError> {
        let entry = self.map_entry(map_id).ok_or(BpfError::NotLoaded)?;
        let access = if entry.charged_bytes == 0 {
            MapAccess::READ_WRITE
        } else {
            entry.access_for(owner).ok_or(BpfError::PermissionDenied)?
        };
        if access.contains(required) {
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
        let map = &self.map_entry(map_id).ok_or(BpfError::NotLoaded)?.runtime;
        let _lease = map.try_lease()?;
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
        self.ensure_map_access(owner, map_id, MapAccess::WRITE)?;
        self.map_update(map_id, key, value, flags)
    }

    pub fn map_delete(&self, map_id: u32, key: &[u8]) -> Result<(), BpfError> {
        self.ensure_map_writable(map_id)?;
        let map = &self.map_entry(map_id).ok_or(BpfError::NotLoaded)?.runtime;
        let _lease = map.try_lease()?;
        map.map.delete(key).map_err(|_| BpfError::NotLoaded)
    }

    pub fn map_delete_for(&self, owner: u64, map_id: u32, key: &[u8]) -> Result<(), BpfError> {
        self.ensure_map_access(owner, map_id, MapAccess::WRITE)?;
        self.map_delete(map_id, key)
    }

    pub fn get_map_def(&self, map_id: u32) -> Option<&kernel_bpf::maps::MapDef> {
        self.map_entry(map_id).map(|entry| entry.runtime.map.def())
    }

    pub fn get_map_def_for(
        &self,
        owner: u64,
        map_id: u32,
    ) -> Result<&kernel_bpf::maps::MapDef, BpfError> {
        self.get_map_def_for_access(owner, map_id, MapAccess::READ)
    }

    pub(crate) fn get_map_def_for_access(
        &self,
        owner: u64,
        map_id: u32,
        required: MapAccess,
    ) -> Result<&kernel_bpf::maps::MapDef, BpfError> {
        self.ensure_map_access(owner, map_id, required)?;
        self.get_map_def(map_id).ok_or(BpfError::NotLoaded)
    }

    pub fn pin_map(&mut self, path: String, map_id: u32) -> Result<(), BpfError> {
        self.pin_map_for(0, path, map_id)
    }

    pub fn pin_map_for(&mut self, owner: u64, path: String, map_id: u32) -> Result<(), BpfError> {
        self.pin_map_with_access_for(owner, path, map_id, MapAccess::READ_WRITE)
    }

    pub fn pin_map_with_access_for(
        &mut self,
        owner: u64,
        path: String,
        map_id: u32,
        offered: MapAccess,
    ) -> Result<(), BpfError> {
        if path.is_empty() || path.len() >= BPF_PIN_PATH_MAX {
            return Err(BpfError::ResourceLimit);
        }
        if !offered.contains(MapAccess::READ) && !offered.contains(MapAccess::WRITE) {
            return Err(BpfError::PermissionDenied);
        }
        self.ensure_map_owner(owner, map_id)?;

        if let Some(existing) = self.pinned_maps.iter().find(|pin| pin.path == path) {
            return if existing.map_id == map_id
                && existing.owner == owner
                && existing.offered == offered
            {
                Ok(())
            } else {
                Err(BpfError::ObjectBusy)
            };
        }
        if self.pinned_maps.len() >= self.limits.max_pinned_maps {
            return Err(BpfError::ResourceLimit);
        }
        append_pinned_map(
            &mut self.pinned_maps,
            PinnedMap {
                path,
                map_id,
                owner,
                offered,
            },
        )
    }

    pub fn get_pinned_map(&self, path: &str) -> Option<u32> {
        self.pinned_maps
            .iter()
            .find(|pin| pin.path == path)
            .map(|pin| pin.map_id)
    }

    pub fn get_pinned_map_for(
        &mut self,
        owner: u64,
        path: &str,
        requested: MapAccess,
    ) -> Result<u32, BpfError> {
        let (map_id, offered) = self
            .pinned_maps
            .iter()
            .find(|pin| pin.path == path)
            .map(|pin| (pin.map_id, pin.offered))
            .ok_or(BpfError::NotLoaded)?;
        if !offered.contains(requested) {
            return Err(BpfError::PermissionDenied);
        }
        let entry = self.map_entry(map_id).ok_or(BpfError::NotLoaded)?;
        if entry.owner != owner {
            let slot = self.map_slot(map_id).ok_or(BpfError::NotLoaded)?;
            self.maps[slot]
                .as_mut()
                .ok_or(BpfError::NotLoaded)?
                .grant(owner, requested)?;
        }
        Ok(map_id)
    }

    pub fn unpin_map(&mut self, path: &str) -> Result<(), BpfError> {
        self.unpin_map_for(0, path, true)
    }

    pub fn unpin_map_for(
        &mut self,
        owner: u64,
        path: &str,
        allow_orphan_cleanup: bool,
    ) -> Result<(), BpfError> {
        let index = self
            .pinned_maps
            .iter()
            .position(|pin| pin.path == path)
            .ok_or(BpfError::NotLoaded)?;
        let pin = &self.pinned_maps[index];
        if pin.owner != owner && (pin.owner != PINNED_MAP_OWNER || !allow_orphan_cleanup) {
            return Err(BpfError::PermissionDenied);
        }
        let map_id = pin.map_id;
        let last_pin = !self
            .pinned_maps
            .iter()
            .enumerate()
            .any(|(other_index, pin)| other_index != index && pin.map_id == map_id);
        let orphaned = self
            .map_entry(map_id)
            .is_some_and(|entry| entry.owner == PINNED_MAP_OWNER);
        self.pinned_maps.remove(index);
        if last_pin && orphaned {
            self.reclaim_unpinned_orphan_maps_if_quiescent();
        }
        Ok(())
    }

    /// Destroy an unpinned user map and reclaim its backing allocation.
    ///
    /// Destruction is refused while the map is pinned or retained by a verified
    /// program runtime, so helper-visible storage cannot disappear in flight.
    pub fn destroy_map(&mut self, map_id: u32) -> Result<(), BpfError> {
        self.destroy_map_for(0, map_id)
    }

    pub fn destroy_map_for(&mut self, owner: u64, map_id: u32) -> Result<(), BpfError> {
        let slot = self.map_slot(map_id).ok_or(BpfError::NotLoaded)?;
        if slot < RESERVED_MAP_COUNT as usize {
            return Err(BpfError::ReadOnlyMap);
        }
        self.ensure_map_owner(owner, map_id)?;
        let entry = self.maps[slot]
            .as_ref()
            .expect("map ownership was checked above");
        if self.pinned_maps.iter().any(|pin| pin.map_id == map_id)
            || Arc::strong_count(&entry.runtime) != 1
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
        self.ensure_map_access(owner, map_id, MapAccess::READ)?;
        self.get_map_info(map_id).ok_or(BpfError::NotLoaded)
    }

    /// Poll for the next event from a ring buffer map.
    ///
    /// Returns the event data if available, or None if the ringbuf is empty.
    /// This is used by the BPF_RINGBUF_POLL syscall command.
    pub fn ringbuf_poll(&self, map_id: u32) -> Option<Vec<u8>> {
        let map = &self.map_entry(map_id)?.runtime;
        let _lease = map.try_lease().ok()?;
        // RingBufMap::lookup() delegates to poll(), which reads and advances the tail
        map.map.lookup(&[])
    }

    pub fn ringbuf_poll_for(&self, owner: u64, map_id: u32) -> Result<Option<Vec<u8>>, BpfError> {
        self.ensure_map_access(owner, map_id, MapAccess::READ)?;
        let map = &self.map_entry(map_id).ok_or(BpfError::NotLoaded)?.runtime;
        let _lease = map.try_lease()?;
        Ok(map.map.lookup(&[]))
    }

    /// Output data to a ring buffer map.
    ///
    /// This is used by the bpf_ringbuf_output helper. For ringbuf maps,
    /// the key is ignored and value is the event data.
    pub fn ringbuf_output(&self, map_id: u32, data: &[u8], flags: u64) -> Result<(), BpfError> {
        self.ensure_map_writable(map_id)?;
        let map = &self.map_entry(map_id).ok_or(BpfError::NotLoaded)?.runtime;
        let _lease = map.try_lease()?;

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
    use kernel_bpf::verifier::{HelperId, LoadCaller, MapPerm};

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

        let (sizes, perms, generations) = manager.map_metadata_for_owner(0, MapAccess::READ_WRITE);

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
    fn map_execution_leases_are_nonblocking_and_per_map() {
        let mut manager = BpfManager::new();
        let first = manager
            .create_map(MapType::Array as u32, 4, 8, 1)
            .expect("create first map");
        let second = manager
            .create_map(MapType::Array as u32, 4, 8, 1)
            .expect("create second map");
        let first_runtime = manager.map_entry(first).unwrap().runtime.clone();
        let _lease = first_runtime.try_lease().expect("acquire first map lease");
        let key = 0u32.to_ne_bytes();
        let value = 1u64.to_ne_bytes();

        assert_eq!(
            manager.map_update(first, &key, &value, 0),
            Err(BpfError::ObjectBusy)
        );
        manager
            .map_update(second, &key, &value, 0)
            .expect("unrelated map remains available");
    }

    #[test]
    fn program_runtime_retains_only_referenced_authorized_maps() {
        let mut manager = BpfManager::new();
        let referenced = manager
            .create_map_for(7, MapType::Array as u32, 4, 8, 1)
            .expect("create owner map");
        let unrelated = manager
            .create_map_for(7, MapType::Array as u32, 4, 8, 1)
            .expect("create unrelated owner map");
        let lookup = vec![
            BpfInsn::mov64_imm(1, 0),
            BpfInsn::new(0x7b, 10, 1, -8, 0),
            BpfInsn::mov64_imm(1, referenced as i32),
            BpfInsn::mov64_reg(2, 10),
            BpfInsn::add64_imm(2, -8),
            BpfInsn::call(HelperId::MapLookupElem as i32),
            BpfInsn::mov64_imm(0, 0),
            BpfInsn::exit(),
        ];
        let program_id = manager
            .load_raw_program_authorized(
                7,
                lookup,
                BpfLoadAuthorization::new(LoadCaller::Unprivileged, false, MapAccess::READ),
            )
            .expect("load owner program");
        let runtime = &manager.program_entry(program_id).unwrap().program;

        assert!(runtime.map(referenced, MapAccess::READ).is_some());
        assert!(runtime.map(referenced, MapAccess::WRITE).is_none());
        assert!(runtime.map(unrelated, MapAccess::READ).is_none());
        assert!(runtime
            .map(
                referenced.wrapping_add(1 << handles::SLOT_BITS),
                MapAccess::READ
            )
            .is_none());

        manager
            .destroy_map_for(7, unrelated)
            .expect("unrelated map is not retained by the program");
        assert_eq!(manager.resource_usage().map_bytes, 8);
        assert_eq!(
            manager.destroy_map_for(7, referenced),
            Err(BpfError::ObjectBusy)
        );
        assert_eq!(manager.resource_usage().map_bytes, 8);
        manager
            .unload_program_for(7, program_id)
            .expect("unload releases the referenced map runtime");
        manager
            .destroy_map_for(7, referenced)
            .expect("referenced map becomes reclaimable after unload");
        assert_eq!(manager.resource_usage().map_bytes, 0);
    }

    #[test]
    fn owner_reclaim_keeps_referenced_map_charged_until_foreign_program_unloads() {
        let mut manager = BpfManager::new();
        let map_id = manager
            .create_map_for(1, MapType::Array as u32, 4, 8, 1)
            .expect("owner map");
        manager
            .pin_map_with_access_for(1, "/shared".into(), map_id, MapAccess::READ)
            .expect("owner offers read access");
        assert_eq!(
            manager
                .get_pinned_map_for(2, "/shared", MapAccess::READ)
                .expect("foreign process accepts read grant"),
            map_id
        );
        let lookup = vec![
            BpfInsn::mov64_imm(1, 0),
            BpfInsn::new(0x7b, 10, 1, -8, 0),
            BpfInsn::mov64_imm(1, map_id as i32),
            BpfInsn::mov64_reg(2, 10),
            BpfInsn::add64_imm(2, -8),
            BpfInsn::call(HelperId::MapLookupElem as i32),
            BpfInsn::mov64_imm(0, 0),
            BpfInsn::exit(),
        ];
        let foreign_program = manager
            .load_raw_program_authorized(
                2,
                lookup,
                BpfLoadAuthorization::new(LoadCaller::Unprivileged, false, MapAccess::READ),
            )
            .expect("foreign program captures granted map");
        manager
            .unpin_map_for(1, "/shared", false)
            .expect("owner removes public pin");

        assert!(manager.reclaim_owner(1));
        assert!(manager.map_entry(map_id).is_some());
        assert_eq!(manager.resource_usage().map_bytes, 8);

        manager
            .unload_program_for(2, foreign_program)
            .expect("foreign program unloads");
        assert!(manager.map_entry(map_id).is_none());
        assert_eq!(manager.resource_usage().map_bytes, 0);
    }

    #[test]
    fn hook_snapshots_are_directly_indexed_and_fanout_bounded() {
        let mut manager = BpfManager::new();
        let program_id = manager
            .load_raw_program(vec![BpfInsn::mov64_imm(0, 0), BpfInsn::exit()])
            .expect("load snapshot test program");
        let runtime = manager.program_entry(program_id).unwrap().program.clone();
        let mut snapshot = HookSnapshot::empty();

        snapshot
            .generic_mut(ATTACH_TYPE_TIMER)
            .unwrap()
            .push(&runtime)
            .unwrap();
        snapshot
            .gpio_mut(0, 17, GpioEdge::Rising as u32)
            .unwrap()
            .push(&runtime)
            .unwrap();

        assert_eq!(
            snapshot.generic(ATTACH_TYPE_TIMER).unwrap().iter().count(),
            1
        );
        assert_eq!(
            snapshot
                .generic(ATTACH_TYPE_SCHED_SWITCH)
                .unwrap()
                .iter()
                .count(),
            0
        );
        assert_eq!(snapshot.gpio(0, 17, 1).unwrap().iter().count(), 1);
        assert_eq!(snapshot.gpio(0, 17, 2).unwrap().iter().count(), 0);

        let timer = snapshot.generic_mut(ATTACH_TYPE_TIMER).unwrap();
        for _ in 1..HOOK_FANOUT_LIMIT {
            timer.push(&runtime).unwrap();
        }
        assert_eq!(timer.push(&runtime), Err(BpfError::ResourceLimit));
    }

    #[test]
    #[cfg(feature = "cloud-profile")]
    fn latency_sensitive_hooks_reject_logging_helpers() {
        let mut manager = BpfManager::new();
        let program_id = manager
            .load_raw_program(vec![
                BpfInsn::mov64_imm(2, 0),
                BpfInsn::call(HelperId::TracePrintk as i32),
                BpfInsn::mov64_imm(0, 0),
                BpfInsn::exit(),
            ])
            .expect("logging remains valid at load time");

        manager
            .attach(ATTACH_TYPE_SYS_ENTER, program_id)
            .expect("non-latency trace hook may use the logging helper");
        manager.detach(ATTACH_TYPE_SYS_ENTER, program_id).unwrap();
        for attach_type in [
            ATTACH_TYPE_TIMER,
            ATTACH_TYPE_GPIO,
            ATTACH_TYPE_SCHED_SWITCH,
        ] {
            assert_eq!(
                manager.attach(attach_type, program_id),
                Err(BpfError::VerificationFailed)
            );
        }
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
        assert_eq!(second & handles::SLOT_MASK, first & handles::SLOT_MASK);
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
    fn pinned_map_access_requires_open_and_honors_offered_rights() {
        let mut manager = BpfManager::new();
        let map_id = manager
            .create_map_for(1, MapType::Array as u32, 4, 8, 1)
            .expect("owner map");
        manager
            .pin_map_with_access_for(1, "/shared-read".into(), map_id, MapAccess::READ)
            .expect("read-only pin");

        assert_eq!(
            manager.map_lookup_for(2, map_id, &0u32.to_ne_bytes()),
            Err(BpfError::PermissionDenied)
        );
        assert_eq!(
            manager.get_pinned_map_for(2, "/shared-read", MapAccess::WRITE),
            Err(BpfError::PermissionDenied)
        );
        assert_eq!(
            manager.get_pinned_map_for(2, "/shared-read", MapAccess::READ),
            Ok(map_id)
        );
        assert!(manager
            .map_lookup_for(2, map_id, &0u32.to_ne_bytes())
            .is_ok());
        assert_eq!(
            manager.map_update_for(2, map_id, &0u32.to_ne_bytes(), &[1; 8], 0),
            Err(BpfError::PermissionDenied)
        );
        assert_eq!(
            manager.unpin_map_for(2, "/shared-read", false),
            Err(BpfError::PermissionDenied)
        );
        manager
            .unpin_map_for(1, "/shared-read", false)
            .expect("pin owner unpins");
        manager
            .destroy_map_for(1, map_id)
            .expect("map owner destroys unpinned map");
    }

    #[test]
    fn pinned_write_only_grant_allows_mutation_without_disclosing_values() {
        let mut manager = BpfManager::new();
        let map_id = manager
            .create_map_for(1, MapType::Array as u32, 4, 8, 1)
            .expect("owner map");
        manager
            .pin_map_with_access_for(1, "/shared-write".into(), map_id, MapAccess::WRITE)
            .expect("write-only pin");
        assert_eq!(
            manager.get_pinned_map_for(2, "/shared-write", MapAccess::WRITE),
            Ok(map_id)
        );

        assert!(manager
            .get_map_def_for_access(2, map_id, MapAccess::WRITE)
            .is_ok());
        manager
            .map_update_for(2, map_id, &0u32.to_ne_bytes(), &[1; 8], 0)
            .expect("write-only grantee updates map");
        assert_eq!(
            manager.map_lookup_for(2, map_id, &0u32.to_ne_bytes()),
            Err(BpfError::PermissionDenied)
        );
    }

    #[test]
    fn pinned_map_grant_table_is_bounded() {
        let mut manager = BpfManager::new();
        let map_id = manager
            .create_map_for(1, MapType::Array as u32, 4, 8, 1)
            .expect("owner map");
        manager
            .pin_map_for(1, "/bounded-grants".into(), map_id)
            .expect("pin map");

        for owner in 2..(MAX_MAP_GRANTS as u64 + 2) {
            assert_eq!(
                manager.get_pinned_map_for(owner, "/bounded-grants", MapAccess::READ_WRITE),
                Ok(map_id)
            );
        }
        assert_eq!(
            manager.get_pinned_map_for(
                MAX_MAP_GRANTS as u64 + 2,
                "/bounded-grants",
                MapAccess::READ_WRITE,
            ),
            Err(BpfError::ResourceLimit)
        );
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
        assert_eq!(second & handles::SLOT_MASK, first & handles::SLOT_MASK);
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
    fn program_map_helpers_cannot_exceed_credential_snapshot() {
        let mut manager = BpfManager::new_with_limits(tiny_limits());
        let owner = 1;
        let map_id = manager
            .create_map_for(owner, MapType::Array as u32, 4, 8, 1)
            .expect("owner map");
        let lookup = vec![
            BpfInsn::mov64_imm(1, 0),
            BpfInsn::new(0x7b, 10, 1, -8, 0),
            BpfInsn::mov64_imm(1, map_id as i32),
            BpfInsn::mov64_reg(2, 10),
            BpfInsn::add64_imm(2, -8),
            BpfInsn::call(HelperId::MapLookupElem as i32),
            BpfInsn::mov64_imm(0, 0),
            BpfInsn::exit(),
        ];

        assert_eq!(
            manager.load_raw_program_authorized(
                owner,
                lookup.clone(),
                BpfLoadAuthorization::new(LoadCaller::Privileged, false, MapAccess::NONE),
            ),
            Err(BpfError::VerificationFailed)
        );
        let lookup_id = manager
            .load_raw_program_authorized(
                owner,
                lookup,
                BpfLoadAuthorization::new(LoadCaller::Privileged, false, MapAccess::READ),
            )
            .expect("read capability permits map lookup helper");
        manager
            .unload_program_for(owner, lookup_id)
            .expect("unload lookup program");

        let update = vec![
            BpfInsn::mov64_imm(5, 0),
            BpfInsn::new(0x7b, 10, 5, -8, 0),
            BpfInsn::new(0x7b, 10, 5, -16, 0),
            BpfInsn::mov64_imm(1, map_id as i32),
            BpfInsn::mov64_reg(2, 10),
            BpfInsn::add64_imm(2, -8),
            BpfInsn::mov64_reg(3, 10),
            BpfInsn::add64_imm(3, -16),
            BpfInsn::mov64_imm(4, 0),
            BpfInsn::call(HelperId::MapUpdateElem as i32),
            BpfInsn::mov64_imm(0, 0),
            BpfInsn::exit(),
        ];
        assert_eq!(
            manager.load_raw_program_authorized(
                owner,
                update.clone(),
                BpfLoadAuthorization::new(LoadCaller::Privileged, false, MapAccess::READ),
            ),
            Err(BpfError::VerificationFailed)
        );
        let update_id = manager
            .load_raw_program_authorized(
                owner,
                update,
                BpfLoadAuthorization::new(LoadCaller::Privileged, false, MapAccess::WRITE),
            )
            .expect("write capability permits map update helper without read authority");
        manager
            .unload_program_for(owner, update_id)
            .expect("unload update program");
        manager
            .destroy_map_for(owner, map_id)
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
        assert_eq!(manager.resource_usage().pinned_maps, 1);
        assert!(manager
            .attachments
            .values()
            .all(|programs| !programs.contains(&program_id)));

        drop(in_flight);
        assert!(manager.reclaim_owner(7));
        assert_eq!(manager.resource_usage().live_programs, 0);
        assert_eq!(manager.resource_usage().live_maps, 1);
        assert_eq!(manager.resource_usage().pinned_maps, 1);
        assert_eq!(
            manager.get_pinned_map_for(8, "/owner-map", MapAccess::READ_WRITE),
            Ok(map_id)
        );
        assert_eq!(
            manager.unpin_map_for(8, "/owner-map", false),
            Err(BpfError::PermissionDenied)
        );
        manager
            .unpin_map_for(8, "/owner-map", true)
            .expect("object administrator cleans up orphaned pin");
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
    fn orphan_unpin_is_nonblocking_and_reclaims_after_program_quiescence() {
        let mut manager = BpfManager::new_with_limits(tiny_limits());
        let map_id = manager
            .create_map_for(7, MapType::Array as u32, 4, 8, 1)
            .expect("owner map");
        manager
            .pin_map_for(7, "/deferred-orphan".into(), map_id)
            .expect("pin owner map");
        let program_id = manager
            .load_raw_program_for(8, vec![BpfInsn::mov64_imm(0, 0), BpfInsn::exit()])
            .expect("unrelated live program");

        assert!(manager.reclaim_owner(7));
        manager
            .unpin_map_for(9, "/deferred-orphan", true)
            .expect("administrator removes orphan pin without waiting");
        assert_eq!(manager.resource_usage().pinned_maps, 0);
        assert_eq!(manager.resource_usage().live_maps, 1);

        manager
            .unload_program_for(8, program_id)
            .expect("quiesce unrelated program");
        assert_eq!(manager.resource_usage().live_maps, 0);
        assert_eq!(manager.resource_usage().map_bytes, 0);
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

        assert_eq!(
            manager.attachments[&ATTACH_TYPE_TIMER].len(),
            HOOK_FANOUT_LIMIT
        );
        assert!(ids[..HOOK_FANOUT_LIMIT]
            .iter()
            .all(|id| { Arc::strong_count(&manager.program_entry(*id).unwrap().program) == 1 }));
    }
}
