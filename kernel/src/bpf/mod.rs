pub mod helpers;
pub mod jit_memory;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use kernel_abi::{BpfObjectInfo, BPF_OBJECT_KIND_MAP};
use kernel_bpf::bytecode::insn::BpfInsn;
use kernel_bpf::bytecode::program::{BpfProgType, BpfProgram};
use kernel_bpf::execution::{BpfContext, BpfError, BpfExecutor, Interpreter};
use kernel_bpf::loader::BpfLoader;
use kernel_bpf::maps::{ArrayMap, BpfMap, HashMap as BpfHashMap, RingBufMap, TimeSeriesMap};
use kernel_bpf::profile::{ActiveProfile, PhysicalProfile};
use kernel_bpf::signing::{SignatureVerifier, TrustedKey};
use kernel_bpf::verifier::admission::AdmissionLedger;
use kernel_bpf::verifier::{Verifier, VerifyConfig};

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
const VERIFY_CTX_SIZE: u32 = core::mem::size_of::<BpfContext>() as u32;

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

pub struct BpfManager {
    programs: Vec<BpfProgram<ActiveProfile>>,
    attachments: BTreeMap<u32, Vec<u32>>,
    maps: Vec<Box<dyn BpfMap<ActiveProfile>>>,
    pinned_maps: BTreeMap<String, u32>,
    /// Trust store for program provenance (#20). A program is authentic if it
    /// is an RBPF [`SignedProgram`] signed by a key in here.
    signature_verifier: SignatureVerifier,
    /// When true, programs without a signature container are accepted. Defaults
    /// to true for v0.1.x because no userspace signer ships yet; flip to false
    /// (via [`BpfManager::set_allow_unsigned`]) to enforce provenance.
    allow_unsigned: bool,
    /// Static WCET cycle bound per loaded program, indexed by prog id —
    /// `VerifyStats::wcet_cycles` captured at load (#43).
    prog_wcet: Vec<u64>,
    /// Utilization-form admission ledger: an attach is refused when the summed
    /// `Σ WCETᵢ·freqᵢ` of all admitted programs would exceed the profile's CPU
    /// utilization budget (#43).
    admission: AdmissionLedger,
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

impl Default for BpfManager {
    fn default() -> Self {
        Self::new()
    }
}

impl BpfManager {
    pub fn new() -> Self {
        Self {
            programs: Vec::new(),
            attachments: BTreeMap::new(),
            maps: Vec::new(),
            pinned_maps: BTreeMap::new(),
            signature_verifier: SignatureVerifier::new(),
            allow_unsigned: true,
            prog_wcet: Vec::new(),
            admission: AdmissionLedger::new(
                <ActiveProfile as PhysicalProfile>::UTILIZATION_BUDGET_NS_PER_S,
                <ActiveProfile as PhysicalProfile>::CYCLE_UNIT_NS,
            ),
        }
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

    /// Per-map value sizes indexed by map id (#123). A map's id is its index in
    /// `self.maps` (see [`create_map`](Self::create_map)), so this Vec, indexed
    /// by the constant map id a `bpf_map_lookup_elem` loads, gives that map's
    /// exact value size for the verifier to bound dereferences with.
    fn map_value_sizes(&self) -> Vec<u32> {
        self.maps.iter().map(|m| m.def().value_size).collect()
    }

    /// Build the verifier config for a load. Borrows `sizes` (built by
    /// [`map_value_sizes`](Self::map_value_sizes)) for the duration of the call.
    fn verify_config<'a>(&self, sizes: &'a [u32]) -> VerifyConfig<'a> {
        VerifyConfig {
            ctx_size: VERIFY_CTX_SIZE,
            map_value_size: VERIFY_MAP_VALUE_SIZE,
            map_value_sizes: sizes,
        }
    }

    pub fn load_program(&mut self, elf_bytes: &[u8]) -> Result<u32, BpfError> {
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
            // Verify before accepting: rejects unsafe bytecode and computes the
            // real stack usage (no longer the hardcoded 0). #48.
            let map_value_sizes = self.map_value_sizes();
            #[cfg(feature = "verifier-cost")]
            let insn_count = loaded_prog.insns().len();
            #[cfg(feature = "verifier-cost")]
            let start_cycles = read_cycles();
            let (bpf_prog, stats) = Verifier::<ActiveProfile>::verify_with_stats(
                loaded_prog.prog_type(),
                loaded_prog.insns(),
                self.verify_config(&map_value_sizes),
            )
            .map_err(|e| {
                log::error!("BpfManager: ELF program rejected by verifier: {}", e);
                BpfError::VerificationFailed
            })?;
            #[cfg(feature = "verifier-cost")]
            let verify_cycles = read_cycles().wrapping_sub(start_cycles);

            let id = self.programs.len() as u32;
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
            self.programs.push(bpf_prog);
            self.prog_wcet.push(stats.wcet_cycles);
            Ok(id)
        } else {
            Err(BpfError::NotLoaded)
        }
    }

    pub fn load_raw_program(&mut self, insns: Vec<BpfInsn>) -> Result<u32, BpfError> {
        // Raw instruction loads carry no signature container, so they cannot be
        // authenticated (#20). Reject them when enforcement is on.
        if !self.allow_unsigned {
            log::error!("BpfManager: raw program rejected (signature enforcement enabled)");
            return Err(BpfError::SignatureRejected);
        }

        // Verify before accepting: this is the gate that makes the verifier
        // load-bearing — unsafe bytecode is rejected and the real stack usage is
        // computed rather than trusting a hardcoded 0. #48.
        let map_value_sizes = self.map_value_sizes();
        #[cfg(feature = "verifier-cost")]
        let insn_count = insns.len();
        #[cfg(feature = "verifier-cost")]
        let start_cycles = read_cycles();
        let (bpf_prog, stats) = Verifier::<ActiveProfile>::verify_with_stats(
            BpfProgType::Unspec,
            &insns,
            self.verify_config(&map_value_sizes),
        )
        .map_err(|e| {
            log::error!("BpfManager: raw program rejected by verifier: {}", e);
            BpfError::VerificationFailed
        })?;
        #[cfg(feature = "verifier-cost")]
        let verify_cycles = read_cycles().wrapping_sub(start_cycles);

        let id = self.programs.len() as u32;
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
        self.programs.push(bpf_prog);
        self.prog_wcet.push(stats.wcet_cycles);
        log::info!(
            "BpfManager: Loaded raw program. Assigned id={}. Total programs={}",
            id,
            self.programs.len()
        );
        Ok(id)
    }

    pub fn attach(&mut self, attach_type: u32, prog_id: u32) -> Result<(), BpfError> {
        log::info!(
            "BpfManager: Attaching prog_id={} to type={}. Total programs={}",
            prog_id,
            attach_type,
            self.programs.len()
        );
        if prog_id as usize >= self.programs.len() {
            log::error!(
                "BpfManager: Attach failed. prog_id={} >= programs.len()={}",
                prog_id,
                self.programs.len()
            );
            return Err(BpfError::NotLoaded);
        }

        // Utilization admission (#43): attaching commits the CPU to running
        // this program on every fire; refuse if `Σ WCETᵢ·freqᵢ` across all
        // admitted hooks would exceed the profile's utilization budget.
        // Safe-but-unschedulable is rejected.
        let already_attached = self
            .attachments
            .get(&attach_type)
            .is_some_and(|list| list.contains(&prog_id));
        if !already_attached {
            let wcet = self.prog_wcet.get(prog_id as usize).copied().unwrap_or(0);
            let freq = hook_frequency_hz(attach_type);
            if let Err(e) = self.admission.admit(attach_type, prog_id, wcet, freq) {
                log::error!("BpfManager: {}", e);
                return Err(BpfError::AdmissionRejected);
            }
            self.attachments
                .entry(attach_type)
                .or_default()
                .push(prog_id);
        }
        Ok(())
    }

    pub fn detach(&mut self, attach_type: u32, prog_id: u32) -> Result<(), BpfError> {
        if let Some(list) = self.attachments.get_mut(&attach_type) {
            if let Some(pos) = list.iter().position(|&id| id == prog_id) {
                list.remove(pos);
                // Return this attachment's utilization to the budget.
                self.admission.release(attach_type, prog_id);
                return Ok(());
            }
        }
        Err(BpfError::NotLoaded)
    }

    pub fn execute(&self, program_id: u32, ctx: &BpfContext) -> Result<u64, BpfError> {
        let program = self
            .programs
            .get(program_id as usize)
            .ok_or(BpfError::NotLoaded)?;

        Self::execute_program(program, ctx)
    }

    /// Execute a BPF program directly (without needing &self).
    ///
    /// This is useful when the caller has already cloned the program
    /// and released the BpfManager lock, allowing BPF helpers to
    /// re-acquire the lock for map operations.
    pub fn execute_program(
        program: &BpfProgram<ActiveProfile>,
        ctx: &BpfContext,
    ) -> Result<u64, BpfError> {
        #[cfg(target_arch = "aarch64")]
        {
            if !<ActiveProfile as PhysicalProfile>::JIT_ALLOWED {
                let interpreter = Interpreter::<ActiveProfile>::new();
                return interpreter.execute(program, ctx);
            }

            use kernel_bpf::execution::Arm64JitExecutor;
            let executor = Arm64JitExecutor::<ActiveProfile>::new();
            executor.execute(program, ctx)
        }

        #[cfg(not(target_arch = "aarch64"))]
        {
            let interpreter = Interpreter::<ActiveProfile>::new();
            interpreter.execute(program, ctx)
        }
    }

    /// Clone a loaded program by id (verifier-cost instrumentation only).
    ///
    /// The bench path clones and then executes *outside* the manager lock,
    /// same as `run_hook_programs` — helpers like `bpf_map_lookup_elem`
    /// re-acquire the lock and would deadlock if it were held during runs.
    #[cfg(feature = "verifier-cost")]
    pub fn get_program(&self, prog_id: u32) -> Option<BpfProgram<ActiveProfile>> {
        self.programs.get(prog_id as usize).cloned()
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

    /// Collect cloned programs for a given attach type.
    ///
    /// Returns a Vec of (prog_id, cloned_program) pairs. This allows callers
    /// to release the BpfManager lock before executing programs, preventing
    /// deadlocks when BPF helpers (like bpf_ringbuf_output) need to re-acquire
    /// the lock to access maps.
    pub fn get_hook_programs(&self, attach_type: u32) -> Vec<(u32, BpfProgram<ActiveProfile>)> {
        let mut result = Vec::new();
        if let Some(progs) = self.attachments.get(&attach_type) {
            for &prog_id in progs {
                if let Some(program) = self.programs.get(prog_id as usize) {
                    result.push((prog_id, program.clone()));
                }
            }
        }
        result
    }

    pub fn run_hook_programs(
        attach_type: u32,
        ctx: &BpfContext,
        hook_name: &str,
    ) -> Result<usize, BpfError> {
        let Some(manager) = crate::BPF_MANAGER.get() else {
            return Ok(0);
        };

        let programs = manager.lock().get_hook_programs(attach_type);
        for (prog_id, program) in &programs {
            match Self::execute_program(program, ctx) {
                Ok(res) => {
                    if res != 0 {
                        log::info!("{hook_name} BPF Hook [id={prog_id}] returned: {res}");
                    }
                }
                Err(e) => {
                    log::error!("{hook_name} BPF Hook [id={prog_id}] failed: {:?}", e);
                    return Err(e);
                }
            }
        }

        Ok(programs.len())
    }

    pub fn execute_hooks(&self, attach_type: u32, ctx: &BpfContext) {
        if let Some(progs) = self.attachments.get(&attach_type) {
            for prog_id in progs {
                match self.execute(*prog_id, ctx) {
                    Ok(res) => {
                        if attach_type == ATTACH_TYPE_IIO {
                            log::info!("IIO BPF Hook [id={}] returned: {}", prog_id, res);
                        } else if attach_type == ATTACH_TYPE_PWM {
                            log::info!("PWM BPF Hook [id={}] returned: {}", prog_id, res);
                        } else if attach_type == ATTACH_TYPE_SYSCALL {
                            // Log only interesting syscalls or just debug info
                            // For demo purposes, we log everything if it returns non-zero
                            if res != 0 {
                                log::info!("Syscall Trace [id={}] syscall_nr: {}", prog_id, res);
                            }
                        }
                    }
                    Err(e) => log::error!("BPF Hook [id={}] failed: {:?}", prog_id, e),
                }
            }
        }
    }

    // --- Map operations ---

    pub fn create_map(
        &mut self,
        map_type: u32,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
    ) -> Result<u32, BpfError> {
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

        let id = self.maps.len() as u32;
        self.maps.push(map);
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
        self.maps.get(map_id as usize)?.lookup(key)
    }

    /// Look up a value by key and return a raw pointer.
    ///
    /// # Safety
    /// The caller must ensure the map will not be resized or deleted while the
    /// pointer is in use. The returned pointer is only valid while the map lock
    /// is held by the caller.
    pub unsafe fn map_lookup_ptr(&self, map_id: u32, key: &[u8]) -> Option<*mut u8> {
        // SAFETY: caller ensures map will not be resized or deleted while pointer is in use
        unsafe { self.maps.get(map_id as usize)?.lookup_ptr(key) }
    }

    pub fn map_update(
        &self,
        map_id: u32,
        key: &[u8],
        value: &[u8],
        flags: u64,
    ) -> Result<(), BpfError> {
        let map = self.maps.get(map_id as usize).ok_or(BpfError::NotLoaded)?;
        map.update(key, value, flags)
            .map_err(|_| BpfError::OutOfMemory)
    }

    pub fn map_delete(&self, map_id: u32, key: &[u8]) -> Result<(), BpfError> {
        let map = self.maps.get(map_id as usize).ok_or(BpfError::NotLoaded)?;
        map.delete(key).map_err(|_| BpfError::NotLoaded)
    }

    pub fn get_map_def(&self, map_id: u32) -> Option<&kernel_bpf::maps::MapDef> {
        self.maps.get(map_id as usize).map(|m| m.def())
    }

    pub fn pin_map(&mut self, path: String, map_id: u32) -> Result<(), BpfError> {
        if self.maps.get(map_id as usize).is_none() {
            return Err(BpfError::NotLoaded);
        }

        self.pinned_maps.insert(path, map_id);
        Ok(())
    }

    pub fn get_pinned_map(&self, path: &str) -> Option<u32> {
        self.pinned_maps.get(path).copied()
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

    /// Poll for the next event from a ring buffer map.
    ///
    /// Returns the event data if available, or None if the ringbuf is empty.
    /// This is used by the BPF_RINGBUF_POLL syscall command.
    pub fn ringbuf_poll(&self, map_id: u32) -> Option<Vec<u8>> {
        let map = self.maps.get(map_id as usize)?;
        // RingBufMap::lookup() delegates to poll(), which reads and advances the tail
        map.lookup(&[])
    }

    /// Output data to a ring buffer map.
    ///
    /// This is used by the bpf_ringbuf_output helper. For ringbuf maps,
    /// the key is ignored and value is the event data.
    pub fn ringbuf_output(&self, map_id: u32, data: &[u8], flags: u64) -> Result<(), BpfError> {
        let map = self.maps.get(map_id as usize).ok_or(BpfError::NotLoaded)?;

        // Ring buffer maps use update() with empty key to output data
        map.update(&[], data, flags)
            .map_err(|_| BpfError::OutOfMemory)
    }
}
