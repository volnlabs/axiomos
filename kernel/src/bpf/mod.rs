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
use kernel_bpf::profile::ActiveProfile;
#[cfg(target_arch = "aarch64")]
use kernel_bpf::profile::PhysicalProfile;
use kernel_bpf::verifier::{Verifier, VerifyConfig};

/// Context size used for load-time verification.
///
/// The exact context size depends on the attach point — each hook passes a
/// different ctx struct (`SyscallTraceContext`, `SchedSwitchContext`, …) — and
/// the attach type is not known at load (attach is a separate syscall). Until
/// verification is repeated at attach time with the real program-type → ctx
/// binding, use a value that covers every kernel ctx struct so context reads
/// are not falsely rejected. Consequence: context-access bounds are not yet
/// *precisely* enforced at load (the attach-time-typing follow-up); every
/// size-independent safety check still is.
const VERIFY_CTX_SIZE: u32 = 256;

/// Map-value size used for load-time verification.
///
/// Precise per-lookup sizing needs the map id from each `bpf_map_lookup_elem`
/// threaded into the verifier (the loader knows the program's maps) — a
/// follow-up. Until then use a permissive value so map-using programs are not
/// falsely rejected.
const VERIFY_MAP_VALUE_SIZE: u32 = 256;

const fn verify_config() -> VerifyConfig {
    VerifyConfig {
        ctx_size: VERIFY_CTX_SIZE,
        map_value_size: VERIFY_MAP_VALUE_SIZE,
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
        }
    }

    pub fn load_program(&mut self, elf_bytes: &[u8]) -> Result<u32, BpfError> {
        let mut loader = BpfLoader::<ActiveProfile>::new();
        let obj = loader.load(elf_bytes).map_err(|_| BpfError::NotLoaded)?;

        if let Some(loaded_prog) = obj.programs().first() {
            // Verify before accepting: rejects unsafe bytecode and computes the
            // real stack usage (no longer the hardcoded 0). #48.
            let bpf_prog = Verifier::<ActiveProfile>::verify_with_config(
                loaded_prog.prog_type(),
                loaded_prog.insns(),
                verify_config(),
            )
            .map_err(|e| {
                log::error!("BpfManager: ELF program rejected by verifier: {}", e);
                BpfError::VerificationFailed
            })?;

            let id = self.programs.len() as u32;
            self.programs.push(bpf_prog);
            Ok(id)
        } else {
            Err(BpfError::NotLoaded)
        }
    }

    pub fn load_raw_program(&mut self, insns: Vec<BpfInsn>) -> Result<u32, BpfError> {
        // Verify before accepting: this is the gate that makes the verifier
        // load-bearing — unsafe bytecode is rejected and the real stack usage is
        // computed rather than trusting a hardcoded 0. #48.
        let bpf_prog = Verifier::<ActiveProfile>::verify_with_config(
            BpfProgType::Unspec,
            &insns,
            verify_config(),
        )
        .map_err(|e| {
            log::error!("BpfManager: raw program rejected by verifier: {}", e);
            BpfError::VerificationFailed
        })?;

        let id = self.programs.len() as u32;
        self.programs.push(bpf_prog);
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

        let list = self.attachments.entry(attach_type).or_default();
        if !list.contains(&prog_id) {
            list.push(prog_id);
        }
        Ok(())
    }

    pub fn detach(&mut self, attach_type: u32, prog_id: u32) -> Result<(), BpfError> {
        if let Some(list) = self.attachments.get_mut(&attach_type) {
            if let Some(pos) = list.iter().position(|&id| id == prog_id) {
                list.remove(pos);
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
