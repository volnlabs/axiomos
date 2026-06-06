// Soundness oracle: a program accepted by the verifier must execute safely
// in the interpreter. "Safely" here means the interpreter terminates and
// returns either `Ok(value)` or `Err(BpfError)` — it must never panic, hang,
// or trigger UB.
//
// If this oracle ever finds an input the verifier accepts but the
// interpreter cannot execute, that's a soundness bug in the verifier — the
// most serious class of finding for this codebase. File the corpus input
// alongside an issue under `verifier-hardening` + `severity-critical`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use kernel_bpf::bytecode::insn::BpfInsn;
use kernel_bpf::bytecode::program::BpfProgType;
use kernel_bpf::execution::{BpfContext, BpfExecutor, Interpreter};
use kernel_bpf::profile::ActiveProfile;
use kernel_bpf::verifier::Verifier;

// BPF helper stubs. The interpreter calls these via `extern "C"`; they are
// supplied by the kernel at link time in normal builds. The fuzz harness
// runs in userspace and has to provide its own. Behaviour: return safe
// defaults; the verifier already enforces that programs treat helper
// returns as untrusted, so 0/null is fine. Side effects (writes, output)
// are no-ops — fuzzing isn't trying to validate helper behaviour, only the
// verify-then-exec soundness path.
//
// Kept in lockstep with `kernel_bpf::execution::helpers_stub`. If a new
// helper is added there, add the matching no-op here.
mod helper_stubs {
    use kernel_bpf::execution::BpfContext;

    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_ktime_get_ns() -> u64 { 0 }
    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_get_interrupt_latency_ns(ctx: *const BpfContext) -> u64 {
        if ctx.is_null() { 0 } else { unsafe { (*ctx).interrupt_latency_ns } }
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_get_boot_time_ms(ctx: *const BpfContext) -> u64 {
        if ctx.is_null() { 0 } else { unsafe { (*ctx).boot_time_ms } }
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_get_kernel_heap_kb(ctx: *const BpfContext) -> u64 {
        if ctx.is_null() { 0 } else { unsafe { (*ctx).kernel_heap_kb } }
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_get_kernel_image_mb(ctx: *const BpfContext) -> u64 {
        if ctx.is_null() { 0 } else { unsafe { (*ctx).kernel_image_mb } }
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_trace_printk(_fmt: *const u8, _len: u32) -> i32 { 0 }
    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_map_lookup_elem(_map_id: u32, _key: *const u8) -> *mut u8 {
        core::ptr::null_mut()
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_map_update_elem(
        _map_id: u32, _key: *const u8, _value: *const u8, _flags: u64,
    ) -> i32 { 0 }
    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_map_delete_elem(_map_id: u32, _key: *const u8) -> i32 { 0 }
    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_ringbuf_output(
        _map_id: u32, _data: *const u8, _size: u64, _flags: u64,
    ) -> i64 { 0 }
    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_gpio_read(_pin: u32) -> i64 { 0 }
    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_gpio_write(_pin: u32, _value: u32) -> i64 { 0 }
    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_pwm_write(_pwm_id: u32, _channel: u32, _duty: u32) -> i64 { 0 }
    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_timeseries_push(
        _map_id: u32, _key: *const u8, _value: *const u8,
    ) -> i64 { 0 }
    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_motor_emergency_stop(_reason: u32) -> i64 { 0 }
}

fn as_insns(data: &[u8]) -> &[BpfInsn] {
    const INSN_SIZE: usize = core::mem::size_of::<BpfInsn>();
    let usable = data.len() / INSN_SIZE * INSN_SIZE;
    if usable == 0 {
        return &[];
    }
    let ptr = data.as_ptr();
    if (ptr as usize) % core::mem::align_of::<BpfInsn>() != 0 {
        return &[];
    }
    // SAFETY: see verify_only.rs — BpfInsn is repr(C) POD; any bit pattern is
    // a syntactically valid (if potentially malformed) instruction.
    unsafe { core::slice::from_raw_parts(ptr as *const BpfInsn, usable / INSN_SIZE) }
}

fuzz_target!(|data: &[u8]| {
    let insns = as_insns(data);
    if insns.is_empty() {
        return;
    }

    // Only proceed to execution for programs the verifier accepts. The
    // verifier's contract is: anything I accept is safe to run.
    let program = match Verifier::<ActiveProfile>::verify(BpfProgType::SocketFilter, insns) {
        Ok(p) => p,
        Err(_) => return,
    };

    // Stand up a minimal context with no packet data. Programs that try to
    // dereference data/data_end should have been rejected by the verifier;
    // if one slips through, we'll see it here.
    let ctx = BpfContext::empty();
    let interp = Interpreter::<ActiveProfile>::new();

    // We don't care about the return value. Soundness is "this call does not
    // panic." If a verified program triggers UB, libfuzzer surfaces the
    // crash and we file an issue with the input.
    let _ = interp.execute(&program, &ctx);
});
