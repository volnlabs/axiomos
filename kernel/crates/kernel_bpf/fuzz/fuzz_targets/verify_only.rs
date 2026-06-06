// Crash oracle: the verifier must terminate on every input within bounded
// resources and never panic. A panic, OOM, or runaway here is a kernel
// denial-of-service.
//
// The verifier is also our gatekeeper for accepting BPF programs in the
// running kernel. If it can be wedged by adversarial bytecode, the entire
// "runtime-programmable kernel" claim is compromised — the attack surface
// for a malicious BPF blob includes both the program (caught by verifier
// guarantees) and the verifier itself (caught here).
//
// This target does not check soundness of the verifier's decisions; see
// `verify_then_exec` for that.

#![no_main]

use libfuzzer_sys::fuzz_target;
use kernel_bpf::bytecode::insn::BpfInsn;
use kernel_bpf::bytecode::program::BpfProgType;
use kernel_bpf::profile::ActiveProfile;
use kernel_bpf::verifier::Verifier;

/// Reinterpret a byte slice as `&[BpfInsn]` if length permits.
/// Returns an empty slice for inputs shorter than one instruction.
fn as_insns(data: &[u8]) -> &[BpfInsn] {
    // `BpfInsn` is 8 bytes, `#[repr(C)]`, all-POD. Safe to transmute a slice
    // of bytes whose length is a multiple of 8 and whose alignment is
    // compatible — libfuzzer's input is always heap-allocated `&[u8]` with
    // at least 8-byte alignment in practice, but we guard explicitly.
    const INSN_SIZE: usize = core::mem::size_of::<BpfInsn>();
    let usable = data.len() / INSN_SIZE * INSN_SIZE;
    if usable == 0 {
        return &[];
    }
    let ptr = data.as_ptr();
    if (ptr as usize) % core::mem::align_of::<BpfInsn>() != 0 {
        return &[];
    }
    // SAFETY: length truncated to a multiple of INSN_SIZE; alignment checked
    // above; BpfInsn is repr(C) with no padding and only POD fields, so any
    // bit-pattern is a valid (if possibly malformed) instruction. The
    // verifier is precisely the code under test for handling malformed input.
    unsafe { core::slice::from_raw_parts(ptr as *const BpfInsn, usable / INSN_SIZE) }
}

fuzz_target!(|data: &[u8]| {
    let insns = as_insns(data);
    if insns.is_empty() {
        return;
    }

    // We don't care about the result; only that the call returns. Panics or
    // hangs are what libfuzzer surfaces.
    let _ = Verifier::<ActiveProfile>::verify(BpfProgType::SocketFilter, insns);
});
