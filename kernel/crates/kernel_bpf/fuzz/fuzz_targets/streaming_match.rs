// Differential oracle: the path-sensitive `Verifier` and the streaming
// variant `StreamingVerifier` must agree on whether to accept a given
// program. They have different precision tradeoffs — the streaming
// verifier is documented to reject some programs the full one accepts —
// but they must never disagree on a clearly accepted or clearly rejected
// program in the corpus we expect to support.
//
// Concretely we relax the oracle to one direction:
//
//   accepted by streaming ⇒ accepted by full verifier
//
// The reverse direction (full accepts, streaming rejects) is acceptable by
// design. Any violation of the forward direction means streaming is
// strictly more permissive than full somewhere, which is a soundness bug.

#![no_main]

use libfuzzer_sys::fuzz_target;
use kernel_bpf::bytecode::insn::BpfInsn;
use kernel_bpf::bytecode::program::BpfProgType;
use kernel_bpf::profile::ActiveProfile;
use kernel_bpf::verifier::{StreamingVerifier, Verifier};

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
    // SAFETY: see verify_only.rs.
    unsafe { core::slice::from_raw_parts(ptr as *const BpfInsn, usable / INSN_SIZE) }
}

fuzz_target!(|data: &[u8]| {
    let insns = as_insns(data);
    if insns.is_empty() {
        return;
    }

    let streaming = StreamingVerifier::<ActiveProfile>::verify(BpfProgType::SocketFilter, insns);
    if streaming.is_err() {
        // Streaming rejected; full verifier may accept or reject. Either is fine.
        return;
    }

    // Streaming accepted. Full verifier must also accept, or streaming is
    // unsoundly permissive.
    let full = Verifier::<ActiveProfile>::verify(BpfProgType::SocketFilter, insns);
    assert!(
        full.is_ok(),
        "streaming verifier accepted a program the full verifier rejected — \
         streaming is more permissive than full, which is a soundness bug. \
         Reproduce with the corpus input that crashed this run."
    );
});
