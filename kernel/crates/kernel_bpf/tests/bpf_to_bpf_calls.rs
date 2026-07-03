//! End-to-end: BPF-to-BPF calls normalize then verify.

use kernel_bpf::bytecode::insn::BpfInsn;
use kernel_bpf::bytecode::program::BpfProgType;
use kernel_bpf::loader::{LoadError, normalize};
use kernel_bpf::profile::ActiveProfile;
use kernel_bpf::verifier::{Verifier, VerifyConfig};

fn subprog_call(at: usize, target: usize) -> BpfInsn {
    let imm = target as i64 - at as i64 - 1;
    let mut i = BpfInsn::call(imm as i32);
    i.regs = (i.regs & 0x0f) | (1 << 4); // src_reg = BPF_PSEUDO_CALL
    i
}

#[test]
fn three_function_program_normalizes_and_verifies() {
    // main(0): call ->3 ; r0 unchanged ; exit
    // leaf(3): r0 = 1 ; exit
    let insns = vec![
        subprog_call(0, 3),
        BpfInsn::mov64_imm(0, 0),
        BpfInsn::exit(),
        BpfInsn::mov64_imm(0, 1),
        BpfInsn::exit(),
    ];
    let norm = normalize(&insns).expect("normalizes");
    assert!(!norm.insns.iter().any(|i| i.is_call() && i.src_reg() == 1));
    let prog = Verifier::<ActiveProfile>::verify_with_config(
        BpfProgType::SocketFilter,
        &norm.insns,
        VerifyConfig::default(),
    );
    assert!(
        prog.is_ok(),
        "verifier accepts normalized program: {:?}",
        prog.err()
    );
}

#[test]
fn recursive_program_is_rejected_at_normalization() {
    let insns = vec![subprog_call(0, 0), BpfInsn::exit()];
    assert_eq!(
        normalize(&insns).err(),
        Some(LoadError::RecursiveCall { subprog: 0 })
    );
}
