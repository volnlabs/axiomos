//! Verifier performance benchmarks.

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use kernel_bpf::bytecode::insn::BpfInsn;
use kernel_bpf::bytecode::program::BpfProgType;
use kernel_bpf::profile::ActiveProfile;
use kernel_bpf::verifier::Verifier;

/// Benchmark verification of small programs.
fn bench_small_programs(c: &mut Criterion) {
    let mut group = c.benchmark_group("verifier/small");

    // Minimal valid program
    let minimal = vec![BpfInsn::mov64_imm(0, 0), BpfInsn::exit()];

    group.bench_function("minimal", |b| {
        b.iter(|| Verifier::<ActiveProfile>::verify(BpfProgType::SocketFilter, black_box(&minimal)))
    });

    // Simple arithmetic
    let arithmetic = vec![
        BpfInsn::mov64_imm(0, 100),
        BpfInsn::mov64_imm(1, 50),
        BpfInsn::add64_reg(0, 1),
        BpfInsn::sub64_imm(0, 25),
        BpfInsn::exit(),
    ];

    group.bench_function("arithmetic", |b| {
        b.iter(|| {
            Verifier::<ActiveProfile>::verify(BpfProgType::SocketFilter, black_box(&arithmetic))
        })
    });

    group.finish();
}

/// Benchmark verification scaling with program size.
fn bench_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("verifier/scaling");

    for insn_count in [10, 50, 100, 500, 1000] {
        // Build a program with N instructions
        let mut insns = Vec::with_capacity(insn_count);

        insns.push(BpfInsn::mov64_imm(0, 0));

        // Add arithmetic instructions
        for i in 1..insn_count - 1 {
            insns.push(BpfInsn::add64_imm(0, (i % 100) as i32));
        }

        insns.push(BpfInsn::exit());

        group.throughput(Throughput::Elements(insn_count as u64));
        group.bench_with_input(
            BenchmarkId::new("instructions", insn_count),
            &insn_count,
            |b, _| {
                b.iter(|| {
                    Verifier::<ActiveProfile>::verify(BpfProgType::SocketFilter, black_box(&insns))
                })
            },
        );
    }

    group.finish();
}

/// Benchmark verification with control flow.
fn bench_control_flow(c: &mut Criterion) {
    let mut group = c.benchmark_group("verifier/control_flow");

    // Linear control flow (no branches)
    let linear = vec![
        BpfInsn::mov64_imm(0, 0),
        BpfInsn::mov64_imm(1, 1),
        BpfInsn::mov64_imm(2, 2),
        BpfInsn::add64_reg(0, 1),
        BpfInsn::add64_reg(0, 2),
        BpfInsn::exit(),
    ];

    group.bench_function("linear", |b| {
        b.iter(|| Verifier::<ActiveProfile>::verify(BpfProgType::SocketFilter, black_box(&linear)))
    });

    // Single branch using jeq_imm
    let single_branch = vec![
        BpfInsn::mov64_imm(0, 10),
        BpfInsn::jeq_imm(0, 5, 2), // if r0 == 5, skip 2 (won't happen)
        BpfInsn::mov64_imm(0, 0),
        BpfInsn::ja(1),
        BpfInsn::mov64_imm(0, 1),
        BpfInsn::exit(),
    ];

    group.bench_function("single_branch", |b| {
        b.iter(|| {
            Verifier::<ActiveProfile>::verify(BpfProgType::SocketFilter, black_box(&single_branch))
        })
    });

    // Multiple branches
    let multi_branch = vec![
        BpfInsn::mov64_imm(0, 10),
        BpfInsn::mov64_imm(1, 20),
        BpfInsn::jeq_reg(0, 1, 3),  // if r0 == r1, skip 3
        BpfInsn::jeq_imm(0, 10, 1), // if r0 == 10, skip 1
        BpfInsn::mov64_imm(0, 0),
        BpfInsn::ja(1),
        BpfInsn::mov64_imm(0, 1),
        BpfInsn::exit(),
    ];

    group.bench_function("multi_branch", |b| {
        b.iter(|| {
            Verifier::<ActiveProfile>::verify(BpfProgType::SocketFilter, black_box(&multi_branch))
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_small_programs,
    bench_scaling,
    bench_control_flow,
);

criterion_main!(benches);
