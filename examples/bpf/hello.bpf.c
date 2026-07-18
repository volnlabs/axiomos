/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* 
 * hello.bpf.c - Simple Hello World BPF program for axiomos
 *
 * This is a minimal BPF program that demonstrates the basic structure
 * of a BPF program. It simply returns 0 (success).
 *
 * NOTE: This file is for documentation purposes. axiomos currently loads
 * raw BPF bytecode directly. To compile this to BPF bytecode:
 *
 *   clang -target bpf -O2 -c hello.bpf.c -o hello.bpf.o
 *
 * The resulting .o file contains BPF bytecode in ELF format.
 */

/* Helper function IDs (matching kernel_bpf::verifier::helpers) */
#define BPF_FUNC_ktime_get_ns     1
#define BPF_FUNC_trace_printk     2

/* BPF program section - marks as tracepoint */
__attribute__((section("tracepoint/syscalls/sys_enter")))
int hello_bpf(void *ctx)
{
    /* Return success */
    return 0;
}

/* Simple timer callback example */
__attribute__((section("timer")))
int timer_tick(void *ctx)
{
    /* 
     * In a real implementation, we would call:
     * bpf_trace_printk("Tick\n", 5);
     * 
     * But that requires a properly linked helper.
     * For now, just return 0.
     */
    return 0;
}

/* License declaration (required for BPF programs) */
char _license[] __attribute__((section("license"))) = "MIT";
