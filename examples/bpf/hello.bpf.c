/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* 
 * hello.bpf.c - Simple Hello World BPF program for axiomos
 *
 * This is a minimal BPF program that demonstrates the basic structure
 * of a BPF program. It simply returns 0 (success).
 *
 * The signed legacy ELF loader accepts exactly one entry and no maps.
 * This example is also the production signed-load smoke fixture. Compile with:
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

/* License declaration (required for BPF programs) */
char _license[] __attribute__((section("license"))) = "MIT";
