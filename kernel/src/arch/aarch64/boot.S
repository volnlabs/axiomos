// boot.S - Raspberry Pi 5 AArch64 Boot Entry Point
//
// Entry state from Pi firmware:
//   x0 = DTB physical address
//   x1-x3 = Reserved
//   Mode: EL2 (hypervisor) or EL1 (kernel)
//   MMU: Disabled
//   Caches: May be enabled by firmware
//
// This code:
//   1. Parks secondary cores (only core 0 continues)
//   2. Drops to EL1 if at EL2
//   3. Sets up the stack pointer
//   4. Clears BSS section
//   5. Sets up exception vector table
//   6. Calls Rust _start(dtb_addr)

.section .text.boot
.global _start_asm

.macro dbg_putc ch
#ifdef RPI5_DBG_UART
    // UART10 base: 0x10_7D00_1000 (Pi5 debug connector PL011)
    // Pi5-only: this address is unmapped on QEMU virt and data-aborts before
    // the exception vectors are installed, killing the boot silently.
    mov     x9, #0x1000
    movk    x9, #0x7d00, lsl #16
    movk    x9, #0x10, lsl #32
    mov     w10, #\ch
    str     w10, [x9]
#endif
.endm

_start_asm:
    dbg_putc 0x7b               // '{'

    // Save DTB address (passed in x0 from firmware)
    mov     x19, x0

    // Check CPU ID - only core 0 should continue
    mrs     x0, mpidr_el1
    and     x0, x0, #0xFF
    cbnz    x0, .Lpark_secondary

    // Check current exception level
    mrs     x0, CurrentEL
    lsr     x0, x0, #2
    cmp     x0, #2              // Check if EL2
    b.ne    .Lat_el1

    // We're at EL2, need to drop to EL1
    // Configure EL2 for EL1 execution
    mov     x0, #(1 << 31)      // RW=1 (AArch64 for EL1)
    orr     x0, x0, #(1 << 1)   // SWIO hardwired on
    msr     hcr_el2, x0

    // Disable traps from EL1 to EL2 for FP/SIMD/system access.
    msr     cptr_el2, xzr

    // Allow EL1 access to physical timer/counter.
    mov     x0, #0x3            // EL1PCTEN|EL1PCEN
    msr     cnthctl_el2, x0
    msr     cntvoff_el2, xzr

    // Set up SPSR for EL1h (SP_EL1, all interrupts masked)
    mov     x0, #0x3C5          // D=1, A=1, I=1, F=1, M=EL1h
    msr     spsr_el2, x0

    // Set return address to .Lat_el1
    adr     x0, .Lat_el1
    msr     elr_el2, x0

    // Exception return to EL1
    eret

.Lat_el1:
    dbg_putc 0x7c               // '|'

    // Now running at EL1
    // Set up stack pointer (stack grows downward)
    ldr     x0, =__stack_top
    mov     sp, x0

    // Clear BSS section
    ldr     x0, =__bss_start
    ldr     x1, =__bss_end

.Lclear_bss:
    cmp     x0, x1
    b.ge    .Lbss_done
    str     xzr, [x0], #8
    b       .Lclear_bss

.Lbss_done:
    // Enable FP/SIMD (Required for Rust)
    mov     x0, #(3 << 20)      // FPEN = 0b11
    msr     cpacr_el1, x0
    isb

    // Set up exception vector table
    ldr     x0, =exception_vector_base
    msr     vbar_el1, x0
    isb

    // Call Rust entry point with DTB address
    dbg_putc 0x7d               // '}'
    mov     x0, x19             // Restore DTB address
    bl      _start              // Call Rust _start(dtb_addr)

    // Should never return, but halt if it does
.Lhalt:
    wfi
    b       .Lhalt

// Secondary cores that enter via _start_asm (spin-table style firmware)
// park here. PSCI CPU_ON brings secondaries in at secondary_start instead.
.Lpark_secondary:
    wfe
    b       .Lpark_secondary

// -----------------------------------------------------------------------
// Secondary CPU entry (PSCI CPU_ON target)
//
// Entry state per PSCI: MMU off, caches off, interrupts masked, EL1 or EL2,
// x0 = context_id (unused; the CPU id is derived from MPIDR_EL1).
//
// IMPORTANT: no RAM writes (no stack) until the MMU + caches are on.
// With caches off, writes bypass coherency and core 0's dirty lines can
// clobber them later. The MMU register values come from SECONDARY_MMU_REGS,
// written and cleaned to PoC by core 0 before CPU_ON (smp.rs).
// -----------------------------------------------------------------------
.global secondary_start
secondary_start:
    // Drop to EL1 if entered at EL2 (same sequence as the primary path)
    mrs     x0, CurrentEL
    lsr     x0, x0, #2
    cmp     x0, #2
    b.ne    .Lsec_at_el1

    mov     x0, #(1 << 31)      // RW=1 (AArch64 for EL1)
    orr     x0, x0, #(1 << 1)   // SWIO hardwired on
    msr     hcr_el2, x0
    msr     cptr_el2, xzr
    mov     x0, #0x3            // EL1PCTEN|EL1PCEN
    msr     cnthctl_el2, x0
    msr     cntvoff_el2, xzr
    mov     x0, #0x3C5          // D=1, A=1, I=1, F=1, M=EL1h
    msr     spsr_el2, x0
    adr     x0, .Lsec_at_el1
    msr     elr_el2, x0
    eret

.Lsec_at_el1:
    // Invalidate local TLB before joining the shared address space
    tlbi    vmalle1
    dsb     nsh

    // Apply core 0's MMU configuration (reads only, cleaned to PoC by core 0)
    ldr     x0, =SECONDARY_MMU_REGS
    ldp     x1, x2, [x0]        // mair, tcr
    ldp     x3, x4, [x0, #16]   // ttbr0, ttbr1
    msr     mair_el1, x1
    msr     tcr_el1, x2
    msr     ttbr0_el1, x3
    msr     ttbr1_el1, x4
    isb

    // Enable MMU + D/I caches (same bits as paging::enable_mmu: M, C, I)
    mrs     x1, sctlr_el1
    mov     x2, #0x1005
    orr     x1, x1, x2
    msr     sctlr_el1, x1
    isb

    // Now coherent: safe to use RAM. Per-CPU stack, top = base + Aff0*16KB
    // (cpu N's stack occupies [base+(N-1)*16KB, base+N*16KB), grows down).
    mrs     x1, mpidr_el1
    and     x1, x1, #0xFF
    ldr     x0, =__secondary_stacks_bottom
    lsl     x2, x1, #14         // Aff0 * 16KB
    add     x0, x0, x2
    mov     sp, x0

    // Enable FP/SIMD (required for Rust)
    mov     x0, #(3 << 20)      // FPEN = 0b11
    msr     cpacr_el1, x0
    isb

    // Exception vector table (per-CPU register)
    ldr     x0, =exception_vector_base
    msr     vbar_el1, x0
    isb

    bl      secondary_rust

.Lsec_halt:
    wfi
    b       .Lsec_halt

// Stack allocation in BSS
.section .bss.stack
.align 16
.global __stack_bottom
__stack_bottom:
    .space 0x10000              // 64KB stack for boot core
.global __stack_top
__stack_top:
// 16KB per secondary core (cores 1..3). ponytail: bump if secondary IRQ
// paths ever grow deep call chains.
.global __secondary_stacks_bottom
__secondary_stacks_bottom:
    .space 0x4000 * 3
