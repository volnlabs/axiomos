// exception_vectors.S - AArch64 Exception Vector Table
//
// ARM64 exception vectors are organized as:
//   - 4 exception types: Synchronous, IRQ, FIQ, SError
//   - 4 execution contexts: current EL SP0, current EL SPx, lower EL 64-bit, lower EL 32-bit
//   - Total: 16 entries, each 128 bytes (0x80)
//   - Table must be 2KB aligned
//
// This provides trampolines to Rust exception handlers.

.section .text
.global exception_vector_base
.global irq_stack_top

// Dedicated interrupt stack for AArch64
.section .bss.irq_stack
.align 16
irq_stack_bottom:
    .space 0x4000              // 16KB IRQ stack
irq_stack_top:

.section .text

// Emit a single debug byte to the Pi5 debug UART through higher-half alias.
// Clobbers x14/x15; use only after register context has been saved.
.macro uart_mark ch
    ldr     x14, =0xFFFF80107D001000
    mov     w15, #\ch
    str     w15, [x14]
.endm

// Macro to save context
// Allocates stack space and saves x0-x30, ELR_EL1, SPSR_EL1, and captures vector_entry_timestamp.
.macro save_context
    // Allocate 288 bytes (aligned to 16)
    // 31 GPRs (x0-x30) = 248 bytes
    // ELR_EL1 + SPSR_EL1 = 16 bytes
    // SP_EL0 = 8 bytes
    // vector_entry_timestamp = 8 bytes
    // Total = 280 bytes -> 288 for 16-byte alignment
    sub     sp, sp, #288

    // Preserve the interrupted x9 before using it as timestamp scratch.
    stp     x8, x9, [sp, #64]
    // Capture hardware timestamp as early as possible
    mrs     x9, cntvct_el0
    str     x9, [sp, #272]

    stp     x0, x1, [sp, #0]
    stp     x2, x3, [sp, #16]
    stp     x4, x5, [sp, #32]
    stp     x6, x7, [sp, #48]
    stp     x10, x11, [sp, #80]
    stp     x12, x13, [sp, #96]
    stp     x14, x15, [sp, #112]
    stp     x16, x17, [sp, #128]
    stp     x18, x19, [sp, #144]
    stp     x20, x21, [sp, #160]
    stp     x22, x23, [sp, #176]
    stp     x24, x25, [sp, #192]
    stp     x26, x27, [sp, #208]
    stp     x28, x29, [sp, #224]
    str     x30, [sp, #240]

    mrs     x9, elr_el1
    mrs     x10, spsr_el1
    stp     x9, x10, [sp, #248]

    mrs     x9, sp_el0
    str     x9, [sp, #264]
.endm

// Macro to restore context
// Restores x0-x30, ELR_EL1, SPSR_EL1 and frees stack space
.macro restore_context
    ldr     x9, [sp, #264]
    msr     sp_el0, x9

    ldp     x9, x10, [sp, #248]
    msr     elr_el1, x9
    msr     spsr_el1, x10

    ldr     x30, [sp, #240]
    ldp     x28, x29, [sp, #224]
    ldp     x26, x27, [sp, #208]
    ldp     x24, x25, [sp, #192]
    ldp     x22, x23, [sp, #176]
    ldp     x20, x21, [sp, #160]
    ldp     x18, x19, [sp, #144]
    ldp     x16, x17, [sp, #128]
    ldp     x14, x15, [sp, #112]
    ldp     x12, x13, [sp, #96]
    ldp     x10, x11, [sp, #80]
    ldp     x8, x9, [sp, #64]
    ldp     x6, x7, [sp, #48]
    ldp     x4, x5, [sp, #32]
    ldp     x2, x3, [sp, #16]
    ldp     x0, x1, [sp, #0]

    add     sp, sp, #288
.endm

// Macro to define a vector table entry
.macro vector_entry label
    .balign 0x80
    b \label
.endm

.balign 2048
exception_vector_base:
    // Current EL with SP0
    vector_entry curr_el_sp0_sync_handler
    vector_entry curr_el_sp0_irq_handler
    vector_entry curr_el_sp0_fiq_handler
    vector_entry curr_el_sp0_serror_handler

    // Current EL with SPx
    vector_entry curr_el_spx_sync_handler
    vector_entry curr_el_spx_irq_handler
    vector_entry curr_el_spx_fiq_handler
    vector_entry curr_el_spx_serror_handler

    // Lower EL using AArch64
    vector_entry lower_el_aarch64_sync_handler
    vector_entry lower_el_aarch64_irq_handler
    vector_entry lower_el_aarch64_fiq_handler
    vector_entry lower_el_aarch64_serror_handler

    // Lower EL using AArch32
    vector_entry lower_el_aarch32_sync_handler
    vector_entry lower_el_aarch32_irq_handler
    vector_entry lower_el_aarch32_fiq_handler
    vector_entry lower_el_aarch32_serror_handler

// Real handlers located outside the 2KB table
.section .text

.macro define_invalid_handler name, kind, source
\name:
    save_context
    mov     x0, #\kind
    mov     x1, #\source
    bl      handle_invalid_exception
    1: wfi
    b 1b
.endm

define_invalid_handler curr_el_sp0_sync_handler, 0, 0
    /*
    save_context
    mov     x0, #0
    mov     x1, #0
    bl      handle_invalid_exception
    restore_context
    
    eret
    */

define_invalid_handler curr_el_sp0_irq_handler, 1, 0
define_invalid_handler curr_el_sp0_fiq_handler, 2, 0
define_invalid_handler curr_el_sp0_serror_handler, 3, 0

curr_el_spx_sync_handler:
    save_context
    mov     x0, sp
    bl      handle_sync_exception
    mov     x0, sp
    bl      check_preemption
    restore_context

    eret

curr_el_spx_irq_handler:
    save_context
    mov     x0, sp
    bl      handle_irq
    mov     x0, sp
    bl      check_preemption
    restore_context
    eret

define_invalid_handler curr_el_spx_fiq_handler, 2, 1
define_invalid_handler curr_el_spx_serror_handler, 3, 1

lower_el_sync_call_wrapper:
    // Preserve caller LR across nested BL so RET returns to vector path.
    mov     x19, x30
    bl      handle_sync_exception
    mov     x30, x19
    ret

lower_el_aarch64_sync_handler:
    save_context
    mov     x0, sp
    bl      lower_el_sync_call_wrapper
    mov     x0, sp
    bl      check_preemption
    restore_context
    eret

lower_el_aarch64_irq_handler:
    save_context
    mov     x0, sp
    bl      handle_irq
    mov     x0, sp
    bl      check_preemption
    restore_context
    eret

define_invalid_handler lower_el_aarch64_fiq_handler, 2, 2
define_invalid_handler lower_el_aarch64_serror_handler, 3, 2

lower_el_aarch32_sync_handler:
    save_context
    mov     x0, #0
    mov     x1, #3
    bl      handle_invalid_exception
    restore_context
    
    eret
define_invalid_handler lower_el_aarch32_irq_handler, 1, 3
define_invalid_handler lower_el_aarch32_fiq_handler, 2, 3
define_invalid_handler lower_el_aarch32_serror_handler, 3, 3
