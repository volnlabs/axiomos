// Link the unmodified production vector object. Handlers below are test fixtures.
.section .text.boot
.global _start
_start:
    msr daifset, #15
    ldr x0, =stack_top
    mov sp, x0
    ldr x0, =exception_vector_base
    msr vbar_el1, x0
    isb

.macro seed
    .irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30
        mov x\n, #(0x100 + \n)
    .endr
.endm

.macro check
    sub sp, sp, #256
    .irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30
        str x\n, [sp, #(8 * \n)]
    .endr
    mov x0, #0
1:  ldr x1, [sp, x0, lsl #3]
    add x2, x0, #0x100
    cmp x1, x2
    b.ne failed
    add x0, x0, #1
    cmp x0, #31
    b.ne 1b
    add sp, sp, #256
.endm

    seed
    svc #0
    check

    // QEMU virt GICv2: enable physical timer PPI 30 and the CPU interface.
    mov x0, #0x08000000
    mov w1, #1
    str w1, [x0]
    mov w1, #0x40000000
    str w1, [x0, #0x100]
    mov w1, #0x80
    add x2, x0, #0x400
    strb w1, [x2, #30]
    mov x0, #0x08010000
    mov w1, #0xff
    str w1, [x0, #4]
    mov w1, #1
    str w1, [x0]
    mov x0, #50000
    msr cntp_tval_el0, x0
    mov x0, #1
    msr cntp_ctl_el0, x0
    dsb sy
    isb
    seed
    msr daifclr, #2
    // Keep all canaries live until the real asynchronous timer IRQ arrives.
    wfi
    // Check IRQ count only after saving all registers.
    msr daifset, #2
    check
    ldr x0, =irq_count
    ldr x0, [x0]
    cmp x0, #1
    b.ne failed
    ldr x0, =success
    bl puts
    mov x2, #0
    b exit

failed:
    ldr x0, =failure
    bl puts
    mov x2, #1
exit:
    // SYS_EXIT_EXTENDED (ADP_Stopped_ApplicationExit, status).
    sub sp, sp, #16
    ldr x1, =0x20026
    str x1, [sp]
    str x2, [sp, #8]
    mov x1, sp
    mov x0, #0x20
    hlt #0xf000
    b .

puts:
    mov x1, #0x09000000
3:  ldrb w2, [x0], #1
    cbz w2, 4f
    str w2, [x1]
    b 3b
4:  ret

.global handle_sync_exception
handle_sync_exception:
    ret
.global handle_irq
handle_irq:
    mov x1, #0x08010000
    ldr w2, [x1, #12]
    mov x3, #0
    msr cntp_ctl_el0, x3
    str w2, [x1, #16]
    ldr x1, =irq_count
    ldr x2, [x1]
    add x2, x2, #1
    str x2, [x1]
    dsb sy
    ret
.global check_preemption
check_preemption:
    ret
.global handle_invalid_exception
handle_invalid_exception:
    b failed

.section .rodata
success: .asciz "PASS: production AArch64 SVC and IRQ preserve x0-x30\n"
failure: .asciz "FAIL: exception register or IRQ delivery canary\n"
.section .bss
.balign 8
irq_count: .skip 8
