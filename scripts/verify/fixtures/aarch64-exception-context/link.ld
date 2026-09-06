ENTRY(_start)
SECTIONS {
    . = 0x40080000;
    .text : { *(.text.boot) *(.text*) }
    .rodata : { *(.rodata*) }
    .data : { *(.data*) }
    .bss (NOLOAD) : { *(.bss*) . = ALIGN(16); . += 0x4000; stack_top = .; }
}
