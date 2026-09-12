MEMORY {
    BOOT2 : ORIGIN = 0x10000000, LENGTH = 0x100
    /* R0.4 has 4 MB, but its factory layout reserves the upper 2 MB for
       LittleFS/FPGA bitstreams. Keep custom firmware inside the first 2 MB. */
    FLASH : ORIGIN = 0x10000100, LENGTH = 2048K - 0x100
    RAM   : ORIGIN = 0x20000000, LENGTH = 256K
}

EXTERN(BOOT2_FIRMWARE)

SECTIONS {
    /* The RP2040 second-stage bootloader must sit at the start of flash. */
    .boot2 ORIGIN(BOOT2) :
    {
        KEEP(*(.boot2));
    } > BOOT2
} INSERT BEFORE .text;
