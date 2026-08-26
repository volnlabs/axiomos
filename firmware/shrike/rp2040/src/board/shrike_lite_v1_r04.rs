//! Shrike-lite V1.0/R0.4 RP2040 GPIO contract.
//!
//! Source: Vicharak Shrike commit 763d0a7dd9ebdfc3f61de148457d5c34f112f61e.
//! All GPIO on the board headers and FPGA interconnect are 3.3 V only.

pub const FPGA_CONFIG: [u8; 4] = [0, 1, 2, 3]; // MISO, SS, SCK, MOSI
pub const FPGA_CONTROL: [u8; 2] = [12, 13]; // PWR, EN
pub const FPGA_RUNTIME: [u8; 2] = [14, 15]; // FPGA GPIO18, GPIO17
pub const MCU_LED: u8 = 4;

pub const MOTOR_DIRECTION: [u8; 4] = [6, 7, 8, 9];
pub const ULTRASONIC: [u8; 2] = [10, 11]; // trigger, echo
pub const PI_UART: [u8; 2] = [16, 17]; // RP2040 TX, RX
pub const ESTOP_OBSERVE: u8 = 5;

const ASSIGNED: [u8; 18] = [0, 1, 2, 3, 12, 13, 14, 15, 4, 5, 6, 7, 8, 9, 10, 11, 16, 17];

pub const fn pin_is_assigned(pin: u8) -> bool {
    let mut i = 0;
    while i < ASSIGNED.len() {
        if ASSIGNED[i] == pin {
            return true;
        }
        i += 1;
    }
    false
}

pub const fn assignments_are_unique() -> bool {
    let mut i = 0;
    while i < ASSIGNED.len() {
        if ASSIGNED[i] > 29 {
            return false;
        }
        let mut j = i + 1;
        while j < ASSIGNED.len() {
            if ASSIGNED[i] == ASSIGNED[j] {
                return false;
            }
            j += 1;
        }
        i += 1;
    }
    true
}

const _: () = assert!(assignments_are_unique());
