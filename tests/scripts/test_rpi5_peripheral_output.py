#!/usr/bin/env python3
"""Run actual GPIO setup and PL011 byte methods against host register storage.

python3 tests/scripts/test_rpi5_peripheral_output.py
The unrelated AArch64 interrupt-dispatch tail is excluded from this host check.
"""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
GPIO = ROOT / "kernel/src/arch/aarch64/platform/rpi5/gpio.rs"
PL011 = ROOT / "kernel/src/arch/aarch64/platform/rpi5/pl011.rs"
HARNESS = r'''
#![allow(dead_code)]
mod memory_map {
    pub const RP1_GPIO_BASE: usize = 0;
    pub const RP1_PADS_BANK0_BASE: usize = 0x1000;
}
mod rp1_irq {
    pub struct Rp1InterruptRoute;
    pub struct Rp1InterruptRouteError;
    pub fn initialize_gpio_route() -> Result<Rp1InterruptRoute, Rp1InterruptRouteError> { unreachable!() }
    pub fn acknowledge_gpio_vector() { unreachable!() }
}
mod mmio {
    use std::sync::atomic::{AtomicU32, Ordering::SeqCst};
    static REGS: [AtomicU32; 4096] = [const { AtomicU32::new(0) }; 4096];
    pub struct MmioReg<T> { addr: usize, marker: std::marker::PhantomData<T> }
    impl MmioReg<u32> {
        pub unsafe fn new(addr: usize) -> Self {
            Self { addr, marker: std::marker::PhantomData }
        }
        pub fn read(&self) -> u32 { REGS[self.addr / 4].load(SeqCst) }
        pub fn write(&self, v: u32) { REGS[self.addr / 4].store(v, SeqCst); }
        pub fn modify(&self, f: impl FnOnce(u32) -> u32) { self.write(f(self.read())); }
    }
}
mod gpio;
fn main() {
    let gpio = unsafe { gpio::Rp1Gpio::new() };
    let ctrl = unsafe { mmio::MmioReg::new(12 * 8 + 4) };
    let pad = unsafe { mmio::MmioReg::new(0x1000 + 4 + 12 * 4) };
    for initial_high in [false, true] {
        ctrl.write(0x80);
        pad.write(0x96);
        gpio.configure_output(12, initial_high);
        assert_eq!(ctrl.read(), if initial_high { 0xf085 } else { 0xe085 });
        gpio.configure_peripheral_output(12, gpio::GpioFunction::Alt0);
        assert_eq!(ctrl.read(), 0xc080,
            "GPIO override must release to peripheral, preserving filter and output enable");
        assert_eq!(pad.read(), 0x56, "pad must remain enabled with input readback");
    }
    println!("PASS: GPIO LOW/HIGH -> peripheral releases forced level");
}
'''

UART_HARNESS = r'''
#![allow(dead_code)]
mod mmio {
    use std::sync::Mutex;
    struct Registers { words: [u32; 32], accesses: usize, writes: Vec<(usize, u32)>, error_on_flags: u32 }
    static REGS: Mutex<Registers> = Mutex::new(Registers {
        words: [0; 32], accesses: 0, writes: Vec::new(), error_on_flags: 0,
    });
    pub struct MmioReg<T> { addr: usize, marker: std::marker::PhantomData<T> }
    impl MmioReg<u32> {
        pub unsafe fn new(addr: usize) -> Self {
            Self { addr, marker: std::marker::PhantomData }
        }
        pub fn read(&self) -> u32 {
            let mut regs = REGS.lock().unwrap();
            regs.accesses += 1;
            assert!(regs.accesses <= 6, "a nonblocking operation must not poll");
            if self.addr == 0x18 { regs.words[1] |= regs.error_on_flags; }
            regs.words[self.addr / 4]
        }
        pub fn write(&self, value: u32) {
            let mut regs = REGS.lock().unwrap();
            regs.accesses += 1;
            assert!(regs.accesses <= 6, "a nonblocking operation must not poll");
            regs.words[self.addr / 4] = value;
            regs.writes.push((self.addr, value));
        }
    }
    pub fn prepare(flags: u32, status: u32, data: u32) {
        let mut regs = REGS.lock().unwrap();
        regs.words = [0; 32];
        regs.words[0x18 / 4] = flags;
        regs.words[0x04 / 4] = status;
        regs.words[0] = data;
        regs.accesses = 0;
        regs.writes.clear();
        regs.error_on_flags = 0;
    }
    pub fn late_error(error: u32) { REGS.lock().unwrap().error_on_flags = error; }
    pub fn writes() -> Vec<(usize, u32)> { REGS.lock().unwrap().writes.clone() }
}
mod pl011;
fn main() {
    let uart = unsafe { pl011::Pl011::new(0) };
    mmio::prepare(1 << 4, 0, 0);
    assert_eq!(uart.read_byte(), Ok(None));
    assert!(mmio::writes().is_empty());
    mmio::prepare(0, 0, 0xa5);
    assert_eq!(uart.read_byte(), Ok(Some(0xa5)));
    for errors in 1..=15 {
        // Per-byte errors and sticky errors with an empty FIFO are faults,
        // never observations that may contribute to a quiet interval.
        for empty in [false, true] {
            mmio::prepare(if empty { 1 << 4 } else { 0 },
                if empty { errors } else { 0 }, (errors << 8) | 0x5a);
            assert_eq!(uart.read_byte(), Err(pl011::ReceiveError(errors as u8)));
            assert_eq!(mmio::writes(), [(0x04, 0)]);
        }
    }
    mmio::prepare(1 << 4, 0, 0);
    mmio::late_error(8);
    assert_eq!(uart.read_byte(), Err(pl011::ReceiveError(8)),
        "an overrun latched by the empty-FIFO observation must not count as idle");
    mmio::prepare(1 << 5, 0, 0);
    assert!(!uart.try_write_byte(0xa5));
    assert!(mmio::writes().is_empty());
    mmio::prepare(0, 0, 0);
    assert!(uart.try_write_byte(0xa5));
    assert_eq!(mmio::writes(), [(0x00, 0xa5)]);
    for (flags, idle) in [(0, false), (1 << 7, true), ((1 << 7) | (1 << 3), false), (1 << 3, false)] {
        mmio::prepare(flags, 0, 0);
        assert_eq!(uart.tx_idle(), idle, "FIFO empty alone does not drain the shift register");
    }
    println!("PASS: actual PL011 RX faults, TX backpressure and physical-idle checks are bounded");
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix="rpi5-gpio-test-") as directory:
        path = Path(directory)
        source, separator, _ = GPIO.read_text().partition("/// Read the ARM generic timer counter")
        assert separator, "GPIO source boundary changed; review host test extraction"
        (path / "gpio.rs").write_text(source)
        (path / "main.rs").write_text(HARNESS)
        subprocess.run(["rustc", "--edition=2021", str(path / "main.rs"), "-o", str(path / "check")], check=True)
        subprocess.run([str(path / "check")], check=True)
        (path / "pl011.rs").write_text(PL011.read_text())
        (path / "main.rs").write_text(UART_HARNESS)
        subprocess.run(["rustc", "--edition=2021", str(path / "main.rs"), "-o", str(path / "check")], check=True)
        subprocess.run([str(path / "check")], check=True, timeout=5)


if __name__ == "__main__":
    main()
