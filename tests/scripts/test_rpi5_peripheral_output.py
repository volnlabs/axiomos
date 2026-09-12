#!/usr/bin/env python3
"""Run the actual GPIO setup methods against host register storage.

python3 tests/scripts/test_rpi5_peripheral_output.py
The unrelated AArch64 interrupt-dispatch tail is excluded from this host check.
"""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
GPIO = ROOT / "kernel/src/arch/aarch64/platform/rpi5/gpio.rs"
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


def main():
    with tempfile.TemporaryDirectory(prefix="rpi5-gpio-test-") as directory:
        path = Path(directory)
        source, separator, _ = GPIO.read_text().partition("/// Read the ARM generic timer counter")
        assert separator, "GPIO source boundary changed; review host test extraction"
        (path / "gpio.rs").write_text(source)
        (path / "main.rs").write_text(HARNESS)
        subprocess.run(["rustc", "--edition=2021", str(path / "main.rs"), "-o", str(path / "check")], check=True)
        subprocess.run([str(path / "check")], check=True)


if __name__ == "__main__":
    main()
