#![no_std]
#![no_main]

// Keep the installed command name while retiring the unsafe PWM observer path.
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    minilib::write(2, b"pwm_demo retired: PWM observation hooks are unsupported. Use the actuation audit and external capture.\n");
    minilib::exit(1);
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    minilib::exit(1);
}
