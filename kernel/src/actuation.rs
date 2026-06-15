//! The kernel-side actuation seam. Every normal actuation-magnitude path routes
//! through here: a request is decided by the global ARM-A monitor, then the
//! decision is applied to RP1 MMIO. The decision logic lives in
//! `kernel_bpf::actuation` (pure, host-tested); this file only owns the global
//! monitor and the MMIO application.

use kernel_bpf::actuation::{
    ActuationKind, ActuationRequest, AuditSource, Authority, ChannelId, Monitor,
};
use kernel_bpf::profile::ActiveProfile;
use spin::Mutex;

/// The single global actuation reference monitor.
pub static ACTUATION_MONITOR: Mutex<Monitor<ActiveProfile>> = Mutex::new(Monitor::new());

/// Route a PWM-duty request through ARM-A and apply the result to RP1 MMIO.
/// Returns 0 when motion proceeds (Allow/Clamp), -1 when policy intervened or
/// the request was invalid (Safe/Reject). The only *monitored* writer of PWM duty.
pub fn guard_pwm_with(
    chip: u8,
    channel: u8,
    duty: u32,
    authority: Authority,
    source: AuditSource,
) -> i64 {
    let ch = ChannelId {
        kind: ActuationKind::PwmDuty,
        chip,
        channel,
    };
    let now = crate::time::get_kernel_time_ns();
    let (value, code) = ACTUATION_MONITOR
        .lock()
        .decide(ActuationRequest { ch, value: duty }, authority, source, now)
        .apply();

    #[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
    {
        use crate::arch::aarch64::platform::rpi5::pwm::{PWM0, PWM1};
        if (1..=2).contains(&channel) {
            match chip {
                0 => PWM0.lock().set_duty_cycle(channel, value),
                1 => PWM1.lock().set_duty_cycle(channel, value),
                _ => {}
            }
        }
    }
    #[cfg(not(all(target_arch = "aarch64", feature = "rpi5")))]
    let _ = value;

    code
}

pub fn guard_pwm(chip: u8, channel: u8, duty: u32) -> i64 {
    guard_pwm_with(
        chip,
        channel,
        duty,
        Authority::Learned,
        AuditSource::LearnedBehavior,
    )
}

/// Route a GPIO output-level request through ARM-A and apply it. The only
/// *monitored* writer of GPIO output level.
pub fn guard_gpio(pin: u8, level: u32) -> i64 {
    guard_gpio_with(
        pin,
        level,
        Authority::Learned,
        AuditSource::LearnedBehavior,
    )
}

pub fn guard_gpio_with(pin: u8, level: u32, authority: Authority, source: AuditSource) -> i64 {
    let ch = ChannelId {
        kind: ActuationKind::GpioLevel,
        chip: 0,
        channel: pin,
    };
    let now = crate::time::get_kernel_time_ns();
    let (value, code) = ACTUATION_MONITOR
        .lock()
        .decide(ActuationRequest { ch, value: level }, authority, source, now)
        .apply();

    #[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
    {
        if pin < crate::arch::aarch64::platform::rpi5::gpio::Rp1Gpio::NUM_PINS {
            // SAFETY: validated pin; kernel has exclusive GPIO access.
            let gpio = unsafe { crate::arch::aarch64::platform::rpi5::gpio::Rp1Gpio::new() };
            if value != 0 {
                gpio.set_high(pin);
            } else {
                gpio.set_low(pin);
            }
        }
    }
    #[cfg(not(all(target_arch = "aarch64", feature = "rpi5")))]
    let _ = value;

    code
}
