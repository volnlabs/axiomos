//! PWM Syscall Implementation

use kernel_bpf::actuation::{AuditSource, Authority};

use crate::arch::aarch64::platform::rpi5::pwm::{PWM0, PWM1};

fn guard_pwm_zero(pwm_id: usize, channel: usize) -> isize {
    crate::actuation::guard_pwm_with(
        pwm_id as u8,
        channel as u8,
        0,
        Authority::Operator,
        AuditSource::SyscallPwm,
    ) as isize
}

fn valid_pwm_channel(channel: usize) -> bool {
    (1..=2).contains(&channel)
}

/// Configure PWM period/frequency
///
/// Arguments:
/// - `pwm_id`: 0 or 1 (PWM controller)
/// - `freq_hz`: Frequency in Hz
pub fn sys_pwm_config(pwm_id: usize, freq_hz: usize) -> isize {
    if !(0..=1).contains(&pwm_id) || freq_hz == 0 {
        return -1;
    }

    if guard_pwm_zero(pwm_id, 1) < 0 || guard_pwm_zero(pwm_id, 2) < 0 {
        return -1;
    }

    match pwm_id {
        0 => {
            let pwm = PWM0.lock();
            pwm.set_frequency(1, freq_hz as u32);
            pwm.set_frequency(2, freq_hz as u32); // Set both channels to same freq for now
            0
        }
        1 => {
            let pwm = PWM1.lock();
            pwm.set_frequency(1, freq_hz as u32);
            pwm.set_frequency(2, freq_hz as u32);
            0
        }
        _ => -1, // Invalid PWM ID
    }
}

/// Set PWM duty cycle
///
/// Arguments:
/// - `pwm_id`: 0 or 1
/// - `channel`: 1 or 2
/// - `duty_percent`: 0-100 (percentage)
pub fn sys_pwm_write(pwm_id: usize, channel: usize, duty_percent: usize) -> isize {
    crate::actuation::guard_pwm_with(
        pwm_id as u8,
        channel as u8,
        duty_percent as u32,
        Authority::Operator,
        AuditSource::SyscallPwm,
    ) as isize
}

/// Enable/Disable PWM channel
///
/// Arguments:
/// - `pwm_id`: 0 or 1
/// - `channel`: 1 or 2
/// - `enable`: 0 (disable) or 1 (enable)
pub fn sys_pwm_enable(pwm_id: usize, channel: usize, enable: usize) -> isize {
    if !(0..=1).contains(&pwm_id) || !valid_pwm_channel(channel) {
        return -1;
    }

    let prepared = guard_pwm_zero(pwm_id, channel);
    if enable != 0 && prepared < 0 {
        return -1;
    }

    match pwm_id {
        0 => {
            let pwm = PWM0.lock();
            if enable != 0 {
                pwm.enable(channel as u8);
            } else {
                pwm.disable(channel as u8);
            }
            0
        }
        1 => {
            let pwm = PWM1.lock();
            if enable != 0 {
                pwm.enable(channel as u8);
            } else {
                pwm.disable(channel as u8);
            }
            0
        }
        _ => -1,
    }
}
