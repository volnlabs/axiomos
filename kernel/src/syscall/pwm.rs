//! PWM Syscall Implementation

use kernel_bpf::actuation::{AuditSource, Authority};

use crate::arch::aarch64::platform::rpi5::pwm::{PWM0, PWM1};

fn guard_pwm_zero(pwm_id: usize, channel: usize) -> isize {
    if !valid_pwm_id(pwm_id) || !valid_pwm_channel(channel) {
        return -1;
    }

    crate::actuation::guard_pwm_with(
        pwm_id as u8,
        channel as u8,
        0,
        Authority::Operator,
        AuditSource::SyscallPwm,
    ) as isize
}

fn valid_pwm_id(pwm_id: usize) -> bool {
    (0..=1).contains(&pwm_id)
}

fn valid_pwm_channel(channel: usize) -> bool {
    (1..=2).contains(&channel)
}

fn motor_setpoint_from_abi(value: usize) -> Option<i32> {
    if value <= i32::MAX as usize {
        Some(value as i32)
    } else {
        let signed = value as i64;
        signed.is_negative().then_some(signed as i32)
    }
}

/// Configure PWM period/frequency
///
/// Arguments:
/// - `pwm_id`: 0 or 1 (PWM controller)
/// - `freq_hz`: Frequency in Hz
pub fn sys_pwm_config(pwm_id: usize, freq_hz: usize) -> isize {
    if !valid_pwm_id(pwm_id) || freq_hz == 0 {
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
/// - `duty_percent`: unsigned for ordinary PWM; signed i32 representation for
///   link-owned motor channels (same ABI word, sign selects direction)
pub fn sys_pwm_write(pwm_id: usize, channel: usize, duty_percent: usize) -> isize {
    if !valid_pwm_id(pwm_id) || !valid_pwm_channel(channel) {
        return -1;
    }
    if crate::actuation::is_motor_channel(pwm_id as u8, channel as u8) {
        let Some(setpoint) = motor_setpoint_from_abi(duty_percent) else {
            return -1;
        };
        return crate::actuation::guard_motor_with(
            pwm_id as u8,
            channel as u8,
            setpoint,
            Authority::Operator,
            AuditSource::SyscallPwm,
        ) as isize;
    }
    let Ok(duty_percent) = u32::try_from(duty_percent) else {
        return -1;
    };

    crate::actuation::guard_pwm_with(
        pwm_id as u8,
        channel as u8,
        duty_percent,
        Authority::Operator,
        AuditSource::SyscallPwm,
    ) as isize
}

#[cfg(test)]
mod tests {
    use super::motor_setpoint_from_abi;

    #[test]
    fn syscall_motor_abi_preserves_signed_direction() {
        assert_eq!(motor_setpoint_from_abi(25), Some(25));
        assert_eq!(motor_setpoint_from_abi((-25i64) as usize), Some(-25));
        assert_eq!(motor_setpoint_from_abi(i32::MAX as usize + 1), None);
    }
}

/// Enable/Disable PWM channel
///
/// Arguments:
/// - `pwm_id`: 0 or 1
/// - `channel`: 1 or 2
/// - `enable`: 0 (disable) or 1 (enable)
pub fn sys_pwm_enable(pwm_id: usize, channel: usize, enable: usize) -> isize {
    if !valid_pwm_id(pwm_id) || !valid_pwm_channel(channel) {
        return -1;
    }

    let prepared = guard_pwm_zero(pwm_id, channel);
    if prepared < 0 {
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
