//! Reference robot behaviors as verified BPF bytecode (v0.4).
//!
//! These are the three v0.4 demo behaviors — forward-drive, obstacle-stop, and
//! wall-follow — authored as BPF programs and proven to pass the verifier
//! ([`crate::verifier`]) under [`ActiveProfile`]. They drive motors through the
//! `bpf_pwm_write` helper, which the kernel routes via ARM-A to the Shrike link
//! (mapped channels) or local PWM. Sensor-reactive behaviors read the ultrasonic
//! echo from the IIO event's `value` field via the `ctx.data` pointer.
//!
//! Loading these onto a robot is hardware bring-up (M5); here they are the
//! verifier-validated source of truth, host-tested so a bytecode mistake is
//! caught without a board.

use alloc::vec::Vec;

use crate::bytecode::insn::BpfInsn;
use crate::verifier::helpers::HelperId;

// Actuation channels (must match control_link::motor_side: chip 0, L=1, R=2).
const CHIP: i32 = 0;
const LEFT: i32 = 1;
const RIGHT: i32 = 2;

// Registers.
const R0: u8 = 0;
const R1: u8 = 1;
const R2: u8 = 2;
const R3: u8 = 3;
const R6: u8 = 6; // ctx.data pointer (callee-saved)
const R7: u8 = 7; // left duty (callee-saved across helper calls)
const R8: u8 = 8; // right duty (callee-saved)

// Opcodes not covered by BpfInsn's named constructors.
const LDXDW: u8 = 0x79; // r_dst = *(u64*)(r_src + off)
const LDXW: u8 = 0x61; // r_dst = *(u32*)(r_src + off)
const JA: u8 = 0x05; // unconditional jump
const JGE_K: u8 = 0x35; // if r_dst >= imm (unsigned)
const JGT_K: u8 = 0x25; // if r_dst >  imm (unsigned)

/// IIO event `value` (the ultrasonic echo time) byte offset, reached through
/// `ctx.data`. Mirrors `IioEvent { timestamp:u64, device_id, channel, value@16 }`.
const IIO_VALUE_OFF: i16 = 16;

const PWM: i32 = HelperId::PwmWrite as i32;

/// `pwm_write(CHIP, channel, duty_reg)` — channel/chip immediate, duty from a reg.
fn pwm_write_reg(out: &mut Vec<BpfInsn>, channel: i32, duty_reg: u8) {
    out.push(BpfInsn::mov64_imm(R1, CHIP));
    out.push(BpfInsn::mov64_imm(R2, channel));
    out.push(BpfInsn::mov64_reg(R3, duty_reg));
    out.push(BpfInsn::call(PWM));
}

/// Load the ultrasonic echo (`IioEvent.value`) into `dst`: deref `ctx.data`
/// (`r1+0`) into R6, then read `value` at `+16`.
fn load_echo(out: &mut Vec<BpfInsn>, dst: u8) {
    out.push(BpfInsn::new(LDXDW, R6, R1, 0, 0)); // r6 = ctx.data
    out.push(BpfInsn::new(LDXW, dst, R6, IIO_VALUE_OFF, 0)); // dst = value
}

/// Forward-drive: both motors at `duty`. Attach to a periodic (timer) hook.
#[must_use]
pub fn forward_drive(duty: i32) -> Vec<BpfInsn> {
    let mut p = Vec::new();
    let mut drive = |ch: i32| {
        p.push(BpfInsn::mov64_imm(R1, CHIP));
        p.push(BpfInsn::mov64_imm(R2, ch));
        p.push(BpfInsn::mov64_imm(R3, duty));
        p.push(BpfInsn::call(PWM));
    };
    drive(LEFT);
    drive(RIGHT);
    p.push(BpfInsn::mov64_imm(R0, 0));
    p.push(BpfInsn::exit());
    p
}

/// Obstacle-stop: read the ultrasonic echo; if the echo is shorter than
/// `threshold` (obstacle close), command both motors to 0, else drive `duty`.
/// Attach to the IIO (ultrasonic) hook.
#[must_use]
pub fn obstacle_stop(threshold: i32, duty: i32) -> Vec<BpfInsn> {
    let mut p = Vec::new();
    load_echo(&mut p, R2); // r2 = echo_us
    p.push(BpfInsn::mov64_imm(R7, duty)); // default: drive
    // if echo >= threshold (clear) skip the stop; else r7 = 0.
    p.push(BpfInsn::new(JGE_K, R2, 0, 1, threshold));
    p.push(BpfInsn::mov64_imm(R7, 0)); // obstacle: stop
    pwm_write_reg(&mut p, LEFT, R7);
    pwm_write_reg(&mut p, RIGHT, R7);
    p.push(BpfInsn::mov64_imm(R0, 0));
    p.push(BpfInsn::exit());
    p
}

/// Wall-follow (discrete proportional): keep the wall echo near `target`.
/// Too close (echo < target) -> slow the right wheel (turn away); too far
/// (echo > target+band) -> slow the left wheel (turn toward); else straight.
/// `fast`/`slow` are the two duty levels. Attach to the IIO hook.
///
/// v0.4 ships the 3-level discrete form; continuous proportional (error*gain
/// with clamping) is a follow-up — it needs signed arithmetic the bang-bang
/// form avoids.
#[must_use]
pub fn wall_follow(target: i32, band: i32, fast: i32, slow: i32) -> Vec<BpfInsn> {
    let mut p = Vec::new();
    load_echo(&mut p, R2); // r2 = echo_us
    p.push(BpfInsn::mov64_imm(R7, fast)); // left default
    p.push(BpfInsn::mov64_imm(R8, fast)); // right default

    // echo < target (too close): right = slow (turn away), then go drive.
    // echo > target+band (too far): left = slow (turn toward).
    // otherwise (in band): straight (both fast).
    p.push(BpfInsn::new(JGE_K, R2, 0, 2, target)); // echo>=target -> skip too-close block (2)
    p.push(BpfInsn::mov64_imm(R8, slow)); // too close -> right slow
    p.push(BpfInsn::new(JA, 0, 0, 3, 0)); // -> drive (skip JGT, in-range JA, left-slow)
    p.push(BpfInsn::new(JGT_K, R2, 0, 1, target + band)); // too far -> skip the in-range JA
    p.push(BpfInsn::new(JA, 0, 0, 1, 0)); // in range -> straight (skip left-slow)
    p.push(BpfInsn::mov64_imm(R7, slow)); // too far -> left slow (turn toward)

    // drive both wheels.
    pwm_write_reg(&mut p, LEFT, R7);
    pwm_write_reg(&mut p, RIGHT, R8);
    p.push(BpfInsn::mov64_imm(R0, 0));
    p.push(BpfInsn::exit());
    p
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode::program::BpfProgType;
    use crate::profile::ActiveProfile;
    use crate::verifier::{MapPerm, Verifier, VerifyConfig};

    fn iio_config() -> VerifyConfig<'static> {
        VerifyConfig {
            ctx_size: core::mem::size_of::<crate::execution::BpfContext<'static>>() as u32,
            ctx_data_size: core::mem::size_of::<crate::attach::IioEvent>() as u32,
            map_perms: &[MapPerm::ReadWrite],
            allow_actuation: true,
            ..VerifyConfig::default()
        }
    }

    fn actuation_config() -> VerifyConfig<'static> {
        VerifyConfig {
            allow_actuation: true,
            ..VerifyConfig::default()
        }
    }

    fn verify(insns: &[BpfInsn], cfg: VerifyConfig) {
        Verifier::<ActiveProfile>::verify_with_config(BpfProgType::SocketFilter, insns, cfg)
            .expect("behavior must verify");
    }

    #[test]
    fn forward_drive_verifies() {
        verify(&forward_drive(60), actuation_config());
    }

    #[test]
    fn obstacle_stop_verifies() {
        verify(&obstacle_stop(1500, 60), iio_config());
    }

    #[test]
    fn wall_follow_verifies() {
        verify(&wall_follow(1500, 300, 60, 30), iio_config());
    }

    #[test]
    fn forward_drive_shape() {
        // 2 motor writes (4 insns each) + mov r0 + exit = 10.
        assert_eq!(forward_drive(60).len(), 10);
    }

    // ---- semantic tests: run the bytecode and observe motor commands ----
    use crate::attach::IioEvent;
    use crate::execution::{BpfContext, BpfExecutor, Interpreter, helpers_stub};

    /// Verify + run `insns` against a synthetic IIO event with the given echo,
    /// returning `(left_duty, right_duty)` actually commanded.
    fn run_with_echo(insns: &[BpfInsn], echo: i32) -> (i64, i64) {
        let prog = Verifier::<ActiveProfile>::verify_with_config(
            BpfProgType::SocketFilter,
            insns,
            iio_config(),
        )
        .expect("verify");
        let event = IioEvent {
            timestamp: 0,
            device_id: 0,
            channel: 0,
            value: echo,
            scale: 1_000_000,
            offset: 0,
            reserved: 0,
        };
        let ctx = BpfContext::from_struct(&event);
        helpers_stub::record_pwm(|| {
            let _ = Interpreter::<ActiveProfile>::new().execute(&prog, &ctx);
        })
    }

    #[test]
    fn obstacle_stop_drives_when_clear_stops_when_close() {
        let prog = obstacle_stop(1500, 60);
        // echo >= threshold -> clear -> drive both at 60
        assert_eq!(run_with_echo(&prog, 2000), (60, 60));
        // echo < threshold -> obstacle -> stop both
        assert_eq!(run_with_echo(&prog, 1000), (0, 0));
        // exactly at threshold counts as clear (>=)
        assert_eq!(run_with_echo(&prog, 1500), (60, 60));
    }

    #[test]
    fn wall_follow_three_zones() {
        // target=1500, band=300 -> in-range [1500, 1800]; fast=60, slow=30.
        let prog = wall_follow(1500, 300, 60, 30);
        // too close (echo < target): turn away -> left fast, right slow
        assert_eq!(run_with_echo(&prog, 1000), (60, 30));
        // in band: straight -> both fast
        assert_eq!(run_with_echo(&prog, 1650), (60, 60));
        // too far (echo > target+band): turn toward -> left slow, right fast
        assert_eq!(run_with_echo(&prog, 2500), (30, 60));
    }
}
