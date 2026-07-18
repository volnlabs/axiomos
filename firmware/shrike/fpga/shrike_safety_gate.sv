// SPDX-License-Identifier: MIT OR Apache-2.0
// Final hardware safety envelope for the Shrike-lite motor PWM outputs.
//
// This module is deliberately clockless.  Its safety response is a direct
// combinational gate: asserting the active-low e-stop, or presenting either
// motor command outside the configured signed per-mille envelope, forces BOTH
// PWM outputs low without waiting for RP2040 firmware, UART traffic, or a
// clock edge.  Direction pins may retain their state; a low PWM enable makes
// the H-bridge output safe.
//
// The RP2040 must route its signed MotorSetpoint values to `*_duty_permille`
// at the FPGA boundary and route its generated PWM signals through this
// module before the motor-driver ENA inputs.  Board pin assignments and the
// ForgeFPGA project are intentionally separate: they depend on the final
// Shrike-lite wiring revision.
module shrike_safety_gate #(
    // v0.4's kernel monitor currently emits forward-only commands in 0..=1000.
    // Keep hardware headroom below full scale; change only with matching
    // kernel envelope and physical validation.
    parameter integer MAX_DUTY_PERMILLE = 800
) (
    input  wire        estop_n,
    input  wire signed [11:0] left_duty_permille,
    input  wire signed [11:0] right_duty_permille,
    input  wire        left_pwm_in,
    input  wire        right_pwm_in,
    output wire        left_pwm_out,
    output wire        right_pwm_out
);

    function automatic command_in_range;
        input signed [11:0] duty;
        begin
            command_in_range = (duty >= -MAX_DUTY_PERMILLE)
                            && (duty <=  MAX_DUTY_PERMILLE);
        end
    endfunction

    // Fail closed: one invalid command disables both motors.  The e-stop is
    // intentionally not synchronized; its low assertion must propagate
    // immediately through the final PWM gate.
    wire envelope_ok = command_in_range(left_duty_permille)
                    && command_in_range(right_duty_permille);
    wire drive_enable = estop_n && envelope_ok;

    assign left_pwm_out = left_pwm_in && drive_enable;
    assign right_pwm_out = right_pwm_in && drive_enable;

endmodule
