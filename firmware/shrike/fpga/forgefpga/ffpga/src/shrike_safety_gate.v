`timescale 1ns/1ps
// SPDX-License-Identifier: MIT OR Apache-2.0
// Verilog-2005 port of the repository's final Shrike motor-PWM gate.
module shrike_safety_gate #(
    parameter integer MAX_DUTY_PERMILLE = 800
) (
    input wire command_valid,
    input wire estop_n,
    input wire signed [11:0] left_duty_permille,
    input wire signed [11:0] right_duty_permille,
    input wire left_pwm_in,
    input wire right_pwm_in,
    output wire left_pwm_out,
    output wire right_pwm_out
);
    function command_in_range;
        input signed [11:0] duty;
        begin
            command_in_range = (duty >= -MAX_DUTY_PERMILLE)
                            && (duty <= MAX_DUTY_PERMILLE);
        end
    endfunction

    wire envelope_ok;
    wire drive_enable;

    assign envelope_ok = command_in_range(left_duty_permille)
                       && command_in_range(right_duty_permille);
    assign drive_enable = command_valid && estop_n && envelope_ok;
    assign left_pwm_out = left_pwm_in && drive_enable;
    assign right_pwm_out = right_pwm_in && drive_enable;
endmodule
