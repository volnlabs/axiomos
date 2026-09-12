`timescale 1ns/1ps
// SPDX-License-Identifier: MIT OR Apache-2.0
module shrike_safety_gate #(
    parameter integer MAX_DUTY_PERMILLE = 800,
    parameter integer CLOCK_HZ = 50000000,
    parameter integer PWM_CARRIER_HZ = 20000
) (
    input wire clk, input wire rst_n, input wire command_valid,
    input wire command_accept, input wire estop_n,
    input wire signed [11:0] left_duty_permille,
    input wire signed [11:0] right_duty_permille,
    input wire left_pwm_in, input wire right_pwm_in,
    output wire left_pwm_out, output wire right_pwm_out,
    output wire left_direction_out, output wire right_direction_out
);
    localparam integer PWM_PERIOD_CYCLES = PWM_CARRIER_HZ > 0
        ? CLOCK_HZ / PWM_CARRIER_HZ : 0;
    localparam CONFIG_VALID = PWM_CARRIER_HZ > 0
        && PWM_PERIOD_CYCLES > 0 && PWM_PERIOD_CYCLES <= 100000000;
    localparam integer COUNT_WIDTH = PWM_PERIOD_CYCLES > 1
        ? $clog2(PWM_PERIOD_CYCLES) : 1;
    reg [COUNT_WIDTH-1:0] pwm_count;
    localparam [COUNT_WIDTH-1:0] PWM_BEFORE_LAST = PWM_PERIOD_CYCLES > 1
        ? PWM_PERIOD_CYCLES - 2 : 0;
    reg pwm_wrap;
    reg estop_armed;
    reg [1:0] estop_release_sync;
    wire safety_rst_n = rst_n & estop_n;
    wire [11:0] left_magnitude = left_duty_permille[11] ? -left_duty_permille : left_duty_permille;
    wire [11:0] right_magnitude = right_duty_permille[11] ? -right_duty_permille : right_duty_permille;
    function within_default_envelope;
        input [11:0] duty;
        begin
            // Signed -800..800 is 0xce0..0xfff or 0x000..0x320.
            within_default_envelope = ((duty[11:10] == 2'b00)
                    && (duty[9:8] != 2'b11
                        || (duty[7:6] == 2'b00 && (!duty[5] || duty[4:0] == 5'b0))))
                || ((duty[11:10] == 2'b11)
                    && (duty[9] || duty[8] || duty[7:5] == 3'b111));
        end
    endfunction
    wire envelope_ok = MAX_DUTY_PERMILLE == 800
        ? within_default_envelope(left_duty_permille) && within_default_envelope(right_duty_permille)
        : left_magnitude <= MAX_DUTY_PERMILLE && right_magnitude <= MAX_DUTY_PERMILLE;
    wire drive_enable = CONFIG_VALID && rst_n && estop_n
                     && estop_release_sync[1] && estop_armed
                     && command_valid && envelope_ok;
    // Reduce the constant ratio before mapping: 2500/1000 becomes 5/2.
    // This preserves floor(magnitude * period / 1000), including calibration.
    function integer gcd;
        input integer a, b;
        integer remainder;
        begin
            while (b != 0) begin
                remainder = a % b;
                a = b;
                b = remainder;
            end
            gcd = a;
        end
    endfunction
    localparam integer SCALE_PERIOD = CONFIG_VALID ? PWM_PERIOD_CYCLES : 1;
    localparam integer SCALE_GCD = gcd(SCALE_PERIOD, 1000);
    localparam integer SCALE_NUMERATOR = SCALE_PERIOD / SCALE_GCD;
    localparam integer SCALE_WIDTH = 12 + $clog2(SCALE_NUMERATOR + 1);
    localparam [SCALE_WIDTH-1:0] SCALE_MULTIPLIER = SCALE_NUMERATOR;
    localparam [SCALE_WIDTH-1:0] SCALE_DIVISOR = 1000 / SCALE_GCD;
    wire [SCALE_WIDTH-1:0] left_scaled = left_magnitude * SCALE_MULTIPLIER;
    wire [SCALE_WIDTH-1:0] right_scaled = right_magnitude * SCALE_MULTIPLIER;
    wire [SCALE_WIDTH-1:0] left_high_cycles = left_scaled / SCALE_DIVISOR;
    wire [SCALE_WIDTH-1:0] right_high_cycles = right_scaled / SCALE_DIVISOR;

    always @(posedge clk or negedge safety_rst_n) begin
        if (!safety_rst_n) begin
            pwm_count <= 0; estop_armed <= 0; estop_release_sync <= 0;
            pwm_wrap <= !CONFIG_VALID || PWM_PERIOD_CYCLES <= 1;
        end
        else begin
            estop_release_sync <= {estop_release_sync[0], 1'b1};
            pwm_count <= pwm_wrap ? 0 : pwm_count + 1'b1;
            // Predict wrap for the next count; avoid a terminal decode on
            // the increment/reset path. Periods zero/one remain clamped.
            pwm_wrap <= !CONFIG_VALID || PWM_PERIOD_CYCLES <= 1
                || (!pwm_wrap && pwm_count == PWM_BEFORE_LAST);
            if (command_accept && estop_release_sync[1]) estop_armed <= 1;
        end
    end
    assign left_pwm_out = drive_enable && pwm_count < left_high_cycles;
    assign right_pwm_out = drive_enable && pwm_count < right_high_cycles;
    assign left_direction_out = drive_enable && left_duty_permille[11];
    assign right_direction_out = drive_enable && right_duty_permille[11];
    wire unused_pwm_inputs = left_pwm_in ^ right_pwm_in;
endmodule
