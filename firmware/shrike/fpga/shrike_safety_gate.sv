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
    reg [31:0] pwm_count;
    reg estop_armed;
    reg [1:0] estop_release_sync;
    wire [11:0] left_magnitude = left_duty_permille[11] ? -left_duty_permille : left_duty_permille;
    wire [11:0] right_magnitude = right_duty_permille[11] ? -right_duty_permille : right_duty_permille;
    wire envelope_ok = left_magnitude <= MAX_DUTY_PERMILLE && right_magnitude <= MAX_DUTY_PERMILLE;
    wire drive_enable = CONFIG_VALID && rst_n && estop_n
                     && estop_release_sync[1] && estop_armed
                     && command_valid && envelope_ok;
    wire [63:0] period_cycles_wide = PWM_PERIOD_CYCLES;
    wire [63:0] left_scaled = left_magnitude * period_cycles_wide;
    wire [63:0] right_scaled = right_magnitude * period_cycles_wide;
    wire [31:0] left_high_cycles = left_scaled / 1000;
    wire [31:0] right_high_cycles = right_scaled / 1000;

    always @(posedge clk or negedge rst_n or negedge estop_n) begin
        if (!rst_n || !estop_n) begin
            pwm_count <= 0; estop_armed <= 0; estop_release_sync <= 0;
        end
        else begin
            estop_release_sync <= {estop_release_sync[0], 1'b1};
            pwm_count <= !CONFIG_VALID || pwm_count == PWM_PERIOD_CYCLES - 1 ? 0 : pwm_count + 1;
            if (command_accept && estop_release_sync[1]) estop_armed <= 1;
        end
    end
    assign left_pwm_out = drive_enable && pwm_count < left_high_cycles;
    assign right_pwm_out = drive_enable && pwm_count < right_high_cycles;
    assign left_direction_out = drive_enable && left_duty_permille[11];
    assign right_direction_out = drive_enable && right_duty_permille[11];
    wire unused_pwm_inputs = left_pwm_in ^ right_pwm_in;
endmodule
