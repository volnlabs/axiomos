`timescale 1ns/1ps
// Derived from the pinned Vicharak spi_loopback_led ForgeFPGA scaffold.
// SPDX-License-Identifier: GPL-2.0-only
(* top *) module top (
    (* iopad_external_pin, clkbuf_inhibit *) input clk,
    (* iopad_external_pin *) output clk_en,
    (* iopad_external_pin *) input rst_n,
    (* iopad_external_pin *) input spi_ss_n,
    (* iopad_external_pin *) input spi_sck,
    (* iopad_external_pin *) input spi_mosi,
    (* iopad_external_pin *) output spi_miso,
    (* iopad_external_pin *) output spi_miso_en,
    (* iopad_external_pin *) input estop_n,
    (* iopad_external_pin *) input left_pwm_in,
    (* iopad_external_pin *) input right_pwm_in,
    (* iopad_external_pin *) output left_pwm_out,
    (* iopad_external_pin *) output left_pwm_out_en,
    (* iopad_external_pin *) output right_pwm_out,
    (* iopad_external_pin *) output right_pwm_out_en
);
    localparam [7:0] SYNC = 8'h7e;
    localparam [7:0] VERSION = 8'h01;
    localparam [7:0] MOTOR_TYPE = 8'h01;
    localparam [7:0] PAYLOAD_LENGTH = 8'h06;
    // Bit 0 is the explicit link-fault indication. Reserved bits also fail
    // closed, so only an all-clear flags byte can authorize motor PWM.
    localparam [7:0] FLAGS_CLEAR = 8'h00;

    wire [7:0] rx_data;
    wire rx_data_valid;
    wire spi_miso_data;
    wire spi_miso_oe_unused;
    wire [7:0] status;
    reg [2:0] ss_n_sync;
    reg [3:0] byte_index;
    reg frame_bad;
    reg [15:0] crc;
    reg [7:0] crc_lo;
    reg [7:0] frame_sequence;
    reg signed [15:0] frame_left;
    reg signed [15:0] frame_right;
    reg [7:0] frame_flags;
    reg sequence_valid;
    reg [7:0] last_sequence;
    reg command_valid;
    reg signed [11:0] left_duty_permille;
    reg signed [11:0] right_duty_permille;

    wire cs_rise;

    assign clk_en = 1'b1;
    assign spi_miso_en = 1'b1;
    assign left_pwm_out_en = 1'b1;
    assign right_pwm_out_en = 1'b1;
    assign status = {rst_n, command_valid, 6'b000000};
    assign spi_miso = spi_ss_n ? rst_n : spi_miso_data;
    assign cs_rise = ~ss_n_sync[2] & ss_n_sync[1];

    function [15:0] crc16_byte;
        input [15:0] crc_in;
        input [7:0] data;
        integer bit_index;
        reg [15:0] next_crc;
        begin
            next_crc = crc_in ^ {data, 8'h00};
            for (bit_index = 0; bit_index < 8; bit_index = bit_index + 1) begin
                if (next_crc[15])
                    next_crc = (next_crc << 1) ^ 16'h1021;
                else
                    next_crc = next_crc << 1;
            end
            crc16_byte = next_crc;
        end
    endfunction

    function command_in_range;
        input signed [15:0] duty;
        begin
            command_in_range = (duty >= -16'sd800) && (duty <= 16'sd800);
        end
    endfunction

    function sequence_is_newer;
        input [7:0] candidate;
        input [7:0] previous;
        reg [7:0] distance;
        begin
            distance = candidate - previous;
            sequence_is_newer = (distance != 8'd0) && (distance < 8'd128);
        end
    endfunction

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            ss_n_sync <= 3'b111;
        else
            ss_n_sync <= {ss_n_sync[1:0], spi_ss_n};
    end

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            byte_index <= 4'd0;
            frame_bad <= 1'b0;
            crc <= 16'hffff;
            crc_lo <= 8'h00;
            frame_sequence <= 8'h00;
            frame_left <= 16'sd0;
            frame_right <= 16'sd0;
            frame_flags <= 8'h00;
            sequence_valid <= 1'b0;
            last_sequence <= 8'h00;
            command_valid <= 1'b0;
            left_duty_permille <= 12'sd0;
            right_duty_permille <= 12'sd0;
        end else if (cs_rise) begin
            if (byte_index != 4'd0)
                command_valid <= 1'b0;
            byte_index <= 4'd0;
            frame_bad <= 1'b0;
            crc <= 16'hffff;
        end else if (rx_data_valid) begin
            case (byte_index)
                4'd0: begin
                    frame_bad <= (rx_data != SYNC);
                    if (rx_data != SYNC)
                        command_valid <= 1'b0;
                end
                4'd1: begin
                    crc <= crc16_byte(16'hffff, rx_data);
                    if (rx_data != VERSION) begin
                        frame_bad <= 1'b1;
                        command_valid <= 1'b0;
                    end
                end
                4'd2: begin
                    crc <= crc16_byte(crc, rx_data);
                    if (rx_data != MOTOR_TYPE) begin
                        frame_bad <= 1'b1;
                        command_valid <= 1'b0;
                    end
                end
                4'd3: begin
                    crc <= crc16_byte(crc, rx_data);
                    if (rx_data != PAYLOAD_LENGTH) begin
                        frame_bad <= 1'b1;
                        command_valid <= 1'b0;
                    end
                end
                4'd4: begin
                    frame_sequence <= rx_data;
                    crc <= crc16_byte(crc, rx_data);
                end
                4'd5: begin
                    frame_left[7:0] <= rx_data;
                    crc <= crc16_byte(crc, rx_data);
                end
                4'd6: begin
                    frame_left[15:8] <= rx_data;
                    crc <= crc16_byte(crc, rx_data);
                end
                4'd7: begin
                    frame_right[7:0] <= rx_data;
                    crc <= crc16_byte(crc, rx_data);
                end
                4'd8: begin
                    frame_right[15:8] <= rx_data;
                    crc <= crc16_byte(crc, rx_data);
                end
                4'd9: begin
                    frame_flags <= rx_data;
                    crc <= crc16_byte(crc, rx_data);
                end
                4'd10: crc_lo <= rx_data;
                4'd11: begin
                    if (!frame_bad
                        && ({rx_data, crc_lo} == crc)
                        && command_in_range(frame_left)
                        && command_in_range(frame_right)
                        && (frame_flags == FLAGS_CLEAR)
                        && (!sequence_valid
                            || sequence_is_newer(frame_sequence, last_sequence))) begin
                        left_duty_permille <= frame_left[11:0];
                        right_duty_permille <= frame_right[11:0];
                        last_sequence <= frame_sequence;
                        sequence_valid <= 1'b1;
                        command_valid <= 1'b1;
                    end else begin
                        command_valid <= 1'b0;
                    end
                    byte_index <= 4'd0;
                    frame_bad <= 1'b0;
                    crc <= 16'hffff;
                end
                default: begin
                    command_valid <= 1'b0;
                    byte_index <= 4'd0;
                    frame_bad <= 1'b0;
                    crc <= 16'hffff;
                end
            endcase
            if (byte_index != 4'd11)
                byte_index <= byte_index + 4'd1;
        end
    end

    spi_target runtime_spi (
        .i_clk(clk),
        .i_rst_n(rst_n),
        .i_enable(1'b1),
        .i_ss_n(spi_ss_n),
        .i_sck(spi_sck),
        .i_mosi(spi_mosi),
        .o_miso(spi_miso_data),
        .o_miso_oe(spi_miso_oe_unused),
        .o_rx_data(rx_data),
        .o_rx_data_valid(rx_data_valid),
        .i_tx_data(status)
    );

    shrike_safety_gate final_gate (
        .command_valid(command_valid),
        .estop_n(estop_n),
        .left_duty_permille(left_duty_permille),
        .right_duty_permille(right_duty_permille),
        .left_pwm_in(left_pwm_in),
        .right_pwm_in(right_pwm_in),
        .left_pwm_out(left_pwm_out),
        .right_pwm_out(right_pwm_out)
    );
endmodule
