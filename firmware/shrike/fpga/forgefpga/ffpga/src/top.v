`timescale 1ns/1ps
// Derived from the pinned Vicharak spi_loopback_led ForgeFPGA scaffold.
// SPDX-License-Identifier: GPL-2.0-only
(* top *) module top #(
    // Default: 50 ms at the scaffold's stated 50 MHz clock. Calibrate this
    // count against the measured Forge clock before hardware acceptance.
    parameter integer COMMAND_TIMEOUT_CYCLES = 2500000,
    parameter integer CLOCK_HZ = 50000000,
    parameter integer PWM_CARRIER_HZ = 20000
) (
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
    (* iopad_external_pin *) output right_pwm_out_en,
    (* iopad_external_pin *) output left_direction_out,
    (* iopad_external_pin *) output left_direction_out_en,
    (* iopad_external_pin *) output right_direction_out,
    (* iopad_external_pin *) output right_direction_out_en
);
    localparam [7:0] SYNC = 8'h7e;
    localparam [7:0] VERSION = 8'h01;
    localparam [7:0] MOTOR_TYPE = 8'h01;
    localparam [7:0] PAYLOAD_LENGTH = 8'h06;
    // Bit 0 is explicit link fault. Reserved bits also fail closed.
    localparam [7:0] FLAGS_CLEAR = 8'h00;
    localparam [7:0] STATUS_READ = 8'ha5;

    // Selected MISO status byte, shifted MSB first in SPI mode 0.
    localparam integer STATUS_READY_BIT = 7;
    localparam integer STATUS_COMMAND_VALID_BIT = 6;
    localparam integer STATUS_WATCHDOG_EXPIRED_BIT = 5;

    wire [7:0] rx_data;
    wire [7:0] rx_next_data;
    wire rx_data_valid;
    wire spi_miso_data;
    wire spi_miso_oe_unused;
    wire spi_sample_pulse;
    wire [7:0] status;
    wire cs_rise;
    wire cs_fall;

    reg [2:0] ss_n_sync;
    reg [3:0] byte_index;
    reg [6:0] payload_phase;
    reg transaction_selected;
    reg transaction_accepted;
    reg transaction_end_pending;
    reg [6:0] transaction_bit_count;
    reg transaction_length_valid;
    reg frame_bad;
    reg [15:0] crc;
    reg [15:0] rx_crc_next;
    reg [7:0] crc_lo;
    reg [7:0] frame_sequence;
    reg signed [15:0] frame_left;
    reg signed [15:0] frame_right;
    reg [7:0] frame_flags;
    reg left_range_valid, right_range_valid, frame_sequence_valid;
    reg [3:0] left_range_parts, right_range_parts;
    reg rx_status_match;
    reg rx_prefix_match, rx_status_prefix_match;
    reg check_byte, allow_status, pre_reject;
    reg [7:0] expected_byte;
    reg frame_checks_valid, crc_low_match, rx_reject;
    reg sequence_valid;
    reg [7:0] last_sequence;
    reg command_valid;
    reg watchdog_expired;
    // The counter stops at the timeout; retain only reachable count bits.
    localparam integer WATCHDOG_WIDTH = COMMAND_TIMEOUT_CYCLES > 1
        ? $clog2(COMMAND_TIMEOUT_CYCLES) : 1;
    localparam [WATCHDOG_WIDTH-1:0] WATCHDOG_LAST = COMMAND_TIMEOUT_CYCLES > 1
        ? COMMAND_TIMEOUT_CYCLES - 1 : 0;
    reg [WATCHDOG_WIDTH-1:0] watchdog_count;
    reg watchdog_due;
    reg signed [11:0] left_duty_permille;
    reg signed [11:0] right_duty_permille;
    reg command_accept;
    reg status_read_selected;
    reg [7:0] status_snapshot;
    reg [7:0] sequence_snapshot;
    reg [1:0] estop_release_sync;
    wire safety_rst_n = rst_n & estop_n;

    assign clk_en = 1'b1;
    assign spi_miso_en = 1'b1;
    assign left_pwm_out_en = 1'b1;
    assign right_pwm_out_en = 1'b1;
    assign left_direction_out_en = 1'b1;
    assign right_direction_out_en = 1'b1;
    assign status[STATUS_READY_BIT] = rst_n;
    assign status[STATUS_COMMAND_VALID_BIT] = command_valid;
    assign status[STATUS_WATCHDOG_EXPIRED_BIT] = watchdog_expired;
    assign status[4:0] = 5'b00000;
    assign spi_miso = spi_ss_n ? rst_n : spi_miso_data;
    assign cs_rise = ~ss_n_sync[2] & ss_n_sync[1];
    assign cs_fall = ss_n_sync[2] & ~ss_n_sync[1];

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

    function [3:0] range_parts;
        input [15:0] duty;
        begin
            range_parts[3] = duty[15:10] == 6'b000000;
            range_parts[2] = duty[15:10] == 6'b111111;
            range_parts[1] = duty[9:8] != 2'b11
                || (duty[7:6] == 2'b00 && (!duty[5] || duty[4:0] == 5'b0));
            range_parts[0] = duty[9] || duty[8] || duty[7:5] == 3'b111;
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

    // CS initializes CRC; the sync byte does not update it.
    wire [15:0] crc_next_word = crc16_byte(crc, rx_next_data);

    // Match the same next shift word captured by the SPI receiver. These
    // checks and rx_data_valid register on the same edge, so the existing
    // byte-consumption edge sees both without another cycle of latency.
    always @(posedge clk or negedge safety_rst_n) begin
        if (!safety_rst_n) begin
            rx_status_match <= 1'b0;
            rx_prefix_match <= 1'b0; rx_status_prefix_match <= 1'b0;
            payload_phase <= 7'd0;
            check_byte <= 1'b0; allow_status <= 1'b0;
            pre_reject <= 1'b1; expected_byte <= 8'd0;
            frame_checks_valid <= 1'b0; crc_low_match <= 1'b0;
            rx_reject <= 1'b1;
            rx_crc_next <= 16'hffff;
            left_range_valid <= 1'b0; right_range_valid <= 1'b0;
            left_range_parts <= 4'b0; right_range_parts <= 4'b0;
            frame_sequence_valid <= 1'b0;
        end else begin
            rx_crc_next <= crc_next_word;
            // The first seven bits have settled before the eighth SCK rise.
            // Compare that prefix early, then qualify the final MOSI bit on
            // the same capture edge as rx_data_valid (no extra response cycle).
            rx_prefix_match <= rx_next_data[7:1] == expected_byte[7:1];
            rx_status_prefix_match <= rx_next_data[7:1] == STATUS_READ[7:1];
            rx_status_match <= rx_status_prefix_match
                && rx_next_data[0] == STATUS_READ[0];
            // Decode the payload destination between bytes, ahead of RX valid.
            payload_phase <= {byte_index == 4'd10, byte_index == 4'd9,
                byte_index == 4'd8, byte_index == 4'd7, byte_index == 4'd6,
                byte_index == 4'd5, byte_index == 4'd4};
            // The phase and completed payload settle between SPI bytes.
            // Decode them ahead of the final-bit capture, not on the byte
            // consumption/command-valid path.
            check_byte <= byte_index <= 4'd3 || byte_index == 4'd11;
            allow_status <= byte_index == 4'd0;
            case (byte_index)
                4'd0: expected_byte <= SYNC;
                4'd2: expected_byte <= MOTOR_TYPE;
                4'd3: expected_byte <= PAYLOAD_LENGTH;
                4'd11: expected_byte <= crc[15:8];
                default: expected_byte <= VERSION;
            endcase
            frame_checks_valid <= !frame_bad && left_range_valid
                && right_range_valid && frame_sequence_valid
                && frame_flags == FLAGS_CLEAR;
            crc_low_match <= crc_lo == crc[7:0];
            pre_reject <= byte_index >= 4'd12 || (byte_index == 4'd11
                && (!frame_checks_valid || !crc_low_match));
            rx_reject <= pre_reject || (check_byte
                && !(rx_prefix_match && rx_next_data[0] == expected_byte[0])
                && !(allow_status && rx_status_prefix_match
                    && rx_next_data[0] == STATUS_READ[0]));
            // Payload fields are stable well before the final CRC byte.
            // Split sign extension from the low-bit bound before combining.
            left_range_parts <= range_parts(frame_left);
            right_range_parts <= range_parts(frame_right);
            left_range_valid <= (left_range_parts[3] && left_range_parts[1])
                || (left_range_parts[2] && left_range_parts[0]);
            right_range_valid <= (right_range_parts[3] && right_range_parts[1])
                || (right_range_parts[2] && right_range_parts[0]);
            frame_sequence_valid <= !sequence_valid
                || sequence_is_newer(frame_sequence, last_sequence);
        end
    end

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            ss_n_sync <= 3'b111;
        else
            ss_n_sync <= {ss_n_sync[1:0], spi_ss_n};
    end

    always @(posedge clk or negedge safety_rst_n) begin
        if (!safety_rst_n)
            estop_release_sync <= 2'b00;
        else
            estop_release_sync <= {estop_release_sync[0], 1'b1};
    end

    wire history_enable;
    shrike_history_enable history_gate (
        .estop_n(estop_n), .end_pending(transaction_end_pending),
        .accepted(transaction_accepted), .length_valid(transaction_length_valid),
        .enable(history_enable)
    );

    // E-stop retains replay history and the selected transaction's snapshot.
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            sequence_valid <= 1'b0;
            last_sequence <= 8'h00;
            status_snapshot <= 8'h00;
            sequence_snapshot <= 8'h00;
        end else begin
            if (history_enable) begin
                last_sequence <= frame_sequence;
                sequence_valid <= 1'b1;
            end
            if (estop_n && cs_fall && estop_release_sync[1]) begin
                status_snapshot <= status;
                sequence_snapshot <= sequence_valid ? last_sequence : 8'h00;
            end
        end
    end

    wire frame_end = transaction_end_pending && !status_read_selected;
    // Accepted is only set inside a selected motor transaction and is cleared
    // together with selection at CS end/reset. Status reads never set it.
    wire frame_commit = transaction_end_pending && transaction_accepted
        && transaction_length_valid;
    wire rx_active;
    shrike_rx_active receive_gate (
        .valid(rx_data_valid), .selected(transaction_selected),
        .status_selected(status_read_selected), .active(rx_active)
    );
    wire reject_byte = rx_active && rx_reject;
    wire frame_bad_set = rx_active && byte_index <= 4'd3 && rx_reject;
    wire frame_bad_clear = transaction_end_pending
        || (cs_fall && estop_release_sync[1])
        || (rx_active && byte_index == 4'd0);

    // Eleven-bit pieces use a registered carry prediction. The carry flags
    // describe the current low bits, including pauses and commit resets.
    localparam integer WATCHDOG_LOW_WIDTH = WATCHDOG_WIDTH < 11 ? WATCHDOG_WIDTH : 11;
    wire [WATCHDOG_WIDTH-1:0] watchdog_increment;
    assign watchdog_increment[WATCHDOG_LOW_WIDTH-1:0]
        = watchdog_count[WATCHDOG_LOW_WIDTH-1:0] + 1'b1;
    genvar watchdog_bit;
    generate for (watchdog_bit = 11; watchdog_bit < WATCHDOG_WIDTH; watchdog_bit = watchdog_bit + 11) begin: watchdog_piece
        localparam integer PIECE_WIDTH = WATCHDOG_WIDTH - watchdog_bit < 11
            ? WATCHDOG_WIDTH - watchdog_bit : 11;
        reg carry;
        always @(posedge clk or negedge safety_rst_n) begin
            if (!safety_rst_n)
                carry <= 1'b0;
            else if (frame_commit)
                carry <= 1'b0;
            else if (command_valid && !watchdog_due)
                carry <= (&watchdog_count[watchdog_bit-1:1]) && !watchdog_count[0];
        end
        assign watchdog_increment[watchdog_bit +: PIECE_WIDTH]
            = watchdog_count[watchdog_bit +: PIECE_WIDTH] + carry;
    end endgenerate

    always @(posedge clk or negedge rst_n or negedge estop_n) begin
        if (!rst_n) begin
            byte_index <= 4'd0;
            transaction_selected <= 1'b0;
            transaction_accepted <= 1'b0;
            transaction_end_pending <= 1'b0;
            transaction_bit_count <= 7'd0;
            transaction_length_valid <= 1'b0;
            // Both resets invalidate the frame; a fresh qualified CS clears it.
            frame_bad <= 1'b1;
            crc <= 16'hffff;
            crc_lo <= 8'h00;
            frame_sequence <= 8'h00;
            frame_left <= 16'sd0;
            frame_right <= 16'sd0;
            frame_flags <= 8'h00;
            command_valid <= 1'b0;
            watchdog_expired <= 1'b0;
            watchdog_count <= 0;
            watchdog_due <= COMMAND_TIMEOUT_CYCLES <= 1;
            left_duty_permille <= 12'sd0;
            right_duty_permille <= 12'sd0;
            command_accept <= 1'b0;
            status_read_selected <= 1'b0;
        end else if (!estop_n) begin
            byte_index <= 4'd0;
            transaction_selected <= 1'b0;
            transaction_accepted <= 1'b0;
            transaction_end_pending <= 1'b0;
            transaction_bit_count <= 7'd0;
            transaction_length_valid <= 1'b0;
            frame_bad <= 1'b1;
            crc <= 16'hffff;
            crc_lo <= 8'h00;
            frame_sequence <= 8'h00;
            frame_left <= 16'sd0;
            frame_right <= 16'sd0;
            frame_flags <= 8'h00;
            command_valid <= 1'b0;
            watchdog_expired <= 1'b0;
            watchdog_count <= 0;
            watchdog_due <= COMMAND_TIMEOUT_CYCLES <= 1;
            left_duty_permille <= 12'sd0;
            right_duty_permille <= 12'sd0;
            command_accept <= 1'b0;
            status_read_selected <= 1'b0;
        end else begin
            command_accept <= 1'b0;
            // A rejecting header overrides CS/end clearing; good later
            // headers preserve prior errors without a priority mux chain.
            frame_bad <= frame_bad_set || (frame_bad && !frame_bad_clear);
            command_valid <= !reject_byte && (frame_commit
                || (command_valid && !frame_end && !watchdog_due));
            // Only a complete, fresh frame below resets this clock-derived
            // liveness bound. Traffic and rejected frames do not refresh it.
            if (command_valid) begin
                if (watchdog_due) begin
                    watchdog_expired <= 1'b1;
                end else begin
                    watchdog_count <= watchdog_increment;
                    // Predict expiry for the incremented count. Holds while
                    // counting is stopped; a commit resets both together.
                    watchdog_due <= watchdog_count == WATCHDOG_LAST - 1'b1;
                end
            end

            if (transaction_selected && spi_sample_pulse
                && transaction_bit_count != 7'd127) begin
                transaction_bit_count <= transaction_bit_count + 7'd1;
                transaction_length_valid <= transaction_bit_count == 7'd95;
            end

            // Delay CS-end validation one clock so a tightly phased final SPI
            // byte can commit before the exact-96-bit transaction is judged.
            if (transaction_end_pending) begin
                if (frame_commit) begin
                    left_duty_permille <= frame_left[11:0];
                    right_duty_permille <= frame_right[11:0];
                    watchdog_expired <= 1'b0;
                    watchdog_count <= 0;
                    watchdog_due <= COMMAND_TIMEOUT_CYCLES <= 1;
                    command_accept <= 1'b1;
                end
                transaction_selected <= 1'b0;
                status_read_selected <= 1'b0;
                transaction_accepted <= 1'b0;
                transaction_end_pending <= 1'b0;
                transaction_bit_count <= 7'd0;
                transaction_length_valid <= 1'b0;
                byte_index <= 4'd0;
                crc <= 16'hffff;
            end

            if (cs_fall && estop_release_sync[1]) begin
                transaction_selected <= 1'b1;
                transaction_accepted <= 1'b0;
                transaction_bit_count <= 7'd0;
                transaction_length_valid <= 1'b0;
                byte_index <= 4'd0;
                crc <= 16'hffff;
                status_read_selected <= 1'b0;
            end

            if (rx_data_valid && transaction_selected && status_read_selected)
                byte_index <= byte_index + 4'd1;
            if (rx_active) begin
                if (payload_phase[0]) frame_sequence <= rx_data;
                if (payload_phase[1]) frame_left[7:0] <= rx_data;
                if (payload_phase[2]) frame_left[15:8] <= rx_data;
                if (payload_phase[3]) frame_right[7:0] <= rx_data;
                if (payload_phase[4]) frame_right[15:8] <= rx_data;
                if (payload_phase[5]) frame_flags <= rx_data;
                if (payload_phase[6]) crc_lo <= rx_data;
                // One precomputed CRC word and one write enable replace the
                // repeated per-byte arithmetic/selection chain.
                if (byte_index >= 4'd1 && byte_index <= 4'd9)
                    crc <= rx_crc_next;
                case (byte_index)
                    4'd0: begin
                        if (rx_status_match)
                            status_read_selected <= 1'b1;
                    end
                    4'd1, 4'd2, 4'd3: begin end
                    4'd4, 4'd5, 4'd6, 4'd7, 4'd8, 4'd9, 4'd10: begin end
                    4'd11: begin
                        if (!rx_reject) begin
                            transaction_accepted <= 1'b1;
                        end else begin
                            transaction_accepted <= 1'b0;
                        end
                        byte_index <= 4'd12;
                    end
                    default: begin
                        transaction_accepted <= 1'b0;
                    end
                endcase
                if (byte_index < 4'd11)
                    byte_index <= byte_index + 4'd1;
            end

            if (cs_rise)
                transaction_end_pending <= 1'b1;
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
        .o_sample_pulse(spi_sample_pulse),
        .o_rx_data(rx_data),
        .o_rx_next_data(rx_next_data),
        .o_rx_data_valid(rx_data_valid),
        .i_tx_data(status_read_selected ? sequence_snapshot : status_snapshot)
    );

    shrike_safety_gate #(.CLOCK_HZ(CLOCK_HZ), .PWM_CARRIER_HZ(PWM_CARRIER_HZ)) final_gate (
        .clk(clk),
        .rst_n(rst_n),
        .command_valid(command_valid),
        .command_accept(command_accept),
        .estop_n(estop_n),
        .left_duty_permille(left_duty_permille),
        .right_duty_permille(right_duty_permille),
        .left_pwm_in(left_pwm_in),
        .right_pwm_in(right_pwm_in),
        .left_pwm_out(left_pwm_out),
        .right_pwm_out(right_pwm_out),
        .left_direction_out(left_direction_out),
        .right_direction_out(right_direction_out)
    );
endmodule

// Keep this four-input enable in one LUT. Sharing the motor-commit term
// followed by another e-stop gate lengthens the replay-history timing path.
(* keep_hierarchy *) module shrike_history_enable (
    input wire estop_n, end_pending, accepted, length_valid,
    output wire enable
);
    assign enable = estop_n & end_pending & accepted & length_valid;
endmodule

// Map the receive qualification to one LUT before flattening for Forge.
(* keep_hierarchy *) module shrike_rx_active (
    input wire valid, selected, status_selected,
    output wire active
);
    assign active = valid & selected & ~status_selected;
endmodule
