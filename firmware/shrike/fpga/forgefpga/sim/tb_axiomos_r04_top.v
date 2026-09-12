`timescale 1ns/1ps
// SPDX-License-Identifier: GPL-2.0-only

module tb_axiomos_r04_top;
    localparam integer WATCHDOG_CYCLES = 2048;
    localparam integer TIGHT_HALF_PERIOD_NS = 60;
    localparam integer PWM_PERIOD_CYCLES = 20;

    reg clk;
    reg rst_n;
    reg spi_ss_n;
    reg spi_sck;
    reg spi_mosi;
    reg estop_n;
    reg left_pwm_in;
    reg right_pwm_in;
    wire clk_en;
    wire spi_miso;
    wire spi_miso_en;
    wire left_pwm_out;
    wire left_pwm_out_en;
    wire right_pwm_out;
    wire right_pwm_out_en;
    wire left_direction_out, left_direction_out_en;
    wire right_direction_out, right_direction_out_en;
    reg [7:0] last_status;
    reg [7:0] accepted_sequence;
    integer failures;

    top #(.COMMAND_TIMEOUT_CYCLES(WATCHDOG_CYCLES),
          .CLOCK_HZ(1000), .PWM_CARRIER_HZ(50)) dut (
        .clk(clk),
        .clk_en(clk_en),
        .rst_n(rst_n),
        .spi_ss_n(spi_ss_n),
        .spi_sck(spi_sck),
        .spi_mosi(spi_mosi),
        .spi_miso(spi_miso),
        .spi_miso_en(spi_miso_en),
        .estop_n(estop_n),
        .left_pwm_in(left_pwm_in),
        .right_pwm_in(right_pwm_in),
        .left_pwm_out(left_pwm_out),
        .left_pwm_out_en(left_pwm_out_en),
        .right_pwm_out(right_pwm_out),
        .right_pwm_out_en(right_pwm_out_en),
        .left_direction_out(left_direction_out),
        .left_direction_out_en(left_direction_out_en),
        .right_direction_out(right_direction_out),
        .right_direction_out_en(right_direction_out_en)
    );

    always #10 clk = ~clk;

    task check;
        input condition;
        input [8*80-1:0] message;
        begin
            if (!condition) begin
                failures = failures + 1;
                $display("FAIL: %0s", message);
            end
        end
    endtask

    task read_runtime_status;
        output [7:0] status_byte;
        output [7:0] accepted_sequence;
        begin
            begin_frame;
            transfer_byte(8'ha5, 100, status_byte);
            transfer_byte(8'h00, 100, accepted_sequence);
            end_frame;
        end
    endtask

    task check_pwm_period;
        input integer expected_left_high;
        input integer expected_right_high;
        input [8*80-1:0] message;
        integer cycle;
        integer left_high;
        integer right_high;
        begin
            left_high = 0;
            right_high = 0;
            @(negedge clk);
            for (cycle = 0; cycle < PWM_PERIOD_CYCLES; cycle = cycle + 1) begin
                @(posedge clk); #1;
                if (left_pwm_out) left_high = left_high + 1;
                if (right_pwm_out) right_high = right_high + 1;
            end
            check(left_high == expected_left_high && right_high == expected_right_high,
                  message);
        end
    endtask

    task transfer_byte;
        input [7:0] value;
        input integer half_period_ns;
        output [7:0] received;
        integer bit_index;
        reg sampled_before_edge;
        begin
            received = 8'h00;
            for (bit_index = 7; bit_index >= 0; bit_index = bit_index - 1) begin
                spi_mosi = value[bit_index];
                #(half_period_ns - 1);
                sampled_before_edge = spi_miso;
                spi_sck = 1'b1;
                #1;
                if (spi_miso !== sampled_before_edge) begin
                    failures = failures + 1;
                    $display("FAIL: MISO changed on the mode-0 sampling edge");
                end
                if (spi_miso_en !== 1'b1) begin
                    failures = failures + 1;
                    $display("FAIL: MISO output enable dropped while selected");
                end
                received = {received[6:0], spi_miso};
                #(half_period_ns - 1) spi_sck = 1'b0;
                #1;
            end
        end
    endtask

    task send_byte;
        input [7:0] value;
        reg [7:0] ignored;
        begin
            transfer_byte(value, 100, ignored);
        end
    endtask

    task send_partial_byte;
        input [7:0] value;
        input integer bit_count;
        integer bit_index;
        begin
            for (bit_index = 7; bit_index >= 8 - bit_count; bit_index = bit_index - 1) begin
                spi_mosi = value[bit_index];
                #99 spi_sck = 1'b1;
                #100 spi_sck = 1'b0;
                #1;
            end
        end
    endtask

    task begin_frame;
        begin
            spi_ss_n = 1'b0;
            #100;
        end
    endtask

    task end_frame;
        begin
            #100 spi_ss_n = 1'b1;
            #100;
        end
    endtask

    task send_command;
        input [7:0] version;
        input [7:0] msg_type;
        input [7:0] length;
        input [7:0] sequence;
        input [15:0] left;
        input [15:0] right;
        input [7:0] flags;
        input [7:0] crc_lo;
        input [7:0] crc_hi;
        begin
            begin_frame;
            transfer_byte(8'h7e, 100, last_status);
            send_byte(version);
            send_byte(msg_type);
            send_byte(length);
            send_byte(sequence);
            send_byte(left[7:0]);
            send_byte(left[15:8]);
            send_byte(right[7:0]);
            send_byte(right[15:8]);
            send_byte(flags);
            send_byte(crc_lo);
            send_byte(crc_hi);
            end_frame;
        end
    endtask

    task send_command_tight;
        input [7:0] sequence;
        input [15:0] left;
        input [15:0] right;
        input [7:0] crc_lo;
        input [7:0] crc_hi;
        reg [7:0] ignored;
        begin
            spi_ss_n = 1'b0;
            #TIGHT_HALF_PERIOD_NS;
            transfer_byte(8'h7e, TIGHT_HALF_PERIOD_NS, last_status);
            transfer_byte(8'h01, TIGHT_HALF_PERIOD_NS, ignored);
            transfer_byte(8'h01, TIGHT_HALF_PERIOD_NS, ignored);
            transfer_byte(8'h06, TIGHT_HALF_PERIOD_NS, ignored);
            transfer_byte(sequence, TIGHT_HALF_PERIOD_NS, ignored);
            transfer_byte(left[7:0], TIGHT_HALF_PERIOD_NS, ignored);
            transfer_byte(left[15:8], TIGHT_HALF_PERIOD_NS, ignored);
            transfer_byte(right[7:0], TIGHT_HALF_PERIOD_NS, ignored);
            transfer_byte(right[15:8], TIGHT_HALF_PERIOD_NS, ignored);
            transfer_byte(8'h00, TIGHT_HALF_PERIOD_NS, ignored);
            transfer_byte(crc_lo, TIGHT_HALF_PERIOD_NS, ignored);
            transfer_byte(crc_hi, TIGHT_HALF_PERIOD_NS, ignored);
            #TIGHT_HALF_PERIOD_NS spi_ss_n = 1'b1;
            #(2 * TIGHT_HALF_PERIOD_NS);
        end
    endtask

    task reset_dut;
        begin
            rst_n = 1'b0;
            spi_ss_n = 1'b1;
            spi_sck = 1'b0;
            spi_mosi = 1'b0;
            #100;
            check(left_pwm_out === 1'b0 && right_pwm_out === 1'b0,
                  "reset must force both PWM outputs low");
            check(spi_miso === 1'b0, "READY must be low during reset");
            rst_n = 1'b1;
            #100;
            check(spi_miso === 1'b1 && spi_miso_en === 1'b1,
                  "GPIO6/MISO must drive READY high after reset");
        end
    endtask

    initial begin
        clk = 1'b0;
        rst_n = 1'b0;
        spi_ss_n = 1'b1;
        spi_sck = 1'b0;
        spi_mosi = 1'b0;
        estop_n = 1'b1;
        left_pwm_in = 1'b1;
        right_pwm_in = 1'b1;
        failures = 0;
        last_status = 8'h00;

        reset_dut;
        check(left_pwm_out === 1'b0 && right_pwm_out === 1'b0,
              "no command must leave both outputs low");

        // Literal CRCs were independently generated from CRC16-CCITT/FALSE
        // over VER,TYPE,LEN,PAYLOAD. A frame is not visible before CRC_HI.
        begin_frame;
        transfer_byte(8'h7e, 100, last_status);
        check(last_status === 8'h80,
              "status must shift READY first with valid/expired clear");
        send_byte(8'h01); send_byte(8'h01); send_byte(8'h06);
        send_byte(8'h01); send_byte(8'h64); send_byte(8'h00);
        send_byte(8'h38); send_byte(8'hff); send_byte(8'h00); send_byte(8'h26);
        check(dut.command_valid === 1'b0 && dut.left_duty_permille === 12'sd0
              && dut.right_duty_permille === 12'sd0,
              "duties must not change before CRC_HI");
        send_byte(8'haf);
        check(dut.command_valid === 1'b0 && dut.left_duty_permille === 12'sd0
              && dut.right_duty_permille === 12'sd0,
              "CRC alone must not publish before exact transaction length is known");
        end_frame;
        check(dut.command_valid === 1'b1 && dut.left_duty_permille === 12'sd100
              && dut.right_duty_permille === -12'sd200,
              "exact valid frame must atomically commit both signed duties");
        left_pwm_in = 1'b0;
        right_pwm_in = 1'b1;
        check_pwm_period(2, 4,
              "FPGA must generate 10/20 percent duty independent of input PWM pins");

        begin_frame;
        send_byte(8'h7e); send_byte(8'h01); send_byte(8'h01); send_byte(8'h06);
        send_byte(8'h02); send_byte(8'hc8); send_byte(8'h00);
        send_byte(8'h2c); send_byte(8'h01); send_byte(8'h00);
        send_byte(8'he5); send_byte(8'h6e); send_byte(8'h00);
        end_frame;
        check(dut.command_valid === 1'b0 && dut.left_duty_permille === 12'sd100,
              "overlong frame must not publish validated prefix duties");

        send_command(8'h01, 8'h01, 8'h06, 8'h02, 16'd200, 16'd300,
                     8'h00, 8'he5, 8'h6f);
        check(last_status === 8'h80,
              "selected status must report READY and prior command validity MSB-first");
        check(dut.command_valid === 1'b0 && left_pwm_out === 1'b0
              && right_pwm_out === 1'b0,
              "CRC corruption must invalidate both outputs");

        send_command(8'h01, 8'h01, 8'h06, 8'h03, 16'd50, 16'd60,
                     8'h00, 8'hee, 8'h23);
        check(last_status === 8'h80,
              "status after CRC fault must clear command-valid bit");
        check(dut.command_valid === 1'b1, "fresh valid frame must recover");

        send_command(8'h02, 8'h01, 8'h06, 8'h04, 16'd50, 16'd60,
                     8'h00, 8'heb, 8'hc6);
        check(dut.command_valid === 1'b0, "bad version must invalidate command");
        send_command(8'h01, 8'h02, 8'h06, 8'h04, 16'd50, 16'd60,
                     8'h00, 8'hda, 8'h23);
        check(dut.command_valid === 1'b0, "bad type must invalidate command");
        send_command(8'h01, 8'h01, 8'h05, 8'h04, 16'd50, 16'd60,
                     8'h00, 8'h2d, 8'h33);
        check(dut.command_valid === 1'b0, "bad length must invalidate command");

        send_command(8'h01, 8'h01, 8'h06, 8'h0a, 16'd20, 16'd30,
                     8'h00, 8'h9b, 8'h46);
        check(dut.command_valid === 1'b1, "fresh sequence must commit");
        begin_frame;
        send_byte(8'h7e); send_byte(8'h01); send_byte(8'h01); send_byte(8'h06);
        send_byte(8'h0b);
        end_frame;
        check(dut.command_valid === 1'b0, "truncated frame must invalidate command");

        send_command(8'h01, 8'h01, 8'h06, 8'h0a, 16'd20, 16'd30,
                     8'h00, 8'h9b, 8'h46);
        check(dut.command_valid === 1'b0, "replayed sequence must be rejected");
        send_command(8'h01, 8'h01, 8'h06, 8'h09, 16'd40, 16'd50,
                     8'h00, 8'h19, 8'hfc);
        check(dut.command_valid === 1'b0, "stale sequence must be rejected");
        send_command(8'h01, 8'h01, 8'h06, 8'h0b, 16'd60, 16'd70,
                     8'h00, 8'hcd, 8'hfe);
        check(dut.command_valid === 1'b1, "newer sequence must recover");

        reset_dut;
        send_command(8'h01, 8'h01, 8'h06, 8'hff, 16'd10, 16'd20,
                     8'h00, 8'h15, 8'h98);
        check(dut.command_valid === 1'b1, "first sequence after reset must establish baseline");
        send_command(8'h01, 8'h01, 8'h06, 8'h00, 16'd30, 16'd40,
                     8'h00, 8'h32, 8'hf1);
        check(dut.command_valid === 1'b1 && dut.left_duty_permille === 12'sd30,
              "sequence 255 to 0 wrap must be accepted");

        reset_dut;
        send_command(8'h01, 8'h01, 8'h06, 8'h01, 16'd801, 16'd0,
                     8'h00, 8'h3e, 8'h69);
        check(dut.command_valid === 1'b0 && left_pwm_out === 1'b0
              && right_pwm_out === 1'b0,
              "+801 per-mille must fail closed");
        send_command(8'h01, 8'h01, 8'h06, 8'h02, -16'sd801, 16'd0,
                     8'h00, 8'h83, 8'h1c);
        check(dut.command_valid === 1'b0 && left_pwm_out === 1'b0
              && right_pwm_out === 1'b0,
              "-801 per-mille must fail closed");
        send_command(8'h01, 8'h01, 8'h06, 8'h03, 16'd100, 16'd100,
                     8'h00, 8'h36, 8'h0c);
        check(dut.command_valid === 1'b1, "valid frame after range faults must recover");

        begin_frame;
        send_byte(8'h7e); send_byte(8'h01); send_byte(8'h01); send_byte(8'h06);
        send_byte(8'h04);
        estop_n = 1'b0; #1;
        estop_n = 1'b1; repeat (3) @(posedge clk);
        send_byte(8'h64); send_byte(8'h00); send_byte(8'h64); send_byte(8'h00);
        send_byte(8'h00); send_byte(8'h77); send_byte(8'hc4); end_frame;
        check(dut.command_valid === 1'b0 && dut.last_sequence === 8'h03,
              "frame begun before e-stop must not complete after release");

        begin_frame;
        send_byte(8'h7e); send_byte(8'h01); send_byte(8'h01); send_byte(8'h06);
        send_byte(8'h04); send_byte(8'h64); send_byte(8'h00);
        send_byte(8'h64); send_byte(8'h00); send_byte(8'h00);
        send_byte(8'h77); send_byte(8'hc4);
        estop_n = 1'b0; #1;
        estop_n = 1'b1; repeat (3) @(posedge clk); end_frame;
        check(dut.command_valid === 1'b0 && dut.last_sequence === 8'h03,
              "e-stop before command CS completion must cancel staged acceptance");

        estop_n = 1'b0;
        #1;
        check(left_pwm_out === 1'b0 && right_pwm_out === 1'b0,
              "physical e-stop must dominate asynchronously");
        check(left_direction_out === 1'b0 && right_direction_out === 1'b0,
              "physical e-stop must force direction outputs safe low");
        estop_n = 1'b1;
        repeat (3) @(posedge clk); #1;
        check(left_pwm_out === 1'b0 && right_pwm_out === 1'b0,
              "e-stop release without a fresh command must remain disabled");

        send_command(8'h01, 8'h01, 8'h06, 8'h04, 16'd100, 16'd100,
                     8'h00, 8'h77, 8'hc4);
        check(dut.command_valid === 1'b1,
              "fresh full command after e-stop release must rearm motion");
        // Exact minimum CS setup: synchronized snapshot occurs on edge three;
        // the SPI shifter reloads it on edge four, before any physical SCK.
        @(negedge clk); #1 spi_ss_n = 1'b0;
        repeat (3) @(posedge clk); #1;
        check(dut.runtime_spi.miso_data === 8'h80,
              "status shifter must not expose the new snapshot before setup edge four");
        @(posedge clk); #1;
        check(dut.runtime_spi.miso_data === 8'hc0,
              "four FPGA setup edges must load the coherent first status byte");
        transfer_byte(8'ha5, 100, last_status);
        transfer_byte(8'h00, 100, accepted_sequence);
        end_frame;
        check(last_status === 8'hc0 && accepted_sequence === 8'h04
              && dut.command_valid === 1'b1,
              "post-commit status read must return coherent validity and accepted sequence");
        read_runtime_status(last_status, accepted_sequence);
        check(last_status === 8'hc0 && accepted_sequence === 8'h04,
              "repeated status read must be read-only");
        begin_frame; send_byte(8'ha5); end_frame;
        begin_frame; send_byte(8'ha5); send_byte(8'h00); send_byte(8'hff); end_frame;
        check(dut.command_valid === 1'b1 && dut.last_sequence === 8'h04,
              "short or long status reads must have no safety authority");

        send_command(8'h01, 8'h01, 8'h06, 8'h05, 16'd100, 16'd100,
                     8'h01, 8'hf6, 8'h91);
        check(dut.command_valid === 1'b0 && left_pwm_out === 1'b0
              && right_pwm_out === 1'b0,
              "explicit link-fault flag must invalidate both outputs");
        send_command(8'h01, 8'h01, 8'h06, 8'h06, 16'd100, 16'd100,
                     8'h00, 8'h37, 8'h4f);
        check(dut.command_valid === 1'b1, "fresh clear-fault frame must recover");

        begin_frame;
        end_frame;
        check(dut.command_valid === 1'b0 && left_pwm_out === 1'b0
              && right_pwm_out === 1'b0,
              "zero-byte selected transaction must invalidate prior command");

        send_command(8'h01, 8'h01, 8'h06, 8'h07, 16'sd800, -16'sd800,
                     8'h00, 8'h13, 8'hb8);
        check(last_status === 8'h80 && dut.command_valid === 1'b1
              && dut.left_duty_permille === 12'sd800
              && dut.right_duty_permille === -12'sd800,
              "exact +800/-800 boundaries must be accepted");
        check(left_direction_out === 1'b0 && right_direction_out === 1'b1,
              "accepted +N/-N must drive independent directions");

        begin_frame;
        send_partial_byte(8'h7e, 3);
        end_frame;
        check(dut.command_valid === 1'b0 && left_pwm_out === 1'b0
              && right_pwm_out === 1'b0,
              "partial first byte must invalidate prior command");

        send_command(8'h01, 8'h01, 8'h06, 8'h08, -16'sd800, 16'sd800,
                     8'h00, 8'h03, 8'h20);
        check(last_status === 8'h80 && dut.command_valid === 1'b1
              && dut.left_duty_permille === -12'sd800
              && dut.right_duty_permille === 12'sd800,
              "exact -800/+800 boundaries must be accepted");
        check(left_direction_out === 1'b1 && right_direction_out === 1'b0,
              "accepted -N/+N must drive independent directions");

        repeat (WATCHDOG_CYCLES - 100) @(posedge clk);
        read_runtime_status(last_status, accepted_sequence);
        #1;
        check(last_status === 8'hc0 && accepted_sequence === 8'h08,
              "status and sequence must remain one pre-expiry CS-start snapshot");
        check(dut.command_valid === 1'b0 && dut.watchdog_expired === 1'b1
              && left_pwm_out === 1'b0 && right_pwm_out === 1'b0,
              "status read must not refresh the command watchdog");

        send_command(8'h01, 8'h01, 8'h06, 8'h09, 16'd100, 16'd100,
                     8'h00, 8'h34, 8'h8a);
        check(last_status === 8'ha0 && dut.command_valid === 1'b1
              && dut.watchdog_expired === 1'b0,
              "expired status must be exposed and fresh frame must recover");

        send_command(8'h01, 8'h01, 8'h06, 8'h0a, 16'd100, 16'd100,
                     8'h80, 8'h5c, 8'hd5);
        check(last_status === 8'hc0 && dut.command_valid === 1'b0,
              "reserved nonzero flags must fail closed");

        send_command_tight(8'h0b, 16'd123, -16'sd321, 8'h7c, 8'hc5);
        check(last_status === 8'h80 && dut.command_valid === 1'b1
              && dut.left_duty_permille === 12'sd123
              && dut.right_duty_permille === -12'sd321,
              "tight legal CS/SCK phasing must preserve mode-0 frame and status");
        check(spi_miso_en === 1'b1,
              "MISO output enable must remain driven when CS returns idle");

        send_command(8'h01, 8'h01, 8'h06, 8'h0c, 16'd0, 16'd0,
                     8'h00, 8'h44, 8'h1e);
        check(dut.command_valid === 1'b1, "zero command must be accepted");
        check_pwm_period(0, 0, "zero command must produce no PWM pulses");

        rst_n = 1'b0;
        #1;
        check(dut.command_valid === 1'b0 && left_pwm_out === 1'b0
              && right_pwm_out === 1'b0,
              "explicit reset/link loss must clear command validity");

        check(clk_en === 1'b1 && left_pwm_out_en === 1'b1
              && right_pwm_out_en === 1'b1,
              "required clock/output enables must be driven");

        if (failures == 0)
            $display("PASS: axiomos_r04_forgefpga_runtime_link");
        else
            $display("FAIL: axiomos_r04_forgefpga_runtime_link (%0d checks)", failures);
        $finish;
    end
endmodule
