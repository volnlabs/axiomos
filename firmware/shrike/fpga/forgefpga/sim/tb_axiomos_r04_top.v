`timescale 1ns/1ps
// SPDX-License-Identifier: GPL-2.0-only

module tb_axiomos_r04_top;
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
    integer failures;

    top dut (
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
        .right_pwm_out_en(right_pwm_out_en)
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

    task send_byte;
        input [7:0] value;
        integer bit_index;
        begin
            for (bit_index = 7; bit_index >= 0; bit_index = bit_index - 1) begin
                spi_mosi = value[bit_index];
                #100 spi_sck = 1'b1;
                #100 spi_sck = 1'b0;
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
            send_byte(8'h7e);
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

        reset_dut;
        check(left_pwm_out === 1'b0 && right_pwm_out === 1'b0,
              "no command must leave both outputs low");

        // Literal CRCs were independently generated from CRC16-CCITT/FALSE
        // over VER,TYPE,LEN,PAYLOAD. A frame is not visible before CRC_HI.
        begin_frame;
        send_byte(8'h7e); send_byte(8'h01); send_byte(8'h01); send_byte(8'h06);
        send_byte(8'h01); send_byte(8'h64); send_byte(8'h00);
        send_byte(8'h38); send_byte(8'hff); send_byte(8'h00); send_byte(8'h26);
        check(dut.command_valid === 1'b0 && dut.left_duty_permille === 12'sd0
              && dut.right_duty_permille === 12'sd0,
              "duties must not change before CRC_HI");
        send_byte(8'haf);
        check(dut.command_valid === 1'b1 && dut.left_duty_permille === 12'sd100
              && dut.right_duty_permille === -12'sd200,
              "valid CRC must atomically commit both signed duties");
        end_frame;
        check(left_pwm_out === 1'b1 && right_pwm_out === 1'b1,
              "valid in-range command must pass both PWM inputs");

        send_command(8'h01, 8'h01, 8'h06, 8'h02, 16'd200, 16'd300,
                     8'h00, 8'he5, 8'h6f);
        check(dut.command_valid === 1'b0 && left_pwm_out === 1'b0
              && right_pwm_out === 1'b0,
              "CRC corruption must invalidate both outputs");

        send_command(8'h01, 8'h01, 8'h06, 8'h03, 16'd50, 16'd60,
                     8'h00, 8'hee, 8'h23);
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

        estop_n = 1'b0;
        #1;
        check(left_pwm_out === 1'b0 && right_pwm_out === 1'b0,
              "physical e-stop must dominate asynchronously");
        estop_n = 1'b1;
        #1;
        check(left_pwm_out === 1'b1 && right_pwm_out === 1'b1,
              "e-stop release may pass the still-valid command");

        send_command(8'h01, 8'h01, 8'h06, 8'h04, 16'd100, 16'd100,
                     8'h01, 8'h56, 8'hd4);
        check(dut.command_valid === 1'b0 && left_pwm_out === 1'b0
              && right_pwm_out === 1'b0,
              "explicit link-fault flag must invalidate both outputs");
        send_command(8'h01, 8'h01, 8'h06, 8'h05, 16'd100, 16'd100,
                     8'h00, 8'hd7, 8'h81);
        check(dut.command_valid === 1'b1, "fresh clear-fault frame must recover");

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
