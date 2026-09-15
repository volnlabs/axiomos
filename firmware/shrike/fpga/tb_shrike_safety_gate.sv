`timescale 1ns/1ps
module tb_shrike_safety_gate;
    reg clk = 0, rst_n = 1, command_valid = 0, command_accept = 0, estop_n = 1;
    reg signed [11:0] left_duty_permille = 0, right_duty_permille = 0;
    reg left_pwm_in = 0, right_pwm_in = 1;
    wire left_pwm_out, right_pwm_out;
    wire left_direction_out, right_direction_out;
    wire invalid_left_pwm_out, invalid_right_pwm_out;
    wire [4:0] scale_done;
    tb_pwm_scale #(.PERIOD(1)) scale_one(scale_done[0]);
    tb_pwm_scale #(.PERIOD(20)) scale_short(scale_done[1]);
    tb_pwm_scale #(.PERIOD(2500)) scale_default(scale_done[2]);
    tb_pwm_scale #(.PERIOD(2501)) scale_calibrated(scale_done[3]);
    tb_pwm_scale #(.PERIOD(100000000)) scale_max(scale_done[4]);
    wire [7:0] count_done;
    tb_pwm_count #(.PERIOD(0)) count_zero(count_done[0]);
    tb_pwm_count #(.PERIOD(1)) count_one(count_done[1]);
    tb_pwm_count #(.PERIOD(2)) count_two(count_done[2]);
    tb_pwm_count #(.PERIOD(3)) count_three(count_done[3]);
    tb_pwm_count #(.PERIOD(20)) count_short(count_done[4]);
    tb_pwm_count #(.PERIOD(2500)) count_default(count_done[5]);
    tb_pwm_count #(.PERIOD(2501)) count_calibrated(count_done[6]);
    tb_pwm_count #(.PERIOD(100000001)) count_invalid(count_done[7]);
    integer i, lh, rh, release_order;
    always #5 clk = ~clk;
    shrike_safety_gate #(.CLOCK_HZ(1000), .PWM_CARRIER_HZ(50)) dut (
        .clk(clk), .rst_n(rst_n), .command_valid(command_valid),
        .command_accept(command_accept), .estop_n(estop_n),
        .left_duty_permille(left_duty_permille), .right_duty_permille(right_duty_permille),
        .left_pwm_in(left_pwm_in), .right_pwm_in(right_pwm_in),
        .left_pwm_out(left_pwm_out), .right_pwm_out(right_pwm_out),
        .left_direction_out(left_direction_out), .right_direction_out(right_direction_out));
    shrike_safety_gate #(.CLOCK_HZ(49), .PWM_CARRIER_HZ(50)) invalid_config (
        .clk(clk), .rst_n(rst_n), .command_valid(command_valid),
        .command_accept(command_accept), .estop_n(estop_n),
        .left_duty_permille(left_duty_permille), .right_duty_permille(right_duty_permille),
        .left_pwm_in(left_pwm_in), .right_pwm_in(right_pwm_in),
        .left_pwm_out(invalid_left_pwm_out), .right_pwm_out(invalid_right_pwm_out));
    task period;
        input integer expected_left, expected_right;
        begin
            lh=0; rh=0;
            for (i=0; i<20; i=i+1) begin @(posedge clk); #1; lh=lh+left_pwm_out; rh=rh+right_pwm_out; end
            if (lh != expected_left || rh != expected_right) $fatal(1, "PWM counts %0d/%0d", lh, rh);
        end
    endtask
    initial begin
        rst_n=0; #2 rst_n=1; repeat (2) @(posedge clk);
        left_duty_permille=100; right_duty_permille=-800;
        command_valid=1; command_accept=1; @(posedge clk); #1 command_accept=0;
        if (invalid_left_pwm_out || invalid_right_pwm_out)
            $fatal(1,"unsupported zero-cycle PWM configuration must stay off");
        period(2,16);
        if (left_direction_out !== 0 || right_direction_out !== 1)
            $fatal(1,"+N/-N direction polarity");
        left_pwm_in=1; right_pwm_in=0; period(2,16);
        left_duty_permille=0; right_duty_permille=0; period(0,0);
        left_duty_permille=100; right_duty_permille=100;
        estop_n=0; #1; if (left_pwm_out || right_pwm_out) $fatal(1,"e-stop assertion");
        if (left_direction_out || right_direction_out) $fatal(1,"e-stop direction safe low");
        estop_n=1; command_accept=1; @(posedge clk); #1 command_accept=0;
        period(0,0);
        repeat (2) @(posedge clk);
        command_accept=1; @(posedge clk); #1 command_accept=0; period(2,2);
        // Neither release order may restore a command held valid over reset.
        for (release_order=0; release_order<2; release_order=release_order+1) begin
            wait (left_pwm_out && right_pwm_out);
            #1 estop_n=0; #1;
            if (left_pwm_out !== 0 || right_pwm_out !== 0)
                $fatal(1,"e-stop must suppress active PWM before the next clock");
            rst_n=0; #1;
            if (release_order == 0) rst_n=1;
            else estop_n=1;
            period(0,0);
            if (left_direction_out !== 0 || right_direction_out !== 0)
                $fatal(1,"overlapping reset must keep direction safe low");
            @(negedge clk); rst_n=1; estop_n=1;
            period(0,0);
            @(negedge clk); command_accept=1;
            @(posedge clk); #1 command_accept=0;
            period(2,2);
        end
        left_duty_permille=801; #1; if (left_pwm_out || right_pwm_out) $fatal(1,"range");
        wait ((&scale_done) && (&count_done));
        $display("PASS: shrike_safety_gate"); $finish;
    end
endmodule

// Exhaust the signed input domain against the original 64-bit PWM formula.
module tb_pwm_scale #(parameter integer PERIOD = 2500)(output reg done = 0);
    reg signed [11:0] left = 0, right = 0;
    integer duty;
    reg [63:0] magnitude, expected;
    shrike_safety_gate #(.CLOCK_HZ(PERIOD), .PWM_CARRIER_HZ(1)) dut (
        .clk(1'b0), .rst_n(1'b0), .command_valid(1'b0),
        .command_accept(1'b0), .estop_n(1'b0),
        .left_duty_permille(left), .right_duty_permille(right),
        .left_pwm_in(1'b0), .right_pwm_in(1'b0));
    initial begin
        for (duty=-2048; duty<2048; duty=duty+1) begin
            left=duty; right=-1-duty; #1;
            if (dut.envelope_ok !== (duty >= -800 && duty <= 800
                    && $signed(right) >= -800 && $signed(right) <= 800))
                $fatal(1,"envelope period=%0d duty=%0d", PERIOD, duty);
            magnitude=duty<0 ? -duty : duty;
            expected=magnitude*PERIOD/1000;
            if (dut.left_high_cycles !== expected)
                $fatal(1,"left scale period=%0d duty=%0d", PERIOD, duty);
            magnitude=right<0 ? -$signed(right) : right;
            expected=magnitude*PERIOD/1000;
            if (dut.right_high_cycles !== expected)
                $fatal(1,"right scale period=%0d duty=%0d", PERIOD, right);
        end
        done=1;
    end
endmodule

// Compare the wrap predictor with the original terminal-count counter.
module tb_pwm_count #(parameter integer PERIOD = 2500)(output reg done = 0);
    localparam VALID = PERIOD > 0 && PERIOD <= 100000000;
    localparam integer STEPS = VALID ? 2 * PERIOD + 3 : 6;
    reg clk = 0, rst_n = 1, estop_n = 1;
    integer expected = 0, cycle;
    shrike_safety_gate #(.CLOCK_HZ(PERIOD), .PWM_CARRIER_HZ(1)) dut (
        .clk(clk), .rst_n(rst_n), .estop_n(estop_n),
        .command_valid(1'b0), .command_accept(1'b0),
        .left_duty_permille(12'sd0), .right_duty_permille(12'sd0),
        .left_pwm_in(1'b0), .right_pwm_in(1'b0));
    initial begin
        #1 rst_n=0; #1 rst_n=1;
        for (cycle=0; cycle<STEPS; cycle=cycle+1) begin
            #1 clk=1;
            expected = !VALID || expected == PERIOD-1 ? 0 : expected+1;
            #1;
            if (dut.pwm_count !== expected)
                $fatal(1,"PWM counter period=%0d cycle=%0d", PERIOD, cycle);
            clk=0;
        end
        estop_n=0; #1;
        if (dut.pwm_count !== 0) $fatal(1,"PWM counter asynchronous e-stop reset");
        done=1;
    end
endmodule
