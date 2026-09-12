`timescale 1ns/1ps
module tb_shrike_safety_gate;
    reg clk = 0, rst_n = 1, command_valid = 0, command_accept = 0, estop_n = 1;
    reg signed [11:0] left_duty_permille = 0, right_duty_permille = 0;
    reg left_pwm_in = 0, right_pwm_in = 1;
    wire left_pwm_out, right_pwm_out;
    wire left_direction_out, right_direction_out;
    wire invalid_left_pwm_out, invalid_right_pwm_out;
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
        $display("PASS: shrike_safety_gate"); $finish;
    end
endmodule
