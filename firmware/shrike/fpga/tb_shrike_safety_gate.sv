`timescale 1ns/1ps

module tb_shrike_safety_gate;
    reg estop_n;
    reg signed [11:0] left_duty_permille;
    reg signed [11:0] right_duty_permille;
    reg left_pwm_in;
    reg right_pwm_in;
    wire left_pwm_out;
    wire right_pwm_out;

    shrike_safety_gate #(.MAX_DUTY_PERMILLE(800)) dut (
        .estop_n(estop_n),
        .left_duty_permille(left_duty_permille),
        .right_duty_permille(right_duty_permille),
        .left_pwm_in(left_pwm_in),
        .right_pwm_in(right_pwm_in),
        .left_pwm_out(left_pwm_out),
        .right_pwm_out(right_pwm_out)
    );

    task check_outputs;
        input expected_left;
        input expected_right;
        begin
            #1;
            if (left_pwm_out !== expected_left || right_pwm_out !== expected_right) begin
                $display("FAIL: estop_n=%b left_duty=%0d right_duty=%0d in=%b%b out=%b%b expected=%b%b",
                    estop_n, left_duty_permille, right_duty_permille,
                    left_pwm_in, right_pwm_in, left_pwm_out, right_pwm_out,
                    expected_left, expected_right);
                $fatal(1);
            end
        end
    endtask

    initial begin
        // Valid signed commands pass each PWM independently.
        estop_n = 1'b1;
        left_duty_permille = 12'sd800;
        right_duty_permille = -12'sd800;
        left_pwm_in = 1'b1;
        right_pwm_in = 1'b0;
        check_outputs(1'b1, 1'b0);

        // The envelope is inclusive at both boundaries.
        right_pwm_in = 1'b1;
        check_outputs(1'b1, 1'b1);

        // Either out-of-range command disables BOTH motors, including a PWM
        // edge already high at the instant the command becomes invalid.
        left_duty_permille = 12'sd801;
        check_outputs(1'b0, 1'b0);
        left_duty_permille = -12'sd801;
        check_outputs(1'b0, 1'b0);
        left_duty_permille = 12'sd0;
        right_duty_permille = 12'sd801;
        check_outputs(1'b0, 1'b0);

        // E-stop dominance is asynchronous and independent of valid commands.
        right_duty_permille = 12'sd0;
        estop_n = 1'b0;
        check_outputs(1'b0, 1'b0);
        estop_n = 1'b1;
        check_outputs(1'b1, 1'b1);

        $display("PASS: shrike_safety_gate");
        $finish;
    end
endmodule
