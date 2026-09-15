#include "managed.h"

/* Demonstration thresholds in raw sonar echo microseconds; calibrate before physical use. */
#define STOP_MAX_ECHO_US 600
#define CRUISE_MIN_ECHO_US 1400
#define APPROACH_PERMILLE 100
#define CRUISE_PERMILLE 300

int managed_control(struct axiom_bpf_context *ctx)
{
    const struct axiom_managed_control_context_v1 *input = axiom_managed_input(ctx);
    int drive = 0;

    if (input->sensor_valid == 1 && input->sensor_value > STOP_MAX_ECHO_US) {
        drive = APPROACH_PERMILLE;
        if (input->sensor_value >= CRUISE_MIN_ECHO_US)
            drive = CRUISE_PERMILLE;
    }

    return (int)axiom_managed_motor_pair_v1(drive, drive);
}
