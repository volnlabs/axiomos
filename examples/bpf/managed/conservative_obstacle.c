#include "managed.h"

/* Demonstration threshold in raw sonar echo microseconds; calibrate for the sensor and chassis. */
#define CRUISE_MIN_ECHO_US 1400
#ifndef CRUISE_PERMILLE
#define CRUISE_PERMILLE 250
#endif

int managed_control(struct axiom_bpf_context *ctx)
{
    const struct axiom_managed_control_context_v1 *input = axiom_managed_input(ctx);
    int drive = 0;

    if (input->sensor_valid == 1 && input->sensor_value > 0 &&
        input->sensor_value >= CRUISE_MIN_ECHO_US)
        drive = CRUISE_PERMILLE;

    return (int)axiom_managed_motor_pair_v1(drive, drive);
}
