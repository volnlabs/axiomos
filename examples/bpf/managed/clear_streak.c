#include "managed.h"

/* Demonstration threshold in raw sonar echo microseconds; calibrate before physical use. */
#define CLEAR_MIN_ECHO_US 1400
#define REQUIRED_CLEAR_SAMPLES 3U
#define DRIVE_PERMILLE 180

int managed_control(struct axiom_bpf_context *ctx)
{
    const struct axiom_managed_control_context_v1 *input = axiom_managed_input(ctx);
    axiom_u32 key = 0;
    axiom_u32 next = 0;
    int drive = 0;

    if (input->sensor_valid == 1 && input->sensor_value >= CLEAR_MIN_ECHO_US) {
        const axiom_u32 *previous = axiom_map_lookup_elem(AXIOM_PRIVATE_ARRAY_HANDLE, &key);

        if (previous) {
            next = *previous;
            if (next < REQUIRED_CLEAR_SAMPLES)
                next++;
        }
    }

    axiom_map_update_elem(AXIOM_PRIVATE_ARRAY_HANDLE, &key, &next, 0);
    if (next >= REQUIRED_CLEAR_SAMPLES)
        drive = DRIVE_PERMILLE;

    return (int)axiom_managed_motor_pair_v1(drive, drive);
}
