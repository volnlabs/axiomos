#ifndef AXIOMOS_MANAGED_BPF_H
#define AXIOMOS_MANAGED_BPF_H

typedef unsigned int axiom_u32;
typedef unsigned long long axiom_u64;
typedef long long axiom_i64;

/* R1 points to the runtime's RawBpfContext; data is its offset-zero payload pointer. */
struct axiom_bpf_context {
    const void *data;
    const void *data_end;
    const void *data_meta;
    axiom_u64 interrupt_latency_ns;
    axiom_u64 boot_time_ms;
    axiom_u64 kernel_heap_kb;
    axiom_u64 kernel_image_mb;
};

struct axiom_managed_control_context_v1 {
    axiom_u32 version;
    axiom_u32 size;
    axiom_u64 cycle_id;
    axiom_u64 scheduled_ns;
    axiom_u64 actual_ns;
    axiom_u64 sensor_ns;
    axiom_i64 sensor_value;
    axiom_u32 sensor_valid;
    axiom_u32 reserved;
};

_Static_assert(__builtin_offsetof(struct axiom_bpf_context, data) == 0,
               "RawBpfContext payload offset changed");
_Static_assert(sizeof(struct axiom_managed_control_context_v1) == 56,
               "ManagedControlContextV1 size changed");
_Static_assert(__builtin_offsetof(struct axiom_managed_control_context_v1, sensor_value) == 40,
               "ManagedControlContextV1 sensor value offset changed");
_Static_assert(__builtin_offsetof(struct axiom_managed_control_context_v1, sensor_valid) == 48,
               "ManagedControlContextV1 sensor validity offset changed");

#define AXIOM_PRIVATE_ARRAY_HANDLE 1U

static void *(*const axiom_map_lookup_elem)(axiom_u32, const void *)
    __attribute__((unused)) = (void *)(unsigned long)5;
static long (*const axiom_map_update_elem)(axiom_u32, const void *, const void *, axiom_u64)
    __attribute__((unused)) = (void *)(unsigned long)6;
/* Helper arguments use canonical signed 64-bit values, including reverse requests. */
static long (*const axiom_managed_motor_pair_v1)(axiom_i64, axiom_i64)
    __attribute__((unused)) = (void *)(unsigned long)1009;

static __attribute__((always_inline)) const struct axiom_managed_control_context_v1 *
axiom_managed_input(const struct axiom_bpf_context *ctx)
{
    return ctx->data;
}

#endif
