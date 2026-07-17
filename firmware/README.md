# Firmware

Firmware contains external-controller software that is built and versioned
separately from the privileged kernel runtime. Product boundaries own their
hardware implementation, reusable control logic, and host simulation together.

- [`shrike/`](shrike/README.md): RP2040 safety/control sidecar and simulation.
