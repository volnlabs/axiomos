# Pi 5 v0.3 benchmark — first-boot card

## Before connecting power

- Use the Raspberry Pi 5 8 GB, official 27 W supply, and active cooling.
- Disconnect Shrike-Lite, HC-SR04, L298N, motors, motor supply, 9 V batteries,
  and every lead from the Pi 40-pin header for the first three cold boots.
- Insert a dedicated Pi 5 microSD card into the laptop's reader. The card must
  already contain pinned Pi 5 boot firmware; axiomos deployment supplies only
  `kernel8.img`, `config.txt` when absent, and the provenance manifest.
- Connect the Raspberry Pi Debug Probe **U/UART** port to the Pi 5 dedicated
  three-pin debug-UART JST-SH connector. Do not use the probe's D/SWD port.
  Connect ground before signal lines whenever separate power is present.
- Leave the Pi 27 W supply disconnected until UART capture is running.

## Host detection gate

The laptop must show both:

- a removable microSD block device other than `/dev/nvme0n1`; and
- a stable debug UART path below `/dev/serial/by-id/` (normally backed by
  `/dev/ttyACM0` for the official Debug Probe).

Do not type a block-device path from memory. Re-run `lsblk`, identify the card
by removable flag, size, transport, and model, and confirm its mounted FAT boot
partition before deployment.

## Deployment and cold-boot gate

Run the repository deployment dry-run first, then deploy only to the confirmed
mounted boot partition. Start 115200-baud, 8-N-1 capture before applying Pi
power. Retain three separate cold-boot logs.

Every passing boot must contain:

- `PI5_BENCH_READY` with `initial_estop_asserted=true` while the header is
  disconnected;
- `INIT_PROCESS_STARTED pid=...`; and
- `PI5_BOOT_OK`.

Reject a boot containing a panic, fatal marker, watchdog reset, repeated reboot,
or an interrupt/log storm. These boots establish platform readiness only; they
are not latency benchmark samples.

## One-edge RP1 route probe — only after cold boots pass

Power the Pi off before wiring:

- pre-wire a normally-open pushbutton from Pi physical pin 1 (3.3 V), through a
  1 kΩ series resistor, to physical pin 16 (GPIO23);
- logic-analyzer CH0 to physical pin 16 (GPIO23 input);
- logic-analyzer CH1 to physical pin 32 (GPIO12 / PWM0 output); and
- logic-analyzer ground to Pi physical pin 6 (GND).

Do not connect motor hardware. Start UART and analyzer capture, power the Pi,
wait for `PI5_BENCH_READY`, then press the pre-wired button once. Continue only
if UART emits exactly one `PI5_GPIO_IRQ_PROVEN pin=23 ... pending_after=0x00000000`
and no interrupt storm occurs. This proves the route; it is not part of the
N=10,000 latency population.
