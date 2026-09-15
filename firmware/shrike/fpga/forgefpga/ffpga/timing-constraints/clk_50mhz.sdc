# Nominal on-chip oscillator, OSC_CLK on West Input0.
# This constrains analysis; it does not program or calibrate the oscillator.
create_clock -name clk {clk} -period 20.000 -waveform {0 10.000}
