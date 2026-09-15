# Separate robustness build: replace clk_50mhz.sdc; never load both files.
# 55.556 MHz exceeds the published 54.110 MHz oscillator maximum under the
# datasheet's stated supply conditions. Board calibration remains required.
create_clock -name clk {clk} -period 18.000 -waveform {0 9.000}
