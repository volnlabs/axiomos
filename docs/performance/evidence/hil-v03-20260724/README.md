# Provisional Pi 5 v0.3 HIL evidence

These captures preserve the 2026-07-24 Raspberry Pi 5 v0.3 lab run. They are
useful engineering observations, but they are not an attributable release
campaign: every deployed-image build record says `worktree_dirty = true`, and
clean rebuilds of the next commits did not reproduce the deployed `kernel8.img`
hashes. See [`provisional.toml`](provisional.toml) for the deployed hashes,
clean-rebuild results, and file hashes.

## Reduction

The two latency UART logs came from separate cold boots of the same deployed
image. Drop 16 cold-cache/TLB samples from each log before pooling:

```sh
python3 scripts/hil/v03b-reduce.py --warmup 16 \
  docs/performance/evidence/hil-v03-20260724/latency-smoke-uart.log \
  docs/performance/evidence/hil-v03-20260724/latency-main-uart.log
```

The retained result is M-A `n=10164`, median 37 ns, maximum 55 ns; and M-C
`n=10162`, median 4.500 µs, p99.9 5.500 µs, maximum 6.888 µs. M-A passes its
5 µs target. M-C has enough samples but fails its 1 µs target.

## Physical capture

`gpio-reflex.sr` was captured at 24 MHz with D0 on GPIO23 and D1 on GPIO12.
The trigger starts the capture after D0 rises; D1 falls at sample 222, or
9.25 µs after the trigger. This is one rig-validation sample, not a latency
distribution or bound.

## Containment capture

`containment-uart.log` contains
`PI5_V03C n=1000 escapes=0 safed=450 seed=0x5652303343000001`. It is a
successful provisional on-device observation, but the dirty deployed-image
source prevents promotion to attributable release evidence.
