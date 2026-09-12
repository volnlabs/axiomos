#!/usr/bin/env python3
"""Synthetic observer checks; these are not physical bench evidence."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import os
import pty
import threading
import time
import tracemalloc
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[2] / 'scripts/hil/shrike-bench.py'

def module():
    spec = importlib.util.spec_from_file_location('shrike_bench', SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def fixture():
    cfg = dict(sample_rate_hz=24_000_000, samples=18100,
               channels=dict(left_pwm=0, right_pwm=1, left_dir=2, right_dir=3, estop=4, stimulus=5),
               period_min=1198, period_max=1202, tolerance_samples=2,
               uncertainty_samples=2, stop_limit_samples=24000,
               sync_timeout_samples=200, repeats=1, uart_max_gap_ns=1_000_000_000,
               steps=[dict(left=500, right=-250, estop=1, settle_samples=1202, min_samples=5900, max_samples=6100),
                      dict(left=-800, right=400, estop=1, settle_samples=1202, min_samples=5900, max_samples=6100),
                      dict(left=0, right=0, estop=0, settle_samples=2, min_samples=5900, max_samples=6100)])
    data = bytearray()
    for t in range(cfg['samples']):
        i = min(2, max(0, (t - 100) // 6000))
        step = cfg['steps'][i]
        value = 16 if t < 12100 else 0
        if t >= 100:
            phase = (t - 100) % 1200
            for pwm, direction, duty in ((0, 2, step['left']), (1, 3, step['right'])):
                if phase < abs(duty) * 1200 // 1000:
                    value |= 1 << pwm
                if duty < 0:
                    value |= 1 << direction
            if (t - 100) % 6000 < 10:
                value |= 32
        data.append(value)
    return cfg, bytes(data)

def repeated_fixture(repeats):
    cfg, _ = fixture()
    cfg['steps'].insert(0, dict(left=0, right=0, estop=1, settle_samples=1202, min_samples=5900, max_samples=6100))
    cfg.update(samples=24000 * repeats, repeats=repeats)
    pattern = bytearray()
    for t in range(24000):
        step = cfg['steps'][t // 6000]
        value = 16 if step['estop'] else 0
        if t % 6000 < 10: value |= 32
        for pwm, direction, duty in ((0, 2, step['left']), (1, 3, step['right'])):
            if t % 1200 < abs(duty) * 1200 // 1000: value |= 1 << pwm
            if duty < 0: value |= 1 << direction
        pattern.append(value)
    return cfg, bytes(pattern)

class ObserverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m = module()

    def test_streaming_round_trip_and_boundaries(self):
        cfg, data = fixture()
        self.m.validate_config(cfg)
        for size in (1, 101, 4096, len(data)):
            observer = self.m.Waveform(cfg)
            for start in range(0, len(data), size):
                observer.feed(data[start:start + size])
            report = observer.finish()
            self.assertEqual(report['stimuli'], 3)
            self.assertGreater(report['left_cycles'], 0)
            self.assertGreater(report['right_cycles'], 0)
            self.assertEqual(observer.offset, len(data))
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.m.archive_stream(io.BytesIO(data), root / 'run', root, cfg, chunk_bytes=4096)
            report = self.m.replay(root / 'run', require_uart=False)
            self.assertEqual(report['samples'], len(data))
            self.assertFalse(report['physical_acceptance'])
            self.assertFalse(any(p.suffix == '.bin' for p in root.rglob('*')))

    def test_bad_configuration_and_waveforms(self):
        cfg, data = fixture()
        for key, value in [('samples', True), ('repeats', 0), ('period_min', 0), ('tolerance_samples', -1)]:
            bad = copy.deepcopy(cfg); bad[key] = value
            with self.assertRaises(ValueError): self.m.validate_config(bad)
        bad = copy.deepcopy(cfg); bad['channels']['right_pwm'] = 0
        with self.assertRaises(ValueError): self.m.validate_config(bad)
        mutations = [lambda x: x.__setitem__(slice(2000, 4000), bytes(v ^ 4 for v in x[2000:4000])),
                     lambda x: x.__setitem__(slice(2000, 4000), bytes(v | 1 for v in x[2000:4000])),
                     lambda x: x.__setitem__(slice(12200, 13000), bytes(v | 2 for v in x[12200:13000])),
                     lambda x: x.__setitem__(slice(6100, 6110), bytes(v & ~32 for v in x[6100:6110]))]
        for mutate in mutations:
            bad = bytearray(data); mutate(bad)
            with self.assertRaises(ValueError):
                observer = self.m.Waveform(cfg); observer.feed(bytes(bad)); observer.finish()

    def test_last_settled_pulse_before_step_boundary_is_checked(self):
        cfg, data = fixture()
        for start, end in ((5200, 5500), (4900, 5500)):
            broken = bytearray(data)
            broken[start:end] = bytes(value & ~1 for value in broken[start:end])
            for size in (1, 101, 4096, len(data)):
                with self.subTest(start=start, size=size), self.assertRaises(ValueError):
                    observer = self.m.Waveform(cfg)
                    for offset in range(0, len(broken), size): observer.feed(broken[offset:offset + size])
                    observer.finish()

    def test_settled_high_cannot_hide_behind_stop_but_shortening_is_valid(self):
        for period in (1198, 1200, 1202):
            for phase in (0, 1, 60, 120, 300, 600, 950, 1197):
                cfg, _ = fixture()
                stop_at = 100 + 5 * period + phase
                cfg['steps'] = [dict(left=100, right=-250, estop=1, settle_samples=1202,
                                     min_samples=stop_at - 101, max_samples=stop_at - 99), cfg['steps'][-1]]
                cfg['samples'] = stop_at + 6000
                data = bytearray()
                for at in range(cfg['samples']):
                    value = 16 if at < stop_at else 0
                    if 100 <= at < stop_at:
                        value |= 8
                        if (at - 100) % period < round(period * .1): value |= 1
                        if (at - 100) % period < round(period * .25): value |= 2
                    if 100 <= at < 110 or stop_at <= at < stop_at + 10: value |= 32
                    data.append(value)
                for size in (101, len(data)):
                    observer = self.m.Waveform(cfg)
                    for at in range(0, len(data), size): observer.feed(data[at:at + size])
                    observer.finish()
                if phase >= 300:
                    start = 100 + 5 * period
                    data[start:stop_at] = bytes(v | 1 for v in data[start:stop_at])
                    with self.assertRaises(ValueError):
                        observer = self.m.Waveform(cfg); observer.feed(data); observer.finish()

    def test_analyzer_loss_marker_before_retained_tail_is_rejected(self):
        with self.assertRaises(ValueError):
            self.m.analyzer_chunk(b'', b'USB transfer error\n' + b'x' * 32000 + b'SR_DF_END\n')

    def test_manifest_rejects_boolean_integer_aliases_and_string_completion(self):
        cfg, data = fixture()
        for record_index, field, value in ((-1, 'complete', 'false'), (-1, 'samples', True),
                                            (0, 'format', True), (1, 'id', False),
                                            (1, 'offset', False), (1, 'compressor_exit', False)):
            with tempfile.TemporaryDirectory() as name:
                root = Path(name); run = root / 'run'
                self.m.archive_stream(io.BytesIO(data), run, root, cfg)
                records = list(self.m.read_json_lines(run / 'manifest.jsonl'))
                records[record_index][field] = value
                (run / 'manifest.jsonl').write_text(''.join(json.dumps(record) + '\n' for record in records))
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    self.m.replay(run, require_uart=False)

    def test_uart_chunk_pairs_are_ordered_and_complete(self):
        before = 'V04_HEARTBEAT seq=1 ts_ns=1\n'
        after = 'V04_HEARTBEAT seq=2 ts_ns=4\n'
        for middle in ('V04_CHUNK chunk_id=1 stage=start ts_ns=2\nV04_CHUNK chunk_id=3 stage=end ts_ns=3\n',
                       'V04_CHUNK chunk_id=1 stage=start ts_ns=2\n',
                       'V04_CHUNK chunk_id=1 stage=end ts_ns=2\n',
                       'V04_CHUNK chunk_id=2 stage=start ts_ns=2\nV04_CHUNK chunk_id=2 stage=end ts_ns=3\n'):
            with self.assertRaises(ValueError):
                uart = self.m.Uart(1000); uart.feed((before + middle + after).encode()); uart.finish()
        uart = self.m.Uart(1000)
        uart.feed((before + 'V04_CHUNK chunk_id=1 stage=start ts_ns=2\nV04_CHUNK chunk_id=1 stage=end ts_ns=3\n' + after).encode())
        uart.finish()

    def test_archive_rejects_integrity_and_order_failures(self):
        cfg, data = fixture()
        for damage in ('corrupt', 'truncate', 'missing', 'duplicate', 'reorder', 'footer'):
            with tempfile.TemporaryDirectory() as name:
                root = Path(name); run = root / 'run'
                self.m.archive_stream(io.BytesIO(data), run, root, cfg, chunk_bytes=4096)
                path = run / 'manifest.jsonl'
                records = [json.loads(line) for line in path.read_text().splitlines()]
                chunk = run / records[1]['file']
                if damage == 'corrupt': chunk.write_bytes(b'not zstd')
                elif damage == 'truncate': chunk.write_bytes(chunk.read_bytes()[:-1])
                elif damage == 'missing': chunk.unlink()
                elif damage == 'duplicate': records.insert(2, records[1])
                elif damage == 'reorder': records[1], records[2] = records[2], records[1]
                elif damage == 'footer': records.pop()
                path.write_text(''.join(json.dumps(record) + '\n' for record in records))
                with self.assertRaises((ValueError, OSError)):
                    self.m.replay(run, require_uart=False)

    def test_budget_disk_and_compressor_failures_are_retained(self):
        cfg, data = fixture()
        for failure in ('budget', 'disk', 'compressor'):
            with tempfile.TemporaryDirectory() as name:
                root = Path(name); run = root / 'run'
                with mock.patch.object(self.m, 'CONTROL_STOP', 1 if failure == 'budget' else self.m.CONTROL_STOP), \
                     mock.patch.object(self.m.shutil, 'disk_usage', return_value=(10**12, 0, 0 if failure == 'disk' else 10**12)), \
                     mock.patch.object(self.m, 'ZSTD', '/bin/false' if failure == 'compressor' else self.m.ZSTD):
                    with self.assertRaises((ValueError, OSError)):
                        self.m.archive_stream(io.BytesIO(data), run, root, cfg, chunk_bytes=4096)
                self.assertTrue((run / 'manifest.jsonl').exists())
                with self.assertRaises((ValueError, OSError)):
                    self.m.replay(run, require_uart=False)

    def test_uart_loss_reset_and_wrapping_heartbeat(self):
        def check(text):
            uart = self.m.Uart(1000)
            for part in (text[:7], text[7:23], text[23:]): uart.feed(part.encode())
            return uart.finish()
        valid = 'V04_HEARTBEAT seq=65535 ts_ns=10\nV04_HEARTBEAT seq=0 ts_ns=20\n'
        self.assertEqual(check(valid)['heartbeats'], 2)
        for text in (valid.replace('seq=0', 'seq=1'), valid + 'PI5_BENCH_LOG_LOSS\n',
                     valid + 'V04_PANIC kind=panic\n', valid + 'PI5_BENCH_READY\n',
                     valid[:-1], valid + 'V04_FAILURE reason=input_overflow count=1 ts_ns=30\n'):
            with self.assertRaises(ValueError): check(text)

    def test_host_uart_receipt_coverage(self):
        valid = dict(first_seconds=.1, last_seconds=9.9, max_gap_seconds=.5, heartbeats=20)
        self.m.check_receipts(valid, 10, 1_000_000_000, 20)
        for field, value in [('first_seconds', 2), ('last_seconds', 2), ('max_gap_seconds', 2), ('heartbeats', 19)]:
            bad = dict(valid); bad[field] = value
            with self.assertRaises(ValueError): self.m.check_receipts(bad, 10, 1_000_000_000, 20)

    def test_capture_loop_with_synthetic_analyzer_and_pty_uart(self):
        for failure in (None, 'uart_silence', 'analyzer'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as name:
                root = Path(name); campaign = root / 'campaign'
                cfg, data = fixture()
                cfg['uart_max_gap_ns'] = 150_000_000
                fake = root / 'fake-analyzer'
                fake.write_text('#!/usr/bin/env python3\nimport sys, time\n'
                                + f'data = {data!r}\n'
                                + 'sys.stdout.buffer.write(data[:9000]); sys.stdout.flush(); time.sleep(.3)\n'
                                + 'sys.stdout.buffer.write(data[9000:]); sys.stdout.flush()\n'
                                + 'sys.stderr.write("SR_DF_END\\n"); sys.stderr.flush(); time.sleep(.05)\n'
                                + f'sys.exit({1 if failure == "analyzer" else 0})\n')
                fake.chmod(0o755)
                runtime = dict(sigrok=dict(path=str(fake)), libsigrok=dict(path='/synthetic/libsigrok'))
                master, slave = pty.openpty()
                stop = threading.Event()
                def beats():
                    started = time.monotonic(); seq = 0
                    while not stop.wait(.02):
                        if failure == 'uart_silence' and seq >= 2: continue
                        ns = int((time.monotonic() - started) * 1e9)
                        os.write(master, f'V04_HEARTBEAT seq={seq} ts_ns={ns}\n'.encode()); seq += 1
                thread = threading.Thread(target=beats); thread.start()
                try:
                    with mock.patch.object(self.m, 'pinned_runtime', return_value=runtime), \
                         mock.patch.object(self.m, 'library_loaded', return_value=True):
                        if failure:
                            with self.assertRaises(ValueError): self.m.capture(cfg, campaign, 'run', os.ttyname(slave), 'synthetic')
                        else:
                            self.m.capture(cfg, campaign, 'run', os.ttyname(slave), 'synthetic')
                            self.m.replay(campaign / 'run')
                finally:
                    stop.set(); thread.join(); os.close(master); os.close(slave)
                records = list(self.m.read_json_lines(campaign / 'run/manifest.jsonl'))
                footer = records[-1]
                self.assertEqual(footer['complete'], failure is None)
                self.assertGreater(footer['samples'], 0)
                self.assertEqual(footer['unretained_pending_samples'], 0)
                if failure:
                    with self.assertRaises(ValueError): self.m.replay(campaign / 'run')

    def test_representative_second_archive_and_replay(self):
        cfg, pattern = repeated_fixture(1000)
        class Stream:
            at = 0
            def read(self, size):
                end = min(cfg['samples'], self.at + size)
                out = bytearray()
                while self.at < end:
                    if self.at < 100:
                        length = min(end - self.at, 100 - self.at)
                        out.extend(b'\x10' * length)
                    else:
                        at = (self.at - 100) % len(pattern)
                        length = min(end - self.at, len(pattern) - at)
                        out.extend(pattern[at:at + length])
                    self.at += length
                return bytes(out)
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            start = time.monotonic()
            self.m.archive_stream(Stream(), root / 'run', root, cfg)
            archived = time.monotonic()
            self.m.replay(root / 'run', require_uart=False)
            done = time.monotonic()
            # Linux ru_maxrss can retain the pre-exec parent's high-water mark.
            # VmHWM measures this observer test process after exec.
            rss = int(next(line.split()[1] for line in Path('/proc/self/status').read_text().splitlines()
                           if line.startswith('VmHWM:')))
            self.assertLess(rss, 128 * 1024)
            print(f'SYNTHETIC ONLY: 24M samples archive={archived-start:.3f}s replay={done-archived:.3f}s '
                  f'combined={24_000_000 / (done-start) / 2**20:.1f} MiB/s peak_RSS={rss} KiB; not physical qualification')

    def test_memory_does_not_grow_with_repeated_chunks(self):
        cfg, pattern = repeated_fixture(300)
        observer = self.m.Waveform(cfg)
        observer.feed(b'\x10' * 100)
        tracemalloc.start()
        for _ in range(10): observer.feed(pattern)
        initial, _ = tracemalloc.get_traced_memory()
        for _ in range(289): observer.feed(pattern)
        observer.feed(pattern[:-100])
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        observer.finish()
        self.assertLess(current - initial, 65536)
        self.assertLess(peak, 1024 * 1024)

    def test_offsets_beyond_32_bits_without_retaining_history(self):
        cfg, data = fixture()
        observer = self.m.Waveform(cfg)
        observer.offset = 2**32 - 100
        observer.sync_limit = observer.offset + 200
        observer.feed(data)
        self.assertGreater(observer.offset, 2**32)
        self.assertLess(len(repr(observer.__dict__)), 10000)

if __name__ == '__main__': unittest.main()
