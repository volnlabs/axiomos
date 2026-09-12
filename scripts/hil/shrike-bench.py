#!/usr/bin/env python3
"""Bounded, unloaded Shrike waveform recorder and offline checker.

capture CONFIG CAMPAIGN RUN --uart DEVICE records all D0..D7 as one byte/sample
from one sigrok process. CONFIG is frozen before acquisition; --driver defaults
 to fx2lafw. Set LD_LIBRARY_PATH to the qualified libsigrok build explicitly.
replay RUN checks every compressed chunk and the independent stimulus schedule.
self-test runs synthetic checks only. No mode flashes firmware or drives pins.

CONFIG fields are documented by validate_config and the synthetic test fixture.
Each rising `stimulus` edge advances the independently authored `steps` list,
repeated `repeats` times. Steps carry signed permille duties (maximum 800), active
LOW estop level, settling allowance, and min/max dwell in analyzer samples.
Other named reference channels require a `references` level map in every step.
The capture begins safe, ends in a zero-duty step, and includes that step's
minimum dwell. Carrier bounds and uncertainty must come from bench calibration.
Runtime pins are absolute path/SHA-256 pairs for sigrok, libsigrok and fx2_patch.

This checks a frozen strobe workload, not arbitrary commands, SPI or all V04
acceptance populations. An offline PASS never closes physical acceptance.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import selectors
import shutil
import subprocess
import sys
import termios
import time

CHUNK_BYTES = 4 * 1024 * 1024
READ_BYTES = 64 * 1024
MAX_CONFIG = 1024 * 1024
MAX_LINE = 16384
HARD_CAP = 50_000_000_000
CONTROL_STOP = 45_000_000_000
RESERVE = HARD_CAP - CONTROL_STOP
ZSTD = shutil.which('zstd') or 'zstd'
ROLES = {'left_pwm', 'right_pwm', 'left_dir', 'right_dir', 'estop', 'stimulus'}
RUNS = re.compile(b'|'.join(re.escape(bytes([n])) + b'+' for n in range(256)))
V04_PARSE = runpy.run_path(str(Path(__file__).parents[1] / 'benchmark/analyze-v04.py'))['parse']


def integer(value, low, high, label):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f'{label} must be an integer in {low}..{high}')
    return value


def validate_config(c):
    required = {'sample_rate_hz', 'samples', 'channels', 'period_min', 'period_max',
                'tolerance_samples', 'uncertainty_samples', 'stop_limit_samples',
                'sync_timeout_samples', 'repeats', 'uart_max_gap_ns', 'steps'}
    if not isinstance(c, dict) or set(c) - required - {'runtime'} or required - set(c):
        raise ValueError('configuration fields mismatch')
    integer(c['sample_rate_hz'], 24_000_000, 24_000_000, 'sample rate')
    for key in ('samples', 'period_min', 'period_max', 'sync_timeout_samples', 'repeats', 'uart_max_gap_ns'):
        integer(c[key], 1, 2**63 - 1, key)
    for key in ('tolerance_samples', 'uncertainty_samples', 'stop_limit_samples'):
        integer(c[key], 0, 24000, key)
    if not 0 < c['period_min'] <= c['period_max'] or c['tolerance_samples'] * 2 >= c['period_min']:
        raise ValueError('invalid calibrated carrier bounds/tolerance')
    if not c['uncertainty_samples'] < c['stop_limit_samples'] <= 24000:
        raise ValueError('stop limit including uncertainty must be <= 1 ms')
    channels = c['channels']
    if not isinstance(channels, dict) or not ROLES <= set(channels) or len(channels) > 8:
        raise ValueError('both PWMs/directions, estop and stimulus must be captured')
    for name, bit in channels.items():
        if not re.fullmatch('[a-z][a-z_]{0,31}', name): raise ValueError('invalid channel name')
        integer(bit, 0, 7, 'channel bit')
    if len(set(channels.values())) != len(channels): raise ValueError('duplicate channel bit')
    if not isinstance(c['steps'], list) or not 1 <= len(c['steps']) <= 128:
        raise ValueError('need 1..128 independently specified workload steps')
    for step in c['steps']:
        required_step = {'left', 'right', 'estop', 'settle_samples', 'min_samples', 'max_samples'}
        if not isinstance(step, dict) or required_step - set(step) or set(step) - required_step - {'references'}:
            raise ValueError('step fields mismatch')
        for side in ('left', 'right'): integer(step[side], -800, 800, side)
        integer(step['estop'], 0, 1, 'estop level')
        for key in ('settle_samples', 'min_samples', 'max_samples'):
            integer(step[key], 0, 2**63 - 1, key)
        if not step['settle_samples'] + 2 * c['period_max'] < step['min_samples'] <= step['max_samples']:
            raise ValueError('step must retain at least two settled carrier periods')
        if not step['estop'] and (step['left'] or step['right']): raise ValueError('motion requested during stop')
        refs = step.get('references', {})
        if not isinstance(refs, dict) or set(refs) != set(channels) - ROLES:
            raise ValueError('all extra reference levels must be independently specified')
        for level in refs.values(): integer(level, 0, 1, 'reference level')
    if c['steps'][-1]['left'] or c['steps'][-1]['right'] or c['steps'][-1]['estop']:
        raise ValueError('last step must hold physical stop and both outputs safe')
    return c


class Waveform:
    """Constant state per channel; no whole-run sample, edge or result lists."""
    def __init__(self, config):
        self.c = validate_config(config)
        self.offset = 0
        self.sync_limit = config['sync_timeout_samples']
        self.previous = None
        self.step = None
        self.start = 0
        self.stimuli = 0
        self.cycles = [0, 0]
        self.step_cycles = [0, 0]
        self.rise = [None, None]
        self.fall = [None, None]
        self.high_start = [None, None]
        self.stop_at = None
        self.stop_seen_low = [False, False]
        self.armed = False
        self.stop_count = 0
        self.max_stop_samples = 0

    def level(self, value, name): return (value >> self.c['channels'][name]) & 1

    def end_step(self, at):
        if self.step is None: return
        duration = at - self.start
        if not self.step['min_samples'] <= duration <= self.step['max_samples']:
            raise ValueError(f'count/deadline: step {self.stimuli} dwell {duration}')
        for i, side in enumerate(('left', 'right')):
            if self.step[side]:
                if self.step_cycles[i] == 0: raise ValueError(f'missing {side} settled response')
                if self.rise[i] is None or at - self.rise[i] > self.c['period_max'] + self.c['tolerance_samples']:
                    raise ValueError(f'missing {side} final carrier pulse')

    def segment(self, value, begin, end):
        prev = self.previous
        estop = self.level(value, 'estop')
        was_stop = self.level(prev, 'estop') if prev is not None else estop
        if not estop and (was_stop or prev is None):
            self.stop_at = begin
            self.stop_seen_low = [False, False]
            self.armed = False
            self.stop_count += int(prev is not None)
        strobe = self.level(value, 'stimulus') and prev is not None and not self.level(prev, 'stimulus')
        if strobe:
            self.end_step(begin)
            if self.stimuli >= len(self.c['steps']) * self.c['repeats']:
                raise ValueError('extra stimulus')
            self.step = self.c['steps'][self.stimuli % len(self.c['steps'])]
            self.start = begin
            self.stimuli += 1
            self.step_cycles = [0, 0]
            self.rise = [None, None]
            self.fall = [None, None]
            # Release alone cannot re-arm; command reference must follow release.
            self.armed = bool(estop and was_stop)
        if self.step is None:
            if end > self.sync_limit: raise ValueError('missing initial stimulus')
        elif end - self.start > self.step['max_samples']:
            raise ValueError('missing stimulus / dwell deadline')
        settled = self.step is not None and end > self.start + self.step['settle_samples']
        if settled:
            if estop != self.step['estop']: raise ValueError('physical estop differs from workload')
            for name, expected in self.step.get('references', {}).items():
                if self.level(value, name) != expected: raise ValueError(f'reference {name} differs from workload')
        for i, side in enumerate(('left', 'right')):
            high = self.level(value, side + '_pwm')
            old = self.level(prev, side + '_pwm') if prev is not None else high
            direction = self.level(value, side + '_dir')
            expected = self.step[side] if self.step else 0
            if high and not self.armed:
                # Allow only an existing high pulse to finish within the stop bound.
                if estop or self.stop_at is None or self.stop_seen_low[i]:
                    raise ValueError(f'{side} output without fresh-command re-arm')
            if not estop and self.stop_at is not None:
                if high and end - self.stop_at + self.c['uncertainty_samples'] > self.c['stop_limit_samples']:
                    raise ValueError(f'{side} physical stop latency exceeds limit')
                if not high and not self.stop_seen_low[i]:
                    self.stop_seen_low[i] = True
                    latency = begin - self.stop_at + self.c['uncertainty_samples']
                    self.max_stop_samples = max(self.max_stop_samples, latency)
            if settled or self.step is None:
                if direction != int(expected < 0): raise ValueError(f'{side} direction mismatch')
                if not expected and high: raise ValueError(f'{side} output in zero-duty interval')
            if high and not old:
                self.high_start[i] = begin
                if self.rise[i] is not None and self.fall[i] is not None:
                    period = begin - self.rise[i]
                    width = self.fall[i] - self.rise[i]
                    if self.rise[i] >= self.start + self.step['settle_samples']:
                        if not self.c['period_min'] <= period <= self.c['period_max']:
                            raise ValueError(f'{side} carrier period mismatch')
                        if abs(width * 1000 - period * abs(expected)) > self.c['tolerance_samples'] * 1000:
                            raise ValueError(f'{side} duty mismatch')
                        self.cycles[i] += 1
                        self.step_cycles[i] += 1
                self.rise[i], self.fall[i] = begin, None
            if old and not high:
                self.fall[i] = begin
                # Validate the high pulse now, including the last pulse before
                # a command boundary where another rising edge may never occur.
                # A strobe clears rise: only transition-truncated pulses skip this.
                if self.rise[i] is not None and self.rise[i] >= self.start + self.step['settle_samples']:
                    width = (begin - self.rise[i]) * 1000
                    low = self.c['period_min'] * abs(expected) - self.c['tolerance_samples'] * 1000
                    high_bound = self.c['period_max'] * abs(expected) + self.c['tolerance_samples'] * 1000
                    if not low <= width <= high_bound: raise ValueError(f'{side} pulse duty mismatch')
            if high and self.high_start[i] is not None:
                if end - self.high_start[i] > self.c['period_max'] * .8 + self.c['tolerance_samples']:
                    raise ValueError(f'{side} high pulse exceeds 80% envelope')
                if self.step and self.high_start[i] >= self.start + self.step['settle_samples']:
                    limit = self.c['period_max'] * abs(expected) + self.c['tolerance_samples'] * 1000
                    if (end - self.high_start[i]) * 1000 > limit:
                        raise ValueError(f'{side} settled high pulse exceeds expected duty')
            if settled and expected:
                last = self.rise[i] if self.rise[i] is not None else self.start + self.step['settle_samples']
                if end - last > self.c['period_max'] + self.c['tolerance_samples']:
                    raise ValueError(f'missing {side} carrier')
        self.previous = value

    def feed(self, data):
        for run in RUNS.finditer(data):
            self.segment(data[run.start()], self.offset + run.start(), self.offset + run.end())
        self.offset += len(data)

    def finish(self):
        self.end_step(self.offset)
        if self.offset != self.c['samples']: raise ValueError('sample count differs from requested acquisition')
        if self.stimuli != len(self.c['steps']) * self.c['repeats']: raise ValueError('missing stimulus responses')
        if self.previous is None or any(self.level(self.previous, role) for role in ROLES - {'stimulus'}):
            raise ValueError('final FPGA outputs/directions/estop must be LOW')
        return dict(samples=self.offset, stimuli=self.stimuli, left_cycles=self.cycles[0],
                    right_cycles=self.cycles[1], stop_assertions=self.stop_count,
                    max_stop_samples_including_uncertainty=self.max_stop_samples)


class Uart:
    """Reuse V04 schemas, retaining counters and one bounded partial line."""
    def __init__(self, max_gap):
        self.buffer = b''
        self.max_gap = max_gap
        self.timestamp = None
        self.heartbeat = None
        self.beat_time = None
        self.beats = 0
        self.ids = {}
        self.records = 0
        self.first_timestamp = None
        self.first_receipt = None
        self.last_receipt = None
        self.max_receipt_gap = 0.0
        self.active_chunk = None
        self.last_chunk = 0

    def feed(self, data, received_at=None):
        self.buffer += data
        while b'\n' in self.buffer:
            line, self.buffer = self.buffer.split(b'\n', 1)
            if len(line) > MAX_LINE: raise ValueError('UART line exceeds bound')
            text = line.decode('utf-8').strip()
            if re.search(r'LOG_LOSS|BENCH_FAIL|panic|fatal|V04_FAILURE|BOOT|PI5_BENCH_READY', text, re.I):
                raise ValueError('UART loss/failure/reset marker')
            records = V04_PARSE(text)
            if not records: continue
            record = records[0]
            self.records += 1
            ts = int(record.get('ts_ns', self.timestamp or 0))
            if self.timestamp is not None and ts < self.timestamp: raise ValueError('UART timestamp reset')
            self.timestamp = ts
            if self.first_timestamp is None: self.first_timestamp = ts
            if record['_event'] == 'V04_HEARTBEAT':
                seq = integer(int(record['seq']), 0, 65535, 'heartbeat seq')
                if self.heartbeat is not None and seq != (self.heartbeat + 1) % 65536:
                    raise ValueError('UART heartbeat loss/reset')
                if ts - (self.beat_time if self.beat_time is not None else self.first_timestamp) > self.max_gap:
                    raise ValueError('UART heartbeat gap')
                self.heartbeat, self.beat_time = seq, ts
                self.beats += 1
                if received_at is not None:
                    if self.first_receipt is None: self.first_receipt = received_at
                    if self.last_receipt is not None:
                        self.max_receipt_gap = max(self.max_receipt_gap, received_at - self.last_receipt)
                    self.last_receipt = received_at
            if record['_event'] == 'V04_CHUNK':
                chunk = int(record['chunk_id'])
                if record['stage'] == 'start':
                    if self.active_chunk is not None or chunk != self.last_chunk + 1:
                        raise ValueError('UART chunk start missing/duplicate/out of order')
                    self.active_chunk = chunk
                else:
                    if chunk != self.active_chunk: raise ValueError('UART chunk end mismatch')
                    self.last_chunk = chunk
                    self.active_chunk = None
            for key in ('sample_id', 'event_id'):
                if key not in record: continue
                stream = (record['_event'], record.get('behavior'), record.get('stage'))
                if stream not in self.ids and len(self.ids) >= 128: raise ValueError('too many UART populations')
                value = int(record[key]); previous = self.ids.get(stream)
                # E-stop stages share event IDs; independent assertion/release streams
                # need monotonic IDs, while sample populations require no gaps.
                if previous is None and key == 'sample_id' and value != 1:
                    raise ValueError('UART initial sample ID is missing')
                if previous is not None and (value <= previous or (key == 'sample_id' and value != previous + 1)):
                    raise ValueError('UART record ID loss/reset')
                self.ids[stream] = value
        if len(self.buffer) > MAX_LINE: raise ValueError('UART partial line exceeds bound')

    def finish(self):
        if self.buffer: raise ValueError('truncated UART record')
        if self.active_chunk is not None: raise ValueError('UART chunk missing end')
        if self.beats < 2: raise ValueError('missing UART heartbeat coverage')
        if self.timestamp - self.beat_time > self.max_gap: raise ValueError('UART trailing heartbeat gap')
        return dict(records=self.records, heartbeats=self.beats)


def sha(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        while data := stream.read(READ_BYTES): digest.update(data)
    return digest.hexdigest()


def campaign_size(root):
    total = 0
    for folder, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            path = Path(folder) / name
            if path.is_symlink(): raise ValueError('campaign evidence must not contain symlinks')
        for name in files: total += (Path(folder) / name).stat().st_size
    return total


class Budget:
    def __init__(self, root):
        self.root = root
        self.used = campaign_size(root)

    def check(self, reserve, final=False):
        if not final and self.used >= CONTROL_STOP: raise ValueError('campaign controlled budget stop (not a passing soak)')
        if self.used + reserve > HARD_CAP: raise ValueError('campaign hard evidence cap')
        if shutil.disk_usage(self.root)[2] < reserve + (0 if final else RESERVE): raise OSError('disk reserve exhausted')

    def write(self, stream, data, final=False):
        self.check(len(data), final=final)
        stream.write(data)
        stream.flush()
        self.used += len(data)


def json_line(stream, record, budget=None, final=False):
    data = (json.dumps(record, sort_keys=True) + '\n').encode()
    if budget: budget.write(stream, data, final=final)
    else:
        stream.write(data)
        stream.flush()


def retain_chunk(data, run, index, offset, budget, final=False):
    budget.check(len(data) + 65536, final=final)
    path = run / f'{index:08d}.zst.part'
    start = time.time_ns()
    with open(path, 'xb') as output:
        process = subprocess.run([ZSTD, '-q', '-1', '-c'], input=data, stdout=output, stderr=subprocess.PIPE)
        output.flush()
        os.fsync(output.fileno())
    budget.used += path.stat().st_size
    if process.returncode: raise ValueError(f'zstd compressor exited {process.returncode}: {process.stderr[:200]!r}')
    final = path.with_suffix('')
    path.rename(final)
    return dict(type='chunk', id=index, file=final.name, offset=offset, samples=len(data),
                sha256=sha(final), raw_sha256=hashlib.sha256(data).hexdigest(),
                bytes=final.stat().st_size, started_ns=start, ended_ns=time.time_ns(), compressor_exit=process.returncode)


def archive_stream(stream, run, campaign, config, chunk_bytes=CHUNK_BYTES):
    """Synthetic/import helper; deliberately cannot create physical evidence."""
    validate_config(config)
    integer(chunk_bytes, 1, CHUNK_BYTES, 'chunk size')
    run.mkdir()
    budget = Budget(campaign)
    with open(run / 'manifest.jsonl', 'xb') as manifest:
        json_line(manifest, dict(type='header', format=1, source='synthetic-or-import', config=config, chunk_bytes=chunk_bytes), budget)
        offset = 0
        try:
            index = 0
            while data := stream.read(chunk_bytes):
                record = retain_chunk(data, run, index, offset, budget)
                json_line(manifest, record, budget)
                offset += len(data); index += 1
            if offset != config['samples']: raise ValueError('import sample count mismatch')
            json_line(manifest, dict(type='end', complete=True, samples=offset, chunks=index, acquisition_exit=0), budget, final=True)
        except BaseException as error:
            json_line(manifest, dict(type='end', complete=False, samples=offset, error=str(error)), budget, final=True)
            raise


def read_json_lines(path):
    with open(path, 'rb') as stream:
        while line := stream.readline(MAX_CONFIG + 1):
            if len(line) > MAX_CONFIG or not line.endswith(b'\n'): raise ValueError('oversized/truncated manifest record')
            yield json.loads(line)


def replay(run, require_uart=True):
    records = iter(read_json_lines(run / 'manifest.jsonl'))
    header = next(records, {})
    if header.get('type') != 'header' or type(header.get('format')) is not int or header.get('format') != 1: raise ValueError('missing/invalid manifest header')
    if header.get('source') not in ('sigrok', 'synthetic-or-import'): raise ValueError('unknown evidence source')
    observer = Waveform(header['config'])
    chunk_limit = integer(header['chunk_bytes'], 1, CHUNK_BYTES, 'chunk size')
    count = 0
    footer = None
    for record in records:
        if footer is not None: raise ValueError('manifest records after completion')
        if record.get('type') == 'end':
            footer = record
            continue
        for field in ('id', 'offset', 'samples', 'bytes', 'started_ns', 'ended_ns', 'compressor_exit'):
            integer(record.get(field), 0, 2**63 - 1, 'chunk ' + field)
        for field in ('sha256', 'raw_sha256'):
            if not isinstance(record.get(field), str) or not re.fullmatch('[0-9a-f]{64}', record[field]):
                raise ValueError('invalid chunk SHA-256')
        if record['started_ns'] > record['ended_ns']: raise ValueError('invalid chunk timestamps')
        if record.get('type') != 'chunk' or record.get('id') != count or record.get('offset') != observer.offset:
            raise ValueError('missing/duplicate/reordered chunk')
        if record.get('file') != f'{count:08d}.zst': raise ValueError('chunk filename mismatch')
        size = integer(record.get('samples'), 1, chunk_limit, 'chunk samples')
        path = run / record['file']
        if path.is_symlink() or path.stat().st_size != record['bytes'] or sha(path) != record['sha256']:
            raise ValueError('compressed chunk integrity failure')
        if record.get('compressor_exit') != 0: raise ValueError('compressor failed')
        process = subprocess.Popen([ZSTD, '-q', '-d', '-c', str(path)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            data = process.stdout.read(size + 1)
            if len(data) != size: raise ValueError('decompressed chunk size mismatch')
            if process.wait(timeout=10) != 0: raise ValueError('zstd decompression failed')
        finally:
            process.stdout.close()
            if process.poll() is None: process.kill(); process.wait()
        if hashlib.sha256(data).hexdigest() != record['raw_sha256']: raise ValueError('raw chunk integrity failure')
        observer.feed(data)
        count += 1
    if not footer or footer.get('complete') is not True:
        raise ValueError('acquisition incomplete or failed')
    for field in ('acquisition_exit', 'chunks', 'samples'):
        integer(footer.get(field), 0, 2**63 - 1, 'completion ' + field)
    if footer.get('acquisition_exit') != 0:
        raise ValueError('acquisition incomplete or failed')
    if footer.get('chunks') != count or footer.get('samples') != observer.offset:
        raise ValueError('completion counts differ')
    report = observer.finish()
    if require_uart:
        uart_path = run / 'uart.log'
        if sha(uart_path) != footer.get('uart_sha256'): raise ValueError('UART integrity failure')
        uart = Uart(header['config']['uart_max_gap_ns'])
        with open(uart_path, 'rb') as stream:
            while data := stream.read(READ_BYTES): uart.feed(data)
        report['uart'] = uart.finish()
    if header.get('source') == 'sigrok':
        if not require_uart: raise ValueError('sigrok replay requires UART')
        check_receipts(footer.get('uart_receipts', {}), footer['elapsed_seconds'], header['config']['uart_max_gap_ns'], report['uart']['heartbeats'])
        if footer.get('sr_df_end') is not True or footer.get('loaded_library_verified') is not True:
            raise ValueError('missing sigrok completion/runtime proof')
        if sha(run / 'analyzer.log') != footer.get('analyzer_sha256'): raise ValueError('analyzer log integrity failure')
    report.update(physical_acceptance=False, evidence_source=header.get('source'),
                  verdict='OFFLINE CHECK PASS; physical qualification remains external')
    return report


def check_receipts(receipts, elapsed, max_gap_ns, beats):
    gap = max_gap_ns / 1e9
    if set(receipts) != {'first_seconds', 'last_seconds', 'max_gap_seconds', 'heartbeats'}:
        raise ValueError('missing host UART heartbeat coverage')
    first, last, maximum = (receipts[k] for k in ('first_seconds', 'last_seconds', 'max_gap_seconds'))
    if any(type(v) not in (int, float) or not 0 <= v <= elapsed for v in (first, last, maximum)):
        raise ValueError('invalid host UART receipt times')
    if first > last or first > gap or elapsed - last > gap or maximum > gap or receipts['heartbeats'] != beats:
        raise ValueError('host UART heartbeat coverage gap')


def pinned_runtime(config):
    runtime = config.get('runtime', {})
    if set(runtime) != {'sigrok', 'libsigrok', 'fx2_patch'}: raise ValueError('pin sigrok, libsigrok and retained FX2 counter patch')
    for name, item in runtime.items():
        if not isinstance(item, dict) or set(item) != {'path', 'sha256'}: raise ValueError(f'invalid runtime pin: {name}')
        path = Path(item['path'])
        if not path.is_absolute() or sha(path) != item['sha256']: raise ValueError(f'runtime hash mismatch: {name}')
    return runtime


def analyzer_chunk(tail, data):
    text = tail + data
    if re.search(rb'overflow|dropped|USB transfer error', text, re.I):
        raise ValueError('analyzer reported acquisition loss')
    return text[-MAX_LINE:], b'SR_DF_END' in text


def library_loaded(pid, path):
    try:
        maps = Path(f'/proc/{pid}/maps').read_text()
        return any(line.split()[-1] == str(Path(path).resolve()) for line in maps.splitlines())
    except FileNotFoundError:
        return False


def capture(config, campaign, run_name, uart_path, driver):
    validate_config(config)
    runtime = pinned_runtime(config)
    if not re.fullmatch('[a-zA-Z0-9_-]{1,80}', run_name): raise ValueError('invalid run directory name')
    campaign.mkdir(parents=True, exist_ok=True)
    with open(campaign / '.shrike-bench.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        run = campaign / run_name
        run.mkdir()
        budget = Budget(campaign)
        observer = Waveform(config)
        uart = Uart(config['uart_max_gap_ns'])
        command = [runtime['sigrok']['path'], '-l', '4', '-d', driver, '-c', 'samplerate=24m',
                   '-C', 'D0,D1,D2,D3,D4,D5,D6,D7', '--samples', str(config['samples']), '-O', 'binary']
        process = None
        uart_fd = None
        old_term = None
        pending = bytearray()
        index = 0
        retained = 0
        loaded = False
        ended = False
        start = time.monotonic()
        deadline = start + config['samples'] / config['sample_rate_hz'] + 60
        footer = dict(type='end', complete=False)
        with open(run / 'manifest.jsonl', 'xb') as manifest, open(run / 'uart.log', 'xb') as uart_log, open(run / 'analyzer.log', 'xb') as analyzer_log:
            json_line(manifest, dict(type='header', format=1, source='sigrok', config=config,
                                    chunk_bytes=CHUNK_BYTES, command=command, started_ns=time.time_ns()), budget)
            try:
                uart_fd = os.open(uart_path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY)
                old_term = termios.tcgetattr(uart_fd)
                settings = termios.tcgetattr(uart_fd)
                settings[0] = 0; settings[1] = 0; settings[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
                settings[3] = 0; settings[4] = termios.B115200; settings[5] = termios.B115200
                settings[6][termios.VMIN] = 0; settings[6][termios.VTIME] = 0
                termios.tcsetattr(uart_fd, termios.TCSANOW, settings)
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ, 'samples')
                    selector.register(process.stderr, selectors.EVENT_READ, 'analyzer')
                    selector.register(uart_fd, selectors.EVENT_READ, 'uart')
                    analyzer_tail = b''
                    outputs = 2
                    while outputs:
                        if time.monotonic() > deadline: raise ValueError('acquisition deadline exceeded')
                        budget.check(CHUNK_BYTES + 65536)
                        since = time.monotonic() - start
                        if since - (uart.last_receipt or 0) > config['uart_max_gap_ns'] / 1e9:
                            raise ValueError('host UART heartbeat deadline exceeded')
                        if not loaded: loaded = library_loaded(process.pid, runtime['libsigrok']['path'])
                        for key, _ in selector.select(timeout=min(1, config['uart_max_gap_ns'] / 2e9)):
                            data = os.read(key.fd, READ_BYTES)
                            if not data:
                                if key.data == 'uart': raise ValueError('UART disconnected')
                                selector.unregister(key.fileobj); outputs -= 1
                                continue
                            if key.data == 'uart':
                                budget.write(uart_log, data); uart.feed(data, time.monotonic() - start)
                            elif key.data == 'analyzer':
                                budget.write(analyzer_log, data)
                                analyzer_tail, chunk_ended = analyzer_chunk(analyzer_tail, data)
                                ended = ended or chunk_ended
                            else:
                                pending.extend(data)
                                if len(pending) >= CHUNK_BYTES:
                                    block = bytes(pending[:CHUNK_BYTES])
                                    record = retain_chunk(block, run, index, retained, budget)
                                    retained += len(block); del pending[:CHUNK_BYTES]
                                    json_line(manifest, record, budget, final=True); index += 1
                                    observer.feed(block)
                    if pending:
                        block = bytes(pending)
                        record = retain_chunk(block, run, index, retained, budget)
                        retained += len(block); pending.clear()
                        json_line(manifest, record, budget, final=True); index += 1
                        observer.feed(block)
                if process.wait(timeout=10) != 0: raise ValueError('sigrok acquisition failed')
                if not loaded or not ended: raise ValueError('missing loaded-library/completion proof')
                observer.finish(); uart.finish()
                check_receipts(dict(first_seconds=uart.first_receipt, last_seconds=uart.last_receipt,
                                    max_gap_seconds=uart.max_receipt_gap, heartbeats=uart.beats),
                               time.monotonic() - start, config['uart_max_gap_ns'], uart.beats)
                pinned_runtime(config)
                footer['complete'] = True
            except BaseException as error:
                footer['error'] = f'{type(error).__name__}: {error}'
            finally:
                if process is not None:
                    if process.poll() is None:
                        process.terminate()
                        try: process.wait(timeout=5)
                        except subprocess.TimeoutExpired: process.kill(); process.wait()
                    footer['acquisition_exit'] = process.returncode
                    process.stdout.close(); process.stderr.close()
                if pending:
                    try:
                        record = retain_chunk(bytes(pending), run, index, retained, budget, final=True)
                        retained += len(pending); pending.clear()
                        json_line(manifest, record, budget, final=True); index += 1
                    except (OSError, ValueError) as error:
                        footer['pending_retention_error'] = str(error)
                if uart_fd is not None:
                    try:
                        if old_term is not None: termios.tcsetattr(uart_fd, termios.TCSANOW, old_term)
                    except OSError as error:
                        footer.update(complete=False, uart_restore_error=str(error))
                    finally:
                        os.close(uart_fd)
                footer.update(samples=retained, chunks=index, sr_df_end=ended, loaded_library_verified=loaded,
                              ended_ns=time.time_ns(), elapsed_seconds=time.monotonic() - start,
                              uart_sha256=sha(run / 'uart.log'), analyzer_sha256=sha(run / 'analyzer.log'),
                              unretained_pending_samples=len(pending), unread_acquisition_samples_unknown=not footer['complete'],
                              campaign_bytes_before_footer=budget.used,
                              uart_receipts=dict(first_seconds=uart.first_receipt, last_seconds=uart.last_receipt,
                                                 max_gap_seconds=uart.max_receipt_gap, heartbeats=uart.beats))
                # The 5 GB reserve permits a final failure record after controlled stop.
                json_line(manifest, footer, budget, final=True)
                os.fsync(manifest.fileno())
        if not footer['complete']: raise ValueError(f'capture failed; retained {run}: {footer.get("error")}')
        return dict(run=str(run), acquisition_complete=True, physical_acceptance=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest='mode', required=True)
    c = commands.add_parser('capture')
    c.add_argument('config', type=Path); c.add_argument('campaign', type=Path); c.add_argument('run')
    c.add_argument('--uart', required=True); c.add_argument('--driver', default='fx2lafw')
    r = commands.add_parser('replay'); r.add_argument('run', type=Path)
    r.add_argument('--synthetic-without-uart', action='store_true', help='non-acceptance fixtures only')
    commands.add_parser('self-test')
    args = parser.parse_args()
    try:
        if args.mode == 'self-test':
            return subprocess.call([sys.executable, '-B', str(Path(__file__).parents[2] / 'tests/scripts/test_shrike_bench.py')])
        if args.mode == 'capture':
            if args.config.stat().st_size > MAX_CONFIG: raise ValueError('configuration exceeds 1 MiB')
            config = json.loads(args.config.read_text())
            report = capture(config, args.campaign, args.run, args.uart, args.driver)
        else:
            if args.synthetic_without_uart:
                header = next(read_json_lines(args.run / 'manifest.jsonl'))
                if header.get('source') != 'synthetic-or-import': raise ValueError('UART bypass is only for synthetic/import fixtures')
            report = replay(args.run, require_uart=not args.synthetic_without_uart)
        print(json.dumps(report, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f'SHRIKE BENCH FAIL: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__': sys.exit(main())
