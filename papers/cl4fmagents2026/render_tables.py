#!/usr/bin/env python3
"""Render review tables from validated analyses without changing retained evidence."""
import argparse
import csv
import json
import math
from collections import defaultdict
from pathlib import Path


def _stats(values):
    if not values:
        return None
    ordered = sorted(values)
    rank = lambda q: ordered[math.ceil(q * len(ordered)) - 1]
    return {"count": len(values), "median": rank(0.5), "p99": rank(0.99),
            "max": ordered[-1]}


def _integer(record, name):
    value = record.get(name)
    if not isinstance(value, int) or value < 0:
        raise ValueError(f"update has invalid {name}")
    return value


def completion_analysis(records):
    """Derive first-call-to-success time, retaining final Busy requests as censored."""
    grouped = defaultdict(list)
    for record in records:
        if record.get("kind") != "update":
            continue
        protocol = record.get("protocol")
        hold = record.get("hold_us")
        run = record.get("run")
        if protocol not in ("atomic", "guarded") or not isinstance(hold, int) or not isinstance(run, int):
            raise ValueError("update has invalid run identity")
        grouped[(protocol, hold, run)].append(record)
    if not grouped:
        raise ValueError("raw cost trace has no update records")

    requests = []
    runs = []
    for (protocol, hold, run), updates in sorted(grouped.items()):
        logical = 0
        retry = 1
        first = None
        previous_end = None
        run_requests = []
        busy_attempts = 0
        for attempt, record in enumerate(updates):
            if (record.get("attempt") != attempt or record.get("logical_update") != logical
                    or record.get("retry_ordinal") != retry):
                raise ValueError(f"invalid retry sequence at {(protocol, hold, run, attempt)}")
            latency = _integer(record, "latency_ns")
            scheduled = _integer(record, "scheduled_offset_ns")
            started = _integer(record, "started_offset_ns")
            lateness = _integer(record, "lateness_ns")
            if started < scheduled or lateness != started - scheduled:
                raise ValueError(f"invalid update timing at {(protocol, hold, run, attempt)}")
            if previous_end is not None and started < previous_end:
                raise ValueError(f"overlapping update attempts at {(protocol, hold, run, attempt)}")
            previous_end = started + latency
            if first is None:
                first = record
            outcome = record.get("outcome")
            if outcome == "Ok":
                completed = True
            elif outcome == "Busy" and protocol == "guarded":
                completed = False
                busy_attempts += 1
            else:
                raise ValueError(f"unexpected update outcome {outcome!r}")

            if completed:
                end = started + latency
                request = {
                    "protocol": protocol, "hold_us": hold, "run": run,
                    "logical_update": logical, "attempts": retry,
                    "outcome": outcome, "completed": True, "censored": False,
                    "first_scheduled_offset_ns": first["scheduled_offset_ns"],
                    "first_started_offset_ns": first["started_offset_ns"],
                    "last_end_offset_ns": end,
                    "elapsed_ns": end - first["started_offset_ns"],
                }
                requests.append(request)
                run_requests.append(request)
                logical += 1
                retry = 1
                first = None
            else:
                retry += 1

        if first is not None:
            last = updates[-1]
            end = last["started_offset_ns"] + last["latency_ns"]
            request = {
                "protocol": protocol, "hold_us": hold, "run": run,
                "logical_update": logical, "attempts": retry - 1,
                "outcome": last["outcome"], "completed": False, "censored": True,
                "first_scheduled_offset_ns": first["scheduled_offset_ns"],
                "first_started_offset_ns": first["started_offset_ns"],
                "last_end_offset_ns": end,
                "elapsed_ns": end - first["started_offset_ns"],
            }
            requests.append(request)
            run_requests.append(request)

        completed_elapsed = [r["elapsed_ns"] for r in run_requests if r["completed"]]
        completed = len(completed_elapsed)
        runs.append({
            "protocol": protocol, "hold_us": hold, "run": run,
            "raw_attempts": len(updates), "requests_started": len(run_requests),
            "completed": completed, "censored": len(run_requests) - completed,
            "busy_attempts": busy_attempts,
            "first_attempt_successes": sum(r["completed"] and r["attempts"] == 1 for r in run_requests),
            "retried_successes": sum(r["completed"] and r["attempts"] > 1 for r in run_requests),
            "elapsed_ns": _stats(completed_elapsed),
        })

    aggregates = []
    for protocol, hold in sorted({(r["protocol"], r["hold_us"]) for r in runs},
                                 key=lambda key: (key[1], key[0])):
        members = [r for r in runs if (r["protocol"], r["hold_us"]) == (protocol, hold)]
        elapsed = [r["elapsed_ns"] for r in members if r["elapsed_ns"]]
        total = lambda name: sum(r[name] for r in members)
        aggregates.append({
            "protocol": protocol, "hold_us": hold, "runs": len(members),
            "raw_attempts": total("raw_attempts"),
            "requests_started": total("requests_started"), "completed": total("completed"),
            "censored": total("censored"), "busy_attempts": total("busy_attempts"),
            "first_attempt_successes": total("first_attempt_successes"),
            "retried_successes": total("retried_successes"),
            "elapsed_ns": None if not elapsed else {
                "runs_with_completions": len(elapsed),
                "median_of_run_medians": _stats([r["median"] for r in elapsed])["median"],
                "median_of_run_p99": _stats([r["p99"] for r in elapsed])["median"],
                "observed_max": max(r["max"] for r in elapsed),
            },
        })
    return requests, runs, aggregates


def _write_csv(path, rows, columns):
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def _flat_summary(row):
    elapsed = row["elapsed_ns"] or {}
    return {k: v for k, v in row.items() if k != "elapsed_ns"} | {
        "elapsed_count": elapsed.get("count", row.get("completed", 0)),
        "elapsed_median_ns": elapsed.get("median", elapsed.get("median_of_run_medians", "")),
        "elapsed_p99_ns": elapsed.get("p99", elapsed.get("median_of_run_p99", "")),
        "elapsed_max_ns": elapsed.get("max", elapsed.get("observed_max", "")),
    }


def _cost_metric(costs, protocol, hold, metric):
    aggregate = next(r for r in costs["aggregates"]
                     if (r["protocol"], r["hold_us"]) == (protocol, hold))
    summary = aggregate["latency_ns"][metric]
    if summary is None:
        return None
    maxima = [r["latency_ns"][metric]["max"] for r in costs["runs"]
              if (r["protocol"], r["hold_us"]) == (protocol, hold)
              and r["latency_ns"][metric] is not None]
    return (summary["median_of_run_medians"], summary["median_of_run_p99"], max(maxima))


def _triple_us(values, digits=2):
    if values is None:
        return "--"
    return "/".join(f"{value / 1000:.{digits}f}" for value in values)


def render(publication, adaptation, destination, raw_cost=None):
    destination.mkdir(parents=True, exist_ok=True)
    fault = json.loads((publication / 'analysis.json').read_text())['paired_summary']
    costs = json.loads((publication / 'cost-analysis.json').read_text())
    replay = json.loads((adaptation / 'analysis.json').read_text())['protocols']
    rows = {}

    def table(name, columns, header, body):
        rows[name] = body
        lines = ['% Generated from validated analyses; presentation only.',
                 r'\begin{tabular}{' + columns + '}', r'\toprule',
                 ' & '.join(header) + r' \\', r'\midrule']
        lines += [' & '.join(row) + r' \\' for row in body]
        lines += [r'\bottomrule', r'\end{tabular}']
        (destination / name).write_text('\n'.join(lines) + '\n')

    protocols = ('atomic_publication', 'transactional')
    table('results.tex', r'@{}p{0.35\linewidth}p{0.28\linewidth}p{0.30\linewidth}@{}',
          ('Observation / fault', 'AP', 'GR'), [
        ('Published-cardinality violations, multi / empty',
         *(f"{fault[p]['dual_snapshots']}/{fault[p]['empty_snapshots']}" for p in protocols)),
        ('Old/new invocation overlaps', *(str(fault[p]['guard_overlap']) for p in protocols)),
        ('Snapshot preparation', 'reject; preserve', 'reject; preserve'),
        ('Authority / budget', 'reject (2/2)', 'reject (2/2)'),
        ('Stale / retry / ABA', 'reject (3/3)', 'reject (3/3)'),
        ('Concurrent proposers', 'one winner', 'one winner'),
        ('Replace while A invocation is active', 'B becomes current; A/B guards overlap',
         r'\texttt{Busy}; A remains current; retry succeeds'),
    ])
    index = {(r['protocol'], r['hold_us']): r for r in costs['aggregates']}
    body = []
    for hold in (0, 10, 100, 500):
        ap, gr = (index[(p, hold)] for p in ('atomic', 'guarded'))
        assert ap['runs'] == gr['runs'] == 10
        def latency(row):
            x = row['latency_ns']['replace_ok']
            return f"{x['median_of_run_medians']/1000:.2f}/{x['median_of_run_p99']/1000:.2f}"
        skips = sum(gr[k] for k in ('transition_busy_skips', 'execution_busy_skips', 'empty_skips'))
        body.append((str(hold), latency(ap), latency(gr),
                     f"{gr['first_attempt_successes']}/{gr['logical_updates_started']}",
                     f"{skips/gr['successful_updates']:.4f}"))
    table('costs.tex', '@{}rrrrr@{}',
          (r'\shortstack{Hold\\($\mu$s)}',
           r'\shortstack{AP replacement\\median/p99 ($\mu$s)}',
           r'\shortstack{GR replacement\\median/p99 ($\mu$s)}',
           r'\shortstack{GR first-try\\success}',
           r'\shortstack{GR natural skips\\per successful\\activation}'), body)
    protocols = ('frozen', 'atomic', 'guarded')
    table('adaptation.tex', r'@{}p{0.49\linewidth}rrr@{}', ('Metric', 'Frozen', 'AP', 'GR'), [
        ('RMSE pre/post', *(f"{replay[p]['pre_rmse']:.3f}/{replay[p]['post_rmse']:.3f}" for p in protocols)),
        ('Activations improving paired-probe RMSE', *(
            '--' if not replay[p]['activations'] else f"{replay[p]['useful_activations']}/{replay[p]['activations']}"
            for p in protocols)),
        ('Old/new installation guard overlaps', *(str(replay[p]['guard_version_overlaps']) for p in protocols)),
        ('Same-installation guard overlaps', *(str(replay[p]['same_version_overlaps']) for p in protocols)),
        ('Retired predecessor commands', *(str(replay[p]['retired_commands_after_publication']) for p in protocols)),
        ('Dispatch skips', *(str(replay[p]['execution_skips'] + replay[p]['transition_skips']) for p in protocols)),
        ('Successful replacement retries', *(str(replay[p]['successful_retries']) for p in protocols)),
    ])
    note = (publication / 'cost-note.tex').read_text()
    for value in ('Busy', 'TransitionBusy', 'ExecutionBusy', 'Stateless'):
        note = note.replace(r'\textsc{' + value + '}', r'\texttt{' + value + '}')
    # The original note uses plain protocol values; change typography only.
    import re
    note = re.sub(r'(?<![A-Za-z{])(TransitionBusy|ExecutionBusy|Busy)(?![A-Za-z}])', r'\\texttt{\1}', note)
    (destination / 'cost-note.tex').write_text(note)

    raw_cost = raw_cost or publication / 'cost-trace.jsonl'
    records = [json.loads(line) for line in raw_cost.read_text().splitlines() if line.strip()]
    requests, runs, completion = completion_analysis(records)
    completion_index = {(r['protocol'], r['hold_us']): r for r in completion}
    cost_index = {(r['protocol'], r['hold_us']): r for r in costs['aggregates']}
    protocols = (('atomic', 'AP'), ('guarded', 'GR'))

    body = []
    for hold in (0, 10, 100, 500):
        for protocol, label in protocols:
            row = completion_index[(protocol, hold)]
            elapsed = row['elapsed_ns']
            body.append((str(hold), label,
                         _triple_us((elapsed['median_of_run_medians'],), 2) if elapsed else '--',
                         _triple_us((elapsed['median_of_run_p99'],), 2) if elapsed else '--',
                         _triple_us((elapsed['observed_max'],), 2) if elapsed else '--',
                         f"{row['completed']}/{row['requests_started']}", str(row['censored'])))
    table('appendix-completion.tex', '@{}rrllllr@{}',
          (r'\shortstack{Hold\\($\mu$s)}', 'P',
           r'\shortstack{Median run\\median ($\mu$s)}',
           r'\shortstack{Median run\\p99 ($\mu$s)}',
           r'\shortstack{Observed\\max ($\mu$s)}',
           r'\shortstack{Completed/\\started}', 'Cens.'), body)

    body = []
    for hold in (0, 10, 100, 500):
        for protocol, label in protocols:
            cost = cost_index[(protocol, hold)]
            complete = completion_index[(protocol, hold)]
            natural_skips = sum(cost[k] for k in
                                ('transition_busy_skips', 'execution_busy_skips', 'empty_skips'))
            body.append((str(hold), label, _triple_us(_cost_metric(costs, protocol, hold, 'replace_ok')),
                         f"{cost['busy_updates']}/{complete['retried_successes']}",
                         str(natural_skips), str(cost['missed_releases'])))
    table('appendix-cost-details.tex', '@{}rrllll@{}',
          (r'\shortstack{Hold\\($\mu$s)}', 'P',
           r'\shortstack{Successful call\\med/p99/max ($\mu$s)}',
           r'\shortstack{Busy calls/\\retried successes}',
           r'\shortstack{Natural\\skips}',
           r'\shortstack{Missed\\releases}'), body)

    body = []
    for hold in (0, 10, 100, 500):
        for protocol, label in protocols:
            body.append((str(hold), label,
                         _triple_us(_cost_metric(costs, protocol, hold, 'dispatch_ok'), 3),
                         _triple_us(_cost_metric(costs, protocol, hold, 'replace_busy'), 3),
                         _triple_us(_cost_metric(costs, protocol, hold, 'controlled_transition'), 3)))
    table('appendix-dispatch-details.tex', '@{}rrlll@{}',
          (r'\shortstack{Hold\\($\mu$s)}', 'P',
           r'\shortstack{Observer Ok\\med/p99/max ($\mu$s)}',
           r'\shortstack{Update Busy\\med/p99/max ($\mu$s)}',
           r'\shortstack{Controlled TB\\med/p99/max ($\mu$s)}'), body)

    analysis = {
        'schema': 1,
        'metric': {
            'name': 'first-call-start-to-success-or-censor', 'unit': 'ns',
            'start': 'first update started_offset_ns',
            'event': 'successful update return',
            'censor': 'final recorded Busy return at the fixed attempt limit',
        },
        'requests': requests, 'runs': runs, 'aggregates': completion,
        'cost_runs': costs['runs'], 'cost_aggregates': costs['aggregates'],
    }
    (destination / 'appendix-analysis.json').write_text(json.dumps(analysis, indent=2, sort_keys=True) + '\n')
    request_columns = tuple(requests[0])
    _write_csv(destination / 'appendix-requests.csv', requests, request_columns)
    flat_runs = [_flat_summary(row) for row in runs]
    flat_completion = [_flat_summary(row) for row in completion]
    _write_csv(destination / 'appendix-runs.csv', flat_runs, tuple(flat_runs[0]))
    _write_csv(destination / 'appendix-summary.csv', flat_completion, tuple(flat_completion[0]))
    latency_rows = []
    for cost_run in costs['runs']:
        for metric, summary in cost_run['latency_ns'].items():
            latency_rows.append({
                'protocol': cost_run['protocol'], 'hold_us': cost_run['hold_us'],
                'run': cost_run['run'], 'metric': metric,
                'count': 0 if summary is None else summary['count'],
                'median_ns': '' if summary is None else summary['median'],
                'p99_ns': '' if summary is None else summary['p99'],
                'max_ns': '' if summary is None else summary['max'],
            })
    _write_csv(destination / 'appendix-latency-runs.csv', latency_rows,
               tuple(latency_rows[0]))
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--publication', type=Path, required=True)
    parser.add_argument('--adaptation', type=Path, required=True)
    parser.add_argument('--raw-cost', type=Path)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    render(args.publication, args.adaptation, args.output_dir, args.raw_cost)


if __name__ == '__main__':
    main()
