#!/usr/bin/env python3
"""Render review tables from validated analyses without changing retained evidence."""
import argparse
import json
from pathlib import Path


def render(publication, adaptation, destination):
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
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--publication', type=Path, required=True)
    parser.add_argument('--adaptation', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    render(args.publication, args.adaptation, args.output_dir)


if __name__ == '__main__':
    main()
