# Who Guards the Update?

Anonymous CL4FMAgents short paper: at most four content pages, followed by references.

```sh
make
python3 verify.py
```

Output: `who-guards-the-update.pdf`. Upload that PDF only. The ignored `private/` directory and repository evidence contain author-facing information and are not anonymous review material. The paper reports software publication correctness, hosted costs, and a deterministic simulated control replay. It does not evaluate foundation-model learning or physical safety.

The v1 campaign remains in `docs/performance/evidence/update-transaction`. The strengthened campaign uses a new directory, `update-transaction-v2`, and compares guarded replacement with a host-only atomic publication path sharing the same manager checks. Host callbacks retain real invocation guards but do not execute privileged bytecode.

From the repository root, reproduce the release correctness campaign, 80 fresh-process measurement runs, separate adaptation replay, generated tables, and paper checks:

```sh
CARGO_TARGET_DIR=/home/utkarsh/Work/axiomOS/target python3 scripts/benchmark/reproduce-update-publication.py --output /tmp/update-publication-reproduction
```

Choose an existing writable Cargo target directory with sufficient disk space on other machines. The output directory and its `<output>-adaptation` sibling must not exist. The measurement driver records affinity and requires two distinct physical cores; its defaults are CPU 12 and 14 on the developer host. No scheduler or governor settings are changed. The retained manifest hashes source and measured executables. Raw scheduler misses and latency tails are retained.

`results.tex`, `costs.tex`, `cost-note.tex`, and `adaptation.tex` are generated from raw traces. Verification checks source/PDF build hashes, page limit, anonymity, citations/build warnings, artifact provenance, and trace-derived tables. Visually inspect every rendered page after layout changes. These artifacts contain developer-identifying provenance and must not accompany the anonymous PDF.

`neurips_2026.sty` is the unmodified official 2026 style. The manuscript uses `dblblindworkshop` and supplies the workshop title. No OpenReview submission receipt has been obtained.

The separate replay evidence is `docs/performance/evidence/update-adaptation-v1`. Its fixed candidate sequence is generated once by a feedback tuner and replayed through real manager installations and host guard callbacks. The plant and control arithmetic are simulated; callbacks do not execute privileged BPF code. A local paired utility probe compares gains from identical activation state/time, separately from aggregate before/after tracking RMSE. One deliberately long invocation exposes the difference between pointer publication and invocation quiescence; it is a finite witness, not an estimated failure rate.

To reproduce only the replay into a new directory:

```sh
CARGO_TARGET_DIR=/home/utkarsh/Work/axiomOS/target python3 scripts/benchmark/reproduce-update-adaptation.py --output /tmp/update-adaptation-reproduction
```
