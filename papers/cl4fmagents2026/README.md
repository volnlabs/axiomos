# Who Guards the Update?

Anonymous CL4FMAgents short paper: at most four content pages, followed by references and a three-to-five-page technical appendix.

```sh
make
python3 verify.py
```

Output: `who-guards-the-update.pdf`. Upload that PDF and the separately generated `artifact-r2.zip` supplement. The ignored `private/` directory and repository evidence contain author-facing information and are not anonymous review material. The paper reports software publication correctness, hosted costs, and a deterministic simulated control replay. It does not evaluate foundation-model learning or physical safety.

The v1 campaign remains in `docs/performance/evidence/update-transaction`. The strengthened campaign uses a new directory, `update-transaction-v2`, and compares guarded replacement with a host-only atomic publication path sharing the same manager checks. Host callbacks retain real invocation guards but do not execute privileged bytecode.

From the repository root, reproduce the release correctness campaign, 80 fresh-process measurement runs, separate adaptation replay, generated tables, and paper checks:

```sh
CARGO_TARGET_DIR=/home/utkarsh/Work/axiomOS/target python3 scripts/benchmark/reproduce-update-publication.py --output /tmp/update-publication-reproduction
```

Choose an existing writable Cargo target directory with sufficient disk space on other machines. The output directory and its `<output>-adaptation` sibling must not exist. The measurement driver records affinity and requires two distinct physical cores; its defaults are CPU 12 and 14 on the developer host. No scheduler or governor settings are changed. The retained manifest hashes source and measured executables. Raw scheduler misses and latency tails are retained.

`render_tables.py` renders `results.tex`, `costs.tex`, `cost-note.tex`, and `adaptation.tex` from the validated retained analyses. The original trace analyzers and their derived outputs remain unchanged; `verify.py` checks both their reproduction and the presentation tables. Verification checks source/PDF build hashes, page limit, anonymity, citations/build warnings, artifact provenance, and trace-derived tables. Visually inspect every rendered page after layout changes. The original repository evidence contains developer-identifying provenance and must not accompany the anonymous PDF. Export a separate anonymized snapshot with `scripts/benchmark/package-anonymous-publication.py`; its README states exactly which analyses and source tests can be reproduced.

`neurips_2026.sty` is the unmodified official 2026 style. The manuscript uses `dblblindworkshop` and supplies the workshop title. The official style hardcodes a main-conference notice for anonymous modes; `main.tex` overrides only that notice text to name the workshop, without changing the style, margins, spacing, or fonts. No OpenReview submission receipt has been obtained.

The separate replay evidence is `docs/performance/evidence/update-adaptation-v1`. Its fixed candidate sequence is generated once by a feedback tuner and replayed through real manager installations and host guard callbacks. The plant and control arithmetic are simulated; callbacks do not execute privileged BPF code. A local paired utility probe compares gains from identical activation state/time, separately from aggregate before/after tracking RMSE. One deliberately long invocation exposes the difference between pointer publication and invocation quiescence; it is a finite witness, not an estimated failure rate.

To reproduce only the replay into a new directory:

```sh
CARGO_TARGET_DIR=/home/utkarsh/Work/axiomOS/target python3 scripts/benchmark/reproduce-update-adaptation.py --output /tmp/update-adaptation-reproduction
```

The technical appendix separates the nine paired AP/GR scenarios from retained integration-test assertions. It adds successful-call timing details and first-actual-call-to-success elapsed time derived from the original cost records; the six unfinished GR requests remain explicitly censored. `test_render_tables.py` checks this derivation. No new timing capture is used. `artifact-r2` includes the extended derived outputs, selected sanitized integration-test evidence, and recorded environment summary; the prior artifact-r1 remains unchanged.
