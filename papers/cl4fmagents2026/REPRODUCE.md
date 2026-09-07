# Reproduction commands

Run from the research worktree. These commands perform local builds and captures only. Validation used Python 3.14.7, Rust/Cargo 1.98.0-nightly (2026-07-01), pdfTeX 1.40.29 and the included official style. Clean raw-data reduction took about 133 seconds on the recorded host; the uncompressed anonymous archive needs about 2.8 GB, plus build space.

## New capture

```sh
CARGO_TARGET_DIR=/home/utkarsh/Work/axiomOS/target python3 scripts/benchmark/reproduce-update-publication.py --output target/cl4fmagents-v3/capture-r3
```

Use a new ignored output directory when repeating the campaign; existing evidence is never overwritten. The paired replay directory is `<output>-adaptation`. The driver pins dispatcher/updater to CPUs 12/14 by default; use its two affinity flags on another machine. The grid is declared in `docs/plans/active/cl4fmagents-evidence-v3.md` before capture.

## Every derived table, without new experiments

```sh
python3 scripts/benchmark/analyze-update-transaction.py target/cl4fmagents-v3/capture-r3/trace.jsonl --output-dir target/cl4fmagents-v3/reduced/publication
python3 scripts/benchmark/analyze-update-cost.py target/cl4fmagents-v3/capture-r3/cost-trace.jsonl --output-dir target/cl4fmagents-v3/reduced/publication
python3 scripts/benchmark/analyze-update-adaptation.py target/cl4fmagents-v3/capture-r3-adaptation/adaptation-trace.jsonl --output-dir target/cl4fmagents-v3/reduced/adaptation
python3 papers/cl4fmagents2026/render_tables.py --publication target/cl4fmagents-v3/reduced/publication --adaptation target/cl4fmagents-v3/reduced/adaptation --raw-cost target/cl4fmagents-v3/capture-r3/cost-trace.jsonl --output-dir target/cl4fmagents-v3/reduced/tables
```

The publication reducer supplies the supporting fault matrix. The cost reducer supplies logical request rows, process summaries, four timing endpoints and threshold populations. The replay reducer supplies legacy results separately from all 500 grid/stress scenarios, request-level timing, and two corrective cases. The renderer supplies the main sweep, cost and corrective tables, appendix distributions and headline macros. No paper cell is computed by hand.

## Checks and paper build

```sh
python3 scripts/benchmark/test_update_cost_analysis.py
python3 scripts/benchmark/test_update_adaptation_analysis.py
CARGO_TARGET_DIR=/home/utkarsh/Work/axiomOS/target python3 scripts/benchmark/test_update_artifact_runner.py
python3 papers/cl4fmagents2026/test_render_tables.py
python3 scripts/benchmark/test_package_anonymous_publication.py --helpers-only
CARGO_TARGET_DIR=/home/utkarsh/Work/axiomOS/target cargo test --locked --release -p kernel --features kernel_bpf/embedded-profile,bpf-unsigned-development,bpf-update-diagnostics --test bpf_update_transaction -- --test-threads=1
CARGO_TARGET_DIR=/home/utkarsh/Work/axiomOS/target cargo test --locked -p kernel_bpf --features loom-model,cloud-profile --test concurrency_model
make -C papers/cl4fmagents2026
python3 papers/cl4fmagents2026/verify.py
```

Set `TMPDIR` to a directory on a disk with several GB free for independent verification. The verifier regenerates evidence into a temporary directory and checks hashes; it does not rewrite retained raw captures. Inspect every page of the final PDF visually as well.

## Anonymous export and clean extraction

```sh
python3 scripts/benchmark/package-anonymous-publication.py --output-root target/cl4fmagents-v3/package
```

Extract `artifact-r3.zip` into a fresh directory, enter `artifact-r3`, then run:

```sh
sha256sum -c MANIFEST.sha256
python3 scripts/reproduce.py
sha256sum -c MANIFEST.sha256
cargo test --manifest-path source/runtime-core/Cargo.toml --features loom-model,cloud-profile --test concurrency_model
```

The anonymous package reproduces retained reductions and the standalone core model. It does not include the complete platform/boot dependencies needed to recapture the hosted manager campaigns. Original capture manifests and the `.private-map.json` file are private provenance, not review material. Supplement delivery must use a supported venue channel; no upload or hosting occurs here.
