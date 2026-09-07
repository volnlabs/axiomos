# Who Guards the Update?

Anonymous CL4FMAgents short systems paper: four content pages, references, and a technical appendix of at most five pages. All work stays on the local research branch. No upload, public release, or submission is performed by the build.

From the repository root, capture, reduce, build, and verify the complete revision:

```sh
CARGO_TARGET_DIR=/home/utkarsh/Work/axiomOS/target python3 scripts/benchmark/reproduce-update-publication.py --output target/cl4fmagents-v3/capture-r3
```

The output and its `-adaptation` sibling must not already exist. Select another ignored output directory for a fresh run. Source files must remain unchanged throughout capture. On another machine, select a writable Cargo target directory and pass `--dispatch-cpu` and `--update-cpu` identifying distinct physical cores. Defaults 12 and 14 match the retained developer host; scheduler/governor settings are not changed.

The campaign includes matched manager faults, 120 fresh hosted measurement processes, the separate legacy replay, 400 complete primary schedule replays, 100 above-period stress replays, and two corrective-stop replays. Raw events, failed captures, compiler commands, source/executable hashes, and environment metadata remain in the private capture directories. Publication and API return are distinct endpoints. Unfinished logical requests remain censored; simulated time is separate from hosted wall-clock measurements.

For an existing capture, rebuild only the paper:

```sh
make -C papers/cl4fmagents2026
python3 papers/cl4fmagents2026/verify.py
```

Override `UPDATE_PUBLICATION_EVIDENCE` and `UPDATE_ADAPTATION_EVIDENCE` to read another capture. The independent reducers reconstruct raw event outcomes; `render_tables.py` performs presentation only. Verification checks provenance, regenerated values, build hashes, page limits, anonymity, citations and layout warnings. Every final page also needs visual inspection.

Generate the anonymous analysis/source subset separately:

```sh
python3 scripts/benchmark/package-anonymous-publication.py --output-root target/cl4fmagents-v3/package
```

Only `artifact-r3.zip` is review material. The package's private map and original captures identify the repository and must not be uploaded. The package regenerates all derived tables and supports the standalone core Loom model; omitted platform/boot modules prevent complete manager-campaign recapture from this source subset. Its README states this limit. The public submission invitation inspected during preparation exposed a PDF field but no supplementary field; the existence of a ZIP does not establish that reviewers will receive it. No external supplement hosting is authorized.

The unmodified official `neurips_2026.sty` uses `dblblindworkshop` with the workshop title. A notice-text override corrects the style's hardcoded anonymous main-conference footer without altering margins, fonts, or spacing. Previous r1/r2 deliverables remain preserved separately.
