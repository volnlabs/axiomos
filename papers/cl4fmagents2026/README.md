# Who Guards the Update?

Anonymous CL4FMAgents short paper: at most four content pages, followed by references.

```sh
make
python3 verify.py
```

Output: `who-guards-the-update.pdf`. Upload that PDF only. The ignored `private/` directory and repository evidence contain author-facing information and are not anonymous review material. The paper reports software publication correctness, not learning quality or physical safety.

`results.tex` is generated from the retained real Rust campaign in `docs/performance/evidence/update-transaction`; regenerate it with the analyzer documented there, then copy `result-table.tex` here. Verification checks the PDF page limit, anonymity, citations/build warnings and every table row against the raw trace. Visually inspect every rendered page after layout changes.

`neurips_2026.sty` is the unmodified official 2026 style. The manuscript uses `dblblindworkshop` and supplies the workshop title. No OpenReview submission receipt has been obtained.
