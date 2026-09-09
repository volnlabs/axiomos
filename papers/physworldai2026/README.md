# PhysWorldAI 2026 extended abstract

Target: the announced non-archival track (September 29–October 29, 2026), not the September 9 archival deadline. No submission has been made from this branch. Recheck the non-archival portal and delivery rules when it opens.

Official call: https://physworld-org.github.io/physworld.github.io/cfp/

This venue-specific manuscript retains the CL4FMAgents implementation, predeclared experiments, data and bibliography. It changes the title, workshop footer, motivation and concluding evaluation recommendation. The mass shift is imposed by simulation; no physical-property estimator, robot experiment or additional learning result is claimed. The corrective replay remains a two-sided tradeoff, not a physical-safety guarantee.

Build with pdfLaTeX, BibTeX and standard TeX Live packages:

```sh
make -C papers/physworldai2026
python3 papers/physworldai2026/verify.py
```

Both commands use retained evidence in `target/cl4fmagents-v3/capture-r3` and `capture-r3-adaptation`. Override `UPDATE_PUBLICATION_EVIDENCE` and `UPDATE_ADAPTATION_EVIDENCE` if needed (Make variables for the build; environment variables for verification). The verifier independently reduces retained traces; it does not rerun experiments. Raw data are local generated artifacts, not Git-tracked files.

The review-source archive uses a portable Makefile to build the included frozen table inputs without raw-data access. The full evidence package is retained separately; the PDF explicitly does not imply delivery of that package.
