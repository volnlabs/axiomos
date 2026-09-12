# PhysWorldAI revision verification

Target: the announced non-archival track. Recheck its separate portal, template instructions and artifact-delivery options when it opens. No submission, remote push or new experiment was performed.

## Changes

- Added a separate manuscript under papers/physworldai2026; CL4FMAgents sources remain unchanged.
- Updated workshop title/footer, paper title and metadata.
- Reframed motivation around changing physical conditions and controller retuning; highlighted payload-shift and corrective-stop evaluation.
- Retained the five-part contract and all empirical claims, including the availability counter-hazard and lack of starvation, physical-safety and downstream-fencing guarantees.
- Appendix G describes a separately retained package without assuming the future non-archival form's upload capabilities.

## Verification

PASS: four-page body limit; three-to-five-page appendix after references; anonymous PDF; verified provenance and trace-derived tables/prose.

- All ten pages rendered and visually inspected: four body pages, one reference page, five appendix pages; no clipping or overlap.
- Official style, bibliography, diagram and all seven numeric inputs byte-identical to CL4FMAgents sources; all 14 cited keys resolve.
- PDF author field empty; no creation date; fonts embedded; correct workshop name and Extended abstract subject.
- Portable source builds byte-identical PDF with pdfLaTeX and BibTeX. ZIP manifest, embedded PDF equality and first-party identifier checks pass.
- PDF SHA-256: `2ae864ac12215e4efb91a2591a052b4762df00f291ea821e18c8b4d37ffcff4b`.

## Commands

```sh
make -C papers/physworldai2026
python3 papers/physworldai2026/verify.py
```

The verification reduces retained traces and runs the existing renderer self-tests; it does not recapture experiments. Raw evidence lives outside Git and must be supplied at the documented paths or through the evidence-directory overrides. The portable source ZIP builds frozen inputs without that data.
