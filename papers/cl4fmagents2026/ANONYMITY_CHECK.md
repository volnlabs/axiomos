# Anonymity and reproducibility check

## Review PDF and source

- Ten pages: four body, one references, five appendix. US Letter; all fonts embedded; author metadata empty; creation date omitted; no acknowledgements, identifying repository URL, username or local path in the PDF.
- All ten pages visually inspected by the lead and independent reviewers. The final citation/caption-only revision preserves the same layout and is rechecked by the PDF verifier.
- The portable source bundle contains only the required LaTeX, bibliography, unmodified official style, generated tables, figure, Makefile and README. Third-party names/URLs in citations and the official template remain as attribution.
- A clean source build produces the identical PDF: SHA-256 `c2734cf251bccc113c74122a74d1471965731a3d8248992e4949a8737d8674c0`.

## Anonymous evidence archive

- Local revision label is `artifact-r3`; no public revision identifier is exported.
- Source and raw traces are exported with identity-only substitutions. Numeric measurements and installation identities are preserved. `MANIFEST.sha256` hashes exported bytes.
- Original source/executable hashes, source revision and private source/export mapping remain outside the review archive. The audit directory is for the author, not an upload bundle.
- Automated checks reject first-party names/crates, emails, user paths, repository URLs, Git objects/metadata, issue/PR/CI links, symlinks and unsafe paths. Full content is scanned, including tokens crossing chunk boundaries. Manual inspection covers the README, manifests, patch, source/script inventory and PDF.
- ZIP entries use fixed 1980 timestamps and neutral 0644/0755 modes. ZIP64 size/offset metadata is permitted; comments and identifying extended fields are not.
- The clean-check archive has 169 entries, 141,801,683 compressed bytes and 2,781,931,165 uncompressed bytes. It contains no `.git`, `__pycache__` or private-map file.
- Clean extraction verifies every manifest hash, reruns all independent reducers and the renderer, then verifies all hashes again. This passed in 132.9 seconds on the recorded host. All seven numeric paper inputs are byte-identical to regenerated outputs.
- The source subset passes eight Loom models. It intentionally does not include platform/boot dependencies for complete campaign recapture; dependency resolution is not locked. These limits are stated in the paper and archive README.

## Delivery boundary

The workshop permits an appendix outside the four-page body, but does not guarantee appendix reading. Its inspected OpenReview invitation exposes a PDF upload and no supplement field. No upload or hosting occurred. Preparing this anonymous archive does not establish delivery to reviewers.

Automated direct-identifier checks are not a proof that source-code resemblance can never identify an author.

## Final archive status

PASS: the full tree and compressed-content scans completed successfully. The final archive is byte-identical to the independently written, clean-extracted archive; SHA-256 `ae2d25f63a054c1208f7745966c0a88f7ceb3bfa8fff3b98effc5d693054b55e`. Clean extraction regenerated all numeric inputs and passed manifest checks and eight Loom models. No unresolved direct-identifier finding remains.

Editorial follow-up: the abstract and table-reference wording changed, and Appendix G now names both separate ZIPs. The evidence archive and its verified hash are unchanged. A fresh BibTeX-enabled source build reproduced the revised PDF byte-for-byte.

Diagram follow-up: separate invocation tracks, aligned request positions and shaded overlap replace the prior figure. The caption defines the visual notation. The final PDF retains four body pages and five appendix pages; source ZIP hashes and its embedded PDF were checked. The evidence archive is unchanged.

Submission availability correction: the live OpenReview invitation was rechecked and contains only a PDF file field. Appendix G explicitly states that the retained reproduction package is not included. Removed archive filenames and commands addressed to reviewers. Pages 1–7 and 9 render identically; revised pages 8 and 10 were visually checked. The refreshed source archive builds the identical final PDF and passes its manifest and direct-identifier scans.
