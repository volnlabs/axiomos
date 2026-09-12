# Who Guards the Update?

Anonymous four-page CL4FMAgents position paper, followed by one references page.

```sh
make
python3 verify.py
```

The output is `who-guards-the-update.pdf`. Upload that PDF only. The ignored
`private/` directory contains author-facing submission fields and the identifying
claim/evidence ledger; it is not review material. No continual-learning or
physical-safety experiment is claimed by this paper.

`neurips_2026.sty` is the unmodified official 2026 style from
<https://media.neurips.cc/Conferences/NeurIPS2026/Formatting_Instructions_For_NeurIPS_2026.zip>.
The manuscript selects `dblblindworkshop` and supplies the workshop title.

The verification command checks page allocation, author metadata and identifying
text, unresolved LaTeX references, and the exact three reported intervals against
the retained repository log. Visual review of every rendered page is also required
after layout changes.
