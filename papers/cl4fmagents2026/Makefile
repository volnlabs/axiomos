OUT := build
PDF := who-guards-the-update.pdf

UPDATE_PUBLICATION_EVIDENCE ?= ../../docs/performance/evidence/update-transaction-v2
UPDATE_ADAPTATION_EVIDENCE ?= ../../docs/performance/evidence/update-adaptation-v1

.PHONY: all
all:
	mkdir -p $(OUT)
	python3 render_tables.py --publication "$(UPDATE_PUBLICATION_EVIDENCE)" --adaptation "$(UPDATE_ADAPTATION_EVIDENCE)" --output-dir .
	sha256sum Makefile render_tables.py *.tex *.bib *.sty > $(OUT)/inputs.sha256
	pdflatex -interaction=nonstopmode -halt-on-error -output-directory=$(OUT) main.tex > $(OUT)/compile.log
	cd $(OUT) && BIBINPUTS=..: bibtex main >> compile.log
	pdflatex -interaction=nonstopmode -halt-on-error -output-directory=$(OUT) main.tex >> $(OUT)/compile.log
	pdflatex -interaction=nonstopmode -halt-on-error -output-directory=$(OUT) main.tex >> $(OUT)/compile.log
	cp $(OUT)/main.pdf $(PDF)
	sha256sum -c $(OUT)/inputs.sha256 >> $(OUT)/compile.log
	sha256sum $(PDF) >> $(OUT)/inputs.sha256
