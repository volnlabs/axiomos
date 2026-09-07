OUT := build
PDF := who-guards-the-update.pdf

.PHONY: all
all:
	mkdir -p $(OUT)
	sha256sum Makefile *.tex *.bib *.sty > $(OUT)/inputs.sha256
	pdflatex -interaction=nonstopmode -halt-on-error -output-directory=$(OUT) main.tex > $(OUT)/compile.log
	cd $(OUT) && BIBINPUTS=..: bibtex main >> compile.log
	pdflatex -interaction=nonstopmode -halt-on-error -output-directory=$(OUT) main.tex >> $(OUT)/compile.log
	pdflatex -interaction=nonstopmode -halt-on-error -output-directory=$(OUT) main.tex >> $(OUT)/compile.log
	cp $(OUT)/main.pdf $(PDF)
	sha256sum -c $(OUT)/inputs.sha256 >> $(OUT)/compile.log
	sha256sum $(PDF) >> $(OUT)/inputs.sha256
