OUT := build
PDF := who-guards-the-update.pdf

.PHONY: all
all:
	mkdir -p $(OUT)
	pdflatex -interaction=nonstopmode -halt-on-error -output-directory=$(OUT) main.tex > $(OUT)/compile.log
	cd $(OUT) && BIBINPUTS=..: bibtex main >> compile.log
	pdflatex -interaction=nonstopmode -halt-on-error -output-directory=$(OUT) main.tex >> $(OUT)/compile.log
	pdflatex -interaction=nonstopmode -halt-on-error -output-directory=$(OUT) main.tex >> $(OUT)/compile.log
	cp $(OUT)/main.pdf $(PDF)
