ROOTDIR = .
SRC = $(wildcard *.tex)
TARGETS = $(subst .tex,.pdf,$(SRC))
# BIBFILES = $(ROOTDIR)/sources/bibliographie/bibliographie.bib
CLEAN_SUFFIXES = .aux .bbl .blg .log .nav .out .snm .toc .bcf .run.xml .vrb .fdb_latexmk .fls .synctex.gz
CLEAN_FILES = $(foreach s,$(CLEAN_SUFFIXES),$(subst .tex,$(s),$(SRC)))

PDFLATEX = pdflatex

all: $(TARGETS)

%.pdf: %.tex
	$(PDFLATEX) $< -o $@
	$(PDFLATEX) $< -o $@
	$(PDFLATEX) $< -o $@
	rm -f $(CLEAN_FILES)

# $(BIBFILES) $< -o $@

.PHONY: clean scratch

clean: 
	rm -f $(CLEAN_FILES)

scratch: clean
	rm -f $(TARGETS)