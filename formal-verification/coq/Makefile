.PHONY: all coqchk clean

COQPROJECT ?= _CoqProject
COQMAKEFILE ?= CoqMakefile

all: $(COQMAKEFILE)
	$(MAKE) -f $(COQMAKEFILE) all

$(COQMAKEFILE): $(COQPROJECT)
	coq_makefile -f $(COQPROJECT) -o $(COQMAKEFILE)

coqchk: all
	coqchk -Q Theories FormalVerification FormalVerification.Root

clean:
	if [ -f "$(COQMAKEFILE)" ]; then $(MAKE) -f "$(COQMAKEFILE)" clean; fi
	rm -f "$(COQMAKEFILE)" .*.aux
