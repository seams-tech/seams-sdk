.PHONY: check proofs coqchk vectors check-vectors guards parity clean

check: guards proofs coqchk check-vectors parity

proofs:
	$(MAKE) -C coq all

coqchk:
	$(MAKE) -C coq coqchk

vectors:
	./scripts/export-vectors.sh

check-vectors:
	./scripts/check-vectors-clean.sh

guards:
	./scripts/check-no-admitted.sh
	./scripts/check-no-axioms.sh

parity:
	./scripts/check-rust-parity.sh

clean:
	$(MAKE) -C coq clean
