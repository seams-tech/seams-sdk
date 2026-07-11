CARGO ?= cargo
TASKS := run --locked --quiet --manifest-path tasks/Cargo.toml --

.PHONY: check reference-spec-check vectors-check cross-language-check parity anti-drift lean-check aeneas-check verus-check constant-time-qualification benchmark-manifest-reproducibility

check:
	@$(CARGO) $(TASKS) all

reference-spec-check:
	@$(CARGO) $(TASKS) reference-spec-check

vectors-check:
	@$(CARGO) $(TASKS) vectors-check

cross-language-check:
	@$(CARGO) $(TASKS) cross-language-check

parity:
	@$(CARGO) $(TASKS) parity

anti-drift:
	@$(CARGO) $(TASKS) anti-drift

lean-check:
	@$(CARGO) $(TASKS) lean-check

aeneas-check:
	@$(CARGO) $(TASKS) aeneas-check

verus-check:
	@$(CARGO) $(TASKS) verus-check

constant-time-qualification:
	@$(CARGO) $(TASKS) constant-time-qualification

benchmark-manifest-reproducibility:
	@$(CARGO) $(TASKS) benchmark-manifest-reproducibility
