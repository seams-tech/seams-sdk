CARGO ?= cargo
TASKS := run --locked --quiet --manifest-path tasks/Cargo.toml --

.PHONY: check vectors-check parity anti-drift lean-check aeneas-check verus-check

check:
	@$(CARGO) $(TASKS) all

vectors-check:
	@$(CARGO) $(TASKS) vectors-check

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
