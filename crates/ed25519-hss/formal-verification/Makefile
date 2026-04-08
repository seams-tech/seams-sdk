CARGO ?= cargo
MANIFEST := ../Cargo.toml
TASK_BIN := run --quiet --manifest-path $(MANIFEST) --bin formal_verification_tasks --

.PHONY: check vectors-check parity lean-check verus-check aeneas-check

check:
	@$(CARGO) $(TASK_BIN) all

vectors-check:
	@$(CARGO) $(TASK_BIN) vectors-check

parity:
	@$(CARGO) $(TASK_BIN) parity

lean-check:
	@$(CARGO) $(TASK_BIN) lean-check

verus-check:
	@$(CARGO) $(TASK_BIN) verus-check

aeneas-check:
	@$(CARGO) $(TASK_BIN) aeneas-check
