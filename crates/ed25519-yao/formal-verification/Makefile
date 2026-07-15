CARGO ?= cargo
TASKS := run --locked --quiet --manifest-path tasks/Cargo.toml --

.PHONY: check reference-spec-check vectors-check cross-language-check parity anti-drift lean-check aeneas-check verus-check constant-time-qualification phase2b-reconciliation-check phase2b-exit-evidence-readiness-check phase2b-change-control-readiness-check phase2b-review-subject-check phase2b-protected-inputs-check phase2b-independent-host-prepare phase2b-independent-host-finalize phase2b-independent-host-record-check phase2b-review-approval-check benchmark-manifest-reproducibility

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

phase2b-reconciliation-check:
	@$(CARGO) $(TASKS) phase2b-reconciliation-check

phase2b-exit-evidence-readiness-check:
	@$(CARGO) $(TASKS) phase2b-exit-evidence-readiness-check

phase2b-change-control-readiness-check:
	@$(CARGO) $(TASKS) phase2b-change-control-readiness-check

phase2b-review-subject-check:
	@$(CARGO) $(TASKS) phase2b-review-subject-check

phase2b-protected-inputs-check:
	@$(CARGO) $(TASKS) phase2b-protected-inputs-check

phase2b-independent-host-prepare:
	@$(CARGO) $(TASKS) phase2b-independent-host-prepare

phase2b-independent-host-finalize:
	@$(CARGO) $(TASKS) phase2b-independent-host-finalize

phase2b-independent-host-record-check:
	@$(CARGO) $(TASKS) phase2b-independent-host-record-check

phase2b-review-approval-check:
	@$(CARGO) $(TASKS) phase2b-review-approval-check

benchmark-manifest-reproducibility:
	@$(CARGO) $(TASKS) benchmark-manifest-reproducibility
