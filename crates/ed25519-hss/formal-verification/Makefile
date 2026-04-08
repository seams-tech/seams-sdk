CARGO ?= cargo
MANIFEST := ../Cargo.toml

.PHONY: check vectors-check parity lean-check aeneas-check

check: vectors-check parity

vectors-check:
	@$(CARGO) run --quiet --manifest-path $(MANIFEST) --bin emit_fixture_json | diff -u ../fixtures/f_expand_v1.json -

parity:
	@$(CARGO) test --manifest-path $(MANIFEST) fv_hss_

lean-check:
	@if command -v lake >/dev/null 2>&1; then \
		cd lean-privacy && lake build; \
	else \
		echo "Lean toolchain not installed; skipping lean-check"; \
	fi

aeneas-check:
	@if command -v aeneas >/dev/null 2>&1 && command -v charon >/dev/null 2>&1; then \
		if command -v lake >/dev/null 2>&1; then \
			cd lean-boundary && lake build; \
		else \
			echo "Lean toolchain not installed; skipping aeneas-check"; \
		fi; \
	else \
		echo "Aeneas toolchain not installed; skipping aeneas-check"; \
	fi
