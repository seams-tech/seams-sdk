CARGO ?= cargo
MANIFEST := ../Cargo.toml

.PHONY: check vectors-check parity proof-check

check: vectors-check parity

vectors-check:
	@$(CARGO) run --quiet --manifest-path $(MANIFEST) --bin emit_fixture_json | diff -u ../fixtures/f_expand_v1.json -

parity:
	@$(CARGO) test --manifest-path $(MANIFEST) fv_hss_

proof-check:
	@if command -v lake >/dev/null 2>&1; then \
		cd lean-privacy && lake build; \
	else \
		echo "Lean toolchain not installed; skipping proof-check"; \
	fi
