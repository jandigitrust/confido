MATURIN ?= maturin
PYTHON ?= python3
PROFILE ?= release
WHEEL_ARGS ?=
.PHONY: licenses wheel install
licenses:
	$(PYTHON) ../../scripts/prepare_attribution.py Cargo.toml licenses
wheel: licenses
	$(MATURIN) build --locked --profile $(PROFILE) --interpreter $(PYTHON) --out dist $(WHEEL_ARGS)
install: wheel
	$(PYTHON) -m pip install --force-reinstall --no-index --no-deps dist/confido_client-0.2.0-*.whl
