MATURIN ?= maturin
PYTHON ?= python3.15
PROFILE ?= release
WHEEL_ARGS ?=
SDK_VERSION = $(shell $(PYTHON) -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')
.PHONY: licenses wheel install
licenses:
	$(PYTHON) ../../scripts/prepare_attribution.py Cargo.toml licenses
wheel: licenses
	$(MATURIN) build --locked --profile $(PROFILE) --interpreter $(PYTHON) --out dist $(WHEEL_ARGS)
install: wheel
	$(PYTHON) -m pip install --force-reinstall --no-index --no-deps \
		--find-links dist "confido-client==$(SDK_VERSION)"
