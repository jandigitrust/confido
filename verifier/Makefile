# Compatibility entry point; Python binding is a separate package.
.PHONY: wheel install clean
wheel install:
	$(MAKE) -C ../bindings/python $@
clean:
	cargo clean
