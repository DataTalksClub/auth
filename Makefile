.PHONY: check lint test test-node

check: lint test

lint:
	uv run --with pytest --with ruff ruff check .

test:
	uv run --with pytest python -m pytest

test-node:
	node --test tests/test_device_login.mjs
