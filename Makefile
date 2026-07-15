ifneq ("$(wildcard .env)","")
    include .env
    export $(shell sed 's/=.*//' .env)
endif

.PHONY: clean build test lint format-check verify publish

clean:
	@echo "Cleaning up..."
	rm -rf dist/ build/ src/*.egg-info

build: clean
	@echo "Building package..."
	uv build -o dist

test:
	uv run pytest tests/ -q

lint:
	uv run ruff check src/ tests/

format-check:
	uv run ruff format --check src/ tests/

# Mirrors .github/workflows/ci.yml's test + lint jobs exactly, so a local
# publish can't happen without the same checks CI enforces.
verify: test lint format-check

publish: verify build
	@test -n "$$UV_PUBLISH_TOKEN" || { echo "UV_PUBLISH_TOKEN is required (set it in .env or the environment)."; exit 1; }
	@echo "Publishing to PyPI..."
	@uv publish --token "$$UV_PUBLISH_TOKEN"
