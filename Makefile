ifneq ("$(wildcard .env)","")
    include .env
    export $(shell sed 's/=.*//' .env)
endif

.PHONY: clean build publish

clean:
	@echo "Cleaning up..."
	rm -rf dist/ build/ src/*.egg-info

build: clean
	@echo "Building package..."
	uv build -o dist

publish: build
	@echo "Publishing to PyPI..."
	uv publish --token $(UV_PUBLISH_TOKEN)
