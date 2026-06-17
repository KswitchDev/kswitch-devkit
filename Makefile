SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c

.PHONY: validate-ep227-release

validate-ep227-release:
	python3 scripts/validate_ep227_release.py
