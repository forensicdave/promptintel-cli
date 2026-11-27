SHELL := /bin/sh
.DEFAULT_GOAL := help
.DELETE_ON_ERROR:

PYTHON ?= python3
PREFIX ?= $(HOME)/.local
DESTDIR ?=
PIP_FLAGS ?=
ARGS ?= --help
LIVE_KEYS ?= $(HOME)/.config/promptintel-cli/test-keys.json
LIVE_AUTH ?= file
LIVE_COMMUNITY_PROFILE ?= community
LIVE_ENTERPRISE_PROFILE ?= enterprise
LIVE_REPORT ?= .test-results/live.json
LIVE_INTERVAL ?= 4
LIVE_TIMEOUT ?= 20
LIVE_PLAN ?= both
LIVE_CASES ?= all
VENV_PYTHON := .venv/bin/python

ifeq ($(LIVE_AUTH),keyring)
LIVE_KEY_ARGS = --keyring --community-profile "$(LIVE_COMMUNITY_PROFILE)" --enterprise-profile "$(LIVE_ENTERPRISE_PROFILE)"
else
LIVE_KEY_ARGS = --keys-file "$(LIVE_KEYS)"
endif

.PHONY: help all venv setup setup-keyring build-tools run test test-live check build zipapp dist install uninstall clean distclean

help: ## Show available targets and overrides
	@awk 'BEGIN {FS = ":.*## "; printf "Usage: make <target> [VARIABLE=value]\n\n"} /^[a-zA-Z_-]+:.*## / {printf "  %-14s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@printf '\nOverrides: PYTHON=python3 PREFIX=$$HOME/.local DESTDIR= PIP_FLAGS= ARGS=--help\n'
	@printf 'Live tests: LIVE_AUTH=file|keyring LIVE_KEYS=path LIVE_REPORT=path LIVE_INTERVAL=4 LIVE_TIMEOUT=20 LIVE_PLAN=both LIVE_CASES=all\n'
	@printf 'Keyring profiles: LIVE_COMMUNITY_PROFILE=community LIVE_ENTERPRISE_PROFILE=enterprise\n'

all: build ## Build the portable executable (same as build)

.venv/bin/python:
	"$(PYTHON)" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else "Python 3.10+ is required")'
	"$(PYTHON)" -m venv .venv

venv: .venv/bin/python ## Create the local development virtual environment

setup: venv ## Install this project in editable mode inside .venv
	"$(VENV_PYTHON)" -m pip install $(PIP_FLAGS) -e .

setup-keyring: venv ## Install editable CLI plus the optional OS keyring dependency in .venv
	"$(VENV_PYTHON)" -m pip install $(PIP_FLAGS) -e '.[keyring]'

build-tools: venv ## Install setuptools for wheel/source builds (may access PyPI)
	"$(VENV_PYTHON)" -m pip install $(PIP_FLAGS) 'setuptools>=77'

run: ## Run from source; for example: make run ARGS='feed --format json'
	"$(PYTHON)" -m promptintel_cli $(ARGS)

test: ## Run offline unit and portable-artifact tests; no API key needed
	"$(PYTHON)" -m unittest discover -v

test-live: ## Opt-in Community/Enterprise live checks using a private key file or keyring
	@case "$(LIVE_AUTH)" in file|keyring) ;; *) printf '%s\n' 'LIVE_AUTH must be file or keyring' >&2; exit 2 ;; esac
	"$(PYTHON)" scripts/test_live.py $(LIVE_KEY_ARGS) --report "$(LIVE_REPORT)" --interval "$(LIVE_INTERVAL)" --timeout "$(LIVE_TIMEOUT)" --plan "$(LIVE_PLAN)" --cases "$(LIVE_CASES)"

check: test ## Run tests and check Python source compilation
	"$(PYTHON)" -m compileall -q promptintel_cli scripts tests

build: zipapp ## Build dist/promptintel-cli and SHA256SUMS without pip or network access

zipapp: ## Build the portable executable using only Python's standard library
	"$(PYTHON)" scripts/build_zipapp.py
	"$(PYTHON)" scripts/checksums.py

dist: build build-tools ## Build the portable file, Python wheel, source archive, and checksums
	"$(VENV_PYTHON)" -c 'from setuptools.build_meta import build_sdist, build_wheel; build_sdist("dist"); build_wheel("dist")'
	"$(PYTHON)" scripts/checksums.py

install: build ## Install the portable CLI to PREFIX/bin (default: ~/.local/bin)
	install -d "$(DESTDIR)$(PREFIX)/bin"
	install -m 755 dist/promptintel-cli "$(DESTDIR)$(PREFIX)/bin/promptintel-cli"
	@printf 'Installed %s\n' "$(DESTDIR)$(PREFIX)/bin/promptintel-cli"

uninstall: ## Remove the CLI from PREFIX/bin; use the same PREFIX/DESTDIR as install
	rm -f "$(DESTDIR)$(PREFIX)/bin/promptintel-cli"

clean: ## Remove generated releases, build metadata, and project bytecode caches
	rm -rf build dist promptintel_cli.egg-info
	"$(PYTHON)" -c 'from pathlib import Path; import shutil; [shutil.rmtree(p) for root in ("promptintel_cli", "scripts", "tests") for p in Path(root).rglob("__pycache__")]'

distclean: clean ## Also remove the .venv development environment
	rm -rf .venv

