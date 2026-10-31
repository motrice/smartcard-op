# SPDX-FileCopyrightText: 2026 Motrice AB
#
# SPDX-License-Identifier: EUPL-1.2

# Dev-loop automation for smartcard-op.
#
# Quick start:
#   mise trust               # allow this checkout's pinned toolchain
#   just install-dev-tools   # install the pinned toolchain
#   just test-unit           # the TDD inner loop
#   just verify              # what CI runs

set shell := ["bash", "-euo", "pipefail", "-c"]
set positional-arguments

export GOLANGCI_LINT_CACHE := env_var_or_default("GOLANGCI_LINT_CACHE", justfile_directory() / ".golangci-lint-cache")

bin := "./bin"
executable := "smartcard-op"

[private]
default:
    @"{{ just_executable() }}" --justfile "{{ justfile() }}" --list --unsorted --list-heading ''

# ============================================================================ #
# SETUP
# ============================================================================ #

# Install the pinned development toolchain; network
[group('setup')]
install-dev-tools:
    @mise install

# ============================================================================ #
# TEST - the TDD loop
# ============================================================================ #

# Everyday tier: untagged unit tests, race detector, shuffled order
[group('test')]
test-unit *args:
    @go test -shuffle=on -count=1 -race -buildvcs=false "$@" ./...

# TDD inner loop: run only the tests matching a filter
[group('test')]
test-run filter *args:
    @go test -count=1 -race -buildvcs=false -run "$1" "${@:2}" ./...

# Single package, for when the filter is the package rather than the test
[group('test')]
test-pkg pkg *args:
    @go test -count=1 -race -buildvcs=false "$1" "${@:2}"

# Unit plus integration tiers; reaches the EFOS test environment over the network
[group('test')]
test-integration *args:
    @go test -shuffle=on -tags=integration -count=1 -race -buildvcs=false "$@" ./...

# Assert every build-tagged tier still compiles
[group('test')]
test-tags-compile:
    @for tag in integration; do \
        printf 'vet -tags %s\n' "$tag"; \
        go vet -tags "$tag" ./... || exit 1; \
    done

# Re-run the unit tier on every Go file change; needs watchexec
[group('test')]
test-watch:
    @watchexec --exts go --clear -- "{{ just_executable() }}" --justfile "{{ justfile() }}" test-unit

[group('test')]
test-coverage:
    @mkdir -p {{ bin }}
    @go test -count=1 -covermode=atomic -coverprofile={{ bin }}/coverage.out ./...
    @go tool cover -html={{ bin }}/coverage.out -o {{ bin }}/coverage.html
    @go tool cover -func={{ bin }}/coverage.out | tail -1

# Unit plus the compile check across build tags
[group('test')]
test: test-tags-compile test-unit

# ============================================================================ #
# LINT
# ============================================================================ #

# Local Go checks plus nanolinter's plan when it is available.
#
# nanolinter is published only as a Linux binary, so on macOS it is absent
# unless built from source. The recipe runs the Go checks regardless and skips
# nanolinter with a note rather than failing the dev loop — forge-ci's pull
# request gate runs it anyway.
[group('lint')]
lint *args:
    @go vet ./...
    @test -z "$(gofmt -l -e .)" || { gofmt -l -e .; echo "gofmt: the files above need formatting"; exit 1; }
    @golangci-lint run ./... 2>/dev/null || echo "golangci-lint not installed locally; forge-ci runs it in the gate"
    @if command -v nanolinter >/dev/null 2>&1; then nanolinter lint "$@"; else \
        echo "nanolinter not installed locally (Linux binary); forge-ci runs it in the gate"; fi

# Requires nanolinter. Use in CI, or when you want the whole plan locally.
[group('lint')]
lint-strict *args:
    @go vet ./...
    @nanolinter verify "$@"

[group('lint')]
lint-fix *args:
    @gofmt -w .
    @if command -v nanolinter >/dev/null 2>&1; then nanolinter lint --fix "$@"; else \
        echo "nanolinter not installed locally; only formatted the Go code"; fi

[group('lint')]
vuln:
    @govulncheck ./...

# Install the nanolinter pre-commit hook
[group('hook')]
hook-install:
    @nanolinter hook install

# ============================================================================ #
# BUILD
# ============================================================================ #

[group('build')]
build:
    @mkdir -p {{ bin }}
    @go build -o {{ bin }}/{{ executable }} ./cmd/smartcard-op

# ============================================================================ #
# VERIFY - what CI runs
# ============================================================================ #

[group('verify')]
verify: lint test
