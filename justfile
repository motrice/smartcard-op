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

# The Go checks.
[group('lint')]
lint *args:
    @go vet ./...
    @test -z "$(gofmt -l -e .)" || { gofmt -l -e .; echo "gofmt: the files above need formatting"; exit 1; }
    @golangci-lint run ./... "$@"

[group('lint')]
lint-fix *args:
    @gofmt -w .
    @golangci-lint run --fix ./... "$@"

# Known Go vulnerabilities in what we actually call.
[group('lint')]
vuln:
    @govulncheck ./...

# REUSE compliance: every file carries an SPDX header, or is annotated in
# REUSE.toml with a reason.
[group('lint')]
reuse:
    @reuse lint

# Committed secrets.
[group('lint')]
secrets:
    @gitleaks dir . --no-banner --redact

# Conventional commits, sign-off, signature and no AI attribution, on the
# commits this branch adds. gommitlint runs on its own defaults; there is no
# config file, because the defaults are stricter than anything we would write.
[group('lint')]
commits base="origin/main":
    @gommitlint validate --base-branch={{ base }}

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
verify: lint reuse secrets test
