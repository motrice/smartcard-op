<!--
SPDX-FileCopyrightText: 2026 Motrice AB

SPDX-License-Identifier: EUPL-1.2
-->

# smartcard-op — EFOS smartcard login for Zitadel

`smartcard-op` is a small OpenID Provider that does one thing: exchange a
verified **EFOS smartcard** for an `id_token`. Zitadel federates to it as a
*Generic OIDC Identity Provider*, because Zitadel itself does not support client
certificates ([zitadel/zitadel#8597](https://github.com/zitadel/zitadel/issues/8597)).

EFOS ("E-identitet för offentlig sektor") is the Swedish public sector eID
issued by Försäkringskassan, approved by DIGG at assurance levels 3 and 4.

## Architecture

```
EFOS card → Envoy (mTLS) → smartcard-op :8081 /login
                               ↓ 302
                            smartcard-op :8080 /authorize /oauth/token /keys
                               ↓ OIDC code + PKCE
                            Zitadel → the applications
```

Two listeners, not one. Zitadel fetches the discovery document and the JWKS, and
performs the code exchange, **from its own server** — which holds no card. Put
the whole provider behind mTLS and the flow breaks at the token exchange. The
OIDC endpoints are therefore not even registered on the card listener, nor
`/login` on the issuer listener.

## Code layers

Ports and adapters, with the dependency direction `cmd → app → domain ←
adapters`. The rules are not style preferences but enforced in two places:
`depguard` in `.golangci.yml` catches them in the editor and the lint, and
`test/archguard` proves them as tests. Both have been verified against a
deliberately introduced violation.

| Package | Responsibility |
|---|---|
| `internal/domain` | The rules and value objects of an EFOS identity. No dependencies outside the standard library. |
| `internal/app` | Use cases and ports. |
| `internal/adapters` | The Envoy header, the EFOS PKI, revocation checking, the OIDC protocol. |
| `cmd/smartcard-op` | Configuration and composition. |

## Getting started

```sh
mise trust                    # trust the pinned toolchain
just install-dev-tools        # install the toolchain from .mise.toml
just test-unit                # the everyday TDD tier
just test-run PersonalIdentity  # the inner loop while developing
just verify                   # what CI runs
```

`just` with no arguments lists every recipe.

`nanolinter` is published only as a Linux binary, so `just lint` skips it on
macOS with a note and runs the Go checks regardless — forge-ci's pull request
gate runs it in any case. `just lint-strict` requires it.

The lint configuration is adopted from forge-ci (CC0) and runs `default: all`:
every linter golangci-lint ships is on unless it is switched off with a reason,
so that a linter a new release adds is evaluated at the next version bump rather
than silently skipped.

## Status

| Part | State |
|---|---|
| `internal/domain` — identity number, assurance level, name, identifiers, card identity, revocation status | done, tested |
| `internal/app/claims.go` — claim mapping for Zitadel | done, tested |
| `internal/app/authenticate.go` — the use case and its ports | done, tested |
| `internal/adapters/xfcc` — Envoy's `x-forwarded-client-cert` | done, tested, fuzzed |
| `internal/adapters/revocation` — OCSP, CRL, policy engine | done, tested against real EFOS data |
| `internal/adapters/efospki` — trust anchor and DN reader | done, tested |
| `test/archguard` — the layer rules | done, verified against a provoked violation |
| `test/authentication` — the whole chain with the real adapters | done, tested |
| CI, Containerfile, REUSE | done |
| `internal/adapters/oidcop` — the OpenID Provider | outstanding |
| `internal/adapters/keys`, `audit` | outstanding |
| `cmd/smartcard-op`, `deploy/` | outstanding |

## What we know about EFOS from real data

The integration tests (`just test-integration`) run against Försäkringskassan's
test environment and have established the following, which the code now rests
on:

- The issuers `Swedish Public Sector Person 2|3|4 CA SAT v1` carry a
  **restricted** extended key usage: `clientAuth`, `emailProtection`,
  `OCSPSigning`, plus `smartcardLogon` and document signing as unknown OIDs.
  **No `serverAuth`** — so whoever verifies a chain must pass `KeyUsages`
  explicitly, or Go defaults to `ExtKeyUsageServerAuth` and the verification
  fails with "incompatible key usage".
- The issuers permit `OCSPSigning`, so they can delegate revocation verdicts.
  The check of the responder certificate's extended key usage in
  `internal/adapters/revocation/ocsp.go` is therefore not theoretical: without
  it, any card carrying that usage could answer for everyone else's revocation
  status. `x/crypto/ocsp` does not perform that check.
- The revocation lists have a 73 h 20 min validity window and 88–181 revoked
  certificates per CA. That sets the floor for the staleness budget.
- The responder at `http://ocspsat.efos.se` correctly answers `revoked` for
  serial numbers taken from its own revocation list.
- The CA certificates carry `anyPolicy`; the assurance-level-bearing policy
  identifiers sit in the end-entity certificates, as the profile states.

Three Go traps the code now handles, each pinned by a test:

- `x509.Certificate.Verify` defaults to `ExtKeyUsageServerAuth` when
  `KeyUsages` is omitted. Against the EFOS restricted extended key usage that
  yields "incompatible key usage", which looks like a broken chain but is the
  caller's mistake.
- `pkix.Name.appendRDNs` skips a named DN field when the same OID already
  appears in `ExtraNames`. And `Subject.ExtraNames` is empty on a **parsed**
  certificate — a reader must go by `Subject.Names`.
- Since Go 1.24, `PolicyIdentifiers` is ignored when certificates are created;
  `Policies` is the field that applies (godebug `x509usepolicies`).

## Before going live

Seven questions must be settled with Försäkringskassan or verified against a
real EFOS test card — see the plan's *open questions*. The most important:
the Relying Party Agreement, the certificate policy OIDs per assurance level as
observed on a real card, and which assurance level your services require.

## Licence

EUPL-1.2. The project follows [REUSE](https://reuse.software/) — every file
carries an SPDX header.
