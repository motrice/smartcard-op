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

forge-ci's lint gate is switched off (`lint-engine: none`). The nanolinter
image it runs from is not publicly pullable — an anonymous pull of
`ghcr.io/itiquette/nanolinter` answers `denied` for every tag, and a consumer's
`GITHUB_TOKEN` does not reach it either; forge-ci's own error says as much, and
that "this is not a lint finding". The checks it would have delegated therefore
run directly, each as a `just` recipe so that a developer runs exactly what CI
runs:

| | |
|---|---|
| `just lint` | `go vet`, `gofmt`, golangci-lint with forge-ci's `default: all` baseline |
| `just reuse` | REUSE compliance — every file carries an SPDX header or is annotated with a reason |
| `just secrets` | gitleaks over the tree |
| `just commits` | conventional commits, sign-off, signature and no AI attribution |
| `just vuln` | govulncheck over what the code actually calls |

`just verify` runs lint, REUSE, secrets and the tests — what CI runs.

There is no `.gommitlint.yaml`: its defaults are stricter than anything we would
write, and they include `cryptosignature` and `aiattribution`, which are two
rules this project wants and would not have thought to add.

The rest of forge-ci's gate is in use: the plan, status and summary jobs, and
the release orchestrator. Those needed one override — the orchestrator at
v0.91.13 defaults `runtime-image` to a tag that was never published, so it is
pinned by digest in `pullrequest.yml` with a note to remove the override once
upstream points at something that exists.

## Status

| Part | State |
|---|---|
| `internal/domain` — identity number, assurance level, name, identifiers, card identity, revocation status | done, tested |
| `internal/app/authenticate.go` — the use case and its ports | done, tested |
| `internal/adapters/xfcc` — Envoy's `x-forwarded-client-cert` | done, tested, fuzzed |
| `internal/adapters/revocation` — OCSP, CRL, policy engine | done, tested against real EFOS data |
| `internal/adapters/efospki` — trust anchor and DN reader | done, tested |
| `internal/adapters/oidcop` — claim mapping for Zitadel | done, tested |
| `test/archguard` — the layer rules | done, verified against a provoked violation |
| `test/authentication` — the whole chain with the real adapters | done, tested |
| `internal/adapters/oidcop` — the OpenID Provider and the Zitadel claim mapping | done, tested end to end |
| `internal/adapters/keys` — signing keys and the JWKS | done, tested |
| CI, Containerfile, REUSE | done |
| `internal/adapters/audit` — the hash-chained audit log | done, tested |
| `cmd/smartcard-op` — the two listeners, configuration, card login handler | done, tested |
| `deploy/` — Envoy listeners, Kubernetes manifests, network policies | done, templates |

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

## The OpenID Provider

The provider is github.com/zitadel/oidc v3.51.16. The choice was made by
counting: `op.Storage` is 23 methods, of which 15 are real and 8 are
deliberately disabled, and the methods are almost entirely bookkeeping — while
a hand-rolled authorize and token endpoint would be roughly the same volume of
code with all of it security-critical. The library already implements exact
redirect_uri matching, single-use authorization codes, PKCE verification and
at_hash/c_hash computation, and Zitadel's own CI tests this exact pairing.

Three settings in it are load-bearing and not obvious:

- `IDTokenUserinfoClaimsAssertion` must be true. The code exchange always
  creates an access token, and with it false the library strips the profile and
  email scopes from the id_token — which would leave Zitadel's id-token mapping
  mode nothing to provision a user from.
- `GrantTypes` lists only the authorization code grant. The library decides
  whether to mint a refresh token by consulting the client's grant types, so
  this is what makes the refresh path unreachable even if `offline_access` is
  requested.
- PKCE is enforced in `CreateAuthRequest`, because the library permits an absent
  challenge and an empty method that RFC 7636 defaults to `plain`. Note that
  Zitadel's "Use PKCE" flag is **off by default** — the gate is also what forces
  an operator to switch it on.

Claims live in this adapter rather than in the use case: they are a protocol
projection, and the synthetic email address exists solely because of how Zitadel
provisions brokered users. The use case has no opinion about either.

The discovery document is corrected on the way out. The library hardcodes an
implicit response type and grant, and a token endpoint auth method of `none`,
with no option to narrow them — so the metadata would otherwise announce that a
client may authenticate with nothing, when the storage always demands a secret.
A document that promises more than it serves is the kind of thing an auditor
should object to.

## The audit trail

One record per authentication attempt, whatever the outcome, written as
newline-delimited JSON to stdout while the application log goes to stderr — so
that retention and access can differ: the audit stream holds personal data and
is kept for years, the application log does not and is not.

Records are hash-chained. That makes the log tamper-evident without a
write-once store, and it detects deletion as well as modification, since
removing a record breaks the links of every record after it. `audit.Verify`
walks a stream and names the first record that no longer holds.

The personal identity number is redacted with a keyed HMAC **by default**. An
unkeyed digest of a twelve-digit number is reversible by brute force in seconds,
so the service refuses to start with hashed redaction and no key. `masked` keeps
the birth date, `full` keeps everything — choose either only where the log
platform's retention and access controls justify it. The certificate fingerprint
is always present in full and is what an investigator pivots on; it discloses
nothing about the person.

The HMAC key must never rotate: a new key orphans every historical record from
the person it concerns, which is the one thing the field exists to support.

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
