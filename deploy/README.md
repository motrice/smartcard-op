<!--
SPDX-FileCopyrightText: 2026 Motrice AB

SPDX-License-Identifier: EUPL-1.2
-->

# Deploying smartcard-op

Templates, not a working configuration. Every `example.se` hostname, every path
and every secret is a placeholder.

## Two hostnames, and why

| | hostname | Envoy TLS | pod port | serves |
|---|---|---|---|---|
| Issuer | `idp.example.se` | server TLS only | 8080 | the whole OIDC router |
| Card | `card.idp.example.se` | mTLS, `require_client_certificate: true` | 8081 | `GET /login` only |

Zitadel fetches the discovery document and the JWKS, and performs the code
exchange, **from its own server** — which holds no EFOS card. Demanding a client
certificate on those endpoints breaks the flow at the token exchange. The split
is also what makes the arrangement auditable: the OIDC endpoints are not
registered on the card listener at all, so a misrouted request cannot reach them
without a certificate.

A browser only prompts for a card on the card hostname, which is the second
reason for the split: on one combined host the user would face the card dialog
on every page load.

## Order of application

```sh
kubectl apply -f k8s/configmap.yaml      # after filling in the real EFOS bundle
kubectl apply -f k8s/secret.example.yaml # after replacing every value
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/networkpolicy.yaml
kubectl apply -f k8s/deployment.yaml
```

Then point Envoy at `envoy/listeners.yaml` and mount the EFOS CA bundle where
its `trusted_ca` expects it.

## What the service refuses to start without

Fail-fast is deliberate. A half-configured service would appear to work while
protecting nothing, and the failure would surface as a successful login by
someone who should have been refused.

- `SMARTCARD_OP_MIN_ASSURANCE_LEVEL` — no default. DIGG requires level 3 for
  many services, and guessing would quietly admit level 2 cards.
- `SMARTCARD_OP_EFOS_CA_BUNDLE` — must contain at least one self-signed
  certificate. A bundle of intermediates alone anchors nothing.
- `SMARTCARD_OP_AUDIT_HMAC_KEY` — required while redaction is `hashed`, which is
  the default. An unkeyed digest of a twelve-digit identity number is reversible
  by brute force in seconds.
- `SMARTCARD_OP_TOKEN_CRYPTO_KEY` — exactly 32 bytes, base64.
- Every URL must be `https`. The OIDC library permits a plaintext redirect URI
  for a confidential client; refusing it is our own policy.

## Revocation is checked by the provider, not by Envoy

`validation_context.crl` is deliberately unset. Envoy supports only a static CRL
file for client certificates, and its own documentation warns that supplying a
CRL for one CA in a chain requires one for every CA or verification fails for
revoked and unrevoked certificates alike. There is no client-certificate OCSP in
Envoy at all — `ocsp_staple` concerns the server's own certificate.

The provider therefore checks live, fail-closed: the EFOS responder first, a
revocation list only when the responder is unreachable, and a denial when
neither answers. That needs egress to `ocsp.efos.se`, `crl.efos.se` and
`aia.efos.se`. **If that egress is blocked, every login fails** — which is the
intended behaviour, not an accident.

## Operating it

**Key rotation**, on a 90-day cadence:

1. Generate a new key and add it as `next.pem`. The key set now publishes both;
   signing still uses `current.pem`.
2. Wait at least 24 hours, so the new key is known everywhere before it is first
   used.
3. Promote: `current.pem` → `retired.pem`, `next.pem` → `current.pem`.
4. After an hour — far longer than the 5-minute token lifetime — delete
   `retired.pem`.

There is never a window in which a token is signed by a key absent from the key
set. Restart the pod after each step; the keys are read at startup.

**The audit HMAC key must never rotate.** A new key orphans every historical
record from the person it concerns, which is the one thing the field exists to
support.

**Alert on** `outcome=denied` with `reason=revoked` (a revoked card was
presented), any `reason=xfcc_missing` on the card listener (Envoy
misconfiguration or an attempt to bypass it), and `reason=revocation_status_
unknown` (EFOS unreachable, and logins are failing closed).

## Accepted residual risks

**Browsers cache the selected client certificate** for the lifetime of the
browser process. Removing the card does not log the user out, and no endpoint
can force re-selection — it is a property of TLS client authentication, not
something the service can fix. Short token and session lifetimes limit the
window; on shared computers, users must be told to close the browser.

**Cancelling the card dialog** produces the browser's own TLS error, which
cannot be styled. Consider an interstitial page on the issuer host — "insert your
card and continue" — so the user meets an explicable step rather than an
unbranded failure.

**The issuer is effectively immutable** after go-live. Zitadel performs discovery
when its identity provider object is constructed, so changing the issuer means
re-saving the provider there.
