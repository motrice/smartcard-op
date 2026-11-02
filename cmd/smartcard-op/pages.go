// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"html/template"
	"net/http"
)

// The pages a card user may be shown. They are server-rendered, carry no
// JavaScript, and say what the user can do about it — which for a card login is
// usually a concrete errand: fetch a new card, pick the other certificate, call
// the service desk.
//
// Swedish first and English below, because the service is Swedish public sector
// but not everyone who holds an EFOS card reads Swedish.
//
// None of them leaks internals. The reference code is how the service desk and
// the audit log are joined up, and it is the only thing that varies.
type page struct {
	status int
	// reason is the audit reason code this page corresponds to, so that the
	// page a user saw can be reconstructed from the log.
	reason     string
	titleSV    string
	bodySV     string
	titleEN    string
	bodyEN     string
	retryAfter bool
}

var pageTemplate = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="sv">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.TitleSV}}</title>
<style>
:root { color-scheme: light dark; }
body { font: 16px/1.5 system-ui, sans-serif; margin: 0; padding: 2rem 1rem; }
main { max-width: 34rem; margin: 0 auto; }
h1 { font-size: 1.4rem; margin: 0 0 .5rem; }
h2 { font-size: 1rem; font-weight: 600; margin: 2rem 0 .5rem; opacity: .75; }
p { margin: 0 0 1rem; }
code { font-family: ui-monospace, monospace; }
hr { border: 0; border-top: 1px solid currentColor; opacity: .2; margin: 2rem 0; }
</style>
</head>
<body>
<main>
<h1>{{.TitleSV}}</h1>
<p>{{.BodySV}}</p>
<hr>
<h2>{{.TitleEN}}</h2>
<p>{{.BodyEN}}</p>
<p>Referens: <code>{{.Reference}}</code></p>
</main>
</body>
</html>
`))

// render writes the page. The reference is the audit record's fingerprint
// prefix, which is what lets the service desk find the attempt.
func (p page) render(w http.ResponseWriter, reference string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")

	if p.retryAfter {
		w.Header().Set("Retry-After", "60")
	}

	w.WriteHeader(p.status)

	_ = pageTemplate.Execute(w, struct {
		TitleSV, BodySV, TitleEN, BodyEN, Reference string
	}{
		TitleSV:   p.titleSV,
		BodySV:    p.bodySV,
		TitleEN:   p.titleEN,
		BodyEN:    p.bodyEN,
		Reference: reference,
	})
}

var (
	pageCertificateMissing = page{
		status:  http.StatusInternalServerError,
		reason:  "xfcc_missing",
		titleSV: "Tekniskt fel",
		bodySV: "Inloggningen med kort kunde inte verifieras. " +
			"Kontakta supporten och ange referensen nedan.",
		titleEN: "Technical error",
		bodyEN: "The card login could not be verified. " +
			"Contact support and quote the reference below.",
	}

	pageCardExpired = page{
		status:  http.StatusForbidden,
		reason:  "certificate_outside_validity",
		titleSV: "Kortet är inte giltigt",
		bodySV: "Ditt EFOS-kort ligger utanför sin giltighetstid. " +
			"Beställ ett nytt kort hos din kortadministratör.",
		titleEN: "The card is not valid",
		bodyEN: "Your EFOS card is outside its validity period. " +
			"Order a new card from your card administrator.",
	}

	pageWrongCertificate = page{
		status:  http.StatusForbidden,
		reason:  "disallowed_key_usage",
		titleSV: "Fel certifikat valt",
		bodySV: "Det valda certifikatet kan inte användas för inloggning. " +
			"Välj ditt legitimeringscertifikat — inte signerings- eller " +
			"krypteringscertifikatet — och försök igen.",
		titleEN: "The wrong certificate was selected",
		bodyEN: "The selected certificate cannot be used for login. " +
			"Choose your authentication certificate, not the signing or " +
			"encryption one, and try again.",
	}

	// The revocation reason and date are deliberately withheld from the
	// page. They are in the audit log; someone holding a stolen card learns
	// nothing from the screen.
	pageCardRevoked = page{
		status:  http.StatusForbidden,
		reason:  "revoked",
		titleSV: "Kortet är återkallat",
		bodySV: "Ditt kort är återkallat och kan inte användas. " +
			"Kontakta din kortadministratör.",
		titleEN: "The card is revoked",
		bodyEN: "Your card has been revoked and cannot be used. " +
			"Contact your card administrator.",
	}

	pageRevocationUnavailable = page{
		status:  http.StatusServiceUnavailable,
		reason:  "revocation_status_unknown",
		titleSV: "Inloggning tillfälligt otillgänglig",
		bodySV: "Kortets spärrstatus kunde inte kontrolleras just nu. " +
			"Försök igen om några minuter.",
		titleEN: "Login temporarily unavailable",
		bodyEN: "The card's revocation status could not be checked right now. " +
			"Try again in a few minutes.",
		retryAfter: true,
	}

	pageAssuranceTooLow = page{
		status:  http.StatusForbidden,
		reason:  "assurance_level_too_low",
		titleSV: "Kortet har för låg tillitsnivå",
		bodySV: "Tjänsten kräver ett EFOS-kort på högre tillitsnivå än ditt. " +
			"Kontakta din kortadministratör.",
		titleEN: "The card's assurance level is too low",
		bodyEN: "This service requires an EFOS card at a higher assurance level " +
			"than yours. Contact your card administrator.",
	}

	pageUntrustedIssuer = page{
		status:  http.StatusForbidden,
		reason:  "certificate_chain",
		titleSV: "Kortet är inte utgivet av en godkänd utgivare",
		bodySV:  "Kortet kan inte knytas till en utgivare tjänsten litar på.",
		titleEN: "The card was not issued by an approved issuer",
		bodyEN:  "The card cannot be tied to an issuer this service trusts.",
	}

	pageIdentityMissing = page{
		status:  http.StatusForbidden,
		reason:  "identity_missing",
		titleSV: "Kortet saknar nödvändig information",
		bodySV: "Kortets certifikat innehåller inte de uppgifter som krävs. " +
			"Kontakta supporten och ange referensen nedan.",
		titleEN: "The card lacks required information",
		bodyEN: "The card's certificate does not contain the required details. " +
			"Contact support and quote the reference below.",
	}

	pageRequestUnknown = page{
		status:  http.StatusBadRequest,
		reason:  "authreq_unknown",
		titleSV: "Inloggningen tog för lång tid",
		bodySV: "Börja om från den tjänst du skulle logga in i. " +
			"Länken du följde är inte längre giltig.",
		titleEN: "The login took too long",
		bodyEN: "Start again from the service you were logging in to. " +
			"The link you followed is no longer valid.",
	}
)
