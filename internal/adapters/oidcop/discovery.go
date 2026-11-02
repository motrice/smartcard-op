// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

package oidcop

import (
	"encoding/json"
	"net/http"
	"slices"
)

// discoveryPath is where the library serves the provider metadata.
const discoveryPath = "/.well-known/openid-configuration"

// The capabilities this provider actually serves. The library derives most of
// the discovery document from its configuration, but hardcodes these three
// lists: ResponseTypes is a fixed slice carrying a TODO, GrantTypes always
// includes implicit, and AuthMethodsTokenEndpoint always includes none. No
// option narrows them.
//
// Leaving the document as the library writes it would advertise an implicit
// flow the storage refuses, and — worse — announce that a client may
// authenticate at the token endpoint with nothing at all, when
// AuthorizeClientIDSecret always demands a secret. A discovery document that
// promises more than it serves is exactly what an auditor should object to, so
// it is corrected here on the way out.
var (
	servedResponseTypes = []string{"code"}
	servedGrantTypes    = []string{"authorization_code"}
	servedAuthMethods   = []string{"client_secret_basic", "client_secret_post"}
)

// withdrawnMetadata are the endpoints and capabilities this provider does not
// serve. The storage fails them and Envoy returns 404 for them, so announcing
// them in the metadata would only invite an attempt that cannot succeed.
var withdrawnMetadata = []string{
	"introspection_endpoint",
	"introspection_endpoint_auth_methods_supported",
	"introspection_endpoint_auth_signing_alg_values_supported",
	"revocation_endpoint",
	"revocation_endpoint_auth_methods_supported",
	"revocation_endpoint_auth_signing_alg_values_supported",
	"end_session_endpoint",
	"device_authorization_endpoint",
	"token_endpoint_auth_signing_alg_values_supported",
	"request_object_signing_alg_values_supported",
	"backchannel_logout_supported",
	"backchannel_logout_session_supported",
}

// HonestDiscovery corrects the provider metadata so that it describes what is
// served and nothing more.
//
// It is an http interceptor rather than a change to the router, because the
// document is the library's to generate: intercepting it keeps our correction
// in one readable place instead of forking the generator.
func HonestDiscovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != discoveryPath {
			next.ServeHTTP(w, r)

			return
		}

		recorder := &bufferingWriter{header: http.Header{}, status: http.StatusOK}
		next.ServeHTTP(recorder, r)

		corrected, err := correctMetadata(recorder.body)
		if err != nil {
			// Serve the library's document rather than nothing: a
			// slightly over-generous metadata document is a lesser
			// harm than a provider Zitadel cannot discover at all.
			copyHeader(w.Header(), recorder.header)
			w.WriteHeader(recorder.status)
			_, _ = w.Write(recorder.body)

			return
		}

		copyHeader(w.Header(), recorder.header)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", itoa(len(corrected)))
		w.WriteHeader(recorder.status)
		_, _ = w.Write(corrected)
	})
}

func correctMetadata(body []byte) ([]byte, error) {
	var document map[string]any
	if err := json.Unmarshal(body, &document); err != nil {
		return nil, err
	}

	document["response_types_supported"] = servedResponseTypes
	document["grant_types_supported"] = servedGrantTypes
	document["token_endpoint_auth_methods_supported"] = servedAuthMethods

	for key := range document {
		if slices.Contains(withdrawnMetadata, key) {
			delete(document, key)
		}
	}

	return json.Marshal(document)
}

// bufferingWriter captures a response so that it can be rewritten. The
// discovery document is a few hundred bytes, so buffering it costs nothing.
type bufferingWriter struct {
	header http.Header
	status int
	body   []byte
}

func (b *bufferingWriter) Header() http.Header { return b.header }

func (b *bufferingWriter) WriteHeader(status int) { b.status = status }

func (b *bufferingWriter) Write(chunk []byte) (int, error) {
	b.body = append(b.body, chunk...)

	return len(chunk), nil
}

func copyHeader(destination, source http.Header) {
	for key, values := range source {
		// Content-Length is set from the corrected body, so the
		// original must not be carried over.
		if key == "Content-Length" {
			continue
		}

		destination[key] = values
	}
}

// itoa avoids pulling strconv in for one call.
func itoa(value int) string {
	if value == 0 {
		return "0"
	}

	var digits []byte

	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}

	return string(digits)
}
