// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

package oidcop

import (
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// Authentication method references per RFC 8176. A smartcard login is proof of
// possession of a hardware-held key released by a PIN, which is honestly more
// than one factor — and saying so lets a relying party reason about it without
// knowing what EFOS is.
var authenticationMethods = []string{
	"sc",  // smart card
	"pin", // personal identification number
	"hwk", // proof of possession of a hardware-secured key
	"mfa", // multiple factors
}

// authRequest is one in-flight authorization request. It satisfies
// op.AuthRequest structurally.
type authRequest struct {
	id            string
	clientID      string
	redirectURI   string
	scopes        []string
	state         string
	nonce         string
	responseType  oidc.ResponseType
	responseMode  oidc.ResponseMode
	codeChallenge *oidc.CodeChallenge
	createdAt     time.Time

	// The fields below are filled when the card listener completes the
	// request. Until then done is false and the library will not issue a
	// code.
	subject  string
	acr      string
	authTime time.Time
	done     bool
}

func (a *authRequest) GetID() string       { return a.id }
func (a *authRequest) GetClientID() string { return a.clientID }
func (a *authRequest) GetRedirectURI() string {
	return a.redirectURI
}
func (a *authRequest) GetScopes() []string { return a.scopes }
func (a *authRequest) GetState() string    { return a.state }
func (a *authRequest) GetNonce() string    { return a.nonce }

func (a *authRequest) GetResponseType() oidc.ResponseType { return a.responseType }
func (a *authRequest) GetResponseMode() oidc.ResponseMode { return a.responseMode }

func (a *authRequest) GetCodeChallenge() *oidc.CodeChallenge { return a.codeChallenge }

func (a *authRequest) GetSubject() string { return a.subject }
func (a *authRequest) GetACR() string     { return a.acr }

// GetAMR describes how the user was authenticated. It is only meaningful once
// the request is done; before that no card has been read.
func (a *authRequest) GetAMR() []string {
	if !a.done {
		return nil
	}

	return authenticationMethods
}

func (a *authRequest) GetAuthTime() time.Time { return a.authTime }

// GetAudience is the relying party alone. This provider issues tokens for
// Zitadel and for nothing else.
func (a *authRequest) GetAudience() []string { return []string{a.clientID} }

// Done reports whether a card has been read and the identity established. The
// library refuses to issue an authorization code until it is true.
func (a *authRequest) Done() bool { return a.done }
