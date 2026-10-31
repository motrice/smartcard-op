// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

package domain

import (
	"errors"
	"fmt"
	"strings"
)

// ErrInvalidName wraps certificates that carry no name at all.
var ErrInvalidName = errors.New("invalid name")

// Name is the person's name taken from the certificate's givenName, surname
// and commonName attributes.
//
// The EFOS profile allows an empty givenName when the person has no marked
// first name. Zitadel, however, refuses to create a brokered user when
// given_name, family_name or name is empty (zitadel/zitadel#12265). The value
// object settles that once and for all: after construction none of the three
// parts is empty.
type Name struct {
	givenName   string
	familyName  string
	displayName string
}

// NewName assembles a name, filling empty parts from the others. At least one
// of the three must contain something other than whitespace.
func NewName(givenName, familyName, displayName string) (Name, error) {
	givenName = strings.TrimSpace(givenName)
	familyName = strings.TrimSpace(familyName)
	displayName = strings.TrimSpace(displayName)

	if displayName == "" {
		displayName = strings.TrimSpace(givenName + " " + familyName)
	}

	if displayName == "" {
		return Name{}, fmt.Errorf("%w: the certificate carries no name", ErrInvalidName)
	}

	// The display name, not the family name, is the fallback: a commonName
	// such as "Anna Andersson" says more about the person than a duplicate
	// of the surname would.
	if givenName == "" {
		givenName = displayName
	}

	if familyName == "" {
		familyName = displayName
	}

	return Name{givenName: givenName, familyName: familyName, displayName: displayName}, nil
}

// GivenName returns a guaranteed non-empty given name.
func (n Name) GivenName() string { return n.givenName }

// FamilyName returns a guaranteed non-empty family name.
func (n Name) FamilyName() string { return n.familyName }

// DisplayName returns a guaranteed non-empty display name.
func (n Name) DisplayName() string { return n.displayName }
