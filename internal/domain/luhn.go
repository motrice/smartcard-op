// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

package domain

// luhnCheckDigit computes the check digit for a digit sequence using the Luhn
// algorithm, which both Swedish personal identity numbers and organization
// numbers rely on. The input is the digits without the check digit.
func luhnCheckDigit(digits string) int {
	sum := 0

	for i := range len(digits) {
		product := int(digits[i]-'0') * (2 - i%2)
		if product > 9 {
			product -= 9
		}

		sum += product
	}

	return (10 - sum%10) % 10
}

// isAllDigits reports whether the string consists solely of ASCII digits.
//
// Deliberately not unicode.IsDigit: EFOS writes ASCII, and Arabic or Devanagari
// digits in a certificate must not be read as a Swedish identity number.
func isAllDigits(s string) bool {
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}

	return len(s) > 0
}
