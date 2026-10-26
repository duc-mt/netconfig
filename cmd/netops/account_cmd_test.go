// ==============================================================================
// File name:     account_cmd_test.go
// Description:   Unit tests for account command password generation and validation.
// License:       MIT
// ==============================================================================
package main

import (
	"strings"
	"testing"

	"netops/internal/task"
	"netops/internal/vendor"
)

func TestGeneratePassword(t *testing.T) {
	// Lengths < 4 must return an error
	badLengths := []int{-1, 0, 1, 2, 3}
	for _, l := range badLengths {
		if pw, err := generatePassword(l); err == nil {
			t.Errorf("generatePassword(%d) expected error, got %q", l, pw)
		}
	}

	// Valid lengths >= 4
	goodLengths := []int{4, 8, 16, 20, 64}
	for _, l := range goodLengths {
		pw, err := generatePassword(l)
		if err != nil {
			t.Fatalf("generatePassword(%d) unexpected error: %v", l, err)
		}
		if len(pw) != l {
			t.Errorf("generatePassword(%d) len = %d; want %d", l, len(pw), l)
		}
		// Validate against vendor constraints
		if err := vendor.ValidatePassword(pw); err != nil {
			t.Errorf("generatePassword(%d) produced invalid password %q: %v", l, pw, err)
		}

		// Ensure it contains all 4 classes: lower, upper, digit, symbol
		hasLower := strings.ContainsAny(pw, "abcdefghijkmnopqrstuvwxyz")
		hasUpper := strings.ContainsAny(pw, "ABCDEFGHJKLMNPQRSTUVWXYZ")
		hasDigit := strings.ContainsAny(pw, "23456789")
		hasSymbol := strings.ContainsAny(pw, "-_.@#%+=")

		if !hasLower || !hasUpper || !hasDigit || !hasSymbol {
			t.Errorf("generatePassword(%d) = %q missing required character class (lower:%v, upper:%v, digit:%v, symbol:%v)",
				l, pw, hasLower, hasUpper, hasDigit, hasSymbol)
		}
	}
}

func TestFactsRecordSanitization(t *testing.T) {
	row := task.FactsRow{
		Hostname: "=cmd|' /C calc'!A0",
		IP:       "10.0.0.1",
		Vendor:   "@cisco",
		Model:    "+2960X",
		Serial:   "-SN12345",
		Version:  "\t15.2",
		Uptime:   "\r5 weeks",
	}
	rec := factsRecord(row)
	expected := []string{
		"'=cmd|' /C calc'!A0",
		"10.0.0.1",
		"'@cisco",
		"'+2960X",
		"'-SN12345",
		"'\t15.2",
		"'\r5 weeks",
	}
	for i, exp := range expected {
		if rec[i] != exp {
			t.Errorf("factsRecord field %d = %q, want %q", i, rec[i], exp)
		}
	}
}
