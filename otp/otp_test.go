package otp

import (
	"net/url"
	"testing"
)

func TestKeyString_AllFields(t *testing.T) {
	key := &Key{
		Secret:      "SECRET123",
		Issuer:      "TestIssuer",
		AccountName: "user@example.com",
		Host:        "totp",
		Period:      30,
		Algorithm:   AlgorithmSHA256,
		Digits:      DigitsSix,
	}

	result := key.String()

	u, err := url.Parse(result)
	if err != nil {
		t.Fatalf("Failed to parse URL: %v", err)
	}

	if u.Scheme != "otpauth" {
		t.Errorf("Expected scheme 'otpauth', got '%s'", u.Scheme)
	}
	if u.Host != "totp" {
		t.Errorf("Expected host 'totp', got '%s'", u.Host)
	}
	expectedPath := "/TestIssuer:user@example.com"
	if u.Path != expectedPath {
		t.Errorf("Expected path '%s', got '%s'", expectedPath, u.Path)
	}

	values, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		t.Fatalf("Failed to parse query: %v", err)
	}

	if values.Get("secret") != "SECRET123" {
		t.Errorf("Expected secret 'SECRET123', got '%s'", values.Get("secret"))
	}
	if values.Get("issuer") != "TestIssuer" {
		t.Errorf("Expected issuer 'TestIssuer', got '%s'", values.Get("issuer"))
	}
	if values.Get("algorithm") != "SHA256" {
		t.Errorf("Expected algorithm 'SHA256', got '%s'", values.Get("algorithm"))
	}
	if values.Get("digits") != "6" {
		t.Errorf("Expected digits '6', got '%s'", values.Get("digits"))
	}
	if values.Get("period") != "30" {
		t.Errorf("Expected period '30', got '%s'", values.Get("period"))
	}
}

func TestKeyString_WithoutPeriod(t *testing.T) {
	key := &Key{
		Secret:      "SECRET456",
		Issuer:      "Issuer2",
		AccountName: "user2@example.com",
		Host:        "hotp",
		Algorithm:   AlgorithmSHA1,
		Digits:      DigitsEight,
	}

	result := key.String()
	u, err := url.Parse(result)
	if err != nil {
		t.Fatalf("Failed to parse URL: %v", err)
	}

	values, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		t.Fatalf("Failed to parse query: %v", err)
	}

	if values.Get("period") != "" {
		t.Errorf("Expected no period, got '%s'", values.Get("period"))
	}
	if values.Get("algorithm") != "SHA1" {
		t.Errorf("Expected algorithm 'SHA1', got '%s'", values.Get("algorithm"))
	}
	if values.Get("digits") != "8" {
		t.Errorf("Expected digits '8', got '%s'", values.Get("digits"))
	}
}
