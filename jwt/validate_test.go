package jwt

import (
	"strings"
	"testing"
	"time"
)

func TestValidateClaims_AllValid(t *testing.T) {
	err := validateClaims(&RegisteredClaims{
		ID:        "12345",
		ExpiresAt: &NumericDate{time.Now().Add(10 * time.Minute)},
		NotBefore: &NumericDate{time.Now().Add(-10 * time.Minute)},
		IssuedAt:  &NumericDate{time.Now().Add(-10 * time.Minute)},
		Issuer:    "issuer",
		Subject:   "subject",
		Audience:  []string{"aud1", "aud2"},
	}, &ExpectedClaims{
		Issuer:   "issuer",
		Subject:  "subject",
		Audience: []string{"aud2"},
	})
	if err != nil {
		t.Errorf("Expected no error for valid claims, got %v", err)
	}
}

func TestValidateClaims_MissingClaims(t *testing.T) {
	err := validateClaims(&RegisteredClaims{}, &ExpectedClaims{})
	if err == nil {
		t.Fatal("Expected error for missing claims")
	}

	errStr := err.Error()
	for _, substr := range []string{
		ErrExpiresAtIsRequired.Error(),
		ErrNotBeforeIsRequired.Error(),
		ErrIssuedAtIsRequired.Error(),
		ErrIssuerIsRequired.Error(),
		ErrSubjectIsRequired.Error(),
		ErrAudienceIsRequired.Error(),
	} {
		if !strings.Contains(errStr, substr) {
			t.Errorf("Expected error message to contain %q, got %q", substr, errStr)
		}
	}
}

func TestValidateClaims_ExpiredToken(t *testing.T) {
	err := validateClaims(&RegisteredClaims{
		ID:        "12345",
		ExpiresAt: &NumericDate{time.Now().Add(-10 * time.Minute)},
		NotBefore: &NumericDate{time.Now().Add(-10 * time.Minute)},
		IssuedAt:  &NumericDate{time.Now().Add(-10 * time.Minute)},
		Issuer:    "issuer",
		Subject:   "subject",
		Audience:  []string{"aud1", "aud2"},
	}, &ExpectedClaims{
		Issuer:   "issuer",
		Subject:  "subject",
		Audience: []string{"aud2"},
	})

	if err == nil {
		t.Fatal("Expected ErrTokenExpired")
	}
	if !strings.Contains(err.Error(), ErrTokenExpired.Error()) {
		t.Errorf("Expected error message to contain %q, got %q", ErrTokenExpired.Error(), err.Error())
	}
}

func TestValidateClaims_NotYetValid(t *testing.T) {
	err := validateClaims(&RegisteredClaims{
		ID:        "12345",
		ExpiresAt: &NumericDate{time.Now().Add(10 * time.Minute)},
		NotBefore: &NumericDate{time.Now().Add(10 * time.Minute)},
		IssuedAt:  &NumericDate{time.Now().Add(-10 * time.Minute)},
		Issuer:    "issuer",
		Subject:   "subject",
		Audience:  []string{"aud1", "aud2"},
	}, &ExpectedClaims{
		Issuer:   "issuer",
		Subject:  "subject",
		Audience: []string{"aud2"},
	})

	if err == nil {
		t.Fatal("Expected ErrTokenNotValidYet")
	}
	if !strings.Contains(err.Error(), ErrTokenNotValidYet.Error()) {
		t.Errorf("Expected error message to contain %q, got %q", ErrTokenNotValidYet.Error(), err.Error())
	}
}

func TestValidateClaims_IssuedInFuture(t *testing.T) {
	err := validateClaims(&RegisteredClaims{
		ID:        "12345",
		ExpiresAt: &NumericDate{time.Now().Add(10 * time.Minute)},
		NotBefore: &NumericDate{time.Now().Add(-10 * time.Minute)},
		IssuedAt:  &NumericDate{time.Now().Add(10 * time.Minute)},
		Issuer:    "issuer",
		Subject:   "subject",
		Audience:  []string{"aud1", "aud2"},
	}, &ExpectedClaims{
		Issuer:   "issuer",
		Subject:  "subject",
		Audience: []string{"aud2"},
	})

	if err == nil {
		t.Fatal("Expected ErrTokenIssuedInFuture")
	}
	if !strings.Contains(err.Error(), ErrTokenIssuedInFuture.Error()) {
		t.Errorf("Expected error message to contain %q, got %q", ErrTokenIssuedInFuture.Error(), err.Error())
	}
}

func TestValidateClaims_IssuerMismatch(t *testing.T) {
	err := validateClaims(&RegisteredClaims{
		ID:        "12345",
		ExpiresAt: &NumericDate{time.Now().Add(10 * time.Minute)},
		NotBefore: &NumericDate{time.Now().Add(-10 * time.Minute)},
		IssuedAt:  &NumericDate{time.Now().Add(-10 * time.Minute)},
		Issuer:    "issuer1",
		Subject:   "subject",
		Audience:  []string{"aud1"},
	}, &ExpectedClaims{
		Issuer:   "issuer2",
		Subject:  "subject",
		Audience: []string{"aud1"},
	})

	if err == nil {
		t.Fatal("Expected ErrIssuerMismatch")
	}
	if !strings.Contains(err.Error(), ErrIssuerMismatch.Error()) {
		t.Errorf("Expected error message to contain %q, got %q", ErrIssuerMismatch.Error(), err.Error())
	}
}

func TestValidateClaims_SubjectMismatch(t *testing.T) {
	err := validateClaims(&RegisteredClaims{
		ID:        "12345",
		ExpiresAt: &NumericDate{time.Now().Add(10 * time.Minute)},
		NotBefore: &NumericDate{time.Now().Add(-10 * time.Minute)},
		IssuedAt:  &NumericDate{time.Now().Add(-10 * time.Minute)},
		Issuer:    "issuer",
		Subject:   "subject1",
		Audience:  []string{"aud1"},
	}, &ExpectedClaims{
		Issuer:   "issuer",
		Subject:  "subject2",
		Audience: []string{"aud1"},
	})

	if err == nil {
		t.Fatal("Expected ErrSubjectMismatch")
	}
	if !strings.Contains(err.Error(), ErrSubjectMismatch.Error()) {
		t.Errorf("Expected error message to contain %q, got %q", ErrSubjectMismatch.Error(), err.Error())
	}
}

func TestValidateClaims_AudienceMismatch(t *testing.T) {
	err := validateClaims(&RegisteredClaims{
		ID:        "12345",
		ExpiresAt: &NumericDate{time.Now().Add(10 * time.Minute)},
		NotBefore: &NumericDate{time.Now().Add(-10 * time.Minute)},
		IssuedAt:  &NumericDate{time.Now().Add(-10 * time.Minute)},
		Issuer:    "issuer",
		Subject:   "subject",
		Audience:  []string{"aud1"},
	}, &ExpectedClaims{
		Issuer:   "issuer",
		Subject:  "subject",
		Audience: []string{"aud2"},
	})

	if err == nil {
		t.Fatal("Expected ErrAudienceMismatch")
	}
	if !strings.Contains(err.Error(), ErrAudienceMismatch.Error()) {
		t.Errorf("Expected error message to contain %q, got %q", ErrAudienceMismatch.Error(), err.Error())
	}
}
