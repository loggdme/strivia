package jwt

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestValidateClaims_AllValid(t *testing.T) {
	assert.NoError(t, validateClaims(&RegisteredClaims{
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
	}), "Expected no error for valid claims")
}

func TestValidateClaims_MissingClaims(t *testing.T) {
	err := validateClaims(&RegisteredClaims{}, &ExpectedClaims{})
	assert.Error(t, err, "Expected error for missing claims")

	assert.Contains(t, err.Error(), ErrExpiresAtIsRequired.Error(), "Expected error message to contain 'ExpiresAt is required'")
	assert.Contains(t, err.Error(), ErrNotBeforeIsRequired.Error(), "Expected error message to contain 'NotBefore is required'")
	assert.Contains(t, err.Error(), ErrIssuedAtIsRequired.Error(), "Expected error message to contain 'IssuedAt is required'")
	assert.Contains(t, err.Error(), ErrIssuerIsRequired.Error(), "Expected error message to contain 'Issuer is required'")
	assert.Contains(t, err.Error(), ErrSubjectIsRequired.Error(), "Expected error message to contain 'Subject is required'")
	assert.Contains(t, err.Error(), ErrAudienceIsRequired.Error(), "Expected error message to contain 'Audience is required'")
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

	assert.Error(t, err, "Expected ErrTokenExpired")
	assert.Contains(t, err.Error(), ErrTokenExpired.Error(), "Expected error message to contain 'Token expired'")
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

	assert.Error(t, err, "Expected ErrTokenNotValidYet")
	assert.Contains(t, err.Error(), ErrTokenNotValidYet.Error(), "Expected error message to contain 'Token not valid yet'")
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

	assert.Error(t, err, "Expected ErrTokenIssuedInFuture")
	assert.Contains(t, err.Error(), ErrTokenIssuedInFuture.Error(), "Expected error message to contain 'Token issued in the future'")
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

	assert.Error(t, err, "Expected ErrIssuerMismatch")
	assert.Contains(t, err.Error(), ErrIssuerMismatch.Error(), "Expected error message to contain 'Issuer mismatch'")
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

	assert.Error(t, err, "Expected ErrSubjectMismatch")
	assert.Contains(t, err.Error(), ErrSubjectMismatch.Error(), "Expected error message to contain 'Subject mismatch'")
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

	assert.Error(t, err, "Expected ErrAudienceMismatch")
	assert.Contains(t, err.Error(), ErrAudienceMismatch.Error(), "Expected error message to contain 'Audience mismatch'")
}
