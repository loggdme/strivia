package jwt

import (
	"errors"
	"slices"
	"strings"
	"time"
)

var (
	ErrExpiresAtIsRequired = errors.New("jwt: 'exp' claim is required")
	ErrNotBeforeIsRequired = errors.New("jwt: 'nbf' claim is required")
	ErrIssuedAtIsRequired  = errors.New("jwt: 'iat' claim is required")
	ErrIssuerIsRequired    = errors.New("jwt: 'iss' claim is required")
	ErrSubjectIsRequired   = errors.New("jwt: 'sub' claim is required")
	ErrAudienceIsRequired  = errors.New("jwt: 'aud' claim is required")
	ErrTokenNotValidYet    = errors.New("jwt: token is not valid yet")
	ErrTokenExpired        = errors.New("jwt: token is expired")
	ErrTokenIssuedInFuture = errors.New("jwt: token is issued in the future")
	ErrIssuerMismatch      = errors.New("jwt: issuer does not match expected issuer")
	ErrSubjectMismatch     = errors.New("jwt: subject does not match expected subject")
	ErrAudienceMismatch    = errors.New("jwt: audience does not match expected audience")
)

type ExpectedClaims struct {
	// Issuer is the expected issuer of the JWT.
	Issuer string `json:"iss,omitempty"`
	// Subject is the expected subject of the JWT.
	Subject string `json:"sub,omitempty"`
	// Audience is the expected audience of the JWT.
	Audience []string `json:"aud,omitempty"`
}

// validateClaims validates the provided claims of type T, which must satisfy the Claims interface.
// It checks the claims and collects any validation errors encountered.
// If no errors are found, it returns nil. Otherwise, it returns a single error containing
// all validation error messages concatenated together.
func validateClaims(claims Claims, expected *ExpectedClaims) error {
	now := time.Now()
	errs := make([]error, 0, 6)

	if err := verifyExpiresAt(claims, now); err != nil {
		errs = append(errs, err)
	}

	if err := verifyNotBefore(claims, now); err != nil {
		errs = append(errs, err)
	}

	if err := verifyIssuedAt(claims, now); err != nil {
		errs = append(errs, err)
	}

	if err := verifyIssuer(claims, expected.Issuer); err != nil {
		errs = append(errs, err)
	}

	if err := verifySubject(claims, expected.Subject); err != nil {
		errs = append(errs, err)
	}

	if err := verifyAudience(claims, expected.Audience); err != nil {
		errs = append(errs, err)
	}

	if len(errs) == 0 {
		return nil
	}

	var sb strings.Builder
	for _, err := range errs {
		sb.WriteString(err.Error() + "; ")
	}

	return errors.New(strings.TrimSuffix(sb.String(), "; "))
}

// verifyExpiresAt compares the exp claim in claims against cmp. This function
// will succeed if cmp < exp.
func verifyExpiresAt(claims Claims, cmp time.Time) error {
	exp := claims.GetExpirationTime()

	if exp == nil {
		return ErrExpiresAtIsRequired
	}

	if cmp.After((exp.Time)) {
		return ErrTokenExpired
	}

	return nil
}

// verifyNotBefore compares the nbf claim in claims against cmp. This function
// will return true if cmp >= nbf.
func verifyNotBefore(claims Claims, cmp time.Time) error {
	nbf := claims.GetNotBefore()

	if nbf == nil {
		return ErrNotBeforeIsRequired
	}

	if cmp.Before(nbf.Time) {
		return ErrTokenNotValidYet
	}

	return nil
}

// verifyIssuedAt compares the iat claim in claims against cmp. This function
// will return true if cmp >= iat.
func verifyIssuedAt(claims Claims, cmp time.Time) error {
	iat := claims.GetIssuedAt()

	if iat == nil {
		return ErrIssuedAtIsRequired
	}

	if cmp.Before(iat.Time) {
		return ErrTokenIssuedInFuture
	}

	return nil
}

// verifyIssuer checks if the issuer claim in claims matches the expected issuer.
func verifyIssuer(claims Claims, expectedIssuer string) error {
	issuer := claims.GetIssuer()

	if issuer == "" {
		return ErrIssuerIsRequired
	}

	if issuer != expectedIssuer {
		return ErrIssuerMismatch
	}

	return nil
}

// verifySubject checks if the subject claim in claims matches the expected subject.
func verifySubject(claims Claims, expectedSubject string) error {
	subject := claims.GetSubject()

	if subject == "" {
		return ErrSubjectIsRequired
	}

	if expectedSubject != "" && subject != expectedSubject {
		return ErrSubjectMismatch
	}

	return nil
}

// verifyAudience checks if the audience claim in claims matches the expected audience.
func verifyAudience(claims Claims, expectedAudience []string) error {
	audience := claims.GetAudience()

	if len(audience) == 0 {
		return ErrAudienceIsRequired
	}

	for _, expAud := range expectedAudience {
		if slices.Contains(audience, expAud) {
			return nil
		}
	}

	return ErrAudienceMismatch
}
