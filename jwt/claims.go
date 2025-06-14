package jwt

type Claims interface {
	GetExpirationTime() *NumericDate
	GetIssuedAt() *NumericDate
	GetNotBefore() *NumericDate
	GetIssuer() string
	GetSubject() string
	GetAudience() []string
	GetID() string
}

// RegisteredClaims are a structured version of the JWT Claims Set, restricted to Registered Claim Names,
// as referenced at https://datatracker.ietf.org/doc/html/rfc7519#section-4.1
type RegisteredClaims struct {
	// the `iss` (Issuer) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1
	Issuer string `json:"iss,omitempty"`

	// the `sub` (Subject) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2
	Subject string `json:"sub,omitempty"`

	// the `aud` (Audience) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
	Audience []string `json:"aud,omitempty"`

	// the `exp` (Expiration Time) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
	ExpiresAt *NumericDate `json:"exp,omitempty"`

	// the `nbf` (Not Before) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
	NotBefore *NumericDate `json:"nbf,omitempty"`

	// the `iat` (Issued At) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6
	IssuedAt *NumericDate `json:"iat,omitempty"`

	// the `jti` (JWT ID) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7
	ID string `json:"jti,omitempty"`
}

// GetIssuer implements the Claims interface.
func (c RegisteredClaims) GetIssuer() string {
	return c.Issuer
}

// GetSubject implements the Claims interface.
func (c RegisteredClaims) GetSubject() string {
	return c.Subject
}

// GetAudience implements the Claims interface.
func (c RegisteredClaims) GetAudience() []string {
	return c.Audience
}

// GetExpirationTime implements the Claims interface.
func (c RegisteredClaims) GetExpirationTime() *NumericDate {
	return c.ExpiresAt
}

// GetNotBefore implements the Claims interface.
func (c RegisteredClaims) GetNotBefore() *NumericDate {
	return c.NotBefore
}

// GetIssuedAt implements the Claims interface.
func (c RegisteredClaims) GetIssuedAt() *NumericDate {
	return c.IssuedAt
}

// GetID implements the Claims interface.
func (c RegisteredClaims) GetID() string {
	return c.ID
}
