package providers

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/loggdme/strivia/jwt"
	"github.com/loggdme/strivia/oauth"
)

// AppleJWKS fetches the Apple JWKS.
func AppleJWKS(customEndpoint *string) (*jwt.JWKS, error) {
	if customEndpoint != nil {
		return jwt.FetchJWKS(*customEndpoint)
	}

	return jwt.FetchJWKS("https://appleid.apple.com/auth/keys")
}

// AppleUserFromIdTokenWithValidation extracts user information from a Apple ID token.
// It does the same as AppleUserFromIdToken but also verifies the token signature
// with the Google JWKS. Use this method when obtaining ID tokens from users.
func AppleUserFromIdTokenWithValidation(jwks *jwt.JWKS, idToken string, nonce string, audience *string) (*oauth.OAuth2User, error) {
	parsed, err := jwt.UnsecureDecodeToken[_AppleIdTokenClaims](idToken)
	if err != nil {
		return nil, err
	}

	// General validation
	algorithm := parsed.Header["alg"].(string)
	if algorithm != "RS256" {
		return nil, jwt.ErrTokenInvalidAlgorithm
	}

	kid, ok := parsed.Header["kid"].(string)
	if !ok {
		return nil, oauth.ErrKidNotFound
	}

	if parsed.Claims.Issuer != "https://appleid.apple.com" {
		return nil, jwt.ErrIssuerMismatch
	}

	if audience != nil && (len(parsed.Claims.Audience) != 1 || parsed.Claims.Audience[0] != *audience) {
		return nil, jwt.ErrAudienceMismatch
	}

	if time.Now().After(parsed.Claims.ExpiresAt.Time) {
		return nil, jwt.ErrTokenExpired
	}

	if parsed.Claims.Email == "" || !parsed.Claims.EmailVerified {
		return nil, oauth.ErrNoVerifiedEmail
	}

	hashedNonce := sha256.Sum256([]byte(nonce))
	hashedNonceString := hex.EncodeToString(hashedNonce[:])
	if hashedNonceString != parsed.Claims.Nonce {
		return nil, oauth.ErrInvalidNonce
	}

	// Get public key for signing check
	jwk, err := jwks.FindKeyByKid(kid)
	if err != nil {
		return nil, oauth.ErrKidNotFound
	}

	pubKey, err := jwk.ToRSAPublicKey()
	if err != nil {
		return nil, oauth.ErrInvalidPublicKey
	}

	// Verify signature
	tokenPayload := parsed.RawParts[0] + "." + parsed.RawParts[1]
	if err := jwt.SigningMethodRS256.VerifyRSA(tokenPayload, parsed.Signature, pubKey); err != nil {
		return nil, oauth.ErrVerificationFailed
	}

	// Return user information
	return &oauth.OAuth2User{
		ID:    parsed.Claims.Subject,
		Email: parsed.Claims.Email,
	}, nil
}

type _AppleIdTokenClaims struct {
	Nonce         string `json:"nonce"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	jwt.RegisteredClaims
}
