package providers

import (
	"time"

	"github.com/loggdme/strivia/jwt"
	"github.com/loggdme/strivia/oauth"
)

type GoogleProvider struct {
	Client *oauth.OAuth2Client
}

// NewGoogleProvider creates and returns a new instance of GoogleProvider using the provided
// clientId, clientSecret, and the redirectUri. It initializes the underlying OAuth
// provider with the given credentials for Google authentication integration.
func NewGoogleProvider(clientId string, clientSecret string, redirectUri string) *GoogleProvider {
	return &GoogleProvider{Client: oauth.NewOauthProvider(clientId, clientSecret, &redirectUri)}
}

// CreateAuthorizationURL generates the Google OAuth 2.0 authorization URL with the specified state and scopes.
// It uses the underlying OAuth client to construct the URL for initiating the authorization flow.
//
// You can find all relevant scopes for Google OAuth 2.0 here https://developers.google.com/identity/protocols/oauth2/scopes#iamcredentials
func (p *GoogleProvider) CreateAuthorizationURL(state string, codeVerifier string, scopes []string) string {
	return p.Client.CreateAuthorizationURLWithPKCE("https://accounts.google.com/o/oauth2/v2/auth", state, oauth.S256, codeVerifier, scopes)
}

// ValidateAuthorizationCode exchanges the provided authorization code and code verifier
// for an access token using Google's OAuth 2.0 token endpoint. It returns the access token
// as a string pointer if successful, or an error if the exchange fails.
//
// With this code you can fetch the Google API from the user's perspective. Read more about it here:
// https://docs.github.com/en/rest/users/emails?apiVersion=2022-11-28
func (p *GoogleProvider) ValidateAuthorizationCode(code string, codeVerifier string) (*oauth.OAuth2Tokens, error) {
	return p.Client.ValidateAuthorizationCode("https://oauth2.googleapis.com/token", code, &codeVerifier)
}

// GetUserFromIdToken extracts user information from a Google ID token.
// It decodes the provided ID token, verifies the email, and returns an OAuth2User
// containing the user's ID and email address. If the token is invalid or the email
// is not verified, an appropriate error is returned.
// Read more about it here: https://developers.google.com/identity/openid-connect/openid-connect#an-id-tokens-payload
// Use this method when obtaining ID tokens from trusted sources.
func GoogleUserFromIdToken(idToken string) (*oauth.OAuth2User, error) {
	claims, err := oauth.DecodeIdToken[_GoogleIdTokenClaims](idToken)
	if err != nil {
		return nil, err
	}

	if claims.Email == "" || !claims.EmailVerified {
		return nil, oauth.ErrNoVerifiedEmail
	}

	return &oauth.OAuth2User{
		ID:    claims.Subject,
		Email: claims.Email,
	}, nil
}

// GoogleJWKS fetches the Google JWKS.
func GoogleJWKS() (*jwt.JWKS, error) {
	jwks, err := jwt.FetchJWKS("https://www.googleapis.com/oauth2/v3/certs")
	if err != nil {
		return nil, err
	}
	return jwks, nil
}

// GoogleUserFromIdTokenWithValidation extracts user information from a Google ID token.
// It does the same as GoogleUserFromIdToken but also verifies the token signature
// with the Google JWKS. Use this method when obtaining ID tokens from users.
func GoogleUserFromIdTokenWithValidation(jwks *jwt.JWKS, idToken string, audience string) (*oauth.OAuth2User, error) {
	parsed, err := jwt.UnsecureDecodeToken[_GoogleIdTokenClaims](idToken)
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

	if parsed.Claims.Issuer != "https://accounts.google.com" {
		return nil, jwt.ErrIssuerMismatch
	}

	if len(parsed.Claims.Audience) != 1 || parsed.Claims.Audience[0] != audience {
		return nil, jwt.ErrAudienceMismatch
	}

	if time.Now().After(parsed.Claims.ExpiresAt.Time) {
		return nil, jwt.ErrTokenExpired
	}

	if parsed.Claims.Email == "" || !parsed.Claims.EmailVerified {
		return nil, oauth.ErrNoVerifiedEmail
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

type _GoogleIdTokenClaims struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	jwt.RegisteredClaims
}
