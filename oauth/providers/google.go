package providers

import (
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
func (p *GoogleProvider) GetUserFromIdToken(idToken string) (*oauth.OAuth2User, error) {
	claims, err := oauth.DecodeIdToken[_GoogleIdTokenClaims](idToken)
	if err != nil {
		return nil, err
	}

	if claims.Email == "" || !claims.EmailVerified {
		return nil, oauth.ErrNoVerifiedEmail
	}

	return &oauth.OAuth2User{
		ID:    claims.Sub,
		Email: claims.Email,
	}, nil
}

type _GoogleIdTokenClaims struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Sub           string `json:"sub"`
}
