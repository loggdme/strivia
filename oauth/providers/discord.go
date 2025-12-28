package providers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/loggdme/strivia/oauth"
)

type DiscordProvider struct {
	Client *oauth.OAuth2Client
}

// NewDiscordProvider creates and returns a new instance of DiscordProvider using the provided
// clientId, clientSecret, and the redirectUri. It initializes the underlying OAuth
// provider with the given credentials for Discord authentication integration.
func NewDiscordProvider(clientId string, clientSecret string, redirectUri string) *DiscordProvider {
	return &DiscordProvider{Client: oauth.NewOauthProvider(clientId, clientSecret, &redirectUri)}
}

// CreateAuthorizationURL generates the Discord OAuth 2.0 authorization URL with the specified state and scopes.
// It uses the underlying OAuth client to construct the URL for initiating the authorization flow.
//
// You can find all relevant scopes for Discord OAuth 2.0 here https://discord.com/developers/docs/topics/oauth2#shared-resources
func (p *DiscordProvider) CreateAuthorizationURL(state string, codeVerifier string, scopes []string) string {
	return p.Client.CreateAuthorizationURLWithPKCE("https://discord.com/oauth2/authorize", state, oauth.S256, codeVerifier, scopes)
}

// ValidateAuthorizationCode exchanges the provided authorization code and code verifier
// for an access token using Discord's OAuth 2.0 token endpoint. It returns the access token
// as a string pointer if successful, or an error if the exchange fails.
//
// With this code you can fetch the Discord API from the user's perspective. Read more about it here:
// https://discord.com/developers/docs/topics/oauth2#shared-resources
func (p *DiscordProvider) ValidateAuthorizationCode(code string, codeVerifier string) (*oauth.OAuth2Tokens, error) {
	return p.Client.ValidateAuthorizationCode("https://discord.com/api/oauth2/token", code, &codeVerifier)
}

// GetUser retrieves the authenticated user's information from Discord using the provided access token.
// Returns an OAuth2User containing the user's ID, username, email, and avatar URL, or an error if any step fails.
func (p *DiscordProvider) GetUser(accessToken string) (*oauth.OAuth2User, error) {
	req, _ := http.NewRequest("GET", "https://discord.com/api/v10/users/@me", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	resp, err := p.Client.Http.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, oauth.ErrFetchingUser
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, oauth.ErrFetchingUser
	}

	var parsedResponse _DiscordUserResponse
	err = json.Unmarshal(bodyBytes, &parsedResponse)
	if err != nil {
		return nil, oauth.ErrFetchingUser
	}

	if parsedResponse.Email == "" || !parsedResponse.Verified {
		return nil, oauth.ErrNoVerifiedEmail
	}

	return &oauth.OAuth2User{
		ID:       parsedResponse.ID,
		Username: &parsedResponse.Username,
		Email:    parsedResponse.Email,
	}, nil
}

type _DiscordUserResponse struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Verified bool   `json:"verified"`
}
