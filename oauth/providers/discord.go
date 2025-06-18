package providers

import (
	"github.com/loggdme/strivia/oauth"
)

type DiscordProvider struct {
	Client *oauth.OAuth2Client
}

// NewDiscordProvider creates and returns a new instance of DiscordProvider using the provided
// clientId, clientSecret, and an optional redirectUri. It initializes the underlying OAuth
// provider with the given credentials for Discord authentication integration.
func NewDiscordProvider(clientId string, clientSecret string, redirectUri string) *DiscordProvider {
	return &DiscordProvider{
		Client: oauth.NewOauthProvider(clientId, clientSecret, &redirectUri),
	}
}

// CreateAuthorizationURL generates the Discord OAuth 2.0 authorization URL with the specified state and scopes.
// It uses the underlying OAuth client to construct the URL for initiating the authorization flow.
//
// You can find all relevant scopes for Discord OAuth 2.0 here https://discord.com/developers/docs/topics/oauth2
func (p *DiscordProvider) CreateAuthorizationURL(state string, scopes []string) string {
	return p.Client.CreateAuthorizationURL("https://discord.com/oauth2/authorize", state, scopes)
}

// ValidateAuthorizationCode exchanges the provided authorization code for an access token
// using Discords OAuth 2.0 endpoint. It returns the access token as a string pointer if successful,
// or an error if the exchange fails.
//
// With this code you can fetch the Discord API from the user's perspective. Read more about it here:
// https://discord.com/developers/docs/resources/user#user-object
func (p *DiscordProvider) ValidateAuthorizationCode(code string) (*oauth.OAuth2Tokens, error) {
	return p.Client.ValidateAuthorizationCode("https://discord.com/api/oauth2/token", code, nil)
}

// GetUser retrieves the authenticated user's information from GitHub using the provided access token.
// It first obtains the user's primary email address, then fetches the user's profile data from the GitHub API.
// Returns an OAuth2User containing the user's ID, username, email, and avatar URL, or an error if any step fails.
//
// If no verified email is found, it returns an error indicating that no verified email is available.
// func (p *DiscordProvider) GetUser(client *http.Client, accessToken string) (*oauth.OAuth2User, error) {
// 	req, _ := http.NewRequest("GET", "https://discord.com/api/users/@me", nil)
// 	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
//
// }

type _DiscordUserResponse struct {
	ID       int64  `json:"id"`
	Email    string `json:"email"`
	Verified string `json:"verified"`
}
