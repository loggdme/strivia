package providers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/loggdme/strivia/oauth"
)

type TwitchProvider struct {
	Client *oauth.OAuth2Client
}

// NewTwitchProvider creates and returns a new instance of TwitchProvider using the provided
// clientId, clientSecret, and the redirectUri. It initializes the underlying OAuth
// provider with the given credentials for Twitch authentication integration.
func NewTwitchProvider(clientId string, clientSecret string, redirectUri string) *TwitchProvider {
	return &TwitchProvider{Client: oauth.NewOauthProvider(clientId, clientSecret, &redirectUri)}
}

// CreateAuthorizationURL generates the Discord OAuth 2.0 authorization URL with the specified state and scopes.
// It uses the underlying OAuth client to construct the URL for initiating the au
func (p *TwitchProvider) CreateAuthorizationURL(state string, scopes []string) string {
	return p.Client.CreateAuthorizationURL("https://id.twitch.tv/oauth2/authorize", state, scopes)
}

// ValidateAuthorizationCode exchanges the provided authorization code and code verifier
// for an access token using Twitch's OAuth 2.0 token endpoint. It returns the access token
// as a string pointer if successful, or an error if the exchange fails.
func (p *TwitchProvider) ValidateAuthorizationCode(code string) (*oauth.OAuth2Tokens, error) {
	body := url.Values{}

	body.Set("grant_type", "authorization_code")
	body.Set("code", code)
	body.Set("redirect_uri", *p.Client.RedirectURI)
	body.Set("client_id", p.Client.ClientID)
	body.Set("client_secret", p.Client.ClientSecret)

	request, err := oauth.CreateOAuth2Request("https://id.twitch.tv/oauth2/token", body)
	if err != nil {
		return nil, err
	}

	tokensMap, err := oauth.SendTokenRequest[map[string]any](request, p.Client.Http)
	if err != nil {
		return nil, err
	}

	oauth2Tokens := &oauth.OAuth2Tokens{}

	if accessToken, ok := (*tokensMap)["access_token"].(string); ok {
		oauth2Tokens.AccessToken = accessToken
	}

	if idToken, ok := (*tokensMap)["id_token"].(string); ok {
		oauth2Tokens.IdToken = &idToken
	}

	return oauth2Tokens, nil
}

// GetUser retrieves the authenticated user's information from Twitch using the provided access token.
// Returns an OAuth2User containing the user's ID, username, email, and avatar URL, or an error if any step fails.
func (p *TwitchProvider) GetUser(accessToken string) (*oauth.OAuth2User, error) {
	req, _ := http.NewRequest("GET", "https://api.twitch.tv/helix/users", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Set("Client-ID", p.Client.ClientID)

	resp, err := p.Client.Http.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, oauth.ErrFetchingUser
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, oauth.ErrFetchingUser
	}

	var parsedResponse _TwitchUserResponse
	err = json.Unmarshal(bodyBytes, &parsedResponse)
	if err != nil {
		return nil, oauth.ErrFetchingUser
	}

	if len(parsedResponse.Data) != 1 {
		return nil, oauth.ErrFetchingUser
	}

	if parsedResponse.Data[0].Email == nil || *parsedResponse.Data[0].Email == "" {
		return nil, oauth.ErrNoVerifiedEmail
	}

	return &oauth.OAuth2User{
		ID:       parsedResponse.Data[0].ID,
		Username: &parsedResponse.Data[0].Login,
		Email:    *parsedResponse.Data[0].Email,
	}, nil
}

type _TwitchUserResponse struct {
	Data []struct {
		ID    string  `json:"id"`
		Login string  `json:"login"`
		Email *string `json:"email"`
	} `json:"data"`
}
