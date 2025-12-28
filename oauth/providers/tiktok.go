package providers

import (
	"net/url"

	"github.com/loggdme/strivia/oauth"
)

type TikTokProvider struct {
	Client *oauth.OAuth2Client
}

// NewTikTokProvider creates and returns a new instance of TikTokProvider using the provided
// clientId, clientSecret, and the redirectUri. It initializes the underlying OAuth
// provider with the given credentials for Discord authentication integration.
func NewTikTokProvider(clientId string, clientSecret string, redirectUri string) *TikTokProvider {
	return &TikTokProvider{Client: oauth.NewOauthProvider(clientId, clientSecret, &redirectUri)}
}

// ValidateAuthorizationCode exchanges the provided authorization code and code verifier
// for an access token using TikTok's OAuth 2.0 token endpoint. It returns the access token
// as a string pointer if successful, or an error if the exchange fails.
func (p *TikTokProvider) ValidateAuthorizationCode(code string, codeVerifier string) (*oauth.OAuth2Tokens, error) {
	body := url.Values{}

	body.Set("grant_type", "authorization_code")
	body.Set("code", code)
	body.Set("redirect_uri", *p.Client.RedirectURI)
	body.Set("code_verifier", codeVerifier)
	body.Set("client_key", p.Client.ClientID)
	body.Set("client_secret", p.Client.ClientSecret)

	request, err := oauth.CreateOAuth2Request("https://open.tiktokapis.com/v2/oauth/token/", body)
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
