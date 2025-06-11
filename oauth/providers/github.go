package providers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/loggdme/strivia/oauth"
)

type GitHubProvider struct {
	Client *oauth.OAuth2Client
}

// NewGitHubProvider creates and returns a new instance of GitHubProvider using the provided
// clientId, clientSecret, and an optional redirectUri. It initializes the underlying OAuth
// provider with the given credentials for GitHub authentication integration.
func NewGitHubProvider(clientId string, clientSecret string, redirectUri *string) *GitHubProvider {
	return &GitHubProvider{
		Client: oauth.NewOauthProvider(clientId, clientSecret, redirectUri),
	}
}

// CreateAuthorizationURL generates the GitHub OAuth 2.0 authorization URL with the specified state and scopes.
// It uses the underlying OAuth client to construct the URL for initiating the authorization flow.
//
// You can find all relevant scopes for GitHub OAuth 2.0 here https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps
func (p *GitHubProvider) CreateAuthorizationURL(state string, scopes []string) string {
	return p.Client.CreateAuthorizationURL("https://github.com/login/oauth/authorize", state, scopes)
}

// ValidateAuthorizationCode exchanges the provided authorization code for an access token
// using GitHub's OAuth 2.0 endpoint. It returns the access token as a string pointer if successful,
// or an error if the exchange fails.
//
// With this code you can fetch the GitHub API from the user's perspective. Read more about it here:
// https://docs.github.com/en/rest/users/emails?apiVersion=2022-11-28
func (p *GitHubProvider) ValidateAuthorizationCode(code string) (*oauth.OAuth2Tokens, error) {
	return p.Client.ValidateAuthorizationCode("https://github.com/login/oauth/access_token", code, nil)
}

// GetUser retrieves the authenticated user's information from GitHub using the provided access token.
// It first obtains the user's primary email address, then fetches the user's profile data from the GitHub API.
// Returns an OAuth2User containing the user's ID, username, email, and avatar URL, or an error if any step fails.
//
// If no verified email is found, it returns an error indicating that no verified email is available.
func (p *GitHubProvider) GetUser(accessToken string) (*oauth.OAuth2User, error) {
	email, err := p.GetUserEmail(accessToken)
	if err != nil {
		return nil, err
	}

	githubUserResponse, err := _MakeGithubRequest[_GitHubUserResponse](p.Client.Http, "GET", "https://api.github.com/user", accessToken)
	if err != nil {
		return nil, err
	}

	return &oauth.OAuth2User{
		ID:    strconv.Itoa(int(githubUserResponse.ID)),
		Email: email,
	}, nil
}

// GetUserEmail retrieves the primary and verified email address associated with the user's GitHub account
// using the provided OAuth access token. It returns the email address if found, or an error if no verified
// primary email is available or if the request fails.
func (p *GitHubProvider) GetUserEmail(accessToken string) (string, error) {
	githubEmailResponse, err := _MakeGithubRequest[_GitHubEmailResponse](p.Client.Http, "GET", "https://api.github.com/user/emails", accessToken)
	if err != nil {
		return "", err
	}

	for _, email := range *githubEmailResponse {
		if email.Verified && email.Primary && email.Email != "" {
			return email.Email, nil
		}
	}

	return "", oauth.ErrNoVerifiedEmail
}

type _GitHubUserResponse struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	AvatarURL string `json:"avatar_url"`
}

type _GitHubEmailResponse []struct {
	Email    string `json:"email"`
	Verified bool   `json:"verified"`
	Primary  bool   `json:"primary"`
}

func _MakeGithubRequest[T any](client *http.Client, method string, url string, accessToken string) (*T, error) {
	req, _ := http.NewRequest(method, url, nil)

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, oauth.ErrFetchingUser
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, oauth.ErrFetchingUser
	}

	var parsedResponse T
	err = json.Unmarshal(bodyBytes, &parsedResponse)
	if err != nil {
		return nil, oauth.ErrFetchingUser
	}

	return &parsedResponse, nil
}
