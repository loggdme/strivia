package oauth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	strivia_random "github.com/loggdme/strivia/random"
)

var (
	ErrTokenFetch           = errors.New("oauth: failed to fetch token")
	ErrOauthRequest         = errors.New("oauth: oauth request error")
	ErrFailedDecodeResponse = errors.New("oauth: failed to decode success response JSON")
	ErrResponseEmpty        = errors.New("oauth: success response is empty")
	ErrUnexpectedStatusCode = errors.New("oauth: unexpected status code")
	ErrTokenResponse        = errors.New("oauth: failed to parse token response")
	ErrFetchingUser         = errors.New("oauth: error fetching user information")
	ErrNoVerifiedEmail      = errors.New("oauth: no verified email found in user information")
)

// OAuth2User represents a user authenticated via an OAuth2 provider.
// It contains basic user information such as ID, username, email, and avatar URL.
type OAuth2User struct {
	ID        string
	Username  string
	Email     string
	AvatarURL string
}

// OAuth2Client represents an OAuth 2.0 client configuration, including credentials,
// redirect URI, and an optional custom HTTP client for making requests to the OAuth provider.
type OAuth2Client struct {
	ClientID     string
	ClientSecret string
	RedirectURI  *string
	Http         *http.Client
}

// NewOauthProvider creates and returns a new instance of OAuth2Client with the provided
// client ID, client secret, and optional redirect URI. The function initializes the
// HTTP client used for OAuth2 requests. If redirectUri is nil, the OAuth2Client will
// not set a redirect URI.
func NewOauthProvider(clientId string, clientSecret string, redirectUri *string) *OAuth2Client {
	return &OAuth2Client{Http: &http.Client{}, ClientID: clientId, ClientSecret: clientSecret, RedirectURI: redirectUri}
}

// CreateAuthorizationURL constructs an OAuth2 authorization URL with the specified endpoint, state, and scopes.
// It sets the required query parameters such as response_type, client_id, state, and optionally scope and redirect_uri.
// The function returns the complete authorization URL as a string.
func (p *OAuth2Client) CreateAuthorizationURL(endpoint string, state string, scopes []string) string {
	u, _ := url.Parse(endpoint)

	q := u.Query()

	q.Set("response_type", "code")
	q.Set("client_id", p.ClientID)
	q.Set("state", state)

	if len(scopes) > 0 {
		q.Set("scope", strings.Join(scopes, " "))
	}

	if p.RedirectURI != nil {
		q.Set("redirect_uri", *p.RedirectURI)
	}

	u.RawQuery = q.Encode()

	return u.String()
}

// ValidateAuthorizationCode exchanges an authorization code for an access token using the OAuth2 protocol.
// It sends a POST request to the specified token endpoint with the provided authorization code and optional redirect URI.
// The client credentials are included in the Authorization header using Basic authentication.
// On success, it returns the access token as a string pointer. If the token exchange fails or the response is invalid,
// it returns an error.
func (p *OAuth2Client) ValidateAuthorizationCode(endpoint string, code string) (*string, error) {
	body := url.Values{}

	body.Set("grant_type", "authorization_code")
	body.Set("code", code)
	if p.RedirectURI != nil {
		body.Set("redirect_uri", *p.RedirectURI)
	}

	request, err := CreateOAuth2Request(endpoint, body)
	if err != nil {
		return nil, err
	}

	encodedCredentials := EncodeBasicCredentials(p.ClientID, p.ClientSecret)
	request.Header.Set("Authorization", fmt.Sprintf("Basic %s", encodedCredentials))

	tokens, err := SendTokenRequest[map[string]any](request, p.Http)
	if err != nil {
		return nil, err
	}

	if tokens != nil && (*tokens)["access_token"] != nil {
		accessToken, _ := (*tokens)["access_token"].(string)
		return &accessToken, nil
	}

	return nil, ErrTokenResponse
}

// CreateOAuth2Request constructs an HTTP POST request for OAuth2 endpoints with the given URL and form-encoded body.
// It sets appropriate headers for content type, accept, user agent, and content length.
// Returns the constructed *http.Request or an error if the request could not be created.
func CreateOAuth2Request(endpoint string, body url.Values) (*http.Request, error) {
	bodyBytes := []byte(body.Encode())

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "strivia")
	req.Header.Set("Content-Length", strconv.Itoa(len(bodyBytes)))

	return req, nil
}

// SendTokenRequest sends an HTTP request using the provided client and attempts to decode the JSON response body into a value of type T.
// It returns a pointer to the decoded value or an error if the request fails, the response status code is unexpected, or decoding fails.
//
// Returns a pointer to the decoded value of type T, or an error if any step fails.
func SendTokenRequest[T any](req *http.Request, client *http.Client) (*T, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, ErrTokenFetch
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrOauthRequest
	}

	if resp.StatusCode == http.StatusOK {
		var data *T
		err := json.NewDecoder(resp.Body).Decode(&data)

		if err != nil {
			return nil, ErrFailedDecodeResponse
		}

		if data == nil {
			return nil, ErrResponseEmpty
		}

		return data, nil
	}

	return nil, ErrUnexpectedStatusCode
}

// EncodeBasicCredentials encodes the provided clientId and clientSecret into a base64-encoded
// string suitable for use as HTTP Basic Authentication credentials. The credentials are
// formatted as "clientId:clientSecret" before encoding.
func EncodeBasicCredentials(clientId, clientSecret string) string {
	credentials := fmt.Sprintf("%s:%s", clientId, clientSecret)
	return base64.StdEncoding.EncodeToString([]byte(credentials))
}

// GenerateRandomState generates a cryptographically secure random string
// encoded in Base32 with a length of 32 characters. This is typically used
// as a state parameter in OAuth flows to prevent cross-site request forgery (CSRF) attacks.
func GenerateRandomState() string {
	return strivia_random.SecureRandomBase32String(32)
}
