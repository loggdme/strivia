package oauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/loggdme/strivia/jwt"
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
	ErrKidNotFound          = errors.New("oauth: kid not found")
	ErrFetchingJWKS         = errors.New("oauth: error fetching JWKS")
	ErrInvalidPublicKey     = errors.New("oauth: invalid public key")
	ErrVerificationFailed   = errors.New("oauth: verification failed")
	ErrInvalidNonce         = errors.New("oauth: invalid nonce")
)

// CodeChallengeMethod represents the method used for the PKCE code challenge.
type CodeChallengeMethod int

const (
	// S256 uses SHA256 to create the code challenge.
	S256 CodeChallengeMethod = iota
	// Plain uses the code verifier directly as the code challenge.
	Plain
)

// OAuth2User represents a user authenticated via an OAuth2 provider.
// It contains basic user information such as ID, username, email, and avatar URL.
type OAuth2User struct {
	ID    string
	Email string
}

type OAuth2Tokens struct {
	AccessToken string
	IdToken     *string
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

// CreateAuthorizationURLWithPKCE constructs an OAuth 2.0 authorization URL with PKCE (Proof Key for Code Exchange) support.
// It builds the URL by setting the required query parameters such as response_type, client_id, redirect_uri, state,
// code_challenge_method, code_challenge, and scope.
func (p *OAuth2Client) CreateAuthorizationURLWithPKCE(authorizationEndpoint string, state string, codeChallengeMethod CodeChallengeMethod, codeVerifier string, scopes []string) string {
	u, _ := url.Parse(authorizationEndpoint)

	q := u.Query()

	q.Set("response_type", "code")
	q.Set("client_id", p.ClientID)
	if p.RedirectURI != nil {
		q.Set("redirect_uri", *p.RedirectURI)
	}
	q.Set("state", state)

	if codeChallengeMethod == S256 {
		codeChallenge := CreateS256CodeChallenge(codeVerifier)
		q.Set("code_challenge_method", "S256")
		q.Set("code_challenge", codeChallenge)
	} else if codeChallengeMethod == Plain {
		q.Set("code_challenge_method", "plain")
		q.Set("code_challenge", codeVerifier)
	}

	if len(scopes) > 0 {
		q.Set("scope", strings.Join(scopes, " "))
	}

	u.RawQuery = q.Encode()

	return u.String()
}

// ValidateAuthorizationCode exchanges an authorization code for an access token using the OAuth2 protocol.
// It sends a POST request to the specified token endpoint with the provided authorization code and optional redirect URI.
// The client credentials are included in the Authorization header using Basic authentication.
func (p *OAuth2Client) ValidateAuthorizationCode(endpoint string, code string, codeVerifier *string) (*OAuth2Tokens, error) {
	body := url.Values{}

	body.Set("grant_type", "authorization_code")
	body.Set("code", code)
	if p.RedirectURI != nil {
		body.Set("redirect_uri", *p.RedirectURI)
	}
	if codeVerifier != nil {
		body.Set("code_verifier", *codeVerifier)
	}

	request, err := CreateOAuth2Request(endpoint, body)
	if err != nil {
		return nil, err
	}

	encodedCredentials := EncodeBasicCredentials(p.ClientID, p.ClientSecret)
	request.Header.Set("Authorization", fmt.Sprintf("Basic %s", encodedCredentials))

	tokensMap, err := SendTokenRequest[map[string]any](request, p.Http)
	if err != nil {
		return nil, err
	}

	oauth2Tokens := &OAuth2Tokens{}

	if accessToken, ok := (*tokensMap)["access_token"].(string); ok {
		oauth2Tokens.AccessToken = accessToken
	}

	if idToken, ok := (*tokensMap)["id_token"].(string); ok {
		oauth2Tokens.IdToken = &idToken
	}

	return oauth2Tokens, nil
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

// DecodeIdToken decodes a JWT ID token string into the specified claims type T without verifying its signature.
// It returns a pointer to the decoded claims or an error if decoding fails.
func DecodeIdToken[T jwt.Claims](token string) (*T, error) {
	parsed, err := jwt.UnsecureDecodeToken[T](token)
	if err != nil {
		return nil, err
	}

	return parsed.Claims, nil
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

// GenerateCodeVerifier generates a cryptographically secure random string
// suitable for use as a PKCE code verifier. The returned string is 43 characters
// long and encoded in Base32, ensuring high entropy and URL safety.
func GenerateCodeVerifier() string {
	return strivia_random.SecureRandomBase32String(43)
}

// CreateS256CodeChallenge generates a PKCE S256 code challenge from the provided code verifier.
// It computes the SHA-256 hash of the code verifier and encodes the result using base64 URL encoding
// without padding, as specified by the OAuth 2.0 PKCE extension.
func CreateS256CodeChallenge(codeVerifier string) string {
	h := sha256.New()
	h.Write([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
