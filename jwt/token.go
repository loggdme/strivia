package jwt

import (
	"crypto/ed25519"

	"github.com/goccy/go-json"
)

// Token represents a JWT Token.  Different fields will be used depending on
// whether you're creating or parsing/verifying a token.
type Token[Claims any] struct {
	Raw       string         // Raw contains the raw token.  Populated when you [Parse] a token
	Header    map[string]any // Header is the first segment of the token in decoded form
	Claims    *Claims        // Claims is the second segment of the token in decoded form
	Signature []byte         // Signature is the third segment of the token in decoded form.  Populated when you Parse a token
	Valid     bool           // Valid specifies if the token is valid.  Populated when you Parse/Verify a token
}

func NewToken[Claims any](claims *Claims) *Token[Claims] {
	return &Token[Claims]{
		Header: map[string]any{"typ": "JWT", "alg": "EdDSA"},
		Claims: claims,
	}
}

// SignedString creates and returns a complete, signed JWT. The token is signed
// using the SigningMethod specified in the token. Please refer to
// https://golang-jwt.github.io/jwt/usage/signing_methods/#signing-methods-and-key-types
// for an overview of the different signing methods and their respective key
// types.
func (t *Token[Claims]) SignedString(key ed25519.PrivateKey) (string, error) {
	header, err := json.Marshal(t.Header)
	if err != nil {
		return "", err
	}

	claims, err := json.Marshal(t.Claims)
	if err != nil {
		return "", err
	}

	signingString := _EncodeSegment(header) + "." + _EncodeSegment(claims)

	sig, err := SignEd25519(signingString, key)
	if err != nil {
		return "", err
	}

	return signingString + "." + _EncodeSegment(sig), nil
}
