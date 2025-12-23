package jwt

import (
	"encoding/json"
	"strings"
)

// VerifyToken verifies a JWT token string using the provided Ed25519 public key.
// It decodes the token, checks the algorithm, verifies the signature, and validates the claims.
// If the token is valid, it returns the parsed Token with its Valid field set to true.
// The generic type T must satisfy the Claims interface.
func VerifyToken[T Claims](tokenString string, key *PublicKey, expected *ExpectedClaims) (*Token[T], error) {
	token, err := UnsecureDecodeToken[T](tokenString)
	if err != nil {
		return nil, err
	}

	if token.Header["alg"] != "EdDSA" {
		return nil, ErrTokenInvalidAlgorithm
	}

	tokenPayload := token.RawParts[0] + "." + token.RawParts[1]
	if err := VerifyEd25519(tokenPayload, token.Signature, key); err != nil {
		return nil, err
	}

	if err := validateClaims(*token.Claims, expected); err != nil {
		return nil, err
	}

	token.Valid = true

	return token, nil
}

// UnsecureDecodeToken decodes a JWT token string without verifying its signature.
// It splits the token into its header, claims, and signature parts, decodes each segment,
// and unmarshal the header and claims into their respective structures.
// This function does not perform any cryptographic verification and should only be used
// in trusted environments or for debugging purposes.
func UnsecureDecodeToken[T Claims](tokenString string) (*Token[T], error) {
	parts, ok := splitToken(tokenString)
	if !ok {
		return nil, ErrTokenMalformed
	}

	token := &Token[T]{Raw: tokenString, RawParts: parts}

	headerBytes, err := _DecodeSegment(parts[0])
	if err != nil {
		return nil, ErrTokenMalformed
	}
	if err := json.Unmarshal(headerBytes, &token.Header); err != nil {
		return token, ErrTokenMalformed
	}

	claimBytes, err := _DecodeSegment(parts[1])
	if err != nil {
		return nil, ErrTokenMalformed
	}
	if err := json.Unmarshal(claimBytes, &token.Claims); err != nil {
		return token, ErrTokenMalformed
	}

	token.Signature, err = _DecodeSegment(parts[2])
	if err != nil {
		return nil, ErrTokenMalformed
	}

	return token, nil
}

// splitToken splits a token string into three parts: header, claims, and signature. It will only
// return true if the token contains exactly two delimiters and three parts. In all other cases, it
// will return nil parts and false.
func splitToken(token string) ([]string, bool) {
	parts := make([]string, 3)

	header, remain, ok := strings.Cut(token, ".")
	if !ok {
		return nil, false
	}
	parts[0] = header

	claims, remain, ok := strings.Cut(remain, ".")
	if !ok {
		return nil, false
	}
	parts[1] = claims

	// One more cut to ensure the signature is the last part of the token and there are no more
	// delimiters. This avoids an issue where malicious input could contain additional delimiters
	// causing unnecessary overhead parsing tokens.
	signature, _, unexpected := strings.Cut(remain, ".")
	if unexpected {
		return nil, false
	}
	parts[2] = signature

	return parts, true
}
