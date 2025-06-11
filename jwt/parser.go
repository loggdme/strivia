package jwt

import (
	"encoding/json"
	"strings"
)

func UnsecureDecodeToken[Claims any](tokenString string) (*Token[Claims], error) {
	parts, ok := splitToken(tokenString)
	if !ok {
		return nil, ErrTokenMalformed
	}

	token := &Token[Claims]{Raw: tokenString}

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
