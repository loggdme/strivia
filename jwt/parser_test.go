package jwt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

/* SplitToken */

func TestSplitToken_NormalInput(t *testing.T) {
	input := "header.claims.signature"
	parts, ok := splitToken(input)

	assert.Equal(t, 3, len(parts), "Expected 3 parts")
	assert.True(t, ok, "Expected split to be successful")
	assert.Equal(t, "header", parts[0], "First part should be 'header'")
	assert.Equal(t, "claims", parts[1], "Second part should be 'claims'")
	assert.Equal(t, "signature", parts[2], "Third part should be 'signature'")
}

func TestSplitToken_TooManyPartsFail(t *testing.T) {
	input := "header.claims.signature.extra"
	parts, ok := splitToken(input)

	assert.Equal(t, 0, len(parts), "Expected 0 parts")
	assert.False(t, ok, "Expected split to fail due to too many parts")
}

/* UnsecureDecodeToken */

func TestUnsecureDecodeToken_ValidToken(t *testing.T) {
	tokenString := _EncodeSegment([]byte(`{"alg":"none"}`)) + "." + _EncodeSegment([]byte(`{"sub":"123"}`)) + "." + _EncodeSegment([]byte("sig"))

	token, err := UnsecureDecodeToken[struct {
		Sub string `json:"sub"`
	}](tokenString)

	assert.NoError(t, err)
	assert.NotNil(t, token)
	assert.Equal(t, token.Raw, tokenString)
	assert.Equal(t, "none", token.Header["alg"])
	assert.Equal(t, "123", token.Claims.Sub)
	assert.Equal(t, []byte("sig"), token.Signature)
}

func TestUnsecureDecodeToken_MalformedTokenParts(t *testing.T) {
	tokenString := "onlyonepart"
	token, err := UnsecureDecodeToken[map[string]any](tokenString)
	assert.Nil(t, token)
	assert.ErrorIs(t, err, ErrTokenMalformed)

	tokenString = "a.b.c.d"
	token, err = UnsecureDecodeToken[map[string]any](tokenString)
	assert.Nil(t, token)
	assert.ErrorIs(t, err, ErrTokenMalformed)
}

func TestUnsecureDecodeToken_InvalidBase64Header(t *testing.T) {
	tokenString := "!!invalid!!." + _EncodeSegment([]byte("{}")) + "." + _EncodeSegment([]byte("sig"))
	token, err := UnsecureDecodeToken[map[string]any](tokenString)
	assert.Nil(t, token)
	assert.ErrorIs(t, err, ErrTokenMalformed)
}

func TestUnsecureDecodeToken_InvalidJSONHeader(t *testing.T) {
	tokenString := _EncodeSegment([]byte("not_json")) + "." + _EncodeSegment([]byte("{}")) + "." + _EncodeSegment([]byte("sig"))
	token, err := UnsecureDecodeToken[map[string]any](tokenString)
	assert.NotNil(t, token)
	assert.ErrorIs(t, err, ErrTokenMalformed)
}

func TestUnsecureDecodeToken_InvalidBase64Claims(t *testing.T) {
	tokenString := _EncodeSegment([]byte("{}")) + ".!!invalid!!." + _EncodeSegment([]byte("sig"))
	token, err := UnsecureDecodeToken[map[string]any](tokenString)
	assert.Nil(t, token)
	assert.ErrorIs(t, err, ErrTokenMalformed)
}

func TestUnsecureDecodeToken_InvalidJSONClaims(t *testing.T) {
	tokenString := _EncodeSegment([]byte("{}")) + "." + _EncodeSegment([]byte("not_json")) + "." + _EncodeSegment([]byte("sig"))
	token, err := UnsecureDecodeToken[map[string]any](tokenString)
	assert.NotNil(t, token)
	assert.ErrorIs(t, err, ErrTokenMalformed)
}

func TestUnsecureDecodeToken_InvalidBase64Signature(t *testing.T) {
	tokenString := _EncodeSegment([]byte("{}")) + "." + _EncodeSegment([]byte("{}")) + ".!!invalid!!"
	token, err := UnsecureDecodeToken[map[string]any](tokenString)
	assert.Nil(t, token)
	assert.ErrorIs(t, err, ErrTokenMalformed)
}
