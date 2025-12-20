package jwt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ====== Benchmarks ======

func BenchmarkUnsecureDecodeToken(b *testing.B) {
	type CustomClaims struct {
		Email string `json:"email"`
		RegisteredClaims
	}

	token := "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InVzZXJfbmV3QGxvZ2dkLm1lIiwiaXNzIjoibG9nZ2QubWUiLCJzdWIiOiJ1bmlxdWUtdXNlci1pZCIsImF1ZCI6WyJsb2dnZC5tZSJdLCJleHAiOjE3NDk3NzA0OTUsIm5iZiI6MTc0OTY4NDA5NSwiaWF0IjoxNzQ5Njg0MDk1LCJqdGkiOiJBQlhHSEhLTlVUR0ZGREo0MzdESVQ3V1VINkVIV1JRV1BKWk1ISUNLUEdOVTRENE00TlRRIn0.1G7vmW5ZEKrjem-TJxOuRLDmueaNZ18en4ybpPL76C5CjlTv7t84bMj-SQuBiCahiP0AqB8yWtQbDS2u3Z8RBQ"

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		UnsecureDecodeToken[CustomClaims](token)
	}
}

// ====== Tests ======

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

	token, err := UnsecureDecodeToken[RegisteredClaims](tokenString)

	assert.NoError(t, err)
	assert.NotNil(t, token)
	assert.Equal(t, token.Raw, tokenString)
	assert.Equal(t, "none", token.Header["alg"])
	assert.Equal(t, "123", token.Claims.Subject)
	assert.Equal(t, []byte("sig"), token.Signature)
}

func TestUnsecureDecodeToken_MalformedTokenParts(t *testing.T) {
	tokenString := "onlyonepart"
	token, err := UnsecureDecodeToken[RegisteredClaims](tokenString)
	assert.Nil(t, token)
	assert.ErrorIs(t, err, ErrTokenMalformed)

	tokenString = "a.b.c.d"
	token, err = UnsecureDecodeToken[RegisteredClaims](tokenString)
	assert.Nil(t, token)
	assert.ErrorIs(t, err, ErrTokenMalformed)
}

func TestUnsecureDecodeToken_InvalidBase64Header(t *testing.T) {
	tokenString := "!!invalid!!." + _EncodeSegment([]byte("{}")) + "." + _EncodeSegment([]byte("sig"))
	token, err := UnsecureDecodeToken[RegisteredClaims](tokenString)
	assert.Nil(t, token)
	assert.ErrorIs(t, err, ErrTokenMalformed)
}

func TestUnsecureDecodeToken_InvalidJSONHeader(t *testing.T) {
	tokenString := _EncodeSegment([]byte("not_json")) + "." + _EncodeSegment([]byte("{}")) + "." + _EncodeSegment([]byte("sig"))
	token, err := UnsecureDecodeToken[RegisteredClaims](tokenString)
	assert.NotNil(t, token)
	assert.ErrorIs(t, err, ErrTokenMalformed)
}

func TestUnsecureDecodeToken_InvalidBase64Claims(t *testing.T) {
	tokenString := _EncodeSegment([]byte("{}")) + ".!!invalid!!." + _EncodeSegment([]byte("sig"))
	token, err := UnsecureDecodeToken[RegisteredClaims](tokenString)
	assert.Nil(t, token)
	assert.ErrorIs(t, err, ErrTokenMalformed)
}

func TestUnsecureDecodeToken_InvalidJSONClaims(t *testing.T) {
	tokenString := _EncodeSegment([]byte("{}")) + "." + _EncodeSegment([]byte("not_json")) + "." + _EncodeSegment([]byte("sig"))
	token, err := UnsecureDecodeToken[RegisteredClaims](tokenString)
	assert.NotNil(t, token)
	assert.ErrorIs(t, err, ErrTokenMalformed)
}

func TestUnsecureDecodeToken_InvalidBase64Signature(t *testing.T) {
	tokenString := _EncodeSegment([]byte("{}")) + "." + _EncodeSegment([]byte("{}")) + ".!!invalid!!"
	token, err := UnsecureDecodeToken[RegisteredClaims](tokenString)
	assert.Nil(t, token)
	assert.ErrorIs(t, err, ErrTokenMalformed)
}

/* VerifyToken */

func TestVerifyToken_ValidToken(t *testing.T) {
	tokenString := "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InVzZXJAbG9nZ2QubWUiLCJpc3MiOiJsb2dnZC5tZSIsInN1YiI6InVuaXF1ZS11c2VyLWlkIiwiYXVkIjoibG9nZ2QubWUiLCJleHAiOjE3OTc3NzA2MjAsIm5iZiI6MTc2NjIzNDYyMCwiaWF0IjoxNzY2MjM0NjIwLCJqdGkiOiI1VUdQM1YzTDNFN1BCTURPQVFBNk5QU1FNSEFBRTVBNUJPQkpKQUc1QzJMS0xLUUFTU1dBIn0.JeIcAj93ncfuEs2WNXEZsaa9LHIl-Rd-90HZdv5L69e5t3mLaY3zFeHIPAydCvURPI3favdsAjzGy3R-uKEgBQ"

	publicKey, err := ParseEd25519PublicKey("MCowBQYDK2VwAyEAIcjUkocF8Vxw6BcY3c8nx1DjgXcCLlqwFfLkma+uJr4=")
	assert.NoError(t, err)

	expectedClaims := ExpectedClaims{
		Issuer:   "loggd.me",
		Subject:  "unique-user-id",
		Audience: []string{"loggd.me"},
	}

	_, err = VerifyToken[RegisteredClaims](tokenString, &publicKey, &expectedClaims)
	assert.NoError(t, err, "Expected no error for valid token")
}

func TestVerifyToken_InvalidAlgorithm(t *testing.T) {
	_, err := VerifyToken[RegisteredClaims]("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2ln", nil, nil)
	assert.ErrorIs(t, err, ErrTokenInvalidAlgorithm)
}

func TestVerifyToken_SignatureVerificationFail(t *testing.T) {
	tokenString := "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.1PUyBb7hgI5SH-6aCWrYiGBy02Y8gwLmdh-j7JmnU7QUMszSyGSOPvGDW8zFI851lprf1M7bJ13KNSDwjbMTHBQ"

	publicKey, err := ParseEd25519PublicKey("MCowBQYDK2VwAyEAIcjUkocF8Vxw6BcY3c8nx1DjgXcCLlqwFfLkma+uJr4=")
	assert.NoError(t, err)

	_, err = VerifyToken[RegisteredClaims](tokenString, &publicKey, nil)
	assert.ErrorIs(t, err, ErrEd25519Verification)
}
