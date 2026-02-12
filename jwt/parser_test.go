package jwt

import (
	"errors"
	"testing"
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

	if len(parts) != 3 {
		t.Errorf("Expected 3 parts, got %d", len(parts))
	}
	if !ok {
		t.Error("Expected split to be successful")
	}
	if parts[0] != "header" {
		t.Errorf("First part should be 'header', got %q", parts[0])
	}
	if parts[1] != "claims" {
		t.Errorf("Second part should be 'claims', got %q", parts[1])
	}
	if parts[2] != "signature" {
		t.Errorf("Third part should be 'signature', got %q", parts[2])
	}
}

func TestSplitToken_TooManyPartsFail(t *testing.T) {
	input := "header.claims.signature.extra"
	parts, ok := splitToken(input)

	if len(parts) != 0 {
		t.Errorf("Expected 0 parts, got %d", len(parts))
	}
	if ok {
		t.Error("Expected split to fail due to too many parts")
	}
}

/* UnsecureDecodeToken */

func TestUnsecureDecodeToken_ValidToken(t *testing.T) {
	tokenString := _EncodeSegment([]byte(`{"alg":"none"}`)) + "." + _EncodeSegment([]byte(`{"sub":"123"}`)) + "." + _EncodeSegment([]byte("sig"))

	token, err := UnsecureDecodeToken[RegisteredClaims](tokenString)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token == nil {
		t.Fatal("expected non-nil token")
	}
	if token.Raw != tokenString {
		t.Errorf("expected Raw %q, got %q", tokenString, token.Raw)
	}
	if token.Header["alg"] != "none" {
		t.Errorf("expected alg \"none\", got %q", token.Header["alg"])
	}
	if token.Claims.Subject != "123" {
		t.Errorf("expected sub \"123\", got %q", token.Claims.Subject)
	}
	if string(token.Signature) != "sig" {
		t.Errorf("expected signature \"sig\", got %q", string(token.Signature))
	}
}

func TestUnsecureDecodeToken_MalformedTokenParts(t *testing.T) {
	tokenString := "onlyonepart"
	token, err := UnsecureDecodeToken[RegisteredClaims](tokenString)
	if token != nil {
		t.Error("expected nil token")
	}
	if !errors.Is(err, ErrTokenMalformed) {
		t.Errorf("expected ErrTokenMalformed, got %v", err)
	}

	tokenString = "a.b.c.d"
	token, err = UnsecureDecodeToken[RegisteredClaims](tokenString)
	if token != nil {
		t.Error("expected nil token")
	}
	if !errors.Is(err, ErrTokenMalformed) {
		t.Errorf("expected ErrTokenMalformed, got %v", err)
	}
}

func TestUnsecureDecodeToken_InvalidBase64Header(t *testing.T) {
	tokenString := "!!invalid!!." + _EncodeSegment([]byte("{}")) + "." + _EncodeSegment([]byte("sig"))
	token, err := UnsecureDecodeToken[RegisteredClaims](tokenString)
	if token != nil {
		t.Error("expected nil token")
	}
	if !errors.Is(err, ErrTokenMalformed) {
		t.Errorf("expected ErrTokenMalformed, got %v", err)
	}
}

func TestUnsecureDecodeToken_InvalidJSONHeader(t *testing.T) {
	tokenString := _EncodeSegment([]byte("not_json")) + "." + _EncodeSegment([]byte("{}")) + "." + _EncodeSegment([]byte("sig"))
	token, err := UnsecureDecodeToken[RegisteredClaims](tokenString)
	if token == nil {
		t.Error("expected non-nil token")
	}
	if !errors.Is(err, ErrTokenMalformed) {
		t.Errorf("expected ErrTokenMalformed, got %v", err)
	}
}

func TestUnsecureDecodeToken_InvalidBase64Claims(t *testing.T) {
	tokenString := _EncodeSegment([]byte("{}")) + ".!!invalid!!." + _EncodeSegment([]byte("sig"))
	token, err := UnsecureDecodeToken[RegisteredClaims](tokenString)
	if token != nil {
		t.Error("expected nil token")
	}
	if !errors.Is(err, ErrTokenMalformed) {
		t.Errorf("expected ErrTokenMalformed, got %v", err)
	}
}

func TestUnsecureDecodeToken_InvalidJSONClaims(t *testing.T) {
	tokenString := _EncodeSegment([]byte("{}")) + "." + _EncodeSegment([]byte("not_json")) + "." + _EncodeSegment([]byte("sig"))
	token, err := UnsecureDecodeToken[RegisteredClaims](tokenString)
	if token == nil {
		t.Error("expected non-nil token")
	}
	if !errors.Is(err, ErrTokenMalformed) {
		t.Errorf("expected ErrTokenMalformed, got %v", err)
	}
}

func TestUnsecureDecodeToken_InvalidBase64Signature(t *testing.T) {
	tokenString := _EncodeSegment([]byte("{}")) + "." + _EncodeSegment([]byte("{}")) + ".!!invalid!!"
	token, err := UnsecureDecodeToken[RegisteredClaims](tokenString)
	if token != nil {
		t.Error("expected nil token")
	}
	if !errors.Is(err, ErrTokenMalformed) {
		t.Errorf("expected ErrTokenMalformed, got %v", err)
	}
}

/* VerifyToken */

func TestVerifyToken_ValidToken(t *testing.T) {
	tokenString := "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InVzZXJAbG9nZ2QubWUiLCJpc3MiOiJsb2dnZC5tZSIsInN1YiI6InVuaXF1ZS11c2VyLWlkIiwiYXVkIjoibG9nZ2QubWUiLCJleHAiOjE3OTc3NzA2MjAsIm5iZiI6MTc2NjIzNDYyMCwiaWF0IjoxNzY2MjM0NjIwLCJqdGkiOiI1VUdQM1YzTDNFN1BCTURPQVFBNk5QU1FNSEFBRTVBNUJPQkpKQUc1QzJMS0xLUUFTU1dBIn0.JeIcAj93ncfuEs2WNXEZsaa9LHIl-Rd-90HZdv5L69e5t3mLaY3zFeHIPAydCvURPI3favdsAjzGy3R-uKEgBQ"

	publicKey, err := ParseEd25519PublicKey("MCowBQYDK2VwAyEAIcjUkocF8Vxw6BcY3c8nx1DjgXcCLlqwFfLkma+uJr4=")
	if err != nil {
		t.Fatalf("unexpected error parsing key: %v", err)
	}

	expectedClaims := ExpectedClaims{
		Issuer:   "loggd.me",
		Subject:  "unique-user-id",
		Audience: []string{"loggd.me"},
	}

	_, err = VerifyToken[RegisteredClaims](tokenString, &publicKey, &expectedClaims)
	if err != nil {
		t.Errorf("expected no error for valid token, got %v", err)
	}
}

func TestVerifyToken_InvalidAlgorithm(t *testing.T) {
	_, err := VerifyToken[RegisteredClaims]("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2ln", nil, nil)
	if !errors.Is(err, ErrTokenInvalidAlgorithm) {
		t.Errorf("expected ErrTokenInvalidAlgorithm, got %v", err)
	}
}

func TestVerifyToken_SignatureVerificationFail(t *testing.T) {
	tokenString := "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.1PUyBb7hgI5SH-6aCWrYiGBy02Y8gwLmdh-j7JmnU7QUMszSyGSOPvGDW8zFI851lprf1M7bJ13KNSDwjbMTHBQ"

	publicKey, err := ParseEd25519PublicKey("MCowBQYDK2VwAyEAIcjUkocF8Vxw6BcY3c8nx1DjgXcCLlqwFfLkma+uJr4=")
	if err != nil {
		t.Fatalf("unexpected error parsing key: %v", err)
	}

	_, err = VerifyToken[RegisteredClaims](tokenString, &publicKey, nil)
	if !errors.Is(err, ErrEd25519Verification) {
		t.Errorf("expected ErrEd25519Verification, got %v", err)
	}
}
