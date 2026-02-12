package jwt

import (
	"testing"
)

// ====== Benchmarks ======

func BenchmarkSignedString(b *testing.B) {
	type Claims struct {
		Email string `json:"email"`
		RegisteredClaims
	}

	privateKey, _ := ParseEd25519PrivateKey("MC4CAQAwBQYDK2VwBCIEIJ7VP4bGde7HFmugf7wnZ+f09S4wXiHTPqCQB/HYLw+s")
	token := NewToken(&Claims{Email: "user_new@loggd.me"})

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		token.SignedString(&privateKey)
	}
}

// ====== Tests ======

func TestSignedString_Success(t *testing.T) {
	type Claims struct {
		Email string `json:"email"`
		RegisteredClaims
	}

	privateKey, err := ParseEd25519PrivateKey("MC4CAQAwBQYDK2VwBCIEIJ7VP4bGde7HFmugf7wnZ+f09S4wXiHTPqCQB/HYLw+s")
	if err != nil {
		t.Fatalf("Failed to parse private key: %v", err)
	}

	token := NewToken(&Claims{Email: "user@loggd.me"})
	signed, err := token.SignedString(&privateKey)
	if err != nil {
		t.Fatalf("SignedString failed: %v", err)
	}

	expectedToken := "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InVzZXJAbG9nZ2QubWUifQ.teoqhuOV4bNqahptstTAwWHtTqjTmHYEYR3X_7ROOQzP6t4OmtdQOIrFunwDnBdYEPS7g7U_7DDTe_xxLD2DBg"
	if signed != expectedToken {
		t.Errorf("Signed token mismatch: expected %q, got %q", expectedToken, signed)
	}
}
