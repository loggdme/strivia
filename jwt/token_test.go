package jwt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type DummyClaims struct {
	Email string `json:"email"`
}

func TestSignedString_Success(t *testing.T) {
	privateKey, err := ParseEd25519PrivateKey("MC4CAQAwBQYDK2VwBCIEIJ7VP4bGde7HFmugf7wnZ+f09S4wXiHTPqCQB/HYLw+s")
	assert.NoError(t, err, "Failed to parse private key")

	token := NewToken(&DummyClaims{Email: "user_new@loggd.me"})
	signed, err := token.SignedString(privateKey)
	assert.NoError(t, err, "SignedString failed")

	expectedToken := "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InVzZXJfbmV3QGxvZ2dkLm1lIn0.zKlqWmAQE6wMZYIJGe0gtJkIesEBBj8HEGrhwi46o60zSojnWQt8lvYFGdA4mLttmb8jGD-vo2EaToZdvUGnDw"
	assert.Equal(t, expectedToken, signed, "Signed token mismatch")
}
