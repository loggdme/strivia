package jwt

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var ed25519TestData = []struct {
	keys        map[string]string
	tokenString string
	valid       bool
}{
	{
		map[string]string{"private": "MC4CAQAwBQYDK2VwBCIEIJ7VP4bGde7HFmugf7wnZ+f09S4wXiHTPqCQB/HYLw+s", "public": "MCowBQYDK2VwAyEA7rD1JBNE9qhzXQBN3mltLsAQy34dwDljiSPzmYeqiiM="},
		"eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InVzZXJfbmV3QGxvZ2dkLm1lIiwiaXNzIjoibG9nZ2QubWUiLCJzdWIiOiJ1bmlxdWUtdXNlci1pZCIsImF1ZCI6WyJsb2dnZC5tZSJdLCJleHAiOjE3NDk3NDkwOTQsIm5iZiI6MTc0OTY2MjY5NCwiaWF0IjoxNzQ5NjYyNjk0LCJqdGkiOiIySlQyUVo3UUpXSjdHNjRNUUpDUERFUVlJVU9FUkxRTFo3NU8zQkxSMzJUWlA0WjRGM1ZRIn0.lpA51axyAHBUvKi2rElnyZ5nJUhQFBHy2ewB5GwrPNpZgEaFlTGqFkT3Xa09xQ3bChzqTxzN2Q98yLZXXXEoBw",
		true,
	},
	{
		map[string]string{"private": "MC4CAQAwBQYDK2VwBCIEIJ7VP4bGde7HFmugf7wnZ+f09S4wXiHTPqCQB/HYLw+s", "public": "MCowBQYDK2VwAyEA7rD1JBNE9qhzXQBN3mltLsAQy34dwDljiSPzmYeqiiM="},
		"eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InVzZXJfbmV3QGxvZ2dkLm1lIiwiaXNzIjoiYXBpLmxvZ2dkLm1lIiwic3ViIjoidW5pcXVlLXVzZXItaWQiLCJhdWQiOlsibG9nZ2QubWUiXSwiZXhwIjoxNzQ5NzQ5MTE5LCJuYmYiOjE3NDk2NjI3MTksImlhdCI6MTc0OTY2MjcxOSwianRpIjoiQTRKRVlSMk9KNzZENlFDTkxMSkk3WFBWTzZVQTdIQUpWRlkzR0I2MkdYSUlIWkNRN1NaQSJ9.lpA51axyAHBUvKi2rElnyZ5nJUhQFBHy2ewB5GwrPNpZgEaFlTGqFkT3Xa09xQ3bChzqTxzN2Q98yLZXXXEoBw",
		false,
	},
}

func TestVerifyEd25519(t *testing.T) {
	for _, data := range ed25519TestData {
		ed25519Key, err := ParseEd25519PublicKey(data.keys["public"])
		assert.NoError(t, err, "Unable to parse Ed25519 public key")

		parts := strings.Split(data.tokenString, ".")
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		err = VerifyEd25519(strings.Join(parts[0:2], "."), sig, ed25519Key)

		if data.valid {
			assert.NoError(t, err, "Error while verifying key")
		} else {
			assert.Error(t, err, "Invalid key passed validation")
		}
	}
}

func TestSignEd25519(t *testing.T) {
	for _, data := range ed25519TestData {
		ed25519Key, err := ParseEd25519PrivateKey(data.keys["private"])
		assert.NoError(t, err, "Unable to parse Ed25519 private key")

		parts := strings.Split(data.tokenString, ".")
		sig, err := SignEd25519(strings.Join(parts[0:2], "."), ed25519Key)
		assert.NoError(t, err, "Error signing token")

		ssig := _EncodeSegment(sig)
		assert.True(t, ssig != parts[2] || data.valid, "Identical signatures found when data was invalid.", parts[2], ssig)
	}
}
