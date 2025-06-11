package jwt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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
