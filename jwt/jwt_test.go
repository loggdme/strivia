package jwt

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNumericDate_MarshalJSON(t *testing.T) {
	dt := time.Date(2024, 6, 1, 12, 34, 56, 123456789, time.UTC)

	nd := NumericDate{dt}
	json, err := nd.MarshalJSON()

	assert.NoError(t, err, "MarshalJSON should not return an error")
	assert.Equal(t, []byte("1717245296"), json, "MarshalJSON should return the correct JSON representation")
}

func TestNumericDate_UnmarshalJSON(t *testing.T) {
	input := []byte("1717245296")

	var nd NumericDate
	err := nd.UnmarshalJSON(input)
	assert.NoError(t, err, "UnmarshalJSON should not return an error")

	expected := time.Unix(1717245296, 0).Truncate(time.Second)
	assert.Equal(t, expected, nd.Time, "UnmarshalJSON should set the correct time")
}
