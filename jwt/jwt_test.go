package jwt

import (
	"bytes"
	"testing"
	"time"
)

func TestNumericDate_MarshalJSON(t *testing.T) {
	dt := time.Date(2024, 6, 1, 12, 34, 56, 123456789, time.UTC)

	nd := NumericDate{dt}
	json, err := nd.MarshalJSON()

	if err != nil {
		t.Fatalf("MarshalJSON should not return an error: %v", err)
	}
	if !bytes.Equal(json, []byte("1717245296")) {
		t.Errorf("MarshalJSON should return the correct JSON representation: expected %q, got %q", []byte("1717245296"), json)
	}
}

func TestNumericDate_UnmarshalJSON(t *testing.T) {
	input := []byte("1717245296")

	var nd NumericDate
	err := nd.UnmarshalJSON(input)
	if err != nil {
		t.Fatalf("UnmarshalJSON should not return an error: %v", err)
	}

	expected := time.Unix(1717245296, 0).Truncate(time.Second)
	if !nd.Time.Equal(expected) {
		t.Errorf("UnmarshalJSON should set the correct time: expected %v, got %v", expected, nd.Time)
	}
}
