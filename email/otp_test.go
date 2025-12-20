package email

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"
)

func TestGenerateRandomOTP_Defaults(t *testing.T) {
	otp, err := GenerateRandomOTP(DefaultOTPOpts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(otp.Code) != 6 {
		t.Errorf("expected code length 6, got %d", len(otp.Code))
	}
	if time.Until(otp.ExpiresAt) < 14*time.Minute {
		t.Errorf("expected validity at least 14 minutes, got %v", time.Until(otp.ExpiresAt))
	}
}

func TestGenerateRandomOTP_CustomOptions(t *testing.T) {
	opts := GenerateOptsRandomOTP{Length: 8, Validity: 30 * time.Minute}
	otp, err := GenerateRandomOTP(opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(otp.Code) != 8 {
		t.Errorf("expected code length 8, got %d", len(otp.Code))
	}
	if time.Until(otp.ExpiresAt) < 29*time.Minute {
		t.Errorf("expected validity at least 29 minutes, got %v", time.Until(otp.ExpiresAt))
	}
}

func TestGenerateRandomOTP_AlphanumericCharacters(t *testing.T) {
	otp, err := GenerateRandomOTP(GenerateOptsRandomOTP{Length: 20})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, r := range otp.Code {
		found := slices.Contains(AlphanumericCharacters, r)
		if !found {
			t.Errorf("character %q in code is not allowed", r)
		}
	}
}

func TestGenerateRandomOTP_UniqueCodes(t *testing.T) {
	codes := make(map[string]struct{})
	for range 10 {
		otp, err := GenerateRandomOTP(DefaultOTPOpts)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, exists := codes[otp.Code]; exists {
			t.Errorf("duplicate code generated: %s", otp.Code)
		}
		codes[otp.Code] = struct{}{}
	}
}

func TestRandomOTPCode_IsValid(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{
			name:      "valid OTP (expires in future)",
			expiresAt: now.Add(1 * time.Minute),
			want:      true,
		},
		{
			name:      "expired OTP (expires in past)",
			expiresAt: now.Add(-1 * time.Minute),
			want:      false,
		},
		{
			name:      "expires exactly now (should be invalid)",
			expiresAt: now,
			want:      false,
		},
	}

	for _, tt := range tests {
		otp := &RandomOTPCode{Code: "ABCDEF", ExpiresAt: tt.expiresAt}
		got := otp.IsValid()
		if got != tt.want {
			t.Errorf("%s: expected %v, got %v", tt.name, tt.want, got)
		}
	}
}

func TestRandomOTPCode_String(t *testing.T) {
	otp := &RandomOTPCode{Code: "ABCDEFG", ExpiresAt: time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)}
	got := otp.String()

	var parsed RandomOTPCode
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("String() output is not valid JSON: %v", err)
	}
	if parsed.Code != otp.Code {
		t.Errorf("expected Code %q, got %q", otp.Code, parsed.Code)
	}
	if !parsed.ExpiresAt.Equal(otp.ExpiresAt) {
		t.Errorf("expected ExpiresAt %v, got %v", otp.ExpiresAt, parsed.ExpiresAt)
	}
}

func TestRandomOTPFromString_ValidInput(t *testing.T) {
	jsonStr := "{\"code\":\"ABCDEFG\",\"expiresAt\":\"2024-06-01T12:00:00Z\"}"

	got, err := RandomOTPFromString(jsonStr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got.Code != "ABCDEFG" {
		t.Errorf("expected Code %q, got %q", "ABCDEFG", got.Code)
	}

	if !got.ExpiresAt.Equal(time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("expected ExpiresAt %s, got %v", "2024-06-01T12:00:00Z", got.ExpiresAt)
	}
}

func TestRandomOTPFromString_InvalidJSON(t *testing.T) {
	invalidJSON := `{"code": "ABC", "expiresAt": "not-a-date"}`
	_, err := RandomOTPFromString(invalidJSON)
	if err == nil || !errors.Is(err, ErrParseRandomOtpFromStringFormat) {
		t.Errorf("expected ErrParseRandomOtpFromStringFormat, got %v", err)
	}
}

func TestRandomOTPFromString_MissingFields(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{
			name: "missing code",
			json: `{"expiresAt":"2024-06-01T12:00:00Z"}`,
		},
		{
			name: "missing expiresAt",
			json: `{"code":"ABCDEFG"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := RandomOTPFromString(tt.json)
			if err == nil || !errors.Is(err, ErrParseRandomOtpFromStringValues) {
				t.Errorf("expected ErrParseRandomOtpFromStringValues, got %v", err)
			}
		})
	}
}
